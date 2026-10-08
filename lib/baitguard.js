/**
 * baitguard.js — refuse (or repair) a bait-list entry that is a public suffix.
 *
 * WHY THIS EXISTS, measured:
 *
 * A bait list is written by scripts/win-bait-walk.ps1, which reduces a serving
 * host to its registrable domain. That reduction USED to be a hand-maintained
 * list of 26 multi-part suffixes, which cut one label too short for anything
 * outside it -- "co.il" for deer.bait.co.il, "com.pl", "github.io". Since the
 * walk gained scripts/psl-root.js it asks the real public suffix list instead,
 * and those 26 rules survive only as a fallback for a machine with no node on
 * PATH or no reachable repo.
 *
 * So the producer is no longer the expected source of a bad root -- and this
 * guard still exists, for three reasons:
 *
 *   - The fallback is still reachable, and still wrong in the same way.
 *   - The publish step writes `||${domain}^` verbatim. formatDomain() never
 *     runs on that path, so nothing else validates what is about to become a
 *     filter rule.
 *   - The dig gate is satisfied by EITHER the root or the sidecar name, so a
 *     bad root rides in on a good serving host. Measured: a bait list of
 *     "co.il" with a sidecar of 0.taro.sansyettusk.com returned verdict
 *     "confirmed", and the run would have published a rule blocking every
 *     domain under an entire ccTLD.
 *
 * It therefore guards two things, both at the last point before publication:
 * a root that is a public suffix, and a root that is not a usable hostname at
 * all. The second was added after a review found that `*.bait.com`,
 * `host.com:8443`, `user@host.com` and `a..b.com` all passed through untouched,
 * and that `*.bait.com` with a matching sidecar reached "confirmed".
 *
 * REPAIR BEFORE REFUSAL. The sidecar records the name the walk's dig gate
 * actually matched, so when the bait is a public suffix AND that name sits
 * under it, psl can name the real registrable domain and the find survives.
 * Only then: a public suffix with no usable sidecar is refused outright,
 * because refusing loses one bait while publishing a public suffix breaks every
 * site beneath it.
 */

const psl = require('psl');
const { hostRejectionReason } = require('./output');

/**
 * Normalise a DNS name for comparison: lowercase, drop the root-anchoring
 * trailing dot, trim.
 *
 * Both odd forms reach a bait list. win-bait-walk.ps1 takes the host straight
 * out of the capture (Get-BaitHosts -> $_.Groups[1].Value) and Get-Root never
 * lowercases -- only Test-DigMatch does -- so Deer.ICKASIDE.CO.IL reduces to
 * "CO.IL", and a root-anchored host leaves "co.il.". psl normalises internally
 * and reports tld "co.il" for all of them, so comparing psl's answer against
 * the RAW name answered "not a public suffix" and waved them through to
 * ||CO.IL^. Measured before this fix: isPublicSuffix('CO.IL') === false and
 * guardBait('CO.IL', ...) returned {domain:'CO.IL'} with no refusal.
 *
 * A no-op on every bait list in production today -- 0 lines across all six need
 * it -- so this closes a latent bypass rather than changing current output.
 */
function normaliseName(name) {
  return String(name).trim().toLowerCase().replace(/\.+$/, '');
}

/** Registrable domain of a host, or null when there is none. */
function registrableOf(host) {
  try { const p = psl.parse(normaliseName(host)); return (p && p.domain) || null; } catch { return null; }
}

/**
 * True when `name` IS exactly a public suffix (co.il, com.pl, github.io, co.uk).
 *
 * Deliberately NOT "psl gives no registrable domain", which is also true for an
 * unknown TLD: `a.invalid` and `x.test` parse with tld `invalid` / `test` and a
 * registrable domain, and an internal or fixture name must not be refused as if
 * it were a suffix.
 */
function isPublicSuffix(name) {
  const n = normaliseName(name);
  try { const p = psl.parse(n); return !!p && p.tld === n; } catch { return false; }
}

/**
 * @param {string} line - One bait-list entry
 * @param {Map<string,string>|object} confirmHost - sidecar: root -> gate-confirmed name
 * @returns {{domain: string, note?: string, via?: string, reject?: string}}
 */
function guardBait(line, confirmHost) {
  const raw = String(line).trim();
  const d = normaliseName(raw);
  // The sidecar map is keyed by whatever the walk wrote, so look it up by the
  // raw name first and fall back to the normalised one. `via` is returned on
  // EVERY branch that found a sidecar, not only on a repair: the caller re-keys
  // the map by the returned domain, and a normalised passthrough would
  // otherwise lose the gate-confirmed name and dig the root alone.
  const lookup = k => (confirmHost && (typeof confirmHost.get === 'function' ? confirmHost.get(k) : confirmHost[k])) || null;
  const altRaw = lookup(raw) || lookup(d);
  const alt = altRaw ? normaliseName(altRaw) : null;

  // Is it even a hostname? Nothing downstream asks. The publish step writes
  // ||${domain}^ with no formatDomain(), so hostRejectionReason()'s checks --
  // a dot, no empty labels, a 2-character TLD, and DNS characters only -- never
  // run on this path, and a review found *.bait.com, host.com:8443,
  // user@host.com, .co.il, a..b.com and "bait .com" all passing through. The
  // first of those reached verdict "confirmed" on a matching sidecar, which
  // would have published ||*.bait.com^.
  //
  // output.js's function is reused rather than reimplemented: its own comment
  // records the measured cases ('*' blocking every .com, '$' starting a rule
  // option), and a second copy of those rules would be free to drift from the
  // one the rest of the output goes through.
  const malformed = hostRejectionReason(d);
  if (malformed) {
    return {
      domain: d,
      ...(alt ? { via: alt } : {}),
      reject: `refused: "${d}" is not a usable hostname (${malformed})`
    };
  }

  if (!isPublicSuffix(d)) return alt ? { domain: d, via: alt } : { domain: d };

  if (alt && (alt === d || alt.endsWith('.' + d))) {
    const repaired = registrableOf(alt);
    // `alt` itself is never structurally checked -- only the bait is -- so the
    // repair is re-checked here before it becomes a rule. Defensive depth, not
    // a fixed bug: psl refuses an invalid character or an over-long label on
    // its own and returns null, so no reachable input was found that satisfies
    // psl and fails hostRejectionReason. Kept because it costs one call and
    // the two validators are free to diverge; deliberately NOT counted as
    // tested, since there is no test that can fail for it.
    if (repaired && repaired !== d && !hostRejectionReason(repaired)) {
      return {
        domain: repaired,
        via: alt,
        note: `bait list gave the public suffix "${d}"; publishing ${repaired}, taken from the gate-confirmed name ${alt}`
      };
    }
  }
  // Three distinct reasons, kept distinct. This branch originally reported "its
  // sidecar name is not under it" for every failure, which is false whenever
  // the sidecar IS under the suffix but yields no registrable domain of its own
  // -- d "il" with alt "co.il", say. A refusal that misdescribes its own cause
  // is worse than a terse one.
  const under = !!alt && (alt === d || alt.endsWith('.' + d));
  return {
    domain: d,
    ...(alt ? { via: alt } : {}),
    reject: !alt
      ? `refused: "${d}" is a public suffix and there is no sidecar name to recover a registrable domain from`
      : under
        ? `refused: "${d}" is a public suffix and its sidecar name ${alt} yields no registrable domain either`
        : `refused: "${d}" is a public suffix and its sidecar name ${alt} is not under it`
  };
}

module.exports = { guardBait, isPublicSuffix, registrableOf, normaliseName };
