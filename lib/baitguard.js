/**
 * baitguard.js — refuse (or repair) a bait-list entry that is a public suffix.
 *
 * WHY THIS EXISTS, measured:
 *
 * A bait list is written by scripts/win-bait-walk.ps1, whose Get-Root reduces a
 * serving host to its registrable domain using a hand-maintained list of 26
 * multi-part suffixes rather than the public suffix list. Any suffix outside
 * that list reduces one label too far:
 *
 *     deer.bait.co.il    -> "co.il"       (psl: bait.co.il)
 *     x.bait.com.pl      -> "com.pl"      (psl: bait.com.pl)
 *     x.bait.com.ua      -> "com.ua"      (psl: bait.com.ua)
 *     x.bait.github.io   -> "github.io"   (psl: bait.github.io)
 *
 * Nothing downstream re-derived it. bait-confirm.js dug the name it was given,
 * and the dig gate is satisfied by EITHER the root or the sidecar name, so the
 * serving host alone could carry a bogus root to "confirmed" -- measured: a
 * bait list of "co.il" with a sidecar of 0.taro.sansyettusk.com returned
 * verdict "confirmed". The publish step then writes `||${domain}^` verbatim,
 * with no formatDomain() guard on that path, so the run would have published a
 * rule blocking every domain under an entire ccTLD.
 *
 * Latent rather than live -- every bait observed so far sits on .com or .cc --
 * but the blast radius is a whole suffix, so it is guarded at the last point
 * before publication rather than only fixed at the producer.
 *
 * REPAIR BEFORE REFUSAL. The sidecar records the name the walk's dig gate
 * actually matched, so when the bait is a public suffix AND that name sits
 * under it, psl can name the real registrable domain and the find survives.
 * Only then: a public suffix with no usable sidecar is refused outright,
 * because refusing loses one bait while publishing a public suffix breaks every
 * site beneath it.
 */

const psl = require('psl');

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

  if (!isPublicSuffix(d)) return alt ? { domain: d, via: alt } : { domain: d };

  if (alt && (alt === d || alt.endsWith('.' + d))) {
    const repaired = registrableOf(alt);
    if (repaired && repaired !== d) {
      return {
        domain: repaired,
        via: alt,
        note: `bait list gave the public suffix "${d}"; publishing ${repaired}, taken from the gate-confirmed name ${alt}`
      };
    }
  }
  return {
    domain: d,
    ...(alt ? { via: alt } : {}),
    reject: alt
      ? `refused: "${d}" is a public suffix and its sidecar name ${alt} is not under it`
      : `refused: "${d}" is a public suffix and there is no sidecar name to recover a registrable domain from`
  };
}

module.exports = { guardBait, isPublicSuffix, registrableOf, normaliseName };
