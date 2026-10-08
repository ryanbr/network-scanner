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

/** Registrable domain of a host, or null when there is none. */
function registrableOf(host) {
  try { const p = psl.parse(String(host)); return (p && p.domain) || null; } catch { return null; }
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
  const n = String(name);
  try { const p = psl.parse(n); return !!p && p.tld === n; } catch { return false; }
}

/**
 * @param {string} line - One bait-list entry
 * @param {Map<string,string>|object} confirmHost - sidecar: root -> gate-confirmed name
 * @returns {{domain: string, note?: string, via?: string, reject?: string}}
 */
function guardBait(line, confirmHost) {
  const d = String(line).trim();
  if (!isPublicSuffix(d)) return { domain: d };

  const alt = confirmHost && (typeof confirmHost.get === 'function' ? confirmHost.get(d) : confirmHost[d]);
  if (alt && (alt === d || String(alt).endsWith('.' + d))) {
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
    reject: alt
      ? `refused: "${d}" is a public suffix and its sidecar name ${alt} is not under it`
      : `refused: "${d}" is a public suffix and there is no sidecar name to recover a registrable domain from`
  };
}

module.exports = { guardBait, isPublicSuffix, registrableOf };
