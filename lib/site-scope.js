/**
 * URL and host semantics that more than one module has to agree on.
 *
 * Everything here exists because two modules were answering the same question
 * separately, which works right up until one of them changes.
 *
 * lib/cookies.js and lib/storage.js both have to answer "what is the site this
 * URL belongs to", and they must answer it the same way or a config that seeds a
 * cookie and a storage entry together gets two different scopes -- measured
 * before this was shared: on an apex -> www redirect the storage entries applied
 * and the cookies were not sent at all. The guards below are the whole reason
 * this is not a bare psl.get() call at each site.
 *
 * The two callers want different fallbacks, which is why there are two exports.
 * storage.js MATCHES an already-loaded document against a scope, so an
 * unwidenable host ('localhost') should still match itself -- siteScope().
 * cookies.js SETS a scope, where the same case must stay host-only, because
 * '.localhost' and '.127.0.0.1' are not scopes a browser will store --
 * registrableDomain(), which returns null instead of the host.
 */

const net = require('node:net');
const psl = require('psl');

// Anchored, so only the first few characters of each URL are inspected. blob: is
// included even though a blob url embeds an origin (blob:https://site/uuid): no
// request leaves the browser for it either.
const HOSTLESS_SCHEME_RE = /^(?:data|about|javascript|blob|filesystem):/i;

/**
 * The registrable domain (eTLD+1) for a hostname, or null when there is no
 * broader scope than the host itself.
 *
 * null cases, each of which must NOT be widened:
 *   - IP literals. psl treats the octets as labels and returns the last two, so
 *     psl.get('127.0.0.1') is '0.1' -- and '10.0.0.1'.endsWith('.0.1') is true,
 *     which would make a scope match span unrelated hosts.
 *   - Single-label hosts ('localhost') and unrecognised suffixes: psl returns
 *     null and there is nothing to widen to.
 *   - A hostname that IS a public suffix ('co.uk'): psl returns null, and
 *     widening to it would be a supercookie scope the browser rejects anyway.
 *
 * @param {string} hostname - Bare hostname (no scheme, path or port)
 * @returns {string|null} Registrable domain, or null if there is none
 */
function registrableDomain(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return null;
  if (net.isIP(h)) return null;
  let site = null;
  try {
    site = psl.get(h);
  } catch (_) {
    // Malformed host; treat as having no broader scope.
    return null;
  }
  if (!site) return null;
  // Never widen past the hostname itself, whatever psl returned.
  if (site !== h && !h.endsWith(`.${site}`)) return null;
  return site;
}

/**
 * The scope a seed applies to: the registrable domain when there is one, else
 * the hostname itself. Used for matching (storage) rather than for setting, so
 * an unwidenable host still gets an exact-match scope instead of nothing.
 * @param {string} hostname - Bare hostname
 * @returns {string|null} Scope, or null for empty input
 */
function siteScope(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return null;
  return registrableDomain(h) || h;
}

/**
 * True for a URL with no host: nothing leaves the browser for one, so no network
 * filter can meaningfully match it.
 *
 * Both adblock engines need this and both had their own copy, which is the
 * duplication this module exists to prevent. It matters because a hostless URI
 * carries its content IN the url, so a path or regex rule will match a substring
 * inside it unless something stops it -- measured,
 * `data:text/html,<img src="/banner-ad.png">` matched the rule `/banner-ad.`,
 * aborting an inert inline resource. The rust engine never did that (its native
 * check throws on a url with no hostname), so the two engines disagreed.
 *
 * @param {string} url - Request URL
 * @returns {boolean}
 */
function isHostlessUrl(url) {
  return HOSTLESS_SCHEME_RE.test(url);
}

module.exports = {
  registrableDomain,
  siteScope,
  isHostlessUrl
};
