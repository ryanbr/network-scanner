/**
 * Cookie pre-seeding — set cookies BEFORE a URL loads.
 *
 * Sites that gate content on a cookie read it during the initial document load
 * (consent walls, A/B buckets, "seen the interstitial" flags, paywall meters).
 * Setting a cookie after navigation is too late: the gate has already decided.
 * These are applied to the browser context before page.goto(), so the cookie
 * rides on the very first request.
 *
 * Config (per site, in the JSON config):
 *
 *   Short form -- name/value pairs, scoped to the site (all subdomains):
 *     "cookies": { "consent": "granted", "ab_bucket": "b" }
 *
 *   Long form -- full control per cookie:
 *     "cookies": [
 *       { "name": "consent", "value": "granted" },
 *       { "name": "sid", "value": "abc", "domain": ".example.com",
 *         "path": "/", "secure": true, "httpOnly": false,
 *         "sameSite": "Lax", "expires": 1790000000 }
 *     ]
 *
 * Both forms may be mixed across sites. Values that are not strings (numbers,
 * booleans) are stringified, since JSON configs naturally carry `"n": 1`.
 *
 * SCOPE -- the leading dot is load-bearing, which is why the short form adds it.
 * A `domain` written WITHOUT a leading dot produces a HOST-ONLY cookie: Chrome
 * stores 'site.example' as-is and sends it to that host alone. Only
 * '.site.example' is stored domain-scoped and reaches subdomains. This is unlike
 * an HTTP `Set-Cookie: Domain=x` header, where the dot is optional and
 * subdomains are included either way -- the CDP path nwss uses does not work
 * that way, and the difference is silent.
 *
 * The short form therefore defaults to '.' + the REGISTRABLE domain (psl), not
 * the URL's host: seeding from https://www.site.example/ sets '.site.example'.
 * Measured with the old host-only default, on an apex -> www redirect: every
 * cookie was dropped while lib/storage.js's entries survived, because that
 * module matches on the registrable domain. Both features now derive the scope
 * through lib/site-scope.js, so they cannot disagree. Two further reasons the
 * wider scope is the right default:
 *   - it is the scope the site itself uses for these gate cookies, which are
 *     nearly always 'Domain=.site.com';
 *   - a host-only seed plus the page writing its own domain-scoped copy produces
 *     TWO cookies of the same name in one request header (measured:
 *     'dup=SEEDED; dup=PAGE_WROTE_THIS'), and which one the server honours is
 *     unspecified. Matching the site's scope means the page simply overwrites
 *     our value, which is one cookie.
 *
 * A host whose scope cannot be widened -- an IP literal, 'localhost', a bare
 * public suffix -- stays host-only; see lib/site-scope.js. To ask for host-only
 * deliberately, use the long form with a dotless `domain`.
 */

// Shared with lib/storage.js so the two seeding features cannot disagree on
// what "the site" is for a URL.
const { registrableDomain } = require('./site-scope');
const { formatLogMessage, messageColors } = require('./colorize');

const COOKIES_TAG = messageColors.processing('[cookies]');

// A cookie name may not contain control characters, whitespace, or the
// delimiters that would let it break out into a second cookie or a header.
// Same class of guard as the CR/LF header filter in lib/curl.js: the config is
// user-supplied, and a malformed pair fails silently inside Chrome otherwise.
const INVALID_NAME_RE = /[\u0000-\u001F\u007F=;,\s]/;
// Values are laxer (spaces and '=' are legal) but still must not carry a ';'
// or control characters.
const INVALID_VALUE_RE = /[\u0000-\u001F\u007F;]/;

const VALID_SAME_SITE = Object.freeze(['Strict', 'Lax', 'None']);

// Recognised per-cookie keys. Anything else is a typo (`secue`, `Domain`,
// `url`) that would otherwise be dropped in silence, leaving a cookie that is
// not the one the config asked for.
const KNOWN_COOKIE_KEYS = Object.freeze([
  'name', 'value', 'domain', 'path', 'secure', 'httpOnly', 'sameSite', 'expires'
]);

// Above this, an `expires` is certainly a millisecond timestamp (Date.now())
// rather than the seconds CDP wants: 1e11 seconds is the year 5138.
const EXPIRES_MILLIS_THRESHOLD = 1e11;

// How many in-flight URLs are relying on each seeded cookie, keyed by
// name/domain/path. Cookies live on ONE shared browser context while processUrl
// runs up to --max-concurrent URLs at a time, so a URL that finishes early must
// NOT delete a cookie a concurrent URL is still using. Measured before this
// existed: with two same-host entries, the first to finish tore the cookie down
// and the second's reload arrived with no cookie at all.
const _seedRefs = new Map();

/** Cookie identity for refcounting, with the leading '.' ignored.
 *
 * Chrome now reports back exactly what we send ('.domain.com' stays dotted,
 * 'domain.com' stays bare), so this is not normalising a round-trip difference
 * -- it deliberately treats a site entry's '.domain.com' seed and another
 * entry's host-only 'domain.com' seed as ONE refcounted identity. Correct on
 * purpose: teardown's matcher is equally lenient, so neither is deleted until
 * both entries are done, and the last one clears both. Distinguishing them would
 * let the first finisher delete a cookie the second is still relying on. */
function cookieKey(c) {
  const domain = String(c.domain || '').replace(/^\./, '').toLowerCase();
  return `${c.name}\u0000${domain}\u0000${c.path || '/'}`;
}

/**
 * Record that one URL is relying on these seeded cookies. Call ONCE per URL --
 * not on the per-reload re-seed, which would inflate the count and leave the
 * cookie behind forever. applySiteCookies({retain}) is the normal caller.
 *
 * It must run BEFORE the cookie reaches the browser, not after. Over one CDP
 * WebSocket the messages are processed in order, so a teardown that is already
 * in flight reads the jar, sees this URL's cookie, and decides to delete it --
 * all before this URL's own setCookie RESPONSE comes back. Claiming after the
 * seed therefore always lost that argument: measured `SET -> SET -> C claimed
 * -> DELETE`, the newcomer claiming in good time by wall clock and still being
 * deleted, because the teardown's decision point had already passed. Claiming
 * first is synchronous and precedes every round trip, so no teardown can miss
 * it. See removeCookies() for the matching check.
 * @param {Array<object>} cookies - Cookies about to be applied
 * @returns {void}
 */
function retainSeeded(cookies) {
  if (!Array.isArray(cookies)) return;
  for (const c of cookies) {
    const k = cookieKey(c);
    _seedRefs.set(k, (_seedRefs.get(k) || 0) + 1);
  }
}

/**
 * Normalize a site's `cookies` config into puppeteer CookieData objects.
 * Never throws: invalid entries are dropped and reported, so one bad cookie
 * cannot abort a scan.
 * @param {object|Array|null|undefined} rawCookies - siteConfig.cookies
 * @param {string} targetUrl - URL being loaded (supplies the default domain)
 * @returns {{cookies: Array<object>, errors: Array<string>}}
 */
function normalizeCookies(rawCookies, targetUrl) {
  const out = { cookies: [], errors: [] };
  if (rawCookies === undefined || rawCookies === null) return out;

  // Default scope: '.' + the registrable domain, i.e. the whole site including
  // subdomains (see SCOPE in the header for why, and for the measurement). Falls
  // back to the bare host when there is no wider scope to take -- an IP literal
  // or 'localhost', where '.127.0.0.1' is not a thing.
  //
  // Deliberately NOT puppeteer's `url` field: that derives the path from the URL,
  // so a cookie seeded from https://site/a/b would only be visible under /a,
  // which is never what a load-time gate wants.
  let defaultDomain = null;
  let targetHost = null;
  let targetSite = null;
  try {
    targetHost = (new URL(targetUrl).hostname || '').toLowerCase() || null;
    if (targetHost) {
      targetSite = registrableDomain(targetHost);
      defaultDomain = targetSite ? `.${targetSite}` : targetHost;
    }
  } catch (_) {
    // Caller passed something unparseable; long-form entries can still carry
    // their own domain, so keep going rather than dropping everything.
  }

  let entries;
  if (Array.isArray(rawCookies)) {
    entries = rawCookies;
  } else if (typeof rawCookies === 'object') {
    // Short form: { name: value } -> [{ name, value }]
    entries = Object.entries(rawCookies).map(([name, value]) => ({ name, value }));
  } else {
    out.errors.push(`'cookies' must be an object or an array, got ${typeof rawCookies}`);
    return out;
  }

  for (const entry of entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      out.errors.push(`cookie entry must be an object, got ${Array.isArray(entry) ? 'array' : typeof entry}`);
      continue;
    }

    const name = entry.name;
    if (typeof name !== 'string' || name.length === 0) {
      out.errors.push(`cookie is missing a string 'name'`);
      continue;
    }
    if (INVALID_NAME_RE.test(name)) {
      out.errors.push(`cookie name ${JSON.stringify(name)} contains an illegal character (control, whitespace, '=', ';' or ',')`);
      continue;
    }

    // Stringify non-strings: a JSON config naturally holds numbers/booleans,
    // and Chrome requires a string. undefined/null become '' rather than the
    // literal text "undefined".
    const rawValue = entry.value;
    const value = (rawValue === undefined || rawValue === null) ? '' : String(rawValue);
    if (INVALID_VALUE_RE.test(value)) {
      out.errors.push(`cookie ${JSON.stringify(name)} has a value containing a control character or ';'`);
      continue;
    }

    const domain = typeof entry.domain === 'string' && entry.domain ? entry.domain : defaultDomain;
    if (!domain) {
      out.errors.push(`cookie ${JSON.stringify(name)} has no 'domain' and one could not be derived from the URL`);
      continue;
    }
    // A dotless PARENT domain is the one shape that can never be sent on this
    // scan: host-only means exact-host, so 'domain.com' while loading
    // www.domain.com matches nothing the page requests. Someone writing that
    // means the HTTP `Domain=domain.com` semantics, where subdomains are
    // included. A dotless domain equal to the target host is a legitimate
    // host-only choice and is left alone.
    //
    // The last condition keeps the suggested fix HONEST: it must name a scope
    // that would actually carry the cookie. Without it, `domain: "com"` on
    // www.domain.com suggested ".com" and `domain: "0.0.1"` on 127.0.0.1
    // suggested ".0.0.1". Measured, neither helps and they fail differently:
    // CDP STORES '.com' (dot dropped, host-only on the literal host "com", so it
    // is never sent anywhere), while '.0.0.1' is rejected as "Invalid cookie
    // fields". Requiring the domain to sit inside the target host's own
    // registrable domain excludes public suffixes and IP fragments, and still
    // catches every genuinely fixable case (including an intermediate
    // 'b.domain.com' under a.b.domain.com).
    const lowerDomain = domain.toLowerCase();
    if (targetHost && targetSite && !domain.startsWith('.') &&
        lowerDomain !== targetHost &&
        targetHost.endsWith(`.${lowerDomain}`) &&
        (lowerDomain === targetSite || lowerDomain.endsWith(`.${targetSite}`))) {
      out.errors.push(`cookie ${JSON.stringify(name)} has domain ${JSON.stringify(domain)} without a leading dot, which Chrome stores HOST-ONLY -- it will never be sent to ${targetHost}; write ${JSON.stringify('.' + domain)} for the whole site`);
    }

    const cookie = {
      name,
      value,
      domain,
      path: '/'
    };

    // A relative `path` is rejected by CDP -- and it used to take every OTHER
    // cookie in the same call with it (see applyCookies). '/' is also the only
    // path a load-time gate is ever read at, so fall back to it and say so
    // rather than drop the cookie the config asked for.
    if (typeof entry.path === 'string' && entry.path) {
      if (entry.path.startsWith('/')) {
        cookie.path = entry.path;
      } else {
        out.errors.push(`cookie ${JSON.stringify(name)} has path ${JSON.stringify(entry.path)}, which is not absolute; the browser rejects that outright -- using "/" instead`);
      }
    }

    // Strict === true, so anything else means false. Every other bad field here
    // is reported; these two used to coerce in silence, and `"secure": "true"`
    // -- a string, which is what a hand-edited JSON config tends to carry --
    // then produced a cookie that was quietly NOT secure.
    if (entry.httpOnly !== undefined) {
      if (typeof entry.httpOnly !== 'boolean') {
        out.errors.push(`cookie ${JSON.stringify(name)} has httpOnly ${JSON.stringify(entry.httpOnly)}, which is not a boolean (true/false, unquoted); treating it as false`);
      }
      cookie.httpOnly = entry.httpOnly === true;
    }
    if (entry.expires !== undefined) {
      const exp = Number(entry.expires);
      if (!Number.isFinite(exp)) {
        out.errors.push(`cookie ${JSON.stringify(name)} has a non-numeric 'expires'; ignoring it (session cookie)`);
      } else {
        // `expires` is SECONDS since the epoch, not milliseconds. Both mistakes
        // below are silent in the browser, which is the whole reason to warn:
        // a past expiry makes the cookie vanish with no error anywhere, and a
        // millisecond value only "works" because Chrome clamps it to its
        // 400-day cap -- not the expiry that was asked for.
        const nowSec = Math.floor(Date.now() / 1000);
        if (exp > EXPIRES_MILLIS_THRESHOLD) {
          out.errors.push(`cookie ${JSON.stringify(name)} has expires=${exp}, which looks like MILLISECONDS — 'expires' is seconds since the epoch (try Math.floor(Date.now()/1000)); the browser will clamp it`);
        } else if (exp <= nowSec) {
          out.errors.push(`cookie ${JSON.stringify(name)} has expires=${exp}, which is in the PAST — the browser discards it immediately, so this cookie will never be sent`);
        }
        cookie.expires = exp;
      }
    }

    // Flag typo'd / unsupported keys rather than dropping them silently.
    const unknown = Object.keys(entry).filter(k => !KNOWN_COOKIE_KEYS.includes(k));
    if (unknown.length > 0) {
      out.errors.push(`cookie ${JSON.stringify(name)} has unrecognised key(s) ${unknown.map(k => JSON.stringify(k)).join(', ')}; supported: ${KNOWN_COOKIE_KEYS.join(', ')}`);
    }

    if (entry.sameSite !== undefined) {
      // Accept any casing -- "lax" in a hand-written config is the common typo.
      const match = VALID_SAME_SITE.find(s => s.toLowerCase() === String(entry.sameSite).toLowerCase());
      if (match) cookie.sameSite = match;
      else out.errors.push(`cookie ${JSON.stringify(name)} has sameSite ${JSON.stringify(entry.sameSite)}; must be Strict, Lax or None -- ignoring it`);
    }

    if (entry.secure !== undefined && typeof entry.secure !== 'boolean') {
      out.errors.push(`cookie ${JSON.stringify(name)} has secure ${JSON.stringify(entry.secure)}, which is not a boolean (true/false, unquoted); treating it as false`);
    }
    cookie.secure = entry.secure === true;
    // Chrome REJECTS SameSite=None without Secure, and silently: the cookie
    // just never appears. Promote rather than hand back a cookie that cannot
    // exist.
    if (cookie.sameSite === 'None' && !cookie.secure) cookie.secure = true;

    out.cookies.push(cookie);
  }

  // A repeated name+domain+path is one cookie in the browser, so the later entry
  // silently won and the earlier one vanished with nothing said -- while
  // lib/storage.js has always warned about exactly this shape for storage keys.
  // Dedupe to match setCookie()'s own semantics (last wins) and report it, so a
  // config with two `consent` entries does not look like it set both.
  if (out.cookies.length > 1) {
    const byIdentity = new Map();
    for (const cookie of out.cookies) {
      const key = cookieKey(cookie);
      if (byIdentity.has(key)) {
        out.errors.push(`cookie ${JSON.stringify(cookie.name)} is declared more than once for domain ${JSON.stringify(cookie.domain)} path ${JSON.stringify(cookie.path)}; the last one wins`);
      }
      byIdentity.set(key, cookie);
    }
    out.cookies = [...byIdentity.values()];
  }

  return out;
}

/**
 * Apply normalized cookies to the page's browser context.
 * @param {object} page - Puppeteer page (not yet navigated)
 * @param {Array<object>} cookies - Output of normalizeCookies().cookies
 * @param {boolean} forceDebug - Verbose logging
 * @returns {Promise<{applied: number, error: string|null}>}
 */
async function applyCookies(page, cookies, forceDebug = false) {
  if (!Array.isArray(cookies) || cookies.length === 0) return { applied: 0, error: null };

  // Prefer the context-level API: page.setCookie is deprecated in puppeteer
  // 23+ and slated for removal. Fall back to it so a v24 lockfile still works.
  const context = typeof page.browserContext === 'function' ? page.browserContext() : null;
  const setSome = (batch) => (context && typeof context.setCookie === 'function')
    ? context.setCookie(...batch)
    : page.setCookie(...batch);

  try {
    await setSome(cookies);
    if (forceDebug) {
      const summary = cookies.map(c => `${c.name}@${c.domain}${c.path}`).join(', ');
      console.log(formatLogMessage('debug', `${COOKIES_TAG} Set ${cookies.length} cookie(s) before load: ${summary}`));
    }
    return { applied: cookies.length, error: null };
  } catch (err) {
    // CDP validates the WHOLE array and rejects all of it on one bad field:
    // measured, a single cookie with a relative path or a domain like '.0.0.1'
    // returned "Invalid cookie fields" and left the jar EMPTY -- every other
    // cookie in the config silently never existed, so the gate they were seeding
    // for was never satisfied and nothing said which entry was at fault.
    // Retry one at a time so one typo costs one cookie, and name the offender.
    const applied = [];
    const failed = [];
    for (const c of cookies) {
      try {
        await setSome([c]);
        applied.push(c);
      } catch (perCookieErr) {
        failed.push(`${c.name} (domain=${c.domain} path=${c.path}): ${perCookieErr.message}`);
      }
    }
    for (const f of failed) {
      console.log(formatLogMessage('warn', `${COOKIES_TAG} Browser rejected cookie ${f}`));
    }
    if (applied.length && forceDebug) {
      const summary = applied.map(c => `${c.name}@${c.domain}${c.path}`).join(', ');
      console.log(formatLogMessage('debug', `${COOKIES_TAG} Set ${applied.length} of ${cookies.length} cookie(s) before load: ${summary}`));
    }
    if (!applied.length) {
      // Nothing landed at all, and the per-cookie retries did not explain why.
      console.log(formatLogMessage('warn', `${COOKIES_TAG} Failed to set cookies: ${err.message}`));
    }
    return { applied: applied.length, error: failed.length ? failed.join('; ') : err.message };
  }
}

/**
 * Remove cookies previously seeded by applyCookies, so a site entry's cookies
 * do not outlive it.
 *
 * Cookies live on the shared browser context and nwss launches ONE browser per
 * run, so without this a later site on the SAME host silently inherits them --
 * measured: a second site declaring no cookies still received `consent=granted`
 * from the first. That can change what the page serves and therefore what the
 * scan captures, with nothing to indicate why.
 *
 * Deletes by name/domain/path, i.e. exactly the keys that were seeded. If the
 * page itself overwrote one of those values, that cookie goes too -- correct,
 * since the entry only exists because we introduced it.
 * @param {object} page - Puppeteer page
 * @param {Array<object>} cookies - The cookies previously applied
 * @param {boolean} forceDebug - Verbose logging
 * @returns {Promise<{removed: number}>}
 */
async function removeCookies(page, cookies, forceDebug = false) {
  if (!Array.isArray(cookies) || cookies.length === 0) return { removed: 0 };

  // Drop this URL's claim, and keep only the cookies nobody else still needs.
  const releasable = [];
  for (const c of cookies) {
    const k = cookieKey(c);
    const next = (_seedRefs.get(k) || 1) - 1;
    if (next <= 0) {
      _seedRefs.delete(k);
      releasable.push(c);
    } else {
      _seedRefs.set(k, next);
    }
  }
  if (releasable.length === 0) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${COOKIES_TAG} Kept ${cookies.length} seeded cookie(s): still in use by a concurrent URL`));
    }
    return { removed: 0 };
  }
  cookies = releasable;
  // Identity comes from cookieKey(), the same function the refcount uses. It was
  // a second copy of that expression until 2026-09-26: the two have to agree,
  // because one decides WHEN a cookie may be deleted and the other decides WHICH
  // cookie gets deleted, so any drift either strands cookies or deletes one a
  // concurrent URL still needs. The leading-dot leniency is explained there; it
  // can only ever reach cookies this run seeded, since `wanted` is built from our
  // own records.
  const wanted = new Set(cookies.map(cookieKey));

  try {
    const context = typeof page.browserContext === 'function' ? page.browserContext() : null;

    // context.deleteCookie() maps to Storage.setCookies and demands COMPLETE
    // Cookie objects -- passing a {name, domain, path} triple fails with
    // "mandatory field missing". So read the live cookies back and hand it the
    // real ones. page.deleteCookie() would accept the partial shape but is
    // deprecated in puppeteer 23+, so it is only the fallback.
    if (context && typeof context.cookies === 'function' && typeof context.deleteCookie === 'function') {
      const live = await context.cookies();
      // Re-check the refcount AFTER that round trip. The decrement above is
      // synchronous, but this delete is two CDP round trips later, and a URL that
      // started and seeded in that window has already claimed these keys again --
      // deleting now hands it a page with no cookie at all, which is the exact
      // failure the refcount exists to prevent.
      //
      // Measured by interleaving one URL's teardown with another's seed: the
      // newcomer SET the cookie, the leaver DELETEd it, and the newcomer then
      // navigated ungated. The reference-count test did not catch it because it
      // covers the safe shape -- both URLs retained before either released -- and
      // the dangerous one is the HANDOFF, where the last holder releases while a
      // replacement is still mid-seed. Reachable from --max-concurrent >= 2 when
      // two same-host URLs finish within a round trip of each other.
      //
      // retainSeeded() is synchronous, so any claim that lands before this check
      // is honoured; one landing between here and the CDP call is not, but that
      // window is a microtask rather than two round trips. The fallback below
      // needs no such check: nothing is awaited between the decrement and it.
      const candidates = (Array.isArray(live) ? live : []).filter(c => wanted.has(cookieKey(c)));
      // THE AUTHORITATIVE CHECK, and it has to be the last statement before the
      // call. Checking against the read above instead is not enough: over one
      // WebSocket the messages are processed in order, so the real interleaving
      // is getCookies -> the newcomer's setCookie -> deleteCookies, which means
      // the claim lands AFTER the read resolves and BEFORE the delete is sent.
      // Measured with the messages ordered that way: `SET -> SET -> C claimed ->
      // DELETE`, the newcomer claiming in good time and still losing its cookie.
      const toDelete = candidates.filter(c => !_seedRefs.has(cookieKey(c)));
      const reclaimed = candidates.length - toDelete.length;
      if (reclaimed > 0 && forceDebug) {
        console.log(formatLogMessage('debug', `${COOKIES_TAG} Kept ${reclaimed} seeded cookie(s): re-claimed by a URL that started during teardown`));
      }
      if (toDelete.length === 0) return { removed: 0 };
      await context.deleteCookie(...toDelete);
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${COOKIES_TAG} Removed ${toDelete.length} seeded cookie(s) after the URL finished`));
      }
      return { removed: toDelete.length };
    }

    if (typeof page.deleteCookie === 'function') {
      const targets = cookies.map(c => ({ name: c.name, domain: c.domain, path: c.path }));
      await page.deleteCookie(...targets);
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${COOKIES_TAG} Removed ${targets.length} seeded cookie(s) after the URL finished (page API)`));
      }
      return { removed: targets.length };
    }
    return { removed: 0 };
  } catch (err) {
    // Never fatal -- but not debug-only either. The refcount has already been
    // dropped, so nothing will retry: these cookies now outlive the entry and the
    // next site on this host inherits them, which changes what that page serves
    // and therefore what the scan captures. Measured with the cookie read forced
    // to fail: both seeded cookies stayed in the jar and a normal run printed
    // nothing at all. Same reasoning as lib/storage.js's teardown warning.
    console.log(formatLogMessage('warn', `${COOKIES_TAG} Could not remove ${cookies.length} seeded cookie(s) (${err.message}); a later URL on this host may inherit them`));
    return { removed: 0 };
  }
}

/**
 * Convenience wrapper: normalize + apply in one call, reporting config errors.
 * @param {object} page - Puppeteer page (not yet navigated)
 * @param {object} siteConfig - Site config carrying an optional `cookies` key
 * @param {string} targetUrl - URL about to be loaded
 * @param {boolean} forceDebug - Verbose logging
 * @param {boolean} reportErrors - Log config problems (pass false on re-seeds so
 *   a bad cookie is not reported once per reload)
 * @param {boolean} retain - Claim these cookies for this URL (retainSeeded) BEFORE
 *   applying them. Pass true on a URL's initial seed and false on a per-reload
 *   re-seed. Done here rather than by the caller because the claim has to be
 *   registered ahead of the browser round trip -- see retainSeeded().
 * @returns {Promise<{applied: number, errors: Array<string>, cookies: Array<object>}>}
 *   `cookies` is the NORMALIZED list, for passing to retainSeeded() and
 *   removeCookies() later -- NOT filtered by what the browser accepted. On the
 *   per-cookie retry path a rejected entry is still listed, so `applied` can be
 *   lower than `cookies.length`. Deliberate: retain and release then see the
 *   same list and stay symmetric, and a cookie that never landed simply matches
 *   nothing at teardown.
 */
async function applySiteCookies(page, siteConfig, targetUrl, forceDebug = false, reportErrors = true, retain = false) {
  const raw = siteConfig && siteConfig.cookies;
  if (raw === undefined || raw === null) return { applied: 0, errors: [], cookies: [] };

  const { cookies, errors } = normalizeCookies(raw, targetUrl);
  if (reportErrors) {
    for (const e of errors) {
      console.log(formatLogMessage('warn', `${COOKIES_TAG} ${targetUrl}: ${e}`));
    }
  }
  // Before the browser call, deliberately: a teardown already in flight makes
  // its keep-or-delete decision from the jar read it has outstanding, which
  // resolves before our setCookie does.
  if (retain) retainSeeded(cookies);
  const { applied } = await applyCookies(page, cookies, forceDebug);
  return { applied, errors, cookies };
}

module.exports = {
  normalizeCookies,
  applyCookies,
  retainSeeded,
  removeCookies,
  applySiteCookies
};
