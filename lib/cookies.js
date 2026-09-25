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
 * Record that one URL is relying on these seeded cookies. Call ONCE per URL,
 * after the initial seed -- not on the per-reload re-seed, which would inflate
 * the count and leave the cookie behind forever.
 * @param {Array<object>} cookies - Cookies that were applied
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

    if (entry.httpOnly !== undefined) cookie.httpOnly = entry.httpOnly === true;
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

    cookie.secure = entry.secure === true;
    // Chrome REJECTS SameSite=None without Secure, and silently: the cookie
    // just never appears. Promote rather than hand back a cookie that cannot
    // exist.
    if (cookie.sameSite === 'None' && !cookie.secure) cookie.secure = true;

    out.cookies.push(cookie);
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
  // Match on name + path + domain, treating a leading '.' as equivalent -- the
  // same leniency as cookieKey(), and for the same reason. It can only ever
  // reach cookies this run seeded, since `wanted` is built from our own records.
  // Defensive too: nothing here has to assume Chrome echoes the domain back in
  // the exact form it was sent.
  const bare = d => String(d || '').replace(/^\./, '').toLowerCase();
  const wanted = new Set(cookies.map(c => `${c.name}\u0000${bare(c.domain)}\u0000${c.path || '/'}`));

  try {
    const context = typeof page.browserContext === 'function' ? page.browserContext() : null;

    // context.deleteCookie() maps to Storage.setCookies and demands COMPLETE
    // Cookie objects -- passing a {name, domain, path} triple fails with
    // "mandatory field missing". So read the live cookies back and hand it the
    // real ones. page.deleteCookie() would accept the partial shape but is
    // deprecated in puppeteer 23+, so it is only the fallback.
    if (context && typeof context.cookies === 'function' && typeof context.deleteCookie === 'function') {
      const live = await context.cookies();
      const toDelete = (Array.isArray(live) ? live : []).filter(c =>
        wanted.has(`${c.name}\u0000${bare(c.domain)}\u0000${c.path || '/'}`));
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
    // Teardown only -- a failure here leaves a cookie behind for later sites on
    // the same host, which is the pre-existing behaviour, so never fatal.
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${COOKIES_TAG} Could not remove seeded cookies: ${err.message}`));
    }
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
 * @returns {Promise<{applied: number, errors: Array<string>, cookies: Array<object>}>}
 *   `cookies` is what was actually set, for passing to removeCookies() later.
 */
async function applySiteCookies(page, siteConfig, targetUrl, forceDebug = false, reportErrors = true) {
  const raw = siteConfig && siteConfig.cookies;
  if (raw === undefined || raw === null) return { applied: 0, errors: [], cookies: [] };

  const { cookies, errors } = normalizeCookies(raw, targetUrl);
  if (reportErrors) {
    for (const e of errors) {
      console.log(formatLogMessage('warn', `${COOKIES_TAG} ${targetUrl}: ${e}`));
    }
  }
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
