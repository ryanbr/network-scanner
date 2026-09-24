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
 *   Short form -- name/value pairs, scoped to the site's own host:
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
 */

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

  // Default scope: the target URL's host, site-wide. Deliberately NOT puppeteer's
  // `url` field -- that derives the path from the URL, so a cookie seeded from
  // https://site/a/b would only be visible under /a, which is never what a
  // load-time gate wants.
  let defaultDomain = null;
  try {
    defaultDomain = new URL(targetUrl).hostname || null;
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

    const cookie = {
      name,
      value,
      domain,
      path: typeof entry.path === 'string' && entry.path ? entry.path : '/'
    };

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

  try {
    // Prefer the context-level API: page.setCookie is deprecated in puppeteer
    // 23+ and slated for removal. Fall back to it so a v24 lockfile still works.
    const context = typeof page.browserContext === 'function' ? page.browserContext() : null;
    if (context && typeof context.setCookie === 'function') {
      await context.setCookie(...cookies);
    } else {
      await page.setCookie(...cookies);
    }

    if (forceDebug) {
      const summary = cookies.map(c => `${c.name}@${c.domain}${c.path}`).join(', ');
      console.log(formatLogMessage('debug', `${COOKIES_TAG} Set ${cookies.length} cookie(s) before load: ${summary}`));
    }
    return { applied: cookies.length, error: null };
  } catch (err) {
    // A rejected cookie must not kill the scan -- the page still loads, just
    // without the gate satisfied, which is visible in the results.
    console.log(formatLogMessage('warn', `${COOKIES_TAG} Failed to set cookies: ${err.message}`));
    return { applied: 0, error: err.message };
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
 * @returns {Promise<{applied: number, errors: Array<string>}>}
 */
async function applySiteCookies(page, siteConfig, targetUrl, forceDebug = false, reportErrors = true) {
  const raw = siteConfig && siteConfig.cookies;
  if (raw === undefined || raw === null) return { applied: 0, errors: [] };

  const { cookies, errors } = normalizeCookies(raw, targetUrl);
  if (reportErrors) {
    for (const e of errors) {
      console.log(formatLogMessage('warn', `${COOKIES_TAG} ${targetUrl}: ${e}`));
    }
  }
  const { applied } = await applyCookies(page, cookies, forceDebug);
  return { applied, errors };
}

module.exports = {
  normalizeCookies,
  applyCookies,
  applySiteCookies
};
