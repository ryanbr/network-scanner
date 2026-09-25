/**
 * localStorage / sessionStorage pre-seeding — set storage entries BEFORE a URL loads.
 *
 * The sibling of lib/cookies.js, for sites that gate on Web Storage rather than
 * a cookie: "terms accepted" flags, consent state written by a CMP, A/B buckets,
 * `visited` markers that suppress an interstitial. Those are read by inline
 * scripts during the first document, so writing them after navigation is too
 * late — the gate has already decided.
 *
 * Config (per site, in the JSON config):
 *
 *   Short form -- name/value pairs:
 *     "local_storage":   { "rta_terms_accepted": true, "theme": "dark" }
 *     "session_storage": { "seen_interstitial": 1 }
 *
 *   Long form -- an array, for keys that are awkward as JSON object keys:
 *     "local_storage": [ { "name": "consent", "value": "granted" } ]
 *
 * Values are stringified the way Web Storage requires: numbers and booleans via
 * String(), and objects/arrays via JSON.stringify -- storing a JSON blob under
 * one key is the common shape for consent state, so `{"cmp":{"ok":true}}` does
 * the useful thing instead of writing "[object Object]".
 *
 * MECHANISM -- why this is not just a setItem() call:
 * Web Storage is origin-scoped and only reachable from a document on that
 * origin, so unlike a cookie it cannot be planted on the browser context before
 * navigating. Seeding therefore uses page.evaluateOnNewDocument(), which runs
 * before any of the page's own scripts on EVERY document the page creates. Two
 * consequences worth knowing:
 *   - reload / forcereload need no re-seeding. The injected script re-runs on
 *     each new document, so the values are back before page scripts execute,
 *     even when clear_sitedata wiped storage in between.
 *   - it runs in child frames too, so the injected code writes only in the TOP
 *     document. Without that guard a cross-origin ad iframe would get the
 *     entries written into ITS origin; restricting to the top document costs
 *     nothing, since a same-origin subframe shares that storage area anyway.
 *   - the match is on the SITE (registrable domain, via psl), not the origin or
 *     the exact hostname. An http -> https upgrade, a port change and a redirect
 *     to another subdomain are all a different origin but the same site, and all
 *     three are routine: measured, stricter matching made a target that 302s
 *     elsewhere read back null because the seed never applied. A redirect
 *     to a different registrable domain is still refused. Because the landed
 *     origin therefore varies per URL, teardown clears every origin the site's
 *     URLs were seen on, not just the one the config named.
 */

const net = require('node:net');
const psl = require('psl');
const { formatLogMessage, messageColors } = require('./colorize');

const STORAGE_TAG = messageColors.processing('[storage]');

// Recognised per-entry keys in the long form. Anything else is a typo (`key`,
// `val`, `Name`) that would otherwise be dropped in silence, leaving storage
// without the entry the config asked for.
const KNOWN_ITEM_KEYS = Object.freeze(['name', 'value']);

// Chrome's per-origin Web Storage quota is ~5MB, and setItem() throws
// QuotaExceededError inside the page where nothing surfaces it. Warn well below
// the ceiling rather than let one oversized value silently drop the whole write.
const LARGE_VALUE_CHARS = 1000000;

// How many in-flight URLs rely on each seeded localStorage key, keyed by
// site + name. localStorage persists in the userDataDir for the whole run, so --
// exactly as for cookies -- a URL that finishes early must not delete a key a
// concurrent URL of the same site is still using. Keyed on the site rather than
// the full origin to match the seeding guard below, which deliberately ignores
// scheme, port and subdomain.
//
// sessionStorage is deliberately absent: it is scoped to the browsing context,
// each URL gets its own page, and it dies when that page closes. Nothing to
// refcount and nothing to tear down.
const _seedRefs = new Map();

// Every origin a site's entries may have been written to, keyed by site. The
// guard accepts any subdomain of the site, so the origin the entries LANDED on
// can differ per URL (domain.com -> www.domain.com for one, -> m.domain.com for
// another). Teardown only fires for the URL that drops the last reference, so
// without accumulating them here that URL would clear its own origin and leave
// every other one behind.
const _seedOrigins = new Map();

/** Refcount identity for a seeded localStorage entry. */
function storageRefKey(site, name) {
  return `${String(site || '').toLowerCase()}\u0000${name}`;
}

/**
 * The scope a seed applies to: the registrable domain (eTLD+1), so a redirect
 * between subdomains of the same site keeps the seed. Matching the exact
 * hostname was measured losing it outright -- a target that redirects to another
 * host read the key back as null -- and `domain.com` -> `www.domain.com` is a
 * routine shape.
 *
 * NOTE this is WIDER than a seeded cookie's default scope, which the sibling
 * module leaves host-only. Measured on an apex -> www redirect: all storage
 * entries survived and every short-form cookie was dropped. A cookie needs an
 * explicit leading-dot `domain` in the long form to match this breadth.
 * @param {string} hostname - Hostname from the target URL
 * @returns {string|null} Registrable domain, or the hostname when there is none
 */
function siteScope(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return null;
  // IP literals first: psl treats them as domains and returns nonsense --
  // psl.get('127.0.0.1') is '0.1', and '10.0.0.1'.endsWith('.0.1') is true, so a
  // registrable-domain match would silently span unrelated hosts. Exact only.
  if (net.isIP(h)) return h;
  let site = null;
  try {
    site = psl.get(h);
  } catch (_) {
    // Malformed host; fall back to the exact match below.
  }
  // null for single-label hosts (localhost) and unrecognised suffixes.
  if (!site) return h;
  // Never widen past the hostname itself, whatever psl returned.
  if (site !== h && !h.endsWith(`.${site}`)) return h;
  return site;
}

/**
 * Record that one URL is relying on these seeded localStorage entries. Call
 * ONCE per URL, after the initial seed.
 * @param {string} site - Site (registrable domain) the entries were seeded on
 * @param {Array<object>} items - Entries that were applied
 * @param {string} [origin] - Origin the config named, recorded for teardown
 * @returns {void}
 */
function retainSeeded(site, items, origin) {
  if (!site || !Array.isArray(items)) return;
  for (const it of items) {
    const k = storageRefKey(site, it.name);
    _seedRefs.set(k, (_seedRefs.get(k) || 0) + 1);
  }
  if (origin) rememberOrigin(site, origin);
}

/** Record an origin this site's entries may live on. */
function rememberOrigin(site, origin) {
  if (!site || !origin) return;
  const key = String(site).toLowerCase();
  if (!_seedOrigins.has(key)) _seedOrigins.set(key, new Set());
  _seedOrigins.get(key).add(origin);
}

/** True while any key for this site is still retained. */
function siteStillReferenced(site) {
  const prefix = `${String(site).toLowerCase()}\u0000`;
  for (const k of _seedRefs.keys()) if (k.startsWith(prefix)) return true;
  return false;
}

/**
 * Coerce a config value into the string Web Storage stores.
 * @param {*} raw - Value straight out of the JSON config
 * @returns {{value: string}|{error: string}}
 */
function toStorageValue(raw) {
  // undefined/null become '' rather than the literal text "undefined", matching
  // how lib/cookies.js treats a valueless entry.
  if (raw === undefined || raw === null) return { value: '' };
  if (typeof raw === 'string') return { value: raw };
  if (typeof raw === 'number' || typeof raw === 'boolean') return { value: String(raw) };
  if (typeof raw === 'object') {
    try {
      const json = JSON.stringify(raw);
      if (typeof json !== 'string') return { error: 'value could not be serialised to JSON' };
      return { value: json };
    } catch (err) {
      return { error: `value could not be serialised to JSON (${err.message})` };
    }
  }
  return { value: String(raw) };
}

/**
 * Normalize a site's `local_storage` / `session_storage` config into
 * {name, value} pairs. Never throws: invalid entries are dropped and reported,
 * so one bad entry cannot abort a scan.
 * @param {object|Array|null|undefined} raw - siteConfig.local_storage or .session_storage
 * @param {string} optionName - Config key name, for error messages
 * @returns {{items: Array<{name: string, value: string}>, errors: Array<string>}}
 */
function normalizeStorageItems(raw, optionName = 'local_storage') {
  const out = { items: [], errors: [] };
  if (raw === undefined || raw === null) return out;

  let entries;
  if (Array.isArray(raw)) {
    entries = raw;
  } else if (typeof raw === 'object') {
    // Short form: { name: value } -> [{ name, value }]
    entries = Object.entries(raw).map(([name, value]) => ({ name, value }));
  } else {
    out.errors.push(`'${optionName}' must be an object or an array, got ${typeof raw}`);
    return out;
  }

  const seen = new Set();
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      out.errors.push(`${optionName} entry must be an object, got ${Array.isArray(entry) ? 'array' : typeof entry}`);
      continue;
    }

    const name = entry.name;
    if (typeof name !== 'string' || name.length === 0) {
      out.errors.push(`${optionName} entry is missing a string 'name'`);
      continue;
    }

    const converted = toStorageValue(entry.value);
    if (converted.error) {
      out.errors.push(`${optionName} ${JSON.stringify(name)}: ${converted.error}`);
      continue;
    }
    const value = converted.value;

    if (value.length > LARGE_VALUE_CHARS) {
      out.errors.push(`${optionName} ${JSON.stringify(name)} has a ${value.length}-character value; the ~5MB per-origin quota may reject it and setItem() fails silently inside the page`);
    }

    // A duplicate name in the long form would have the later entry win with no
    // indication the earlier one was discarded. The short form cannot collide:
    // JSON object keys are already unique.
    if (seen.has(name)) {
      out.errors.push(`${optionName} has a duplicate 'name' ${JSON.stringify(name)}; the last one wins`);
    }
    seen.add(name);

    const unknown = Object.keys(entry).filter(k => !KNOWN_ITEM_KEYS.includes(k));
    if (unknown.length > 0) {
      out.errors.push(`${optionName} ${JSON.stringify(name)} has unrecognised key(s) ${unknown.map(k => JSON.stringify(k)).join(', ')}; supported: ${KNOWN_ITEM_KEYS.join(', ')}`);
    }

    out.items.push({ name, value });
  }

  // Later duplicates win, matching setItem() semantics.
  if (seen.size !== out.items.length) {
    const deduped = new Map();
    for (const it of out.items) deduped.set(it.name, it);
    out.items = [...deduped.values()];
  }

  return out;
}

/**
 * Install the seeding script for one storage area. Runs before the page's own
 * scripts on every document, including reloads.
 * @param {object} page - Puppeteer page (not yet navigated)
 * @param {Array<object>} items - Output of normalizeStorageItems().items
 * @param {'local'|'session'} area - Which storage area to write
 * @param {string} site - Only write in the main document of this site (eTLD+1)
 * @param {boolean} forceDebug - Verbose logging
 * @returns {Promise<{applied: number, error: string|null}>}
 */
async function applyStorage(page, items, area, site, forceDebug = false) {
  if (!Array.isArray(items) || items.length === 0) return { applied: 0, error: null };
  if (!site) return { applied: 0, error: 'no site could be derived from the URL' };

  try {
    await page.evaluateOnNewDocument((payload) => {
      try {
        // Main document only. Child frames run this too, and writing there would
        // put the entries on the frame's own origin -- for a cross-origin ad
        // frame, a completely unrelated one. Restricting to the top document
        // loses nothing: a same-origin subframe shares the top document's
        // storage area anyway.
        if (window !== window.top) return;
        // Matched on the SITE (registrable domain), not the origin or the exact
        // hostname. An http -> https upgrade, a port change or a redirect to
        // another subdomain is a different origin but the same site, and all
        // three are routine -- measured, stricter matching saw the seed skipped
        // entirely and the page read null. `payload.site` is already an eTLD+1
        // computed with psl, so the suffix test cannot reach into a neighbouring
        // registrable domain: for site "domain.com", "evil-domain.com" fails
        // while "abc.xyz.domain.com" passes. This is the breadth a leading-dot
        // ".domain.com" cookie has -- wider than the host-only cookie the
        // sibling module seeds by default.
        var docHost = String(window.location.hostname || '').toLowerCase();
        if (docHost !== payload.site &&
            !(docHost.length > payload.site.length && docHost.endsWith('.' + payload.site))) return;
        const store = payload.area === 'session' ? window.sessionStorage : window.localStorage;
        if (!store) return;
        for (const item of payload.items) {
          // Per-key try/catch: one QuotaExceededError must not stop the rest.
          try { store.setItem(item.name, item.value); } catch (_) {}
        }
      } catch (_) {
        // Storage access throws outright when it is disabled for the origin
        // (third-party data blocked, opaque origin). Nothing to do but let the
        // page load without the seed.
      }
    }, { area, site, items });

    if (forceDebug) {
      const summary = items.map(i => i.name).join(', ');
      console.log(formatLogMessage('debug', `${STORAGE_TAG} Seeding ${items.length} ${area}Storage item(s) on every document for ${site} (and its subdomains): ${summary}`));
    }
    return { applied: items.length, error: null };
  } catch (err) {
    // A failed injection must not kill the scan -- the page still loads, just
    // without the gate satisfied, which shows up in the results.
    console.log(formatLogMessage('warn', `${STORAGE_TAG} Failed to seed ${area}Storage: ${err.message}`));
    return { applied: 0, error: err.message };
  }
}

/**
 * Remove localStorage entries previously seeded by applyStorage, so a site
 * entry's storage does not outlive it.
 *
 * Same reasoning as removeCookies(): one browser serves the whole run with no
 * per-site context, so a key left behind is silently inherited by any LATER
 * site on the same host that never asked for it, changing what that page serves
 * and therefore what the scan captures.
 *
 * Removal goes through CDP with an explicit origin rather than page.evaluate,
 * because by teardown time the page has often navigated elsewhere. An in-page
 * eval would then be running on the wrong document and its own guard would skip
 * it, stranding the keys.
 * @param {object} page - Puppeteer page
 * @param {Array<object>} items - The entries previously applied
 * @param {{host: string, origin: string}} scope - Where they were seeded
 * @param {boolean} forceDebug - Verbose logging
 * @returns {Promise<{removed: number}>}
 */
async function removeStorage(page, items, scope, forceDebug = false) {
  const site = scope && scope.site;
  if (!Array.isArray(items) || items.length === 0 || !site) return { removed: 0 };

  // Record where this URL actually ended up BEFORE releasing the refcount: if
  // this is not the last URL holding these keys, the one that eventually clears
  // them still has to know about this origin.
  if (scope.origin) rememberOrigin(site, scope.origin);
  try {
    const finalUrl = typeof page.url === 'function' ? page.url() : null;
    if (finalUrl) {
      const u = new URL(finalUrl);
      const h = u.hostname.toLowerCase();
      if (h === site || h.endsWith(`.${site}`)) rememberOrigin(site, u.origin);
    }
  } catch (_) {
    // Unparseable current URL (about:blank after a crash); the configured origin
    // is still recorded above.
  }

  // Drop this URL's claim, unconditionally. The removal below is best-effort --
  // the page may already be gone -- but the refcount must fall either way, or
  // the key stays retained forever and no later URL on this site can release it.
  const releasable = [];
  for (const it of items) {
    const k = storageRefKey(site, it.name);
    const next = (_seedRefs.get(k) || 1) - 1;
    if (next <= 0) {
      _seedRefs.delete(k);
      releasable.push(it);
    } else {
      _seedRefs.set(k, next);
    }
  }
  if (releasable.length === 0) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${STORAGE_TAG} Kept ${items.length} seeded localStorage item(s): still in use by a concurrent URL`));
    }
    return { removed: 0 };
  }

  // Every origin this site's entries could have landed on -- the config's own,
  // plus whatever each URL of the site actually resolved to. The guard accepts
  // any subdomain, so clearing only this URL's origin would leave a sibling
  // subdomain's copy behind.
  const origins = new Set(_seedOrigins.get(String(site).toLowerCase()) || []);

  let session = null;
  try {
    session = await page.target().createCDPSession();
    // Count KEYS cleared, not calls: with two candidate origins a per-call
    // tally would double-report.
    const cleared = new Set();
    for (const origin of origins) {
      const storageId = { securityOrigin: origin, isLocalStorage: true };
      for (const it of releasable) {
        try {
          await session.send('DOMStorage.removeDOMStorageItem', { storageId, key: it.name });
          cleared.add(it.name);
        } catch (_) {
          // No storage area for that origin (navigation failed, or the upgrade
          // origin was never actually visited). Not there to leak; keep going.
        }
      }
    }
    if (forceDebug && cleared.size > 0) {
      console.log(formatLogMessage('debug', `${STORAGE_TAG} Cleared ${cleared.size} seeded localStorage key(s) on ${origins.size} origin(s) after the URL finished`));
    }
    return { removed: cleared.size };
  } catch (err) {
    // Teardown only: an in-page removal is better than leaving the keys, and the
    // hostname guard keeps it from clearing an unrelated site's storage.
    try {
      const removed = await page.evaluate((payload) => {
        try {
          var docHost = String(window.location.hostname || '').toLowerCase();
          if (docHost !== payload.site && !docHost.endsWith('.' + payload.site)) return 0;
          let n = 0;
          for (const name of payload.names) {
            try {
              if (window.localStorage.getItem(name) !== null) {
                window.localStorage.removeItem(name);
                n++;
              }
            } catch (_) {}
          }
          return n;
        } catch (_) { return 0; }
      }, { site, names: releasable.map(i => i.name) });
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${STORAGE_TAG} Removed ${removed} seeded localStorage item(s) via in-page fallback (CDP: ${err.message})`));
      }
      return { removed: removed || 0 };
    } catch (_) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${STORAGE_TAG} Could not remove seeded localStorage items: ${err.message}`));
      }
      return { removed: 0 };
    }
  } finally {
    if (session) { try { await session.detach(); } catch (_) {} }
    // Last holder for this site has gone: stop tracking its origins so a long
    // run does not accumulate a set per site visited.
    if (!siteStillReferenced(site)) _seedOrigins.delete(String(site).toLowerCase());
  }
}

/**
 * Convenience wrapper: normalize + install both storage areas in one call.
 * @param {object} page - Puppeteer page (not yet navigated)
 * @param {object} siteConfig - Site config carrying optional `local_storage` / `session_storage`
 * @param {string} targetUrl - URL about to be loaded (supplies the origin)
 * @param {boolean} forceDebug - Verbose logging
 * @param {boolean} reportErrors - Log config problems (pass false on re-seeds)
 * @returns {Promise<{applied: number, errors: Array<string>, localItems: Array<object>, scope: object|null}>}
 *   `localItems` + `scope` are what removeStorage() needs later; sessionStorage
 *   needs no teardown because it dies with the page.
 */
async function applySiteStorage(page, siteConfig, targetUrl, forceDebug = false, reportErrors = true) {
  const rawLocal = siteConfig && siteConfig.local_storage;
  const rawSession = siteConfig && siteConfig.session_storage;
  const empty = { applied: 0, errors: [], localItems: [], scope: null };
  if ((rawLocal === undefined || rawLocal === null) && (rawSession === undefined || rawSession === null)) {
    return empty;
  }

  let origin = null;
  let host = null;
  let site = null;
  try {
    const parsed = new URL(targetUrl);
    origin = parsed.origin;
    host = parsed.hostname || null;
    site = siteScope(host);
  } catch (_) {
    // Unparseable target: nothing can be scoped, so report and do nothing
    // rather than write onto whatever origin happens to load.
  }
  // "null" is what an opaque origin (data:, sandboxed) serialises to; seeding
  // against it would match every opaque document.
  if (!origin || origin === 'null' || !host || !site) {
    const msg = `cannot derive an origin from ${JSON.stringify(String(targetUrl))}; local_storage/session_storage skipped`;
    if (reportErrors) console.log(formatLogMessage('warn', `${STORAGE_TAG} ${msg}`));
    return { ...empty, errors: [msg] };
  }

  const local = normalizeStorageItems(rawLocal, 'local_storage');
  const session = normalizeStorageItems(rawSession, 'session_storage');
  const errors = [...local.errors, ...session.errors];
  if (reportErrors) {
    for (const e of errors) {
      console.log(formatLogMessage('warn', `${STORAGE_TAG} ${targetUrl}: ${e}`));
    }
  }

  let applied = 0;
  if (local.items.length) applied += (await applyStorage(page, local.items, 'local', site, forceDebug)).applied;
  if (session.items.length) applied += (await applyStorage(page, session.items, 'session', site, forceDebug)).applied;

  return { applied, errors, localItems: local.items, scope: { site, host, origin } };
}

module.exports = {
  siteScope,
  normalizeStorageItems,
  applyStorage,
  retainSeeded,
  removeStorage,
  applySiteStorage
};
