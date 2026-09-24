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
 *   - the match is on HOSTNAME, not origin. An http -> https upgrade (or a port
 *     change) is a different origin but the same site, and it is the routine
 *     case: measured, an origin match made a target that 302s elsewhere read
 *     back null because the seed never applied. Cookies are not scheme-scoped
 *     either, so this also keeps the two features consistent. Teardown
 *     therefore clears both the configured origin and the one the page landed
 *     on.
 */

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
// hostname + name. localStorage persists in the userDataDir for the whole run,
// so -- exactly as for cookies -- a URL that finishes early must not delete a
// key a concurrent same-host URL is still using. Keyed on hostname rather than
// full origin to match the seeding guard below, which deliberately ignores
// scheme and port.
//
// sessionStorage is deliberately absent: it is scoped to the browsing context,
// each URL gets its own page, and it dies when that page closes. Nothing to
// refcount and nothing to tear down.
const _seedRefs = new Map();

/** Refcount identity for a seeded localStorage entry. */
function storageRefKey(host, name) {
  return `${String(host || '').toLowerCase()}\u0000${name}`;
}

/**
 * Record that one URL is relying on these seeded localStorage entries. Call
 * ONCE per URL, after the initial seed.
 * @param {string} host - Hostname the entries were seeded on
 * @param {Array<object>} items - Entries that were applied
 * @returns {void}
 */
function retainSeeded(host, items) {
  if (!host || !Array.isArray(items)) return;
  for (const it of items) {
    const k = storageRefKey(host, it.name);
    _seedRefs.set(k, (_seedRefs.get(k) || 0) + 1);
  }
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
 * @param {string} host - Only write in the main document of this hostname
 * @param {boolean} forceDebug - Verbose logging
 * @returns {Promise<{applied: number, error: string|null}>}
 */
async function applyStorage(page, items, area, host, forceDebug = false) {
  if (!Array.isArray(items) || items.length === 0) return { applied: 0, error: null };
  if (!host) return { applied: 0, error: 'no hostname could be derived from the URL' };

  try {
    await page.evaluateOnNewDocument((payload) => {
      try {
        // Main document only. Child frames run this too, and writing there would
        // put the entries on the frame's own origin -- for a cross-origin ad
        // frame, a completely unrelated one. Restricting to the top document
        // loses nothing: a same-origin subframe shares the top document's
        // storage area anyway.
        if (window !== window.top) return;
        // Matched on hostname, NOT origin: an http -> https upgrade (or a port
        // change) is a different origin but the same site, and it is the routine
        // case -- measured, a target that 302s to another origin saw the seed
        // skipped entirely and read null. Cookies are not scheme-scoped either,
        // so this also keeps the two features consistent.
        if (window.location.hostname !== payload.host) return;
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
    }, { area, host, items });

    if (forceDebug) {
      const summary = items.map(i => i.name).join(', ');
      console.log(formatLogMessage('debug', `${STORAGE_TAG} Seeding ${items.length} ${area}Storage item(s) on every document for ${host}: ${summary}`));
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
  const host = scope && scope.host;
  if (!Array.isArray(items) || items.length === 0 || !host) return { removed: 0 };

  // Drop this URL's claim FIRST, unconditionally. The removal below is
  // best-effort -- the page may already be gone -- but the refcount must fall
  // either way, or the key stays retained forever and no later URL on this host
  // can ever release it.
  const releasable = [];
  for (const it of items) {
    const k = storageRefKey(host, it.name);
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

  // Candidate origins. The seeding guard matches on hostname, so the entries may
  // live on an origin the config never named: an http -> https upgrade or a port
  // change is the same host but a different storage area. Clear the origin the
  // config implied AND the one the page actually ended on.
  const origins = new Set();
  if (scope.origin) origins.add(scope.origin);
  try {
    const finalUrl = typeof page.url === 'function' ? page.url() : null;
    if (finalUrl) {
      const u = new URL(finalUrl);
      if (u.hostname === host) origins.add(u.origin);
    }
  } catch (_) {
    // Unparseable current URL (about:blank after a crash); the configured origin
    // is still worth clearing.
  }

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
          if (window.location.hostname !== payload.host) return 0;
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
      }, { host, names: releasable.map(i => i.name) });
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
  try {
    const parsed = new URL(targetUrl);
    origin = parsed.origin;
    host = parsed.hostname || null;
  } catch (_) {
    // Unparseable target: nothing can be scoped, so report and do nothing
    // rather than write onto whatever origin happens to load.
  }
  // "null" is what an opaque origin (data:, sandboxed) serialises to; seeding
  // against it would match every opaque document.
  if (!origin || origin === 'null' || !host) {
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
  if (local.items.length) applied += (await applyStorage(page, local.items, 'local', host, forceDebug)).applied;
  if (session.items.length) applied += (await applyStorage(page, session.items, 'session', host, forceDebug)).applied;

  return { applied, errors, localItems: local.items, scope: { host, origin } };
}

module.exports = {
  normalizeStorageItems,
  applyStorage,
  retainSeeded,
  removeStorage,
  applySiteStorage
};
