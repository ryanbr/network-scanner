// === Clear Site Data Module ===
// Handles comprehensive site data clearing via CDP and page-level fallbacks
// Resolves SecurityError issues with localStorage/sessionStorage access

const { formatLogMessage, messageColors } = require('./colorize');
// The cookie refcount lives in lib/cookies.js; the clear has to honour the same
// claims teardown does, or it deletes a cookie a concurrent URL is relying on.
const { isSeedClaimed } = require('./cookies');
const CLEAR_SITEDATA_TAG = messageColors.processing('[clear_sitedata]');

/**
 * Clears site data using CDP (bypasses same-origin restrictions)
 * @param {Page} page - Puppeteer page instance
 * @param {string} currentUrl - URL being processed
 * @param {boolean} forceDebug - Debug logging flag
 * @param {boolean} quickMode - If true, skip the HEAVY storage types
 *   (IndexedDB, WebSQL, service workers) and the page-level fallback. Still
 *   clears cookies + cache + localStorage + sessionStorage, which are the
 *   four storage layers where session-cap tracking actually lives for
 *   ad/popunder networks. Used between reloads where full storage wipes
 *   would add unwanted latency on every cycle.
 * @returns {Promise<{success: boolean, operations: string[]}>}
 */
async function clearSiteDataViaCDP(page, currentUrl, forceDebug, quickMode = false) {
  let clearDataSession = null;
  // Hoisted outside the try so the catch-block orphan-cleanup branch can
  // reference it — same pattern as cdp.js (commit 0772ccd). Promise.race
  // cannot cancel the underlying createCDPSession() call; if the 10s timer
  // wins, the original promise may still resolve to a real session that
  // nothing references → orphan on the browser side.
  let sessionPromise = null;
  const completedOperations = [];

  try {
    // Capture the timeout-timer ID so we can clear it once the race
    // resolves. Previously the setTimeout fired 10s after the success
    // path completed — reject was swallowed (race already settled)
    // but the timer kept the event loop reference for up to 10s.
    let timeoutTimer;
    sessionPromise = page.target().createCDPSession();
    const timeoutPromise = new Promise((_, reject) => {
      timeoutTimer = setTimeout(() => reject(new Error('CDP session timeout')), 10000);
      if (typeof timeoutTimer.unref === 'function') timeoutTimer.unref();
    });
    try {
      clearDataSession = await Promise.race([sessionPromise, timeoutPromise]);
    } finally {
      clearTimeout(timeoutTimer);
    }
    
    const origin = new URL(currentUrl).origin;
    
    // Always-on quick-mode batch: cookies + cache + localStorage + sessionStorage.
    // All four are independent CDP methods touching different Chromium
    // subsystems (Network domain vs Storage domain, distinct storage types) —
    // no ordering dependency, no shared mutex. Previously these ran as 4
    // sequential `await session.send(...)` calls, burning 3 microtask-roundtrips
    // of pure wait time per site load; Promise.all collapses them to one
    // slowest-of-four wait (~5-15ms saved per site load with clear_sitedata).
    //
    // localStorage/sessionStorage MUST stay in this always-on batch — they're
    // (sessionStorage via the page, not CDP; see the batch entry below)
    // where AdsCore-family popunder networks track per-session caps
    // (aclibSubKey-popunder etc.; see commit 11e1f49). Skipping them in quick
    // mode capped popunder discovery at ~1 capture per scan.
    //
    // Heavier storage types (IndexedDB, WebSQL, service workers) still gate
    // on !quickMode below.
    const parallelOps = [
      // Deletes every cookie EXCEPT the ones an in-flight URL has seeded and
      // claimed. `Network.clearBrowserCookies` is browser-wide and
      // unconditional, which broke the thing seeding exists to do: nwss runs a
      // site's URLs concurrently in one browser, so a sibling's clear wiped the
      // cookies this URL had just been seeded with. The sibling re-seeds
      // immediately afterwards, but a reload whose document commits inside that
      // window reads a page with no cookies at all -- measured at 2 of 20
      // reproducer runs, always the first URL's reload, always inside the
      // sibling's clear window.
      //
      // Honouring the refcount is also what makes a CONCURRENT MULTI-SITE scan
      // behave: one site's clear used to delete another site's seeded cookies,
      // which no amount of re-seeding by the first site puts back.
      //
      // Same read-then-delete shape as removeCookies(), for the reason recorded
      // there: context.deleteCookie() maps to Storage.setCookies and demands
      // COMPLETE cookie objects, so the live jar is read and the real objects
      // handed back. The claim check is deliberately the LAST thing before the
      // delete, though what makes it correct is the ORDER on the wire --
      // applySiteCookies({retain}) claims synchronously before its seed goes
      // out, so a claim is already visible to this read.
      { send: async () => {
          const context = typeof page.browserContext === 'function' ? page.browserContext() : null;
          if (!context || typeof context.cookies !== 'function' || typeof context.deleteCookie !== 'function') {
            // Puppeteer too old for the context API. The blunt clear is still
            // better than not clearing -- it just cannot spare a sibling.
            await clearDataSession.send('Network.clearBrowserCookies');
            return;
          }
          const live = await context.cookies();
          const all = Array.isArray(live) ? live : [];
          const doomed = all.filter(c => !isSeedClaimed(c));
          const spared = all.length - doomed.length;
          if (spared > 0 && forceDebug) {
            console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} Kept ${spared} seeded cookie(s): claimed by an in-flight URL`));
          }
          if (doomed.length === 0) return;
          await context.deleteCookie(...doomed);
        }, name: 'cookies' },
      { send: () => clearDataSession.send('Network.clearBrowserCache'), name: 'cache' },
      // Cleared IN THE PAGE, not with Storage.clearDataForOrigin, because that
      // call does not stay inside localStorage: measured side by side, with two
      // tabs on one origin each holding s1 + l1, one tab's
      // clearDataForOrigin({storageTypes:'local_storage'}) left the SIBLING tab
      // with s:[] l:[], while an in-page localStorage.clear() left it s:[s1]
      // l:[] -- i.e. the CDP call tears down every tab's sessionStorage
      // namespace for the origin, and the in-page clear touches neither.
      //
      // That mattered because nwss runs a site's URLs concurrently in ONE
      // browser, so same-origin siblings are the normal case: the sibling's
      // clear wiped this tab's seeded sessionStorage while its reloaded
      // document was committing, and the seed's write -- which landed and
      // verified -- went down with the namespace. The page then read 0 session
      // entries while localStorage read all of them (localStorage is a
      // persistent origin store, so the document-start seed survives). Measured
      // on the repro: 6/20 runs failed this way with two URLs, 0/12 with one.
      //
      // localStorage is origin-scoped either way, so clearing it from the page
      // removes exactly the same data; only the collateral damage differs.
      { send: async () => {
          const res = await page.evaluate((wantOrigin) => {
            try {
              // A redirect can leave the page on another origin, where an
              // in-page clear would wipe somebody else's data instead.
              if (location.origin !== wantOrigin) return 'elsewhere';
              if (!window.localStorage) return 'absent';
              window.localStorage.clear();
              // VERIFIED, not assumed: an in-page clear runs code the page can
              // tamper with (localStorage.clear, or the accessor itself), where
              // the CDP call could not be touched. Unverified, a site that
              // defends its own storage would get a clean "cleared" report and
              // keep the session-cap state clear_sitedata exists to remove --
              // reporting success while doing nothing, which is the failure
              // mode this whole path has already produced once.
              return window.localStorage.length === 0 ? 'ok' : 'not empty after clear';
            } catch (e) { return 'denied: ' + (e && e.name ? e.name : 'error'); }
          }, origin);
          if (res === 'ok' || res === 'absent') return;
          // No usable document on the origin, or the page would not let go of
          // it. The PRE-NAVIGATION clear is the ordinary case: it runs on
          // about:blank, where storage access throws SecurityError. CDP can
          // reach an origin without a document on it and cannot be tampered
          // with, so it stays the fallback -- and its cross-tab cost is
          // acceptable here, since before navigation this URL has nothing of
          // its own to lose and the alternative is not clearing at all.
          await clearDataSession.send('Storage.clearDataForOrigin', { origin, storageTypes: 'local_storage' });
        }, name: 'localStorage' },
      // sessionStorage is NOT a CDP storage type. It is scoped to a browsing
      // context, not to an origin, so it has no entry in Chrome's StorageType
      // enum -- `storageTypes: 'session_storage'` was rejected on every clear
      // with "No valid storage type specified", at debug level only. Measured:
      // the quick batch reported "cleared: cookies, cache, localStorage" and
      // sessionStorage was silently absent, for as long as this line existed,
      // while the module header promised it was cleared.
      //
      // Cleared in the page instead, which is the only mechanism that works --
      // and the right scope: per-tab, so it cannot wipe a concurrent sibling's
      // sessionStorage the way an origin-wide clear would.
      //
      // Off-origin is a SKIP, not a failure: the pre-navigation clear runs on
      // about:blank, where there is no session area of this origin's to clear
      // and storage access throws SecurityError outright. That used to be
      // reported as "sessionStorage clear failed: denied: SecurityError" on
      // every pre-navigation clear -- a failure line for a no-op, while this
      // comment already claimed the case was handled.
      { send: async () => {
          const res = await page.evaluate((wantOrigin) => {
            try {
              // A session area belongs to a tab AND an origin; on any other
              // document there is nothing of this URL's to clear.
              if (location.origin !== wantOrigin) return 'skipped';
              if (!window.sessionStorage) return 'absent';
              window.sessionStorage.clear();
              return window.sessionStorage.length === 0 ? 'ok' : 'not empty after clear';
            } catch (e) { return 'denied: ' + (e && e.name ? e.name : 'error'); }
          }, origin);
          if (res === 'skipped') return 'skipped';
          if (res !== 'ok' && res !== 'absent') throw new Error(res);
        }, name: 'sessionStorage' }
    ];

    // Promise.all preserves input order in the results array, so iterating
    // back in order gives the same completedOperations ordering as the old
    // sequential loops (cookies, cache, localStorage, sessionStorage) — keeps
    // debug logs stable.
    const results = await Promise.all(parallelOps.map(op =>
      op.send().then(
        (outcome) => ({ name: op.name, ok: true, skipped: outcome === 'skipped' }),
        err => ({ name: op.name, ok: false, err })
      )
    ));
    for (const r of results) {
      if (r.ok) {
        // A skip is neither a clear nor a failure, and must not be listed as
        // cleared -- that is how the sessionStorage line read as done for as
        // long as it was silently rejected by CDP.
        if (!r.skipped) completedOperations.push(r.name);
      } else if (forceDebug) {
        console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} ${r.name} clear failed: ${r.err.message}`));
      }
    }

    // Full storage clearing (skip in quick mode for reloads)
    if (!quickMode) {
      // Try comprehensive storage clearing first
      try {
        await clearDataSession.send('Storage.clearDataForOrigin', {
          origin: origin,
          storageTypes: 'all'
        });
        completedOperations.push('all_storage');
      } catch (allStorageErr) {
        // Fallback: try individual storage types. local_storage and
        // session_storage are intentionally omitted here — they were already
        // cleared in the quick-mode-always-on block above (lines ~73-86),
        // so re-clearing them would just add 2 wasted CDP roundtrips.
        const storageTypes = [
          { type: 'indexeddb', name: 'indexedDB' },
          { type: 'websql', name: 'webSQL' },
          { type: 'service_workers', name: 'serviceWorkers' }
        ];
        
        for (const storage of storageTypes) {
          try {
            await clearDataSession.send('Storage.clearDataForOrigin', {
              origin: origin,
              storageTypes: storage.type
            });
            completedOperations.push(storage.name);
          } catch (individualErr) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} ${storage.name} clear failed: ${individualErr.message}`));
            }
          }
        }
      }
    }
    
    if (forceDebug && completedOperations.length > 0) {
      // Not "CDP cleared": localStorage and sessionStorage are cleared in the
      // page (CDP only as a fallback), so naming the transport here would be
      // wrong for half the list.
      console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} Cleared: ${completedOperations.join(', ')}`));
    }
    
    return { success: completedOperations.length > 0, operations: completedOperations };
    
  } catch (cdpErr) {
    // Orphan cleanup: if clearDataSession is null, the race lost (timer
    // won) before the underlying createCDPSession() resolved. Attach a
    // detach-on-resolve so the orphan is reaped if it arrives after we
    // gave up. The outer finally only handles the case where the session
    // was actually assigned. Same fix pattern as cdp.js L2.
    if (!clearDataSession && sessionPromise) {
      sessionPromise.then(s => s.detach().catch(() => {})).catch(() => {});
    }
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} CDP session failed: ${cdpErr.message}`));
    }
    return { success: false, operations: completedOperations };
  } finally {
    if (clearDataSession) {
      try { 
        await clearDataSession.detach(); 
      } catch (detachErr) { 
        // Ignore detach errors
      }
    }
  }
}

/**
 * Fallback page-level clearing with security error handling
 * @param {Page} page - Puppeteer page instance  
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Promise<{success: boolean, operations: string[]}>}
 */
async function clearSiteDataViaPage(page, forceDebug) {
  try {
    // Page-side body is now async so we can `await` the IndexedDB
    // cleanup chain. Previously it was sync and the indexedDB.databases()
    // promise was fire-and-forget — cleared.push('indexedDB') ran before
    // the deletion actually completed, so callers saw 'indexedDB' in the
    // operations list even though the dbs were still pending deletion
    // when page.evaluate returned.
    const result = await page.evaluate(async () => {
      const cleared = [];

      // Test and clear localStorage
      try {
        if (window.localStorage && typeof window.localStorage.setItem === 'function') {
          // setItem+removeItem is a permission probe — throws SecurityError
          // on some origins before we get to clear(). Don't simplify to
          // just clear() unless you want to swallow those errors silently.
          const testKey = '__nwss_access_test__';
          localStorage.setItem(testKey, 'test');
          localStorage.removeItem(testKey);
          localStorage.clear();
          cleared.push('localStorage');
        }
      } catch (e) {
        // Security error expected on some sites
      }

      // Test and clear sessionStorage
      try {
        if (window.sessionStorage && typeof window.sessionStorage.setItem === 'function') {
          const testKey = '__nwss_access_test__';
          sessionStorage.setItem(testKey, 'test');
          sessionStorage.removeItem(testKey);
          sessionStorage.clear();
          cleared.push('sessionStorage');
        }
      } catch (e) {
        // Security error expected on some sites
      }

      // Clear IndexedDB — actually wait for the deletion chain to
      // complete before reporting. indexedDB.deleteDatabase returns an
      // IDBRequest (not a Promise), so wrap each in a Promise that
      // resolves on success/error/blocked, then Promise.all.
      try {
        if (window.indexedDB && typeof window.indexedDB.databases === 'function') {
          const dbs = await window.indexedDB.databases();
          await Promise.all(dbs.map(db => new Promise((resolve) => {
            if (!db.name) return resolve();
            let req;
            try { req = window.indexedDB.deleteDatabase(db.name); }
            catch (_) { return resolve(); }
            req.onsuccess = () => resolve();
            req.onerror = () => resolve();   // best-effort — don't fail the batch
            req.onblocked = () => resolve(); // another tab has it open; can't wait forever
          })));
          cleared.push('indexedDB');
        }
      } catch (e) {
        // IndexedDB may not be available, or databases() may reject
      }

      return cleared;
    });
    
    if (forceDebug && result.length > 0) {
      console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} Page-level cleared: ${result.join(', ')}`));
    }
    
    return { success: result.length > 0, operations: result };
  } catch (pageErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} Page evaluation failed: ${pageErr.message}`));
    }
    return { success: false, operations: [] };
  }
}

/**
 * Main entry point for site data clearing
 * Attempts CDP clearing first, falls back to page-level if needed
 * @param {Page} page - Puppeteer page instance
 * @param {string} currentUrl - URL being processed
 * @param {boolean} forceDebug - Debug logging flag
 * @param {boolean} quickMode - If true, skip heavy storage types
 *   (IndexedDB / WebSQL / serviceWorkers) and the page-level fallback. Still
 *   clears cookies + cache + localStorage + sessionStorage — the four
 *   storage layers where session-cap tracking actually lives for ad/
 *   popunder networks. Used between reloads where full clears would add
 *   per-cycle latency without freeing additional session state.
 * @returns {Promise<{success: boolean, operations: string[], method: string}>}
 */
async function clearSiteData(page, currentUrl, forceDebug, quickMode = false) {
  // Try CDP clearing first (preferred method)
  const cdpResult = await clearSiteDataViaCDP(page, currentUrl, forceDebug, quickMode);
  
  if (cdpResult.success) {
    return {
      success: true,
      operations: cdpResult.operations,
      method: 'CDP'
    };
  }
  
  // Fallback to page-level clearing if CDP failed and not in quick mode
  if (!quickMode) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `CDP clearing failed, attempting page-level fallback for ${currentUrl}`));
    }
    
    const pageResult = await clearSiteDataViaPage(page, forceDebug);
    
    return {
      success: pageResult.success,
      operations: pageResult.operations,
      method: pageResult.success ? 'page-level' : 'failed'
    };
  }
  
  return {
    success: false,
    operations: [],
    method: 'failed'
  };
}

// Public surface. clearSiteDataViaCDP / clearSiteDataViaPage are
// internal helpers but exported for testing / advanced callers.
// (Previously also defined a clearSiteDataEnhanced function that wasn't
// even exported and had zero callers anywhere — 117 lines of dead code
// removed, including a mislabeled "Security.disable" CDP call dressed
// up as "security_reset" that just disabled the CDP Security domain
// with no actual security effect.)
module.exports = {
  clearSiteData,
  clearSiteDataViaCDP,
  clearSiteDataViaPage
};