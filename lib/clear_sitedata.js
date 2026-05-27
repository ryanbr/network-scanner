// === Clear Site Data Module ===
// Handles comprehensive site data clearing via CDP and page-level fallbacks
// Resolves SecurityError issues with localStorage/sessionStorage access

const { formatLogMessage, messageColors } = require('./colorize');
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
    // where AdsCore-family popunder networks track per-session caps
    // (aclibSubKey-popunder etc.; see commit 11e1f49). Skipping them in quick
    // mode capped popunder discovery at ~1 capture per scan.
    //
    // Heavier storage types (IndexedDB, WebSQL, service workers) still gate
    // on !quickMode below.
    const parallelOps = [
      { send: () => clearDataSession.send('Network.clearBrowserCookies'), name: 'cookies' },
      { send: () => clearDataSession.send('Network.clearBrowserCache'), name: 'cache' },
      { send: () => clearDataSession.send('Storage.clearDataForOrigin', { origin, storageTypes: 'local_storage' }), name: 'localStorage' },
      { send: () => clearDataSession.send('Storage.clearDataForOrigin', { origin, storageTypes: 'session_storage' }), name: 'sessionStorage' }
    ];

    // Promise.all preserves input order in the results array, so iterating
    // back in order gives the same completedOperations ordering as the old
    // sequential loops (cookies, cache, localStorage, sessionStorage) — keeps
    // debug logs stable.
    const results = await Promise.all(parallelOps.map(op =>
      op.send().then(
        () => ({ name: op.name, ok: true }),
        err => ({ name: op.name, ok: false, err })
      )
    ));
    for (const r of results) {
      if (r.ok) {
        completedOperations.push(r.name);
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
      console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} CDP cleared: ${completedOperations.join(', ')}`));
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