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
 * @param {boolean} quickMode - If true, only clear cache/cookies (for reloads)
 * @returns {Promise<{success: boolean, operations: string[]}>}
 */
async function clearSiteDataViaCDP(page, currentUrl, forceDebug, quickMode = false) {
  let clearDataSession = null;
  const completedOperations = [];

  try {
    // Capture the timeout-timer ID so we can clear it once the race
    // resolves. Previously the setTimeout fired 10s after the success
    // path completed — reject was swallowed (race already settled)
    // but the timer kept the event loop reference for up to 10s.
    let timeoutTimer;
    const sessionPromise = page.target().createCDPSession();
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
    
    // Always clear cache and cookies (even in quick mode)
    const basicOperations = [
      { cmd: 'Network.clearBrowserCookies', name: 'cookies' },
      { cmd: 'Network.clearBrowserCache', name: 'cache' }
    ];
    
    for (const op of basicOperations) {
      try {
        await clearDataSession.send(op.cmd);
        completedOperations.push(op.name);
      } catch (opErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} ${op.name} clear failed: ${opErr.message}`));
        }
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
        // Fallback: try individual storage types
        const storageTypes = [
          { type: 'local_storage', name: 'localStorage' },
          { type: 'session_storage', name: 'sessionStorage' },
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
 * @param {boolean} quickMode - If true, only clear cache/cookies (for reloads)
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