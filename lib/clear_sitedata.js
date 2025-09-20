// === Clear Site Data Module ===
// Handles comprehensive site data clearing via CDP and page-level fallbacks
// Resolves SecurityError issues with localStorage/sessionStorage access

const { formatLogMessage } = require('./colorize');

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
    clearDataSession = await Promise.race([
      page.target().createCDPSession(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('CDP session timeout')), 10000)
      )
    ]);
    
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
          console.log(formatLogMessage('debug', `[clear_sitedata] ${op.name} clear failed: ${opErr.message}`));
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
              console.log(formatLogMessage('debug', `[clear_sitedata] ${storage.name} clear failed: ${individualErr.message}`));
            }
          }
        }
      }
    }
    
    if (forceDebug && completedOperations.length > 0) {
      console.log(formatLogMessage('debug', `[clear_sitedata] CDP cleared: ${completedOperations.join(', ')}`));
    }
    
    return { success: completedOperations.length > 0, operations: completedOperations };
    
  } catch (cdpErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[clear_sitedata] CDP session failed: ${cdpErr.message}`));
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
    const result = await page.evaluate(() => {
      const cleared = [];
      
      // Test and clear localStorage
      try {
        if (window.localStorage && typeof window.localStorage.setItem === 'function') {
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
      
      // Clear IndexedDB
      try {
        if (window.indexedDB && typeof window.indexedDB.databases === 'function') {
          window.indexedDB.databases().then(dbs => {
            dbs.forEach(db => {
              try {
                window.indexedDB.deleteDatabase(db.name);
              } catch (dbErr) {
                // Individual DB deletion may fail
              }
            });
          }).catch(() => {
            // Database listing may fail
          });
          cleared.push('indexedDB');
        }
      } catch (e) {
        // IndexedDB may not be available
      }
      
      return cleared;
    });
    
    if (forceDebug && result.length > 0) {
      console.log(formatLogMessage('debug', `[clear_sitedata] Page-level cleared: ${result.join(', ')}`));
    }
    
    return { success: result.length > 0, operations: result };
  } catch (pageErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[clear_sitedata] Page evaluation failed: ${pageErr.message}`));
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

/**
 * Enhanced site data clearing with additional browser-level operations
 * Includes cache warming prevention and comprehensive storage cleanup
 * @param {Page} page - Puppeteer page instance
 * @param {string} currentUrl - URL being processed  
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Promise<{success: boolean, operations: string[], method: string}>}
 */
async function clearSiteDataEnhanced(page, currentUrl, forceDebug) {
  let clearDataSession = null;
  const completedOperations = [];
  
  try {
    clearDataSession = await Promise.race([
      page.target().createCDPSession(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Enhanced CDP session timeout')), 15000)
      )
    ]);
    
    const origin = new URL(currentUrl).origin;
    
    // Enhanced clearing operations
    const enhancedOperations = [
      // Network layer
      { cmd: 'Network.clearBrowserCookies', name: 'cookies' },
      { cmd: 'Network.clearBrowserCache', name: 'cache' },
      
      // Storage layer - comprehensive
      {
        cmd: 'Storage.clearDataForOrigin',
        params: { origin, storageTypes: 'all' },
        name: 'all_storage'
      },
      
      // Runtime layer
      { cmd: 'Runtime.discardConsoleEntries', name: 'console' },
      
      // Security layer
      { cmd: 'Security.disable', name: 'security_reset' }
    ];
    
    for (const op of enhancedOperations) {
      try {
        if (op.params) {
          await clearDataSession.send(op.cmd, op.params);
        } else {
          await clearDataSession.send(op.cmd);
        }
        completedOperations.push(op.name);
      } catch (opErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[clear_sitedata_enhanced] ${op.name} failed: ${opErr.message}`));
        }
        
        // For storage operations, try individual fallbacks
        if (op.name === 'all_storage') {
          const individualTypes = ['local_storage', 'session_storage', 'indexeddb', 'websql', 'service_workers'];
          for (const type of individualTypes) {
            try {
              await clearDataSession.send('Storage.clearDataForOrigin', {
                origin,
                storageTypes: type
              });
              completedOperations.push(type);
            } catch (individualErr) {
              // Continue trying other types
            }
          }
        }
      }
    }
    
    // Additional DOM cleanup via page evaluation
    try {
      await page.evaluate(() => {
        // Clear any cached DOM queries
        if (window.document && document.querySelectorAll) {
          // Force garbage collection of cached selectors
          const div = document.createElement('div');
          document.body.appendChild(div);
          document.body.removeChild(div);
        }
        
        // Clear performance entries
        if (window.performance && performance.clearMarks) {
          performance.clearMarks();
          performance.clearMeasures();
        }
      });
      completedOperations.push('dom_cleanup');
    } catch (domErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[clear_sitedata_enhanced] DOM cleanup failed: ${domErr.message}`));
      }
    }
    
    if (forceDebug && completedOperations.length > 0) {
      console.log(formatLogMessage('debug', `[clear_sitedata_enhanced] Cleared: ${completedOperations.join(', ')}`));
    }
    
    return {
      success: completedOperations.length > 0,
      operations: completedOperations,
      method: 'enhanced_CDP'
    };
    
  } catch (enhancedErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[clear_sitedata_enhanced] Failed: ${enhancedErr.message}`));
    }
    
    // Fallback to regular clearing
    return await clearSiteData(page, currentUrl, forceDebug, false);
    
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

module.exports = {
  clearSiteData,
  clearSiteDataViaCDP,
  clearSiteDataViaPage,
  clearSiteDataEnhanced
};