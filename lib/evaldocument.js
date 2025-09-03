/**
 * Module for handling evaluateOnNewDocument functionality
 * Provides Fetch/XHR interception and page protection mechanisms
 */

/**
 * Applies evaluateOnNewDocument script injection to a page
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {string} currentUrl - Current URL being processed
 * @param {Object} siteConfig - Site configuration
 * @param {boolean} globalEvalOnDoc - Global eval-on-doc flag
 * @param {boolean} forceDebug - Debug logging flag
 * @param {Function} formatLogMessage - Log formatting function
 * @returns {Promise<boolean>} Success status of injection
 */
async function applyEvaluateOnNewDocument(page, currentUrl, siteConfig, globalEvalOnDoc, forceDebug, formatLogMessage) {
  const shouldInjectEvalForPage = siteConfig.evaluateOnNewDocument === true || globalEvalOnDoc;
  let evalOnDocSuccess = false;
  
  if (!shouldInjectEvalForPage) {
    return false;
  }

  if (forceDebug) {
    if (globalEvalOnDoc) {
      console.log(formatLogMessage('debug', `[evalOnDoc] Global Fetch/XHR interception enabled, applying to: ${currentUrl}`));
    } else {
      console.log(formatLogMessage('debug', `[evalOnDoc] Site-specific Fetch/XHR interception enabled for: ${currentUrl}`));
    }
  }
  
  // Strategy 1: Try full injection with health check
  let browserResponsive = false;
  try {
    await Promise.race([
      page.browser().version(), // Quick responsiveness test
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Browser health check timeout')), 3000)
      )
    ]);
    browserResponsive = true;
  } catch (healthErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[evalOnDoc] Browser health check failed: ${healthErr.message}`));
    }
    browserResponsive = false;
  }
  
  // Strategy 2: Try injection with reduced complexity if browser is responsive
  if (browserResponsive) {
    try {
      await Promise.race([
        page.evaluateOnNewDocument(createFullInterceptionScript()),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Injection timeout')), 8000)
        )
      ]);
      evalOnDocSuccess = true;
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[evalOnDoc] Full injection successful for ${currentUrl}`));
      }
    } catch (fullInjectionErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[evalOnDoc] Full injection failed: ${fullInjectionErr.message}, trying simplified fallback`));
      }
      
      // Strategy 3: Fallback - Try minimal injection (just fetch monitoring)
      try {
        await Promise.race([
          page.evaluateOnNewDocument(createMinimalInterceptionScript()),
          new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Minimal injection timeout')), 3000)
          )
        ]);
        evalOnDocSuccess = true;
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[evalOnDoc] Minimal injection successful for ${currentUrl}`));
        }
      } catch (minimalInjectionErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[evalOnDoc] Minimal injection also failed: ${minimalInjectionErr.message}`));
        }
        evalOnDocSuccess = false;
      }
    }
  } else {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[evalOnDoc] Browser unresponsive, skipping injection for ${currentUrl}`));
    }
    evalOnDocSuccess = false;
  }
  
  // Final status logging
  if (!evalOnDocSuccess) {
    console.warn(formatLogMessage('warn', `[evalOnDoc] All injection strategies failed for ${currentUrl} - continuing with standard request monitoring only`));
  }
  
  return evalOnDocSuccess;
}

/**
 * Creates the full interception script with all protections
 * @returns {Function} Script function for evaluateOnNewDocument
 */
function createFullInterceptionScript() {
  return () => {
    // Prevent infinite reload loops
    let reloadCount = 0;
    const MAX_RELOADS = 2;
    const originalReload = window.location.reload;
    const originalReplace = window.location.replace;
    const originalAssign = window.location.assign;
    
    window.location.reload = function() {
      if (++reloadCount > MAX_RELOADS) {
        console.log('[loop-protection] Blocked excessive reload attempt');
        return;
      }
      return originalReload.apply(this, arguments);
    };
    
    // Also protect against location.replace/assign to same URL
    const currentHref = window.location.href;
    window.location.replace = function(url) {
      if (url === currentHref && ++reloadCount > MAX_RELOADS) {
        console.log('[loop-protection] Blocked same-page replace attempt');
        return;
      }
      return originalReplace.apply(this, arguments);
    };

    // This script intercepts and logs Fetch and XHR requests
    // from within the page context at the earliest possible moment.
    const originalFetch = window.fetch;
    window.fetch = (...args) => {
      try {
        console.log('[evalOnDoc][fetch]', args[0]); // Log fetch requests
        const fetchPromise = originalFetch.apply(this, args);
        
        // Add network error handling to prevent page errors
        return fetchPromise.catch(fetchErr => {
          console.log('[evalOnDoc][fetch-error]', args[0], fetchErr.message);
          throw fetchErr; // Re-throw to maintain normal error flow
        });
      } catch (fetchWrapperErr) {
        console.log('[evalOnDoc][fetch-wrapper-error]', fetchWrapperErr.message);
        return originalFetch.apply(this, args);
      }
    };

    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, xhrUrl) {
      try {
        console.log('[evalOnDoc][xhr]', xhrUrl); // Log XHR requests
        
        // Add error handling for XHR
        this.addEventListener('error', function(event) {
          console.log('[evalOnDoc][xhr-error]', xhrUrl, 'Network error occurred');
        });
        
        return originalXHROpen.apply(this, arguments);
      } catch (xhrOpenErr) {
        console.log('[evalOnDoc][xhr-open-error]', xhrOpenErr.message);
        return originalXHROpen.apply(this, arguments);
      }
    };
  };
}

/**
 * Creates the minimal interception script (fetch only)
 * @returns {Function} Script function for evaluateOnNewDocument
 */
function createMinimalInterceptionScript() {
  return () => {
    // Minimal injection - just fetch monitoring
    if (window.fetch) {
      const originalFetch = window.fetch;
      window.fetch = (...args) => {
        try {
          console.log('[evalOnDoc][fetch-minimal]', args[0]);
          return originalFetch.apply(this, args);
        } catch (err) {
          return originalFetch.apply(this, args);
        }
      };
    }
  };
}

module.exports = {
  applyEvaluateOnNewDocument
};