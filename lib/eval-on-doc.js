/**
 * Fetch/XHR interception injected before the page's own scripts run.
 *
 * Opt-in per site with `evaluateOnNewDocument: true`, or globally with
 * `--eval-on-doc`. Wraps `window.fetch` and `XMLHttpRequest.prototype.open` at
 * the earliest possible moment so requests made from page script are visible
 * from inside the page context.
 *
 * The reload-loop protection that used to sit inside that injected script is now
 * installReloadLoopGuard() below, and it had to leave the page entirely:
 * `location.reload`/`.replace`/`.assign` are [[Unforgeable]] per the HTML spec, so
 * each Location instance owns them as non-writable, non-configurable properties.
 * Measured in Chrome — the in-page assignment neither threw (sloppy mode) nor took
 * effect, so those guards had never once run.
 *
 * NOTE the wrappers report via the page's own `console.log`, and nwss.js only
 * forwards console messages of type 'error' (deliberately — attaching any
 * console listener arms DevTools-detection traps, see nwss.js's 'console'
 * handler). So these lines are visible to a devtools session, not in scan
 * output. That is pre-existing behaviour, preserved here unchanged.
 *
 * Three strategies, in order, because CDP's addScriptToEvaluateOnNewDocument is
 * the operation most likely to hang on a degraded browser:
 *   1. health-check the browser (a cheap pages() call with a timeout);
 *   2. full injection (fetch + XHR wrappers) under a 5s timeout;
 *   3. on a non-CDP failure only, a minimal fetch-only injection under 3s.
 * A CDP/Protocol error skips straight to giving up: it means browser
 * communication is broken, so retrying a bigger payload only costs time.
 */

const { formatLogMessage } = require('./colorize');
const { messageColors } = require('./colorize');
const { updatePageUsage } = require('./browserhealth');

const EVAL_ON_DOC_TAG = messageColors.processing('[evalOnDoc]');

/**
 * Install the Fetch/XHR interception script on a page, before navigation.
 *
 * @param {object} page - Puppeteer page (not yet navigated)
 * @param {object} options
 * @param {object} options.siteConfig - Site config (`evaluateOnNewDocument`, `window_cleanup`)
 * @param {string} options.currentUrl - URL about to be loaded, for log lines
 * @param {object} options.browserInstance - Browser, for the health check
 * @param {boolean} options.globalEvalOnDoc - Whether --eval-on-doc was passed
 * @param {boolean} [options.forceDebug=false] - Verbose logging
 * @returns {Promise<{requested: boolean, injected: boolean, strategy: string|null}>}
 *   `requested` is false when neither the site nor the flag asked for it.
 */
async function installFetchXhrInterception(page, {
  siteConfig,
  currentUrl,
  browserInstance,
  globalEvalOnDoc = false,
  forceDebug = false
} = {}) {
  const shouldInjectEvalForPage = (siteConfig && siteConfig.evaluateOnNewDocument === true) || globalEvalOnDoc;
  if (!shouldInjectEvalForPage) return { requested: false, injected: false, strategy: null };

  let evalOnDocSuccess = false;
  let strategy = null;

  // PREVENT realtime cleanup during injection to avoid "Session closed" errors
  if (siteConfig && siteConfig.window_cleanup === 'realtime') {
    updatePageUsage(page, true); // Mark page as actively processing BEFORE injection
  }

  if (forceDebug) {
    if (globalEvalOnDoc) {
      console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Global Fetch/XHR interception enabled, applying to: ${currentUrl}`));
    } else { // siteConfig.evaluateOnNewDocument must be true
      console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Site-specific Fetch/XHR interception enabled for: ${currentUrl}`));
    }
  }

  // Strategy 1: Try full injection with health check
  let browserResponsive = false;
  try {
    // Check if browser is still connected before attempting health check
    if (!browserInstance.connected) {
      throw new Error('Browser not connected');
    }

    await Promise.race([
      browserInstance.pages(), // Simple existence check that doesn't require active session
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Browser health check timeout')), 3000)
      )
    ]);
    browserResponsive = true;
  } catch (healthErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Browser health check failed: ${healthErr.message}`));
    }
    browserResponsive = false;
  }

  // Strategy 2: Try injection with reduced complexity if browser is responsive
  if (browserResponsive) {
    try {
      // Add comprehensive timeout protection for evaluateOnNewDocument
      await Promise.race([
        // Main injection with all safety checks
        page.evaluateOnNewDocument(() => {
          // Prevent duplicate injections
          if (window.__nwss_injection_applied) {
            console.log('[evalOnDoc] Already injected, skipping');
            return;
          }
          window.__nwss_injection_applied = true;

          // Wrap everything in try-catch to prevent page crashes
          try {
            // Add timeout check within the injection
            const injectionTimeout = setTimeout(() => {
              console.log('[evalOnDoc] Injection taking too long, aborting');
            }, 3000);

            // (Reload-loop protection used to sit here, assigning to
            // window.location.reload/replace. Those are [[Unforgeable]], so it
            // never did anything; it now lives in installReloadLoopGuard().)

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
            clearTimeout(injectionTimeout);
          } catch (injectionError) {
            console.log('[evalOnDoc][error]', 'Injection failed:', injectionError.message);
          }
        }),
        // Reduced timeout for faster failure
        new Promise((_, reject) => {
          setTimeout(() => {
            reject(new Error('evaluateOnNewDocument timeout - browser may be unresponsive'));
          }, 5000); // Reduced from 8000ms
        })
      ]);
      evalOnDocSuccess = true;
      strategy = 'full';
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Full injection successful for ${currentUrl}`));
      }
    } catch (fullInjectionErr) {
      // Enhanced error detection for CDP issues
      const isCDPError = fullInjectionErr.constructor.name === 'ProtocolError' ||
                        fullInjectionErr.name === 'ProtocolError' ||
                        fullInjectionErr.message.includes('addScriptToEvaluateOnNewDocument timed out') ||
                        fullInjectionErr.message.includes('Protocol error');

      if (forceDebug) {
        const errorType = isCDPError ? 'CDP/Protocol error' : 'timeout/other';
        console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Full injection failed (${errorType}): ${fullInjectionErr.message}`));
      }

      // Skip fallback for CDP errors - they indicate browser communication issues
      if (isCDPError) {
        console.warn(formatLogMessage('warn', `${EVAL_ON_DOC_TAG} CDP communication failure - skipping injection for ${currentUrl}`));
        evalOnDocSuccess = false;
      } else {
        // Strategy 3: Fallback - Try minimal injection (just fetch monitoring)
        try {
          await Promise.race([
            (async () => {
              // Validate page state before minimal injection
              if (!page || page.isClosed()) {
                throw new Error('Page is closed');
              }

              // FIX: Properly wrap page.url() in try-catch to handle race condition
              let pageUrl;
              try {
                pageUrl = await page.url();
              } catch (urlErr) {
                // Page closed between isClosed check and url call
                throw new Error('Page closed while getting URL');
              }

              if (pageUrl === 'about:blank') {
                throw new Error('Cannot inject on about:blank');
              }

              return page.evaluateOnNewDocument(() => {
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
              });
            })(),
            new Promise((_, reject) =>
              setTimeout(() => reject(new Error('Minimal injection timeout')), 3000)
            )
          ]);
          evalOnDocSuccess = true;
          strategy = 'minimal';
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Minimal injection successful for ${currentUrl}`));
          }
        } catch (minimalInjectionErr) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Minimal injection also failed: ${minimalInjectionErr.message}`));
          }
          evalOnDocSuccess = false;
        }
      }
    }
  } else {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Browser unresponsive, skipping injection for ${currentUrl}`));
    }
    evalOnDocSuccess = false;
  }

  // Final status logging
  if (!evalOnDocSuccess) {
    console.warn(formatLogMessage('warn', `${EVAL_ON_DOC_TAG} All injection strategies failed for ${currentUrl} - continuing with standard request monitoring only`));
  }

  // Allow realtime cleanup to proceed after injection completes
  if (siteConfig && siteConfig.window_cleanup === 'realtime') {
    updatePageUsage(page, false); // Mark page as idle after injection
  }

  return { requested: true, injected: evalOnDocSuccess, strategy };
}

/**
 * Watch for a page reloading itself in a loop, and stop it.
 *
 * Why this is driver-side and not in the page: `location.reload`, `.replace` and
 * `.assign` are [[Unforgeable]] (own properties of each Location instance,
 * non-writable and non-configurable), so no injected script can intercept them.
 * Counting main-frame navigations instead is strictly better anyway -- it catches
 * a loop however it is driven, including `location.href = ...` and a <meta
 * refresh>, neither of which patching reload/replace would ever have seen.
 *
 * HOW it stops the loop matters. Aborting the navigation was measured leaving the
 * page on chrome-error://chromewebdata/, which would hand every post-load step
 * (grep, searchstring, screenshot, interaction) an error page instead of the site.
 * Disabling script execution leaves the document exactly as it is -- measured: the
 * URL, the DOM and page.content() all survive -- and the loop dies with the script
 * that drove it, after the already-scheduled navigations drain.
 *
 * Only navigations to the SAME url count, and the guard is told how many loads the
 * scan itself intends (`reload: N`), so nwss's own reloads cannot trip it.
 *
 * @param {object} page - Puppeteer page, before navigation
 * @param {object} options
 * @param {string} options.currentUrl - The URL being scanned
 * @param {number} [options.expectedLoads=1] - Loads the scan itself will perform
 * @param {number} [options.maxExtraReloads=2] - Self-reloads tolerated beyond that
 * @param {boolean} [options.forceDebug=false] - Verbose logging
 * @returns {Promise<{stop: Function, tripped: Function, loads: Function}>}
 *   `stop()` detaches the listener and CDP session; safe to call twice.
 */
async function installReloadLoopGuard(page, {
  currentUrl,
  expectedLoads = 1,
  maxExtraReloads = 2,
  forceDebug = false
} = {}) {
  const limit = Math.max(1, expectedLoads) + Math.max(0, maxExtraReloads);
  let loads = 0;
  let tripped = false;
  let session = null;
  let stopped = false;

  const onNavigated = async (frame) => {
    try {
      if (stopped || tripped || frame !== page.mainFrame()) return;
      if (frame.url() !== currentUrl) return;   // a different page, not a reload
      loads++;
      if (loads <= limit) return;

      tripped = true;
      if (!session) session = await page.target().createCDPSession();
      await session.send('Emulation.setScriptExecutionDisabled', { value: true });
      console.log(formatLogMessage('warn', `${EVAL_ON_DOC_TAG} ${currentUrl} reloaded itself ${loads} times (limit ${limit}) -- script execution disabled to break the loop; the document is kept, but no further page script will run`));
    } catch (err) {
      // A broken guard must not take the scan with it: a reload loop is wasteful,
      // not fatal, and the URL still has its own timeout.
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Reload-loop guard could not disable script for ${currentUrl}: ${err.message}`));
      }
    }
  };

  page.on('framenavigated', onNavigated);

  return {
    tripped: () => tripped,
    loads: () => loads,
    async stop() {
      if (stopped) return;
      stopped = true;
      try { page.off('framenavigated', onNavigated); } catch (_) { /* page gone */ }
      if (session) {
        try { await session.detach(); } catch (_) { /* session died with the page */ }
        session = null;
      }
    }
  };
}

module.exports = {
  installFetchXhrInterception,
  installReloadLoopGuard
};
