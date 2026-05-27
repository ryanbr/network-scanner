// === Chrome DevTools Protocol (CDP) Module ===
// Handles CDP session management and network request logging for enhanced browser monitoring
//
// INTEGRATION GUIDE FOR OTHER APPLICATIONS:
// This module provides a clean interface for Chrome DevTools Protocol integration with Puppeteer.
// It can be easily integrated into any Node.js application that uses Puppeteer for browser automation.
//
// BASIC USAGE:
//   const { createCDPSession } = require('./lib/cdp');
//   const cdpManager = await createCDPSession(page, url, options);
//   // ... do your work ...
//   await cdpManager.cleanup(); // Always cleanup when done
//
// DEPENDENCIES:
//   - Puppeteer (any recent version)
//   - ./colorize module (for logging) - can be replaced with console.log if needed
//
// PERFORMANCE CONSIDERATIONS:
//   - CDP adds ~10-20% overhead to page processing
//   - Use selectively on complex sites that need deep network visibility
//   - Avoid on high-volume batch processing unless debugging
//
// COMPATIBILITY:
//   - Works with Chrome/Chromium browsers
//   - Compatible with headless and headful modes
//   - Tested with Puppeteer 13+ but should work with older versions

const { formatLogMessage, messageColors } = require('./colorize');

// Precomputed colored '[cdp]' subsystem prefix. formatLogMessage only colors
// the [severity] tag; '[cdp]' was sitting plain inside the message string.
const CDP_TAG = messageColors.processing('[cdp]');

/**
 * Race a promise against a timeout, clearing the timer when the promise settles.
 * Prevents leaked setTimeout handles that hold closure references until they fire.
 * @param {Promise} promise - The operation to race
 * @param {number} ms - Timeout in milliseconds
 * @param {string} message - Error message for timeout
 * @returns {Promise} Resolves/rejects with the operation result, or rejects on timeout
 */
function raceWithTimeout(promise, ms, message) {
  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timeoutId));
}

// Shared no-op cleanup used by every no-CDP / CDP-failed return path. Hoisted
// so the success path doesn't allocate a fresh `async () => {}` per call
// when cleanup logic isn't needed, and so NOOP_SESSION_RESULT can reuse it.
const NOOP_CLEANUP = async () => {};

/**
 * Safely extract a hostname from a URL string with a fallback for malformed URLs.
 * Used in logs where 'unknown' or a truncated URL is acceptable on parse failure.
 */
function safeHostname(url, fallback = 'unknown') {
  try { return new URL(url).hostname; } catch { return fallback; }
}

/**
 * Recognize CDP errors that mean the browser is broken and needs restarting.
 * Centralized so setRequestInterceptionWithTimeout and createCDPSession's catch
 * stay in sync — previously each had its own slightly-different pattern list.
 */
function isCriticalCDPError(message) {
  if (!message) return false;
  return message.includes('Network.enable timed out') ||
         message.includes('Protocol error') ||
         message.includes('ProtocolError') ||
         message.includes('Session closed') ||
         message.includes('Target closed') ||
         message.includes('Browser has been closed');
}

// Pre-allocated singleton for both the early-exit case (CDP not enabled OR
// not in debug mode) AND the non-critical-error path. Frozen so callers can't
// mutate the shared instance. Result shape is {session, cleanup}; previously
// also carried an `isEnhanced: false` field that had zero consumers anywhere.
const NOOP_SESSION_RESULT = Object.freeze({
  session: null,
  cleanup: NOOP_CLEANUP
});

/**
 * Creates a new page with timeout protection to prevent CDP hangs.
 *
 * Orphan-page handling: Promise.race cannot cancel browser.newPage(). If the
 * timer wins, the underlying call keeps running and eventually resolves to a
 * real Page tab nothing references → leaked tab in the browser. We capture
 * the original promise and attach a close-on-resolve cleanup so the orphan
 * is reaped if it arrives after the race lost.
 *
 * @param {import('puppeteer').Browser} browser - Browser instance
 * @param {number} timeout - Timeout in milliseconds (default: 30000)
 * @returns {Promise<import('puppeteer').Page>} Page instance
 */
async function createPageWithTimeout(browser, timeout = 30000) {
  const pagePromise = browser.newPage();
  try {
    return await raceWithTimeout(pagePromise, timeout, 'Page creation timeout - browser may be unresponsive');
  } catch (err) {
    // If pagePromise eventually resolves after the race gave up, close the
    // orphan tab. .catch(() => {}) handles the case where pagePromise also
    // rejected (no resource to clean up).
    pagePromise.then(p => p.close().catch(() => {})).catch(() => {});
    throw err;
  }
}

/**
 * Sets request interception with timeout protection
 * @param {import('puppeteer').Page} page - Page instance
 * @param {number} timeout - Timeout in milliseconds (default: 15000)
 * @returns {Promise<void>}
 */
async function setRequestInterceptionWithTimeout(page, timeout = 15000) {
  try {
    await raceWithTimeout(page.setRequestInterception(true), timeout, 'Request interception timeout - first attempt');
  } catch (firstError) {
    // Don't retry if the browser/session is already gone — escalate immediately.
    if (isCriticalCDPError(firstError.message)) {
      throw new Error('CRITICAL_BROWSER_ERROR: ' + firstError.message);
    }

    // Retry with extended timeout
    try {
      await raceWithTimeout(page.setRequestInterception(true), timeout * 2, 'Request interception timeout - retry failed');
    } catch (retryError) {
      if (isCriticalCDPError(retryError.message)) {
        throw new Error('CRITICAL_NETWORK_ERROR: ' + retryError.message);
      }
      throw retryError;
    }
  }
}

/**
 * Creates and manages a CDP session for network monitoring
 * 
 * INTEGRATION EXAMPLE:
 *   const cdpManager = await createCDPSession(page, 'https://example.com', {
 *     enableCDP: true,        // Global CDP flag
 *     siteSpecificCDP: true,  // Site-specific CDP flag  
 *     forceDebug: true        // When true, install the Network.requestWillBeSent log listener
 *   });
 *   
 *   // Your page automation code here...
 *   await page.goto('https://example.com');
 *   
 *   // Always cleanup when done
 *   await cdpManager.cleanup();
 *
 * WHAT IT MONITORS:
 *   - All network requests (GET, POST, etc.)
 *   - Request initiators (script, parser, user, etc.)
 *   - Request/response timing
 *   - Failed requests and errors
 *
 * ERROR HANDLING:
 *   - Gracefully handles CDP connection failures
 *   - Distinguishes between critical and non-critical errors
 *   - Returns null session object if CDP setup fails
 *   - Never throws on cleanup operations
 *
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {string} currentUrl - The URL being processed (used for logging context)
 * @param {object} options - Configuration options
 * @param {boolean} options.enableCDP - Global CDP flag (from --cdp command line)
 * @param {boolean} options.siteSpecificCDP - Site-specific CDP flag (from config)
 * @param {boolean} options.forceDebug - Debug logging flag
 * @returns {Promise<object>} CDP session object with cleanup method
 */
async function createCDPSession(page, currentUrl, options = {}) {
  const { enableCDP, siteSpecificCDP, forceDebug } = options;

  // The only thing this function's CDP session does is feed a debug-gated
  // Network.requestWillBeSent listener. With !forceDebug the listener body is
  // a no-op, so setting up CDP (and paying Network.enable's overhead) buys
  // nothing. Skip entirely in that case — same observable behavior as before,
  // minus the wasted protocol traffic.
  const cdpLoggingNeeded = (enableCDP || siteSpecificCDP === true) && forceDebug;

  if (!cdpLoggingNeeded) {
    return NOOP_SESSION_RESULT;
  }

  // Parse the current URL hostname once and reuse it for the mode-log line,
  // the per-request listener's first-vs-third-party comparison, and (with a
  // different fallback) the catch-block error context.
  const currentHostname = safeHostname(currentUrl);

  // Log which CDP mode is being used
  if (enableCDP) {
    console.log(formatLogMessage('debug', `${CDP_TAG} Global CDP enabled by --cdp flag for ${currentHostname}`));
  } else if (siteSpecificCDP === true) {
    console.log(formatLogMessage('debug', `${CDP_TAG} Site-specific CDP enabled for ${currentHostname} (via cdp: true or cdp_specific domain match)`));
  }

  let cdpSession = null;
  let cdpSessionPromise = null;

  try {
    // Create CDP session using modern Puppeteer 20+ API.
    // Capture the promise BEFORE racing so the catch block can attach an
    // orphan-cleanup chain — if our race times out but the underlying
    // createCDPSession() later resolves, we'd otherwise leak a CDP session
    // on the browser side that nothing references.
    cdpSessionPromise = page.createCDPSession();
    cdpSession = await raceWithTimeout(cdpSessionPromise, 20000, 'CDP session creation timeout');

    // Enable network domain — required for network event monitoring. This is
    // the operation the rest of the codebase has learned can hang under
    // overload; race against a watchdog so we don't block the page load.
    await raceWithTimeout(
      cdpSession.send('Network.enable'),
      15000,
      'Network.enable timed out'
    );

    // Set up network request monitoring
    // This captures ALL network requests at the browser engine level.
    // (We've already established forceDebug is true at this point — no inner
    // check needed.)
    cdpSession.on('Network.requestWillBeSent', (params) => {
      const { url: requestUrl, method } = params.request;
      const initiator = params.initiator?.type ?? 'unknown';
      let hostnameForLog = currentHostname;
      try {
        const requestHostname = new URL(requestUrl).hostname;
        if (currentHostname !== requestHostname) {
          hostnameForLog = `${currentHostname}?${requestHostname}`;
        }
      } catch (_) {}
      console.log(formatLogMessage('debug', `${CDP_TAG}[${hostnameForLog}] ${method} ${requestUrl} (initiator: ${initiator})`));
    });

    console.log(formatLogMessage('debug', `${CDP_TAG} CDP session created successfully for ${currentUrl}`));

    return {
      session: cdpSession,
      cleanup: async () => {
        // Safe cleanup that never throws errors. Idempotent — null out the
        // captured reference after the first successful detach so a
        // double-cleanup is a true no-op instead of generating a misleading
        // "Failed to detach: Session closed" debug log on the second call.
        if (cdpSession) {
          try {
            await cdpSession.detach();
            console.log(formatLogMessage('debug', `${CDP_TAG} CDP session detached for ${currentUrl}`));
          } catch (cdpCleanupErr) {
            // Log cleanup errors but don't throw - cleanup should never fail the calling code
            console.log(formatLogMessage('debug', `${CDP_TAG} Failed to detach CDP session for ${currentUrl}: ${cdpCleanupErr.message}`));
          } finally {
            cdpSession = null;
          }
        }
      }
    };

  } catch (cdpErr) {
    // Two distinct cleanup paths depending on where the failure was:
    //
    //   a) cdpSession IS set → failure was AFTER createCDPSession() resolved
    //      (e.g. Network.enable timed out). We have a real handle — detach
    //      directly. Previously the code just nulled the local and orphaned
    //      the session; now we detach and log any failure.
    //
    //   b) cdpSession is null but cdpSessionPromise was started → the race
    //      timed out before assignment. The underlying createCDPSession()
    //      may still resolve later, producing an orphan session on the
    //      browser side. Attach a detach-on-resolve chain; .catch(()=>{})
    //      swallows the case where the underlying promise also rejected.
    if (cdpSession) {
      try { await cdpSession.detach(); }
      catch (partialDetachErr) {
        console.log(formatLogMessage('debug', `${CDP_TAG} Partial-session detach failed for ${currentUrl}: ${partialDetachErr.message}`));
      }
    } else if (cdpSessionPromise) {
      cdpSessionPromise.then(s => s.detach().catch(() => {})).catch(() => {});
    }

    // Enhanced error context for CDP domain-specific debugging. Reuse the
    // currentHostname computed at function entry (one URL parse vs two);
    // only fall back to the truncated raw URL when that parse failed too.
    const urlContext = currentHostname !== 'unknown'
      ? currentHostname
      : `${currentUrl.substring(0, 50)}...`;

    // Critical errors: browser is broken, propagate so the caller can restart.
    if (isCriticalCDPError(cdpErr.message)) {
      throw new Error(`Browser protocol broken (${urlContext}): ${cdpErr.message}`);
    }

    // NON-CRITICAL ERROR: CDP failed but browser is still usable
    // Log warning but return working session object
    console.warn(formatLogMessage('warn', `${CDP_TAG} Failed to attach CDP session for ${urlContext}: ${cdpErr.message}`));

    // Return null session with no-op cleanup for consistent API
    return NOOP_SESSION_RESULT;
  }
}

// EXPORT INTERFACE FOR OTHER APPLICATIONS:
// This module provides a clean, reusable interface for CDP integration.
// Simply require this module and use the exported functions.
//
// CUSTOMIZATION TIPS:
// 1. Replace './colorize' import with your own logging system
// 2. Modify the request logging format in the Network.requestWillBeSent handler
// 3. Add additional CDP domain subscriptions in createCDPSession
// 4. Customize error categorization in the catch blocks
//
// TROUBLESHOOTING:
// - If you get "Protocol error" frequently, the browser may be overloaded
// - Timeout errors usually indicate the browser needs to be restarted
// - "Target closed" means the page was closed while CDP was active
//
// BROWSER COMPATIBILITY:
// - Chrome/Chromium 60+ (older versions may have limited CDP support)
// - Works in both headless and headed modes
// - Some features may not work in --no-sandbox mode
module.exports = {
  createCDPSession,
  createPageWithTimeout,
  setRequestInterceptionWithTimeout
};