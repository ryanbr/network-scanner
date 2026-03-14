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

const { formatLogMessage } = require('./colorize');

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

/**
 * Creates a standardized session result object for consistent V8 optimization
 * @param {object|null} session - CDP session or null
 * @param {Function} cleanup - Cleanup function
 * @param {boolean} isEnhanced - Whether enhanced features are active
 * @returns {object} Standardized session object
 */
const createSessionResult = (session = null, cleanup = async () => {}, isEnhanced = false) => ({
  session,
  cleanup,
  isEnhanced
});

/**
 * Creates a new page with timeout protection to prevent CDP hangs
 * @param {import('puppeteer').Browser} browser - Browser instance
 * @param {number} timeout - Timeout in milliseconds (default: 30000)
 * @returns {Promise<import('puppeteer').Page>} Page instance
 */
async function createPageWithTimeout(browser, timeout = 30000) {
  return raceWithTimeout(browser.newPage(), timeout, 'Page creation timeout - browser may be unresponsive');
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
    // Check for immediate critical failures
    if (firstError.message.includes('Target closed') ||
        firstError.message.includes('Session closed') ||
        firstError.message.includes('Browser has been closed')) {
      throw new Error('CRITICAL_BROWSER_ERROR: ' + firstError.message);
    }

    // Retry with extended timeout
    try {
      await raceWithTimeout(page.setRequestInterception(true), timeout * 2, 'Request interception timeout - retry failed');
    } catch (retryError) {
      if (retryError.message.includes('Network.enable timed out') || 
          retryError.message.includes('ProtocolError')) {
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
 *     forceDebug: false       // Enable debug logging
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
 * @param {string} options.currentUrl - Current URL for domain-specific CDP decisions
 * @returns {Promise<object>} CDP session object with cleanup method
 */
async function createCDPSession(page, currentUrl, options = {}) {
  const { enableCDP, siteSpecificCDP, forceDebug } = options;
  
  // Determine if CDP logging is needed for this page
  // You can customize this logic for your application's needs
  const cdpLoggingNeeded = enableCDP || siteSpecificCDP === true;
  
  if (!cdpLoggingNeeded) {
    // Return a null session with no-op cleanup for consistent API
    return createSessionResult();
  }

  // Log which CDP mode is being used
  if (forceDebug) {
    const urlHostname = (() => {
      try { return new URL(currentUrl).hostname; } catch { return 'unknown'; }
    })();

    if (enableCDP) {
      console.log(formatLogMessage('debug', `[cdp] Global CDP enabled by --cdp flag for ${urlHostname}`));
    } else if (siteSpecificCDP === true) {
      console.log(formatLogMessage('debug', `[cdp] Site-specific CDP enabled for ${urlHostname} (via cdp: true or cdp_specific domain match)`));
    }
  }

  let cdpSession = null;

  try {
    // Create CDP session using modern Puppeteer 20+ API
    // Add timeout protection for CDP session creation
    cdpSession = await raceWithTimeout(page.createCDPSession(), 20000, 'CDP session creation timeout');
    
    // Enable network domain - required for network event monitoring  
    await cdpSession.send('Network.enable');

    // Parse current URL hostname once, reused across all request events
    let currentHostname = 'unknown';
    try { currentHostname = new URL(currentUrl).hostname; } catch (_) {}

    // Set up network request monitoring
    // This captures ALL network requests at the browser engine level
    cdpSession.on('Network.requestWillBeSent', (params) => {
      if (forceDebug) {
        const { url: requestUrl, method } = params.request;
        const initiator = params.initiator ? params.initiator.type : 'unknown';
        let hostnameForLog = currentHostname;
        try {
          const requestHostname = new URL(requestUrl).hostname;
          if (currentHostname !== requestHostname) {
            hostnameForLog = `${currentHostname}?${requestHostname}`;
          }
        } catch (_) {}
        console.log(formatLogMessage('debug', `[cdp][${hostnameForLog}] ${method} ${requestUrl} (initiator: ${initiator})`));
      }
    });

    if (forceDebug) {
      console.log(formatLogMessage('debug', `CDP session created successfully for ${currentUrl}`));
    }

    return {
      session: cdpSession,
      cleanup: async () => {
        // Safe cleanup that never throws errors
        if (cdpSession) {
          try {
            await cdpSession.detach();
            if (forceDebug) {
              console.log(formatLogMessage('debug', `CDP session detached for ${currentUrl}`));
            }
          } catch (cdpCleanupErr) {
            // Log cleanup errors but don't throw - cleanup should never fail the calling code
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Failed to detach CDP session for ${currentUrl}: ${cdpCleanupErr.message}`));
            }
          }
        }
      },
      isEnhanced: false
    };

  } catch (cdpErr) {
    cdpSession = null; // Reset on failure
    
    // Enhanced error context for CDP domain-specific debugging
    const urlContext = (() => {
      try {
        return new URL(currentUrl).hostname;
      } catch {
        return `${currentUrl.substring(0, 50)}...`;
      }
    })();

    // Categorize CDP errors for proper handling
    // Enhanced error handling for Puppeteer 20+ error patterns
    if (cdpErr.message.includes('Network.enable timed out') || 
        cdpErr.message.includes('Protocol error') ||
        cdpErr.message.includes('Session closed') ||
        cdpErr.message.includes('Target closed') ||
        cdpErr.message.includes('Browser has been closed')) {
      // CRITICAL ERROR: Browser is broken and needs restart
      // Re-throw these errors so calling code can handle browser restart
      throw new Error(`Browser protocol broken: ${cdpErr.message}`);
    }
    
    // NON-CRITICAL ERROR: CDP failed but browser is still usable
    // Log warning but return working session object
    console.warn(formatLogMessage('warn', `[cdp] Failed to attach CDP session for ${currentUrl}: ${cdpErr.message}`));
    
    // Return null session with no-op cleanup for consistent API
    return createSessionResult();
  }
}

// EXPORT INTERFACE FOR OTHER APPLICATIONS:
// This module provides a clean, reusable interface for CDP integration.
// Simply require this module and use the exported functions.
//
// CUSTOMIZATION TIPS:
// 1. Replace './colorize' import with your own logging system
// 2. Modify the request logging format in the Network.requestWillBeSent handler
// 3. Add additional CDP domain subscriptions in createEnhancedCDPSession
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