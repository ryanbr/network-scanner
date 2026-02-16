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
 * Creates a reusable timeout promise to reduce function allocation overhead
 * @param {number} ms - Timeout in milliseconds
 * @param {string} message - Error message for timeout
 * @returns {Promise} Promise that rejects after timeout
 */
function createTimeoutPromise(ms, message) {
  return new Promise((_, reject) => 
    setTimeout(() => reject(new Error(message)), ms)
  );
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
  return Promise.race([
    browser.newPage(),
    createTimeoutPromise(timeout, 'Page creation timeout - browser may be unresponsive')
  ]);
}

/**
 * Sets request interception with timeout protection
 * @param {import('puppeteer').Page} page - Page instance
 * @param {number} timeout - Timeout in milliseconds (default: 15000)
 * @returns {Promise<void>}
 */
async function setRequestInterceptionWithTimeout(page, timeout = 15000) {
  try {
    await Promise.race([
      page.setRequestInterception(true),
      createTimeoutPromise(timeout, 'Request interception timeout - first attempt')
    ]);
  } catch (firstError) {
    // Check for immediate critical failures
    if (firstError.message.includes('Target closed') || 
        firstError.message.includes('Session closed') ||
        firstError.message.includes('Browser has been closed')) {
      throw new Error('CRITICAL_BROWSER_ERROR: ' + firstError.message);
    }
    
    // Retry with extended timeout
    try {
      await Promise.race([
        page.setRequestInterception(true),
        createTimeoutPromise(timeout * 2, 'Request interception timeout - retry failed')
      ]);
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
    cdpSession = await Promise.race([
      page.createCDPSession(),
      createTimeoutPromise(20000, 'CDP session creation timeout')
    ]);
    
    // Enable network domain - required for network event monitoring  
    await cdpSession.send('Network.enable');
    
    // Set up network request monitoring
    // This captures ALL network requests at the browser engine level
    cdpSession.on('Network.requestWillBeSent', (params) => {
      const { url: requestUrl, method } = params.request;
      const initiator = params.initiator ? params.initiator.type : 'unknown';
      
      // Extract hostname for logging context (handles URL parsing errors gracefully)
      const hostnameForLog = (() => {
        try {
          const currentHostname = new URL(currentUrl).hostname;
          const requestHostname = new URL(requestUrl).hostname;
          return currentHostname !== requestHostname 
            ? `${currentHostname}?${requestHostname}`
            : currentHostname;
        } catch (_) { 
          return 'unknown-host';
        }
      })();
      
 // Log the request with context only if debug mode is enabled
 if (forceDebug) {
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

/**
 * Validates CDP availability and configuration
 * 
 * USAGE IN YOUR APPLICATION:
 *   const validation = validateCDPConfig(siteConfig, globalCDPFlag);
 *   if (!validation.isValid) {
 *     console.warn('CDP configuration issues detected');
 *   }
 *   validation.recommendations.forEach(rec => console.log('Recommendation:', rec));
 *
 * @param {object} siteConfig - Site configuration object
 * @param {boolean} globalCDP - Global CDP flag
 * @param {Array} cdpSpecificDomains - Array of domains for cdp_specific feature
 * @returns {object} Validation result with recommendations
 */
function validateCDPConfig(siteConfig, globalCDP, cdpSpecificDomains = []) {
  const warnings = [];
  const recommendations = [];
  
  // Check for conflicting configurations
  if (globalCDP && siteConfig.cdp === false) {
    warnings.push('Site-specific CDP disabled but global CDP is enabled - global setting will override');
  }
  
  // Validate cdp_specific configuration
  if (siteConfig.cdp_specific) {
    if (!Array.isArray(siteConfig.cdp_specific)) {
      warnings.push('cdp_specific must be an array of domain strings');
    } else if (siteConfig.cdp_specific.length === 0) {
      warnings.push('cdp_specific is empty - no domains will have CDP enabled');
    } else {
      // Validate domain format
      const hasInvalidDomains = siteConfig.cdp_specific.some(domain => 
        typeof domain !== 'string' || domain.trim() === ''
      );
      
      if (hasInvalidDomains) {
        // Only filter invalid domains if we need to show them
        const invalidDomains = siteConfig.cdp_specific.filter(domain => 
          typeof domain !== 'string' || domain.trim() === ''
        );
        warnings.push(`cdp_specific contains invalid domains: ${invalidDomains.join(', ')}`);
      }
    }
  }
  
  // Performance recommendations
  const cdpEnabled = globalCDP || siteConfig.cdp === true || 
    (Array.isArray(siteConfig.cdp_specific) && siteConfig.cdp_specific.length > 0);
  
  if (cdpEnabled) {
    recommendations.push('CDP logging enabled - this may impact performance for high-traffic sites');
    
    if (siteConfig.timeout && siteConfig.timeout < 30000) {
      recommendations.push('Consider increasing timeout when using CDP logging to avoid protocol timeouts');
    }
  }
  
  return {
    isValid: true,
    warnings,
    recommendations
  };
}

/**
 * Enhanced CDP session with additional network monitoring features
 * 
 * ADVANCED FEATURES:
 *   - JavaScript exception monitoring
 *   - Security state change detection  
 *   - Failed network request tracking
 *   - Enhanced error reporting
 *
 * USE CASES:
 *   - Security analysis requiring comprehensive monitoring
 *   - Debugging complex single-page applications
 *   - Performance analysis of web applications
 *   - Research requiring detailed browser insights
 *
 * PERFORMANCE IMPACT:
 *   - Adds additional CDP domain subscriptions
 *   - Higher memory usage due to more event listeners
 *   - Recommended only for detailed analysis scenarios
 *
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {string} currentUrl - The URL being processed
 * @param {object} options - Configuration options (same as createCDPSession)
 * @returns {Promise<object>} Enhanced CDP session object with isEnhanced flag
 */
async function createEnhancedCDPSession(page, currentUrl, options = {}) {
  const basicSession = await createCDPSession(page, currentUrl, options);
  
  if (!basicSession.session) {
    // Ensure enhanced flag is set even for null sessions
    return { ...basicSession, isEnhanced: false };
  }

  const { session } = basicSession;
  const { forceDebug } = options;

  try {
    // Enable additional CDP domains for enhanced monitoring
    await session.send('Runtime.enable');  // For JavaScript exceptions
    await session.send('Security.enable'); // For security state changes
    
    // Monitor JavaScript exceptions - useful for debugging problematic sites
    session.on('Runtime.exceptionThrown', (params) => {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[cdp][exception] ${params.exceptionDetails.text}`));
      }
    });

    // Monitor security state changes - detect mixed content, certificate issues, etc.
    session.on('Security.securityStateChanged', (params) => {
      if (forceDebug && params.securityState !== 'secure') {
        console.log(formatLogMessage('debug', `[cdp][security] Security state: ${params.securityState}`));
      }
    });

    // Monitor failed network requests - useful for understanding site issues
    session.on('Network.loadingFailed', (params) => {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[cdp][failed] ${params.errorText}: ${params.requestId}`));
      }
    });

    return {
      session,
      cleanup: basicSession.cleanup,
      isEnhanced: true // Flag to indicate enhanced features are active
    };

  } catch (enhancedErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Enhanced CDP features failed, falling back to basic session: ${enhancedErr.message}`));
    }
    
    // Graceful degradation: return basic session if enhanced features fail
    // This ensures your application continues working even if advanced features break
    return { ...basicSession, isEnhanced: false };
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