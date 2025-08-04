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
 * @returns {Promise<object>} CDP session object with cleanup method
 */
async function createCDPSession(page, currentUrl, options = {}) {
  const { enableCDP, siteSpecificCDP, forceDebug } = options;
  
  // Determine if CDP logging is needed for this page
  // You can customize this logic for your application's needs
  const cdpLoggingNeeded = enableCDP || siteSpecificCDP === true;
  
  if (!cdpLoggingNeeded) {
    // Return a null session with no-op cleanup for consistent API
    return { session: null, cleanup: async () => {} };
  }

  // Log which CDP mode is being used
  if (forceDebug) {
    if (enableCDP) {
      console.log(formatLogMessage('debug', `CDP logging globally enabled by --cdp, applying to page: ${currentUrl}`));
    } else if (siteSpecificCDP === true) {
      console.log(formatLogMessage('debug', `CDP logging enabled for page ${currentUrl} via site-specific 'cdp: true' config.`));
    }
  }

  let cdpSession = null;

  try {
    // Create CDP session - this connects to Chrome's internal debugging interface
    cdpSession = await page.target().createCDPSession();
    
    // Enable network domain - required for network event monitoring  
    await cdpSession.send('Network.enable');
    
    // Set up network request monitoring
    // This captures ALL network requests at the browser engine level
    cdpSession.on('Network.requestWillBeSent', (params) => {
      const { url: requestUrl, method } = params.request;
      const initiator = params.initiator ? params.initiator.type : 'unknown';
      
      // Extract hostname for logging context (handles URL parsing errors gracefully)
      let hostnameForLog = 'unknown-host';
      try {
        hostnameForLog = new URL(currentUrl).hostname;
      } catch (_) { 
        // Ignore URL parsing errors for logging context
      }
      
      // Log the request with context - customize this for your needs
      // Format: [cdp][hostname] METHOD url (initiator: type)
      console.log(formatLogMessage('debug', `[cdp][${hostnameForLog}] ${method} ${requestUrl} (initiator: ${initiator})`));
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
      }
    };

  } catch (cdpErr) {
    cdpSession = null; // Reset on failure
    
    // Categorize CDP errors for proper handling
    if (cdpErr.message.includes('Network.enable timed out') || 
        cdpErr.message.includes('Protocol error')) {
      // CRITICAL ERROR: Browser is broken and needs restart
      // Re-throw these errors so calling code can handle browser restart
      throw new Error(`Browser protocol broken: ${cdpErr.message}`);
    }
    
    // NON-CRITICAL ERROR: CDP failed but browser is still usable
    // Log warning but return working session object
    console.warn(formatLogMessage('warn', `[cdp] Failed to attach CDP session for ${currentUrl}: ${cdpErr.message}`));
    
    // Return null session with no-op cleanup for consistent API
    return {
      session: null,
      cleanup: async () => {}
    };
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
 * @returns {object} Validation result with recommendations
 */
function validateCDPConfig(siteConfig, globalCDP) {
  const warnings = [];
  const recommendations = [];
  
  // Check for conflicting configurations
  if (globalCDP && siteConfig.cdp === false) {
    warnings.push('Site-specific CDP disabled but global CDP is enabled - global setting will override');
  }
  
  // Performance recommendations
  if (globalCDP || siteConfig.cdp === true) {
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
    return basicSession;
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
    return basicSession;
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
  validateCDPConfig,
  createEnhancedCDPSession
};