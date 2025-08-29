/**
 * Cloudflare bypass and challenge handling module - Optimized with smart detection and adaptive timeouts
 * Version: 2.4.0 - Fix possible endless loops with retry logic and loop detection
 * Version: 2.3.1 - Colorize CF
 * Version: 2.3.0 - Support CF iframe challenges, and better error handling
 * Version: 2.2.0 - Enhanced with retry logic, caching, and improved error handling
 * Version: 2.1.0 - Enhanced with quick detection, adaptive timeouts, and comprehensive debug logging
 * Handles phishing warnings, Turnstile challenges, and modern Cloudflare protections
 */

// Import color utilities
const { formatLogMessage } = require('./colorize');

/**
 * Module version information
 */
const CLOUDFLARE_MODULE_VERSION = '2.4.0';

/**
 * Timeout constants for various operations (in milliseconds)
 * Optimized timeout constants for Puppeteer 22.x performance (in milliseconds)
 * All values tuned for maximum scanning speed while maintaining functionality
 */
const TIMEOUTS = {
  PAGE_EVALUATION: 8000,           // Standard page evaluation timeout
  PAGE_EVALUATION_SAFE: 10000,     // Safe page evaluation with extra buffer
  PHISHING_CLICK: 3000,           // Timeout for clicking phishing continue button
  PHISHING_NAVIGATION: 8000,       // Wait for navigation after phishing bypass
  JS_CHALLENGE_BUFFER: 18000,     // JS challenge with safety buffer
  TURNSTILE_COMPLETION: 12000,    // Turnstile completion check
  TURNSTILE_COMPLETION_BUFFER: 15000, // Turnstile completion with buffer
  CLICK_TIMEOUT: 5000,            // Standard click operation timeout
  CLICK_TIMEOUT_BUFFER: 1000,     // Click timeout safety buffer
  NAVIGATION_TIMEOUT: 15000,      // Standard navigation timeout
  NAVIGATION_TIMEOUT_BUFFER: 2000, // Navigation timeout safety buffer
  ADAPTIVE_TIMEOUT_WITH_INDICATORS: 25000,    // Adaptive timeout when indicators found + explicit config
  ADAPTIVE_TIMEOUT_WITHOUT_INDICATORS: 20000, // Adaptive timeout with explicit config only
  ADAPTIVE_TIMEOUT_AUTO_WITH_INDICATORS: 15000,   // Adaptive timeout for auto-detected with indicators
  ADAPTIVE_TIMEOUT_AUTO_WITHOUT_INDICATORS: 10000, // Adaptive timeout for auto-detected without indicators
  // New timeouts for enhanced functionality
  RETRY_DELAY: 1000,              // Delay between retry attempts
  MAX_RETRIES: 3,                 // Maximum retry attempts for operations
  CHALLENGE_POLL_INTERVAL: 500,   // Interval for polling challenge completion
  CHALLENGE_MAX_POLLS: 20         // Maximum polling attempts
};

// Fast timeout constants - optimized for speed
const FAST_TIMEOUTS = {
  QUICK_DETECTION: 2000,           // Fast Cloudflare detection
  PHISHING_WAIT: 1000,            // Fast phishing check
  CHALLENGE_WAIT: 500,            // Fast challenge detection
  ELEMENT_INTERACTION_DELAY: 250, // Fast element interactions
  SELECTOR_WAIT: 1500,            // Fast selector waits
  TURNSTILE_OPERATION: 6000,      // Fast Turnstile operations
  JS_CHALLENGE: 12000,            // Fast JS challenge completion
  CHALLENGE_SOLVING: 15000,       // Fast overall challenge solving
  CHALLENGE_COMPLETION: 3000      // Fast completion check
};

/**
 * Error categories for better handling
 */
const ERROR_TYPES = {
  NETWORK: 'network',
  TIMEOUT: 'timeout',
  ELEMENT_NOT_FOUND: 'element_not_found',
  EVALUATION_FAILED: 'evaluation_failed',
  NAVIGATION_FAILED: 'navigation_failed',
  UNKNOWN: 'unknown'
};

/**
 * Gets the retry configuration for a site, merging site-specific and global settings
 * @param {Object} siteConfig - Site configuration object
 * @returns {Object} Merged retry configuration
 */
function getRetryConfig(siteConfig) {
  return {
    maxAttempts: siteConfig.cloudflare_max_retries || RETRY_CONFIG.maxAttempts,
    baseDelay: RETRY_CONFIG.baseDelay,
    maxDelay: RETRY_CONFIG.maxDelay,
    backoffMultiplier: RETRY_CONFIG.backoffMultiplier,
    retryableErrors: RETRY_CONFIG.retryableErrors,
    retryOnError: siteConfig.cloudflare_retry_on_error !== false // Default to true
  };
}

/**
 * Detects if we're in a challenge redirect loop by checking URL patterns
 */
function detectChallengeLoop(url, previousUrls = []) {
  // Check if current URL contains challenge indicators and we've seen similar URLs
  const isChallengeUrl = url.includes('/cdn-cgi/challenge-platform/') ||
                        url.includes('challenges.cloudflare.com') ||
                        url.includes('cf-ray');
  
  if (!isChallengeUrl) return false;
  
  // Check if we've seen this exact URL or very similar challenge URLs
  const similarUrls = previousUrls.filter(prevUrl => {
    if (prevUrl === url) return true; // Exact match
    // Check for similar challenge URLs with different ray IDs
    if (prevUrl.includes('/cdn-cgi/challenge-platform/') && url.includes('/cdn-cgi/challenge-platform/')) {
      return true;
    }
    return false;
  });
  
  return similarUrls.length >= 2; // Loop detected if we've seen similar URLs 2+ times
}

/**
 * Retry configuration with exponential backoff
 */
const RETRY_CONFIG = {
  maxAttempts: 3,
  baseDelay: 1000,
  maxDelay: 8000,
  backoffMultiplier: 2,
  retryableErrors: [ERROR_TYPES.NETWORK, ERROR_TYPES.TIMEOUT, ERROR_TYPES.ELEMENT_NOT_FOUND]
};

/**
 * Performance cache for detection results
 * Stores detection results per domain to avoid redundant checks
 */
class CloudflareDetectionCache {
  constructor(ttl = 300000) { // 5 minutes TTL by default
    this.cache = new Map();
    this.ttl = ttl;
    this.hits = 0;
    this.misses = 0;
  }

  getCacheKey(url) {
    try {
      const urlObj = new URL(url);
      return `${urlObj.hostname}${urlObj.pathname}`;
    } catch {
      return url;
    }
  }

  get(url) {
    const key = this.getCacheKey(url);
    const cached = this.cache.get(key);
    
    if (cached && Date.now() - cached.timestamp < this.ttl) {
      this.hits++;
      return cached.data;
    }
    
    if (cached) {
      this.cache.delete(key); // Remove expired entry
    }
    
    this.misses++;
    return null;
  }

  set(url, data) {
    const key = this.getCacheKey(url);
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
    
    // Prevent cache from growing too large
    if (this.cache.size > 1000) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
  }

  clear() {
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
  }

  getStats() {
    const total = this.hits + this.misses;
    return {
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? (this.hits / total * 100).toFixed(2) + '%' : '0%',
      size: this.cache.size
    };
  }
}

// Initialize cache singleton
const detectionCache = new CloudflareDetectionCache();

/**
 * Gets module version information
 * @returns {object} Version information object
 */
function getModuleInfo() {
  return {
    version: CLOUDFLARE_MODULE_VERSION,
    name: 'Cloudflare Protection Handler'
  };
}

/**
 * Validates if a URL should be processed by Cloudflare protection
 * Only allows HTTP/HTTPS URLs, skips browser-internal and special protocols
 * @param {string} url - URL to validate
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {boolean} True if URL should be processed
 */
function shouldProcessUrl(url, forceDebug = false) {
  if (!url || typeof url !== 'string') {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `[url-validation] Skipping invalid URL: ${url}`));
    return false;
  }

  // Skip browser-internal and special protocol URLs
  const skipPatterns = [
    'about:', 'chrome:', 'chrome-extension:', 'chrome-error:', 'chrome-search:',
    'devtools:', 'edge:', 'moz-extension:', 'safari-extension:', 'webkit:',
    'data:', 'blob:', 'javascript:', 'vbscript:', 'file:', 'ftp:', 'ftps:'
  ];

  const urlLower = url.toLowerCase();
  for (const pattern of skipPatterns) {
    if (urlLower.startsWith(pattern)) {
      if (forceDebug) {
        console.log(formatLogMessage('cloudflare', `[url-validation] Skipping ${pattern} URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`));
      }
      return false;
    }
  }

  // Only process HTTP/HTTPS URLs
  if (!urlLower.startsWith('http://') && !urlLower.startsWith('https://')) {
    if (forceDebug) {
      console.log(formatLogMessage('cloudflare', `[url-validation] Skipping non-HTTP(S) URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`));
    }
    return false;
  }

  return true;
}

/**
 * Fast timeout helper for Puppeteer 22.x compatibility 
 * Replaces deprecated page.waitForTimeout() with standard Promise-based approach
 */
async function waitForTimeout(page, timeout) {
  // Use fast Promise-based timeout for Puppeteer 22.x compatibility
  // This eliminates the deprecated API dependency and improves performance
  return new Promise(resolve => setTimeout(resolve, timeout));
}

/**
 * Categorizes errors for better handling
 */
function categorizeError(error) {
  const errorMessage = error.message || '';
  
  if (errorMessage.includes('timeout') || errorMessage.includes('Timeout')) {
    return ERROR_TYPES.TIMEOUT;
  }
  if (errorMessage.includes('Protocol error') || errorMessage.includes('Target closed')) {
    return ERROR_TYPES.NETWORK;
  }
  if (errorMessage.includes('evaluation') || errorMessage.includes('Evaluation')) {
    return ERROR_TYPES.EVALUATION_FAILED;
  }
  if (errorMessage.includes('navigation') || errorMessage.includes('Navigation')) {
    return ERROR_TYPES.NAVIGATION_FAILED;
  }
  
  return ERROR_TYPES.UNKNOWN;
}

/**
 * Implements exponential backoff delay
 */
async function getRetryDelay(attempt) {
  const delay = Math.min(
    RETRY_CONFIG.baseDelay * Math.pow(RETRY_CONFIG.backoffMultiplier, attempt - 1),
    RETRY_CONFIG.maxDelay
  );
  return new Promise(resolve => setTimeout(resolve, delay));
}

/**
 * Enhanced safe page evaluation with retry logic and better error handling
 */
async function safePageEvaluate(page, func, timeout = TIMEOUTS.PAGE_EVALUATION_SAFE, options = {}) {
  const { maxRetries = RETRY_CONFIG.maxAttempts, forceDebug = false } = options;
  let lastError = null;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const result = await Promise.race([
        page.evaluate(func),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Page evaluation timeout')), timeout)
        )
      ]);
      
      if (forceDebug && attempt > 1) {
        console.log(formatLogMessage('cloudflare', `Page evaluation succeeded on attempt ${attempt}`));
      }
      
      return result;
    } catch (error) {
      lastError = error;
      const errorType = categorizeError(error);
      
      if (forceDebug) {
        console.warn(formatLogMessage('cloudflare', `Page evaluation failed (attempt ${attempt}/${maxRetries}): ${error.message} [${errorType}]`));
      }
      
      // Don't retry if error type is not retryable or if it's the last attempt
      if (!RETRY_CONFIG.retryableErrors.includes(errorType) || attempt === maxRetries) {
        return {
          isChallengePresent: false,
          isPhishingWarning: false,
          isTurnstile: false,
          isJSChallenge: false,
          isChallengeCompleted: false,
          error: error.message,
          errorType: errorType,
          attempts: attempt
        };
      }
      
      // Wait before retrying with exponential backoff
      await getRetryDelay(attempt);
    }
  }
  
  return {
    isChallengePresent: false,
    isPhishingWarning: false,
    isTurnstile: false,
    isJSChallenge: false,
    isChallengeCompleted: false,
    error: lastError?.message || 'Unknown error',
    errorType: categorizeError(lastError),
    attempts: maxRetries
  };
}

/**
 * Safe element clicking with timeout protection
 */
async function safeClick(page, selector, timeout = TIMEOUTS.CLICK_TIMEOUT) {
  try {
    return await Promise.race([
      page.click(selector, { timeout: timeout }),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Click timeout')), timeout + TIMEOUTS.CLICK_TIMEOUT_BUFFER)
      )
    ]);
  } catch (error) {
    throw new Error(`Click failed: ${error.message}`);
  }
}

/**
 * Safe navigation waiting with timeout protection
 */
async function safeWaitForNavigation(page, timeout = TIMEOUTS.NAVIGATION_TIMEOUT) {
  try {
    return await Promise.race([
      page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: timeout }),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Navigation timeout')), timeout + TIMEOUTS.NAVIGATION_TIMEOUT_BUFFER)
      )
    ]);
  } catch (error) {
    console.warn(formatLogMessage('cloudflare', `Navigation wait failed: ${error.message}`));
    // Don't throw - just continue
  }
}

/**
 * Quick Cloudflare detection with caching for performance
 */
async function quickCloudflareDetection(page, forceDebug = false) {
  try {
    // Get current page URL and validate it
    const currentPageUrl = await page.url();
    
    if (!shouldProcessUrl(currentPageUrl, forceDebug)) {
      if (forceDebug) {
        console.log(formatLogMessage('cloudflare', `Quick detection skipping non-HTTP(S) page: ${currentPageUrl}`));
      }
      return { hasIndicators: false, skippedInvalidUrl: true };
    }

    // Check cache first
    const cachedResult = detectionCache.get(currentPageUrl);
    if (cachedResult !== null) {
      if (forceDebug) {
        const stats = detectionCache.getStats();
        console.log(formatLogMessage('cloudflare', `Using cached detection result (cache hit rate: ${stats.hitRate})`));
      }
      return cachedResult;
    }

    // Perform actual detection with enhanced error handling
    const quickCheck = await safePageEvaluate(page, () => {
      const title = document.title || '';
      const bodyText = document.body ? document.body.textContent.substring(0, 500) : '';
      const url = window.location.href;
      
      // Enhanced indicators with 2025 patterns
      const hasCloudflareIndicators = 
        title.includes('Just a moment') ||
        title.includes('Checking your browser') ||
        title.includes('Attention Required') ||
        title.includes('Security check') || // New pattern
        bodyText.includes('Cloudflare') ||
        bodyText.includes('cf-ray') ||
        bodyText.includes('Verify you are human') ||
        bodyText.includes('This website has been reported for potential phishing') ||
        bodyText.includes('Please wait while we verify') ||
        bodyText.includes('Checking if the site connection is secure') || // New pattern
        url.includes('/cdn-cgi/challenge-platform/') ||
        url.includes('cloudflare.com') ||
        document.querySelector('[data-ray]') ||
        document.querySelector('[data-cf-challenge]') ||
        document.querySelector('.cf-challenge-running') ||
        document.querySelector('.cf-challenge-container') ||
        document.querySelector('.cf-turnstile') ||
        document.querySelector('.ctp-checkbox-container') ||
        document.querySelector('iframe[src*="challenges.cloudflare.com"]') ||
        document.querySelector('iframe[title*="Cloudflare security challenge"]') ||
        document.querySelector('script[src*="/cdn-cgi/challenge-platform/"]') ||
        document.querySelector('a[href*="continue"]') ||
        // New selectors for 2025
        document.querySelector('.cf-managed-challenge') ||
        document.querySelector('[data-cf-managed]');
      
      return {
        hasIndicators: hasCloudflareIndicators,
        title,
        url,
        bodySnippet: bodyText.substring(0, 200)
      };
    }, FAST_TIMEOUTS.QUICK_DETECTION, { maxRetries: 2, forceDebug });
    
    // Cache the result
    detectionCache.set(currentPageUrl, quickCheck);
    
    if (forceDebug) {
      if (quickCheck.hasIndicators) {
        console.log(formatLogMessage('cloudflare', `Quick detection found Cloudflare indicators on ${quickCheck.url}`));
      } else {
        console.log(formatLogMessage('cloudflare', `Quick detection found no Cloudflare indicators on ${quickCheck.url}`));
      }
      
      if (quickCheck.attempts && quickCheck.attempts > 1) {
        console.log(formatLogMessage('cloudflare', `Detection required ${quickCheck.attempts} attempts`));
      }
    }
    
    return quickCheck;
  } catch (error) {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Quick detection failed: ${error.message}`));
    return { hasIndicators: false, error: error.message };
  }
}

/**
 * Analyzes the current page to detect Cloudflare challenges - Enhanced with timeout protection and detailed debug logging
 */
async function analyzeCloudflareChallenge(page) {
  try {
    return await safePageEvaluate(page, () => {
      const title = document.title || '';
      const bodyText = document.body ? document.body.textContent : '';
      
      // Updated selectors for 2025 Cloudflare challenges
      const hasTurnstileIframe = document.querySelector('iframe[title*="Cloudflare security challenge"]') !== null ||
                                 document.querySelector('iframe[src*="challenges.cloudflare.com"]') !== null ||
                                 document.querySelector('iframe[title*="Widget containing a Cloudflare"]') !== null;
      
      const hasTurnstileContainer = document.querySelector('.cf-turnstile') !== null ||
                                   document.querySelector('.ctp-checkbox-container') !== null ||
                                   document.querySelector('.ctp-checkbox-label') !== null;
      
      const hasTurnstileCheckbox = document.querySelector('input[type="checkbox"].ctp-checkbox') !== null ||
                                  document.querySelector('.ctp-checkbox') !== null;
      
      const hasLegacyCheckbox = document.querySelector('input[type="checkbox"]#challenge-form') !== null ||
                               document.querySelector('input[type="checkbox"][name="cf_captcha_kind"]') !== null;
      
      const hasChallengeRunning = document.querySelector('.cf-challenge-running') !== null ||
                                 document.querySelector('.cf-challenge-container') !== null ||
                                 document.querySelector('.challenge-stage') !== null ||
                                 document.querySelector('.challenge-form') !== null;
      
      const hasDataRay = document.querySelector('[data-ray]') !== null ||
                        document.querySelector('[data-cf-challenge]') !== null;
      
      const hasCaptcha = bodyText.includes('CAPTCHA') || bodyText.includes('captcha') ||
                        bodyText.includes('hCaptcha') || bodyText.includes('reCAPTCHA');
      
      const hasJSChallenge = document.querySelector('script[src*="/cdn-cgi/challenge-platform/"]') !== null ||
                            bodyText.includes('Checking your browser') ||
                            bodyText.includes('Please wait while we verify');
      
      const hasPhishingWarning = bodyText.includes('This website has been reported for potential phishing') ||
                                title.includes('Attention Required') ||
                                document.querySelector('a[href*="continue"]') !== null;
      
      const hasTurnstileResponse = document.querySelector('input[name="cf-turnstile-response"]') !== null;
      
      const isChallengeCompleted = hasTurnstileResponse && 
                                  document.querySelector('input[name="cf-turnstile-response"]')?.value;
      
      const isChallengePresent = title.includes('Just a moment') ||
                               title.includes('Checking your browser') ||
                               bodyText.includes('Verify you are human') ||
                               hasLegacyCheckbox || 
                               hasChallengeRunning || 
                               hasDataRay ||
                               hasTurnstileIframe ||
                               hasTurnstileContainer ||
                               hasJSChallenge;
      
      return {
        isChallengePresent,
        isPhishingWarning: hasPhishingWarning,
        isTurnstile: hasTurnstileIframe || hasTurnstileContainer || hasTurnstileCheckbox,
        isJSChallenge: hasJSChallenge,
        isChallengeCompleted,
        title,
        hasLegacyCheckbox,
        hasTurnstileIframe,
        hasTurnstileContainer,
        hasTurnstileCheckbox,
        hasChallengeRunning,
        hasDataRay,
        hasCaptcha,
        hasTurnstileResponse,
        url: window.location.href,
        bodySnippet: bodyText.substring(0, 200)
      };
    }, TIMEOUTS.PAGE_EVALUATION);
  } catch (error) {
    return {
      isChallengePresent: false,
      isPhishingWarning: false,
      isTurnstile: false,
      isJSChallenge: false,
      isChallengeCompleted: false,
      error: error.message
    };
  }
}

/**
 * Handles Cloudflare phishing warnings with timeout protection and enhanced debug logging
 * 
 * @param {Object} page - Puppeteer page instance
 * @param {string} currentUrl - URL being processed  
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Promise<Object>} Phishing warning result:
 * {
 *   success: boolean,    // True if no warning found OR successfully bypassed
 *   attempted: boolean,  // True if warning was detected and bypass attempted
 *   error: string|null,  // Error message if bypass failed
 *   details: object|null // Analysis details from analyzeCloudflareChallenge()
 * }
 */
async function handlePhishingWarning(page, currentUrl, forceDebug = false) {
  const result = {
    success: false,
    attempted: false,
    error: null,
    details: null
  };

  try {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Checking for phishing warning on ${currentUrl}`));
    
    // Shorter wait with timeout protection
    await waitForTimeout(page, FAST_TIMEOUTS.PHISHING_WAIT);

    const challengeInfo = await analyzeCloudflareChallenge(page);
    
    if (challengeInfo.isPhishingWarning) {
      result.attempted = true;
      result.details = challengeInfo;
      
      if (forceDebug) {
        console.log(formatLogMessage('cloudflare', `Phishing warning detected on ${currentUrl}:`));
        console.log(formatLogMessage('cloudflare', `  Page Title: "${challengeInfo.title}"`));
        console.log(formatLogMessage('cloudflare', `  Current URL: ${challengeInfo.url}`));
        console.log(formatLogMessage('cloudflare', `  Body snippet: ${challengeInfo.bodySnippet}`));
      }

      try {
        // Use safe click with shorter timeout
        await safeClick(page, 'a[href*="continue"]', TIMEOUTS.PHISHING_CLICK);
        await safeWaitForNavigation(page, TIMEOUTS.PHISHING_NAVIGATION);
        
        result.success = true;
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Successfully bypassed phishing warning for ${currentUrl}`));
      } catch (clickError) {
        result.error = `Failed to click continue button: ${clickError.message}`;
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Failed to bypass phishing warning: ${clickError.message}`));
      }
    } else {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `No phishing warning detected on ${currentUrl}`));
      result.success = true; // No warning to handle
    }
  } catch (error) {
    result.error = error.message;
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Phishing warning check failed for ${currentUrl}: ${error.message}`));
  }

  return result;
}

/**
 * Attempts to solve Cloudflare challenges with timeout protection and enhanced debug logging
 * 
 * @param {Object} page - Puppeteer page instance
 * @param {string} currentUrl - URL being processed
 * @param {boolean} forceDebug - Debug logging flag  
 * @returns {Promise<Object>} Challenge verification result:
 * {
 *   success: boolean,        // True if no challenge found OR successfully solved
 *   attempted: boolean,      // True if challenge was detected and solving attempted
 *   error: string|null,      // Error message if solving failed
 *   requiresHuman: boolean,  // True if CAPTCHA detected (requires manual intervention)
 *   method: string|null,     // Method that succeeded: 'js_challenge_wait', 'turnstile', 'legacy_checkbox'
 *   details: object|null     // Analysis details from analyzeCloudflareChallenge()
 * }
 */
async function handleVerificationChallenge(page, currentUrl, forceDebug = false) {
  const result = {
    success: false,
    attempted: false,
    error: null,
    details: null,
    requiresHuman: false,
    method: null
  };

  try {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Checking for verification challenge on ${currentUrl}`));
    
    // Reduced wait time
    await waitForTimeout(page, FAST_TIMEOUTS.CHALLENGE_WAIT);

    const challengeInfo = await analyzeCloudflareChallenge(page);
    result.details = challengeInfo;

    if (challengeInfo.isChallengePresent) {
      result.attempted = true;
      
      if (forceDebug) {
        console.log(formatLogMessage('cloudflare', `Challenge detected on ${currentUrl}:`));
        console.log(formatLogMessage('cloudflare', `  Page Title: "${challengeInfo.title}"`));
        console.log(formatLogMessage('cloudflare', `  Current URL: ${challengeInfo.url}`));
        console.log(formatLogMessage('cloudflare', `  Is Turnstile: ${challengeInfo.isTurnstile}`));
        console.log(formatLogMessage('cloudflare', `  Is JS Challenge: ${challengeInfo.isJSChallenge}`));
        console.log(formatLogMessage('cloudflare', `  Has Legacy Checkbox: ${challengeInfo.hasLegacyCheckbox}`));
        console.log(formatLogMessage('cloudflare', `  Has Turnstile Iframe: ${challengeInfo.hasTurnstileIframe}`));
        console.log(formatLogMessage('cloudflare', `  Has Turnstile Container: ${challengeInfo.hasTurnstileContainer}`));
        console.log(formatLogMessage('cloudflare', `  Has Turnstile Checkbox: ${challengeInfo.hasTurnstileCheckbox}`));
        console.log(formatLogMessage('cloudflare', `  Has CAPTCHA: ${challengeInfo.hasCaptcha}`));
        console.log(formatLogMessage('cloudflare', `  Has Challenge Running: ${challengeInfo.hasChallengeRunning}`));
        console.log(formatLogMessage('cloudflare', `  Has Data Ray: ${challengeInfo.hasDataRay}`));
        console.log(formatLogMessage('cloudflare', `  Has Turnstile Response: ${challengeInfo.hasTurnstileResponse}`));
        console.log(formatLogMessage('cloudflare', `  Body snippet: ${challengeInfo.bodySnippet}`));
      }

      // Check for CAPTCHA that requires human intervention
      if (challengeInfo.hasCaptcha) {
        result.requiresHuman = true;
        result.error = 'CAPTCHA detected - requires human intervention';
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Skipping automatic bypass due to CAPTCHA requirement`));
        return result;
      }

      // Attempt to solve the challenge with timeout protection
      const solveResult = await attemptChallengeSolveWithTimeout(page, currentUrl, challengeInfo, forceDebug);
      result.success = solveResult.success;
      result.error = solveResult.error;
      result.method = solveResult.method;
      
    } else {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `No verification challenge detected on ${currentUrl}`));
      result.success = true;
    }
  } catch (error) {
    result.error = error.message;
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Challenge check failed for ${currentUrl}: ${error.message}`));
  }

  return result;
}

/**
 * Enhanced challenge handling with retry logic and loop detection
 */
async function handleVerificationChallengeWithRetries(page, currentUrl, siteConfig, forceDebug = false) {
  const retryConfig = getRetryConfig(siteConfig);
  const visitedUrls = []; // Track URLs to detect redirect loops
  let lastError = null;
  
  if (forceDebug) {
    console.log(formatLogMessage('cloudflare', `Starting verification challenge with max ${retryConfig.maxAttempts} attempts`));
  }
  
  for (let attempt = 1; attempt <= retryConfig.maxAttempts; attempt++) {
    try {
      const currentPageUrl = await page.url();
      visitedUrls.push(currentPageUrl);
      
      // Check for redirect loops
      if (detectChallengeLoop(currentPageUrl, visitedUrls)) {
        const error = `Challenge redirect loop detected after ${attempt} attempts. URLs: ${visitedUrls.slice(-3).join(' -> ')}`;
        if (forceDebug) {
          console.log(formatLogMessage('cloudflare', error));
        }
        return {
          success: false,
          attempted: true,
          error: error,
          details: null,
          requiresHuman: false,
          method: null,
          attempts: attempt,
          loopDetected: true
        };
      }
      
      if (forceDebug && attempt > 1) {
        console.log(formatLogMessage('cloudflare', `Challenge attempt ${attempt}/${retryConfig.maxAttempts} for ${currentUrl}`));
      }
      
      const result = await handleVerificationChallenge(page, currentUrl, forceDebug);
      
      if (result.success || result.requiresHuman || !retryConfig.retryOnError) {
        if (forceDebug && attempt > 1) {
          console.log(`[debug][cloudflare] Challenge ${result.success ? 'succeeded' : 'failed'} on attempt ${attempt}`);
        }
        return { ...result, attempts: attempt };
      }
      
      // If this wasn't the last attempt, wait before retrying
      if (attempt < retryConfig.maxAttempts) {
        const delay = await getRetryDelay(attempt);
        if (forceDebug) {
          console.log(formatLogMessage('cloudflare', `Challenge attempt ${attempt} failed, retrying in ${delay}ms: ${result.error}`));
        }
        await new Promise(resolve => setTimeout(resolve, delay));
        
        // Refresh the page to get a fresh challenge
        try {
          await page.reload({ waitUntil: 'domcontentloaded', timeout: 10000 });
          await waitForTimeout(page, 2000); // Give challenge time to load
        } catch (reloadErr) {
          if (forceDebug) {
            console.log(formatLogMessage('cloudflare', `Page reload failed on attempt ${attempt}: ${reloadErr.message}`));
          }
        }
      }
      
      lastError = result.error;
    } catch (error) {
      lastError = error.message;
      const errorType = categorizeError(error);
      
      if (forceDebug) {
        console.warn(formatLogMessage('cloudflare', `Challenge attempt ${attempt}/${retryConfig.maxAttempts} failed: ${error.message} [${errorType}]`));
      }
      
      // Don't retry if error type is not retryable or if it's the last attempt
      if (!retryConfig.retryableErrors.includes(errorType) || attempt === retryConfig.maxAttempts) {
        return {
          success: false,
          attempted: true,
          error: lastError,
          details: null,
          requiresHuman: false,
          method: null,
          attempts: attempt,
          errorType: errorType
        };
      }
      
      // Wait before retrying with exponential backoff
      if (attempt < retryConfig.maxAttempts) {
        await getRetryDelay(attempt);
      }
    }
  }
  
  return {
    success: false,
    attempted: true,
    error: `All ${retryConfig.maxAttempts} challenge attempts failed. Last error: ${lastError}`,
    details: null,
    requiresHuman: false,
    method: null,
    attempts: retryConfig.maxAttempts,
    maxRetriesExceeded: true
  };
}

/**
 * Enhanced phishing warning handling with retry logic
 */
async function handlePhishingWarningWithRetries(page, currentUrl, siteConfig, forceDebug = false) {
  const retryConfig = getRetryConfig(siteConfig);
  let lastError = null;
  
  for (let attempt = 1; attempt <= retryConfig.maxAttempts; attempt++) {
    try {
      if (forceDebug && attempt > 1) {
        console.log(formatLogMessage('cloudflare', `Phishing warning attempt ${attempt}/${retryConfig.maxAttempts} for ${currentUrl}`));
      }
      
      const result = await handlePhishingWarning(page, currentUrl, forceDebug);
      
      if (result.success || !retryConfig.retryOnError) {
        if (forceDebug && attempt > 1) {
          console.log(`[debug][cloudflare] Phishing warning ${result.success ? 'succeeded' : 'failed'} on attempt ${attempt}`);
        }
        return { ...result, attempts: attempt };
      }
      
      // If this wasn't the last attempt, wait before retrying
      if (attempt < retryConfig.maxAttempts) {
        const delay = await getRetryDelay(attempt);
        if (forceDebug) {
          console.log(formatLogMessage('cloudflare', `Phishing warning attempt ${attempt} failed, retrying in ${delay}ms: ${result.error}`));
        }
        await new Promise(resolve => setTimeout(resolve, delay));
      }
      
      lastError = result.error;
    } catch (error) {
      lastError = error.message;
      const errorType = categorizeError(error);
      
      if (forceDebug) {
        console.warn(formatLogMessage('cloudflare', `Phishing warning attempt ${attempt}/${retryConfig.maxAttempts} failed: ${error.message} [${errorType}]`));
      }
      
      // Don't retry if error type is not retryable or if it's the last attempt
      if (!retryConfig.retryableErrors.includes(errorType) || attempt === retryConfig.maxAttempts) {
        return {
          success: false,
          attempted: true,
          error: lastError,
          details: null,
          attempts: attempt,
          errorType: errorType
        };
      }
      
      // Wait before retrying with exponential backoff
      if (attempt < retryConfig.maxAttempts) {
        await getRetryDelay(attempt);
      }
    }
  }
  
  return {
    success: false,
    attempted: true,
    error: `All ${retryConfig.maxAttempts} phishing warning attempts failed. Last error: ${lastError}`,
    details: null,
    attempts: retryConfig.maxAttempts,
    maxRetriesExceeded: true
  };
}


/**
 * Challenge solving with overall timeout protection
 */
async function attemptChallengeSolveWithTimeout(page, currentUrl, challengeInfo, forceDebug = false) {
  const result = {
    success: false,
    error: null,
    method: null
  };

  try {
    // Reduced timeout for challenge solving
    return await Promise.race([
      attemptChallengeSolve(page, currentUrl, challengeInfo, forceDebug),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Challenge solving timeout')), FAST_TIMEOUTS.CHALLENGE_SOLVING)
      )
    ]);
  } catch (error) {
    result.error = `Challenge solving timed out: ${error.message}`;
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Challenge solving timeout for ${currentUrl}`));
    return result;
  }
}

/**
 * Attempts to solve a Cloudflare challenge with modern techniques and enhanced debug logging
 */
async function attemptChallengeSolve(page, currentUrl, challengeInfo, forceDebug = false) {
  const result = {
    success: false,
    error: null,
    method: null
  };

  // Method 1: Handle JS challenges (wait for automatic completion) - Most reliable
  if (challengeInfo.isJSChallenge) {
    try {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Attempting JS challenge wait for ${currentUrl}`));
      
      const jsResult = await waitForJSChallengeCompletion(page, forceDebug);
      if (jsResult.success) {
        result.success = true;
        result.method = 'js_challenge_wait';
        if (forceDebug) console.log(formatLogMessage('cloudflare', `JS challenge completed successfully for ${currentUrl}`));
        return result;
      }
    } catch (jsError) {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `JS challenge wait failed for ${currentUrl}: ${jsError.message}`));
    }
  }

  // Method 2: Handle Turnstile challenges (interactive)
  if (challengeInfo.isTurnstile) {
    try {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Attempting Turnstile method for ${currentUrl}`));
      
      const turnstileResult = await handleTurnstileChallenge(page, forceDebug);
      if (turnstileResult.success) {
        result.success = true;
        result.method = 'turnstile';
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Turnstile challenge solved successfully for ${currentUrl}`));
        return result;
      }
    } catch (turnstileError) {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Turnstile method failed for ${currentUrl}: ${turnstileError.message}`));
    }
  }

  // Method 3: Legacy checkbox interaction (fallback)
  if (challengeInfo.hasLegacyCheckbox) {
    try {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Attempting legacy checkbox method for ${currentUrl}`));
      
      const legacyResult = await handleLegacyCheckbox(page, forceDebug);
      if (legacyResult.success) {
        result.success = true;
        result.method = 'legacy_checkbox';
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Legacy checkbox method succeeded for ${currentUrl}`));
        return result;
      }
    } catch (legacyError) {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Legacy checkbox method failed for ${currentUrl}: ${legacyError.message}`));
    }
  }

  if (!result.success) {
    result.error = result.error || 'All challenge bypass methods failed';
  }

  return result;
}

 /**
 * Enhanced embedded iframe challenge detection and interaction
 */
async function handleEmbeddedIframeChallenge(page, forceDebug = false) {
  const result = {
    success: false,
    error: null
  };

  try {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Checking for embedded iframe challenges`));

    // Enhanced iframe selectors including challenges.cloudflare.com
    const iframeSelectors = [
      'iframe[src*="challenges.cloudflare.com"]',
      'iframe[title*="Verify you are human"]',
      'iframe[title*="Cloudflare security challenge"]',
      'iframe[title*="Widget containing a Cloudflare"]'
    ];

    // Wait for iframe to appear
    let iframeFound = false;
    for (const selector of iframeSelectors) {
      try {
        await Promise.race([
          page.waitForSelector(selector, { timeout: FAST_TIMEOUTS.SELECTOR_WAIT }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), FAST_TIMEOUTS.SELECTOR_WAIT + 1000))
        ]);
        iframeFound = true;
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Found iframe: ${selector}`));
        break;
      } catch (e) {
        continue;
      }
    }

    if (!iframeFound) {
      result.error = 'No embedded iframe found';
      return result;
    }

    // Find challenge frame using existing frame detection logic
    const frames = await page.frames();
    const challengeFrame = frames.find(frame => {
      const frameUrl = frame.url();
      return frameUrl.includes('challenges.cloudflare.com') ||
             frameUrl.includes('/turnstile/if/') ||
             frameUrl.includes('captcha-delivery.com') ||
             frameUrl.includes('/challenge-platform/') ||
             frameUrl.includes('turnstile');
    });

    if (!challengeFrame) {
      result.error = 'Challenge iframe not accessible';
      return result;
    }

    if (forceDebug) console.log(formatLogMessage('cloudflare', `Interacting with iframe: ${challengeFrame.url()}`));

    // Reuse existing checkbox interaction logic
    const checkboxSelectors = [
      'input[type="checkbox"]',
      '.ctp-checkbox',
      'input.ctp-checkbox',
      '.cf-turnstile input',
      '.ctp-checkbox-label'
    ];
    
    let checkboxInteractionSuccess = false;
    for (const selector of checkboxSelectors) {
      try {
        await Promise.race([
          challengeFrame.waitForSelector(selector, { timeout: FAST_TIMEOUTS.SELECTOR_WAIT }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), FAST_TIMEOUTS.SELECTOR_WAIT + 1000))
        ]);
        
        await waitForTimeout(page, FAST_TIMEOUTS.ELEMENT_INTERACTION_DELAY);
        await challengeFrame.click(selector);
        
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Clicked iframe element: ${selector}`));
        checkboxInteractionSuccess = true;
        break;
      } catch (e) {
        continue;
      }
    }

    // Try alternative interaction only if standard selectors failed
    if (!checkboxInteractionSuccess) {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Checkbox interactions failed, trying container fallback`));
      await waitForTimeout(page, 1000);

      try {
        // Try clicking on the iframe container itself as fallback
        const iframeElement = await page.$('iframe[src*="challenges.cloudflare.com"]');
        if (iframeElement) {
          await iframeElement.click();
          if (forceDebug) console.log(formatLogMessage('cloudflare', `Clicked iframe container as fallback`));
        }
      } catch (containerClickError) {
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Container click failed: ${containerClickError.message}`));
      }
    } else {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Checkbox interaction successful, skipping container fallback`));
    }

    // Reuse existing completion check pattern with error handling
    try {
      await Promise.race([
        page.waitForFunction(
          () => {
            const responseInput = document.querySelector('input[name="cf-turnstile-response"]');
            const hasResponse = responseInput && responseInput.value && responseInput.value.length > 0;
            const hasClearance = document.cookie.includes('cf_clearance');
            const noChallenge = !document.body.textContent.includes('Verify you are human');
            
            return hasResponse || hasClearance || noChallenge;
          },
          { timeout: TIMEOUTS.TURNSTILE_COMPLETION }
        ),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Completion check timeout')), TIMEOUTS.TURNSTILE_COMPLETION_BUFFER))
      ]);

      result.success = true;
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Embedded iframe challenge completed`));
    } catch (completionError) {
      result.error = `Challenge completion check failed: ${completionError.message}`;
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Completion check failed: ${completionError.message}`));
    }

  } catch (error) {
    result.error = `Embedded iframe handling failed: ${error.message}`;
    if (forceDebug) console.log(formatLogMessage('cloudflare', result.error));
  }

  return result;
}

/**
 * Waits for JS challenge completion with timeout protection and enhanced debug logging
 */
async function waitForJSChallengeCompletion(page, forceDebug = false) {
  const result = {
    success: false,
    error: null
  };

  try {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Waiting for JS challenge completion`));
    
    // Reduced timeout for JS challenge completion
    await Promise.race([
      page.waitForFunction(
        () => {
          return !document.body.textContent.includes('Checking your browser') &&
                 !document.body.textContent.includes('Please wait while we verify') &&
                 !document.querySelector('.cf-challenge-running') &&
                 !document.querySelector('[data-cf-challenge]');
        },
        { timeout: FAST_TIMEOUTS.JS_CHALLENGE }
      ),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('JS challenge timeout')), TIMEOUTS.JS_CHALLENGE_BUFFER)
      )
    ]);
    
    result.success = true;
    if (forceDebug) console.log(formatLogMessage('cloudflare', `JS challenge completed automatically`));
  } catch (error) {
    result.error = `JS challenge timeout: ${error.message}`;
    if (forceDebug) console.log(formatLogMessage('cloudflare', `JS challenge wait failed: ${error.message}`));
  }

  return result;
}

/**
 * Handles modern Turnstile challenges with timeout protection and enhanced debug logging
 */
async function handleTurnstileChallenge(page, forceDebug = false) {
  const result = {
    success: false,
    error: null
  };

  // Try embedded iframe approach first
  const iframeResult = await handleEmbeddedIframeChallenge(page, forceDebug);
  if (iframeResult.success) {
    return { ...result, success: true };
  }
  
  if (forceDebug) console.log(formatLogMessage('cloudflare', `Embedded iframe failed: ${iframeResult.error}, trying legacy method`));

  try {
    // Use fast timeout for Turnstile operations
    const turnstileTimeout = FAST_TIMEOUTS.TURNSTILE_OPERATION;
    
    const turnstileSelectors = [
      'iframe[src*="challenges.cloudflare.com"]',
      'iframe[title*="Widget containing a Cloudflare"]',
      'iframe[title*="Cloudflare security challenge"]'
    ];
    
    let turnstileFrame = null;
    for (const selector of turnstileSelectors) {
      try {
        await Promise.race([
          page.waitForSelector(selector, { timeout: FAST_TIMEOUTS.SELECTOR_WAIT }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Selector timeout')), FAST_TIMEOUTS.SELECTOR_WAIT + 500))
        ]);
        
        const frames = await page.frames();
        turnstileFrame = frames.find(frame => 
          frame.url().includes('challenges.cloudflare.com') ||
          frame.url().includes('turnstile')
        );
        if (turnstileFrame) {
          if (forceDebug) console.log(formatLogMessage('cloudflare', `Found Turnstile iframe using selector: ${selector}`));
          break;
        }
      } catch (e) {
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Selector ${selector} not found or timed out`));
        continue;
      }
    }

    if (turnstileFrame) {
      if (forceDebug) {
        console.log(formatLogMessage('cloudflare', `Found Turnstile iframe with URL: ${turnstileFrame.url()}`));
      }
      
      const checkboxSelectors = [
        'input[type="checkbox"].ctp-checkbox',
        'input[type="checkbox"]',
        '.ctp-checkbox-label',
        '.ctp-checkbox'
      ];
      
      for (const selector of checkboxSelectors) {
        try {
          await Promise.race([
            turnstileFrame.waitForSelector(selector, { timeout: FAST_TIMEOUTS.SELECTOR_WAIT }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Checkbox timeout')), FAST_TIMEOUTS.SELECTOR_WAIT + 500))
          ]);
          
          await waitForTimeout(page, FAST_TIMEOUTS.ELEMENT_INTERACTION_DELAY);
          await turnstileFrame.click(selector);
          
          if (forceDebug) console.log(formatLogMessage('cloudflare', `Clicked Turnstile checkbox: ${selector}`));
          break;
        } catch (e) {
          if (forceDebug) console.log(formatLogMessage('cloudflare', `Checkbox selector ${selector} not found or failed to click`));
          continue;
        }
      }
      
      // Wait for Turnstile completion with reduced timeout
      await Promise.race([
        page.waitForFunction(
          () => {
            const responseInput = document.querySelector('input[name="cf-turnstile-response"]');
            return responseInput && responseInput.value && responseInput.value.length > 0;
          },
          { timeout: TIMEOUTS.TURNSTILE_COMPLETION }
        ),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Turnstile completion timeout')), TIMEOUTS.TURNSTILE_COMPLETION_BUFFER))
      ]);
      
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Turnstile response token generated successfully`));
      result.success = true;
    } else {
      // Try container-based Turnstile (non-iframe)
      if (forceDebug) console.log(formatLogMessage('cloudflare', `No Turnstile iframe found, trying container-based approach`));
      
      const containerSelectors = [
        '.cf-turnstile',
        '.ctp-checkbox-container',
        '.ctp-checkbox-label'
      ];
      
      for (const selector of containerSelectors) {
        try {
          await Promise.race([
            page.waitForSelector(selector, { timeout: FAST_TIMEOUTS.SELECTOR_WAIT }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Container timeout')), FAST_TIMEOUTS.SELECTOR_WAIT + 500))
          ]);
          
          await waitForTimeout(page, FAST_TIMEOUTS.ELEMENT_INTERACTION_DELAY);
          await page.click(selector);
          
          if (forceDebug) console.log(formatLogMessage('cloudflare', `Clicked Turnstile container: ${selector}`));
          
          const completionCheck = await checkChallengeCompletion(page);
          if (completionCheck.isCompleted) {
            result.success = true;
            if (forceDebug) console.log(formatLogMessage('cloudflare', `Container-based Turnstile completed successfully`));
            break;
          }
        } catch (e) {
          if (forceDebug) console.log(formatLogMessage('cloudflare', `Container selector ${selector} not found or failed`));
          continue;
        }
      }
      
      if (!result.success) {
        result.error = 'Turnstile iframe/container not found or not interactive';
        if (forceDebug) console.log(formatLogMessage('cloudflare', result.error));
      }
    }
    
  } catch (error) {
    result.error = `Turnstile handling failed: ${error.message}`;
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Turnstile handling error: ${error.message}`));
  }

  return result;
}

/**
 * Handles legacy checkbox challenges with timeout protection and enhanced debug logging
 */
async function handleLegacyCheckbox(page, forceDebug = false) {
  const result = {
    success: false,
    error: null
  };

  try {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Attempting legacy checkbox challenge`));
    
    const legacySelectors = [
      'input[type="checkbox"]#challenge-form',
      'input[type="checkbox"][name="cf_captcha_kind"]',
      '.cf-turnstile input[type="checkbox"]'
    ];

    for (const selector of legacySelectors) {
      try {
        await Promise.race([
          page.waitForSelector(selector, { timeout: FAST_TIMEOUTS.SELECTOR_WAIT }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Legacy selector timeout')), FAST_TIMEOUTS.SELECTOR_WAIT + 500))
        ]);
        
        const checkbox = await page.$(selector);
        if (checkbox) {
          await checkbox.click();
          if (forceDebug) console.log(formatLogMessage('cloudflare', `Clicked legacy checkbox: ${selector}`));

          const completionCheck = await checkChallengeCompletion(page);
          if (completionCheck.isCompleted) {
            result.success = true;
            if (forceDebug) console.log(formatLogMessage('cloudflare', `Legacy checkbox challenge completed successfully`));
            break;
          }
        }
      } catch (e) {
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Legacy selector ${selector} failed: ${e.message}`));
        continue;
      }
    }

    if (!result.success) {
      result.error = 'No interactive legacy checkbox found';
      if (forceDebug) console.log(formatLogMessage('cloudflare', result.error));
    }
    
  } catch (error) {
    result.error = `Legacy checkbox handling failed: ${error.message}`;
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Legacy checkbox error: ${error.message}`));
  }

  return result;
}

/**
 * Checks if challenge has been completed with timeout protection and enhanced debug logging
 */
async function checkChallengeCompletion(page) {
  try {
    const isCompleted = await safePageEvaluate(page, () => {
      const noChallengeRunning = !document.querySelector('.cf-challenge-running');
      const noChallengeContainer = !document.querySelector('.cf-challenge-container');
      const noChallengePage = !document.body.textContent.includes('Checking your browser') &&
                             !document.body.textContent.includes('Just a moment') &&
                             !document.body.textContent.includes('Verify you are human');
      
      const hasClearanceCookie = document.cookie.includes('cf_clearance');
      const hasTurnstileResponse = document.querySelector('input[name="cf-turnstile-response"]')?.value;
      
      return (noChallengeRunning && noChallengeContainer && noChallengePage) ||
             hasClearanceCookie ||
             hasTurnstileResponse;
    }, FAST_TIMEOUTS.CHALLENGE_COMPLETION);
    
    return { isCompleted };
  } catch (error) {
    return { isCompleted: false, error: error.message };
  }
}

/**
 * Main function to handle all Cloudflare challenges with smart detection and adaptive timeouts
 * 
 * @param {Object} page - Puppeteer page instance
 * @param {string} currentUrl - URL being processed
 * @param {Object} siteConfig - Configuration object with cloudflare_phish and cloudflare_bypass flags
 * @param {boolean} forceDebug - Enable debug logging
 * 
 * @returns {Promise<Object>} Result object with the following structure:
 * {
 *   phishingWarning: {
 *     attempted: boolean,     // Whether phishing bypass was attempted
 *     success: boolean,       // Whether bypass succeeded (true if no warning or successfully bypassed)
 *     error: string|null,     // Error message if bypass failed
 *     details: object|null    // Challenge analysis details from analyzeCloudflareChallenge()
 *   },
 *   verificationChallenge: {
 *     attempted: boolean,     // Whether challenge bypass was attempted
 *     success: boolean,       // Whether challenge was solved (true if no challenge or successfully solved)
 *     error: string|null,     // Error message if solving failed
 *     requiresHuman: boolean, // True if CAPTCHA detected - requires manual intervention
 *     method: string|null,    // Successful method used: 'js_challenge_wait', 'turnstile', 'legacy_checkbox'
 *     details: object|null    // Challenge analysis details from analyzeCloudflareChallenge()
 *   },
 *   overallSuccess: boolean,  // True if no critical failures occurred (challenges may be unsolved but didn't error)
 *   errors: string[],         // Array of error messages from failed operations
 *   skippedNoIndicators: boolean, // True if processing was skipped due to no Cloudflare indicators detected
 *   timedOut: boolean         // True if adaptive timeout was reached (processing continued anyway)
 * }
 * 
 * @example
 * const result = await handleCloudflareProtection(page, url, {cloudflare_bypass: true}, false);
 * if (result.verificationChallenge.requiresHuman) {
 *   console.log('Manual CAPTCHA solving required');
 * } else if (!result.overallSuccess) {
 *   console.error('Critical errors:', result.errors);
 * } else if (result.verificationChallenge.attempted && result.verificationChallenge.success) {
 *   console.log(`Challenge solved using: ${result.verificationChallenge.method}`);
 * }
 */
async function handleCloudflareProtection(page, currentUrl, siteConfig, forceDebug = false) {
  if (forceDebug) {
    console.log(formatLogMessage('cloudflare', `Using Cloudflare module v${CLOUDFLARE_MODULE_VERSION} for ${currentUrl}`));
  }
  
  // VALIDATE URL FIRST - Skip protection handling for non-HTTP(S) URLs
  if (!shouldProcessUrl(currentUrl, forceDebug)) {
    if (forceDebug) {
      console.log(formatLogMessage('cloudflare', `Skipping protection handling for non-HTTP(S) URL: ${currentUrl}`));
    }
    return {
      phishingWarning: { attempted: false, success: true },
      verificationChallenge: { attempted: false, success: true },
      overallSuccess: true,
      errors: [],
      skippedInvalidUrl: true
    };
  }
  
  // Quick detection first - exit early if no Cloudflare detected and no explicit config
  const quickDetection = await quickCloudflareDetection(page, forceDebug);

  // Early return structure when no Cloudflare indicators found
  // Sets attempted: false, success: true for both protection types
 
  // Only proceed if we have indicators OR explicit config enables Cloudflare handling
  if (!quickDetection.hasIndicators && !siteConfig.cloudflare_phish && !siteConfig.cloudflare_bypass) {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `No Cloudflare indicators found and no explicit config, skipping protection handling for ${currentUrl}`));
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Quick detection details: title="${quickDetection.title}", bodySnippet="${quickDetection.bodySnippet}"`));
    return {
      phishingWarning: { attempted: false, success: true },
      verificationChallenge: { attempted: false, success: true },
      overallSuccess: true,
      errors: [],
      skippedNoIndicators: true
    };
  }

  // Standard return structure for all processing paths
  // Individual handlers update their respective sections
  // overallSuccess becomes false if any critical errors occur
  const result = {
    phishingWarning: { attempted: false, success: false },
    verificationChallenge: { attempted: false, success: false },
    overallSuccess: true,
    errors: []
  };

  try {
    // Adaptive timeout based on detection results and explicit config
    let adaptiveTimeout;
    if (siteConfig.cloudflare_phish || siteConfig.cloudflare_bypass) {
      // Explicit config - give more time
      adaptiveTimeout = quickDetection.hasIndicators ? TIMEOUTS.ADAPTIVE_TIMEOUT_WITH_INDICATORS : TIMEOUTS.ADAPTIVE_TIMEOUT_WITHOUT_INDICATORS;
    } else {
      // Auto-detected only - shorter timeout
      adaptiveTimeout = quickDetection.hasIndicators ? TIMEOUTS.ADAPTIVE_TIMEOUT_AUTO_WITH_INDICATORS : TIMEOUTS.ADAPTIVE_TIMEOUT_AUTO_WITHOUT_INDICATORS;
    }

    if (forceDebug) {
      console.log(formatLogMessage('cloudflare', `Using adaptive timeout of ${adaptiveTimeout}ms for ${currentUrl} (indicators: ${quickDetection.hasIndicators}, explicit config: ${!!(siteConfig.cloudflare_phish || siteConfig.cloudflare_bypass)})`));
    }
    
    return await Promise.race([
      performCloudflareHandling(page, currentUrl, siteConfig, forceDebug),
      new Promise((resolve) => {
        setTimeout(() => {
        console.warn(formatLogMessage('cloudflare', `Adaptive timeout (${adaptiveTimeout}ms) for ${currentUrl} - continuing with scan`));
          resolve({
            phishingWarning: { attempted: false, success: true },
            verificationChallenge: { attempted: false, success: true },
            overallSuccess: true,
            errors: ['Cloudflare handling timed out'],
            timedOut: true
          });
        }, adaptiveTimeout);
      })
    ]);
  } catch (error) {
    result.overallSuccess = false;
    result.errors.push(`Cloudflare handling failed: ${error.message}`);
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Overall handling failed: ${error.message}`));
    return result;
  }
}

/**
 * Performs the actual Cloudflare handling with enhanced debug logging
 * 
 * @param {Object} page - Puppeteer page instance  
 * @param {string} currentUrl - URL being processed
 * @param {Object} siteConfig - Configuration flags
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Promise<Object>} Same structure as handleCloudflareProtection()
 */
async function performCloudflareHandling(page, currentUrl, siteConfig, forceDebug = false) {
  const result = {
    phishingWarning: { attempted: false, success: false },
    verificationChallenge: { attempted: false, success: false },
    overallSuccess: true,
    errors: []
  };

  if (forceDebug) console.log(formatLogMessage('cloudflare', `Starting Cloudflare protection handling for ${currentUrl}`));

  // Handle phishing warnings first - updates result.phishingWarning
  // Only runs if siteConfig.cloudflare_phish === true
  // Handle phishing warnings if enabled
  if (siteConfig.cloudflare_phish === true) {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Phishing warning bypass enabled for ${currentUrl}`));
    
    const phishingResult = await handlePhishingWarningWithRetries(page, currentUrl, siteConfig, forceDebug);
    result.phishingWarning = phishingResult;

    // Check for max retries exceeded
    if (phishingResult.maxRetriesExceeded) {
      result.overallSuccess = false;
      result.errors.push(`Phishing warning bypass exceeded max retries (${phishingResult.attempts}): ${phishingResult.error}`);
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Phishing warning max retries exceeded: ${phishingResult.error}`));
      // Exit early if max retries exceeded
      return result;
    }
    
    if (phishingResult.attempted && !phishingResult.success) {
      result.overallSuccess = false;
      if (phishingResult.loopDetected) {
        result.errors.push(`Phishing warning bypass failed (redirect loop): ${phishingResult.error}`);
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Phishing warning redirect loop detected: ${phishingResult.error}`));
      } else {
        result.errors.push(`Phishing warning bypass failed: ${phishingResult.error}`);
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Phishing warning handling failed: ${phishingResult.error}`));
      }
    } else if (phishingResult.attempted && phishingResult.success) {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Phishing warning handled successfully`));
    }
  } else if (forceDebug) {
    console.log(formatLogMessage('cloudflare', `Phishing warning bypass disabled for ${currentUrl}`));
  }

  // Handle verification challenges second - updates result.verificationChallenge  
  // Only runs if siteConfig.cloudflare_bypass === true
  // Sets requiresHuman: true if CAPTCHA detected (no bypass attempted)
  // Handle verification challenges if enabled
  if (siteConfig.cloudflare_bypass === true) {
    if (forceDebug) console.log(formatLogMessage('cloudflare', `Challenge bypass enabled for ${currentUrl}`));
    
    const challengeResult = await handleVerificationChallengeWithRetries(page, currentUrl, siteConfig, forceDebug);
    result.verificationChallenge = challengeResult;

    // Check for max retries exceeded
    if (challengeResult.maxRetriesExceeded) {
      result.overallSuccess = false;
      result.errors.push(`Challenge bypass exceeded max retries (${challengeResult.attempts}): ${challengeResult.error}`);
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Challenge bypass max retries exceeded: ${challengeResult.error}`));
      // Exit early if max retries exceeded
      return result;
    }
    
    if (challengeResult.attempted && !challengeResult.success) {
      result.overallSuccess = false;
      if (challengeResult.requiresHuman) {
        result.errors.push(`Human intervention required: ${challengeResult.error}`);
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Human intervention required: ${challengeResult.error}`));
      } else if (challengeResult.loopDetected) {
        result.errors.push(`Challenge bypass failed (redirect loop): ${challengeResult.error}`);
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Challenge redirect loop detected: ${challengeResult.error}`));
      } else {
        result.errors.push(`Challenge bypass failed: ${challengeResult.error}`);
        if (forceDebug) console.log(formatLogMessage('cloudflare', `Challenge bypass failed: ${challengeResult.error}`));
      }
    } else if (challengeResult.attempted && challengeResult.success) {
      if (forceDebug) console.log(formatLogMessage('cloudflare', `Challenge handled successfully using method: ${challengeResult.method || 'unknown'}`));
    }
  } else if (forceDebug) {
     console.log(formatLogMessage('cloudflare', `Challenge bypass disabled for ${currentUrl}`));
  }

  // Log overall result
  if (!result.overallSuccess && forceDebug) {
    console.log(formatLogMessage('cloudflare', `Overall Cloudflare handling failed for ${currentUrl}:`));
    result.errors.forEach(error => {
      console.log(formatLogMessage('cloudflare', `  - ${error}`));
    });
  } else if ((result.phishingWarning.attempted || result.verificationChallenge.attempted) && forceDebug) {
    console.log(formatLogMessage('cloudflare', `Successfully handled Cloudflare protections for ${currentUrl}`));
  } else if (forceDebug) {
    console.log(formatLogMessage('cloudflare', `No Cloudflare protections detected or enabled for ${currentUrl}`));
  }

  return result;
}

/**
 * Performs parallel detection of multiple challenge types for better performance
 */
async function parallelChallengeDetection(page, forceDebug = false) {
  const detectionPromises = [];
  
  // Check for JS challenge
  detectionPromises.push(
    page.evaluate(() => {
      return {
        type: 'js',
        detected: document.querySelector('script[src*="/cdn-cgi/challenge-platform/"]') !== null ||
                  document.body?.textContent?.includes('Checking your browser') ||
                  document.body?.textContent?.includes('Please wait while we verify')
      };
    }).catch(err => ({ type: 'js', detected: false, error: err.message }))
  );
  
  // Check for Turnstile
  detectionPromises.push(
    page.evaluate(() => {
      return {
        type: 'turnstile',
        detected: document.querySelector('.cf-turnstile') !== null ||
                  document.querySelector('iframe[src*="challenges.cloudflare.com"]') !== null ||
                  document.querySelector('.ctp-checkbox-container') !== null
      };
    }).catch(err => ({ type: 'turnstile', detected: false, error: err.message }))
  );
  
  // Check for phishing warning
  detectionPromises.push(
    page.evaluate(() => {
      return {
        type: 'phishing',
        detected: document.body?.textContent?.includes('This website has been reported for potential phishing') ||
                  document.querySelector('a[href*="continue"]') !== null
      };
    }).catch(err => ({ type: 'phishing', detected: false, error: err.message }))
  );
  
  // Check for managed challenge
  detectionPromises.push(
    page.evaluate(() => {
      return {
        type: 'managed',
        detected: document.querySelector('.cf-managed-challenge') !== null ||
                  document.querySelector('[data-cf-managed]') !== null
      };
    }).catch(err => ({ type: 'managed', detected: false, error: err.message }))
  );
  
  const results = await Promise.all(detectionPromises);
  
  const detectedChallenges = results.filter(r => r.detected).map(r => r.type);
  
  if (forceDebug && detectedChallenges.length > 0) {
    console.log(formatLogMessage('cloudflare', `Parallel detection found challenges: ${detectedChallenges.join(', ')}`));
  }
  
  return {
    challenges: detectedChallenges,
    hasAnyChallenge: detectedChallenges.length > 0,
    details: results
  };
}

/**
 * Enhanced parallel detection including embedded iframe challenges
 */
async function enhancedParallelChallengeDetection(page, forceDebug = false) {
  const existingDetection = await parallelChallengeDetection(page, forceDebug);
  
  try {
    const hasEmbeddedIframe = await page.evaluate(() => {
      return document.querySelector('iframe[src*="challenges.cloudflare.com"]') !== null ||
             document.querySelector('iframe[title*="Verify you are human"]') !== null;
    });
    
    if (hasEmbeddedIframe && !existingDetection.challenges.includes('embedded_iframe')) {
      existingDetection.challenges.push('embedded_iframe');
      existingDetection.hasAnyChallenge = true;
    }
  } catch (e) {
    // Ignore detection errors
  }
  
  return existingDetection;
}

/**
 * Gets cache statistics for performance monitoring
 */
function getCacheStats() {
  return detectionCache.getStats();
}

/**
 * Clears the detection cache
 */
function clearDetectionCache() {
  detectionCache.clear();
}

module.exports = {
  analyzeCloudflareChallenge,
  handlePhishingWarning,
  handleVerificationChallenge,
  handleCloudflareProtection,
  waitForTimeout,
  handleTurnstileChallenge,
  waitForJSChallengeCompletion,
  handleLegacyCheckbox,
  checkChallengeCompletion,
  handleEmbeddedIframeChallenge,
  enhancedParallelChallengeDetection,
  quickCloudflareDetection,
  getModuleInfo,
  CLOUDFLARE_MODULE_VERSION,
  // New exports
  parallelChallengeDetection,
  getCacheStats,
  clearDetectionCache,
  categorizeError,
  ERROR_TYPES,
  RETRY_CONFIG,
  getRetryConfig,
  detectChallengeLoop
};