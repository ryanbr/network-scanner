/**
 * Cloudflare bypass and challenge handling module - Optimized with smart detection and adaptive timeouts
 * Version: 2.1.0 - Enhanced with quick detection, adaptive timeouts, and comprehensive debug logging
 * Handles phishing warnings, Turnstile challenges, and modern Cloudflare protections
 */

/**
 * Module version information
 */
const CLOUDFLARE_MODULE_VERSION = '2.1.0';

/**
 * Timeout constants for various operations (in milliseconds)
 */
const TIMEOUTS = {
  QUICK_DETECTION: 3000,           // Quick Cloudflare detection check
  PAGE_EVALUATION: 8000,           // Standard page evaluation timeout
  PAGE_EVALUATION_SAFE: 10000,     // Safe page evaluation with extra buffer
  CHALLENGE_COMPLETION: 3000,      // Challenge completion check
  PHISHING_WAIT: 2000,            // Wait before checking phishing warning
  PHISHING_CLICK: 3000,           // Timeout for clicking phishing continue button
  PHISHING_NAVIGATION: 8000,       // Wait for navigation after phishing bypass
  CHALLENGE_WAIT: 1000,           // Wait before checking verification challenge
  CHALLENGE_SOLVING: 20000,        // Overall challenge solving timeout
  JS_CHALLENGE: 15000,            // JS challenge completion wait
  JS_CHALLENGE_BUFFER: 18000,     // JS challenge with safety buffer
  TURNSTILE_OPERATION: 8000,      // Turnstile iframe operations
  TURNSTILE_COMPLETION: 12000,    // Turnstile completion check
  TURNSTILE_COMPLETION_BUFFER: 15000, // Turnstile completion with buffer
  SELECTOR_WAIT: 2000,            // Wait for selector to appear
  SELECTOR_WAIT_BUFFER: 2500,     // Selector wait with safety buffer
  ELEMENT_INTERACTION_DELAY: 500, // Delay before element interactions
  CLICK_TIMEOUT: 5000,            // Standard click operation timeout
  CLICK_TIMEOUT_BUFFER: 1000,     // Click timeout safety buffer
  NAVIGATION_TIMEOUT: 15000,      // Standard navigation timeout
  NAVIGATION_TIMEOUT_BUFFER: 2000, // Navigation timeout safety buffer
  FALLBACK_TIMEOUT: 5000,         // Fallback timeout for failed operations
  ADAPTIVE_TIMEOUT_WITH_INDICATORS: 25000,    // Adaptive timeout when indicators found + explicit config
  ADAPTIVE_TIMEOUT_WITHOUT_INDICATORS: 20000, // Adaptive timeout with explicit config only
  ADAPTIVE_TIMEOUT_AUTO_WITH_INDICATORS: 15000,   // Adaptive timeout for auto-detected with indicators
  ADAPTIVE_TIMEOUT_AUTO_WITHOUT_INDICATORS: 10000 // Adaptive timeout for auto-detected without indicators
};

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
    if (forceDebug) console.log(`[cloudflare][url-validation] Skipping invalid URL: ${url}`);
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
        console.log(`[cloudflare][url-validation] Skipping ${pattern} URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`);
      }
      return false;
    }
  }

  // Only process HTTP/HTTPS URLs
  if (!urlLower.startsWith('http://') && !urlLower.startsWith('https://')) {
    if (forceDebug) {
      console.log(`[cloudflare][url-validation] Skipping non-HTTP(S) URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`);
    }
    return false;
  }

  return true;
}

/**
 * Cross-version compatible timeout function for Puppeteer with timeout protection
 */
async function waitForTimeout(page, timeout) {
  try {
    // Try newer Puppeteer method first
    if (typeof page.waitForTimeout === 'function') {
      await Promise.race([
        page.waitForTimeout(timeout),
        new Promise((_, reject) => setTimeout(() => reject(new Error('waitForTimeout exceeded')), timeout + TIMEOUTS.FALLBACK_TIMEOUT))
      ]);
    } else if (typeof page.waitFor === 'function') {
      await Promise.race([
        page.waitFor(timeout),
        new Promise((_, reject) => setTimeout(() => reject(new Error('waitFor exceeded')), timeout + TIMEOUTS.FALLBACK_TIMEOUT))
      ]);
    } else {
      await new Promise(resolve => setTimeout(resolve, timeout));
    }
  } catch (error) {
    // If all else fails, use setTimeout
    await new Promise(resolve => setTimeout(resolve, Math.min(timeout, TIMEOUTS.FALLBACK_TIMEOUT)));
  }
}

/**
 * Safe page evaluation with timeout protection
 */
async function safePageEvaluate(page, func, timeout = TIMEOUTS.PAGE_EVALUATION_SAFE) {
  try {
    return await Promise.race([
      page.evaluate(func),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Page evaluation timeout')), timeout)
      )
    ]);
  } catch (error) {
    console.warn(`[cloudflare] Page evaluation failed: ${error.message}`);
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
    console.warn(`[cloudflare] Navigation wait failed: ${error.message}`);
    // Don't throw - just continue
  }
}

/**
 * Quick Cloudflare detection - faster initial check to avoid unnecessary waiting
 */
async function quickCloudflareDetection(page, forceDebug = false) {
  try {
    // Get current page URL and validate it
    const currentPageUrl = await page.url();
    
    if (!shouldProcessUrl(currentPageUrl, forceDebug)) {
      if (forceDebug) {
        console.log(`[debug][cloudflare] Quick detection skipping non-HTTP(S) page: ${currentPageUrl}`);
      }
      return { hasIndicators: false, skippedInvalidUrl: true };
    }

    // Continue with existing detection logic only for valid HTTP(S) URLs
    
    const quickCheck = await safePageEvaluate(page, () => {
      const title = document.title || '';
      const bodyText = document.body ? document.body.textContent.substring(0, 500) : '';
      const url = window.location.href;
      
      // Quick indicators of Cloudflare presence
      const hasCloudflareIndicators = 
        title.includes('Just a moment') ||
        title.includes('Checking your browser') ||
        title.includes('Attention Required') ||
        bodyText.includes('Cloudflare') ||
        bodyText.includes('cf-ray') ||
        bodyText.includes('Verify you are human') ||
        bodyText.includes('This website has been reported for potential phishing') ||
        bodyText.includes('Please wait while we verify') ||
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
        document.querySelector('a[href*="continue"]');
      
      return {
        hasIndicators: hasCloudflareIndicators,
        title,
        url,
        bodySnippet: bodyText.substring(0, 200)
      };
    }, TIMEOUTS.QUICK_DETECTION);
    
    if (forceDebug && quickCheck.hasIndicators) {
      console.log(`[debug][cloudflare] Quick detection found Cloudflare indicators on ${quickCheck.url}`);
    } else if (forceDebug && !quickCheck.hasIndicators) {
      console.log(`[debug][cloudflare] Quick detection found no Cloudflare indicators on ${quickCheck.url}`);
    }
    
    return quickCheck;
  } catch (error) {
    if (forceDebug) console.log(`[debug][cloudflare] Quick detection failed: ${error.message}`);
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
    if (forceDebug) console.log(`[debug][cloudflare] Checking for phishing warning on ${currentUrl}`);
    
    // Shorter wait with timeout protection
    await waitForTimeout(page, TIMEOUTS.PHISHING_WAIT);

    const challengeInfo = await analyzeCloudflareChallenge(page);
    
    if (challengeInfo.isPhishingWarning) {
      result.attempted = true;
      result.details = challengeInfo;
      
      if (forceDebug) {
        console.log(`[debug][cloudflare] Phishing warning detected on ${currentUrl}:`);
        console.log(`[debug][cloudflare]   Page Title: "${challengeInfo.title}"`);
        console.log(`[debug][cloudflare]   Current URL: ${challengeInfo.url}`);
        console.log(`[debug][cloudflare]   Body snippet: ${challengeInfo.bodySnippet}`);
      }

      try {
        // Use safe click with shorter timeout
        await safeClick(page, 'a[href*="continue"]', TIMEOUTS.PHISHING_CLICK);
        await safeWaitForNavigation(page, TIMEOUTS.PHISHING_NAVIGATION);
        
        result.success = true;
        if (forceDebug) console.log(`[debug][cloudflare] Successfully bypassed phishing warning for ${currentUrl}`);
      } catch (clickError) {
        result.error = `Failed to click continue button: ${clickError.message}`;
        if (forceDebug) console.log(`[debug][cloudflare] Failed to bypass phishing warning: ${clickError.message}`);
      }
    } else {
      if (forceDebug) console.log(`[debug][cloudflare] No phishing warning detected on ${currentUrl}`);
      result.success = true; // No warning to handle
    }
  } catch (error) {
    result.error = error.message;
    if (forceDebug) console.log(`[debug][cloudflare] Phishing warning check failed for ${currentUrl}: ${error.message}`);
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
    if (forceDebug) console.log(`[debug][cloudflare] Checking for verification challenge on ${currentUrl}`);
    
    // Reduced wait time
    await waitForTimeout(page, TIMEOUTS.CHALLENGE_WAIT);

    const challengeInfo = await analyzeCloudflareChallenge(page);
    result.details = challengeInfo;

    if (challengeInfo.isChallengePresent) {
      result.attempted = true;
      
      if (forceDebug) {
        console.log(`[debug][cloudflare] Challenge detected on ${currentUrl}:`);
        console.log(`[debug][cloudflare]   Page Title: "${challengeInfo.title}"`);
        console.log(`[debug][cloudflare]   Current URL: ${challengeInfo.url}`);
        console.log(`[debug][cloudflare]   Is Turnstile: ${challengeInfo.isTurnstile}`);
        console.log(`[debug][cloudflare]   Is JS Challenge: ${challengeInfo.isJSChallenge}`);
        console.log(`[debug][cloudflare]   Has Legacy Checkbox: ${challengeInfo.hasLegacyCheckbox}`);
        console.log(`[debug][cloudflare]   Has Turnstile Iframe: ${challengeInfo.hasTurnstileIframe}`);
        console.log(`[debug][cloudflare]   Has Turnstile Container: ${challengeInfo.hasTurnstileContainer}`);
        console.log(`[debug][cloudflare]   Has Turnstile Checkbox: ${challengeInfo.hasTurnstileCheckbox}`);
        console.log(`[debug][cloudflare]   Has CAPTCHA: ${challengeInfo.hasCaptcha}`);
        console.log(`[debug][cloudflare]   Has Challenge Running: ${challengeInfo.hasChallengeRunning}`);
        console.log(`[debug][cloudflare]   Has Data Ray: ${challengeInfo.hasDataRay}`);
        console.log(`[debug][cloudflare]   Has Turnstile Response: ${challengeInfo.hasTurnstileResponse}`);
        console.log(`[debug][cloudflare]   Body snippet: ${challengeInfo.bodySnippet}`);
      }

      // Check for CAPTCHA that requires human intervention
      if (challengeInfo.hasCaptcha) {
        result.requiresHuman = true;
        result.error = 'CAPTCHA detected - requires human intervention';
        if (forceDebug) console.log(`[debug][cloudflare] Skipping automatic bypass due to CAPTCHA requirement`);
        return result;
      }

      // Attempt to solve the challenge with timeout protection
      const solveResult = await attemptChallengeSolveWithTimeout(page, currentUrl, challengeInfo, forceDebug);
      result.success = solveResult.success;
      result.error = solveResult.error;
      result.method = solveResult.method;
      
    } else {
      if (forceDebug) console.log(`[debug][cloudflare] No verification challenge detected on ${currentUrl}`);
      result.success = true;
    }
  } catch (error) {
    result.error = error.message;
    if (forceDebug) console.log(`[debug][cloudflare] Challenge check failed for ${currentUrl}: ${error.message}`);
  }

  return result;
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
        setTimeout(() => reject(new Error('Challenge solving timeout')), TIMEOUTS.CHALLENGE_SOLVING)
      )
    ]);
  } catch (error) {
    result.error = `Challenge solving timed out: ${error.message}`;
    if (forceDebug) console.log(`[debug][cloudflare] Challenge solving timeout for ${currentUrl}`);
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
      if (forceDebug) console.log(`[debug][cloudflare] Attempting JS challenge wait for ${currentUrl}`);
      
      const jsResult = await waitForJSChallengeCompletion(page, forceDebug);
      if (jsResult.success) {
        result.success = true;
        result.method = 'js_challenge_wait';
        if (forceDebug) console.log(`[debug][cloudflare] JS challenge completed successfully for ${currentUrl}`);
        return result;
      }
    } catch (jsError) {
      if (forceDebug) console.log(`[debug][cloudflare] JS challenge wait failed for ${currentUrl}: ${jsError.message}`);
    }
  }

  // Method 2: Handle Turnstile challenges (interactive)
  if (challengeInfo.isTurnstile) {
    try {
      if (forceDebug) console.log(`[debug][cloudflare] Attempting Turnstile method for ${currentUrl}`);
      
      const turnstileResult = await handleTurnstileChallenge(page, forceDebug);
      if (turnstileResult.success) {
        result.success = true;
        result.method = 'turnstile';
        if (forceDebug) console.log(`[debug][cloudflare] Turnstile challenge solved successfully for ${currentUrl}`);
        return result;
      }
    } catch (turnstileError) {
      if (forceDebug) console.log(`[debug][cloudflare] Turnstile method failed for ${currentUrl}: ${turnstileError.message}`);
    }
  }

  // Method 3: Legacy checkbox interaction (fallback)
  if (challengeInfo.hasLegacyCheckbox) {
    try {
      if (forceDebug) console.log(`[debug][cloudflare] Attempting legacy checkbox method for ${currentUrl}`);
      
      const legacyResult = await handleLegacyCheckbox(page, forceDebug);
      if (legacyResult.success) {
        result.success = true;
        result.method = 'legacy_checkbox';
        if (forceDebug) console.log(`[debug][cloudflare] Legacy checkbox method succeeded for ${currentUrl}`);
        return result;
      }
    } catch (legacyError) {
      if (forceDebug) console.log(`[debug][cloudflare] Legacy checkbox method failed for ${currentUrl}: ${legacyError.message}`);
    }
  }

  if (!result.success) {
    result.error = result.error || 'All challenge bypass methods failed';
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
    if (forceDebug) console.log(`[debug][cloudflare] Waiting for JS challenge completion`);
    
    // Reduced timeout for JS challenge completion
    await Promise.race([
      page.waitForFunction(
        () => {
          return !document.body.textContent.includes('Checking your browser') &&
                 !document.body.textContent.includes('Please wait while we verify') &&
                 !document.querySelector('.cf-challenge-running') &&
                 !document.querySelector('[data-cf-challenge]');
        },
        { timeout: TIMEOUTS.JS_CHALLENGE }
      ),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('JS challenge timeout')), TIMEOUTS.JS_CHALLENGE_BUFFER)
      )
    ]);
    
    result.success = true;
    if (forceDebug) console.log(`[debug][cloudflare] JS challenge completed automatically`);
  } catch (error) {
    result.error = `JS challenge timeout: ${error.message}`;
    if (forceDebug) console.log(`[debug][cloudflare] JS challenge wait failed: ${error.message}`);
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

  try {
    // Reduced timeout for Turnstile operations
    const turnstileTimeout = TIMEOUTS.TURNSTILE_OPERATION;
    
    const turnstileSelectors = [
      'iframe[src*="challenges.cloudflare.com"]',
      'iframe[title*="Widget containing a Cloudflare"]',
      'iframe[title*="Cloudflare security challenge"]'
    ];
    
    let turnstileFrame = null;
    for (const selector of turnstileSelectors) {
      try {
        await Promise.race([
          page.waitForSelector(selector, { timeout: TIMEOUTS.SELECTOR_WAIT }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Selector timeout')), TIMEOUTS.SELECTOR_WAIT_BUFFER))
        ]);
        
        const frames = await page.frames();
        turnstileFrame = frames.find(frame => 
          frame.url().includes('challenges.cloudflare.com') ||
          frame.url().includes('turnstile')
        );
        if (turnstileFrame) {
          if (forceDebug) console.log(`[debug][cloudflare] Found Turnstile iframe using selector: ${selector}`);
          break;
        }
      } catch (e) {
        if (forceDebug) console.log(`[debug][cloudflare] Selector ${selector} not found or timed out`);
        continue;
      }
    }

    if (turnstileFrame) {
      if (forceDebug) {
        console.log(`[debug][cloudflare] Found Turnstile iframe with URL: ${turnstileFrame.url()}`);
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
            turnstileFrame.waitForSelector(selector, { timeout: TIMEOUTS.SELECTOR_WAIT }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Checkbox timeout')), TIMEOUTS.SELECTOR_WAIT_BUFFER))
          ]);
          
          await waitForTimeout(page, TIMEOUTS.ELEMENT_INTERACTION_DELAY);
          await turnstileFrame.click(selector);
          
          if (forceDebug) console.log(`[debug][cloudflare] Clicked Turnstile checkbox: ${selector}`);
          break;
        } catch (e) {
          if (forceDebug) console.log(`[debug][cloudflare] Checkbox selector ${selector} not found or failed to click`);
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
      
      if (forceDebug) console.log(`[debug][cloudflare] Turnstile response token generated successfully`);
      result.success = true;
    } else {
      // Try container-based Turnstile (non-iframe)
      if (forceDebug) console.log(`[debug][cloudflare] No Turnstile iframe found, trying container-based approach`);
      
      const containerSelectors = [
        '.cf-turnstile',
        '.ctp-checkbox-container',
        '.ctp-checkbox-label'
      ];
      
      for (const selector of containerSelectors) {
        try {
          await Promise.race([
            page.waitForSelector(selector, { timeout: TIMEOUTS.SELECTOR_WAIT }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Container timeout')), TIMEOUTS.SELECTOR_WAIT_BUFFER))
          ]);
          
          await waitForTimeout(page, TIMEOUTS.ELEMENT_INTERACTION_DELAY);
          await page.click(selector);
          
          if (forceDebug) console.log(`[debug][cloudflare] Clicked Turnstile container: ${selector}`);
          
          const completionCheck = await checkChallengeCompletion(page);
          if (completionCheck.isCompleted) {
            result.success = true;
            if (forceDebug) console.log(`[debug][cloudflare] Container-based Turnstile completed successfully`);
            break;
          }
        } catch (e) {
          if (forceDebug) console.log(`[debug][cloudflare] Container selector ${selector} not found or failed`);
          continue;
        }
      }
      
      if (!result.success) {
        result.error = 'Turnstile iframe/container not found or not interactive';
        if (forceDebug) console.log(`[debug][cloudflare] ${result.error}`);
      }
    }
    
  } catch (error) {
    result.error = `Turnstile handling failed: ${error.message}`;
    if (forceDebug) console.log(`[debug][cloudflare] Turnstile handling error: ${error.message}`);
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
    if (forceDebug) console.log(`[debug][cloudflare] Attempting legacy checkbox challenge`);
    
    const legacySelectors = [
      'input[type="checkbox"]#challenge-form',
      'input[type="checkbox"][name="cf_captcha_kind"]',
      '.cf-turnstile input[type="checkbox"]'
    ];

    for (const selector of legacySelectors) {
      try {
        await Promise.race([
          page.waitForSelector(selector, { timeout: TIMEOUTS.SELECTOR_WAIT }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Legacy selector timeout')), TIMEOUTS.SELECTOR_WAIT_BUFFER))
        ]);
        
        const checkbox = await page.$(selector);
        if (checkbox) {
          await checkbox.click();
          if (forceDebug) console.log(`[debug][cloudflare] Clicked legacy checkbox: ${selector}`);

          const completionCheck = await checkChallengeCompletion(page);
          if (completionCheck.isCompleted) {
            result.success = true;
            if (forceDebug) console.log(`[debug][cloudflare] Legacy checkbox challenge completed successfully`);
            break;
          }
        }
      } catch (e) {
        if (forceDebug) console.log(`[debug][cloudflare] Legacy selector ${selector} failed: ${e.message}`);
        continue;
      }
    }

    if (!result.success) {
      result.error = 'No interactive legacy checkbox found';
      if (forceDebug) console.log(`[debug][cloudflare] ${result.error}`);
    }
    
  } catch (error) {
    result.error = `Legacy checkbox handling failed: ${error.message}`;
    if (forceDebug) console.log(`[debug][cloudflare] Legacy checkbox error: ${error.message}`);
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
    }, TIMEOUTS.CHALLENGE_COMPLETION);
    
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
    console.log(`[debug][cloudflare] Using Cloudflare module v${CLOUDFLARE_MODULE_VERSION} for ${currentUrl}`);
  }
  
  // VALIDATE URL FIRST - Skip protection handling for non-HTTP(S) URLs
  if (!shouldProcessUrl(currentUrl, forceDebug)) {
    if (forceDebug) {
      console.log(`[debug][cloudflare] Skipping protection handling for non-HTTP(S) URL: ${currentUrl}`);
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
    if (forceDebug) console.log(`[debug][cloudflare] No Cloudflare indicators found and no explicit config, skipping protection handling for ${currentUrl}`);
    if (forceDebug) console.log(`[debug][cloudflare] Quick detection details: title="${quickDetection.title}", bodySnippet="${quickDetection.bodySnippet}"`);
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
      console.log(`[debug][cloudflare] Using adaptive timeout of ${adaptiveTimeout}ms for ${currentUrl} (indicators: ${quickDetection.hasIndicators}, explicit config: ${!!(siteConfig.cloudflare_phish || siteConfig.cloudflare_bypass)})`);
    }
    
    return await Promise.race([
      performCloudflareHandling(page, currentUrl, siteConfig, forceDebug),
      new Promise((resolve) => {
        setTimeout(() => {
        console.warn(`[cloudflare] Adaptive timeout (${adaptiveTimeout}ms) for ${currentUrl} - continuing with scan`);
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
    if (forceDebug) console.log(`[debug][cloudflare] Overall handling failed: ${error.message}`);
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

  if (forceDebug) console.log(`[debug][cloudflare] Starting Cloudflare protection handling for ${currentUrl}`);

  // Handle phishing warnings first - updates result.phishingWarning
  // Only runs if siteConfig.cloudflare_phish === true
  // Handle phishing warnings if enabled
  if (siteConfig.cloudflare_phish === true) {
    if (forceDebug) console.log(`[debug][cloudflare] Phishing warning bypass enabled for ${currentUrl}`);
    
    const phishingResult = await handlePhishingWarning(page, currentUrl, forceDebug);
    result.phishingWarning = phishingResult;
    
    if (phishingResult.attempted && !phishingResult.success) {
      result.overallSuccess = false;
      result.errors.push(`Phishing warning bypass failed: ${phishingResult.error}`);
      if (forceDebug) console.log(`[debug][cloudflare] Phishing warning handling failed: ${phishingResult.error}`);
    } else if (phishingResult.attempted && phishingResult.success) {
      if (forceDebug) console.log(`[debug][cloudflare] Phishing warning handled successfully`);
    }
  } else if (forceDebug) {
    console.log(`[debug][cloudflare] Phishing warning bypass disabled for ${currentUrl}`);
  }

  // Handle verification challenges second - updates result.verificationChallenge  
  // Only runs if siteConfig.cloudflare_bypass === true
  // Sets requiresHuman: true if CAPTCHA detected (no bypass attempted)
  // Handle verification challenges if enabled
  if (siteConfig.cloudflare_bypass === true) {
    if (forceDebug) console.log(`[debug][cloudflare] Challenge bypass enabled for ${currentUrl}`);
    
    const challengeResult = await handleVerificationChallenge(page, currentUrl, forceDebug);
    result.verificationChallenge = challengeResult;
    
    if (challengeResult.attempted && !challengeResult.success) {
      result.overallSuccess = false;
      if (challengeResult.requiresHuman) {
        result.errors.push(`Human intervention required: ${challengeResult.error}`);
        if (forceDebug) console.log(`[debug][cloudflare] Human intervention required: ${challengeResult.error}`);
      } else {
        result.errors.push(`Challenge bypass failed: ${challengeResult.error}`);
        if (forceDebug) console.log(`[debug][cloudflare] Challenge bypass failed: ${challengeResult.error}`);
      }
    } else if (challengeResult.attempted && challengeResult.success) {
      if (forceDebug) console.log(`[debug][cloudflare] Challenge handled successfully using method: ${challengeResult.method || 'unknown'}`);
    }
  } else if (forceDebug) {
    console.log(`[debug][cloudflare] Challenge bypass disabled for ${currentUrl}`);
  }

  // Log overall result
  if (!result.overallSuccess && forceDebug) {
    console.log(`[debug][cloudflare] Overall Cloudflare handling failed for ${currentUrl}:`);
    result.errors.forEach(error => {
      console.log(`[debug][cloudflare]   - ${error}`);
    });
  } else if ((result.phishingWarning.attempted || result.verificationChallenge.attempted) && forceDebug) {
    console.log(`[debug][cloudflare] Successfully handled Cloudflare protections for ${currentUrl}`);
  } else if (forceDebug) {
    console.log(`[debug][cloudflare] No Cloudflare protections detected or enabled for ${currentUrl}`);
  }

  return result;
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
  quickCloudflareDetection,
  getModuleInfo,
  CLOUDFLARE_MODULE_VERSION
};
