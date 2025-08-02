/**
 * FlowProxy protection detection and handling module
 * Detects flowProxy DDoS protection and handles it appropriately for security scanning
 */

/**
 * Validates if a URL should be processed by FlowProxy protection
 * Only allows HTTP/HTTPS URLs, skips browser-internal and special protocols
 * @param {string} url - URL to validate
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {boolean} True if URL should be processed
 */
function shouldProcessUrl(url, forceDebug = false) {
  if (!url || typeof url !== 'string') {
    if (forceDebug) console.log(`[flowproxy][url-validation] Skipping invalid URL: ${url}`);
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
        console.log(`[flowproxy][url-validation] Skipping ${pattern} URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`);
      }
      return false;
    }
  }

  // Only process HTTP/HTTPS URLs
  if (!urlLower.startsWith('http://') && !urlLower.startsWith('https://')) {
    if (forceDebug) {
      console.log(`[flowproxy][url-validation] Skipping non-HTTP(S) URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`);
    }
    return false;
  }

  return true;
}

/**
 * Cross-version compatible timeout function for Puppeteer
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<void>}
 */
async function waitForTimeout(page, timeout) {
  try {
    if (typeof page.waitForTimeout === 'function') {
      await page.waitForTimeout(timeout);
    } else if (typeof page.waitFor === 'function') {
      await page.waitFor(timeout);
    } else {
      await new Promise(resolve => setTimeout(resolve, timeout));
    }
  } catch (error) {
    await new Promise(resolve => setTimeout(resolve, timeout));
  }
}

/**
 * Analyzes the current page to detect flowProxy protection
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @returns {Promise<object>} Detection information object
 */
async function analyzeFlowProxyProtection(page) {
  try {
    // Get current page URL and validate it
    const currentPageUrl = await page.url();
    
    if (!shouldProcessUrl(currentPageUrl, false)) {
      return {
        isFlowProxyDetected: false,
        skippedInvalidUrl: true,
        url: currentPageUrl
      };
    }

    // Continue with existing analysis only for valid HTTP(S) URLs
    return await page.evaluate(() => {
      const title = document.title || '';
      const bodyText = document.body ? document.body.textContent : '';
      const url = window.location.href;
      
      // Check for flowProxy/aurologic specific indicators
      const hasFlowProxyDomain = url.includes('aurologic') || 
                                 url.includes('flowproxy') ||
                                 url.includes('ddos-protection');
      
      // Check for flowProxy challenge page indicators
      const hasProtectionPage = title.includes('DDoS Protection') ||
                               title.includes('Please wait') ||
                               title.includes('Checking your browser') ||
                               bodyText.includes('DDoS protection by aurologic') ||
                               bodyText.includes('flowProxy') ||
                               bodyText.includes('Verifying your browser');
      
      // Check for specific flowProxy elements
      const hasFlowProxyElements = document.querySelector('[data-flowproxy]') !== null ||
                                  document.querySelector('.flowproxy-challenge') !== null ||
                                  document.querySelector('#flowproxy-container') !== null ||
                                  document.querySelector('.aurologic-protection') !== null;
      
      // Check for challenge indicators
      const hasChallengeElements = document.querySelector('.challenge-running') !== null ||
                                  document.querySelector('.verification-container') !== null ||
                                  document.querySelector('input[name="flowproxy-response"]') !== null;
      
      // Check for rate limiting indicators
      const isRateLimited = bodyText.includes('Rate limited') ||
                           bodyText.includes('Too many requests') ||
                           bodyText.includes('Please try again later') ||
                           title.includes('429') ||
                           title.includes('Rate Limit');
      
      // Check for JavaScript challenge indicators
      const hasJSChallenge = document.querySelector('script[src*="flowproxy"]') !== null ||
                            document.querySelector('script[src*="aurologic"]') !== null ||
                            bodyText.includes('JavaScript is required') ||
                            bodyText.includes('Please enable JavaScript');
      
      // Check for loading/processing indicators
      const isProcessing = bodyText.includes('Processing') ||
                          bodyText.includes('Loading') ||
                          document.querySelector('.loading-spinner') !== null ||
                          document.querySelector('.processing-indicator') !== null;
      
      const isFlowProxyDetected = hasFlowProxyDomain || 
                                 hasProtectionPage || 
                                 hasFlowProxyElements || 
                                 hasChallengeElements;
      
      return {
        isFlowProxyDetected,
        hasFlowProxyDomain,
        hasProtectionPage,
        hasFlowProxyElements,
        hasChallengeElements,
        isRateLimited,
        hasJSChallenge,
        isProcessing,
        title,
        url,
        bodySnippet: bodyText.substring(0, 200) // First 200 chars for debugging
      };
    });
  } catch (error) {
    return {
      isFlowProxyDetected: false,
      hasFlowProxyDomain: false,
      hasProtectionPage: false,
      hasFlowProxyElements: false,
      hasChallengeElements: false,
      isRateLimited: false,
      hasJSChallenge: false,
      isProcessing: false,
      error: error.message
    };
  }
}

/**
 * Handles flowProxy protection by implementing appropriate delays and retry logic
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {string} currentUrl - Current URL being processed
 * @param {object} siteConfig - Site configuration object
 * @param {boolean} forceDebug - Debug mode flag
 * @returns {Promise<object>} Result object with handling details
 */
async function handleFlowProxyProtection(page, currentUrl, siteConfig, forceDebug = false) {

  // VALIDATE URL FIRST - Skip protection handling for non-HTTP(S) URLs
  if (!shouldProcessUrl(currentUrl, forceDebug)) {
    if (forceDebug) {
      console.log(`[debug][flowproxy] Skipping protection handling for non-HTTP(S) URL: ${currentUrl}`);
    }
    return {
      flowProxyDetection: { attempted: false, detected: false },
      handlingResult: { attempted: false, success: true },
      overallSuccess: true,
      errors: [],
      warnings: [],
      skippedInvalidUrl: true
    };
  }

  const result = {
    flowProxyDetection: { attempted: false, detected: false },
    handlingResult: { attempted: false, success: false },
    overallSuccess: true,
    errors: [],
    warnings: []
  };

  try {
    if (forceDebug) console.log(`[debug][flowproxy] Checking for flowProxy protection on ${currentUrl}`);
    
    // Wait a moment for the page to load
    await waitForTimeout(page, 2000);

    const detectionInfo = await analyzeFlowProxyProtection(page);
    result.flowProxyDetection = { 
      attempted: true, 
      detected: detectionInfo.isFlowProxyDetected,
      details: detectionInfo 
    };
    
    if (detectionInfo.isFlowProxyDetected) {
      result.handlingResult.attempted = true;
      
      if (forceDebug) {
        console.log(`[debug][flowproxy] FlowProxy protection detected on ${currentUrl}:`);
        console.log(`[debug][flowproxy]   Page Title: "${detectionInfo.title}"`);
        console.log(`[debug][flowproxy]   Current URL: ${detectionInfo.url}`);
        console.log(`[debug][flowproxy]   Has Protection Page: ${detectionInfo.hasProtectionPage}`);
        console.log(`[debug][flowproxy]   Has Challenge Elements: ${detectionInfo.hasChallengeElements}`);
        console.log(`[debug][flowproxy]   Is Rate Limited: ${detectionInfo.isRateLimited}`);
        console.log(`[debug][flowproxy]   Has JS Challenge: ${detectionInfo.hasJSChallenge}`);
      }

      // Handle rate limiting
      if (detectionInfo.isRateLimited) {
        const rateLimitDelay = siteConfig.flowproxy_delay || 30000; // 30 second default
        result.warnings.push(`Rate limiting detected - implementing ${rateLimitDelay}ms delay`);
        if (forceDebug) console.log(`[debug][flowproxy] Rate limiting detected, waiting ${rateLimitDelay}ms`);
        await waitForTimeout(page, rateLimitDelay);
      }

      // Handle JavaScript challenges by waiting for completion
      if (detectionInfo.hasJSChallenge || detectionInfo.isProcessing) {
        const jsWaitTime = siteConfig.flowproxy_js_timeout || 15000; // 15 second default
        if (forceDebug) console.log(`[debug][flowproxy] JavaScript challenge detected, waiting up to ${jsWaitTime}ms for completion`);
        
        try {
          // Wait for challenge to complete or timeout
          await page.waitForFunction(
            () => {
              const bodyText = document.body ? document.body.textContent : '';
              return !bodyText.includes('Processing') && 
                     !bodyText.includes('Checking your browser') &&
                     !bodyText.includes('Please wait') &&
                     !document.querySelector('.loading-spinner') &&
                     !document.querySelector('.processing-indicator');
            },
            { timeout: jsWaitTime }
          );
          
          if (forceDebug) console.log(`[debug][flowproxy] JavaScript challenge appears to have completed`);
        } catch (timeoutErr) {
          result.warnings.push(`JavaScript challenge timeout after ${jsWaitTime}ms`);
          if (forceDebug) console.log(`[debug][flowproxy] JavaScript challenge timeout - continuing anyway`);
        }
      }

      // Implement additional delay for flowProxy processing
      const additionalDelay = siteConfig.flowproxy_additional_delay || 5000; // 5 second default
      if (forceDebug) console.log(`[debug][flowproxy] Implementing additional ${additionalDelay}ms delay for flowProxy processing`);
      await waitForTimeout(page, additionalDelay);

      // Check if we're still on a protection page
      const finalCheck = await analyzeFlowProxyProtection(page);
      if (finalCheck.isFlowProxyDetected && finalCheck.hasProtectionPage) {
        result.warnings.push('Still on flowProxy protection page after handling attempts');
        if (forceDebug) console.log(`[debug][flowproxy] Warning: Still appears to be on protection page`);
      } else {
        result.handlingResult.success = true;
        if (forceDebug) console.log(`[debug][flowproxy] Successfully handled flowProxy protection for ${currentUrl}`);
      }
      
    } else {
      if (forceDebug) console.log(`[debug][flowproxy] No flowProxy protection detected on ${currentUrl}`);
      result.overallSuccess = true; // No protection to handle
    }
    
  } catch (error) {
    result.errors.push(`FlowProxy handling error: ${error.message}`);
    result.overallSuccess = false;
    if (forceDebug) {
      console.log(`[debug][flowproxy] FlowProxy handling failed for ${currentUrl}:`);
      console.log(`[debug][flowproxy]   Error: ${error.message}`);
    }
  }

  // Log overall result
  if (result.errors.length > 0 && forceDebug) {
    console.log(`[debug][flowproxy] FlowProxy handling completed with errors for ${currentUrl}:`);
    result.errors.forEach(error => {
      console.log(`[debug][flowproxy]   - ${error}`);
    });
  } else if (result.warnings.length > 0 && forceDebug) {
    console.log(`[debug][flowproxy] FlowProxy handling completed with warnings for ${currentUrl}:`);
    result.warnings.forEach(warning => {
      console.log(`[debug][flowproxy]   - ${warning}`);
    });
  } else if (result.flowProxyDetection.attempted && forceDebug) {
    console.log(`[debug][flowproxy] FlowProxy handling completed successfully for ${currentUrl}`);
  }

  return result;
}

/**
 * Checks if the current page might be behind flowProxy protection
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @returns {Promise<boolean>} True if flowProxy protection is suspected
 */
async function isFlowProxyProtected(page) {
  try {
    const detection = await analyzeFlowProxyProtection(page);
    return detection.isFlowProxyDetected;
  } catch (error) {
    return false;
  }
}

/**
 * Gets recommended timeout values for flowProxy protected sites
 * @param {object} siteConfig - Site configuration object
 * @returns {object} Recommended timeout values
 */
function getFlowProxyTimeouts(siteConfig) {
  return {
    pageTimeout: siteConfig.flowproxy_page_timeout || 45000, // 45 seconds
    navigationTimeout: siteConfig.flowproxy_nav_timeout || 45000, // 45 seconds
    challengeTimeout: siteConfig.flowproxy_js_timeout || 15000, // 15 seconds
    rateLimit: siteConfig.flowproxy_delay || 30000, // 30 seconds
    additionalDelay: siteConfig.flowproxy_additional_delay || 5000 // 5 seconds
  };
}

module.exports = {
  analyzeFlowProxyProtection,
  handleFlowProxyProtection,
  isFlowProxyProtected,
  getFlowProxyTimeouts,
  waitForTimeout
};