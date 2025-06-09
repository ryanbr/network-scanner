/**
 * Cloudflare bypass and challenge handling module - Updated for 2025
 * Handles phishing warnings, Turnstile challenges, and modern Cloudflare protections
 */

/**
 * Cross-version compatible timeout function for Puppeteer
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<void>}
 */
async function waitForTimeout(page, timeout) {
  try {
    // Try newer Puppeteer method first
    if (typeof page.waitForTimeout === 'function') {
      await page.waitForTimeout(timeout);
    } else if (typeof page.waitFor === 'function') {
      // Fallback to older Puppeteer method
      await page.waitFor(timeout);
    } else {
      // Ultimate fallback using setTimeout
      await new Promise(resolve => setTimeout(resolve, timeout));
    }
  } catch (error) {
    // If all else fails, use setTimeout
    await new Promise(resolve => setTimeout(resolve, timeout));
  }
}

/**
 * Analyzes the current page to detect Cloudflare challenges - Updated for 2025
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @returns {Promise<object>} Challenge information object
 */
async function analyzeCloudflareChallenge(page) {
  try {
    return await page.evaluate(() => {
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
      
      // Legacy challenge detection (still used on some sites)
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
      
      // Check for Turnstile response token
      const hasTurnstileResponse = document.querySelector('input[name="cf-turnstile-response"]') !== null;
      
      // Check for challenge completion indicators
      const isChallengeCompleted = hasTurnstileResponse && 
                                  document.querySelector('input[name="cf-turnstile-response"]')?.value;
      
      // Enhanced challenge detection logic
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
        bodySnippet: bodyText.substring(0, 200) // First 200 chars for debugging
      };
    });
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
 * Handles Cloudflare phishing warnings by clicking the continue button
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {string} currentUrl - Current URL being processed
 * @param {boolean} forceDebug - Debug mode flag
 * @returns {Promise<object>} Result object with success status and details
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
    
    // Wait a moment for the warning page to load
    await waitForTimeout(page, 2000);

    const challengeInfo = await analyzeCloudflareChallenge(page);
    
    if (challengeInfo.isPhishingWarning) {
      result.attempted = true;
      result.details = challengeInfo;
      
      if (forceDebug) {
        console.log(`[debug][cloudflare] Phishing warning detected on ${currentUrl}:`);
        console.log(`[debug][cloudflare]   Page Title: "${challengeInfo.title}"`);
        console.log(`[debug][cloudflare]   Current URL: ${challengeInfo.url}`);
      }

      try {
        await page.click('a[href*="continue"]', { timeout: 5000 });
        await page.waitForNavigation({ waitUntil: 'load', timeout: 30000 });
        
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
 * Attempts to solve Cloudflare challenges including Turnstile - Updated for 2025
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {string} currentUrl - Current URL being processed
 * @param {boolean} forceDebug - Debug mode flag
 * @returns {Promise<object>} Result object with success status and details
 */
async function handleVerificationChallenge(page, currentUrl, forceDebug = false) {
  const result = {
    success: false,
    attempted: false,
    error: null,
    details: null,
    requiresHuman: false
  };

  try {
    if (forceDebug) console.log(`[debug][cloudflare] Checking for verification challenge on ${currentUrl}`);
    
    // Wait for potential Cloudflare challenge to appear
    await waitForTimeout(page, 3000);

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
        console.log(`[debug][cloudflare]   Has CAPTCHA: ${challengeInfo.hasCaptcha}`);
      }

      // Check for CAPTCHA that requires human intervention
      if (challengeInfo.hasCaptcha) {
        result.requiresHuman = true;
        result.error = 'CAPTCHA detected - requires human intervention';
        console.warn(`? [cloudflare] CAPTCHA detected on ${currentUrl} - requires human intervention`);
        if (forceDebug) console.log(`[debug][cloudflare] Skipping automatic bypass due to CAPTCHA requirement`);
        return result;
      }

      // Attempt to solve the challenge with updated methods
      const solveResult = await attemptChallengeSolve(page, currentUrl, challengeInfo, forceDebug);
      result.success = solveResult.success;
      result.error = solveResult.error;
      
    } else {
      if (forceDebug) console.log(`[debug][cloudflare] No verification challenge detected on ${currentUrl}`);
      result.success = true; // No challenge to handle
    }
  } catch (error) {
    result.error = error.message;
    if (forceDebug) {
      console.log(`[debug][cloudflare] Challenge check failed for ${currentUrl}:`);
      console.log(`[debug][cloudflare]   Error: ${error.message}`);
      console.log(`[debug][cloudflare]   Stack: ${error.stack}`);
    }
  }

  return result;
}

/**
 * Attempts to solve a Cloudflare challenge with modern techniques - Updated for 2025
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {string} currentUrl - Current URL being processed
 * @param {object} challengeInfo - Challenge analysis results
 * @param {boolean} forceDebug - Debug mode flag
 * @returns {Promise<object>} Solve attempt result
 */
async function attemptChallengeSolve(page, currentUrl, challengeInfo, forceDebug = false) {
  const result = {
    success: false,
    error: null,
    method: null
  };

  // Method 1: Handle Turnstile challenges (2025 primary method)
  if (challengeInfo.isTurnstile) {
    try {
      if (forceDebug) console.log(`[debug][cloudflare] Attempting Turnstile method for ${currentUrl}`);
      
      const turnstileResult = await handleTurnstileChallenge(page, forceDebug);
      if (turnstileResult.success) {
        result.success = true;
        result.method = 'turnstile';
        if (forceDebug) console.log(`[debug][cloudflare] Turnstile challenge solved successfully for ${currentUrl}`);
        return result;
      } else {
        if (forceDebug) console.log(`[debug][cloudflare] Turnstile method failed: ${turnstileResult.error}`);
      }
    } catch (turnstileError) {
      if (forceDebug) console.log(`[debug][cloudflare] Turnstile method error: ${turnstileError.message}`);
    }
  }

  // Method 2: Handle JS challenges (wait for automatic completion)
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
      if (forceDebug) console.log(`[debug][cloudflare] JS challenge wait error: ${jsError.message}`);
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
      if (forceDebug) console.log(`[debug][cloudflare] Legacy checkbox method error: ${legacyError.message}`);
    }
  }

  // Method 4: Alternative element clicking (final fallback)
  try {
    if (forceDebug) console.log(`[debug][cloudflare] Trying alternative click method for ${currentUrl}`);
    
    const alternatives = [
      '.cf-challenge-running',
      '[data-ray]',
      '.challenge-stage',
      '.challenge-form'
    ];
    
    for (const selector of alternatives) {
      try {
        await page.click(selector, { timeout: 3000 });
        await waitForTimeout(page, 3000);
        
        // Check if challenge is solved
        const completionCheck = await checkChallengeCompletion(page);
        if (completionCheck.isCompleted) {
          result.success = true;
          result.method = 'alternative_click';
          if (forceDebug) console.log(`[debug][cloudflare] Alternative click method succeeded for ${currentUrl} using ${selector}`);
          return result;
        }
      } catch (clickError) {
        // Continue to next selector
        continue;
      }
    }
  } catch (altError) {
    result.error = `All bypass methods failed. Last error: ${altError.message}`;
    if (forceDebug) console.log(`[debug][cloudflare] All bypass methods failed for ${currentUrl}: ${altError.message}`);
  }

  if (!result.success) {
    result.error = result.error || 'All challenge bypass methods failed';
  }

  return result;
}

/**
 * Handles modern Turnstile challenges - New for 2025
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {boolean} forceDebug - Debug mode flag
 * @returns {Promise<object>} Turnstile handling result
 */
async function handleTurnstileChallenge(page, forceDebug = false) {
  const result = {
    success: false,
    error: null
  };

  try {
    // Wait for Turnstile iframe to load
    const turnstileSelectors = [
      'iframe[src*="challenges.cloudflare.com"]',
      'iframe[title*="Widget containing a Cloudflare"]',
      'iframe[title*="Cloudflare security challenge"]'
    ];
    
    let turnstileFrame = null;
    for (const selector of turnstileSelectors) {
      try {
        await page.waitForSelector(selector, { timeout: 5000 });
        const frames = await page.frames();
        turnstileFrame = frames.find(frame => 
          frame.url().includes('challenges.cloudflare.com') ||
          frame.url().includes('turnstile')
        );
        if (turnstileFrame) break;
      } catch (e) {
        continue;
      }
    }

    if (turnstileFrame) {
      if (forceDebug) console.log(`[debug][cloudflare] Found Turnstile iframe`);
      
      // Wait for checkbox in iframe
      const checkboxSelectors = [
        'input[type="checkbox"].ctp-checkbox',
        'input[type="checkbox"]',
        '.ctp-checkbox-label',
        '.ctp-checkbox'
      ];
      
      for (const selector of checkboxSelectors) {
        try {
          await turnstileFrame.waitForSelector(selector, { timeout: 5000 });
          
          // Simulate human-like interaction
          await waitForTimeout(page, Math.random() * 1000 + 500);
          await turnstileFrame.click(selector);
          
          if (forceDebug) console.log(`[debug][cloudflare] Clicked Turnstile checkbox: ${selector}`);
          break;
        } catch (e) {
          continue;
        }
      }
      
      // Wait for Turnstile completion
      await page.waitForFunction(
        () => {
          const responseInput = document.querySelector('input[name="cf-turnstile-response"]');
          return responseInput && responseInput.value && responseInput.value.length > 0;
        },
        { timeout: 30000 }
      );
      
      result.success = true;
    } else {
      // Try container-based Turnstile (non-iframe)
      const containerSelectors = [
        '.cf-turnstile',
        '.ctp-checkbox-container',
        '.ctp-checkbox-label'
      ];
      
      for (const selector of containerSelectors) {
        try {
          await page.waitForSelector(selector, { timeout: 5000 });
          
          // Human-like interaction
          await waitForTimeout(page, Math.random() * 1000 + 500);
          await page.click(selector);
          
          if (forceDebug) console.log(`[debug][cloudflare] Clicked Turnstile container: ${selector}`);
          
          // Wait for completion
          const completionCheck = await checkChallengeCompletion(page);
          if (completionCheck.isCompleted) {
            result.success = true;
            break;
          }
        } catch (e) {
          continue;
        }
      }
      
      if (!result.success) {
        result.error = 'Turnstile iframe/container not found or not interactive';
      }
    }
    
  } catch (error) {
    result.error = `Turnstile handling failed: ${error.message}`;
  }

  return result;
}

/**
 * Waits for JS challenge completion - New for 2025
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {boolean} forceDebug - Debug mode flag
 * @returns {Promise<object>} JS challenge result
 */
async function waitForJSChallengeCompletion(page, forceDebug = false) {
  const result = {
    success: false,
    error: null
  };

  try {
    if (forceDebug) console.log(`[debug][cloudflare] Waiting for JS challenge completion`);
    
    // Wait for challenge to complete automatically
    await page.waitForFunction(
      () => {
        return !document.body.textContent.includes('Checking your browser') &&
               !document.body.textContent.includes('Please wait while we verify') &&
               !document.querySelector('.cf-challenge-running') &&
               !document.querySelector('[data-cf-challenge]');
      },
      { timeout: 30000 }
    );
    
    result.success = true;
  } catch (error) {
    result.error = `JS challenge timeout: ${error.message}`;
  }

  return result;
}

/**
 * Handles legacy checkbox challenges - Fallback for older implementations
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {boolean} forceDebug - Debug mode flag
 * @returns {Promise<object>} Legacy challenge result
 */
async function handleLegacyCheckbox(page, forceDebug = false) {
  const result = {
    success: false,
    error: null
  };

  try {
    const legacySelectors = [
      'input[type="checkbox"]#challenge-form',
      'input[type="checkbox"][name="cf_captcha_kind"]',
      '.cf-turnstile input[type="checkbox"]'
    ];

    for (const selector of legacySelectors) {
      try {
        await page.waitForSelector(selector, { timeout: 5000 });
        
        const checkbox = await page.$(selector);
        if (checkbox) {
          const box = await checkbox.boundingBox();
          if (box) {
            // Simulate human-like mouse movement
            await page.mouse.move(box.x - 50, box.y - 50);
            await waitForTimeout(page, Math.random() * 500 + 200);
            await page.mouse.move(box.x + box.width/2, box.y + box.height/2, { steps: 5 });
            await waitForTimeout(page, Math.random() * 300 + 100);

            await checkbox.click();
            if (forceDebug) console.log(`[debug][cloudflare] Clicked legacy checkbox: ${selector}`);

            // Wait for challenge completion
            const completionCheck = await checkChallengeCompletion(page);
            if (completionCheck.isCompleted) {
              result.success = true;
              break;
            }
          }
        }
      } catch (e) {
        continue;
      }
    }

    if (!result.success) {
      result.error = 'No interactive legacy checkbox found';
    }
    
  } catch (error) {
    result.error = `Legacy checkbox handling failed: ${error.message}`;
  }

  return result;
}

/**
 * Checks if challenge has been completed - New utility function
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @returns {Promise<object>} Completion status
 */
async function checkChallengeCompletion(page) {
  try {
    const isCompleted = await page.evaluate(() => {
      // Check for absence of challenge indicators
      const noChallengeRunning = !document.querySelector('.cf-challenge-running');
      const noChallengeContainer = !document.querySelector('.cf-challenge-container');
      const noChallengePage = !document.body.textContent.includes('Checking your browser') &&
                             !document.body.textContent.includes('Just a moment') &&
                             !document.body.textContent.includes('Verify you are human');
      
      // Check for completion indicators
      const hasClearanceCookie = document.cookie.includes('cf_clearance');
      const hasTurnstileResponse = document.querySelector('input[name="cf-turnstile-response"]')?.value;
      
      return (noChallengeRunning && noChallengeContainer && noChallengePage) ||
             hasClearanceCookie ||
             hasTurnstileResponse;
    });
    
    return { isCompleted };
  } catch (error) {
    return { isCompleted: false, error: error.message };
  }
}

/**
 * Main function to handle all Cloudflare challenges for a given page - Updated for 2025
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {string} currentUrl - Current URL being processed
 * @param {object} siteConfig - Site configuration object
 * @param {boolean} forceDebug - Debug mode flag
 * @returns {Promise<object>} Combined result of all Cloudflare handling
 */
async function handleCloudflareProtection(page, currentUrl, siteConfig, forceDebug = false) {
  const result = {
    phishingWarning: { attempted: false, success: false },
    verificationChallenge: { attempted: false, success: false },
    overallSuccess: true,
    errors: []
  };

  // Handle phishing warnings if enabled
  if (siteConfig.cloudflare_phish === true) {
    const phishingResult = await handlePhishingWarning(page, currentUrl, forceDebug);
    result.phishingWarning = phishingResult;
    
    if (phishingResult.attempted && !phishingResult.success) {
      result.overallSuccess = false;
      result.errors.push(`Phishing warning bypass failed: ${phishingResult.error}`);
    }
  }

  // Handle verification challenges if enabled
  if (siteConfig.cloudflare_bypass === true) {
    const challengeResult = await handleVerificationChallenge(page, currentUrl, forceDebug);
    result.verificationChallenge = challengeResult;
    
    if (challengeResult.attempted && !challengeResult.success) {
      result.overallSuccess = false;
      if (challengeResult.requiresHuman) {
        result.errors.push(`Human intervention required: ${challengeResult.error}`);
      } else {
        result.errors.push(`Challenge bypass failed: ${challengeResult.error}`);
      }
    }
  }

  // Log overall result
  if (!result.overallSuccess && forceDebug) {
    console.log(`[debug][cloudflare] Overall Cloudflare handling failed for ${currentUrl}:`);
    result.errors.forEach(error => {
      console.log(`[debug][cloudflare]   - ${error}`);
    });
  } else if ((result.phishingWarning.attempted || result.verificationChallenge.attempted) && forceDebug) {
    console.log(`[debug][cloudflare] Successfully handled Cloudflare protections for ${currentUrl}`);
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
  checkChallengeCompletion
};