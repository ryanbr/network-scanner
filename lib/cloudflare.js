/**
 * Cloudflare bypass and challenge handling module - Enhanced with timeout handling
 * Handles phishing warnings, Turnstile challenges, and modern Cloudflare protections
 */

/**
 * Cross-version compatible timeout function for Puppeteer with timeout protection
 */
async function waitForTimeout(page, timeout) {
  try {
    // Try newer Puppeteer method first
    if (typeof page.waitForTimeout === 'function') {
      await Promise.race([
        page.waitForTimeout(timeout),
        new Promise((_, reject) => setTimeout(() => reject(new Error('waitForTimeout exceeded')), timeout + 5000))
      ]);
    } else if (typeof page.waitFor === 'function') {
      await Promise.race([
        page.waitFor(timeout),
        new Promise((_, reject) => setTimeout(() => reject(new Error('waitFor exceeded')), timeout + 5000))
      ]);
    } else {
      await new Promise(resolve => setTimeout(resolve, timeout));
    }
  } catch (error) {
    // If all else fails, use setTimeout
    await new Promise(resolve => setTimeout(resolve, Math.min(timeout, 5000)));
  }
}

/**
 * Safe page evaluation with timeout protection
 */
async function safePageEvaluate(page, func, timeout = 10000) {
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
async function safeClick(page, selector, timeout = 5000) {
  try {
    return await Promise.race([
      page.click(selector, { timeout: timeout }),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Click timeout')), timeout + 1000)
      )
    ]);
  } catch (error) {
    throw new Error(`Click failed: ${error.message}`);
  }
}

/**
 * Safe navigation waiting with timeout protection
 */
async function safeWaitForNavigation(page, timeout = 15000) {
  try {
    return await Promise.race([
      page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: timeout }),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Navigation timeout')), timeout + 2000)
      )
    ]);
  } catch (error) {
    console.warn(`[cloudflare] Navigation wait failed: ${error.message}`);
    // Don't throw - just continue
  }
}

/**
 * Analyzes the current page to detect Cloudflare challenges - Enhanced with timeout protection
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
    }, 10000); // 10 second timeout for page evaluation
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
 * Handles Cloudflare phishing warnings with timeout protection
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
    await waitForTimeout(page, 2000);

    const challengeInfo = await analyzeCloudflareChallenge(page);
    
    if (challengeInfo.isPhishingWarning) {
      result.attempted = true;
      result.details = challengeInfo;
      
      if (forceDebug) {
        console.log(`[debug][cloudflare] Phishing warning detected on ${currentUrl}`);
      }

      try {
        // Use safe click with shorter timeout
        await safeClick(page, 'a[href*="continue"]', 3000);
        await safeWaitForNavigation(page, 10000);
        
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
 * Attempts to solve Cloudflare challenges with timeout protection
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
    
    // Shorter wait for challenges
    await waitForTimeout(page, 2000);

    const challengeInfo = await analyzeCloudflareChallenge(page);
    result.details = challengeInfo;

    if (challengeInfo.isChallengePresent) {
      result.attempted = true;
      
      if (forceDebug) {
        console.log(`[debug][cloudflare] Challenge detected on ${currentUrl}`);
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
    // Overall timeout for all challenge solving attempts
    return await Promise.race([
      attemptChallengeSolve(page, currentUrl, challengeInfo, forceDebug),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Challenge solving timeout')), 30000)
      )
    ]);
  } catch (error) {
    result.error = `Challenge solving timed out: ${error.message}`;
    if (forceDebug) console.log(`[debug][cloudflare] Challenge solving timeout for ${currentUrl}`);
    return result;
  }
}

/**
 * Attempts to solve a Cloudflare challenge with modern techniques
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
      if (forceDebug) console.log(`[debug][cloudflare] JS challenge wait error: ${jsError.message}`);
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
      if (forceDebug) console.log(`[debug][cloudflare] Turnstile method error: ${turnstileError.message}`);
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

  if (!result.success) {
    result.error = result.error || 'All challenge bypass methods failed';
  }

  return result;
}

/**
 * Waits for JS challenge completion with timeout protection
 */
async function waitForJSChallengeCompletion(page, forceDebug = false) {
  const result = {
    success: false,
    error: null
  };

  try {
    if (forceDebug) console.log(`[debug][cloudflare] Waiting for JS challenge completion`);
    
    // Wait for challenge to complete automatically with shorter timeout
    await Promise.race([
      page.waitForFunction(
        () => {
          return !document.body.textContent.includes('Checking your browser') &&
                 !document.body.textContent.includes('Please wait while we verify') &&
                 !document.querySelector('.cf-challenge-running') &&
                 !document.querySelector('[data-cf-challenge]');
        },
        { timeout: 20000 }
      ),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('JS challenge timeout')), 25000)
      )
    ]);
    
    result.success = true;
  } catch (error) {
    result.error = `JS challenge timeout: ${error.message}`;
  }

  return result;
}

/**
 * Handles modern Turnstile challenges with timeout protection
 */
async function handleTurnstileChallenge(page, forceDebug = false) {
  const result = {
    success: false,
    error: null
  };

  try {
    // Much shorter timeout for Turnstile operations
    const turnstileTimeout = 10000; // 10 seconds
    
    const turnstileSelectors = [
      'iframe[src*="challenges.cloudflare.com"]',
      'iframe[title*="Widget containing a Cloudflare"]',
      'iframe[title*="Cloudflare security challenge"]'
    ];
    
    let turnstileFrame = null;
    for (const selector of turnstileSelectors) {
      try {
        await Promise.race([
          page.waitForSelector(selector, { timeout: 3000 }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Selector timeout')), 4000))
        ]);
        
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
      
      const checkboxSelectors = [
        'input[type="checkbox"].ctp-checkbox',
        'input[type="checkbox"]',
        '.ctp-checkbox-label',
        '.ctp-checkbox'
      ];
      
      for (const selector of checkboxSelectors) {
        try {
          await Promise.race([
            turnstileFrame.waitForSelector(selector, { timeout: 3000 }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Checkbox timeout')), 4000))
          ]);
          
          await waitForTimeout(page, 500);
          await turnstileFrame.click(selector);
          
          if (forceDebug) console.log(`[debug][cloudflare] Clicked Turnstile checkbox: ${selector}`);
          break;
        } catch (e) {
          continue;
        }
      }
      
      // Wait for Turnstile completion with timeout
      await Promise.race([
        page.waitForFunction(
          () => {
            const responseInput = document.querySelector('input[name="cf-turnstile-response"]');
            return responseInput && responseInput.value && responseInput.value.length > 0;
          },
          { timeout: 15000 }
        ),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Turnstile completion timeout')), 20000))
      ]);
      
      result.success = true;
    } else {
      result.error = 'Turnstile iframe not found';
    }
    
  } catch (error) {
    result.error = `Turnstile handling failed: ${error.message}`;
  }

  return result;
}

/**
 * Handles legacy checkbox challenges with timeout protection
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
        await Promise.race([
          page.waitForSelector(selector, { timeout: 3000 }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Legacy selector timeout')), 4000))
        ]);
        
        const checkbox = await page.$(selector);
        if (checkbox) {
          await checkbox.click();
          if (forceDebug) console.log(`[debug][cloudflare] Clicked legacy checkbox: ${selector}`);

          const completionCheck = await checkChallengeCompletion(page);
          if (completionCheck.isCompleted) {
            result.success = true;
            break;
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
 * Checks if challenge has been completed with timeout protection
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
    }, 5000);
    
    return { isCompleted };
  } catch (error) {
    return { isCompleted: false, error: error.message };
  }
}

/**
 * Main function to handle all Cloudflare challenges with comprehensive timeout protection
 */
async function handleCloudflareProtection(page, currentUrl, siteConfig, forceDebug = false) {
  const result = {
    phishingWarning: { attempted: false, success: false },
    verificationChallenge: { attempted: false, success: false },
    overallSuccess: true,
    errors: []
  };

  try {
    // Overall timeout for all Cloudflare operations
    return await Promise.race([
      performCloudflareHandling(page, currentUrl, siteConfig, forceDebug),
      new Promise((resolve) => {
        setTimeout(() => {
          console.warn(`[cloudflare] Overall timeout for ${currentUrl} - continuing with scan`);
          resolve({
            phishingWarning: { attempted: false, success: true },
            verificationChallenge: { attempted: false, success: true },
            overallSuccess: true,
            errors: ['Cloudflare handling timed out']
          });
        }, 45000); // 45 second overall timeout
      })
    ]);
  } catch (error) {
    result.overallSuccess = false;
    result.errors.push(`Cloudflare handling failed: ${error.message}`);
    return result;
  }
}

/**
 * Performs the actual Cloudflare handling
 */
async function performCloudflareHandling(page, currentUrl, siteConfig, forceDebug = false) {
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
