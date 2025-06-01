/**
 * Cloudflare bypass and challenge handling module
 * Handles phishing warnings and "Verify you are human" challenges
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
 * Analyzes the current page to detect Cloudflare challenges
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @returns {Promise<object>} Challenge information object
 */
async function analyzeCloudflareChallenge(page) {
  try {
    return await page.evaluate(() => {
      const title = document.title || '';
      const bodyText = document.body ? document.body.textContent : '';
      const hasCheckbox = document.querySelector('input[type="checkbox"]#challenge-form') !== null;
      const hasChallengeRunning = document.querySelector('.cf-challenge-running') !== null;
      const hasDataRay = document.querySelector('[data-ray]') !== null;
      const hasTurnstile = document.querySelector('.cf-turnstile') !== null;
      const hasCaptcha = bodyText.includes('CAPTCHA') || bodyText.includes('captcha');
      const hasPhishingWarning = bodyText.includes('This website has been reported for potential phishing') ||
                                title.includes('Attention Required') ||
                                document.querySelector('a[href*="continue"]') !== null;
      
      return {
        isChallengePresent: title.includes('Just a moment') ||
                           bodyText.includes('Checking your browser') ||
                           bodyText.includes('Verify you are human') ||
                           hasCheckbox || hasChallengeRunning || hasDataRay,
        isPhishingWarning: hasPhishingWarning,
        title,
        hasCheckbox,
        hasChallengeRunning,
        hasDataRay,
        hasTurnstile,
        hasCaptcha,
        url: window.location.href,
        bodySnippet: bodyText.substring(0, 200) // First 200 chars for debugging
      };
    });
  } catch (error) {
    return {
      isChallengePresent: false,
      isPhishingWarning: false,
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
 * Attempts to solve Cloudflare "Verify you are human" challenges
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
        console.log(`[debug][cloudflare]   Has Checkbox: ${challengeInfo.hasCheckbox}`);
        console.log(`[debug][cloudflare]   Has Challenge Running: ${challengeInfo.hasChallengeRunning}`);
        console.log(`[debug][cloudflare]   Has Data Ray: ${challengeInfo.hasDataRay}`);
        console.log(`[debug][cloudflare]   Has Turnstile: ${challengeInfo.hasTurnstile}`);
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

      // Attempt to solve the challenge
      const solveResult = await attemptChallengeSolve(page, currentUrl, forceDebug);
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
 * Attempts to solve a Cloudflare challenge by interacting with UI elements
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {string} currentUrl - Current URL being processed
 * @param {boolean} forceDebug - Debug mode flag
 * @returns {Promise<object>} Solve attempt result
 */
async function attemptChallengeSolve(page, currentUrl, forceDebug = false) {
  const result = {
    success: false,
    error: null,
    method: null
  };

  // Look for the verification checkbox
  const checkboxSelector = 'input[type="checkbox"]#challenge-form, input[type="checkbox"][name="cf_captcha_kind"], .cf-turnstile input[type="checkbox"], iframe[src*="challenges.cloudflare.com"]';

  try {
    // Method 1: Try checkbox interaction
    if (forceDebug) console.log(`[debug][cloudflare] Attempting checkbox method for ${currentUrl}`);
    
    await page.waitForSelector(checkboxSelector, { timeout: 10000 });
    
    const checkbox = await page.$(checkboxSelector);
    if (checkbox) {
      const box = await checkbox.boundingBox();
      if (box) {
        if (forceDebug) console.log(`[debug][cloudflare] Found checkbox, clicking at coordinates (${box.x + box.width/2}, ${box.y + box.height/2})`);
        
        // Simulate human-like mouse movement
        await page.mouse.move(box.x - 50, box.y - 50);
        await waitForTimeout(page, Math.random() * 500 + 200);
        await page.mouse.move(box.x + box.width/2, box.y + box.height/2, { steps: 5 });
        await waitForTimeout(page, Math.random() * 300 + 100);

        // Click the checkbox
        await checkbox.click();
        if (forceDebug) console.log(`[debug][cloudflare] Clicked verification checkbox`);

        // Wait for challenge to complete
        await waitForTimeout(page, 5000);

        // Check if challenge is solved
        await page.waitForFunction(() => {
          return !document.body.textContent.includes('Checking your browser') &&
                 !document.body.textContent.includes('Just a moment');
        }, { timeout: 30000 });
        
        result.success = true;
        result.method = 'checkbox';
        if (forceDebug) console.log(`[debug][cloudflare] Challenge solved successfully for ${currentUrl}`);
        return result;
      } else {
        if (forceDebug) console.log(`[debug][cloudflare] Could not get bounding box for checkbox`);
      }
    } else {
      if (forceDebug) console.log(`[debug][cloudflare] Checkbox element not found`);
    }
  } catch (checkboxError) {
    if (forceDebug) console.log(`[debug][cloudflare] Checkbox method failed: ${checkboxError.message}`);
    
    // Method 2: Try alternative click approach
    try {
      if (forceDebug) console.log(`[debug][cloudflare] Trying alternative click method for ${currentUrl}`);
      
      await page.click('.cf-challenge-running, [data-ray], .cf-turnstile', { timeout: 5000 });
      await waitForTimeout(page, 5000);
      
      // Check if challenge is solved
      await page.waitForFunction(() => {
        return !document.body.textContent.includes('Checking your browser') &&
               !document.body.textContent.includes('Just a moment');
      }, { timeout: 15000 });
      
      result.success = true;
      result.method = 'alternative_click';
      if (forceDebug) console.log(`[debug][cloudflare] Alternative click method succeeded for ${currentUrl}`);
      return result;
    } catch (altError) {
      result.error = `All bypass methods failed. Checkbox error: ${checkboxError.message}. Alternative error: ${altError.message}`;
      if (forceDebug) console.log(`[debug][cloudflare] All bypass methods failed for ${currentUrl}: ${altError.message}`);
    }
  }

  return result;
}

/**
 * Main function to handle all Cloudflare challenges for a given page
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
  waitForTimeout
};