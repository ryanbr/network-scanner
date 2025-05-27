// === Cloudflare Bypass Module ===
// This module handles Cloudflare security bypass functionality for the network scanner script.
// It provides methods to automatically handle phishing warnings and verification challenges.

/**
 * CloudflareBypass class handles various Cloudflare security measures.
 * Supports both phishing warning bypasses and verification challenge solving.
 */
class CloudflareBypass {
  constructor() {
    this.debugMode = false;
  }

  /**
   * Initialize the Cloudflare bypass manager
   * @param {boolean} debugMode - Enable debug logging
   */
  initialize(debugMode = false) {
    this.debugMode = debugMode;
    
    if (this.debugMode) {
      console.log(`[debug][cloudflare] Cloudflare bypass manager initialized`);
    }
  }

  /**
   * Detect if the current page is a Cloudflare phishing warning
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @returns {Promise<boolean>} True if phishing warning is detected
   */
  async detectPhishingWarning(page) {
    try {
      const isPhishingWarning = await page.evaluate(() => {
        const bodyText = document.body.textContent || '';
        const title = document.title || '';
        
        // Check for common phishing warning indicators
        const phishingIndicators = [
          'This website has been reported for potential phishing',
          'Attention Required',
          'Security Check',
          'Phishing Warning'
        ];
        
        const hasPhishingText = phishingIndicators.some(indicator => 
          bodyText.includes(indicator) || title.includes(indicator)
        );
        
        // Check for continue button that's typically present in phishing warnings
        const hasContinueButton = document.querySelector('a[href*="continue"]') !== null ||
                                  document.querySelector('button[data-action="continue"]') !== null ||
                                  document.querySelector('.continue-button') !== null;
        
        return hasPhishingText || hasContinueButton;
      });

      return isPhishingWarning;
    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][cloudflare] Error detecting phishing warning: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Attempt to bypass Cloudflare phishing warning
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async bypassPhishingWarning(page, currentUrl = 'unknown') {
    try {
      if (this.debugMode) {
        console.log(`[debug][cloudflare] Checking for phishing warning on ${currentUrl}`);
      }

      // Wait a moment for the warning page to fully load
      await page.waitForTimeout(2000);

      const isPhishingWarning = await this.detectPhishingWarning(page);
      
      if (!isPhishingWarning) {
        return true; // No phishing warning to bypass
      }

      if (this.debugMode) {
        console.log(`[debug][cloudflare] Phishing warning detected, attempting to bypass`);
      }

      // Try multiple selectors for the continue button
      const continueSelectors = [
        'a[href*="continue"]',
        'button[data-action="continue"]',
        '.continue-button',
        '[data-testid="continue-button"]',
        'a[data-cy="continue-link"]',
        'button:contains("Continue")',
        'a:contains("Continue")'
      ];

      let bypassSuccessful = false;

      for (const selector of continueSelectors) {
        try {
          // Check if element exists
          const element = await page.$(selector);
          if (element) {
            if (this.debugMode) {
              console.log(`[debug][cloudflare] Found continue element with selector: ${selector}`);
            }

            // Click the continue button
            await element.click();
            
            // Wait for navigation
            await page.waitForNavigation({ 
              waitUntil: 'load', 
              timeout: 30000 
            });

            bypassSuccessful = true;
            if (this.debugMode) {
              console.log(`[debug][cloudflare] Successfully bypassed phishing warning`);
            }
            break;
          }
        } catch (selectorError) {
          // Try next selector
          continue;
        }
      }

      if (!bypassSuccessful) {
        // Fallback: try clicking anywhere that might be a continue action
        try {
          await page.evaluate(() => {
            // Look for any clickable element with "continue" text
            const allElements = document.querySelectorAll('*');
            for (const element of allElements) {
              const text = element.textContent?.toLowerCase() || '';
              if (text.includes('continue') && (element.tagName === 'A' || element.tagName === 'BUTTON')) {
                element.click();
                return true;
              }
            }
            return false;
          });

          await page.waitForTimeout(3000);
          bypassSuccessful = true;
        } catch (fallbackError) {
          if (this.debugMode) {
            console.log(`[debug][cloudflare] Fallback bypass method failed: ${fallbackError.message}`);
          }
        }
      }

      return bypassSuccessful;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][cloudflare] Phishing warning bypass failed: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Detect if the current page has a Cloudflare verification challenge
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @returns {Promise<boolean>} True if verification challenge is detected
   */
  async detectVerificationChallenge(page) {
    try {
      const isChallengePresent = await page.evaluate(() => {
        const bodyText = document.body.textContent || '';
        const title = document.title || '';
        
        // Check for common challenge indicators
        const challengeIndicators = [
          'Just a moment',
          'Checking your browser',
          'Verify you are human',
          'Please complete the security check',
          'DDoS protection by Cloudflare'
        ];
        
        const hasChallengeText = challengeIndicators.some(indicator => 
          bodyText.includes(indicator) || title.includes(indicator)
        );
        
        // Check for common challenge elements
        const challengeSelectors = [
          'input[type="checkbox"]#challenge-form',
          'input[type="checkbox"][name="cf_captcha_kind"]',
          '.cf-turnstile input[type="checkbox"]',
          'iframe[src*="challenges.cloudflare.com"]',
          '.cf-challenge-running',
          '[data-ray]',
          '.cf-turnstile'
        ];
        
        const hasChallengeElements = challengeSelectors.some(selector => 
          document.querySelector(selector) !== null
        );
        
        return hasChallengeText || hasChallengeElements;
      });

      return isChallengePresent;
    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][cloudflare] Error detecting verification challenge: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Attempt to solve Cloudflare verification challenge
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async solveVerificationChallenge(page, currentUrl = 'unknown') {
    try {
      if (this.debugMode) {
        console.log(`[debug][cloudflare] Checking for verification challenge on ${currentUrl}`);
      }

      // Wait for potential challenge to appear
      await page.waitForTimeout(3000);

      const isChallengePresent = await this.detectVerificationChallenge(page);
      
      if (!isChallengePresent) {
        return true; // No challenge to solve
      }

      if (this.debugMode) {
        console.log(`[debug][cloudflare] Verification challenge detected, attempting to solve`);
      }

      // Multiple checkbox selectors to try
      const checkboxSelectors = [
        'input[type="checkbox"]#challenge-form',
        'input[type="checkbox"][name="cf_captcha_kind"]',
        '.cf-turnstile input[type="checkbox"]',
        'iframe[src*="challenges.cloudflare.com"]',
        '.cf-turnstile',
        '[data-sitekey]'
      ];

      let solveSuccessful = false;

      for (const checkboxSelector of checkboxSelectors) {
        try {
          // Wait for checkbox to be available
          await page.waitForSelector(checkboxSelector, { timeout: 10000 });

          if (this.debugMode) {
            console.log(`[debug][cloudflare] Found challenge element with selector: ${checkboxSelector}`);
          }

          // Get the checkbox element
          const checkbox = await page.$(checkboxSelector);
          if (checkbox) {
            // Get bounding box for human-like interaction
            const box = await checkbox.boundingBox();
            if (box) {
              // Simulate human-like mouse movement
              await this.simulateHumanMouseMovement(page, box);

              // Click the checkbox
              await checkbox.click();
              
              if (this.debugMode) {
                console.log(`[debug][cloudflare] Clicked verification checkbox`);
              }

              // Wait for challenge to complete
              await page.waitForTimeout(5000);

              // Check if challenge is solved by waiting for page content to change
              await page.waitForFunction(() => {
                const bodyText = document.body.textContent || '';
                return !bodyText.includes('Checking your browser') &&
                       !bodyText.includes('Just a moment') &&
                       !bodyText.includes('Verify you are human');
              }, { timeout: 30000 });

              solveSuccessful = true;
              if (this.debugMode) {
                console.log(`[debug][cloudflare] Successfully solved verification challenge`);
              }
              break;
            }
          }
        } catch (selectorError) {
          // Try next selector
          continue;
        }
      }

      // Alternative approach if checkbox method failed
      if (!solveSuccessful) {
        try {
          if (this.debugMode) {
            console.log(`[debug][cloudflare] Checkbox method failed, trying alternative approach`);
          }

          // Try clicking on common challenge containers
          const alternativeSelectors = [
            '.cf-challenge-running',
            '[data-ray]',
            '.cf-turnstile',
            '.challenge-form'
          ];

          for (const selector of alternativeSelectors) {
            try {
              await page.click(selector, { timeout: 5000 });
              await page.waitForTimeout(5000);
              solveSuccessful = true;
              break;
            } catch (altErr) {
              continue;
            }
          }
        } catch (alternativeError) {
          if (this.debugMode) {
            console.log(`[debug][cloudflare] Alternative approach failed: ${alternativeError.message}`);
          }
        }
      }

      return solveSuccessful;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][cloudflare] Verification challenge solving failed: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Simulate human-like mouse movement before clicking
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {object} targetBox - Bounding box of the target element
   */
  async simulateHumanMouseMovement(page, targetBox) {
    try {
      // Start from a random position near the target
      const startX = targetBox.x - 50 + Math.random() * 100;
      const startY = targetBox.y - 50 + Math.random() * 100;
      
      // Move to start position
      await page.mouse.move(startX, startY);
      await page.waitForTimeout(Math.random() * 500 + 200);
      
      // Move to target center with steps for natural movement
      const targetX = targetBox.x + targetBox.width / 2;
      const targetY = targetBox.y + targetBox.height / 2;
      
      await page.mouse.move(targetX, targetY, { steps: 5 });
      await page.waitForTimeout(Math.random() * 300 + 100);
      
    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][cloudflare] Mouse movement simulation failed: ${error.message}`);
      }
    }
  }

  /**
   * Handle both phishing warning and verification challenge if enabled
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {boolean} phishBypass - Enable phishing warning bypass
   * @param {boolean} challengeBypass - Enable verification challenge bypass
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<{phishing: boolean, challenge: boolean}>} Success status for both methods
   */
  async handleCloudflareProtection(page, phishBypass, challengeBypass, currentUrl = 'unknown') {
    const results = {
      phishing: true, // Default to true if not attempted
      challenge: true // Default to true if not attempted
    };

    if (phishBypass) {
      results.phishing = await this.bypassPhishingWarning(page, currentUrl);
    }

    if (challengeBypass) {
      results.challenge = await this.solveVerificationChallenge(page, currentUrl);
    }

    return results;
  }

  /**
   * Get statistics about Cloudflare bypass capabilities
   * @returns {object} Statistics object
   */
  getStats() {
    return {
      supportedMethods: ['phishingBypass', 'challengeSolving'],
      detectionMethods: ['textAnalysis', 'elementDetection'],
      humanSimulation: true
    };
  }

  /**
   * Test if current page has any Cloudflare protection
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @returns {Promise<{hasPhishing: boolean, hasChallenge: boolean}>} Detection results
   */
  async detectCloudflareProtection(page) {
    try {
      const hasPhishing = await this.detectPhishingWarning(page);
      const hasChallenge = await this.detectVerificationChallenge(page);
      
      if (this.debugMode && (hasPhishing || hasChallenge)) {
        console.log(`[debug][cloudflare] Protection detected - Phishing: ${hasPhishing}, Challenge: ${hasChallenge}`);
      }
      
      return {
        hasPhishing,
        hasChallenge
      };
    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][cloudflare] Protection detection failed: ${error.message}`);
      }
      return {
        hasPhishing: false,
        hasChallenge: false
      };
    }
  }
}

// Export the class and create a default instance
const cloudflareBypass = new CloudflareBypass();

module.exports = {
  CloudflareBypass,
  cloudflareBypass
};
