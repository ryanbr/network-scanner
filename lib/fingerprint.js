// === Fingerprint Spoofing Module ===
// This module handles browser fingerprint spoofing functionality for the network scanner script.
// It provides methods to generate randomized or fixed fingerprint values to bypass detection.

/**
 * FingerprintManager class handles browser fingerprint spoofing.
 * Supports both randomized and fixed fingerprint values.
 */
class FingerprintManager {
  constructor() {
    this.debugMode = false;
    // Default values for fingerprint spoofing if not set to 'random'
    this.DEFAULT_PLATFORM = 'Win32';
    this.DEFAULT_TIMEZONE = 'America/New_York';
  }

  /**
   * Initialize the fingerprint manager
   * @param {boolean} debugMode - Enable debug logging
   */
  initialize(debugMode = false) {
    this.debugMode = debugMode;
    
    if (this.debugMode) {
      console.log(`[debug][fingerprint] Fingerprint manager initialized`);
    }
  }

  /**
   * Generates an object with randomized browser fingerprint values.
   * This is used to spoof various navigator and screen properties to make
   * the headless browser instance appear more like a regular user's browser
   * and potentially bypass some fingerprint-based bot detection.
   *
   * @returns {object} An object containing the spoofed fingerprint properties:
   * @property {number} deviceMemory - Randomized device memory (4 or 8 GB).
   * @property {number} hardwareConcurrency - Randomized CPU cores (2, 4, or 8).
   * @property {object} screen - Randomized screen dimensions and color depth.
   * @property {number} screen.width - Randomized screen width.
   * @property {number} screen.height - Randomized screen height.
   * @property {number} screen.colorDepth - Fixed color depth (24).
   * @property {string} platform - Fixed platform string ('Linux x86_64').
   * @property {string} timezone - Fixed timezone ('UTC').
   */
  getRandomFingerprint() {
    const fingerprint = {
      deviceMemory: Math.random() < 0.5 ? 4 : 8,
      hardwareConcurrency: [2, 4, 8][Math.floor(Math.random() * 3)],
      screen: {
        width: 360 + Math.floor(Math.random() * 400),
        height: 640 + Math.floor(Math.random() * 500),
        colorDepth: 24
      },
      platform: 'Linux x86_64',
      timezone: 'UTC'
    };

    if (this.debugMode) {
      console.log(`[debug][fingerprint] Generated random fingerprint:`, {
        deviceMemory: fingerprint.deviceMemory,
        hardwareConcurrency: fingerprint.hardwareConcurrency,
        screen: `${fingerprint.screen.width}x${fingerprint.screen.height}`,
        platform: fingerprint.platform,
        timezone: fingerprint.timezone
      });
    }

    return fingerprint;
  }

  /**
   * Generates a fixed fingerprint with default values
   * @returns {object} Fixed fingerprint object
   */
  getFixedFingerprint() {
    const fingerprint = {
      deviceMemory: 8,
      hardwareConcurrency: 4,
      screen: {
        width: 1920,
        height: 1080,
        colorDepth: 24
      },
      platform: this.DEFAULT_PLATFORM,
      timezone: this.DEFAULT_TIMEZONE
    };

    if (this.debugMode) {
      console.log(`[debug][fingerprint] Using fixed fingerprint:`, {
        deviceMemory: fingerprint.deviceMemory,
        hardwareConcurrency: fingerprint.hardwareConcurrency,
        screen: `${fingerprint.screen.width}x${fingerprint.screen.height}`,
        platform: fingerprint.platform,
        timezone: fingerprint.timezone
      });
    }

    return fingerprint;
  }

  /**
   * Get appropriate fingerprint based on setting
   * @param {string|boolean} fingerprintSetting - The fingerprint setting ('random', true, false)
   * @returns {object|null} Fingerprint object or null if disabled
   */
  getFingerprint(fingerprintSetting) {
    if (!fingerprintSetting) {
      return null;
    }

    if (fingerprintSetting === 'random') {
      return this.getRandomFingerprint();
    }

    // For any truthy value that's not 'random', use fixed fingerprint
    return this.getFixedFingerprint();
  }

  /**
   * Apply fingerprint spoofing to a Puppeteer page using evaluateOnNewDocument
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {string|boolean} fingerprintSetting - The fingerprint setting
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async applyFingerprint(page, fingerprintSetting, currentUrl = 'unknown') {
    if (!fingerprintSetting) {
      return true; // No fingerprinting needed
    }

    try {
      const spoof = this.getFingerprint(fingerprintSetting);
      
      if (!spoof) {
        return true; // No spoofing needed
      }

      if (this.debugMode) {
        console.log(`[debug][fingerprint] Applying fingerprint protection to ${currentUrl}`);
      }

      await page.evaluateOnNewDocument(({ spoof }) => {
        // Override device memory
        Object.defineProperty(navigator, 'deviceMemory', { 
          get: () => spoof.deviceMemory,
          configurable: true
        });

        // Override hardware concurrency (CPU cores)
        Object.defineProperty(navigator, 'hardwareConcurrency', { 
          get: () => spoof.hardwareConcurrency,
          configurable: true
        });

        // Override screen dimensions
        Object.defineProperty(window.screen, 'width', { 
          get: () => spoof.screen.width,
          configurable: true
        });
        Object.defineProperty(window.screen, 'height', { 
          get: () => spoof.screen.height,
          configurable: true
        });
        Object.defineProperty(window.screen, 'colorDepth', { 
          get: () => spoof.screen.colorDepth,
          configurable: true
        });

        // Override platform
        Object.defineProperty(navigator, 'platform', { 
          get: () => spoof.platform,
          configurable: true
        });

        // Override timezone through Intl.DateTimeFormat
        const OriginalDateTimeFormat = Intl.DateTimeFormat;
        Intl.DateTimeFormat = class extends OriginalDateTimeFormat {
          resolvedOptions() { 
            const options = super.resolvedOptions();
            options.timeZone = spoof.timezone;
            return options;
          }
        };

        // Also override getTimezoneOffset for Date objects
        const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
        Date.prototype.getTimezoneOffset = function() {
          // Return offset for the spoofed timezone (UTC = 0)
          if (spoof.timezone === 'UTC') {
            return 0;
          }
          // For other timezones, you might want to implement proper offset calculation
          return originalGetTimezoneOffset.call(this);
        };

      }, { spoof });

      return true;

    } catch (error) {
      console.warn(`[warn][fingerprint] Failed to apply fingerprint spoofing for ${currentUrl}: ${error.message}`);
      return false;
    }
  }

  /**
   * Apply Brave browser spoofing to a Puppeteer page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async applyBraveSpoofing(page, currentUrl = 'unknown') {
    try {
      if (this.debugMode) {
        console.log(`[debug][fingerprint] Applying Brave spoofing to ${currentUrl}`);
      }

      await page.evaluateOnNewDocument(() => {
        // Add Brave-specific navigator property
        Object.defineProperty(navigator, 'brave', {
          get: () => ({ 
            isBrave: () => Promise.resolve(true),
            // Add other Brave-specific methods if needed
            isDefault: () => Promise.resolve(false)
          }),
          configurable: true
        });

        // Brave also has specific user agent patterns, but that's handled separately
      });

      return true;

    } catch (error) {
      console.warn(`[warn][fingerprint] Failed to apply Brave spoofing for ${currentUrl}: ${error.message}`);
      return false;
    }
  }

  /**
   * Get predefined user agent strings
   * @returns {object} Object containing user agent strings for different browsers
   */
  getUserAgents() {
    return {
      chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
      firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
      safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
      brave: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36" // Brave uses Chrome UA
    };
  }

  /**
   * Apply user agent spoofing to a Puppeteer page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {string} userAgentType - The user agent type ('chrome', 'firefox', 'safari', 'brave')
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async applyUserAgent(page, userAgentType, currentUrl = 'unknown') {
    if (!userAgentType) {
      return true;
    }

    try {
      const userAgents = this.getUserAgents();
      const ua = userAgents[userAgentType.toLowerCase()];

      if (!ua) {
        console.warn(`[warn][fingerprint] Unknown user agent type: ${userAgentType}`);
        return false;
      }

      if (this.debugMode) {
        console.log(`[debug][fingerprint] Applying ${userAgentType} user agent to ${currentUrl}`);
      }

      await page.setUserAgent(ua);
      return true;

    } catch (error) {
      console.warn(`[warn][fingerprint] Failed to apply user agent for ${currentUrl}: ${error.message}`);
      return false;
    }
  }

  /**
   * Get statistics about fingerprint spoofing usage
   * @returns {object} Statistics object
   */
  getStats() {
    return {
      defaultPlatform: this.DEFAULT_PLATFORM,
      defaultTimezone: this.DEFAULT_TIMEZONE,
      availableUserAgents: Object.keys(this.getUserAgents())
    };
  }
}

// Export the class and create a default instance
const fingerprintManager = new FingerprintManager();

module.exports = {
  FingerprintManager,
  fingerprintManager
};
