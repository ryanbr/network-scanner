// === Fingerprint Protection Module ===
// This module handles browser fingerprint spoofing, user agent changes,
// and Brave browser detection spoofing to help bypass bot detection.

// Default values for fingerprint spoofing if not set to 'random'
const DEFAULT_PLATFORM = 'Win32';
const DEFAULT_TIMEZONE = 'America/New_York';

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
function getRandomFingerprint() {
  return {
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
}

/**
 * Applies user agent spoofing to the page based on the configuration.
 * Supports Chrome, Firefox, and Safari user agents.
 *
 * @param {import('puppeteer').Page} page - The Puppeteer page instance.
 * @param {object} siteConfig - The site configuration object.
 * @param {boolean} forceDebug - Whether debug logging is enabled.
 * @param {string} currentUrl - The current URL being processed (for logging).
 * @returns {Promise<void>}
 */
async function applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.userAgent) return;

  if (forceDebug) console.log(`[debug] userAgent spoofing enabled for ${currentUrl}: ${siteConfig.userAgent}`);
  
  const userAgents = {
    chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
    safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15"
  };
  
  const ua = userAgents[siteConfig.userAgent.toLowerCase()];
  if (ua) {
    await page.setUserAgent(ua);
  }
}

/**
 * Applies Brave browser spoofing by injecting navigator.brave property.
 * This makes the page appear as if it's running in the Brave browser.
 *
 * @param {import('puppeteer').Page} page - The Puppeteer page instance.
 * @param {object} siteConfig - The site configuration object.
 * @param {boolean} forceDebug - Whether debug logging is enabled.
 * @param {string} currentUrl - The current URL being processed (for logging).
 * @returns {Promise<void>}
 */
async function applyBraveSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.isBrave) return;

  if (forceDebug) console.log(`[debug] Brave spoofing enabled for ${currentUrl}`);
  
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, 'brave', {
      get: () => ({ isBrave: () => Promise.resolve(true) })
    });
  });
}

/**
 * Applies fingerprint protection by spoofing various browser properties.
 * Can use either fixed values or randomized values based on configuration.
 *
 * @param {import('puppeteer').Page} page - The Puppeteer page instance.
 * @param {object} siteConfig - The site configuration object.
 * @param {boolean} forceDebug - Whether debug logging is enabled.
 * @param {string} currentUrl - The current URL being processed (for logging).
 * @returns {Promise<void>}
 */
async function applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl) {
  const fingerprintSetting = siteConfig.fingerprint_protection;
  if (!fingerprintSetting) return;

  if (forceDebug) console.log(`[debug] fingerprint_protection enabled for ${currentUrl}`);
  
  const spoof = fingerprintSetting === 'random' ? getRandomFingerprint() : {
    deviceMemory: 8, 
    hardwareConcurrency: 4,
    screen: { width: 1920, height: 1080, colorDepth: 24 },
    platform: DEFAULT_PLATFORM, 
    timezone: DEFAULT_TIMEZONE
  };

  try {
    await page.evaluateOnNewDocument(({ spoof }) => {
      Object.defineProperty(navigator, 'deviceMemory', { get: () => spoof.deviceMemory });
      Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => spoof.hardwareConcurrency });
      Object.defineProperty(window.screen, 'width', { get: () => spoof.screen.width });
      Object.defineProperty(window.screen, 'height', { get: () => spoof.screen.height });
      Object.defineProperty(window.screen, 'colorDepth', { get: () => spoof.screen.colorDepth });
      Object.defineProperty(navigator, 'platform', { get: () => spoof.platform });
      Intl.DateTimeFormat = class extends Intl.DateTimeFormat {
        resolvedOptions() { return { timeZone: spoof.timezone }; }
      };
    }, { spoof });
  } catch (err) {
    console.warn(`[fingerprint spoof failed] ${currentUrl}: ${err.message}`);
  }
}

/**
 * Applies all fingerprint-related spoofing techniques to a page.
 * This is the main function that should be called to set up all spoofing.
 *
 * @param {import('puppeteer').Page} page - The Puppeteer page instance.
 * @param {object} siteConfig - The site configuration object.
 * @param {boolean} forceDebug - Whether debug logging is enabled.
 * @param {string} currentUrl - The current URL being processed (for logging).
 * @returns {Promise<void>}
 */
async function applyAllFingerprintSpoofing(page, siteConfig, forceDebug, currentUrl) {
  await applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl);
  await applyBraveSpoofing(page, siteConfig, forceDebug, currentUrl);
  await applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl);
}

module.exports = {
  getRandomFingerprint,
  applyUserAgentSpoofing,
  applyBraveSpoofing,
  applyFingerprintProtection,
  applyAllFingerprintSpoofing,
  DEFAULT_PLATFORM,
  DEFAULT_TIMEZONE
};
