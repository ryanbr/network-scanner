// === Enhanced Fingerprint Protection Module ===
// This module handles advanced browser fingerprint spoofing, user agent changes,
// and comprehensive bot detection evasion techniques.

// Default values for fingerprint spoofing if not set to 'random'
const DEFAULT_PLATFORM = 'Win32';
const DEFAULT_TIMEZONE = 'America/New_York';

/**
 * Generates realistic screen resolutions based on common monitor sizes
 * @returns {object} Screen resolution object with width and height
 */
function getRealisticScreenResolution() {
  const commonResolutions = [
    { width: 1920, height: 1080 }, // Full HD - most common
    { width: 1366, height: 768 },  // Common laptop
    { width: 1440, height: 900 },  // MacBook Air
    { width: 1536, height: 864 },  // Scaled HD
    { width: 1600, height: 900 },  // 16:9 widescreen
    { width: 2560, height: 1440 }, // 1440p
    { width: 1280, height: 720 },  // 720p
    { width: 3440, height: 1440 }  // Ultrawide
  ];
  
  return commonResolutions[Math.floor(Math.random() * commonResolutions.length)];
}

/**
 * Generates an object with randomized but realistic browser fingerprint values.
 * This is used to spoof various navigator and screen properties to make
 * the headless browser instance appear more like a regular user's browser
 * and bypass fingerprint-based bot detection.
 *
 * @returns {object} An object containing the spoofed fingerprint properties
 */
function getRandomFingerprint() {
  const resolution = getRealisticScreenResolution();
  
  return {
    deviceMemory: [4, 8, 16, 32][Math.floor(Math.random() * 4)],
    hardwareConcurrency: [2, 4, 6, 8, 12, 16][Math.floor(Math.random() * 6)],
    screen: {
      width: resolution.width,
      height: resolution.height,
      availWidth: resolution.width,
      availHeight: resolution.height - 40, // Account for taskbar
      colorDepth: 24,
      pixelDepth: 24
    },
    platform: Math.random() > 0.3 ? 'Win32' : 'MacIntel',
    timezone: ['America/New_York', 'America/Los_Angeles', 'Europe/London', 'America/Chicago'][Math.floor(Math.random() * 4)],
    language: ['en-US', 'en-GB', 'en-CA'][Math.floor(Math.random() * 3)],
    cookieEnabled: true,
    doNotTrack: Math.random() > 0.7 ? '1' : null
  };
}

/**
 * Enhanced user agent spoofing with latest browser versions and comprehensive stealth protection
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.userAgent) return;

  if (forceDebug) console.log(`[debug] Enhanced userAgent spoofing enabled for ${currentUrl}: ${siteConfig.userAgent}`);
  
  // Updated user agents with latest browser versions
  const userAgents = {
    chrome: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ],
    firefox: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
      "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
    ],
    safari: [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
    ]
  };
  
  const selectedUserAgents = userAgents[siteConfig.userAgent.toLowerCase()];
  const ua = selectedUserAgents ? selectedUserAgents[Math.floor(Math.random() * selectedUserAgents.length)] : null;
  
  if (ua) {
    await page.setUserAgent(ua);
    
    // Apply comprehensive stealth protection when userAgent is set
    if (forceDebug) console.log(`[debug] Applying enhanced stealth protection for ${currentUrl}`);
    
    try {
      await page.evaluateOnNewDocument((userAgent) => {
        // 1. Enhanced webdriver removal with descriptor manipulation
        delete navigator.webdriver;
        Object.defineProperty(navigator, 'webdriver', {
          get: () => undefined,
          configurable: false,
          enumerable: false
        });
        
        // 2. Enhanced automation detection removal
        const automationProps = [
          'callPhantom', '_phantom', '__nightmare', '_selenium',
          '__selenium_unwrapped', '__webdriver_evaluate', '__driver_evaluate',
          '__webdriver_script_function', '__webdriver_script_func',
          '__webdriver_script_fn', '__fxdriver_evaluate', '__driver_unwrapped',
          '__webdriver_unwrapped', '__selenium_evaluate', '__fxdriver_unwrapped',
          'spawn', 'emit', 'Buffer', '__webdriver_script_func', 'domAutomation',
          'domAutomationController', '__lastWatirAlert', '__lastWatirConfirm',
          '__lastWatirPrompt', '_Selenium_IDE_Recorder', '_selenium', 'calledSelenium',
          '__webdriver_script_function', '__webdriver_script_func'
        ];
        
        automationProps.forEach(prop => {
          delete window[prop];
          delete navigator[prop];
          Object.defineProperty(window, prop, {
            get: () => undefined,
            configurable: false,
            enumerable: false
          });
        });
        
        // 3. Enhanced Chrome runtime simulation
        if (!window.chrome || !window.chrome.runtime) {
          window.chrome = {
            runtime: {
              onConnect: { addListener: () => {}, removeListener: () => {} },
              onMessage: { addListener: () => {}, removeListener: () => {} },
              sendMessage: () => {},
              connect: () => ({
                onMessage: { addListener: () => {}, removeListener: () => {} },
                postMessage: () => {},
                disconnect: () => {}
              }),
              getManifest: () => ({
                name: "Chrome",
                version: "131.0.0.0"
              }),
              getURL: (path) => `chrome-extension://invalid/${path}`,
              id: undefined
            },
            loadTimes: () => ({
              commitLoadTime: performance.now() - Math.random() * 1000,
              connectionInfo: 'http/1.1',
              finishDocumentLoadTime: performance.now() - Math.random() * 500,
              finishLoadTime: performance.now() - Math.random() * 100,
              firstPaintAfterLoadTime: performance.now() - Math.random() * 50,
              firstPaintTime: performance.now() - Math.random() * 200,
              navigationType: 'Navigation',
              npnNegotiatedProtocol: 'unknown',
              requestTime: performance.now() - Math.random() * 2000,
              startLoadTime: performance.now() - Math.random() * 1500,
              wasAlternateProtocolAvailable: false,
              wasFetchedViaSpdy: false,
              wasNpnNegotiated: false
            }),
            csi: () => ({
              onloadT: Date.now(),
              pageT: Math.random() * 1000,
              startE: Date.now() - Math.random() * 2000,
              tran: Math.floor(Math.random() * 20)
            }),
            app: {
              isInstalled: false,
              InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
              RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }
            }
          };
        }
        
        // 4. Realistic plugins based on user agent
        const isChrome = userAgent.includes('Chrome');
        const isFirefox = userAgent.includes('Firefox');
        const isSafari = userAgent.includes('Safari') && !userAgent.includes('Chrome');
        
        let plugins = [];
        if (isChrome) {
          plugins = [
            { name: 'Chrome PDF Plugin', length: 1, description: 'Portable Document Format', filename: 'internal-pdf-viewer' },
            { name: 'Chrome PDF Viewer', length: 1, description: 'PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
            { name: 'Native Client', length: 2, description: 'Native Client Executable', filename: 'internal-nacl-plugin' }
          ];
        } else if (isFirefox) {
          plugins = [
            { name: 'PDF.js', length: 2, description: 'Portable Document Format', filename: 'internal-pdf-js' }
          ];
        } else if (isSafari) {
          plugins = [
            { name: 'WebKit built-in PDF', length: 1, description: 'Portable Document Format', filename: 'internal-pdf-viewer' }
          ];
        }
        
        Object.defineProperty(navigator, 'plugins', {
          get: () => plugins,
          configurable: true
        });
        
        // 5. Enhanced language spoofing
        const languages = ['en-US', 'en'];
        Object.defineProperty(navigator, 'languages', {
          get: () => languages,
          configurable: true
        });
        Object.defineProperty(navigator, 'language', {
          get: () => languages[0],
          configurable: true
        });
        
        // 6. Vendor and product info based on user agent
        let vendor = 'Google Inc.';
        let product = 'Gecko';
        
        if (isFirefox) {
          vendor = '';
          product = 'Gecko';
        } else if (isSafari) {
          vendor = 'Apple Computer, Inc.';
          product = 'Gecko';
        }
        
        Object.defineProperty(navigator, 'vendor', {
          get: () => vendor,
          configurable: true
        });
        Object.defineProperty(navigator, 'product', {
          get: () => product,
          configurable: true
        });
        
        // 7. Add realistic mimeTypes
        Object.defineProperty(navigator, 'mimeTypes', {
          get: () => {
            if (isChrome) {
              return [
                { type: 'application/pdf', description: 'Portable Document Format', suffixes: 'pdf', enabledPlugin: plugins[0] },
                { type: 'application/x-google-chrome-pdf', description: 'Portable Document Format', suffixes: 'pdf', enabledPlugin: plugins[1] },
                { type: 'application/x-nacl', description: 'Native Client Executable', suffixes: '', enabledPlugin: plugins[2] }
              ];
            }
            return [];
          },
          configurable: true
        });
        
        // 8. Enhanced permission API spoofing
        if (navigator.permissions && navigator.permissions.query) {
          const originalQuery = navigator.permissions.query;
          navigator.permissions.query = function(parameters) {
            const granted = ['camera', 'microphone', 'notifications'];
            const denied = ['midi', 'push', 'speaker'];
            const prompt = ['geolocation'];
            
            if (granted.includes(parameters.name)) {
              return Promise.resolve({ state: 'granted', onchange: null });
            } else if (denied.includes(parameters.name)) {
              return Promise.resolve({ state: 'denied', onchange: null });
            } else if (prompt.includes(parameters.name)) {
              return Promise.resolve({ state: 'prompt', onchange: null });
            }
            return originalQuery.apply(this, arguments);
          };
        }
        
        // 9. Spoof iframe contentWindow access (common detection method)
        const originalContentWindow = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
        if (originalContentWindow) {
          Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
            get: function() {
              const win = originalContentWindow.get.call(this);
              if (win) {
                // Remove automation properties from iframe windows too
                automationProps.forEach(prop => {
                  try { 
                    delete win[prop];
                    Object.defineProperty(win, prop, {
                      get: () => undefined,
                      configurable: false,
                      enumerable: false
                    });
                  } catch(e) {}
                });
              }
              return win;
            },
            configurable: true
          });
        }
        
        // 10. Enhanced connection information spoofing
        if (navigator.connection) {
          Object.defineProperties(navigator.connection, {
            rtt: { get: () => Math.floor(Math.random() * 100) + 50, configurable: true },
            downlink: { get: () => Math.random() * 10 + 1, configurable: true },
            effectiveType: { get: () => '4g', configurable: true },
            saveData: { get: () => false, configurable: true }
          });
        }
        
        // 11. Spoof WebGL fingerprinting
        const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
          if (parameter === 37445) { // UNMASKED_VENDOR_WEBGL
            return 'Intel Inc.';
          }
          if (parameter === 37446) { // UNMASKED_RENDERER_WEBGL
            return 'Intel Iris OpenGL Engine';
          }
          return getParameter.call(this, parameter);
        };
        
        // 12. Spoof canvas fingerprinting with subtle noise
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(...args) {
          const context = this.getContext('2d');
          if (context) {
            // Add subtle noise to canvas to prevent fingerprinting
            const imageData = context.getImageData(0, 0, this.width, this.height);
            for (let i = 0; i < imageData.data.length; i += 4) {
              imageData.data[i] = imageData.data[i] + Math.floor(Math.random() * 3) - 1;
            }
            context.putImageData(imageData, 0, 0);
          }
          return originalToDataURL.apply(this, args);
        };
        
        // 13. Enhanced Error.captureStackTrace to prevent detection
        if (Error.captureStackTrace) {
          const originalCaptureStackTrace = Error.captureStackTrace;
          Error.captureStackTrace = function(targetObject, constructorOpt) {
            const result = originalCaptureStackTrace.call(this, targetObject, constructorOpt);
            if (targetObject.stack) {
              // Remove puppeteer-related stack traces
              targetObject.stack = targetObject.stack
                .split('\n')
                .filter(line => !line.includes('puppeteer') && !line.includes('DevTools') && !line.includes('chrome-devtools'))
                .join('\n');
            }
            return result;
          };
        }
        
        // 14. Patch toString methods to prevent detection
        Function.prototype.toString = new Proxy(Function.prototype.toString, {
          apply: function(target, thisArg, argumentsList) {
            const result = target.apply(thisArg, argumentsList);
            return result.replace(/puppeteer/gi, 'browser').replace(/headless/gi, 'chrome');
          }
        });
        
        // 15. Spoof battery API if available
        if (navigator.getBattery) {
          const originalGetBattery = navigator.getBattery;
          navigator.getBattery = function() {
            return Promise.resolve({
              charging: Math.random() > 0.5,
              chargingTime: Math.random() > 0.5 ? Infinity : Math.random() * 3600,
              dischargingTime: Math.random() * 7200,
              level: Math.random() * 0.99 + 0.01,
              addEventListener: () => {},
              removeEventListener: () => {},
              dispatchEvent: () => true
            });
          };
        }
        
        // 16. Add realistic timing to console methods
        ['debug', 'error', 'info', 'log', 'warn'].forEach(method => {
          const original = console[method];
          console[method] = function(...args) {
            // Add tiny random delay to mimic human-like console timing
            setTimeout(() => original.apply(console, args), Math.random() * 5);
          };
        });
        
      }, ua);
    } catch (stealthErr) {
      console.warn(`[enhanced stealth protection failed] ${currentUrl}: ${stealthErr.message}`);
    }
  }
}

/**
 * Enhanced Brave browser spoofing with more realistic implementation
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyBraveSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.isBrave) return;

  if (forceDebug) console.log(`[debug] Enhanced Brave spoofing enabled for ${currentUrl}`);
  
  await page.evaluateOnNewDocument(() => {
    // More comprehensive Brave spoofing
    Object.defineProperty(navigator, 'brave', {
      get: () => ({
        isBrave: () => Promise.resolve(true),
        setBadge: () => {},
        clearBadge: () => {},
        getAdBlockEnabled: () => Promise.resolve(true),
        getShieldsEnabled: () => Promise.resolve(true)
      }),
      configurable: true
    });
    
    // Brave-specific user agent adjustments
    if (navigator.userAgent && !navigator.userAgent.includes('Brave')) {
      Object.defineProperty(navigator, 'userAgent', {
        get: () => navigator.userAgent.replace('Chrome/', 'Brave/').replace('Safari/537.36', 'Safari/537.36 Brave/1.60'),
        configurable: true
      });
    }
  });
}

/**
 * Enhanced fingerprint protection with more realistic and varied spoofing
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl) {
  const fingerprintSetting = siteConfig.fingerprint_protection;
  if (!fingerprintSetting) return;

  if (forceDebug) console.log(`[debug] Enhanced fingerprint_protection enabled for ${currentUrl}`);
  
  const spoof = fingerprintSetting === 'random' ? getRandomFingerprint() : {
    deviceMemory: 8, 
    hardwareConcurrency: 4,
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    platform: DEFAULT_PLATFORM, 
    timezone: DEFAULT_TIMEZONE,
    language: 'en-US',
    cookieEnabled: true,
    doNotTrack: null
  };

  try {
    await page.evaluateOnNewDocument(({ spoof }) => {
      // Enhanced property spoofing with more realistic values
      Object.defineProperty(navigator, 'deviceMemory', { 
        get: () => spoof.deviceMemory,
        configurable: true,
        enumerable: true
      });
      
      Object.defineProperty(navigator, 'hardwareConcurrency', { 
        get: () => spoof.hardwareConcurrency,
        configurable: true,
        enumerable: true
      });
      
      // Enhanced screen properties
      ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'].forEach(prop => {
        if (spoof.screen[prop] !== undefined) {
          Object.defineProperty(window.screen, prop, { 
            get: () => spoof.screen[prop],
            configurable: true,
            enumerable: true
          });
        }
      });
      
      Object.defineProperty(navigator, 'platform', { 
        get: () => spoof.platform,
        configurable: true,
        enumerable: true
      });
      
      // Enhanced timezone spoofing
      const originalDateTimeFormat = Intl.DateTimeFormat;
      Intl.DateTimeFormat = function(...args) {
        const instance = new originalDateTimeFormat(...args);
        const originalResolvedOptions = instance.resolvedOptions;
        instance.resolvedOptions = function() {
          const options = originalResolvedOptions.call(this);
          options.timeZone = spoof.timezone;
          return options;
        };
        return instance;
      };
      
      // Spoof Date.getTimezoneOffset
      const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
      Date.prototype.getTimezoneOffset = function() {
        // Return offset for spoofed timezone
        const timezoneOffsets = {
          'America/New_York': 300,    // EST offset
          'America/Los_Angeles': 480, // PST offset
          'Europe/London': 0,         // GMT offset
          'America/Chicago': 360      // CST offset
        };
        return timezoneOffsets[spoof.timezone] || originalGetTimezoneOffset.call(this);
      };
      
      // Enhanced cookie and DNT spoofing
      if (spoof.cookieEnabled !== undefined) {
        Object.defineProperty(navigator, 'cookieEnabled', {
          get: () => spoof.cookieEnabled,
          configurable: true
        });
      }
      
      if (spoof.doNotTrack !== undefined) {
        Object.defineProperty(navigator, 'doNotTrack', {
          get: () => spoof.doNotTrack,
          configurable: true
        });
      }
      
    }, { spoof });
  } catch (err) {
    console.warn(`[enhanced fingerprint spoof failed] ${currentUrl}: ${err.message}`);
  }
}

/**
 * Add mouse movement simulation to appear more human-like
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @returns {Promise<void>}
 */
async function simulateHumanBehavior(page, forceDebug) {
  try {
    await page.evaluateOnNewDocument(() => {
      // Simulate human-like mouse movements
      let mouseX = Math.random() * window.innerWidth;
      let mouseY = Math.random() * window.innerHeight;
      
      const moveInterval = setInterval(() => {
        mouseX += (Math.random() - 0.5) * 20;
        mouseY += (Math.random() - 0.5) * 20;
        
        mouseX = Math.max(0, Math.min(window.innerWidth, mouseX));
        mouseY = Math.max(0, Math.min(window.innerHeight, mouseY));
        
        document.dispatchEvent(new MouseEvent('mousemove', {
          clientX: mouseX,
          clientY: mouseY,
          bubbles: true
        }));
      }, 1000 + Math.random() * 2000);
      
      // Simulate occasional clicks and scrolls
      setTimeout(() => {
        if (Math.random() > 0.7) {
          document.dispatchEvent(new MouseEvent('click', {
            clientX: mouseX,
            clientY: mouseY,
            bubbles: true
          }));
        }
        
        // Simulate scroll events
        if (Math.random() > 0.8) {
          window.scrollBy(0, Math.random() * 100 - 50);
        }
      }, 5000 + Math.random() * 10000);
      
      // Stop simulation after 30 seconds to avoid detection
      setTimeout(() => {
        clearInterval(moveInterval);
      }, 30000);
    });
  } catch (err) {
    if (forceDebug) console.log(`[debug] Human behavior simulation failed: ${err.message}`);
  }
}

/**
 * Enhanced main function that applies all fingerprint spoofing techniques
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyAllFingerprintSpoofing(page, siteConfig, forceDebug, currentUrl) {
  await applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl);
  await applyBraveSpoofing(page, siteConfig, forceDebug, currentUrl);
  await applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl);
  
  // Add human behavior simulation if user agent spoofing is enabled
  if (siteConfig.userAgent) {
    await simulateHumanBehavior(page, forceDebug);
  }
}

module.exports = {
  getRandomFingerprint,
  getRealisticScreenResolution,
  applyUserAgentSpoofing,
  applyBraveSpoofing,
  applyFingerprintProtection,
  applyAllFingerprintSpoofing,
  simulateHumanBehavior,
  DEFAULT_PLATFORM,
  DEFAULT_TIMEZONE
};