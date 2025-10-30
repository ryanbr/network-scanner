// === Enhanced Fingerprint Protection Module - Puppeteer 23.x Compatible ===
// This module handles advanced browser fingerprint spoofing, user agent changes,
// and comprehensive bot detection evasion techniques.
//const { applyErrorSuppression } = require('./error-suppression');

// Default values for fingerprint spoofing if not set to 'random'
const DEFAULT_PLATFORM = 'Win32';
const DEFAULT_TIMEZONE = 'America/New_York';

// Cached property descriptors for V8 optimization
const CACHED_DESCRIPTORS = {
  readOnlyValue: (value) => ({ value, writable: false, enumerable: true, configurable: true }),
  getter: (fn) => ({ get: fn, enumerable: true, configurable: true }),
  hiddenValue: (value) => ({ value, writable: false, enumerable: false, configurable: true })
};

// Type-specific property spoofing functions for monomorphic optimization
function spoofNavigatorProperties(navigator, properties, options = {}) {
  if (!navigator || typeof navigator !== 'object') return false;
  
  for (const [prop, descriptor] of Object.entries(properties)) {
    if (!safeDefineProperty(navigator, prop, descriptor, options)) {
      if (options.debug) console.log(`[fingerprint] Failed to spoof navigator.${prop}`);
    }
  }
  return true;
}

function spoofScreenProperties(screen, properties, options = {}) {
  if (!screen || typeof screen !== 'object') return false;
  
  for (const [prop, descriptor] of Object.entries(properties)) {
    if (!safeDefineProperty(screen, prop, descriptor, options)) {
      if (options.debug) console.log(`[fingerprint] Failed to spoof screen.${prop}`);
    }
  }
  return true;
}

function spoofWindowProperties(window, properties, options = {}) {
  if (!window || typeof window !== 'object') return false;
  
  for (const [prop, descriptor] of Object.entries(properties)) {
    if (!safeDefineProperty(window, prop, descriptor, options)) {
      if (options.debug) console.log(`[fingerprint] Failed to spoof window.${prop}`);
    }
  }
  return true;
}

// Pre-compiled mock objects for V8 optimization
const PRECOMPILED_MOCKS = Object.freeze({
  chromeRuntime: Object.freeze({
    onConnect: Object.freeze({ addListener: () => {}, removeListener: () => {} }),
    onMessage: Object.freeze({ addListener: () => {}, removeListener: () => {} }),
    sendMessage: () => {},
    connect: () => Object.freeze({
      onMessage: Object.freeze({ addListener: () => {}, removeListener: () => {} }),
      postMessage: () => {},
      disconnect: () => {}
    }),
    getManifest: () => Object.freeze({ name: "Chrome", version: "142.0.0.0" }),
    getURL: (path) => `chrome-extension://invalid/${path}`,
    id: undefined
  }),
  
  fingerprintResult: Object.freeze({
    visitorId: 'mock_visitor_' + Math.random().toString(36).substr(2, 9),
    confidence: Object.freeze({ score: 0.99 }),
    components: Object.freeze({
      screen: Object.freeze({ value: Object.freeze({ width: 1920, height: 1080 }) }),
      timezone: Object.freeze({ value: 'America/New_York' }),
      language: Object.freeze({ value: 'en-US' })
    })
  }),
  
  loadTimes: Object.freeze({
    commitLoadTime: performance.now() - Math.random() * 1000,
    connectionInfo: 'http/1.1',
    finishDocumentLoadTime: performance.now() - Math.random() * 500,
    navigationType: 'Navigation'
  })
});

// Built-in properties that should not be modified
const BUILT_IN_PROPERTIES = new Set([
  'href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash',
  'constructor', 'prototype', '__proto__', 'toString', 'valueOf', 'assign', 'reload', 'replace'
]);

// User agent collections with latest versions
const USER_AGENT_COLLECTIONS = Object.freeze(new Map([
  ['chrome', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"],
  ['chrome_mac', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"],
  ['chrome_linux', "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"],
  ['firefox', "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"],
  ['firefox_mac', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0"],
  ['firefox_linux', "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0"],
  ['safari', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15"]
]));

// Timezone configuration with offsets
const TIMEZONE_CONFIG = {
  'America/New_York': { offset: 300, abbr: 'EST' },
  'America/Los_Angeles': { offset: 480, abbr: 'PST' },
  'Europe/London': { offset: 0, abbr: 'GMT' },
  'America/Chicago': { offset: 360, abbr: 'CST' }
};

/**
 * Safely defines a property with comprehensive error handling
 */
function safeDefineProperty(target, property, descriptor, options = {}) {
  if (BUILT_IN_PROPERTIES.has(property)) {
    if (options.debug) console.log(`[fingerprint] Skipping built-in property: ${property}`);
    return false;
  }

  try {
    const existing = Object.getOwnPropertyDescriptor(target, property);
    if (existing?.configurable === false) {
      if (options.debug) console.log(`[fingerprint] Cannot modify non-configurable: ${property}`);
      return false;
    }

    Object.defineProperty(target, property, descriptor);
    return true;
  } catch (err) {
    if (options.debug) console.log(`[fingerprint] Failed to define ${property}: ${err.message}`);
    return false;
  }
}

/**
 * Safely executes spoofing operations with error handling
 */
function safeSpoofingExecution(spoofFunction, description, options = {}) {
  try {
    spoofFunction();
    return true;
  } catch (err) {
    if (options.debug) console.log(`[fingerprint] ${description} failed: ${err.message}`);
    return false;
  }
}

/**
 * Generates realistic screen resolutions based on common monitor sizes
 */
function getRealisticScreenResolution() {
  const commonResolutions = [
    { width: 1920, height: 1080 },
    { width: 1366, height: 768 },
    { width: 1440, height: 900 },
    { width: 1536, height: 864 },
    { width: 1600, height: 900 },
    { width: 2560, height: 1440 },
    { width: 1280, height: 720 },
    { width: 3440, height: 1440 }
  ];
  return commonResolutions[Math.floor(Math.random() * commonResolutions.length)];
}

/**
 * Generates randomized but realistic browser fingerprint values
 */
function generateRealisticFingerprint(userAgent) {
  // Determine OS from user agent
  let osType = 'windows';
  if (userAgent.includes('Macintosh') || userAgent.includes('Mac OS X')) {
    osType = 'mac';
  } else if (userAgent.includes('X11; Linux') || userAgent.includes('Ubuntu')) {
    osType = 'linux';
  }
  
  // Generate OS-appropriate hardware specs
  const profiles = {
    windows: {
      deviceMemory: [8, 16], // Common Windows configurations
      hardwareConcurrency: [4, 6, 8], // Typical consumer CPUs
      platform: 'Win32',
      timezone: 'America/New_York',
      language: 'en-US',
      resolutions: [
        { width: 1920, height: 1080 },
        { width: 2560, height: 1440 },
        { width: 1366, height: 768 }
      ]
    },
    mac: {
      deviceMemory: [8, 16], // MacBook/iMac typical configs
      hardwareConcurrency: [8, 10], // Apple Silicon M1/M2 cores
      platform: 'MacIntel',
      timezone: 'America/Los_Angeles',
      language: 'en-US',
      resolutions: [
        { width: 2560, height: 1600 }, // MacBook Pro
        { width: 3840, height: 2160 }, // iMac 4K
        { width: 1440, height: 900 }   // MacBook Air
      ]
    },
    linux: {
      deviceMemory: [8, 16],
      hardwareConcurrency: [4, 8, 12], // Wide variety on Linux
      platform: 'Linux x86_64',
      timezone: 'America/New_York',
      language: 'en-US',
      resolutions: [
        { width: 1920, height: 1080 },
        { width: 2560, height: 1440 },
        { width: 1600, height: 900 }
      ]
    }
  };
  
  const profile = profiles[osType];
  const resolution = profile.resolutions[Math.floor(Math.random() * profile.resolutions.length)];
  
  return {
    deviceMemory: profile.deviceMemory[Math.floor(Math.random() * profile.deviceMemory.length)],
    hardwareConcurrency: profile.hardwareConcurrency[Math.floor(Math.random() * profile.hardwareConcurrency.length)],
    screen: {
      width: resolution.width,
      height: resolution.height,
      availWidth: resolution.width,
      availHeight: resolution.height - 40,
      colorDepth: 24,
      pixelDepth: 24
    },
    platform: profile.platform,
    timezone: profile.timezone,
    language: profile.language,
    cookieEnabled: true,
    doNotTrack: null // Most users don't enable DNT
  };
}

/**
 * Creates mock Chrome runtime objects
 */
function createMockChromeRuntime() {
  return PRECOMPILED_MOCKS.chromeRuntime;
}

/**
 * Generates realistic Chrome loadTimes data
 */
function generateRealisticLoadTimes() {
  const now = performance.now();
  // Return a copy with updated timing values
  return { ...PRECOMPILED_MOCKS.loadTimes, commitLoadTime: now - Math.random() * 1000 };
}

/**
 * Generates Chrome CSI data
 */
function generateCSIData() {
  return {
    onloadT: Date.now(),
    pageT: Math.random() * 1000,
    startE: Date.now() - Math.random() * 2000,
    tran: Math.floor(Math.random() * 20)
  };
}

/**
 * Validates page state before script injection to avoid timeouts
 */
async function validatePageForInjection(page, currentUrl, forceDebug) {
  try {
    if (!page || page.isClosed()) return false;
    
    if (!page.browser().isConnected()) {
      if (forceDebug) console.log(`[debug] Page validation failed - browser disconnected: ${currentUrl}`);
      return false;
    }
    await Promise.race([
      page.evaluate(() => document.readyState || 'loading'),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Page evaluation timeout')), 1500))
    ]);
    return true;
  } catch (validationErr) {
    if (forceDebug) console.log(`[debug] Page validation failed - ${validationErr.message}: ${currentUrl}`);
    return false;
  }
}

/**
 * Creates mock fingerprinting objects
 */
function createFingerprintMocks() {
  const mockResult = PRECOMPILED_MOCKS.fingerprintResult;
  
  return {
    fp: {
      getResult: (callback) => callback ? setTimeout(() => callback(mockResult), 0) : mockResult,
      get: (callback) => Promise.resolve(mockResult),
      load: () => Promise.resolve(window.fp),
      components: mockResult.components,
      x64hash128: () => 'mock_hash',
      tz: DEFAULT_TIMEZONE,
      timezone: DEFAULT_TIMEZONE
    },
    FingerprintJS: {
      load: () => Promise.resolve({
        get: () => Promise.resolve(mockResult)
      })
    },
    ClientJS: function() {
      this.getFingerprint = () => 'mock_fingerprint_' + Math.random().toString(36).substr(2, 9);
      this.getBrowser = () => 'Chrome';
      this.getOS = () => 'Windows';
      this.fp = {};
    }
  };
}

/**
 * Applies timezone spoofing
 */
function applyTimezoneSpoofing(timezone, options = {}) {
  const tzConfig = TIMEZONE_CONFIG[timezone] || TIMEZONE_CONFIG[DEFAULT_TIMEZONE];
  
  // Spoof Intl.DateTimeFormat
  if (window.Intl?.DateTimeFormat) {
    const OriginalDateTimeFormat = window.Intl.DateTimeFormat;
    window.Intl.DateTimeFormat = function(...args) {
      const instance = new OriginalDateTimeFormat(...args);
      const originalResolvedOptions = instance.resolvedOptions;
      
      instance.resolvedOptions = function() {
        const opts = originalResolvedOptions.call(this);
        opts.timeZone = timezone;
        return opts;
      };
      return instance;
    };
    Object.setPrototypeOf(window.Intl.DateTimeFormat, OriginalDateTimeFormat);
  }
  
  // Spoof Date.getTimezoneOffset
  const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
  Date.prototype.getTimezoneOffset = function() {
    return tzConfig.offset;
  };
  
  return true;
}

/**
 * Enhanced user agent spoofing with stealth protection
 */
async function applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.userAgent) return;

  if (forceDebug) console.log(`[debug] User agent spoofing: ${siteConfig.userAgent}`);

  // Browser connection check
  try { 
    if (!page.browser().isConnected() || page.isClosed()) return; 
    if (page.browser().process()?.killed) return;
  } catch { return; }

  // Validate page state before injection
  if (!(await validatePageForInjection(page, currentUrl, forceDebug))) return;

  const ua = USER_AGENT_COLLECTIONS.get(siteConfig.userAgent.toLowerCase());
  
  if (ua) {
    await page.setUserAgent(ua);
    
    if (forceDebug) console.log(`[debug] Applying stealth protection for ${currentUrl}`);
    
    try {
      await page.evaluateOnNewDocument((userAgent, debugEnabled) => {
      
        // Apply inline error suppression first
        (function() {
          const originalConsoleError = console.error;
          const originalWindowError = window.onerror;
          
          function shouldSuppressFingerprintError(message) {
            const patterns = [
              /\.closest is not a function/i,
              /\.querySelector is not a function/i,
              /\.addEventListener is not a function/i,
              /Cannot read propert(y|ies) of null \\(reading 'fp'\\)/i,
              /Cannot read propert(y|ies) of undefined \\(reading 'fp'\\)/i,
              /Cannot redefine property: href/i,
              /Cannot redefine property: __webdriver_script_func/i,
              /Cannot redefine property: webdriver/i,
              /Cannot read propert(y|ies) of undefined \\(reading 'toLowerCase'\\)/i,
              /\\.toLowerCase is not a function/i,
              /fp is not defined/i,
              /fingerprint is not defined/i,
              /FingerprintJS is not defined/i,
              /\\$ is not defined/i,
              /jQuery is not defined/i,
              /_ is not defined/i,
              /Failed to load resource.*server responded with a status of [45]\\d{2}/i,
              /Failed to fetch/i,
              /(webdriver|callPhantom|_phantom|__nightmare|_selenium) is not defined/i,
              /Failed to execute 'observe' on 'IntersectionObserver'.*parameter 1 is not of type 'Element'/i,
              /tz check/i,
              /new window\\.Error.*<anonymous>/i,
              /Failed to load resource.*server responded with a status of 40[34]/i,
              /Blocked script execution in 'about:blank'.*sandboxed.*allow-scripts/i,
              /Page JavaScript error:/i,
              /^[a-zA-Z0-9_$]+\[.*\]\s+is not a function/i,
              /^[a-zA-Z0-9_$]+\(.*\)\s+is not a function/i,
              /^[a-zA-Z0-9_$]+\.[a-zA-Z0-9_$]+.*is not a function/i
            ];
            return patterns.some(pattern => pattern.test(String(message || '')));
          }
          
          console.error = function(...args) {
            const message = args.join(' ');
            if (shouldSuppressFingerprintError(message)) {
              if (debugEnabled) console.log("[fingerprint] Suppressed error:", message);
              return;
            }
            return originalConsoleError.apply(this, arguments);
          };
          
          window.onerror = function(message, source, lineno, colno, error) {
            if (shouldSuppressFingerprintError(message)) {
              if (debugEnabled) console.log("[fingerprint] Suppressed window error:", message);
              return true;
            }
            if (originalWindowError) {
              return originalWindowError.apply(this, arguments);
            }
            return false;
          };
        })();
        
        // Create safe property definition helper
        function safeDefinePropertyLocal(target, property, descriptor) {
          const builtInProps = new Set(['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash', 'constructor', 'prototype', '__proto__', 'toString', 'valueOf', 'assign', 'reload', 'replace']);
       
          if (builtInProps.has(property)) {
            if (debugEnabled) console.log(`[fingerprint] Skipping built-in property: ${property}`);
            return false;
          }

          try {
            const existing = Object.getOwnPropertyDescriptor(target, property);
            if (existing?.configurable === false) {
              if (debugEnabled) console.log(`[fingerprint] Cannot modify non-configurable: ${property}`);
              return false;
            }

            Object.defineProperty(target, property, {
              ...descriptor,
              configurable: true
            });
            return true;
          } catch (err) {
            if (debugEnabled) console.log(`[fingerprint] Failed to define ${property}: ${err.message}`);
            return false;
          }
        }

        // Add cached descriptors helper for page context
        const CACHED_DESCRIPTORS = {
          getter: (fn) => ({ get: fn, enumerable: true, configurable: true })
        };
        
        // Add monomorphic spoofing functions for page context
        function spoofNavigatorProperties(navigator, properties) {
          for (const [prop, descriptor] of Object.entries(properties)) {
            safeDefinePropertyLocal(navigator, prop, descriptor);
          }
        }
        
        function spoofScreenProperties(screen, properties) {
          for (const [prop, descriptor] of Object.entries(properties)) {
            safeDefinePropertyLocal(screen, prop, descriptor);
          }
        }
        
        // Safe execution wrapper
        function safeExecute(fn, description) {
          try {
            fn();
            return true;
          } catch (err) {
            if (debugEnabled) console.log(`[fingerprint] ${description} failed: ${err.message}`);
            return false;
          }
        }

        // Remove webdriver properties
        //
        safeExecute(() => {
          try {
            delete navigator.webdriver;
          } catch (e) {}
          safeDefinePropertyLocal(navigator, 'webdriver', { get: () => undefined });
        }, 'webdriver removal');

        // Remove automation properties
        //
        safeExecute(() => {
          const automationProps = [
            'callPhantom', '_phantom', '__nightmare', '_selenium', '__selenium_unwrapped',
            '__webdriver_evaluate', '__driver_evaluate', '__webdriver_script_function',
            '__fxdriver_evaluate', '__fxdriver_unwrapped', '__webdriver_script_fn',
            'phantomjs', '_Selenium_IDE_Recorder', 'callSelenium', '_selenium',
            '__phantomas', '__selenium_evaluate', '__driver_unwrapped',
            'webdriver-evaluate', '__webdriverFunc', 'driver-evaluate', '__driver-evaluate', '__selenium-evaluate',
            'spawn', 'emit', 'Buffer', 'domAutomation', 'domAutomationController',
            'cdc_adoQpoasnfa76pfcZLmcfl_JSON', 'cdc_adoQpoasnfa76pfcZLmcfl_Object',
            'cdc_adoQpoasnfa76pfcZLmcfl_Proxy', 'cdc_adoQpoasnfa76pfcZLmcfl_Reflect',
            '$cdc_asdjflasutopfhvcZLmcfl_', '$chrome_asyncScriptInfo', '__$webdriverAsyncExecutor'
          ];
          
          automationProps.forEach(prop => {
            try {
              delete window[prop];
              delete navigator[prop];
              safeDefinePropertyLocal(window, prop, { get: () => undefined });
              safeDefinePropertyLocal(navigator, prop, { get: () => undefined });
            } catch (e) {}
          });
        }, 'automation properties removal');

        // Simulate Chrome runtime
        //
        safeExecute(() => {
          if (!window.chrome) {
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
                  version: "142.0.0.0",
                  manifest_version: 3,
                  description: "Chrome Browser"
                }),
                getURL: (path) => `chrome-extension://invalid/${path}`,
                id: undefined,
                getPlatformInfo: (callback) => callback({
                  os: navigator.platform.includes('Win') ? 'win' : 
                      navigator.platform.includes('Mac') ? 'mac' : 'linux',
                  arch: 'x86-64',
                  nacl_arch: 'x86-64'
                })
              },
              storage: {
                local: {
                  get: (keys, callback) => callback && callback({}),
                  set: (items, callback) => callback && callback(),
                  remove: (keys, callback) => callback && callback(),
                  clear: (callback) => callback && callback()
                },
                sync: {
                  get: (keys, callback) => callback && callback({}),
                  set: (items, callback) => callback && callback(),
                  remove: (keys, callback) => callback && callback(),
                  clear: (callback) => callback && callback()
                }
              },
              loadTimes: () => {
                const now = performance.now();
                return {
                  commitLoadTime: now - Math.random() * 1000,
                  connectionInfo: 'http/1.1',
                  finishDocumentLoadTime: now - Math.random() * 500,
                  finishLoadTime: now - Math.random() * 100,
                  navigationType: 'Navigation'
                };
              },
              csi: () => ({
                onloadT: Date.now(),
                pageT: Math.random() * 1000,
                startE: Date.now() - Math.random() * 2000
              })
            };
            
            // Make chrome object non-enumerable to match real Chrome
            Object.defineProperty(window, 'chrome', {
              value: window.chrome,
              writable: false,
              enumerable: false,
              configurable: true
            });
            
            // Add Chrome-specific globals that Cloudflare might check
            if (!window.external) {
              window.external = {
                AddSearchProvider: () => {},
                IsSearchProviderInstalled: () => 0
              };
            }
            
            // Ensure chrome.runtime appears as a native object
            Object.defineProperty(window.chrome.runtime, 'toString', {
              value: () => '[object Object]'
            });
          }
        }, 'Chrome runtime simulation');

        // Add realistic Chrome browser behavior
        //
        safeExecute(() => {
          // Remove Puppeteer-specific properties not covered in main automation cleanup
          delete window.__puppeteer_evaluation_script__;
          delete window.__runtime;
          delete window._asyncToGenerator;
          delete window.__puppeteer;
          delete window.__cdp;
          delete window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
          
          // Simulate Chrome's performance observer
          if (window.PerformanceObserver) {
            try {
              const observer = new PerformanceObserver(() => {});
              observer.observe({entryTypes: ['navigation']});
            } catch(e) {
              // Silently ignore if PerformanceObserver fails
            }
          }
          
          // Ensure external object exists (don't overwrite chrome object)
          window.external = window.external || {};
          
        }, 'realistic Chrome behavior');

        // Spoof plugins based on user agent
        //
        safeExecute(() => {
          let plugins = [];
          if (userAgent.includes('Chrome')) {
            plugins = [
              { 
                name: 'Chrome PDF Plugin', 
                description: 'Portable Document Format', 
                filename: 'internal-pdf-viewer',
                length: 1,
                version: ''
              },
              { 
                name: 'Chrome PDF Viewer', 
                description: '', 
                filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai',
                length: 1,
                version: ''
              }
            ];
          } else if (userAgent.includes('Firefox')) {
            plugins = [
              { 
                name: 'PDF.js', 
                description: 'Portable Document Format', 
                filename: 'internal-pdf-js',
                length: 2,
                version: '5.4.70'
              }
            ];
          } else if (userAgent.includes('Safari')) {
            // Safari typically has no plugins in modern versions
            plugins = [];
          }
          // Create proper array-like object with enumerable indices and length
          const pluginsArray = {};
          plugins.forEach((plugin, index) => {
            pluginsArray[index] = plugin;
          });
          
          // Ensure length property is properly defined
          Object.defineProperty(pluginsArray, 'length', {
            value: plugins.length,
            writable: false,
            enumerable: false,
            configurable: false
          });

          safeDefinePropertyLocal(navigator, 'plugins', { get: () => pluginsArray });
        }, 'plugins spoofing');

        // Spoof languages
        //
        safeExecute(() => {
          const languages = ['en-US', 'en'];
          const languageProps = {
            languages: { get: () => languages },
            language: { get: () => languages[0] }
          };
          spoofNavigatorProperties(navigator, languageProps);
        }, 'language spoofing');

        // Spoof vendor information
        //
        safeExecute(() => {
          let vendor = 'Google Inc.';
          let product = 'Gecko';
          
          if (userAgent.includes('Firefox')) {
            vendor = '';
          } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
            vendor = 'Apple Computer, Inc.';
          }
          
          const vendorProps = {
            vendor: { get: () => vendor },
            product: { get: () => product }
          };
          spoofNavigatorProperties(navigator, vendorProps);
        }, 'vendor/product spoofing');

        // Enhanced OS fingerprinting protection based on actual user agent content
        //
        safeExecute(() => {
          let osType = 'windows';
          let browserType = 'chrome';
          
          // Detect OS from user agent string patterns
          if (userAgent.includes('Macintosh') || userAgent.includes('Mac OS X')) {
            osType = 'mac';
          } else if (userAgent.includes('X11; Linux') || userAgent.includes('Ubuntu')) {
            osType = 'linux';
          } else if (userAgent.includes('Windows NT')) {
            osType = 'windows';
          }
          
          // Detect browser type
          if (userAgent.includes('Firefox/')) {
            browserType = 'firefox';
          } else if (userAgent.includes('Safari/') && !userAgent.includes('Chrome/')) {
            browserType = 'safari';
          }
          
          // Apply OS-specific navigator properties
          if (osType === 'windows') {
            if (browserType === 'firefox') {
              safeDefinePropertyLocal(navigator, 'oscpu', { get: () => 'Windows NT 10.0; Win64; x64' });
              safeDefinePropertyLocal(navigator, 'buildID', { get: () => '20100101' });
            }
            if (window.screen) {
              safeDefinePropertyLocal(window.screen, 'fontSmoothingEnabled', { get: () => true });
            }
          } else if (osType === 'mac') {
            if (browserType === 'firefox') {
              safeDefinePropertyLocal(navigator, 'oscpu', { get: () => 'Intel Mac OS X 10.15' });
              safeDefinePropertyLocal(navigator, 'buildID', { get: () => '20100101' });
            }
          } else if (osType === 'linux') {
            if (browserType === 'firefox') {
              safeDefinePropertyLocal(navigator, 'oscpu', { get: () => 'Linux x86_64' });
              safeDefinePropertyLocal(navigator, 'buildID', { get: () => '20100101' });
            }
          }
        }, 'enhanced OS fingerprinting protection');

        // Hardware concurrency spoofing (universal coverage)
        //
        safeExecute(() => {
          const hardwareProps = {
            hardwareConcurrency: { get: () => [4, 6, 8, 12][Math.floor(Math.random() * 4)] }
          };
          spoofNavigatorProperties(navigator, hardwareProps);
        }, 'hardware concurrency spoofing');


        // Screen resolution fingerprinting protection
        //
        safeExecute(() => {
          // Common realistic resolutions to avoid fingerprinting
          const commonResolutions = [
            { width: 1920, height: 1080 },
            { width: 2560, height: 1440 },
            { width: 3840, height: 2160 },
            { width: 1280, height: 720 },
            { width: 1366, height: 768 },
            { width: 1440, height: 900 },
            { width: 1536, height: 864 }
          ];
          const resolution = commonResolutions[Math.floor(Math.random() * commonResolutions.length)];
          
          const screenProps = {
            width: { get: () => resolution.width },
            height: { get: () => resolution.height },
            availWidth: { get: () => resolution.width },
            availHeight: { get: () => resolution.height - 40 }
          };
          spoofScreenProperties(window.screen, screenProps);
        }, 'screen resolution protection');

        // Spoof MIME types
        //
        safeExecute(() => {
          let mimeTypes = [];
          if (userAgent.includes('Chrome')) {
            mimeTypes = [
              { type: 'application/pdf', description: 'Portable Document Format', suffixes: 'pdf' },
              { type: 'application/x-google-chrome-pdf', description: 'Portable Document Format', suffixes: 'pdf' }
            ];
          }
          safeDefinePropertyLocal(navigator, 'mimeTypes', { get: () => mimeTypes });
        }, 'mimeTypes spoofing');

        // Enhanced Error.stack protection for CDP detection
        safeExecute(() => {
          const OriginalError = window.Error;
          window.Error = function(...args) {
            const error = new OriginalError(...args);
            const originalStack = error.stack;
            
            Object.defineProperty(error, 'stack', {
              get: function() {
                if (typeof originalStack === 'string') {
                  return originalStack
                    .replace(/.*puppeteer.*\n?/gi, '')
                    .replace(/.*chrome-devtools.*\n?/gi, '')
                    .replace(/.*webdriver.*\n?/gi, '')
                    .replace(/.*automation.*\n?/gi, '')
                    .trim() || `${this.name || 'Error'}: ${this.message || ''}\n    at unknown location`;
                }
                return originalStack;
              },
              configurable: true
            });
            return error;
          };
          
          window.Error.prototype = OriginalError.prototype;
          Object.setPrototypeOf(window.Error, OriginalError);
          
          // Copy static properties
          ['captureStackTrace', 'stackTraceLimit', 'prepareStackTrace'].forEach(prop => {
            if (OriginalError[prop]) {
              try { window.Error[prop] = OriginalError[prop]; } catch (e) {}
            }
          });
        }, 'Error stack protection');

        // Create fingerprinting mock objects
        safeExecute(() => {
          const mockResult = {
            visitorId: 'mock_visitor_' + Math.random().toString(36).substr(2, 9),
            confidence: { score: 0.99 },
            components: {
              screen: { value: { width: 1920, height: 1080 } },
              timezone: { value: 'America/New_York' }
            }
          };

          window.fp = window.fp || {
            getResult: (callback) => callback ? setTimeout(() => callback(mockResult), 0) : mockResult,
            get: (callback) => Promise.resolve(mockResult),
            load: () => Promise.resolve(window.fp)
          };

          window.FingerprintJS = window.FingerprintJS || {
            load: () => Promise.resolve({ get: () => Promise.resolve(mockResult) })
          };

          window.ClientJS = window.ClientJS || function() {
            this.getFingerprint = () => 'mock_fingerprint_' + Math.random().toString(36).substr(2, 9);
          };
        }, 'fingerprinting mocks');

        // WebGL spoofing
        //
        safeExecute(() => {
          // Enhanced WebGL fingerprinting protection
          const webglParams = {
            37445: 'Intel Inc.',                    // VENDOR
            37446: 'Intel(R) UHD Graphics 630',    // RENDERER (more realistic)
            7936: 'WebGL 1.0 (OpenGL ES 2.0 Chromium)', // VERSION
            35724: 'WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.00 Chromium)', // SHADING_LANGUAGE_VERSION
            34076: 16384,                          // MAX_TEXTURE_SIZE
            34024: 16384,                          // MAX_CUBE_MAP_TEXTURE_SIZE
            34930: new Float32Array([1, 1]),       // ALIASED_LINE_WIDTH_RANGE
            33901: new Float32Array([0, 1]),       // ALIASED_POINT_SIZE_RANGE
            35660: 16,                             // MAX_VERTEX_ATTRIBS
            35661: 16,                             // MAX_VERTEX_UNIFORM_VECTORS
            35659: 16,                             // MAX_VARYING_VECTORS
            35663: 16,                             // MAX_FRAGMENT_UNIFORM_VECTORS
            36347: 4096,                           // MAX_RENDERBUFFER_SIZE
            34852: 32,                             // MAX_COMBINED_TEXTURE_IMAGE_UNITS
            2978: new Int32Array([0, 0, 1920, 1080]), // VIEWPORT
            3379: new Int32Array([0, 0, 1920, 1080])  // SCISSOR_BOX
          };
          
          if (window.WebGLRenderingContext) {
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
              if (webglParams.hasOwnProperty(parameter)) {
                return webglParams[parameter];
              }
              return getParameter.call(this, parameter);
            };
            // Spoof supported extensions
            const getSupportedExtensions = WebGLRenderingContext.prototype.getSupportedExtensions;
            WebGLRenderingContext.prototype.getSupportedExtensions = function() {
              return [
                'ANGLE_instanced_arrays',
                'EXT_blend_minmax',
                'EXT_color_buffer_half_float',
                'EXT_disjoint_timer_query',
                'EXT_float_blend',
                'EXT_frag_depth',
                'EXT_shader_texture_lod',
                'EXT_texture_compression_rgtc',
                'EXT_texture_filter_anisotropic',
                'WEBKIT_EXT_texture_filter_anisotropic',
                'EXT_sRGB',
                'OES_element_index_uint',
                'OES_fbo_render_mipmap',
                'OES_standard_derivatives',
                'OES_texture_float',
                'OES_texture_float_linear',
                'OES_texture_half_float',
                'OES_texture_half_float_linear',
                'OES_vertex_array_object',
                'WEBGL_color_buffer_float',
                'WEBGL_compressed_texture_s3tc',
                'WEBGL_debug_renderer_info',
                'WEBGL_debug_shaders',
                'WEBGL_depth_texture',
                'WEBGL_draw_buffers',
                'WEBGL_lose_context'
              ];
            };
          }
          // Also handle WebGL2 context
          if (window.WebGL2RenderingContext) {
            const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
            WebGL2RenderingContext.prototype.getParameter = function(parameter) {
              if (webglParams.hasOwnProperty(parameter)) {
                return webglParams[parameter];
              }
              return getParameter2.call(this, parameter);
            };
          }
        }, 'WebGL spoofing');

        // Permissions API spoofing
        //
        safeExecute(() => {
          if (navigator.permissions?.query) {
            const originalQuery = navigator.permissions.query;
            navigator.permissions.query = function(descriptor) {

              const permissionName = descriptor.name || descriptor;
              // Realistic Chrome permission defaults
              const chromeDefaults = {
                'notifications': 'default',
                'geolocation': 'prompt', 
                'camera': 'prompt',
                'microphone': 'prompt',
                'persistent-storage': 'granted',
                'background-sync': 'granted',
                'midi': 'prompt',
                'push': 'prompt',
                'accelerometer': 'granted',
                'gyroscope': 'granted',
                'magnetometer': 'granted'
              };
              
              const state = chromeDefaults[permissionName] || 'prompt';
              
              return Promise.resolve({ 
                state,
                onchange: null
              });
              }

          }

          // Block permission prompts from actually appearing
          if (window.Notification && Notification.requestPermission) {
            Notification.requestPermission = () => Promise.resolve('default');
          }
        }, 'permissions API spoofing');

        // Media Device Spoofing
        //
        safeExecute(() => {
          if (navigator.mediaDevices?.enumerateDevices) {
            navigator.mediaDevices.enumerateDevices = function() {
              return Promise.resolve([
                { deviceId: 'default', kind: 'audioinput', label: 'Default - Microphone (Realtek Audio)', groupId: 'group1' },
                { deviceId: 'default', kind: 'audiooutput', label: 'Default - Speakers (Realtek Audio)', groupId: 'group1' },
                { deviceId: 'default', kind: 'videoinput', label: 'HD WebCam (USB Camera)', groupId: 'group2' }
              ]);
            };
          }
        }, 'media device spoofing');
        
        // Fetch Request Headers Normalization
        //
        safeExecute(() => {
          const originalFetch = window.fetch;
          window.fetch = function(url, options = {}) {
            const headers = { ...(options.headers || {}) };
            
            // Add common browser headers if missing
            if (!headers['Accept']) {
              headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
            }
            if (!headers['Accept-Language']) {
              headers['Accept-Language'] = 'en-US,en;q=0.5';
            }
            if (!headers['Accept-Encoding']) {
              headers['Accept-Encoding'] = 'gzip, deflate, br';
            }
            
            return originalFetch.call(this, url, { ...options, headers });
          };
        }, 'fetch headers normalization');
        
        // Image Loading Pattern Obfuscation
        //
        safeExecute(() => {
          const originalImageSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
          if (originalImageSrc) {
            Object.defineProperty(HTMLImageElement.prototype, 'src', {
              set: function(value) {
                // Add random delay to image loading (0-50ms)
                setTimeout(() => {
                  originalImageSrc.set.call(this, value);
                }, Math.random() * 50);
              },
              get: originalImageSrc.get,
              configurable: true
            });
          }
        }, 'image loading obfuscation');

        // CSS Media Query Spoofing
        //
        safeExecute(() => {
          const originalMatchMedia = window.matchMedia;
          window.matchMedia = function(query) {
            const result = originalMatchMedia.call(this, query);
            // Add slight randomization to avoid fingerprinting for device queries
            if (query.includes('device-width') || query.includes('device-height') || 
                query.includes('aspect-ratio') || query.includes('color-gamut')) {
              Object.defineProperty(result, 'matches', {
                get: () => Math.random() > 0.1 ? originalMatchMedia.call(window, query).matches : !originalMatchMedia.call(window, query).matches,
                configurable: true
              });
            }
            return result;
          };
        }, 'CSS media query spoofing');

        // Enhanced WebRTC Spoofing
        //
        safeExecute(() => {
          if (window.RTCPeerConnection) {
            const OriginalRTC = window.RTCPeerConnection;
            window.RTCPeerConnection = function(...args) {
              const pc = new OriginalRTC(...args);
              const originalCreateOffer = pc.createOffer;
              pc.createOffer = function() {
                return Promise.reject(new Error('WebRTC disabled'));
              };
              return pc;
            };
            Object.setPrototypeOf(window.RTCPeerConnection, OriginalRTC);
          }
        }, 'WebRTC spoofing');

        // Font fingerprinting protection
        //
        safeExecute(() => {
          // OS-specific font profiles for better realism
          const getOSFonts = (userAgent) => {
            if (userAgent.includes('Windows') || userAgent.includes('Win')) {
              return ['Arial', 'Times New Roman', 'Courier New', 'Verdana', 'Tahoma', 'Trebuchet MS', 'Georgia', 'Impact', 'Comic Sans MS', 'Segoe UI'];
            } else if (userAgent.includes('Macintosh') || userAgent.includes('Mac OS X')) {
              return ['Arial', 'Times New Roman', 'Courier New', 'Helvetica', 'Times', 'Courier', 'Verdana', 'Georgia', 'Palatino', 'San Francisco'];
            } else {
              return ['Arial', 'Times New Roman', 'Courier New', 'Liberation Sans', 'Liberation Serif', 'DejaVu Sans', 'Ubuntu'];
            }
          };
          const standardFonts = getOSFonts(navigator.userAgent);
          
          // CRITICAL: Block font enumeration
          if (document.fonts) {
            Object.defineProperty(document.fonts, 'values', {
              value: () => standardFonts.map(font => ({ family: font, style: 'normal', weight: '400' }))[Symbol.iterator]()
            });
            Object.defineProperty(document.fonts, 'forEach', {
              value: (callback) => standardFonts.forEach((font, i) => callback({ family: font, style: 'normal', weight: '400' }, i))
            });
            Object.defineProperty(document.fonts, 'size', { get: () => standardFonts.length });
          }
          
          // Intercept font availability detection
          if (document.fonts && document.fonts.check) {
            const originalCheck = document.fonts.check;
            document.fonts.check = function(fontSpec) {
              // Always return true for standard fonts, false for others
              const fontFamily = fontSpec.match(/['"]([^'"]+)['"]/)?.[1] || fontSpec.split(' ').pop();
              return standardFonts.some(font => fontFamily.includes(font));
            };
          }
          
          // Prevent font loading detection
          if (document.fonts && document.fonts.load) {
            document.fonts.load = function() {
              return Promise.resolve([]);
            };
          }

          // Canvas-based font fingerprinting protection
          //
          const originalFillText = CanvasRenderingContext2D.prototype.fillText;
          const originalStrokeText = CanvasRenderingContext2D.prototype.strokeText;
          const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
          
          CanvasRenderingContext2D.prototype.fillText = function(text, x, y, maxWidth) {
            // Normalize font to standard before drawing
            const currentFont = this.font;
            if (currentFont && !standardFonts.some(font => currentFont.includes(font))) {
              this.font = currentFont.replace(/['"]?[^'"]*['"]?/, '"Arial"');
            }
            return originalFillText.call(this, text, x, y, maxWidth);
          };
          
          CanvasRenderingContext2D.prototype.strokeText = function(text, x, y, maxWidth) {
            const currentFont = this.font;
            if (currentFont && !standardFonts.some(font => currentFont.includes(font))) {
              this.font = currentFont.replace(/['"]?[^'"]*['"]?/, '"Arial"');
            }
            return originalStrokeText.call(this, text, x, y, maxWidth);
          };
          
          CanvasRenderingContext2D.prototype.measureText = function(text) {
            const result = originalMeasureText.call(this, text);
            // Add slight noise to text measurements to prevent precise fingerprinting
            result.width += (Math.random() - 0.5) * 0.1;
            return result;
          };

          // Comprehensive canvas fingerprinting protection
          //
          const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
          CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
            const imageData = originalGetImageData.call(this, sx, sy, sw, sh);
            // Add subtle noise to pixel data
            for (let i = 0; i < imageData.data.length; i += 4) {
              if (Math.random() < 0.1) { // 10% chance to modify each pixel
                imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + Math.floor(Math.random() * 3) - 1));
                imageData.data[i + 1] = Math.max(0, Math.min(255, imageData.data[i + 1] + Math.floor(Math.random() * 3) - 1));
                imageData.data[i + 2] = Math.max(0, Math.min(255, imageData.data[i + 2] + Math.floor(Math.random() * 3) - 1));
              }
            }
            return imageData;
          };
          
          // WebGL canvas context fingerprinting
          const originalGetContext = HTMLCanvasElement.prototype.getContext;
          HTMLCanvasElement.prototype.getContext = function(contextType, contextAttributes) {
            const context = originalGetContext.call(this, contextType, contextAttributes);
            
            if (contextType === 'webgl' || contextType === 'webgl2' || contextType === 'experimental-webgl') {
              // Override WebGL-specific fingerprinting methods
              const originalGetShaderPrecisionFormat = context.getShaderPrecisionFormat;
              context.getShaderPrecisionFormat = function(shaderType, precisionType) {
                return {
                  rangeMin: 127,
                  rangeMax: 127,
                  precision: 23
                };
              };
              
              const originalGetExtension = context.getExtension;
              context.getExtension = function(name) {
                // Block access to fingerprinting-sensitive extensions
                if (name === 'WEBGL_debug_renderer_info') {
                  return null;
                }
                return originalGetExtension.call(this, name);
              };
            }
            
            return context;
          };

          // Override font detection methods
          //
          const originalOffsetWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
          const originalOffsetHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight');
          
          if (originalOffsetWidth && originalOffsetHeight) {
            Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
              get: function() {
                if (this.style && this.style.fontFamily) {
                  return Math.floor(originalOffsetWidth.get.call(this) + (Math.random() - 0.5) * 2);
                }
                return originalOffsetWidth.get.call(this);
              },
              configurable: true
            });
          }
        }, 'font fingerprinting protection');

        // Performance timing obfuscation
        //
        safeExecute(() => {
          const originalNow = performance.now;
          performance.now = function() {
            return originalNow.call(this) + (Math.random() - 0.5) * 2; // +/- 1ms variation
          };
        }, 'performance timing obfuscation');

        // Canvas fingerprinting protection
        //
        safeExecute(() => {
          const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
          HTMLCanvasElement.prototype.toDataURL = function(...args) {
            const context = this.getContext('2d');
            if (context) {
              const imageData = context.getImageData(0, 0, this.width, this.height);
              for (let i = 0; i < imageData.data.length; i += 4) {
                imageData.data[i] = imageData.data[i] + Math.floor(Math.random() * 3) - 1;
              }
              context.putImageData(imageData, 0, 0);
            }
            return originalToDataURL.apply(this, args);
          };
        }, 'canvas fingerprinting protection');

        // Battery API spoofing
        //
        safeExecute(() => {
          if (navigator.getBattery) {
            navigator.getBattery = function() {
              return Promise.resolve({
                charging: Math.random() > 0.5,
                chargingTime: Math.random() > 0.5 ? Infinity : Math.random() * 3600,
                dischargingTime: Math.random() * 7200,
                level: Math.random() * 0.99 + 0.01
              });
            };
          }
        }, 'battery API spoofing');

        // Enhanced Mouse/Pointer Spoofing
        //
        safeExecute(() => {
          // Spoof pointer capabilities
          if (navigator.maxTouchPoints !== undefined) {
            safeDefinePropertyLocal(navigator, 'maxTouchPoints', { 
              get: () => Math.random() > 0.7 ? 0 : Math.floor(Math.random() * 5) + 1 
            });
          }
          
          // Spoof mouse timing patterns to prevent behavioral fingerprinting
          const originalAddEventListener = EventTarget.prototype.addEventListener;
          EventTarget.prototype.addEventListener = function(type, listener, options) {
            if (type === 'mousemove' && typeof listener === 'function') {
              const wrappedListener = function(event) {
                // Add slight timing variation to prevent pattern detection
                const delay = Math.random() * 2; // 0-2ms variation
                setTimeout(() => listener.call(this, event), delay);
              };
              return originalAddEventListener.call(this, type, wrappedListener, options);
            }
            return originalAddEventListener.call(this, type, listener, options);
          };
          
          // Spoof PointerEvent if available
          //
          if (window.PointerEvent) {
            const OriginalPointerEvent = window.PointerEvent;
            window.PointerEvent = function(type, eventInitDict = {}) {
              // Add realistic pointer properties
              const enhancedDict = {
                ...eventInitDict,
                pressure: eventInitDict.pressure || (Math.random() * 0.3 + 0.2), // 0.2-0.5
                tangentialPressure: eventInitDict.tangentialPressure || 0,
                tiltX: eventInitDict.tiltX || (Math.random() * 10 - 5), // -5 to 5
                tiltY: eventInitDict.tiltY || (Math.random() * 10 - 5),
                twist: eventInitDict.twist || Math.random() * 360,
                pointerType: eventInitDict.pointerType || 'mouse'
              };
              return new OriginalPointerEvent(type, enhancedDict);
            };
            Object.setPrototypeOf(window.PointerEvent, OriginalPointerEvent);
          }
          
          // Spoof touch capabilities for mobile detection evasion
          if (!window.TouchEvent && Math.random() > 0.8) {
            // 20% chance to add touch support to confuse fingerprinters
            window.TouchEvent = function(type, eventInitDict = {}) {
              return new MouseEvent(type, eventInitDict);
            };
            
            safeDefinePropertyLocal(navigator, 'maxTouchPoints', { get: () => 1 });
          }
          
          // Spoof mouse wheel behavior
          //
          const originalWheelEvent = window.WheelEvent;
          if (originalWheelEvent) {
            window.WheelEvent = function(type, eventInitDict = {}) {
              const enhancedDict = {
                ...eventInitDict,
                deltaMode: eventInitDict.deltaMode || 0,
                deltaX: eventInitDict.deltaX || 0,
                deltaY: eventInitDict.deltaY || (Math.random() * 100 - 50),
                deltaZ: eventInitDict.deltaZ || 0
              };
              return new originalWheelEvent(type, enhancedDict);
            };
          }
          
        }, 'enhanced mouse/pointer spoofing');

        safeExecute(() => {
          // Filter DevTools/automation traces from console.debug
          const originalConsoleDebug = console.debug;
          console.debug = function(...args) {
            const message = args.join(' ');
            if (typeof message === 'string' && (
                message.includes('DevTools') ||
                message.includes('Runtime.evaluate') ||
                message.includes('Page.addScriptToEvaluateOnNewDocument') ||
                message.includes('Protocol error'))) {
              return; // Silently drop DevTools-related debug messages
            }
            return originalConsoleDebug.apply(this, args);
          };

          const originalConsoleError = console.error;
          console.error = function(...args) {
            const message = args.join(' ');
            if (typeof message === 'string' && (
                message.includes('Failed to load resource') ||
                message.includes('is not defined') ||
                message.includes('is not a function')
              )) {
              if (debugEnabled) console.log(`[fingerprint] Suppressed error: ${message}`);
              return;
            }
            return originalConsoleError.apply(this, arguments);
          };
        }, 'console error suppression');
        
        // Hide source URL indicators (data: URLs reveal script injection)
        safeExecute(() => {
          const originalLocation = window.location;
          Object.defineProperty(window, 'location', {
            value: new Proxy(originalLocation, {
              get: function(target, prop) {
                if (prop === 'href' && target[prop] && target[prop].includes('data:')) {
                  return 'about:blank';
                }
                return target[prop];
              }
            }),
            configurable: false
          });
        }, 'location URL masking');

      }, ua, forceDebug);
    } catch (stealthErr) {
      if (stealthErr.message.includes('Session closed') || 
          stealthErr.message.includes('addScriptToEvaluateOnNewDocument timed out') ||
          stealthErr.message.includes('Target closed') ||
          stealthErr.message.includes('Protocol error') || stealthErr.name === 'ProtocolError' ||
          stealthErr.message.includes('detached Frame') || stealthErr.message.includes('Navigating frame was detached') ||
          stealthErr.message.includes('Cannot find context') ||
          stealthErr.message.includes('Execution context was destroyed')) {
        if (forceDebug) console.log(`[debug] Page closed during stealth injection: ${currentUrl}`);
        return;
      }
      console.warn(`[stealth protection failed] ${currentUrl}: ${stealthErr.message}`);
    }
  }
}

/**
 * Enhanced Brave browser spoofing
 */
async function applyBraveSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.isBrave) return;

  if (forceDebug) console.log(`[debug] Brave spoofing enabled for ${currentUrl}`);
  
  // Browser connection check
  try { 
    if (!page.browser().isConnected() || page.isClosed()) return; 
    if (page.browser().process()?.killed) return;
  } catch { return; }

  // Validate page state before injection
  if (!(await validatePageForInjection(page, currentUrl, forceDebug))) return;
  
  try {
    await page.evaluateOnNewDocument((debugEnabled) => {
      try {
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

      if (navigator.userAgent && !navigator.userAgent.includes('Brave')) {
        Object.defineProperty(navigator, 'userAgent', {
          get: () => navigator.userAgent.replace('Chrome/', 'Brave/').replace('Safari/537.36', 'Safari/537.36 Brave/1.60'),
          configurable: true
        });
      }
    } catch (err) {
      if (debugEnabled) console.log(`[fingerprint] Brave spoofing error: ${err.message}`);
    }
    }, forceDebug);
  } catch (braveErr) {
    if (braveErr.message.includes('Session closed') || 
        braveErr.message.includes('addScriptToEvaluateOnNewDocument timed out') ||
        braveErr.message.includes('Target closed') ||
        braveErr.message.includes('Protocol error') || braveErr.name === 'ProtocolError' ||
        braveErr.message.includes('detached Frame') || braveErr.message.includes('Navigating frame was detached') ||
        braveErr.message.includes('Cannot find context') ||
        braveErr.message.includes('Execution context was destroyed')) {
      if (forceDebug) console.log(`[debug] Page closed during Brave injection: ${currentUrl}`);
      return;
    }
    if (forceDebug) console.log(`[debug] Brave spoofing failed: ${currentUrl} - ${braveErr.message}`);
  }
}

/**
 * Enhanced fingerprint protection with realistic spoofing
 */
async function applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl) {
  const fingerprintSetting = siteConfig.fingerprint_protection;
  if (!fingerprintSetting) return;

  if (forceDebug) console.log(`[debug] Fingerprint protection enabled for ${currentUrl}`);
  
  // Browser connection check
  try { 
    if (!page.browser().isConnected() || page.isClosed()) return; 
    if (page.browser().process()?.killed) return;
  } catch { return; }
  
  // Validate page state before injection
  if (!(await validatePageForInjection(page, currentUrl, forceDebug))) return;
  
 const currentUserAgent = await page.evaluate(() => navigator.userAgent);
  
 const spoof = fingerprintSetting === 'random' ? generateRealisticFingerprint(currentUserAgent) : {
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
    await page.evaluateOnNewDocument(({ spoof, debugEnabled }) => {
    
      // Define helper functions FIRST in this context
      function spoofNavigatorProperties(navigator, properties) {
        for (const [prop, descriptor] of Object.entries(properties)) {
          safeDefinePropertyLocal(navigator, prop, descriptor);
        }
      }
      
      function spoofScreenProperties(screen, properties) {
        for (const [prop, descriptor] of Object.entries(properties)) {
          safeDefinePropertyLocal(screen, prop, descriptor);
        }
      }
      
      function safeDefinePropertyLocal(target, property, descriptor) {
        try {
          const existing = Object.getOwnPropertyDescriptor(target, property);
          if (existing?.configurable === false) return false;
          
          Object.defineProperty(target, property, {
            ...descriptor,
            configurable: true
          });
          return true;
        } catch (err) {
          if (debugEnabled) console.log(`[fingerprint] Failed to define ${property}: ${err.message}`);
          return false;
        }
      }

      // Platform spoofing
      const navigatorProps = {
        platform: { get: () => spoof.platform },
        deviceMemory: { get: () => spoof.deviceMemory },
        hardwareConcurrency: { get: () => spoof.hardwareConcurrency }
      };
      spoofNavigatorProperties(navigator, navigatorProps);
      
      // Platform, memory, and hardware spoofing combined for better V8 optimization
      // (moved into navigatorProps above);

      // Connection type spoofing
      safeDefinePropertyLocal(navigator, 'connection', {
        get: () => ({
          effectiveType: ['slow-2g', '2g', '3g', '4g'][Math.floor(Math.random() * 4)],
          type: Math.random() > 0.5 ? 'cellular' : 'wifi',
          saveData: Math.random() > 0.8,
          downlink: 1.5 + Math.random() * 8,
          rtt: 50 + Math.random() * 200
        })
      });
      
      // Screen properties spoofing
      const screenSpoofProps = {};
      ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'].forEach(prop => {
        if (spoof.screen[prop] !== undefined) {
          screenSpoofProps[prop] = { get: () => spoof.screen[prop] };
        }
      });
      spoofScreenProperties(window.screen, screenSpoofProps);
      
      // Language spoofing
      const languages = Array.isArray(spoof.language) ? spoof.language : [spoof.language, spoof.language.split('-')[0]];
      const languageSpoofProps = {
        languages: { get: () => languages },
        language: { get: () => languages[0] }
      };
      spoofNavigatorProperties(navigator, languageSpoofProps);

      // Timezone spoofing
      if (spoof.timezone && window.Intl?.DateTimeFormat) {
        const OriginalDateTimeFormat = window.Intl.DateTimeFormat;
        window.Intl.DateTimeFormat = function(...args) {
          const instance = new OriginalDateTimeFormat(...args);
          const originalResolvedOptions = instance.resolvedOptions;
          
          instance.resolvedOptions = function() {
            const opts = originalResolvedOptions.call(this);
            opts.timeZone = spoof.timezone;
            return opts;
          };
          return instance;
        };
        Object.setPrototypeOf(window.Intl.DateTimeFormat, OriginalDateTimeFormat);

        // Timezone offset spoofing
        const timezoneOffsets = {
          'America/New_York': 300,
          'America/Los_Angeles': 480,
          'Europe/London': 0,
          'America/Chicago': 360
        };
        
        const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
        Date.prototype.getTimezoneOffset = function() {
          return timezoneOffsets[spoof.timezone] || originalGetTimezoneOffset.call(this);
        };
      }
      
      // Cookie and DNT spoofing
      if (spoof.cookieEnabled !== undefined) {
        safeDefinePropertyLocal(navigator, 'cookieEnabled', { get: () => spoof.cookieEnabled });
      }
      if (spoof.doNotTrack !== undefined) {
        safeDefinePropertyLocal(navigator, 'doNotTrack', { get: () => spoof.doNotTrack });
      }
      
    }, { spoof, debugEnabled: forceDebug });
  } catch (err) {
    if (err.message.includes('Session closed') || 
        err.message.includes('addScriptToEvaluateOnNewDocument timed out') ||
        err.message.includes('Target closed') ||
        err.message.includes('Protocol error') || err.name === 'ProtocolError' ||
        err.message.includes('detached Frame') || err.message.includes('Navigating frame was detached') ||
        err.message.includes('Cannot find context') ||
        err.message.includes('Execution context was destroyed')) {
      if (forceDebug) console.log(`[debug] Page closed during fingerprint injection: ${currentUrl}`);
      return;
    }
    console.warn(`[fingerprint protection failed] ${currentUrl}: ${err.message}`);
  }
}

/**
 * Simulate human-like behavior
 * Enhanced with realistic mouse patterns and timing
 */
async function simulateHumanBehavior(page, forceDebug) {
  try {
    // Validate page state before injection
    if (!page || page.isClosed()) {
      if (forceDebug) console.log(`[debug] Human behavior simulation skipped - page closed`);
      return;
    }
    
    // Check if browser is still connected
    if (!page.browser().isConnected()) {
      if (forceDebug) console.log(`[debug] Human behavior simulation skipped - browser disconnected`);
      return;
    }

    await page.evaluateOnNewDocument((debugEnabled) => {
      
      try {
        // Enhanced human-like mouse simulation with realistic patterns
        let mouseX = Math.random() * (window.innerWidth - 100) + 50;
        let mouseY = Math.random() * (window.innerHeight - 100) + 50;
        let lastMoveTime = Date.now();
        let moveCount = 0;
        
        // Realistic mouse movement patterns
        const movePatterns = {
          linear: () => ({
            deltaX: (Math.random() - 0.5) * 4,
            deltaY: (Math.random() - 0.5) * 4
          }),
          curved: () => {
            const angle = moveCount * 0.1;
            return {
              deltaX: Math.sin(angle) * 3 + (Math.random() - 0.5) * 2,
              deltaY: Math.cos(angle) * 3 + (Math.random() - 0.5) * 2
            };
          },
          jittery: () => ({
            deltaX: (Math.random() - 0.5) * 8,
            deltaY: (Math.random() - 0.5) * 8
          })
        };
        
        const patterns = Object.keys(movePatterns);
        let currentPattern = patterns[Math.floor(Math.random() * patterns.length)];
        let patternChangeCounter = 0;
        
        const moveInterval = setInterval(() => {
          const now = Date.now();
          const timeDelta = now - lastMoveTime;
          
          // Change pattern occasionally
          if (patternChangeCounter++ > 20 + Math.random() * 30) {
            currentPattern = patterns[Math.floor(Math.random() * patterns.length)];
            patternChangeCounter = 0;
          }
          
          // Apply movement pattern
          const movement = movePatterns[currentPattern]();
          mouseX += movement.deltaX;
          mouseY += movement.deltaY;
          
          // Keep within bounds with padding
          mouseX = Math.max(10, Math.min(window.innerWidth - 10, mouseX));
          mouseY = Math.max(10, Math.min(window.innerHeight - 10, mouseY));
          
          try {
            // Dispatch realistic mouse events with varying timing
            document.dispatchEvent(new MouseEvent('mousemove', {
              clientX: mouseX,
              clientY: mouseY,
              bubbles: true,
              cancelable: true,
              view: window,
              detail: 0,
              buttons: 0,
              button: 0
            }));

            // Occasionally simulate clicks for more realistic behavior
            if (Math.random() > 0.995) { // Very rare clicks
              document.dispatchEvent(new MouseEvent('click', {
                clientX: mouseX,
                clientY: mouseY,
                bubbles: true,
                cancelable: true,
                view: window
              }));
            }
            
            moveCount++;
            lastMoveTime = now;

          } catch (e) {}
        }, 50 + Math.random() * 100); // More frequent, realistic timing (50-150ms)
        
        // Stop after 45 seconds with gradual slowdown
        setTimeout(() => {
          try { 
            clearInterval(moveInterval);
            if (debugEnabled) console.log('[fingerprint] Enhanced mouse simulation completed');
          } catch (e) {}
        }, 45000);
        
      } catch (err) {
        if (debugEnabled) console.log(`[fingerprint] Human behavior simulation failed: ${err.message}`);
      }
      
    }, forceDebug);
  } catch (err) {
    if (forceDebug) console.log(`[debug] Human behavior simulation setup failed: ${err.message}`);
  }
}

/**
 * Main function that applies all fingerprint spoofing techniques
 */
async function applyAllFingerprintSpoofing(page, siteConfig, forceDebug, currentUrl) {

  const techniques = [
    { fn: applyUserAgentSpoofing, name: 'User agent spoofing' },
    { fn: applyBraveSpoofing, name: 'Brave spoofing' },
    { fn: applyFingerprintProtection, name: 'Fingerprint protection' }
  ];

  for (const { fn, name } of techniques) {
    try {
      await fn(page, siteConfig, forceDebug, currentUrl);
    } catch (err) {
      if (forceDebug) console.log(`[debug] ${name} failed for ${currentUrl}: ${err.message}`);
    }
  }
  
  // Add human behavior simulation if user agent spoofing is enabled
  if (siteConfig.userAgent) {
    try {
      await simulateHumanBehavior(page, forceDebug);
    } catch (behaviorErr) {
      if (forceDebug) console.log(`[debug] Human behavior simulation failed for ${currentUrl}: ${behaviorErr.message}`);
    }
  }
}

// Legacy compatibility function - maintained for backwards compatibility
function safeExecuteSpoofing(spoofFunction, description, forceDebug = false) {
  return safeSpoofingExecution(spoofFunction, description, { debug: forceDebug });
}


module.exports = {
  generateRealisticFingerprint,
  getRealisticScreenResolution,
  applyUserAgentSpoofing,
  applyBraveSpoofing,
  applyFingerprintProtection,
  applyAllFingerprintSpoofing,
  simulateHumanBehavior,
  safeDefineProperty,
  safeExecuteSpoofing, // Legacy compatibility
  safeSpoofingExecution,
  createFingerprintMocks,
  applyTimezoneSpoofing,
  DEFAULT_PLATFORM,
  DEFAULT_TIMEZONE
};
