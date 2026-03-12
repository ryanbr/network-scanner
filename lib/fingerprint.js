// === Enhanced Fingerprint Protection Module - Puppeteer 23.x Compatible ===
// This module handles advanced browser fingerprint spoofing, user agent changes,
// and comprehensive bot detection evasion techniques.
//const { applyErrorSuppression } = require('./error-suppression');

// Default values for fingerprint spoofing if not set to 'random'
const DEFAULT_PLATFORM = 'Win32';
const DEFAULT_TIMEZONE = 'America/New_York';

// Deterministic random generator seeded by domain string
// Same domain always produces the same sequence of values
function seededRandom(seed) {
  let h = 0;
  for (let i = 0; i < seed.length; i++) {
    h = ((h << 5) - h + seed.charCodeAt(i)) | 0;
  }
  return () => {
    h = (h * 1664525 + 1013904223) | 0;
    return (h >>> 0) / 4294967296;
  };
}

// Cache fingerprints per domain so reloads and multi-page visits stay consistent
const _fingerprintCache = new Map();

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

// Built-in properties that should not be modified
const BUILT_IN_PROPERTIES = new Set([
  'href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash',
  'constructor', 'prototype', '__proto__', 'toString', 'valueOf', 'assign', 'reload', 'replace'
]);

// User agent collections with latest versions
const USER_AGENT_COLLECTIONS = Object.freeze(new Map([
  ['chrome', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"],
  ['chrome_mac', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"],
  ['chrome_linux', "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"],
  ['firefox', "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"],
  ['firefox_mac', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0"],
  ['firefox_linux', "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0"],
  ['safari', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15"]
]));

// Timezone configuration with offsets

// GPU pool — realistic vendor/renderer combos per OS (used for WebGL spoofing)
const GPU_POOL = {
  windows: [
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (NVIDIA GeForce GTX 1060 6GB Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (AMD Radeon RX 6600 XT Direct3D11 vs_5_0 ps_5_0, D3D11)' },
  ],
  mac: [
    { vendor: 'Apple', renderer: 'Apple M1' },
    { vendor: 'Apple', renderer: 'Apple M1 Pro' },
    { vendor: 'Apple', renderer: 'Apple M2' },
    { vendor: 'Apple', renderer: 'Apple M3' },
    { vendor: 'Intel Inc.', renderer: 'Intel(R) UHD Graphics 630' },
    { vendor: 'Intel Inc.', renderer: 'Intel(R) Iris(TM) Plus Graphics 655' },
    { vendor: 'Intel Inc.', renderer: 'Intel(R) Iris(TM) Plus Graphics' },
  ],
  linux: [
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (Intel(R) UHD Graphics 630, Mesa 23.2.1, OpenGL 4.6)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (Intel(R) UHD Graphics 770, Mesa 24.0.3, OpenGL 4.6)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (NVIDIA GeForce GTX 1080, NVIDIA 535.183.01, OpenGL 4.6.0)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (NVIDIA GeForce RTX 3070, NVIDIA 545.29.06, OpenGL 4.6.0)' },
    { vendor: 'Google Inc. (ANGLE)', renderer: 'ANGLE (AMD Radeon RX 580, Mesa 23.2.1, OpenGL 4.6)' },
  ]
};

/**
 * Select a GPU from the pool based on user agent string.
 * Called once per browser session so the GPU stays consistent across page loads.
 */
function selectGpuForUserAgent(userAgentString) {
  let osKey = 'windows';
  if (userAgentString && (userAgentString.includes('Macintosh') || userAgentString.includes('Mac OS X'))) osKey = 'mac';
  else if (userAgentString && (userAgentString.includes('X11; Linux') || userAgentString.includes('Ubuntu'))) osKey = 'linux';
  const pool = GPU_POOL[osKey];
  return pool[Math.floor(Math.random() * pool.length)];
}
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
 * When domain is provided, values are deterministic per-domain (consistent across reloads)
 */
function generateRealisticFingerprint(userAgent, domain = '') {
  // Return cached fingerprint if same domain visited again
  if (domain) {
    const cached = _fingerprintCache.get(domain);
    if (cached) return cached;
  }

  // Use seeded random for consistency, or Math.random if no domain
  const rand = domain ? seededRandom(domain) : Math.random;

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
  const resolution = profile.resolutions[Math.floor(rand() * profile.resolutions.length)];
  
  const fingerprint = {
    deviceMemory: profile.deviceMemory[Math.floor(rand() * profile.deviceMemory.length)],
    hardwareConcurrency: profile.hardwareConcurrency[Math.floor(rand() * profile.hardwareConcurrency.length)],
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
  
  // Cache for this domain
  if (domain) _fingerprintCache.set(domain, fingerprint);

  return fingerprint;
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
    // FIX: Wrap setUserAgent in try-catch to handle race condition
    try {
      await page.setUserAgent(ua);
    } catch (uaErr) {
      if (forceDebug) console.log(`[debug] Could not set user agent - page closed: ${currentUrl}`);
      return;
    }
    
    if (forceDebug) console.log(`[debug] Applying stealth protection for ${currentUrl}`);
    
    try {
      // Select GPU once per session — stays consistent across all page loads
      const selectedGpu = selectGpuForUserAgent(ua);
      if (forceDebug) console.log(`[debug] Selected GPU: ${selectedGpu.vendor} / ${selectedGpu.renderer}`);

      await page.evaluateOnNewDocument((userAgent, debugEnabled, gpuConfig) => {
      
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
              /^[a-zA-Z0-9_$]+\.[a-zA-Z0-9_$]+.*is not a function/i,
              /Failed to load resource/i,
              /is not defined/i,
              /is not a function/i
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

        // Function.prototype.toString protection — make spoofed functions appear native
        // Must be installed BEFORE any property overrides so all spoofs are protected
        const nativeFunctionStore = new WeakMap();
        const originalToString = Function.prototype.toString;
        
        function maskAsNative(fn, nativeName) {
          if (typeof fn === 'function') {
            nativeFunctionStore.set(fn, nativeName || fn.name || '');
          }
          return fn;
        }
        
        Function.prototype.toString = function() {
          if (nativeFunctionStore.has(this)) {
            return `function ${nativeFunctionStore.get(this)}() { [native code] }`;
          }
          return originalToString.call(this);
        };
        // Protect the toString override itself
        nativeFunctionStore.set(Function.prototype.toString, 'toString');
        
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
          // In real Chrome, webdriver lives on Navigator.prototype, not the instance.
          // Override it there so Object.getOwnPropertyDescriptor(navigator, 'webdriver') returns undefined.
          try { delete navigator.webdriver; } catch (e) {}
          Object.defineProperty(Navigator.prototype, 'webdriver', {
            get: () => false,
            configurable: true,
            enumerable: true
          });
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
            window.chrome = {};
          }
          
          // Add runtime if missing — headless Chrome has chrome object but no runtime
          if (!window.chrome.runtime) {
            window.chrome.runtime = {
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
                version: "145.0.0.0",
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
            };
            Object.defineProperty(window.chrome.runtime, 'toString', {
              value: () => '[object Object]'
            });
          }
          
          // Add app if missing
          if (!window.chrome.app) {
            window.chrome.app = {
              isInstalled: false,
              InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
              RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
              getDetails: () => null,
              getIsInstalled: () => false
            };
          }

          // Add storage if missing
          if (!window.chrome.storage) {
            window.chrome.storage = {
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
            };
          }
          
          // Add loadTimes/csi if missing
          if (!window.chrome.loadTimes) {
            window.chrome.loadTimes = () => {
              const now = performance.now();
              return {
                commitLoadTime: now - Math.random() * 1000,
                connectionInfo: 'http/1.1',
                finishDocumentLoadTime: now - Math.random() * 500,
                finishLoadTime: now - Math.random() * 100,
                navigationType: 'Navigation'
              };
            };
          }
          if (!window.chrome.csi) {
            window.chrome.csi = () => ({
              onloadT: Date.now(),
              pageT: Math.random() * 1000,
              startE: Date.now() - Math.random() * 2000
            });
          }

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
          // Create proper PluginArray-like object with required methods
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

          // PluginArray methods that bot detectors check for
          pluginsArray.item = function(i) { return plugins[i] || null; };
          pluginsArray.namedItem = function(name) { return plugins.find(p => p.name === name) || null; };
          pluginsArray.refresh = function() {};
          pluginsArray[Symbol.iterator] = function*() { for (const p of plugins) yield p; };
          pluginsArray[Symbol.toStringTag] = 'PluginArray';

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

        // navigator.userAgentData — Chrome's Client Hints JS API
        // Detection scripts check this; headless may have it missing or inconsistent
        safeExecute(() => {
          if (!userAgent.includes('Chrome/')) return; // Only for Chrome UAs

          const chromeMatch = userAgent.match(/Chrome\/(\d+)/);
          const majorVersion = chromeMatch ? chromeMatch[1] : '145';

          let platform = 'Windows';
          let platformVersion = '15.0.0';
          let architecture = 'x86';
          let model = '';
          let bitness = '64';
          if (userAgent.includes('Macintosh') || userAgent.includes('Mac OS X')) {
            platform = 'macOS';
            platformVersion = '13.5.0';
            architecture = 'arm';
          } else if (userAgent.includes('X11; Linux')) {
            platform = 'Linux';
            platformVersion = '6.5.0';
            architecture = 'x86';
          }

          const brands = [
            { brand: 'Not:A-Brand', version: '99' },
            { brand: 'Google Chrome', version: majorVersion },
            { brand: 'Chromium', version: majorVersion }
          ];

          const uaData = {
            brands: brands,
            mobile: false,
            platform: platform,
            getHighEntropyValues: function(hints) {
              const result = {
                brands: brands,
                mobile: false,
                platform: platform,
                architecture: architecture,
                bitness: bitness,
                model: model,
                platformVersion: platformVersion,
                fullVersionList: [
                  { brand: 'Not:A-Brand', version: '99.0.0.0' },
                  { brand: 'Google Chrome', version: majorVersion + '.0.7632.160' },
                  { brand: 'Chromium', version: majorVersion + '.0.7632.160' }
                ]
              };
              // Only return requested hints
              const filtered = {};
              for (const hint of hints) {
                if (result.hasOwnProperty(hint)) filtered[hint] = result[hint];
              }
              return Promise.resolve(filtered);
            },
            toJSON: function() {
              return { brands: brands, mobile: false, platform: platform };
            }
          };
          Object.defineProperty(navigator, 'userAgentData', {
            get: () => uaData,
            configurable: true
          });
        }, 'navigator.userAgentData spoofing');

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
          const spoofedCores = [4, 6, 8, 12][Math.floor(Math.random() * 4)];
          const hardwareProps = {
            hardwareConcurrency: { get: () => spoofedCores }
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
                    .replace(/.*__puppeteer_evaluation_script__.*\n?/gi, '')
                    .replace(/.*evaluateOnNewDocument.*\n?/gi, '')
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

        // GPU identity — selected once per browser session, passed from Node.js
        const GPU_VENDOR = gpuConfig.vendor;
        const GPU_RENDERER = gpuConfig.renderer;
        if (debugEnabled) console.log(`[fingerprint] GPU: ${GPU_VENDOR} / ${GPU_RENDERER}`);

        // WebGL spoofing
        //
        safeExecute(() => {
          // Enhanced WebGL fingerprinting protection
          const webglParams = {
            37445: GPU_VENDOR,                      // VENDOR
            37446: GPU_RENDERER,                    // RENDERER
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
            // Intercept getExtension to control WEBGL_debug_renderer_info
            const getExtension = WebGLRenderingContext.prototype.getExtension;
            WebGLRenderingContext.prototype.getExtension = function(name) {
              if (name === 'WEBGL_debug_renderer_info') {
                return { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 };
              }
              return getExtension.call(this, name);
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
            const getExtension2 = WebGL2RenderingContext.prototype.getExtension;
            WebGL2RenderingContext.prototype.getExtension = function(name) {
              if (name === 'WEBGL_debug_renderer_info') {
                return { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 };
              }
              return getExtension2.call(this, name);
            };
          }
        }, 'WebGL spoofing');

        // WebGL context patching — Proxy wrapper for real contexts + null-context safety
        safeExecute(() => {
          const webglSpoofParams = {
            37445: GPU_VENDOR,
            37446: GPU_RENDERER
          };
          const debugRendererExt = { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 };

          const originalGetContext = HTMLCanvasElement.prototype.getContext;
          HTMLCanvasElement.prototype.getContext = function(type, attrs) {
            const ctx = originalGetContext.call(this, type, attrs);
            if (type !== 'webgl' && type !== 'experimental-webgl' && type !== 'webgl2') return ctx;

            const noop = () => {};

            // Null context — return mock to prevent crashes
            if (ctx === null) {
              const canvasEl = this; // capture the actual canvas element
              const mock = new Proxy({}, {
                get(target, prop) {
                  if (prop === 'getShaderPrecisionFormat') return () => ({ rangeMin: 127, rangeMax: 127, precision: 23 });
                  if (prop === 'getParameter') return (p) => webglSpoofParams[p] || 0;
                  if (prop === 'getSupportedExtensions') return () => [];
                  if (prop === 'getExtension') return (name) => {
                    if (name === 'WEBGL_debug_renderer_info') return { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 };
                    return null;
                  };
                  if (prop === 'getContextAttributes') return () => ({
                    alpha: true, antialias: true, depth: true, failIfMajorPerformanceCaveat: false,
                    desynchronized: false, premultipliedAlpha: true, preserveDrawingBuffer: false,
                    powerPreference: 'default', stencil: false, xrCompatible: false
                  });
                  if (prop === 'isContextLost') return () => false;
                  if (prop === 'canvas') return canvasEl;
                  if (prop === 'drawingBufferWidth') return canvasEl.width || 1920;
                  if (prop === 'drawingBufferHeight') return canvasEl.height || 1080;
                  if (prop === 'drawingBufferColorSpace') return 'srgb';
                  // Identity — let prototype chain handle constructor/toString/Symbol.toStringTag
                  if (prop === 'constructor') return WebGLRenderingContext;
                  if (prop === Symbol.toStringTag) return 'WebGLRenderingContext';
                  // Common draw/state methods — return noop to prevent crashes
                  return noop;
                }
              });
              // Make mock pass instanceof checks
              if (window.WebGLRenderingContext) {
                Object.setPrototypeOf(mock, WebGLRenderingContext.prototype);
              }
              return mock;
            }

            // Real context — wrap in Proxy to intercept getParameter/getExtension
            // Direct property assignment fails silently on native WebGL objects
            return new Proxy(ctx, {
              get(target, prop, receiver) {
                if (prop === 'getParameter') {
                  return function(param) {
                    if (webglSpoofParams.hasOwnProperty(param)) return webglSpoofParams[param];
                    return target.getParameter(param);
                  };
                }
                if (prop === 'getExtension') {
                  return function(name) {
                    if (name === 'WEBGL_debug_renderer_info') return debugRendererExt;
                    return target.getExtension(name);
                  };
                }
                const val = Reflect.get(target, prop, receiver);
                return typeof val === 'function' ? val.bind(target) : val;
              }
            });
          };
        }, 'WebGL context patching');        // Permissions API spoofing
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

        // Window dimensions — headless Chrome reports 0 for outer dimensions
        safeExecute(() => {
          if (!window.outerWidth || window.outerWidth === 0 || window.outerWidth === window.innerWidth) {
            Object.defineProperty(window, 'outerWidth', { get: () => window.innerWidth + 16, configurable: true });
          }
          if (!window.outerHeight || window.outerHeight === 0 || window.outerHeight === window.innerHeight) {
            Object.defineProperty(window, 'outerHeight', { get: () => window.innerHeight + 88, configurable: true });
          }
          if (window.screenX === 0 && window.screenY === 0) {
            const sX = Math.floor(Math.random() * 200);
            const sY = Math.floor(Math.random() * 50) + 20;
            Object.defineProperty(window, 'screenX', { get: () => sX });
            Object.defineProperty(window, 'screenY', { get: () => sY });
          }
        }, 'window dimension spoofing');

        // navigator.connection — missing or incomplete in headless
        safeExecute(() => {
          if (!navigator.connection) {
            Object.defineProperty(navigator, 'connection', {
              get: () => ({
                effectiveType: '4g',
                rtt: 50,
                downlink: 10,
                saveData: false,
                type: 'wifi',
                addEventListener: () => {},
                removeEventListener: () => {}
              })
            });
          }
        }, 'connection API spoofing');

        // navigator.pdfViewerEnabled — missing in headless, true in real Chrome
        safeExecute(() => {
          if (navigator.pdfViewerEnabled === undefined) {
            Object.defineProperty(navigator, 'pdfViewerEnabled', {
              get: () => true, configurable: true
            });
          }
        }, 'pdfViewerEnabled spoofing');

        // speechSynthesis — headless returns empty voices array
        safeExecute(() => {
          if (window.speechSynthesis) {
            const origGetVoices = speechSynthesis.getVoices.bind(speechSynthesis);
            speechSynthesis.getVoices = function() {
              const voices = origGetVoices();
              if (voices.length === 0) {
                return [{
                  default: true, lang: 'en-US', localService: true,
                  name: 'Microsoft David - English (United States)', voiceURI: 'Microsoft David - English (United States)'
                }, {
                  default: false, lang: 'en-US', localService: true,
                  name: 'Microsoft Zira - English (United States)', voiceURI: 'Microsoft Zira - English (United States)'
                }];
              }
              return voices;
            };
          }
        }, 'speechSynthesis spoofing');

        // AudioContext — headless has distinct audio processing fingerprint
        safeExecute(() => {
          if (window.AudioContext || window.webkitAudioContext) {
            const OrigAudioContext = window.AudioContext || window.webkitAudioContext;
            const origCreateOscillator = OrigAudioContext.prototype.createOscillator;
            const origCreateDynamicsCompressor = OrigAudioContext.prototype.createDynamicsCompressor;
            
            // Inject deterministic noise into audio output — consistent per session
            const audioNoiseSeed = Math.random() * 0.01 - 0.005;
            const compNoiseSeed = Math.random() * 0.1 - 0.05;
            
            OrigAudioContext.prototype.createOscillator = function() {
              const osc = origCreateOscillator.call(this);
              const origFreq = osc.frequency.value;
              osc.frequency.value = origFreq + audioNoiseSeed;
              return osc;
            };
            OrigAudioContext.prototype.createDynamicsCompressor = function() {
              const comp = origCreateDynamicsCompressor.call(this);
              const origThreshold = comp.threshold.value;
              comp.threshold.value = origThreshold + compNoiseSeed;
              return comp;
            };
          }
        }, 'AudioContext fingerprint spoofing');

        // Broken image dimensions — headless returns 0x0, real browsers show broken icon
        safeExecute(() => {
          // Patch Image constructor to intercept broken image detection
          const OrigImage = window.Image;
          window.Image = function(w, h) {
            const img = arguments.length ? new OrigImage(w, h) : new OrigImage();
            // After load attempt, if broken, fake dimensions
            const origWidthDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'width');
            const origHeightDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'height');
            
            // Monitor for broken state
            img.addEventListener('error', function() {
              // Force non-zero dimensions for broken images
              Object.defineProperty(this, 'width', { get: () => 24, configurable: true });
              Object.defineProperty(this, 'height', { get: () => 24, configurable: true });
              Object.defineProperty(this, 'naturalWidth', { get: () => 24, configurable: true });
              Object.defineProperty(this, 'naturalHeight', { get: () => 24, configurable: true });
            });
            return img;
          };
          window.Image.prototype = OrigImage.prototype;
          Object.defineProperty(window, 'Image', { writable: true, configurable: true });
        }, 'broken image dimension spoofing');
        
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
        // CSS media query — pass through normally. Screen dimensions are already spoofed
        // so matchMedia results will naturally reflect the spoofed values.
        // No modification needed here.

        // Enhanced WebRTC Spoofing
        //
        safeExecute(() => {
          if (window.RTCPeerConnection) {
            const OriginalRTC = window.RTCPeerConnection;
            window.RTCPeerConnection = function(...args) {
              const pc = new OriginalRTC(...args);
              
              // Intercept onicecandidate to strip local IP addresses
              const origAddEventListener = pc.addEventListener.bind(pc);
              pc.addEventListener = function(type, listener, ...rest) {
                if (type === 'icecandidate') {
                  const wrappedListener = function(event) {
                    if (event.candidate && event.candidate.candidate) {
                      // Strip candidates containing local/private IPs
                      const c = event.candidate.candidate;
                      if (c.includes('.local') || /(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\./.test(c)) {
                        return; // suppress local IP candidates
                      }
                    }
                    listener.call(this, event);
                  };
                  return origAddEventListener(type, wrappedListener, ...rest);
                }
                return origAddEventListener(type, listener, ...rest);
              };
              
              // Also intercept the property-based handler
              let _onicecandidateHandler = null;
              Object.defineProperty(pc, 'onicecandidate', {
                get: () => _onicecandidateHandler,
                set: (handler) => {
                  _onicecandidateHandler = handler;
                  // No-op — the addEventListener wrapper above handles filtering
                },
                configurable: true
              });
              
              return pc;
            };
            Object.setPrototypeOf(window.RTCPeerConnection, OriginalRTC);
            window.RTCPeerConnection.prototype = OriginalRTC.prototype;
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
            // Deterministic slight noise to text measurements
            const originalWidth = result.width;
            const hash = text.length * 7 + (text.charCodeAt(0) || 0);
            const noise = ((hash * 2654435761 >>> 0) % 100 - 50) / 500; // -0.1 to +0.1, deterministic per text
            return Object.create(result, {
              width: { get: () => originalWidth + noise }
            });
          };

          // Override font detection methods
          //
          const originalOffsetWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
          const originalOffsetHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight');
          
          if (originalOffsetWidth && originalOffsetHeight) {
            Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
              get: function() {
                if (this.style && this.style.fontFamily) {
                  const w = originalOffsetWidth.get.call(this);
                  // Deterministic per font family — same font always gets same offset
                  const fontHash = this.style.fontFamily.split('').reduce((a, c) => (a * 31 + c.charCodeAt(0)) & 0xffff, 0);
                  return Math.floor(w + ((fontHash % 3) - 1));
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
          // Per-session seed — consistent within session, varies between sessions
          const canvasSeed = Math.floor(Math.random() * 2147483647);
          
          // Simple seeded PRNG — deterministic for same input
          function seededNoise(seed) {
            let s = seed ^ 0x5DEECE66D;
            s = (s * 1103515245 + 12345) & 0x7fffffff;
            return s;
          }

          const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
          CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh) {
            const imageData = originalGetImageData.call(this, sx, sy, sw, sh);
            if (imageData.data.length > 2000000) return imageData;
            // Deterministic noise — same canvas content + position = same noise every call
            for (let i = 0; i < imageData.data.length; i += 4) {
              const n = seededNoise(canvasSeed ^ (i >> 2));
              if ((n & 0xf) < 2) { // ~12.5% of pixels
                const shift = (n >> 4 & 3) - 1; // -1, 0, or +1
                imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + shift));
                imageData.data[i + 1] = Math.max(0, Math.min(255, imageData.data[i + 1] + shift));
              }
            }
            return imageData;
          };

          const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
          HTMLCanvasElement.prototype.toDataURL = function(...args) {
            // Apply same deterministic noise by reading through spoofed getImageData
            try {
              const ctx = this.getContext('2d');
              if (ctx && this.width > 0 && this.height > 0 && this.width * this.height < 500000) {
                const imageData = ctx.getImageData(0, 0, this.width, this.height);
                ctx.putImageData(imageData, 0, 0);
              }
            } catch (e) {} // WebGL or other context — skip
            return originalToDataURL.apply(this, args);
          };

          const originalToBlob = HTMLCanvasElement.prototype.toBlob;
          if (originalToBlob) {
            HTMLCanvasElement.prototype.toBlob = function(callback, ...args) {
              try {
                const ctx = this.getContext('2d');
                if (ctx && this.width > 0 && this.height > 0 && this.width * this.height < 500000) {
                  const imageData = ctx.getImageData(0, 0, this.width, this.height);
                  ctx.putImageData(imageData, 0, 0);
                }
              } catch (e) {}
              return originalToBlob.call(this, callback, ...args);
            };
          }
        }, 'canvas fingerprinting protection');

        // Battery API spoofing
        //
        safeExecute(() => {
          if (navigator.getBattery) {
            const batteryState = {
              charging: Math.random() > 0.5,
              chargingTime: Math.random() > 0.5 ? Infinity : Math.floor(Math.random() * 3600),
              dischargingTime: Math.floor(Math.random() * 7200),
              level: Math.round((Math.random() * 0.7 + 0.25) * 100) / 100,
              addEventListener: () => {},
              removeEventListener: () => {},
              dispatchEvent: () => true
            };
            navigator.getBattery = function() {
              return Promise.resolve(batteryState);
            };
          }
        }, 'battery API spoofing');

        // Enhanced Mouse/Pointer Spoofing
        //
        safeExecute(() => {
          // Spoof pointer capabilities
          const spoofedTouchPoints = Math.random() > 0.7 ? 0 : Math.floor(Math.random() * 5) + 1;
          if (navigator.maxTouchPoints !== undefined) {
            safeDefinePropertyLocal(navigator, 'maxTouchPoints', { 
              get: () => spoofedTouchPoints
            });
          }
          
          // Spoof mouse timing patterns to prevent behavioral fingerprinting
          const listenerMap = new WeakMap();
          const originalAddEventListener = EventTarget.prototype.addEventListener;
          const originalRemoveEventListener = EventTarget.prototype.removeEventListener;
          EventTarget.prototype.addEventListener = function(type, listener, options) {
            if (type === 'mousemove' && typeof listener === 'function') {
              const wrappedListener = function(event) {
                // Add slight timing variation to prevent pattern detection
                const delay = Math.random() * 2; // 0-2ms variation
                setTimeout(() => listener.call(this, event), delay);
              };
              listenerMap.set(listener, wrappedListener);
              return originalAddEventListener.call(this, type, wrappedListener, options);
            }
            return originalAddEventListener.call(this, type, listener, options);
          };
          EventTarget.prototype.removeEventListener = function(type, listener, options) {
            if (type === 'mousemove' && typeof listener === 'function') {
              const wrapped = listenerMap.get(listener);
              if (wrapped) {
                listenerMap.delete(listener);
                return originalRemoveEventListener.call(this, type, wrapped, options);
              }
            }
            return originalRemoveEventListener.call(this, type, listener, options);
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

        // Bulk-mask all spoofed prototype methods so toString() returns "[native code]"
        // Must run AFTER all overrides are applied
        safeExecute(() => {
          const protoMasks = [
            [WebGLRenderingContext.prototype, ['getParameter', 'getExtension', 'getSupportedExtensions']],
            [HTMLCanvasElement.prototype, ['getContext', 'toDataURL', 'toBlob']],
            [CanvasRenderingContext2D.prototype, ['getImageData', 'fillText', 'strokeText', 'measureText']],
            [EventTarget.prototype, ['addEventListener', 'removeEventListener']],
            [Date.prototype, ['getTimezoneOffset']],
          ];
          if (typeof WebGL2RenderingContext !== 'undefined') {
            protoMasks.push([WebGL2RenderingContext.prototype, ['getParameter', 'getExtension']]);
          }
          protoMasks.forEach(([proto, methods]) => {
            methods.forEach(name => {
              if (typeof proto[name] === 'function') maskAsNative(proto[name], name);
            });
          });

          // Mask navigator/window method overrides
          if (typeof navigator.permissions?.query === 'function') maskAsNative(navigator.permissions.query, 'query');
          if (typeof navigator.getBattery === 'function') maskAsNative(navigator.getBattery, 'getBattery');
          if (typeof speechSynthesis?.getVoices === 'function') maskAsNative(speechSynthesis.getVoices, 'getVoices');
          if (typeof performance.now === 'function') maskAsNative(performance.now, 'now');
          if (typeof Notification?.requestPermission === 'function') maskAsNative(Notification.requestPermission, 'requestPermission');
          if (typeof window.RTCPeerConnection === 'function') maskAsNative(window.RTCPeerConnection, 'RTCPeerConnection');
          if (typeof window.Image === 'function') maskAsNative(window.Image, 'Image');
          if (typeof window.fetch === 'function') maskAsNative(window.fetch, 'fetch');
          if (typeof window.PointerEvent === 'function') maskAsNative(window.PointerEvent, 'PointerEvent');

          // Mask property getters on navigator
          const navProps = ['userAgentData', 'connection', 'pdfViewerEnabled', 'webdriver',
                            'hardwareConcurrency', 'deviceMemory', 'platform', 'maxTouchPoints'];
          navProps.forEach(prop => {
            // Check both instance and prototype (webdriver lives on prototype)
            const desc = Object.getOwnPropertyDescriptor(navigator, prop)
                      || Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
            if (desc?.get) maskAsNative(desc.get, 'get ' + prop);
          });

          // Mask window property getters
          ['screenX', 'screenY', 'outerWidth', 'outerHeight'].forEach(prop => {
            const desc = Object.getOwnPropertyDescriptor(window, prop);
            if (desc?.get) maskAsNative(desc.get, 'get ' + prop);
          });

          if (debugEnabled) console.log('[fingerprint] toString protection applied to all spoofed functions');
        }, 'Function.prototype.toString bulk masking');

      }, ua, forceDebug, selectedGpu);
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

      const originalUA = navigator.userAgent;
      if (originalUA && !originalUA.includes('Brave')) {
        Object.defineProperty(navigator, 'userAgent', {
          get: () => originalUA.replace('Chrome/', 'Brave/').replace('Safari/537.36', 'Safari/537.36 Brave/1.60'),
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

  // FIX: Wrap page.evaluate in try-catch to handle race condition 
  let currentUserAgent;
  try {
    currentUserAgent = await page.evaluate(() => navigator.userAgent);
  } catch (evalErr) {
    if (forceDebug) console.log(`[debug] Could not get user agent - page closed: ${currentUrl}`);
    return;
  }
  
  // Extract root domain for consistent per-site fingerprinting
  let siteDomain = '';
  try { siteDomain = new URL(currentUrl).hostname; } catch (_) {}

  const spoof = fingerprintSetting === 'random' ? generateRealisticFingerprint(currentUserAgent, siteDomain) : {
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

      const connectionInfo = {
        effectiveType: ['slow-2g', '2g', '3g', '4g'][Math.floor(Math.random() * 4)],
        type: Math.random() > 0.5 ? 'cellular' : 'wifi',
        saveData: Math.random() > 0.8,
        downlink: 1.5 + Math.random() * 8,
        rtt: 50 + Math.random() * 200
      };

      // Connection type spoofing
      safeDefinePropertyLocal(navigator, 'connection', {
        get: () => connectionInfo
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
        
        let moveTimeout;
        function scheduleMove() {
          moveTimeout = setTimeout(() => {
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
            scheduleMove();
          }, 50 + Math.random() * 100);
        }
        scheduleMove();
        
        // Stop after 45 seconds with gradual slowdown
        setTimeout(() => {
          try { 
            clearTimeout(moveTimeout);
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
  DEFAULT_PLATFORM,
  DEFAULT_TIMEZONE
};
