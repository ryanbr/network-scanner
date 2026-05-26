// === Enhanced Fingerprint Protection Module - Puppeteer 23.x Compatible ===
// This module handles advanced browser fingerprint spoofing, user agent changes,
// and comprehensive bot detection evasion techniques.
//const { applyErrorSuppression } = require('./error-suppression');

const { formatLogMessage } = require('./colorize');

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
const FINGERPRINT_CACHE_MAX = 500;

// User agent collections with latest versions
const USER_AGENT_COLLECTIONS = Object.freeze(new Map([
  ['chrome', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"],
  ['chrome_mac', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"],
  ['chrome_linux', "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"],
  ['firefox', "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"],
  ['firefox_mac', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0"],
  ['firefox_linux', "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"],
  ['safari', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15"]
]));

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
 * Select a GPU from the pool based on user agent string. When `domain` is
 * provided, selection is deterministic per-domain (seeded) -- a tracker
 * logging UNMASKED_RENDERER_WEBGL sees the SAME machine across reloads of
 * the same site. Without `domain`, falls back to Math.random for ad-hoc
 * callers. Matches the same per-domain consistency that
 * generateRealisticFingerprint uses for the rest of the spoof set.
 */
function selectGpuForUserAgent(userAgentString, domain = '') {
  let osKey = 'windows';
  if (userAgentString && (userAgentString.includes('Macintosh') || userAgentString.includes('Mac OS X'))) osKey = 'mac';
  else if (userAgentString && (userAgentString.includes('X11; Linux') || userAgentString.includes('Ubuntu'))) osKey = 'linux';
  const pool = GPU_POOL[osKey];
  // Distinct seed suffix so the GPU pick doesn't collide with the
  // fingerprint generator's advance sequence for the same domain.
  const rand = domain ? seededRandom(domain + ':gpu') : Math.random;
  return pool[Math.floor(rand() * pool.length)];
}

/**
 * One-shot "is this browser dead?" guard. Three of the four spoof entry
 * points (applyUserAgentSpoofing, applyBraveSpoofing,
 * applyFingerprintProtection) had this exact try/catch block inline:
 *
 *   try {
 *     if (!page.browser().connected || page.isClosed()) return;
 *     if (page.browser().process()?.killed) return;
 *   } catch { return; }
 *
 * Three copies meant any Puppeteer API change (like the v25
 * isConnected -> connected swap) needed three fixes. Now one.
 *
 * simulateHumanBehavior is NOT migrated here -- it has different debug
 * log messages per failure mode ("page closed" vs "browser
 * disconnected") that this helper doesn't preserve. Could plumb a
 * callback for the log but the existing inline form is fine for one
 * caller.
 */
function isBrowserDead(page) {
  try {
    if (!page || page.isClosed()) return true;
    const browser = page.browser();
    if (!browser.connected) return true;
    if (browser.process()?.killed) return true;
    return false;
  } catch {
    return true; // any failure reading browser state -> treat as dead
  }
}

/**
 * Checks if an error is a session/protocol closed error (common during page navigation)
 */
function isSessionClosedError(err) {
  const msg = err.message;
  return msg.includes('Session closed') ||
    msg.includes('addScriptToEvaluateOnNewDocument timed out') ||
    msg.includes('Target closed') ||
    msg.includes('Protocol error') || err.name === 'ProtocolError' ||
    msg.includes('detached Frame') || msg.includes('Navigating frame was detached') ||
    msg.includes('Cannot find context') ||
    msg.includes('Execution context was destroyed');
}

/**
 * Generates randomized but realistic browser fingerprint values.
 * When domain is provided, values are deterministic per-(domain, userAgent)
 * tuple -- consistent across reloads, but distinct across UA rotation so
 * a re-scan with `userAgent: 'firefox'` doesn't reuse a previous
 * `userAgent: 'chrome'` cache entry (which would ship Mac/Win-platform
 * values under a Firefox UA, etc.).
 */
function generateRealisticFingerprint(userAgent, domain = '') {
  // Cache key includes UA so a domain scanned twice with different UAs
  // doesn't get the first UA's OS-mismatched fingerprint reused for the
  // second. The `|` separator can't appear in a hostname (RFC 952/RFC
  // 1123 allow only LDH) so it's collision-safe.
  const cacheKey = domain ? `${domain}|${userAgent}` : '';
  if (cacheKey) {
    const cached = _fingerprintCache.get(cacheKey);
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
  
  // Cache for this (domain, userAgent) tuple. Same key as the lookup above.
  if (cacheKey) {
    if (_fingerprintCache.size >= FINGERPRINT_CACHE_MAX) {
      _fingerprintCache.delete(_fingerprintCache.keys().next().value);
    }
    _fingerprintCache.set(cacheKey, fingerprint);
  }

  return fingerprint;
}

/**
 * Validates page state before script injection to avoid timeouts
 */
async function validatePageForInjection(page, currentUrl, forceDebug) {
  try {
    if (!page || page.isClosed()) return false;
    
    if (!page.browser().connected) {
      if (forceDebug) console.log(formatLogMessage('debug', `Page validation failed - browser disconnected: ${currentUrl}`));
      return false;
    }
    await Promise.race([
      page.evaluate(() => document.readyState || 'loading'),
      new Promise((_, reject) => {
        // unref so a still-pending race timer (page.evaluate won) doesn't
        // hold the Node event loop alive for up to 1.5s past scan exit.
        // Same pattern as the nettools timer unrefs in 83209d4 / 0c5d644;
        // closes the last known node-side unref'd setTimeout in the
        // fingerprint module.
        const t = setTimeout(() => reject(new Error('Page evaluation timeout')), 1500);
        if (typeof t.unref === 'function') t.unref();
      })
    ]);
    return true;
  } catch (validationErr) {
    if (forceDebug) console.log(formatLogMessage('debug', `Page validation failed - ${validationErr.message}: ${currentUrl}`));
    return false;
  }
}

/**
 * Enhanced user agent spoofing with stealth protection
 */
async function applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.userAgent) return;
  // Type guard: callers (including config-driven paths) might pass non-string
  // values by accident (e.g. an array, an object). Without this guard, the
  // .toLowerCase() call below would throw and crash the whole spoof
  // pipeline for this URL with no actionable error.
  if (typeof siteConfig.userAgent !== 'string') {
    if (forceDebug) console.log(formatLogMessage('debug', `Invalid userAgent type for ${currentUrl}: expected string, got ${typeof siteConfig.userAgent}`));
    return;
  }

  if (forceDebug) console.log(formatLogMessage('debug', `User agent spoofing: ${siteConfig.userAgent}`));

  if (isBrowserDead(page)) return;

  // Validate page state before injection
  if (!(await validatePageForInjection(page, currentUrl, forceDebug))) return;

  const ua = USER_AGENT_COLLECTIONS.get(siteConfig.userAgent.toLowerCase());
  
  if (ua) {
    // FIX: Wrap setUserAgent in try-catch to handle race condition
    try {
      await page.setUserAgent(ua);
    } catch (uaErr) {
      if (forceDebug) console.log(formatLogMessage('debug', `Could not set user agent - page closed: ${currentUrl}`));
      return;
    }
    
    if (forceDebug) console.log(formatLogMessage('debug', `Applying stealth protection for ${currentUrl}`));
    
    try {
      // Derive site domain once -- used to seed the per-domain GPU pick
      // (so a tracker logging UNMASKED_RENDERER_WEBGL sees one machine per
      // site) AND to pre-compute hardware-concurrency from the SAME
      // realistic-fingerprint generator that applyFingerprintProtection
      // uses. That kills the order-dependent visible-value bug: previously
      // hardwareConcurrency was random in the UA block (line 819) and
      // domain-seeded in applyFingerprintProtection -- whichever evaluate
      // ran second won. Now both paths produce the same value.
      let siteDomain = '';
      try { siteDomain = new URL(currentUrl).hostname; } catch (_) {}

      const selectedGpu = selectGpuForUserAgent(ua, siteDomain);
      if (forceDebug) console.log(formatLogMessage('debug', `Selected GPU: ${selectedGpu.vendor} / ${selectedGpu.renderer}`));

      // Pre-compute hardware-concurrency from the (cached, domain-seeded)
      // realistic fingerprint so the UA-spoof block uses the same value
      // applyFingerprintProtection will later -- no order dependency,
      // same value regardless of which evaluate runs first.
      const realistic = generateRealisticFingerprint(ua, siteDomain);

      await page.evaluateOnNewDocument((userAgent, debugEnabled, gpuConfig, seededCores) => {
      
        // Apply inline error suppression first
        (function() {
          const originalConsoleError = console.error;
          const originalWindowError = window.onerror;
          
          function shouldSuppressFingerprintError(message) {
            // Suppression list, ordered specific -> general.
            // .some() stops at first match, so a broken specific just means
            // the general catchers below do the work instead.
            //
            // Fixed (was using `\\.` / `\\d` / `\\(` / `\\$` -- DOUBLE
            // backslashes in source). Each `\\X` parses as
            // literal-backslash + wildcard-X, requiring a literal `\` in
            // the error text -- which never appears. So those entries
            // silently never matched anything; only the general catchers
            // below were actually suppressing those error families.
            // Switched to single-backslash form (literal-X escapes) so
            // each specific entry now matches its intended error class
            // for accurate debug logging of WHICH pattern matched.
            //
            // Also dropped:
            //   - /Failed to load resource.*40[34]/i -- fully subsumed by
            //     the broader /[45]\d{2}/i below.
            const patterns = [
              /\.closest is not a function/i,
              /\.querySelector is not a function/i,
              /\.addEventListener is not a function/i,
              /Cannot read propert(y|ies) of null \(reading 'fp'\)/i,
              /Cannot read propert(y|ies) of undefined \(reading 'fp'\)/i,
              /Cannot redefine property: href/i,
              /Cannot redefine property: __webdriver_script_func/i,
              /Cannot redefine property: webdriver/i,
              /Cannot read propert(y|ies) of undefined \(reading 'toLowerCase'\)/i,
              /\.toLowerCase is not a function/i,
              /fp is not defined/i,
              /fingerprint is not defined/i,
              /FingerprintJS is not defined/i,
              /\$ is not defined/i,
              /jQuery is not defined/i,
              /_ is not defined/i,
              /Failed to load resource.*server responded with a status of [45]\d{2}/i,
              /Failed to fetch/i,
              /(webdriver|callPhantom|_phantom|__nightmare|_selenium) is not defined/i,
              /Failed to execute 'observe' on 'IntersectionObserver'.*parameter 1 is not of type 'Element'/i,
              /tz check/i,
              /new window\.Error.*<anonymous>/i,
              /Blocked script execution in 'about:blank'.*sandboxed.*allow-scripts/i,
              /Page JavaScript error:/i,
              /^[a-zA-Z0-9_$]+\[.*\]\s+is not a function/i,
              /^[a-zA-Z0-9_$]+\(.*\)\s+is not a function/i,
              /^[a-zA-Z0-9_$]+\.[a-zA-Z0-9_$]+.*is not a function/i,
              // General catchers — kept last so the specific entries
              // above can match first for accurate debug attribution.
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

        // Wrapper-constructor identity preserver. Function.name and
        // Function.length are own data properties of every function
        // object, NOT inherited via prototype chain -- so even after
        // Object.setPrototypeOf(wrapper, OriginalCtor), the wrapper
        // still has its own name (empty for anonymous expressions) and
        // length (count of leading formal params). A bot detector that
        // checks `Error.name === 'Error'` would see '' on our spoof.
        //
        // Real Chrome's Function.name has descriptor
        //   {value: ..., writable: false, enumerable: false, configurable: true}
        // -- match that shape so getOwnPropertyDescriptor checks pass too.
        function preserveCtorIdentity(wrapper, original) {
          try {
            Object.defineProperty(wrapper, 'name', {
              value: original.name, writable: false, enumerable: false, configurable: true
            });
            Object.defineProperty(wrapper, 'length', {
              value: original.length, writable: false, enumerable: false, configurable: true
            });
          } catch (e) {
            if (debugEnabled) console.log(`[fingerprint] preserveCtorIdentity failed: ${e.message}`);
          }
        }
        
        Function.prototype.toString = function() {
          if (nativeFunctionStore.has(this)) {
            return `function ${nativeFunctionStore.get(this)}() { [native code] }`;
          }
          return originalToString.call(this);
        };
        // Protect the toString override itself
        nativeFunctionStore.set(Function.prototype.toString, 'toString');
        
        // Create safe property definition helper.
        // configurable: true is a DEFAULT (not a force) -- if a caller
        // wants to lock a property (configurable: false) the spread won't
        // override their explicit value. Previously `{ ...descriptor,
        // configurable: true }` silently overrode any caller intent.
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
              configurable: true,
              ...descriptor
            });
            return true;
          } catch (err) {
            if (debugEnabled) console.log(`[fingerprint] Failed to define ${property}: ${err.message}`);
            return false;
          }
        }

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

          // Belt-and-suspenders: some older Chromium-driver setups leave a
          // `webdriver` attribute on the <html> element (different surface
          // from navigator.webdriver). DataDome and similar detectors
          // check both. Modern Puppeteer with ignoreDefaultArgs:
          // ['--enable-automation'] (set in nwss.js's createBrowser) doesn't
          // emit this attribute, so this is defensive against rare edge
          // cases. documentElement should exist by evaluateOnNewDocument
          // time; wrapped in optional-chaining + try/catch for the contexts
          // where it doesn't.
          try {
            if (document?.documentElement?.hasAttribute('webdriver')) {
              document.documentElement.removeAttribute('webdriver');
            }
          } catch (_) {}
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
          
          // Just delete -- DO NOT re-add as undefined-returning getters.
          // The previous version did:
          //   delete window[prop];
          //   safeDefinePropertyLocal(window, prop, { get: () => undefined });
          // which made `window.callPhantom` return undefined (good) but ALSO
          // made `'callPhantom' in window` return TRUE (bad) -- the property
          // exists on the object even if the getter returns undefined. Real
          // Chrome doesn't have these props at all, so `in`-operator and
          // Object.getOwnPropertyNames probes saw a present property and
          // flagged us as a bot. This own-goal was caught by
          // scripts/test-stealth.js sannysoft (PHANTOM_PROPERTIES and
          // SELENIUM_DRIVER cells went red because of it).
          automationProps.forEach(prop => {
            try { delete window[prop]; } catch (e) {}
            try { delete navigator[prop]; } catch (e) {}
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
              getManifest: () => {
                // Derive Chrome version from the spoofed UA so a tracker
                // cross-checking navigator.userAgent's Chrome version
                // against chrome.runtime.getManifest().version sees a
                // consistent number. Was hardcoded "146.0.0.0" which lied
                // any time the UA was rotated to a different Chrome major.
                const m = userAgent.match(/Chrome\/(\d+)/);
                const major = m ? m[1] : '146';
                return {
                  name: "Chrome",
                  version: `${major}.0.0.0`,
                  manifest_version: 3,
                  description: "Chrome Browser"
                };
              },
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

          // The old comment claimed "non-enumerable to match real Chrome" --
          // but real Chrome's window.chrome property descriptor is
          // {value: ..., writable: true, enumerable: true, configurable: true}.
          // The previous writable:false + enumerable:false were themselves
          // fingerprintable tells: a bot detector reading
          //   Object.getOwnPropertyDescriptor(window, 'chrome')
          // would see {writable:false, enumerable:false} and know this
          // isn't real Chrome. `window.chrome = 'x'` would also silently
          // fail (vs succeed on real Chrome). Match real Chrome's
          // descriptor instead. The defineProperty is kept (rather than
          // removed entirely) so re-injection on reload doesn't lose the
          // descriptor shape if anything earlier tightened it.
          Object.defineProperty(window, 'chrome', {
            value: window.chrome,
            writable: true,
            enumerable: true,
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
          // Each plugin object needs to identify as a Plugin instance so
          // `navigator.plugins[i].toString() === '[object Plugin]'` passes.
          // (Sannysoft's actual PluginArray check tests this -- found via
          // scripts/test-stealth.js sannysoft.) Resolve Plugin.prototype the
          // same way we resolve PluginArray.prototype below: prefer the
          // global, fall back to navigator.plugins[0]'s prototype if a real
          // plugin exists, fall back to just Symbol.toStringTag if neither.
          let pluginProto = null;
          try {
            if (typeof Plugin !== 'undefined' && Plugin.prototype) {
              pluginProto = Plugin.prototype;
            } else if (navigator.plugins && navigator.plugins[0]) {
              pluginProto = Object.getPrototypeOf(navigator.plugins[0]);
            }
          } catch (e) {}
          plugins = plugins.map(p => {
            const wrapped = Object.assign(Object.create(pluginProto || Object.prototype), p);
            if (!pluginProto) {
              // Last-ditch: at least toString() returns "[object Plugin]"
              wrapped[Symbol.toStringTag] = 'Plugin';
            }
            return wrapped;
          });

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

          // Make `navigator.plugins instanceof PluginArray` evaluate true.
          // Multiple ways to get PluginArray.prototype, in order of
          // preference -- evaluateOnNewDocument can fire before all globals
          // are bound, so we don't assume `PluginArray` is in scope. Falls
          // back to inheriting from the existing navigator.plugins's own
          // prototype, which is ALWAYS a real PluginArray.prototype on
          // any DOM-bearing context.
          try {
            let pluginArrayProto = null;
            if (typeof PluginArray !== 'undefined' && PluginArray.prototype) {
              pluginArrayProto = PluginArray.prototype;
            } else if (navigator.plugins) {
              pluginArrayProto = Object.getPrototypeOf(navigator.plugins);
            }
            if (pluginArrayProto && pluginArrayProto !== Object.prototype) {
              Object.setPrototypeOf(pluginsArray, pluginArrayProto);
            }
          } catch (e) {
            if (debugEnabled) console.log(`[fingerprint] PluginArray prototype setup failed: ${e.message}`);
          }

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
          // productSub is a legacy Mozilla-era property: '20030107' for
          // every browser EXCEPT Firefox (which uses '20100101'). Real
          // Chrome / Safari / etc. all report '20030107'. Real Firefox
          // reports '20100101'. Common bot-detection signal because
          // anti-detection libraries often spoof UA but forget this.
          // vendorSub is always '' across all browsers (legacy/unused).
          let productSub = '20030107';
          const vendorSub = '';

          if (userAgent.includes('Firefox')) {
            vendor = '';
            productSub = '20100101';
          } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
            vendor = 'Apple Computer, Inc.';
          }

          const vendorProps = {
            vendor: { get: () => vendor },
            product: { get: () => product },
            productSub: { get: () => productSub },
            vendorSub: { get: () => vendorSub }
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

        // Hardware concurrency spoofing (universal coverage).
        // Uses the domain-seeded value passed in from the Node-side
        // generateRealisticFingerprint call -- previously did its own
        // Math.random() pick from [4,6,8,12], which conflicted with the
        // domain-seeded value set later by applyFingerprintProtection.
        // Whichever evaluate ran second won, producing an order-dependent
        // visible value. Now both paths use the same seeded value, so
        // double-spoof becomes idempotent.
        safeExecute(() => {
          const hardwareProps = {
            hardwareConcurrency: { get: () => seededCores }
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
          preserveCtorIdentity(window.Error, OriginalError);
          
          // Forward static properties via getter/setter pairs instead of
          // value-copy, so live mutations to OriginalError (e.g. page
          // code doing `Error.stackTraceLimit = 100`) propagate through
          // the wrapper. Previously the value-copy froze a snapshot at
          // injection time; a tracker that mutated stackTraceLimit and
          // then read it back from the wrapped Error would see the old
          // value -- a real fingerprint tell.
          ['captureStackTrace', 'stackTraceLimit', 'prepareStackTrace'].forEach(prop => {
            try {
              Object.defineProperty(window.Error, prop, {
                get: () => OriginalError[prop],
                set: (v) => { OriginalError[prop] = v; },
                configurable: true,
                enumerable: false
              });
            } catch (e) {}
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

          // Notification.permission STATIC PROPERTY — distinct from the
          // requestPermission() method patched above. DataDome and similar
          // detectors read Notification.permission directly. Real Chrome
          // with no granted permission returns 'default'; headless Chrome
          // returns 'denied'. Without this override the prior block (which
          // only patched the method) leaves the static property as a live
          // headless tell. Wrapped in try/catch because some embedded
          // contexts make Notification non-configurable.
          if (window.Notification) {
            try {
              Object.defineProperty(Notification, 'permission', {
                get: () => 'default',
                configurable: true
              });
            } catch (_) {}
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
            // screenLeft / screenTop are the legacy IE-era aliases for
            // screenX / screenY; real Chrome exposes them as identical
            // values. Headless / spoofers often leave them undefined or 0,
            // which is a tell since the screenX/Y patch above changed
            // those values to be non-zero. Mirror them explicitly so the
            // four properties stay consistent.
            Object.defineProperty(window, 'screenLeft', { get: () => sX });
            Object.defineProperty(window, 'screenTop', { get: () => sY });
          }
        }, 'window dimension spoofing');

        // Modern Chrome API stubs — these APIs exist in real desktop
        // Chrome but may be missing or wrong in headless. Detectors check
        // presence + minimal shape as a 'real browser?' signal. Each one
        // is wrapped individually so a failure on one doesn't break the
        // others, and the existence checks let real-Chrome paths
        // (where the property already exists with the right value) skip
        // the override entirely.
        safeExecute(() => {
          // Document.hasStorageAccess() — Storage Access API. Real Chrome
          // returns a Promise<boolean>; resolve with true to mimic the
          // common 'storage already accessible (top-level context)' state.
          if (document && typeof document.hasStorageAccess !== 'function') {
            try {
              Object.defineProperty(document, 'hasStorageAccess', {
                value: () => Promise.resolve(true),
                configurable: true,
                writable: true
              });
            } catch (_) {}
          }
        }, 'document.hasStorageAccess stub');

        safeExecute(() => {
          // navigator.userActivation — UserActivation interface tracking
          // whether the page has had a user gesture. Real Chrome exposes
          // {hasBeenActive: bool, isActive: bool}. After interaction
          // simulation (interact / ghost-cursor) both should be true; we
          // default to true so a site checking before our synthetic
          // gestures fire still sees a 'user activated' page.
          if (navigator && !navigator.userActivation) {
            try {
              const userActivation = {
                hasBeenActive: true,
                isActive: true
              };
              Object.defineProperty(navigator, 'userActivation', {
                get: () => userActivation,
                configurable: true
              });
            } catch (_) {}
          }
        }, 'navigator.userActivation stub');

        safeExecute(() => {
          // navigator.getInstalledRelatedApps() — Chrome-specific API
          // returning installed PWAs/native apps related to the current
          // origin. Real Chrome has this as a function; absence is a tell
          // for non-Chrome / headless. Return empty array (the common
          // no-related-apps case) — same as a fresh real-Chrome profile.
          if (navigator && typeof navigator.getInstalledRelatedApps !== 'function') {
            try {
              Object.defineProperty(navigator, 'getInstalledRelatedApps', {
                value: () => Promise.resolve([]),
                configurable: true,
                writable: true
              });
            } catch (_) {}
          }
        }, 'navigator.getInstalledRelatedApps stub');

        // screen.orientation — modern browsers expose a ScreenOrientation
        // interface ({type, angle, addEventListener, lock, unlock, ...}).
        // Missing entirely in some headless contexts; presence + shape are
        // checked by DataDome and similar detectors as a "real browser"
        // signal. The values below mirror real desktop Chrome's landscape
        // primary orientation; lock()/unlock() match real-Chrome behaviour
        // when no fullscreen element is active (lock rejects with
        // NotSupportedError, unlock is a no-op). Object identity is stable
        // (hoisted out of the getter) so reference-equality checks pass.
        safeExecute(() => {
          if (!window.screen.orientation) {
            const orientation = {
              type: 'landscape-primary',
              angle: 0,
              onchange: null,
              addEventListener: () => {},
              removeEventListener: () => {},
              dispatchEvent: () => false,
              lock: () => Promise.reject(new Error('NotSupportedError')),
              unlock: () => {}
            };
            Object.defineProperty(window.screen, 'orientation', {
              get: () => orientation,
              configurable: true
            });
          }
        }, 'screen.orientation spoofing');

        // navigator.connection — missing or incomplete in headless.
        // Object literal hoisted out of the getter so identity is stable
        // across reads. Real Chrome's NetworkInformation instance has
        // `navigator.connection === navigator.connection`; previously
        // the getter returned a new object on every read, which a
        // tracker could detect by comparing references.
        //
        // Per-domain seeded values (FNV-1a hash of hostname): hardcoded
        // '4g/wifi/50/10' across every site was a cross-publisher
        // tracking axis -- a fingerprinter aggregating across N sites
        // running the same script saw identical connection values
        // everywhere, useful as a stable identity signal. Domain-seeding
        // breaks that while keeping values stable per-domain (real
        // navigator.connection IS stable per-session; per-navigation
        // randomness would be its own anomaly). Same pattern as the
        // Battery API fix in c1affe4.
        safeExecute(() => {
          if (!navigator.connection) {
            let h = 0x811c9dc5;
            const domain = (window.location && window.location.hostname) || '';
            for (let i = 0; i < domain.length; i++) {
              h = ((h ^ domain.charCodeAt(i)) * 0x01000193) >>> 0;
            }
            // 4g 75%, 3g 18%, 2g 5%, slow-2g 2% — distribution biased
            // toward modern broadband since most page loads happen there.
            const etRoll = (h >>> 4) % 100;
            const effectiveType = etRoll < 75 ? '4g'
                                : etRoll < 93 ? '3g'
                                : etRoll < 98 ? '2g'
                                : 'slow-2g';
            // rtt + downlink MUST correlate with effectiveType — the
            // W3C Network Information API defines effectiveType as a
            // CLASSIFICATION of rtt/downlink ranges, so producing
            // slow-2g with 32.5 Mbps downlink (as the prior uncorrelated
            // version did) is physically impossible in real Chrome. A
            // detector cross-checking effectiveType against rtt/downlink
            // magnitudes catches that trivially. Ranges below match the
            // spec's boundaries:
            //   slow-2g: rtt > 2000ms, downlink < 0.05 Mbps
            //   2g:      rtt > 1400ms, downlink < 0.07 Mbps
            //   3g:      rtt > 270ms,  downlink < 0.7 Mbps
            //   4g:      rtt < 270ms,  downlink >= 0.7 Mbps
            const rttRange = effectiveType === '4g'      ? [25, 250]
                           : effectiveType === '3g'      ? [275, 1400]
                           : effectiveType === '2g'      ? [1425, 2000]
                           : /* slow-2g */                 [2025, 5000];
            const dlRange  = effectiveType === '4g'      ? [1.0, 50.0]
                           : effectiveType === '3g'      ? [0.1, 0.7]
                           : effectiveType === '2g'      ? [0.05, 0.07]
                           : /* slow-2g */                 [0.01, 0.05];
            // 25ms-bucketed rtt (Chrome's privacy rounding granularity)
            const rttRaw = rttRange[0] + (((h >>> 8) % 1000) / 1000) * (rttRange[1] - rttRange[0]);
            const rtt = Math.round(rttRaw / 25) * 25;
            // 0.025-precision downlink (Chrome's privacy rounding)
            const dlRaw = dlRange[0] + (((h >>> 16) % 1000) / 1000) * (dlRange[1] - dlRange[0]);
            const downlink = Math.round(dlRaw * 40) / 40;
            // saveData ~5% — most users don't enable Data Saver
            const saveData = ((h >>> 24) & 0xff) < 13;
            // NetworkInformation extends EventTarget — real Chrome has
            // dispatchEvent in addition to add/removeEventListener.
            // Returning true per the EventTarget spec for the
            // no-listeners case (no preventDefault called).
            const connectionInfoStable = {
              effectiveType,
              rtt,
              downlink,
              saveData,
              addEventListener: () => {},
              removeEventListener: () => {},
              dispatchEvent: () => true
            };
            // NetworkInformation.type is DEPRECATED and only exposed on
            // mobile Chrome. On desktop Chrome (Windows/Mac/Linux) it's
            // not present — `'type' in navigator.connection` returns
            // false. Only include it when spoofing a mobile UA, else
            // its presence is a fingerprint tell against the desktop
            // platform our UA collection currently advertises.
            if (/Android|iPhone|iPad|iPod|Mobile/i.test(userAgent || '')) {
              connectionInfoStable.type = ((h >>> 12) % 10) < 7 ? 'wifi' : 'cellular';
            }
            Object.defineProperty(navigator, 'connection', {
              get: () => connectionInfoStable
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

        // AudioContext fingerprint spoofing — intercept the actual READ
        // surface fingerprinters care about.
        //
        // Previous spoof modified default frequency / threshold values on
        // OscillatorNode / DynamicsCompressor at create time. That was
        // essentially useless: real audio fingerprinters do
        //   const osc = ctx.createOscillator();
        //   osc.frequency.value = 1000;  // ← OVERWRITES our noise
        //   ... render ... ctx.startRendering().then(buf => hash(buf.getChannelData(0)));
        // The noise we put on the default 440 Hz was blown away the
        // moment the probe set its own value, and never affected the
        // rendered output the fingerprinter actually hashes.
        //
        // Correct attack surface: AudioBuffer.prototype.getChannelData.
        // EVERY audio fingerprinter ends up reading the rendered buffer
        // via this method (it's the only way to get Float32Array data
        // out). Wrap it at the prototype so all AudioBuffers (from
        // OfflineAudioContext.startRendering, from AudioBufferSourceNode,
        // from decodeAudioData, etc.) get the same treatment.
        //
        // Noise design:
        //   - sparse (every 100th sample) so audio remains perceptually
        //     identical if actually played
        //   - tiny magnitude (±0.00005) so the hash differs but the wave
        //     shape doesn't
        //   - deterministic per session (audioSeed) so repeated renders
        //     of the same audio produce the same noised output
        //   - per-(buffer, channel) idempotency via WeakMap: calling
        //     getChannelData(0) twice on the same buffer returns the
        //     same data (real Chrome's getChannelData returns a stable
        //     Float32Array view; double-noising on second call would be
        //     detectable)
        safeExecute(() => {
          if (typeof AudioBuffer === 'undefined' || !AudioBuffer.prototype || typeof AudioBuffer.prototype.getChannelData !== 'function') return;

          const audioSeed = Math.floor(Math.random() * 2147483647);
          const noisedChannels = new WeakMap(); // buffer -> Set<channel>

          // Shared noise function so getChannelData and copyFromChannel
          // produce noise at the SAME source-channel positions
          // (mod 100). A detector comparing a value from one method
          // against the same source position read via the other method
          // sees consistent noised values — no cross-method anomaly.
          const noiseAt = (channel, srcIdx) => {
            const n = ((audioSeed ^ srcIdx ^ (channel * 31)) * 1103515245 + 12345) & 0x7fffffff;
            return (n / 0x7fffffff) * 0.0001 - 0.00005;
          };

          const origGetChannelData = AudioBuffer.prototype.getChannelData;
          const wrappedGetChannelData = function(channel) {
            const data = origGetChannelData.call(this, channel);
            // Cap large buffers — per-sample loop on multi-MB Float32Arrays
            // is too slow. 1M samples ≈ 22.6s of 44.1kHz mono audio; way
            // beyond what fingerprinters use (typically 44k = 1s).
            if (data.length > 1000000) return data;

            let channelSet = noisedChannels.get(this);
            if (!channelSet) {
              channelSet = new Set();
              noisedChannels.set(this, channelSet);
            }
            if (!channelSet.has(channel)) {
              for (let i = 0; i < data.length; i += 100) {
                data[i] = Math.max(-1, Math.min(1, data[i] + noiseAt(channel, i)));
              }
              channelSet.add(channel);
            }
            return data;
          };
          maskAsNative(wrappedGetChannelData, 'getChannelData');
          AudioBuffer.prototype.getChannelData = wrappedGetChannelData;

          // copyFromChannel — alternative read API. Without wrapping it,
          // a fingerprinter calling `buffer.copyFromChannel(dest, 0, 0)`
          // instead of `buffer.getChannelData(0)` gets the unmodified
          // canonical Chrome data, fully bypassing our getChannelData
          // noise. Same defense logic applied here; noise aligned by
          // SOURCE channel position (startInChannel + destination
          // offset) so cross-method consistency holds.
          if (typeof AudioBuffer.prototype.copyFromChannel === 'function') {
            const origCopyFromChannel = AudioBuffer.prototype.copyFromChannel;
            const wrappedCopyFromChannel = function(destination, channelNumber, startInChannel) {
              origCopyFromChannel.call(this, destination, channelNumber, startInChannel);
              if (!destination || destination.length > 1000000) return;
              // If getChannelData has ALREADY noised this (buffer,
              // channel) in-place, origCopyFromChannel just copied the
              // already-noised data into `destination`. Adding our own
              // noise on top would produce 2× noise -- detectable via
              // cross-method consistency probes
              // (data[i] === dest[i] should hold). Skip when previously
              // noised.
              const channelSet = noisedChannels.get(this);
              if (channelSet && channelSet.has(channelNumber)) return;
              const startSrc = startInChannel || 0;
              // Align noise positions to the same mod-100 source-channel
              // grid getChannelData uses. firstNoisedSrc is the smallest
              // multiple of 100 >= startSrc; map back to destination index.
              const firstNoisedSrc = Math.ceil(startSrc / 100) * 100;
              const firstNoisedDest = firstNoisedSrc - startSrc;
              for (let destI = firstNoisedDest; destI < destination.length; destI += 100) {
                const srcIdx = startSrc + destI;
                destination[destI] = Math.max(-1, Math.min(1, destination[destI] + noiseAt(channelNumber, srcIdx)));
              }
            };
            maskAsNative(wrappedCopyFromChannel, 'copyFromChannel');
            AudioBuffer.prototype.copyFromChannel = wrappedCopyFromChannel;
          }

          // copyToChannel — page WRITES to the buffer, overwriting any
          // existing contents (including our in-place noise from a prior
          // getChannelData call). Without this wrap, the noisedChannels
          // flag remained set but the underlying data was fresh -- next
          // getChannelData would SKIP noise (channelSet.has(ch) === true)
          // and return the page's probe pattern unnoised. A fingerprinter
          // priming the buffer with a known pattern then re-reading via
          // getChannelData would see the canonical (unspoofed) values,
          // confirming our spoof isn't actually noising.
          // Fix: clear the noisedChannels flag for the written channel
          // before forwarding the write, so the next read re-noises.
          if (typeof AudioBuffer.prototype.copyToChannel === 'function') {
            const origCopyToChannel = AudioBuffer.prototype.copyToChannel;
            const wrappedCopyToChannel = function(source, channelNumber, startInChannel) {
              // Forward FIRST. If the original throws (invalid args,
              // detached buffer, etc.) the buffer is unchanged and we
              // must NOT clear the noisedChannels flag — otherwise the
              // next getChannelData would re-noise already-noised data,
              // stacking 2x noise that drifts on subsequent reads.
              const result = origCopyToChannel.call(this, source, channelNumber, startInChannel);
              const channelSet = noisedChannels.get(this);
              if (channelSet) channelSet.delete(channelNumber);
              return result;
            };
            maskAsNative(wrappedCopyToChannel, 'copyToChannel');
            AudioBuffer.prototype.copyToChannel = wrappedCopyToChannel;
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
          preserveCtorIdentity(window.Image, OrigImage);
          // (Note: the prior Object.defineProperty(window, 'Image', ...) here
          // was a no-op -- changed descriptor flags without setting value.
          // Removed; the wrapper is already assigned to window.Image above.)
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

        // CSS Media Query Spoofing — specifically the hardware-presence
        // queries that distinguish a real desktop browser from headless.
        //
        // Headless Chrome reports NO hover device and NO fine pointer
        // (there's no mouse hardware attached). matchMedia('(any-hover:
        // hover)') returns matches=false in headless, matches=true in
        // real desktop. CreepJS and DataDome both probe these queries
        // explicitly as a hard binary 'is this real browser hardware?'
        // signal — one of the biggest single contributors to CreepJS's
        // headless-detection score.
        //
        // Pass-through for all OTHER queries (max-width, prefers-color-
        // scheme, etc.) so legitimate responsive-design checks still work.
        // Screen-dimension queries naturally reflect the already-spoofed
        // screen.width/height — no extra handling needed for those.
        safeExecute(() => {
          if (typeof window.matchMedia !== 'function') return;
          const origMatchMedia = window.matchMedia;
          // Make a fake MediaQueryList that quacks like the real thing.
          // Real Chrome's MediaQueryList implements EventTarget, so the
          // listener methods need to exist as callable no-ops.
          const fakeMql = (query, matches) => ({
            matches,
            media: query,
            onchange: null,
            addEventListener: () => {},
            removeEventListener: () => {},
            addListener: () => {},      // deprecated alias but still present in Chrome
            removeListener: () => {},
            dispatchEvent: () => false
          });
          window.matchMedia = function(query) {
            const q = String(query || '').toLowerCase();
            // Spoof to "yes, mouse + hover hardware present" — the real
            // desktop answer. Match both `(any-hover: hover)` and the
            // legacy `(hover: hover)`; same for pointer.
            if (q.includes('any-hover: hover') || q.includes('hover: hover')) {
              return fakeMql(query, true);
            }
            if (q.includes('any-hover: none') || q.includes('hover: none')) {
              return fakeMql(query, false);
            }
            if (q.includes('any-pointer: fine') || q.includes('pointer: fine')) {
              return fakeMql(query, true);
            }
            if (q.includes('any-pointer: none') || q.includes('pointer: none')) {
              return fakeMql(query, false);
            }
            if (q.includes('any-pointer: coarse') || q.includes('pointer: coarse')) {
              return fakeMql(query, false);  // desktop = no coarse touch pointer
            }
            // Anything else falls through to real matchMedia (responsive
            // queries, color-scheme, reduced-motion, etc. all behave normally).
            return origMatchMedia.call(this, query);
          };
        }, 'matchMedia hover/pointer spoofing');

        // Enhanced WebRTC Spoofing
        //
        // Previously stripped only RFC1918 private IPs from ICE candidates,
        // which leaked the STUN-discovered public IP (`typ srflx`) — visible
        // in CreepJS's WebRTC section and trivially also probed by DataDome
        // and other modern fingerprint suites. STUN traffic is UDP, so it
        // bypasses the SOCKS5 proxy entirely, meaning the real host IP
        // reaches the fingerprinter regardless of proxy config.
        //
        // Fix: strip EVERY ICE candidate (host / srflx / prflx / relay /
        // mDNS). The scanner never needs functional WebRTC peer connections,
        // so complete suppression is the right trade-off — the page sees
        // ICE gathering complete with zero candidates, indistinguishable
        // from a real browser with no usable network interfaces. The
        // null-candidate sentinel (end-of-gathering signal) still fires so
        // calling code that awaits ICE-complete doesn't hang.
        safeExecute(() => {
          if (window.RTCPeerConnection) {
            const OriginalRTC = window.RTCPeerConnection;
            // Filter helper hoisted so both addEventListener and the
            // property-handler paths apply identical filtering.
            const stripCandidate = (event) => !event.candidate;

            window.RTCPeerConnection = function(...args) {
              const pc = new OriginalRTC(...args);

              const origAddEventListener = pc.addEventListener.bind(pc);
              // Named function (not anonymous) so maskAsNative gets a sensible
              // 'addEventListener' name when reporting [native code]. The
              // bulk-mask block at end of applyFingerprintProtection masks
              // window-level functions ONCE; per-instance functions created
              // inside this factory (one new closure per `new RTCPeerConnection()`)
              // would slip through unmasked — detectable via
              // pc.addEventListener.toString(). Mask each per-instance to
              // close that.
              const addEventListenerWrap = function(type, listener, ...rest) {
                if (type === 'icecandidate') {
                  const wrappedListener = function(event) {
                    if (stripCandidate(event)) listener.call(this, event);
                  };
                  return origAddEventListener(type, wrappedListener, ...rest);
                }
                return origAddEventListener(type, listener, ...rest);
              };
              maskAsNative(addEventListenerWrap, 'addEventListener');
              pc.addEventListener = addEventListenerWrap;

              // Property-based handler. Previously this just stored the
              // handler in a local variable and never wired it up — pages
              // setting `pc.onicecandidate = fn` got NO events at all,
              // detectable as a mismatch vs addEventListener (which DID
              // fire). Now we forward the wrapped handler to the underlying
              // setter so both paths behave identically: the page sees only
              // the null-candidate sentinel. Both get/set extracted to named
              // consts so maskAsNative can wrap them — without this, a probe
              // doing `Object.getOwnPropertyDescriptor(pc, 'onicecandidate').get.toString()`
              // would see the arrow-function source instead of [native code].
              let _userHandler = null;
              const getOnIceCandidate = function() { return _userHandler; };
              const setOnIceCandidate = function(handler) {
                _userHandler = handler;
                // Use the prototype setter so we don't infinite-loop on
                // our own defineProperty. The wrapped handler applies
                // the same filter as addEventListener.
                const proto = Object.getPrototypeOf(pc);
                const desc = Object.getOwnPropertyDescriptor(proto, 'onicecandidate');
                if (desc && desc.set) {
                  desc.set.call(pc, typeof handler === 'function'
                    ? function(event) { if (stripCandidate(event)) handler.call(this, event); }
                    : handler);
                }
              };
              maskAsNative(getOnIceCandidate, 'get onicecandidate');
              maskAsNative(setOnIceCandidate, 'set onicecandidate');
              Object.defineProperty(pc, 'onicecandidate', {
                get: getOnIceCandidate,
                set: setOnIceCandidate,
                configurable: true
              });

              return pc;
            };
            Object.setPrototypeOf(window.RTCPeerConnection, OriginalRTC);
            window.RTCPeerConnection.prototype = OriginalRTC.prototype;
            preserveCtorIdentity(window.RTCPeerConnection, OriginalRTC);
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

        // PerformanceNavigationTiming jitter — wrap entries returned by
        // performance.getEntriesByType('navigation') with a Proxy that adds
        // ±0.5ms jitter to each timing field. Headless Chrome's navigation
        // timings are suspiciously deterministic (no UI competing for the
        // main thread, no GC stalls from background rendering); adding
        // small jitter makes the per-phase durations look human-like.
        // Probed by some ad-network fingerprinters (e.g. ct.captcha-delivery,
        // popunder loaders sampling for fraud heuristics) as a 'robotic
        // timing' signal. Per-entry jitter offsets cached via WeakMap so
        // repeated reads on the same entry stay consistent (real navigation
        // timing values are stable per navigation).
        //
        // Scope: navigation entries only. 'resource' entries (per-subresource
        // timing) and PerformanceObserver-delivered entries are NOT wrapped
        // — significant additional complexity for marginal gain since
        // typical fingerprinters check only navigation timing.
        safeExecute(() => {
          if (typeof performance === 'undefined' || typeof performance.getEntriesByType !== 'function') return;

          const TIMING_FIELDS = new Set([
            'fetchStart', 'startTime', 'duration', 'redirectStart', 'redirectEnd',
            'workerStart',  // service-worker startup timing (was missing — partial-coverage tell)
            'domainLookupStart', 'domainLookupEnd',
            'connectStart', 'connectEnd', 'secureConnectionStart',
            'requestStart', 'responseStart', 'responseEnd',
            'domInteractive', 'domContentLoadedEventStart', 'domContentLoadedEventEnd',
            'domComplete', 'loadEventStart', 'loadEventEnd'
          ]);
          const wrappedEntries = new WeakMap();

          const wrapEntry = (entry) => {
            if (entry == null || typeof entry !== 'object') return entry;
            const cached = wrappedEntries.get(entry);
            if (cached) return cached.proxy;

            // Per-(entry, field) jitter cache so repeated reads of the
            // same timing field return the SAME jittered value (real
            // PerformanceNavigationTiming values are immutable per
            // navigation; jitter-noise on every read would be detectable
            // as anomalous). Don't jitter 0 -- those mean 'event never
            // occurred' (e.g. secureConnectionStart=0 for non-HTTPS);
            // adding noise would invent a connection that didn't happen.
            const jitterCache = new Map();
            const getJittered = (field, value) => {
              if (typeof value !== 'number' || value === 0) return value;
              let v = jitterCache.get(field);
              if (v === undefined) {
                v = value + (Math.random() - 0.5); // ±0.5ms
                jitterCache.set(field, v);
              }
              return v;
            };

            // Per-property bound-method cache so accessing the same method
            // twice returns the same function identity (`p.toJSON === p.toJSON`
            // is true on real Chrome; without caching, Proxy returns a new
            // bound function every access — strict-equality probes catch us).
            // Bound methods also maskAsNative'd so their .toString() reports
            // '[native code]' rather than the bound-fn source.
            const methodCache = new Map();

            const proxy = new Proxy(entry, {
              get(target, prop) {
                const value = target[prop];
                if (TIMING_FIELDS.has(prop)) return getJittered(prop, value);
                if (typeof value === 'function') {
                  let m = methodCache.get(prop);
                  if (m === undefined) {
                    if (prop === 'toJSON') {
                      // toJSON drives JSON.stringify; apply same per-field
                      // jitter cache to the serialised object so direct-read
                      // and JSON-roundtrip yield identical values.
                      m = function() {
                        const json = value.call(target);
                        for (const f of TIMING_FIELDS) {
                          if (f in json) json[f] = getJittered(f, json[f]);
                        }
                        return json;
                      };
                    } else {
                      m = value.bind(target);
                    }
                    maskAsNative(m, prop);
                    methodCache.set(prop, m);
                  }
                  return m;
                }
                return value;
              }
            });
            wrappedEntries.set(entry, { proxy, jitterCache, methodCache });
            return proxy;
          };

          const origGetByType = performance.getEntriesByType;
          performance.getEntriesByType = function(type) {
            const entries = origGetByType.call(this, type);
            if (type === 'navigation') return entries.map(wrapEntry);
            return entries;
          };
          maskAsNative(performance.getEntriesByType, 'getEntriesByType');
        }, 'PerformanceNavigationTiming jitter');

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

          // Cache of canvases already noised in their current bytes. toDataURL
          // and toBlob both do a getImageData + putImageData round-trip to
          // bake noise into the canvas before the actual export. Each
          // round-trip is O(width × height) -- ~2M iterations for a 1920x1080
          // canvas, capped at 500k pixels via the size guard below.
          //
          // Repeated calls on the SAME canvas don't need re-noising: the
          // first call already wrote noised pixel data into the canvas via
          // putImageData. Skip the round-trip for subsequent calls; the
          // canvas backing store still has the noised content. Trade-off:
          // if a page redraws between calls (canvas.drawImage, fillRect,
          // etc.), the new content won't be re-noised. Acceptable for the
          // common fingerprinter pattern (draw probe content -> single
          // toDataURL -> compare to known signature); pathological for
          // animated canvases that re-toDataURL per frame. WeakMap so a
          // GC'd canvas drops its noise-cache entry automatically.
          const noisedCanvases = new WeakMap();

          const applyCanvasNoise = function(canvas) {
            if (noisedCanvases.has(canvas)) return;
            try {
              const ctx = canvas.getContext('2d');
              if (ctx && canvas.width > 0 && canvas.height > 0 && canvas.width * canvas.height < 500000) {
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                ctx.putImageData(imageData, 0, 0);
                noisedCanvases.set(canvas, true);
              }
            } catch (e) {} // WebGL or other context — skip
          };

          const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
          HTMLCanvasElement.prototype.toDataURL = function(...args) {
            applyCanvasNoise(this);
            return originalToDataURL.apply(this, args);
          };

          const originalToBlob = HTMLCanvasElement.prototype.toBlob;
          if (originalToBlob) {
            HTMLCanvasElement.prototype.toBlob = function(callback, ...args) {
              applyCanvasNoise(this);
              return originalToBlob.call(this, callback, ...args);
            };
          }
        }, 'canvas fingerprinting protection');

        // Battery API spoofing
        //
        // Previously: `Math.random()` for every field, fired on every
        // evaluateOnNewDocument injection (i.e. every page load). Battery
        // 'level' jumping from 0.42 to 0.87 to 0.31 across navigations on
        // the same site is anomalous -- real battery state changes slowly
        // (minutes, not seconds). Detector noting battery delta across
        // reloads catches us.
        //
        // Now: FNV-1a hash of window.location.hostname seeds all four
        // fields. Stable per-domain across navigations; varies across
        // sites (so cross-publisher correlation isn't trivial via this
        // signal). Also corrects two real-Chrome invariants the old
        // spoof violated:
        //   - charging=true  -> chargingTime finite, dischargingTime = Infinity
        //   - charging=false -> chargingTime = Infinity, dischargingTime finite
        // The old spoof could produce 'both finite' which never happens
        // in real Chrome.
        safeExecute(() => {
          if (navigator.getBattery) {
            // FNV-1a 32-bit hash of the hostname -- cheap, deterministic.
            let h = 0x811c9dc5;
            const domain = (window.location && window.location.hostname) || '';
            for (let i = 0; i < domain.length; i++) {
              h = ((h ^ domain.charCodeAt(i)) * 0x01000193) >>> 0;
            }
            const charging = (h & 1) === 1;
            const batteryState = {
              charging,
              chargingTime: charging ? (((h >>> 4) % 3540) + 60) : Infinity,        // 60..3600s when charging
              dischargingTime: charging ? Infinity : (((h >>> 8) % 6600) + 600),    // 600..7200s when on battery
              level: Math.round((((h >>> 16) % 70) + 25)) / 100,                    // 0.25..0.94, 2-decimal precision
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
          // Spoof pointer capabilities — UA-consistent. Previous code did
          //   Math.random() > 0.7 ? 0 : Math.floor(Math.random() * 5) + 1
          // which randomly told the page 'this Windows Chrome has 3 touch
          // points' -- a fingerprinter cross-checking userAgent against
          // maxTouchPoints catches the invariant violation:
          //   Windows/Mac/Linux Chrome   -> maxTouchPoints = 0
          //   iOS Safari, Android Chrome -> maxTouchPoints = 5 (typical)
          //   Touch-laptop hybrid        -> maxTouchPoints = 10 (rare)
          // Use the spoofed UA (userAgent variable in this closure) to
          // pick the right value. Mobile UAs get 5; desktop UAs get 0.
          const isMobileUA = /Android|iPhone|iPad|iPod|Mobile/i.test(userAgent || '');
          const spoofedTouchPoints = isMobileUA ? 5 : 0;
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
            preserveCtorIdentity(window.PointerEvent, OriginalPointerEvent);
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
            Object.setPrototypeOf(window.WheelEvent, originalWheelEvent);
            preserveCtorIdentity(window.WheelEvent, originalWheelEvent);
          }
          
        }, 'enhanced mouse/pointer spoofing');

        safeExecute(() => {
          // Neutralize CDP fingerprinting traps and filter DevTools traces
          // CDP's Runtime.enable causes the inspector to read properties on console-logged objects.
          // Detection scripts exploit this via console.debug with Error objects (custom .stack getters)
          // or objects with Proxy prototypes. Only override console.debug — safest, minimal footprint.

          const originalConsoleDebug = console.debug;
          console.debug = function(...args) {
            // Filter DevTools-related messages
            const message = args.join(' ');
            if (typeof message === 'string' && (
                message.includes('DevTools') ||
                message.includes('Runtime.evaluate') ||
                message.includes('Page.addScriptToEvaluateOnNewDocument') ||
                message.includes('Protocol error'))) {
              return;
            }
            // Sanitize args to neutralize CDP fingerprinting traps
            const sanitized = args.map(arg => {
              // Strip Error objects with custom .stack getters (CDP inspector reads .stack)
              if (arg instanceof Error) {
                const desc = Object.getOwnPropertyDescriptor(arg, 'stack');
                if (desc && desc.get) return `${arg.name}: ${arg.message}`;
              }
              // Neutralize Proxy prototype traps (CDP inspector walks prototype chain)
              if (arg !== null && typeof arg === 'object') {
                try {
                  const proto = Object.getPrototypeOf(arg);
                  if (proto && proto !== Object.prototype && proto !== Array.prototype) {
                    try { Object.keys(proto); } catch { return '[object Object]'; }
                  }
                } catch { return '[object Object]'; }
              }
              return arg;
            });
            return originalConsoleDebug.apply(this, sanitized);
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
          if (typeof console.debug === 'function') maskAsNative(console.debug, 'debug');
          // Methods added in this session — same toString-tampering concern.
          if (typeof window.matchMedia === 'function') maskAsNative(window.matchMedia, 'matchMedia');
          if (typeof document.hasStorageAccess === 'function') maskAsNative(document.hasStorageAccess, 'hasStorageAccess');
          if (typeof navigator.getInstalledRelatedApps === 'function') maskAsNative(navigator.getInstalledRelatedApps, 'getInstalledRelatedApps');

          // Mask property getters on navigator
          // 'userActivation' added in this session; 'productSub'/'vendorSub'
          // are this commit's additions alongside the existing vendor/product.
          const navProps = ['userAgentData', 'connection', 'pdfViewerEnabled', 'webdriver',
                            'hardwareConcurrency', 'deviceMemory', 'platform', 'maxTouchPoints',
                            'userActivation', 'vendor', 'product', 'productSub', 'vendorSub'];
          navProps.forEach(prop => {
            // Check both instance and prototype (webdriver lives on prototype)
            const desc = Object.getOwnPropertyDescriptor(navigator, prop)
                      || Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
            if (desc?.get) maskAsNative(desc.get, 'get ' + prop);
          });

          // Mask Notification.permission getter (static property, added this session).
          if (typeof Notification !== 'undefined') {
            const npDesc = Object.getOwnPropertyDescriptor(Notification, 'permission');
            if (npDesc?.get) maskAsNative(npDesc.get, 'get permission');
          }

          // Mask screen.orientation getter (added this session).
          const orientDesc = Object.getOwnPropertyDescriptor(window.screen, 'orientation');
          if (orientDesc?.get) maskAsNative(orientDesc.get, 'get orientation');

          // Mask window property getters — screenLeft/Top added this session.
          ['screenX', 'screenY', 'screenLeft', 'screenTop', 'outerWidth', 'outerHeight'].forEach(prop => {
            const desc = Object.getOwnPropertyDescriptor(window, prop);
            if (desc?.get) maskAsNative(desc.get, 'get ' + prop);
          });

          if (debugEnabled) console.log('[fingerprint] toString protection applied to all spoofed functions');
        }, 'Function.prototype.toString bulk masking');

        // Trigger interaction-gated scripts (GTM, Monetag etc.) on page load
        safeExecute(() => {
          function triggerInteraction() {
            setTimeout(() => {
              const x = Math.floor(Math.random() * 800) + 100;
              const y = Math.floor(Math.random() * 400) + 100;
              window.dispatchEvent(new MouseEvent('mousemove', {
                clientX: x, clientY: y, pageX: x, pageY: y, bubbles: true, cancelable: true, view: window
              }));
              window.dispatchEvent(new Event('scroll', { bubbles: true }));
              document.dispatchEvent(new KeyboardEvent('keydown', {
                key: 'Tab', code: 'Tab', bubbles: true
              }));
            }, 50);
          }
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', triggerInteraction, { once: true });
          } else {
            triggerInteraction();
          }
        }, 'interaction-gated script trigger');

      }, ua, forceDebug, selectedGpu, realistic.hardwareConcurrency);
    } catch (stealthErr) {
      if (isSessionClosedError(stealthErr)) {
        if (forceDebug) console.log(formatLogMessage('debug', `Page closed during stealth injection: ${currentUrl}`));
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

  if (forceDebug) console.log(formatLogMessage('debug', `Brave spoofing enabled for ${currentUrl}`));

  if (isBrowserDead(page)) return;

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
    if (isSessionClosedError(braveErr)) {
      if (forceDebug) console.log(formatLogMessage('debug', `Page closed during Brave injection: ${currentUrl}`));
      return;
    }
    if (forceDebug) console.log(formatLogMessage('debug', `Brave spoofing failed: ${currentUrl} - ${braveErr.message}`));
  }
}

/**
 * Enhanced fingerprint protection with realistic spoofing
 */
async function applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl) {
  const fingerprintSetting = siteConfig.fingerprint_protection;
  if (!fingerprintSetting) return;

  if (forceDebug) console.log(formatLogMessage('debug', `Fingerprint protection enabled for ${currentUrl}`));

  if (isBrowserDead(page)) return;
  
  // Validate page state before injection
  if (!(await validatePageForInjection(page, currentUrl, forceDebug))) return;

  // FIX: Wrap page.evaluate in try-catch to handle race condition 
  let currentUserAgent;
  try {
    currentUserAgent = await page.evaluate(() => navigator.userAgent);
  } catch (evalErr) {
    if (forceDebug) console.log(formatLogMessage('debug', `Could not get user agent - page closed: ${currentUrl}`));
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
      
      // Mirror of the helper defined inside applyUserAgentSpoofing's
      // evaluate -- both behave identically: skip built-ins, refuse to
      // touch non-configurable, default (not force) configurable:true so
      // explicit caller intent is preserved. Previously this copy
      // diverged: it had no built-in check AND it force-overrode
      // configurable:true regardless of caller. Now consistent.
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
            configurable: true,
            ...descriptor
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

      // navigator.connection spoof DELETED -- was dead code.
      // The UA-spoof block (applyUserAgentSpoofing's eOND, ~line 1452)
      // already defines navigator.connection earlier in the eOND
      // registration order, with Object.defineProperty (default
      // configurable: false). The previous re-spoof here used
      // safeDefinePropertyLocal which has an `existing?.configurable
      // === false` guard, so it silently failed every time the UA spoof
      // ran. Net effect: per-navigation random connection values
      // generated here NEVER reached navigator.connection -- the
      // hardcoded '4g'/wifi/50/10 from the UA block always won.
      // Removing this block has zero behavioural change in the typical
      // (UA + fingerprint_protection) case, and makes the code's actual
      // behaviour match what reading it would suggest. Per-domain
      // realistic-randomization of connection is a future improvement;
      // do it ONCE in the UA-spoof block, not twice with one of them dead.

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
    if (isSessionClosedError(err)) {
      if (forceDebug) console.log(formatLogMessage('debug', `Page closed during fingerprint injection: ${currentUrl}`));
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
      if (forceDebug) console.log(formatLogMessage('debug', `Human behavior simulation skipped - page closed`));
      return;
    }
    
    // Check if browser is still connected
    if (!page.browser().connected) {
      if (forceDebug) console.log(formatLogMessage('debug', `Human behavior simulation skipped - browser disconnected`));
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
              pageX: mouseX + (window.scrollX || 0),
              pageY: mouseY + (window.scrollY || 0),
              screenX: mouseX + (window.screenX || 0),
              screenY: mouseY + (window.screenY || 0),
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
                pageX: mouseX + (window.scrollX || 0),
                pageY: mouseY + (window.scrollY || 0),
                screenX: mouseX + (window.screenX || 0),
                screenY: mouseY + (window.screenY || 0),
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
    if (forceDebug) console.log(formatLogMessage('debug', `Human behavior simulation setup failed: ${err.message}`));
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
      if (forceDebug) console.log(formatLogMessage('debug', `${name} failed for ${currentUrl}: ${err.message}`));
    }
  }
  
  // Add human behavior simulation if user agent spoofing is enabled
  if (siteConfig.userAgent) {
    try {
      await simulateHumanBehavior(page, forceDebug);
    } catch (behaviorErr) {
      if (forceDebug) console.log(formatLogMessage('debug', `Human behavior simulation failed for ${currentUrl}: ${behaviorErr.message}`));
    }
  }
}

// Public surface kept narrow on purpose -- only what nwss.js actually
// imports. Internal helpers (generateRealisticFingerprint,
// applyUserAgentSpoofing, applyBraveSpoofing, applyFingerprintProtection,
// simulateHumanBehavior, selectGpuForUserAgent, isBrowserDead,
// isSessionClosedError, validatePageForInjection, seededRandom,
// DEFAULT_PLATFORM, DEFAULT_TIMEZONE) stay as module-local; move back to
// module.exports only if a new external consumer appears.
module.exports = {
  applyAllFingerprintSpoofing,
  // Exposed for scripts/test-stealth.js so the harness can validate --ua=
  // against the canonical UA list (instead of duplicating the keys here).
  // The Map itself is frozen; consumers cannot mutate the spoof source.
  USER_AGENT_COLLECTIONS
};
