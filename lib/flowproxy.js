/**
 * FlowProxy protection detection and handling module
 * Version: 1.0.0 - Enhanced with comprehensive documentation and smart detection
 * Detects flowProxy DDoS protection and handles it appropriately for security scanning
 * 
 * FlowProxy (by Aurologic) is a DDoS protection service similar to Cloudflare that:
 * - Implements rate limiting and browser verification
 * - Uses JavaScript challenges to verify legitimate browsers
 * - Can block automated tools and scrapers
 * - Requires specific handling for security scanning tools
 */

const { formatLogMessage, messageColors } = require('./colorize');

// Precomputed colored '[flowproxy]' subsystem prefix. formatLogMessage only
// colors the [severity] tag; this constant colors the subsystem prefix so
// '[debug] [flowproxy] X' has both tags visually distinct.
const FLOWPROXY_TAG = messageColors.processing('[flowproxy]');

/**
 * Timeout constants for FlowProxy operations (in milliseconds)
 * Optimized for Puppeteer 22.x performance while maintaining FlowProxy compatibility
 */
const TIMEOUTS = {
  PAGE_EVALUATION_SAFE: 10000,    // Safe page evaluation timeout
  // FlowProxy-specific timeouts
  JS_CHALLENGE_DEFAULT: 15000,    // Default JavaScript challenge timeout
  RATE_LIMIT_DEFAULT: 30000,      // Default rate limit delay
  PAGE_TIMEOUT_DEFAULT: 45000,    // Default page timeout
  NAVIGATION_TIMEOUT_DEFAULT: 45000 // Default navigation timeout
};

// Default-false detection shape returned by the catch paths in
// safePageEvaluate / analyzeFlowProxyProtection. Hoisted so the two
// catch branches don't drift if a new detection flag is added.
const DEFAULT_DETECTION = Object.freeze({
  isFlowProxyDetected: false,
  hasSpecificSignal: false,
  hasFlowProxyDomain: false,
  hasFlowProxyElements: false,
  hasFlowProxyScripts: false,
  hasFlowProxyBrandText: false,
  hasFlowProxyHeaders: false,
  hasFlowProxyCookies: false,
  matchedHeader: null,
  matchedCookie: null,
  hasProtectionPage: false,
  hasChallengeElements: false,
  isRateLimited: false,
  hasJSChallenge: false,
  isProcessing: false
});

// === HTTP RESPONSE HEADER / COOKIE DETECTION =================================
// Per-page accumulator for vendor-specific HTTP response signals. Populated
// by the response listener attached via attachFlowProxyHeaderListener();
// read by analyzeFlowProxyProtection() to merge with the DOM/text scan.
//
// WeakMap so the entry is released when Puppeteer drops the page reference —
// no manual cleanup needed.
const pageHeaderState = new WeakMap();

// Header/cookie tokens that uniquely identify FlowProxy/Aurologic. Lowercase
// for case-insensitive matching (response.headers() returns lowercase keys
// but values keep their case).
const VENDOR_TOKENS = ['flowproxy', 'aurologic'];

// Header names where a vendor token in the VALUE is a strong signal.
// (Server, Via, X-Powered-By, X-Cache, X-CDN are all places a CDN/proxy
// commonly self-identifies.)
const VENDOR_VALUE_HEADERS = ['server', 'via', 'x-powered-by', 'x-cache', 'x-cdn'];

/**
 * Attach a response listener to a page that watches for FlowProxy/Aurologic
 * HTTP response headers + cookies. Idempotent — safe to call multiple times.
 *
 * Headers are the most reliable signal: DOM scraping can be fooled by any
 * "Please wait" / "Loading" string, but a `Server: flowProxy` header is
 * uniquely the vendor's. Cookies likewise — `flowproxy_*` / `aurologic_*`
 * names don't collide with anything else in practice.
 *
 * Call BEFORE page.goto() so the navigation response itself is observed.
 * State is read later via analyzeFlowProxyProtection().
 *
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 */
function attachFlowProxyHeaderListener(page) {
  if (pageHeaderState.has(page)) return; // idempotent

  const state = {
    hasFlowProxyHeaders: false,
    hasFlowProxyCookies: false,
    matchedHeader: null
  };
  pageHeaderState.set(page, state);

  page.on('response', (response) => {
    // Once both signals are found there's nothing more to learn — bail
    // immediately to keep per-response overhead near zero on long pages.
    if (state.hasFlowProxyHeaders && state.hasFlowProxyCookies) return;

    try {
      const headers = response.headers();
      if (!headers) return;

      // 1) Vendor-token search across the well-known value-bearing headers.
      if (!state.hasFlowProxyHeaders) {
        for (const h of VENDOR_VALUE_HEADERS) {
          const v = headers[h];
          if (!v) continue;
          const vl = v.toLowerCase();
          for (const tok of VENDOR_TOKENS) {
            if (vl.includes(tok)) {
              state.hasFlowProxyHeaders = true;
              state.matchedHeader = `${h}: ${v}`;
              break;
            }
          }
          if (state.hasFlowProxyHeaders) break;
        }
      }

      // 2) Any X-FlowProxy-* or X-Aurologic-* custom header name — those
      //    are vendor-namespaced by convention and don't collide.
      if (!state.hasFlowProxyHeaders) {
        for (const key of Object.keys(headers)) {
          // key is already lowercase per Puppeteer's headers() contract
          if (key.startsWith('x-flowproxy-') || key.startsWith('x-aurologic-')) {
            state.hasFlowProxyHeaders = true;
            state.matchedHeader = `${key}: ${headers[key]}`;
            break;
          }
        }
      }

      // 3) Set-Cookie inspection — flowproxy_* / aurologic_* prefixes.
      //    Puppeteer joins multi-cookie set-cookie values with '\n'.
      if (!state.hasFlowProxyCookies) {
        const setCookie = headers['set-cookie'];
        if (setCookie) {
          const sc = setCookie.toLowerCase();
          if (sc.includes('flowproxy_') || sc.includes('flowproxy=') ||
              sc.includes('aurologic_') || sc.includes('aurologic=')) {
            state.hasFlowProxyCookies = true;
          }
        }
      }
    } catch (_) {
      // Observation-only — never let a header read throw into Puppeteer's
      // event-emitter chain.
    }
  });
}

// Fast timeout constants - optimized for speed while respecting FlowProxy delays
const FAST_TIMEOUTS = {
  PAGE_LOAD_WAIT: 1500,           // Reduced from 2000ms
  ADDITIONAL_DELAY_DEFAULT: 3000  // Reduced from 5000ms
};

// Protocols to skip — FlowProxy only protects web traffic
const SKIP_PATTERNS = [
  'about:', 'chrome:', 'chrome-extension:', 'chrome-error:', 'chrome-search:',
  'devtools:', 'edge:', 'moz-extension:', 'safari-extension:', 'webkit:',
  'data:', 'blob:', 'javascript:', 'vbscript:', 'file:', 'ftp:', 'ftps:'
];

/**
 * Validates if a URL should be processed by FlowProxy protection
 * Only allows HTTP/HTTPS URLs, skips browser-internal and special protocols
 * 
 * @param {string} url - URL to validate
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {boolean} True if URL should be processed
 * 
 * @example
 * // Valid URLs that will be processed
 * shouldProcessUrl('https://example.com') // => true
 * shouldProcessUrl('http://test.com') // => true
 * 
 * // Invalid URLs that will be skipped
 * shouldProcessUrl('chrome://settings') // => false
 * shouldProcessUrl('about:blank') // => false
 * shouldProcessUrl('file:///local/file.html') // => false
 */
function shouldProcessUrl(url, forceDebug = false) {
  if (!url || typeof url !== 'string') {
    if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}[url-validation] Skipping invalid URL: ${url}`));
    return false;
  }

  // Skip browser-internal and special protocol URLs
  const urlLower = url.toLowerCase();
  for (const pattern of SKIP_PATTERNS) {
    if (urlLower.startsWith(pattern)) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}[url-validation] Skipping ${pattern} URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`));
      }
      return false;
    }
  }

  // Only process HTTP/HTTPS URLs - FlowProxy only protects web traffic
  if (!urlLower.startsWith('http://') && !urlLower.startsWith('https://')) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}[url-validation] Skipping non-HTTP(S) URL: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`));
    }
    return false;
  }

  return true;
}

/**
 * Fast timeout helper for Puppeteer 22.x compatibility 
 * Replaces deprecated page.waitForTimeout() with standard Promise-based approach
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<void>}
 */
async function waitForTimeout(page, timeout) {
  // Use fast Promise-based timeout for Puppeteer 22.x compatibility
  return new Promise(resolve => setTimeout(resolve, timeout));
}

/**
 * Safe page evaluation with timeout protection for FlowProxy analysis
 */
async function safePageEvaluate(page, func, timeout = TIMEOUTS.PAGE_EVALUATION_SAFE) {
  let timer;
  try {
    return await Promise.race([
      page.evaluate(func),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('FlowProxy page evaluation timeout')), timeout);
      })
    ]);
  } catch (error) {
    // Return full default-false shape so downstream `.hasProtectionPage`
    // etc. read as `false` instead of `undefined` — keeps debug logs
    // honest and conditional branches in handleFlowProxyProtection
    // deterministic.
    return { ...DEFAULT_DETECTION, error: error.message };
  } finally {
    if (timer) clearTimeout(timer);
  }
}


/**
 * Analyzes the current page to detect flowProxy protection with comprehensive detection logic
 * 
 * FlowProxy protection typically manifests as:
 * - DDoS protection pages with "Please wait" messages
 * - Rate limiting responses (429 errors)
 * - JavaScript challenges that must complete before access
 * - Aurologic branding and flowproxy-specific elements
 * - Browser verification processes
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @returns {Promise<object>} Detection information object with detailed analysis
 * 
 * @example
 * const analysis = await analyzeFlowProxyProtection(page);
 * if (analysis.isFlowProxyDetected) {
 *   console.log(`FlowProxy protection found: ${analysis.title}`);
 *   if (analysis.isRateLimited) {
 *     console.log('Rate limiting is active');
 *   }
 * }
 */
async function analyzeFlowProxyProtection(page) {
  try {
    // Get current page URL and validate it first.
    // page.url() is synchronous in Puppeteer 20+; no await needed.
    const currentPageUrl = page.url();

    if (!shouldProcessUrl(currentPageUrl, false)) {
      return {
        isFlowProxyDetected: false,
        skippedInvalidUrl: true,
        url: currentPageUrl
      };
    }

    // Pull HTTP-layer signals collected by the response listener (populated
    // by attachFlowProxyHeaderListener if the caller wired it up before
    // navigation). Falls back to false-defaults if the listener was never
    // attached, so DOM-only detection still works.
    const httpState = pageHeaderState.get(page) || {
      hasFlowProxyHeaders: false,
      hasFlowProxyCookies: false,
      matchedHeader: null
    };

    // Continue with comprehensive FlowProxy detection for valid HTTP(S) URLs
    const domResult = await safePageEvaluate(page, () => {
      const title = document.title || '';
      const bodyText = document.body ? document.body.textContent : '';
      const url = window.location.href;

      // === VENDOR-SPECIFIC SIGNALS (high-confidence FlowProxy markers) ===
      // Anything here is unambiguous: it names FlowProxy or its parent
      // company Aurologic. At least ONE of these must be present for the
      // primary detection to fire — generic loaders / Cloudflare's
      // "Checking your browser" / SPA spinners alone do NOT count.

      // URL signals — note: 'ddos-protection' was moved out of this set;
      // it's too broad (matches docs/blog URLs about DDoS protection).
      const hasFlowProxyDomain = url.includes('aurologic') ||
                                 url.includes('flowproxy');

      // DOM signals tied to the vendor's class/id/data-attribute namespace
      // or its uniquely named challenge input.
      const hasFlowProxyElements = document.querySelector('[data-flowproxy]') !== null ||
                                   document.querySelector('.flowproxy-challenge') !== null ||
                                   document.querySelector('#flowproxy-container') !== null ||
                                   document.querySelector('.aurologic-protection') !== null ||
                                   document.querySelector('input[name="flowproxy-response"]') !== null;

      // Script src patterns from the vendor.
      const hasFlowProxyScripts = document.querySelector('script[src*="flowproxy"]') !== null ||
                                  document.querySelector('script[src*="aurologic"]') !== null;

      // Brand-name strings — "flowProxy" (cased) and the canonical
      // Aurologic attribution line.
      const hasFlowProxyBrandText = bodyText.includes('DDoS protection by aurologic') ||
                                    bodyText.includes('flowProxy');

      // DOM-side specific signals only. The Node caller below merges this
      // with HTTP-header / cookie signals (which live outside the page
      // context) to produce the final hasSpecificSignal.
      const domSpecificSignal = hasFlowProxyDomain ||
                                hasFlowProxyElements ||
                                hasFlowProxyScripts ||
                                hasFlowProxyBrandText;

      // === GENERIC SIGNALS (low-confidence; used for sub-handling only) ===
      // These flags help the handler decide WHICH delay to apply once
      // FlowProxy presence is already confirmed by a specific signal.
      // They are NOT inputs to isFlowProxyDetected — by themselves they
      // collide with Cloudflare, Sucuri, generic SPA loaders, etc.

      // Generic protection-page text (kept for verification-step semantics
      // and debug logging — exposed as `hasProtectionPage` for backward
      // compat with the rest of the module).
      const hasProtectionPage = hasFlowProxyBrandText ||
                                title.includes('DDoS Protection') ||
                                title.includes('Please wait') ||
                                title.includes('Checking your browser') ||
                                bodyText.includes('Verifying your browser') ||
                                url.includes('ddos-protection');

      // Generic challenge-element markers (still exposed for the handler's
      // sub-decisions; hasFlowProxyElements above is the strong subset).
      const hasChallengeElements = hasFlowProxyElements ||
                                   document.querySelector('.challenge-running') !== null ||
                                   document.querySelector('.verification-container') !== null;

      const isRateLimited = bodyText.includes('Rate limited') ||
                            bodyText.includes('Too many requests') ||
                            bodyText.includes('Please try again later') ||
                            title.includes('429') ||
                            title.includes('Rate Limit');

      // hasJSChallenge gates the wait-for-challenge-completion path. The
      // vendor script-src patterns are strong; the JS-required strings are
      // generic but only matter when hasSpecificSignal already gated us in.
      const hasJSChallenge = hasFlowProxyScripts ||
                             bodyText.includes('JavaScript is required') ||
                             bodyText.includes('Please enable JavaScript');

      const isProcessing = bodyText.includes('Processing') ||
                           bodyText.includes('Loading') ||
                           document.querySelector('.loading-spinner') !== null ||
                           document.querySelector('.processing-indicator') !== null;

      // The Node-side caller merges this with HTTP signals to compute
      // the final hasSpecificSignal / isFlowProxyDetected.
      return {
        domSpecificSignal,
        hasFlowProxyDomain,
        hasFlowProxyElements,
        hasFlowProxyScripts,
        hasFlowProxyBrandText,
        hasProtectionPage,
        hasChallengeElements,
        isRateLimited,
        hasJSChallenge,
        isProcessing,
        title,
        url,
        bodySnippet: bodyText.substring(0, 200) // First 200 chars for debugging
      };
    });

    // Cookie-jar check: complements the Set-Cookie response-header listener
    // by reading what's ACTUALLY persisted in the browser jar. Catches:
    //   - cookies set on prior visits (session-reuse scenarios)
    //   - cookies set via document.cookie = '...' from page JS
    //   - cookies whose Set-Cookie header was emitted before the listener
    //     attached (won't happen with our current wiring, but defensive)
    //   - cookies that the listener's substring search missed
    // Try/catch because page.cookies() throws on closed/detached pages.
    let hasJarCookie = false;
    let matchedCookie = null;
    try {
      const cookies = await page.cookies();
      if (Array.isArray(cookies)) {
        for (let i = 0; i < cookies.length; i++) {
          const name = (cookies[i].name || '').toLowerCase();
          if (name === 'flowproxy' || name === 'aurologic' ||
              name.startsWith('flowproxy_') || name.startsWith('aurologic_') ||
              name.startsWith('flowproxy-') || name.startsWith('aurologic-')) {
            hasJarCookie = true;
            matchedCookie = cookies[i].name;
            break;
          }
        }
      }
    } catch (_) {
      // Observation-only — never fail detection because the jar read errored.
    }

    // If the safePageEvaluate error path fired, domResult has only the
    // DEFAULT_DETECTION fields (+ error) — propagate that without further
    // merging so the failure surface is preserved. Still include the
    // jar/header signals we managed to collect, since those are usable
    // even when DOM scraping died.
    if (domResult && domResult.error) {
      return {
        ...domResult,
        ...httpState,
        hasFlowProxyCookies: httpState.hasFlowProxyCookies || hasJarCookie,
        matchedCookie
      };
    }

    // Cookies are the union of Set-Cookie observations (from the listener)
    // and the actual browser-jar state read here. Either source firing
    // counts as a vendor-specific cookie signal.
    const hasFlowProxyCookies = httpState.hasFlowProxyCookies || hasJarCookie;

    // Merge DOM + HTTP signals. Headers/cookies are vendor-namespaced
    // by convention so they're treated as strong signals on par with
    // the DOM-side specific markers. Either side firing is enough.
    const hasSpecificSignal = (domResult && domResult.domSpecificSignal) ||
                              httpState.hasFlowProxyHeaders ||
                              hasFlowProxyCookies;

    return {
      ...domResult,
      hasFlowProxyHeaders: httpState.hasFlowProxyHeaders,
      hasFlowProxyCookies,
      matchedHeader: httpState.matchedHeader,
      matchedCookie,
      hasSpecificSignal,
      // PRIMARY DETECTION: at least one vendor-specific signal across DOM
      // OR HTTP layer. Headers are the most reliable signal; cookies
      // close behind. DOM markers remain the fallback for sites where
      // the listener wasn't wired up before navigation.
      isFlowProxyDetected: hasSpecificSignal
    };
  } catch (error) {
    // Return safe defaults if page evaluation fails
    return { ...DEFAULT_DETECTION, error: error.message };
  }
}

/**
 * Handles flowProxy protection by implementing appropriate delays and retry logic
 * 
 * FlowProxy handling strategy:
 * 1. Detect protection type (rate limiting, JS challenge, etc.)
 * 2. Implement appropriate delays based on protection type
 * 3. Wait for JavaScript challenges to complete
 * 4. Verify successful bypass before continuing
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {string} currentUrl - Current URL being processed
 * @param {object} siteConfig - Site configuration object with FlowProxy settings
 * @param {boolean} forceDebug - Debug mode flag for detailed logging
 * 
 * @returns {Promise<object>} Result object with comprehensive handling details:
 * {
 *   flowProxyDetection: {
 *     attempted: boolean,     // Whether detection was attempted
 *     detected: boolean,      // Whether FlowProxy protection was found
 *     details: object|null    // Detailed detection information
 *   },
 *   handlingResult: {
 *     attempted: boolean,     // Whether handling was attempted
 *     success: boolean        // Whether handling succeeded
 *   },
 *   overallSuccess: boolean,  // True if no critical failures occurred
 *   errors: string[],         // Array of error messages
 *   warnings: string[],       // Array of warning messages
 *   skippedInvalidUrl: boolean // True if URL was skipped due to invalid protocol
 * }
 * 
 * @example
 * const config = {
 *   flowproxy_delay: 45000,           // Rate limit delay (45 seconds)
 *   flowproxy_js_timeout: 20000,      // JS challenge timeout (20 seconds)
 *   flowproxy_additional_delay: 8000  // Additional processing delay (8 seconds)
 * };
 * 
 * const result = await handleFlowProxyProtection(page, url, config, true);
 * if (result.flowProxyDetection.detected) {
 *   console.log('FlowProxy protection handled');
 *   if (result.warnings.length > 0) {
 *     console.log('Warnings:', result.warnings);
 *   }
 * }
 */
async function handleFlowProxyProtection(page, currentUrl, siteConfig, forceDebug = false) {

  // VALIDATE URL FIRST - Skip protection handling for non-HTTP(S) URLs
  // FlowProxy only protects web traffic, so other protocols should be skipped
  if (!shouldProcessUrl(currentUrl, forceDebug)) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} Skipping protection handling for non-HTTP(S) URL: ${currentUrl}`));
    }
    return {
      flowProxyDetection: { attempted: false, detected: false },
      handlingResult: { attempted: false, success: true },
      overallSuccess: true,
      errors: [],
      warnings: [],
      skippedInvalidUrl: true
    };
  }

  // Initialize result structure for tracking all handling aspects
  const result = {
    flowProxyDetection: { attempted: false, detected: false },
    handlingResult: { attempted: false, success: false },
    overallSuccess: true,
    errors: [],
    warnings: []
  };

  try {
    if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} Checking for flowProxy protection on ${currentUrl}`));
    
    // Wait for initial page load before analyzing
    // FlowProxy protection pages need time to fully render their elements
    await waitForTimeout(page, FAST_TIMEOUTS.PAGE_LOAD_WAIT);

    // Perform comprehensive FlowProxy detection
    const detectionInfo = await analyzeFlowProxyProtection(page);
    result.flowProxyDetection = { 
      attempted: true, 
      detected: detectionInfo.isFlowProxyDetected,
      details: detectionInfo 
    };
    
    // Only proceed with handling if FlowProxy protection is detected
    if (detectionInfo.isFlowProxyDetected) {
      result.handlingResult.attempted = true;
      
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} FlowProxy protection detected on ${currentUrl}:`));
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Page Title: "${detectionInfo.title}"`));
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Current URL: ${detectionInfo.url}`));
        // Specific-signal breakdown — which vendor-specific marker(s) fired
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Specific signals: domain=${detectionInfo.hasFlowProxyDomain} elements=${detectionInfo.hasFlowProxyElements} scripts=${detectionInfo.hasFlowProxyScripts} brandText=${detectionInfo.hasFlowProxyBrandText} headers=${detectionInfo.hasFlowProxyHeaders} cookies=${detectionInfo.hasFlowProxyCookies}`));
        if (detectionInfo.matchedHeader) {
          console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Matched header: ${detectionInfo.matchedHeader}`));
        }
        if (detectionInfo.matchedCookie) {
          console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Matched cookie: ${detectionInfo.matchedCookie}`));
        }
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Has Protection Page: ${detectionInfo.hasProtectionPage}`));
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Has Challenge Elements: ${detectionInfo.hasChallengeElements}`));
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Is Rate Limited: ${detectionInfo.isRateLimited}`));
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Has JS Challenge: ${detectionInfo.hasJSChallenge}`));
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Is Processing: ${detectionInfo.isProcessing}`));
        console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Body Snippet: "${detectionInfo.bodySnippet}"`));
      }

      // HANDLE RATE LIMITING - Highest priority as it blocks all requests
      // Rate limiting requires waiting before any other actions
      if (detectionInfo.isRateLimited) {
        const rateLimitDelay = siteConfig.flowproxy_delay || TIMEOUTS.RATE_LIMIT_DEFAULT;
        result.warnings.push(`Rate limiting detected - implementing ${rateLimitDelay}ms delay`);
        if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} Rate limiting detected, waiting ${rateLimitDelay}ms`));
        await waitForTimeout(page, rateLimitDelay);
      }

      // HANDLE JAVASCRIPT CHALLENGES - Second priority as they must complete
      // FlowProxy uses JS challenges to verify browser legitimacy
      if (detectionInfo.hasJSChallenge || detectionInfo.isProcessing) {
        const jsWaitTime = siteConfig.flowproxy_js_timeout || TIMEOUTS.JS_CHALLENGE_DEFAULT;
        if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} JavaScript challenge detected, waiting up to ${jsWaitTime}ms for completion`));
        
        try {
          // Wait for challenge completion indicators to disappear.
          // page.waitForFunction has its own { timeout } — the previous
          // outer Promise.race added a setTimeout that fired 5s LATER,
          // leaked its timer on the success path, and never won the race
          // in practice. Dropped: waitForFunction's own timeout is the
          // single source of truth.
          await page.waitForFunction(
            () => {
              const bodyText = document.body ? document.body.textContent : '';
              return !bodyText.includes('Processing') &&
                     !bodyText.includes('Checking your browser') &&
                     !bodyText.includes('Please wait') &&
                     !document.querySelector('.loading-spinner') &&
                     !document.querySelector('.processing-indicator');
            },
            { timeout: jsWaitTime }
          );

          if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} JavaScript challenge appears to have completed`));
        } catch (timeoutErr) {
          // Continue even if timeout occurs - some challenges may take longer
          result.warnings.push(`JavaScript challenge timeout after ${jsWaitTime}ms`);
          if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} JavaScript challenge timeout - continuing anyway`));
        }
      }

      // IMPLEMENT ADDITIONAL DELAY - Final step to ensure all processing completes
      // FlowProxy may need extra time even after challenges complete
      const additionalDelay = siteConfig.flowproxy_additional_delay || FAST_TIMEOUTS.ADDITIONAL_DELAY_DEFAULT;
      if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} Implementing additional ${additionalDelay}ms delay for flowProxy processing`));
      await waitForTimeout(page, additionalDelay);

      // VERIFY SUCCESSFUL BYPASS - Check if we're still on a protection page
      // This helps identify if our handling was successful
      const finalCheck = await analyzeFlowProxyProtection(page);
      if (finalCheck.isFlowProxyDetected && finalCheck.hasProtectionPage) {
        result.warnings.push('Still on flowProxy protection page after handling attempts');
        if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} Warning: Still appears to be on protection page`));
        // Don't mark as failure - protection page may persist but still allow access
      } else {
        result.handlingResult.success = true;
        if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} Successfully handled flowProxy protection for ${currentUrl}`));
      }
      
    } else {
      // No FlowProxy protection detected — nothing to handle.
      // result.overallSuccess is already true from initialization.
      if (forceDebug) console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} No flowProxy protection detected on ${currentUrl}`));
    }
    
  } catch (error) {
    // Critical error occurred during handling
    result.errors.push(`FlowProxy handling error: ${error.message}`);
    result.overallSuccess = false;
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} FlowProxy handling failed for ${currentUrl}:`));
      console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Error: ${error.message}`));
      console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   Stack: ${error.stack}`));
    }
  }

  // LOG COMPREHENSIVE RESULTS for debugging and monitoring
  if (result.errors.length > 0 && forceDebug) {
    console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} FlowProxy handling completed with errors for ${currentUrl}:`));
    result.errors.forEach(error => {
      console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   - ${error}`));
    });
  } else if (result.warnings.length > 0 && forceDebug) {
    console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} FlowProxy handling completed with warnings for ${currentUrl}:`));
    result.warnings.forEach(warning => {
      console.log(formatLogMessage('debug', `${FLOWPROXY_TAG}   - ${warning}`));
    });
  } else if (result.flowProxyDetection.attempted && forceDebug) {
    console.log(formatLogMessage('debug', `${FLOWPROXY_TAG} FlowProxy handling completed successfully for ${currentUrl}`));
  }

  return result;
}

/**
 * Gets page-level timeout values for flowProxy-protected sites. Used by
 * nwss.js to call page.setDefaultTimeout/setDefaultNavigationTimeout
 * before navigating. The handler itself reads challenge/rate-limit/
 * additional-delay values directly from siteConfig (with TIMEOUTS
 * fallbacks), so those don't need to round-trip through this function.
 *
 * @param {object} siteConfig - Site configuration object
 * @returns {{ pageTimeout: number, navigationTimeout: number }}
 *
 * @example
 * const { pageTimeout, navigationTimeout } = getFlowProxyTimeouts(siteConfig);
 * page.setDefaultTimeout(pageTimeout);
 * page.setDefaultNavigationTimeout(navigationTimeout);
 */
function getFlowProxyTimeouts(siteConfig) {
  return {
    pageTimeout: siteConfig.flowproxy_page_timeout || TIMEOUTS.PAGE_TIMEOUT_DEFAULT,
    navigationTimeout: siteConfig.flowproxy_nav_timeout || TIMEOUTS.NAVIGATION_TIMEOUT_DEFAULT
  };
}

// Public surface used by nwss.js. Internal helpers (waitForTimeout,
// safePageEvaluate, analyzeFlowProxyProtection, shouldProcessUrl) stay
// module-private — the old export list included several functions no
// caller imported.
//
// attachFlowProxyHeaderListener should be called by the caller BEFORE
// navigation so the response listener observes the document response's
// own headers. Without it, header/cookie detection silently no-ops and
// the module falls back to DOM-only detection.
module.exports = {
  handleFlowProxyProtection,
  getFlowProxyTimeouts,
  attachFlowProxyHeaderListener
};