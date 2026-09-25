// redirect.js - Enhanced redirect handling module for nwss.js
// Handles HTTP redirects, JavaScript redirects, meta refresh, and delayed redirects

/**
 * Enhanced navigation with comprehensive redirect detection including JavaScript redirects
 * @param {Page} page - Puppeteer page instance
 * @param {string} currentUrl - Original URL to navigate to
 * @param {object} siteConfig - Site configuration
 * @param {object} gotoOptions - Computed goto options from existing logic
 * @param {boolean} forceDebug - Debug logging flag
 * @param {Function} formatLogMessage - Log formatting function from main script
 * @returns {Promise<{finalUrl: string, redirected: boolean, redirectChain: string[]}>}
 */
async function navigateWithRedirectHandling(page, currentUrl, siteConfig, gotoOptions = {}, forceDebug = false, formatLogMessage) {
  const redirectChain = [currentUrl];
  // Parallel Set for O(1) membership checks — the array below was scanned with
  // .includes() (O(n)) on every candidate hop. Kept in sync at each push.
  const redirectChainSet = new Set([currentUrl]);
  let finalUrl = currentUrl;
  let redirected = false;
  // Hoisted so they're in scope at the return outside the try block below.
  let httpStatus = null;
  let cfRay = null;
  // Number check, not ||, for the same reason as max_redirects below: 0 is a
  // meaningful value -- "do not wait for JS redirects at all" -- and `||` swallowed
  // it as falsy and silently substituted 5000, so the wait could not be turned
  // off. Only absent/negative/non-number falls back to the default.
  //
  // 0 is the one clean way to opt out of the per-URL cost of this wait (see the
  // poll loop below: the effective spend is jsRedirectTimeout / JS_REDIRECT_POLLS
  // on EVERY url, whether or not it redirects).
  //
  // What 0 actually gives up is narrower than it sounds, measured rather than
  // assumed: only redirects that land AFTER navigation settles stop being
  // tracked. Anything that commits during page.goto -- an HTTP 30x, or an inline
  // `location.href = ...` that runs on parse -- is still caught by the
  // framenavigated handler, which does not depend on this wait. Verified at 0: a
  // 302 tracked, an inline JS redirect tracked, a setTimeout(2000ms) redirect
  // NOT tracked. In all cases the landed page still loads and its requests are
  // still captured; only the chain, finalUrl and first-party promotion miss the
  // late hop.
  const jsRedirectTimeout = (typeof siteConfig.js_redirect_timeout === 'number' && siteConfig.js_redirect_timeout >= 0)
    ? siteConfig.js_redirect_timeout : 5000;
  // Use a number check, not || , so max_redirects: 0 (follow none) isn't
  // swallowed as falsy and silently bumped to 10. Only absent/negative/non-number defaults.
  const maxRedirects = (typeof siteConfig.max_redirects === 'number' && siteConfig.max_redirects >= 0)
    ? siteConfig.max_redirects : 10;
  const detectJSPatterns = siteConfig.detect_js_patterns !== false; // Default to true

  // Monitor frame navigations to detect redirects
  const navigationHandler = (frame) => {
    if (frame === page.mainFrame()) {
      const frameUrl = frame.url();
      // Skip about:blank and chrome-error:// — the latter is what Puppeteer
      // navigates to on DNS/connection failures, and pushing it into the
      // redirect chain produces bogus entries like
      // "chrome-error://chromewebdata/" that downstream consumers
      // (redirectDomains, logs) treat as a real intermediate hop.
      if (frameUrl && frameUrl !== 'about:blank' && !frameUrl.startsWith('chrome-error://') && !redirectChainSet.has(frameUrl)) {
        // Check redirect limit before adding.
        //
        // `>` not `>=`: redirectChain is seeded with the ORIGINAL url, so its
        // length is already 1 here before any redirect has been recorded. With
        // `>=` a value of N tracked only N-1 redirects and 0 and 1 behaved
        // identically -- both tracked none -- which is not what
        // "max_redirects: 1" reads as. With `>` the value means what it says: 0
        // tracks none, 1 tracks one, the default 10 tracks ten.
        //
        // This caps TRACKING only. Chrome follows redirects natively whatever
        // this says, so bailing here does not stop the navigation; it leaves
        // `redirected` false and `finalUrl` at the original, which means the
        // destination is never added to the first-party set and so stays
        // eligible for filterRegex/dig capture. Verified against a cross-host
        // 302: even at 0 the landed page is still loaded and its requests are
        // still captured.
        if (redirectChain.length > maxRedirects) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached, stopping redirect chain`));
          }
          return; // Stop processing more redirects
        }
        redirectChain.push(frameUrl);
        redirectChainSet.add(frameUrl);
        finalUrl = frameUrl;
        redirected = true;
        
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Frame navigation detected: ${frameUrl}`));
        }
      }
    }
  };

  // Monitor JavaScript redirects by intercepting location changes
  const jsRedirectDetector = async () => {
    try {
      // Validate page state before injection
      if (!page || page.isClosed()) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', 'JS redirect detector skipped - page closed'));
        }
        return;
      }
      
      // Check if browser is still connected
      if (!page.browser().connected) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', 'JS redirect detector skipped - browser disconnected'));
        }
        return;
      }

      await page.evaluateOnNewDocument(() => {
        // Flags read by the poll loop below. Set FIRST so they exist even if
        // everything after this fails.
        window._jsRedirectDetected = false;
        window._jsRedirectUrl = null;
        window._jsRedirectType = null;

        // There are deliberately NO location.replace / location.assign /
        // location.href hooks here any more: they could not work. In current
        // Chrome window.location's properties are non-writable and
        // non-configurable, so the assignments silently no-opped and
        // Object.defineProperty(window.location, 'href', ...) threw
        // "TypeError: Cannot redefine property: href" -- measured directly, along
        // with configurable:false on the descriptor.
        //
        // Because that throw happened inside an evaluateOnNewDocument script,
        // Puppeteer never surfaced it as a page error, and it aborted the rest of
        // this function -- so the MutationObserver below was never installed
        // either. Meta-refresh detection silently did nothing and
        // _jsRedirectDetected stayed false forever, which is why every tracked
        // hop logged as "URL change detected" (the framenavigated handler
        // comparing URLs) rather than "JavaScript redirect detected", and why the
        // poll loop's detected-branches were unreachable.
        //
        // Everything below is wrapped so one failure cannot take the rest with it
        // again.
        try {
          const noteMetaRefresh = (content) => {
            if (!content) return;
            window._jsRedirectDetected = true;
            window._jsRedirectUrl = content;
            window._jsRedirectType = 'meta.refresh';
          };

          const isMetaRefresh = (node) => {
            if (!node || node.nodeName !== 'META' || !node.getAttribute) return false;
            const equiv = node.getAttribute('http-equiv');
            return !!equiv && equiv.toLowerCase() === 'refresh';
          };

          // Nodes added later -- the usual case, since the parser inserts <meta>
          // during load, after this script has already run.
          const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
              for (const node of mutation.addedNodes) {
                if (isMetaRefresh(node)) noteMetaRefresh(node.getAttribute('content'));
              }
            }
          });

          // A meta refresh ALREADY in the DOM is invisible to the observer, which
          // only reports additions, so sweep once as a backstop when observing
          // starts.
          const sweepExisting = () => {
            try {
              const nodes = document.querySelectorAll('meta[http-equiv]');
              for (const node of nodes) {
                if (isMetaRefresh(node)) { noteMetaRefresh(node.getAttribute('content')); return; }
              }
            } catch (_) { /* observer still covers additions */ }
          };

          const startObserving = () => {
            if (!document.head) return false;
            observer.observe(document.head, { childList: true, subtree: true });
            sweepExisting();
            return true;
          };

          if (!startObserving()) {
            document.addEventListener('DOMContentLoaded', startObserving);
          }
        } catch (_) {
          // Detector unavailable. The framenavigated handler still tracks hops,
          // so this degrades to exactly the behaviour that shipped before.
        }
      });
    } catch (jsErr) {
      if (jsErr.message.includes('Session closed') || 
          jsErr.message.includes('Target closed') ||
          jsErr.message.includes('Protocol error')) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', 'JS redirect detector skipped - session ended'));
        }
        return;
      } else if (forceDebug) {
        console.log(formatLogMessage('debug', `Failed to inject JS redirect detector: ${jsErr.message}`));
      }
    }
  };

  try {
    // Set up event listeners
    page.on('framenavigated', navigationHandler);
    
    // Inject JavaScript redirect detection
    await jsRedirectDetector();

    if (forceDebug) {
      // Avoid Object.keys allocation just to check emptiness — a for...in
      // early-exit on the first own key is enough.
      let hasOpts = false;
      for (const _k in gotoOptions) { hasOpts = true; break; }
      if (hasOpts) {
        console.log(formatLogMessage('debug', `Using goto options: ${JSON.stringify(gotoOptions)}`));
      }
    }

    // Initial navigation. Puppeteer's page.goto returns the response for the
    // last HTTP request in the chain (it follows HTTP redirects internally),
    // so response.status() reflects the page that actually rendered, not the
    // 301/302 hop. JS redirects via window.location detected later in this
    // function will land on a different page, in which case httpStatus/cfRay
    // captured here are pre-JS-redirect — a known limitation.
    const response = await page.goto(currentUrl, gotoOptions);
    if (response) {
      try {
        httpStatus = response.status();
        const headers = response.headers();
        if (headers && headers['cf-ray']) cfRay = headers['cf-ray'];
      } catch (_) { /* response disposed or detached — fine, stays null */ }
    }

    if (response && response.url() !== currentUrl && !response.url().startsWith('chrome-error://')) {
      // Check redirect limit before adding
      if (redirectChain.length > maxRedirects) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached during HTTP redirect`));
        }
        finalUrl = currentUrl; // Keep original URL
      } else {
        finalUrl = response.url();
        redirected = true;
        if (!redirectChainSet.has(finalUrl)) { redirectChain.push(finalUrl); redirectChainSet.add(finalUrl); }
      }
      if (forceDebug) {
        console.log(formatLogMessage('debug', `HTTP redirect detected: ${currentUrl} -> ${finalUrl}`));
      }
    }

    // Wait for potential JavaScript redirects.
    //
    // The shape here is easy to misread, so: the loop does NOT spend
    // jsRedirectTimeout. It sleeps ONE poll interval, checks, and normally stops
    // -- so the effective budget is jsRedirectTimeout / JS_REDIRECT_POLLS, and a
    // redirect that lands later than that is simply not tracked (the page still
    // loads and its requests are still captured either way; only the chain,
    // finalUrl and the first-party promotion depend on tracking).
    //
    // Why it normally stops after one poll: the in-page detector is installed
    // with evaluateOnNewDocument, so `window._jsRedirectDetected` is reset to
    // false on every new document. Once a hop commits, the next poll reads the
    // FRESH document's flag as false and the "no activity" break below fires.
    // The retry path is therefore reserved for the genuine race it was written
    // for -- the hooks saw location.href/replace/assign execute, but the
    // navigation has not committed yet, so the flag is true while the URL is
    // unchanged. JS_REDIRECT_POLLS bounds how many times that race is re-checked;
    // it is not a budget multiplier.
    const JS_REDIRECT_POLLS = 3;
    const jsPollIntervalMs = jsRedirectTimeout / JS_REDIRECT_POLLS;
    if (forceDebug) {
      if (jsRedirectTimeout === 0) {
        console.log(formatLogMessage('debug', `js_redirect_timeout: 0 — skipping the JavaScript-redirect wait entirely (HTTP 30x redirects are still tracked)`));
      } else {
        console.log(formatLogMessage('debug', `Polling up to ${JS_REDIRECT_POLLS}x${Math.round(jsPollIntervalMs)}ms for JavaScript redirects (first quiet poll stops it, so normally ~${Math.round(jsPollIntervalMs)}ms)...`));
      }
    }

    let pendingRedirectRechecks = 0;

    while (jsRedirectTimeout > 0 && pendingRedirectRechecks < JS_REDIRECT_POLLS) {
      await new Promise(resolve => setTimeout(resolve, jsPollIntervalMs));
      
      try {
        // Check for JavaScript redirect detection
        const jsRedirectResult = await page.evaluate(() => {
          return {
            detected: window._jsRedirectDetected || false,
            url: window._jsRedirectUrl || null,
            type: window._jsRedirectType || null,
            currentUrl: window.location.href
          };
        });
        
        // Check if URL changed (either through JS redirect or automatic redirect).
        // Skip chrome-error://* — it's Puppeteer's landing page on DNS/connection
        // failure and adding it to the chain produces bogus intermediate hops.
        const currentPageUrl = page.url();
        if (currentPageUrl && currentPageUrl !== finalUrl && !currentPageUrl.startsWith('chrome-error://') && !redirectChainSet.has(currentPageUrl)) {
          // Check redirect limit before adding
          if (redirectChain.length > maxRedirects) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached during JS redirect detection`));
            }
            break; // Stop processing more redirects
          }
          redirectChain.push(currentPageUrl);
          redirectChainSet.add(currentPageUrl);
          finalUrl = currentPageUrl;
          redirected = true;
          
          if (forceDebug) {
            if (jsRedirectResult.detected) {
              console.log(formatLogMessage('debug', `JavaScript redirect detected (${jsRedirectResult.type}): ${jsRedirectResult.url || currentPageUrl}`));
            } else {
              console.log(formatLogMessage('debug', `URL change detected: ${currentPageUrl}`));
            }
          }
        }
        
        // If JS redirect was explicitly detected but URL hasn't changed yet, wait a bit more
        if (jsRedirectResult.detected && !redirected) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `JS redirect detected (${jsRedirectResult.type}) but not yet executed, waiting...`));
          }
          pendingRedirectRechecks++;
          continue;
        }
        
        // If no new redirects detected, break out of loop
        if (!jsRedirectResult.detected) {
          break;
        }
        
      } catch (evalErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Error checking JS redirects: ${evalErr.message}`));
        }
        break;
      }
      
      pendingRedirectRechecks++;
    }

    // Optional: Detect common JavaScript redirect patterns in page source
    if (detectJSPatterns) {
      await detectCommonJSRedirects(page, forceDebug, formatLogMessage);
    }

    // Final URL check. Same chrome-error://* skip as the earlier branches —
    // a navigation that ended in a chrome-error landing shouldn't be treated
    // as the "final" URL of a successful redirect chain.
    const finalPageUrl = page.url();
    if (finalPageUrl && finalPageUrl !== finalUrl && !finalPageUrl.startsWith('chrome-error://')) {
      // Check redirect limit before final update
      if (redirectChain.length > maxRedirects) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached, keeping current finalUrl`));
        }
      } else {
        finalUrl = finalPageUrl;
        redirected = true;
        if (!redirectChainSet.has(finalUrl)) {
          redirectChain.push(finalUrl);
          redirectChainSet.add(finalUrl);
        }
      }
    }

  } finally {
    page.off('framenavigated', navigationHandler);
  }

  // Log redirect summary
  if (redirected && forceDebug) {
    console.log(formatLogMessage('debug', `Redirect chain: ${redirectChain.join(' -> ')}`));
  }

  // Extract intermediate redirect domains (exclude the final entry). Single
  // loop instead of slice().map().filter() — three array allocations down to
  // one push-loop. redirectChain is bounded at maxRedirects (default 10).
  const redirectDomains = [];
  if (redirected && redirectChain.length > 1) {
    for (let i = 0; i < redirectChain.length - 1; i++) {
      try {
        redirectDomains.push(new URL(redirectChain[i]).hostname);
      } catch (_) { /* skip malformed entries */ }
    }
  }

  return { finalUrl, redirected, redirectChain, originalUrl: currentUrl, redirectDomains, httpStatus, cfRay };
}

/**
 * Detect common JavaScript redirect patterns in page source
 * @param {Page} page - Puppeteer page instance
 * @param {boolean} forceDebug - Debug logging flag
 * @param {Function} formatLogMessage - Log formatting function
 * @returns {Promise<Array>} Array of detected patterns
 */
async function detectCommonJSRedirects(page, forceDebug = false, formatLogMessage) {
  // This function's only externally-visible behavior is the per-pattern
  // debug log below. The return value isn't read by any caller. Bail
  // before the expensive page.evaluate + outerHTML serialization when
  // there's no debug consumer for the result.
  if (!forceDebug) return [];

  try {
    const redirectPatterns = await page.evaluate(() => {
      const patterns = [];

      // Cap the source read to 100KB. document.documentElement.outerHTML
      // materializes the full page (potentially many MB on content-heavy
      // sites) AND serializes it over CDP back to Node. JS redirects all
      // appear early — in head meta tags or top-of-body inline scripts —
      // so a head-anchored cap is enough for real-world coverage.
      const pageSource = document.documentElement.outerHTML.substring(0, 100000);

      // Pattern 1: window.location = "url"
      const locationAssign = pageSource.match(/window\.location\s*=\s*["']([^"']+)["']/g);
      if (locationAssign) {
        patterns.push({ type: 'window.location assignment', matches: locationAssign });
      }
      
      // Pattern 2: location.href = "url"
      const hrefAssign = pageSource.match(/location\.href\s*=\s*["']([^"']+)["']/g);
      if (hrefAssign) {
        patterns.push({ type: 'location.href assignment', matches: hrefAssign });
      }
      
      // Pattern 3: setTimeout redirects
      const timeoutRedirect = pageSource.match(/setTimeout\s*\([^)]*location[^)]*\)/g);
      if (timeoutRedirect) {
        patterns.push({ type: 'setTimeout redirect', matches: timeoutRedirect });
      }
      
      // Pattern 4: Meta refresh
      const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
      if (metaRefresh) {
        patterns.push({ type: 'meta refresh', content: metaRefresh.getAttribute('content') });
      }
      
      // Pattern 5: document.location redirects
      const docLocationAssign = pageSource.match(/document\.location\s*=\s*["']([^"']+)["']/g);
      if (docLocationAssign) {
        patterns.push({ type: 'document.location assignment', matches: docLocationAssign });
      }
      
      return patterns;
    });
    
    if (redirectPatterns.length > 0 && forceDebug) {
      console.log(formatLogMessage('debug', `Found ${redirectPatterns.length} potential JS redirect pattern(s):`));
      redirectPatterns.forEach((pattern, idx) => {
        console.log(formatLogMessage('debug', `  [${idx + 1}] ${pattern.type}: ${JSON.stringify(pattern.matches || pattern.content)}`));
      });
    }
    
    return redirectPatterns;
    
  } catch (detectErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Error detecting JS redirect patterns: ${detectErr.message}`));
    }
    return [];
  }
}

/**
 * Enhanced timeout error handling for partial redirects
 * @param {Page} page - Puppeteer page instance
 * @param {string} originalUrl - Original URL that was requested
 * @param {Error} error - Navigation timeout error
 * @param {Function} safeGetDomain - Domain extraction function
 * @param {boolean} forceDebug - Debug logging flag
 * @param {Function} formatLogMessage - Log formatting function
 * @returns {Promise<{success: boolean, finalUrl: string, redirected: boolean}>}
 */
async function handleRedirectTimeout(page, originalUrl, error, safeGetDomain, forceDebug = false, formatLogMessage) {
  if (!error.message.includes('Navigation timeout')) {
    return { success: false, finalUrl: originalUrl, redirected: false };
  }
  
  try {
    const currentPageUrl = page.url();
    // Skip chrome-error://* the same way navigateWithRedirectHandling does:
    // a DNS/connection-failure landing isn't a "partial redirect recovery",
    // and safeGetDomain('chrome-error://chromewebdata/') returns
    // 'chromewebdata', which would otherwise differ from the original
    // domain and falsely report success here.
    if (currentPageUrl
        && currentPageUrl !== 'about:blank'
        && !currentPageUrl.startsWith('chrome-error://')
        && currentPageUrl !== originalUrl) {
      const originalDomain = safeGetDomain(originalUrl);
      const currentDomain = safeGetDomain(currentPageUrl);

      if (originalDomain !== currentDomain) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Partial redirect timeout recovered: ${originalDomain} -> ${currentDomain}`));
        }
        return { success: true, finalUrl: currentPageUrl, redirected: true };
      }
    }
    return { success: false, finalUrl: originalUrl, redirected: false };
  } catch (urlError) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Error during timeout recovery: ${urlError.message}`));
    }
    return { success: false, finalUrl: originalUrl, redirected: false };
  }
}

module.exports = {
  navigateWithRedirectHandling,
  detectCommonJSRedirects,
  handleRedirectTimeout
};
