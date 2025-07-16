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
  let finalUrl = currentUrl;
  let redirected = false;
  const jsRedirectTimeout = siteConfig.js_redirect_timeout || 5000; // Wait 5s for JS redirects
  const maxRedirects = siteConfig.max_redirects || 10;
  const detectJSPatterns = siteConfig.detect_js_patterns !== false; // Default to true

  // Monitor frame navigations to detect redirects
  const navigationHandler = (frame) => {
    if (frame === page.mainFrame()) {
      const frameUrl = frame.url();
      if (frameUrl && frameUrl !== 'about:blank' && !redirectChain.includes(frameUrl)) {
        // Check redirect limit before adding
        if (redirectChain.length >= maxRedirects) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached, stopping redirect chain`));
          }
          return; // Stop processing more redirects
        }
        redirectChain.push(frameUrl);
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
      await page.evaluateOnNewDocument(() => {
        // Store original location methods
        const originalReplace = window.location.replace;
        const originalAssign = window.location.assign;
        const originalHrefSetter = Object.getOwnPropertyDescriptor(window.location, 'href')?.set;
        
        // Flag to track if JS redirect occurred
        window._jsRedirectDetected = false;
        window._jsRedirectUrl = null;
        window._jsRedirectType = null;
        
        // Intercept location.replace()
        window.location.replace = function(url) {
          window._jsRedirectDetected = true;
          window._jsRedirectUrl = url;
          window._jsRedirectType = 'location.replace';
          console.log('[jsRedirect] location.replace:', url);
          return originalReplace.call(this, url);
        };
        
        // Intercept location.assign()
        window.location.assign = function(url) {
          window._jsRedirectDetected = true;
          window._jsRedirectUrl = url;
          window._jsRedirectType = 'location.assign';
          console.log('[jsRedirect] location.assign:', url);
          return originalAssign.call(this, url);
        };
        
        // Intercept location.href setter
        if (originalHrefSetter) {
          Object.defineProperty(window.location, 'href', {
            set: function(url) {
              window._jsRedirectDetected = true;
              window._jsRedirectUrl = url;
              window._jsRedirectType = 'location.href';
              console.log('[jsRedirect] location.href set:', url);
              return originalHrefSetter.call(this, url);
            },
            get: function() {
              return window.location.toString();
            }
          });
        }
        
        // Monitor meta refresh redirects
        const observer = new MutationObserver((mutations) => {
          mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
              if (node.nodeName === 'META' && 
                  node.getAttribute && 
                  node.getAttribute('http-equiv') === 'refresh') {
                const content = node.getAttribute('content');
                if (content) {
                  window._jsRedirectDetected = true;
                  window._jsRedirectUrl = content;
                  window._jsRedirectType = 'meta.refresh';
                  console.log('[jsRedirect] meta refresh:', content);
                }
              }
            });
          });
        });
        
        // Start observing when DOM is ready
        if (document.head) {
          observer.observe(document.head, { childList: true, subtree: true });
        } else {
          document.addEventListener('DOMContentLoaded', () => {
            if (document.head) {
              observer.observe(document.head, { childList: true, subtree: true });
            }
          });
        }
      });
    } catch (jsErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Failed to inject JS redirect detector: ${jsErr.message}`));
      }
    }
  };

  try {
    // Set up event listeners
    page.on('framenavigated', navigationHandler);
    
    // Inject JavaScript redirect detection
    await jsRedirectDetector();

    if (forceDebug && Object.keys(gotoOptions).length > 0) {
      console.log(formatLogMessage('debug', `Using goto options: ${JSON.stringify(gotoOptions)}`));
    }

    // Initial navigation
    const response = await page.goto(currentUrl, gotoOptions);
    
    if (response && response.url() !== currentUrl) {
      // Check redirect limit before adding
      if (redirectChain.length >= maxRedirects) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached during HTTP redirect`));
        }
        finalUrl = currentUrl; // Keep original URL
      } else {
      finalUrl = response.url();
      redirected = true;
      if (!redirectChain.includes(finalUrl)) redirectChain.push(finalUrl);
      }
      if (forceDebug) {
        console.log(formatLogMessage('debug', `HTTP redirect detected: ${currentUrl} ? ${finalUrl}`));
      }
    }

    // Wait for potential JavaScript redirects
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Waiting ${jsRedirectTimeout}ms for potential JavaScript redirects...`));
    }
    
    let jsRedirectAttempts = 0;
    const maxJsRedirectAttempts = 3;
    
    while (jsRedirectAttempts < maxJsRedirectAttempts) {
      await new Promise(resolve => setTimeout(resolve, jsRedirectTimeout / maxJsRedirectAttempts));
      
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
        
        // Check if URL changed (either through JS redirect or automatic redirect)
        const currentPageUrl = page.url();
        if (currentPageUrl && currentPageUrl !== finalUrl && !redirectChain.includes(currentPageUrl)) {
          // Check redirect limit before adding
          if (redirectChain.length >= maxRedirects) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached during JS redirect detection`));
            }
            break; // Stop processing more redirects
          }
          redirectChain.push(currentPageUrl);
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
          jsRedirectAttempts++;
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
      
      jsRedirectAttempts++;
    }

    // Optional: Detect common JavaScript redirect patterns in page source
    if (detectJSPatterns) {
      await detectCommonJSRedirects(page, forceDebug, formatLogMessage);
    }

    // Final URL check
    const finalPageUrl = page.url();
    if (finalPageUrl && finalPageUrl !== finalUrl) {
      // Check redirect limit before final update
      if (redirectChain.length >= maxRedirects) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Maximum redirects (${maxRedirects}) reached, keeping current finalUrl`));
        }
      } else {
      finalUrl = finalPageUrl;
      redirected = true;
      if (!redirectChain.includes(finalUrl)) {
        redirectChain.push(finalUrl);
      }
     }
    }

  } finally {
    page.off('framenavigated', navigationHandler);
  }

  // Log redirect summary
  if (redirected && forceDebug) {
    console.log(formatLogMessage('debug', `Redirect chain: ${redirectChain.join(' ? ')}`));
  }

  // Extract redirect domains to exclude from matching
  let redirectDomains = [];
  if (redirected && redirectChain.length > 1) {
    // Get all intermediate domains (exclude the final domain)
    const intermediateDomains = redirectChain.slice(0, -1).map(url => {
      try {
        return new URL(url).hostname;
      } catch {
        return null;
      }
    }).filter(Boolean);
    redirectDomains = intermediateDomains;
  }

  return { finalUrl, redirected, redirectChain, originalUrl: currentUrl, redirectDomains };
}

/**
 * Detect common JavaScript redirect patterns in page source
 * @param {Page} page - Puppeteer page instance
 * @param {boolean} forceDebug - Debug logging flag
 * @param {Function} formatLogMessage - Log formatting function
 * @returns {Promise<Array>} Array of detected patterns
 */
async function detectCommonJSRedirects(page, forceDebug = false, formatLogMessage) {
  try {
    const redirectPatterns = await page.evaluate(() => {
      const patterns = [];
      
      // Check for common redirect patterns in page source
      const pageSource = document.documentElement.outerHTML;
      
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
    if (currentPageUrl && currentPageUrl !== 'about:blank' && currentPageUrl !== originalUrl) {
      const originalDomain = safeGetDomain(originalUrl);
      const currentDomain = safeGetDomain(currentPageUrl);
      
      if (originalDomain !== currentDomain) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Partial redirect timeout recovered: ${originalDomain} ? ${currentDomain}`));
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
