// === CSS Element Blocking Module ===
// This module handles CSS-based element blocking functionality for the network scanner script.
// It provides methods to hide elements using CSS selectors before and after page load.

/**
 * CSSBlocker class handles CSS-based element blocking using selectors.
 * Supports both pre-load injection (evaluateOnNewDocument) and runtime application.
 */
class CSSBlocker {
  constructor() {
    this.debugMode = false;
  }

  /**
   * Initialize the CSS blocker
   * @param {boolean} debugMode - Enable debug logging
   */
  initialize(debugMode = false) {
    this.debugMode = debugMode;
    
    if (this.debugMode) {
      console.log(`[debug][css-blocker] CSS blocker initialized`);
    }
  }

  /**
   * Validate and sanitize CSS selectors
   * @param {Array} selectors - Array of CSS selectors to validate
   * @returns {Array} Array of valid CSS selectors
   */
  validateSelectors(selectors) {
    if (!Array.isArray(selectors)) {
      return [];
    }

    const validSelectors = [];
    
    for (const selector of selectors) {
      if (typeof selector !== 'string' || !selector.trim()) {
        if (this.debugMode) {
          console.warn(`[debug][css-blocker] Skipping invalid selector: ${selector}`);
        }
        continue;
      }

      const trimmedSelector = selector.trim();
      
      // Basic validation - check if it looks like a CSS selector
      if (this.isValidCSSSelector(trimmedSelector)) {
        validSelectors.push(trimmedSelector);
      } else {
        if (this.debugMode) {
          console.warn(`[debug][css-blocker] Skipping potentially unsafe selector: ${trimmedSelector}`);
        }
      }
    }

    return validSelectors;
  }

  /**
   * Basic CSS selector validation
   * @param {string} selector - CSS selector to validate
   * @returns {boolean} True if selector appears valid
   */
  isValidCSSSelector(selector) {
    // Allow common CSS selector patterns
    const validPattern = /^[#.]?[\w\-\[\]=":(),\s>+~*]+$/;
    
    // Reject potentially dangerous patterns
    const dangerousPatterns = [
      /javascript:/i,
      /expression\s*\(/i,
      /url\s*\(/i,
      /@import/i,
      /behavior\s*:/i
    ];

    if (!validPattern.test(selector)) {
      return false;
    }

    for (const dangerousPattern of dangerousPatterns) {
      if (dangerousPattern.test(selector)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Generate CSS rules to hide elements
   * @param {Array} selectors - Array of CSS selectors
   * @returns {string} CSS rules string
   */
  generateCSSRules(selectors) {
    const validSelectors = this.validateSelectors(selectors);
    
    if (validSelectors.length === 0) {
      return '';
    }

    const cssRules = validSelectors.map(selector => 
      `${selector} { display: none !important; visibility: hidden !important; opacity: 0 !important; }`
    ).join('\n');

    if (this.debugMode) {
      console.log(`[debug][css-blocker] Generated CSS rules for ${validSelectors.length} selectors`);
    }

    return cssRules;
  }

  /**
   * Apply CSS blocking before page load using evaluateOnNewDocument
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {Array} selectors - Array of CSS selectors to block
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async applyPreLoadBlocking(page, selectors, currentUrl = 'unknown') {
    if (!selectors || !Array.isArray(selectors) || selectors.length === 0) {
      return true; // No blocking needed
    }

    try {
      const validSelectors = this.validateSelectors(selectors);
      
      if (validSelectors.length === 0) {
        if (this.debugMode) {
          console.warn(`[debug][css-blocker] No valid selectors found for ${currentUrl}`);
        }
        return true;
      }

      if (this.debugMode) {
        console.log(`[debug][css-blocker] Applying pre-load CSS blocking for ${currentUrl}: ${validSelectors.join(', ')}`);
      }

      await page.evaluateOnNewDocument(({ selectors }) => {
        // Inject CSS to hide blocked elements as early as possible
        const style = document.createElement('style');
        style.type = 'text/css';
        style.id = 'css-blocker-preload';
        
        const cssRules = selectors.map(selector => 
          `${selector} { display: none !important; visibility: hidden !important; opacity: 0 !important; }`
        ).join('\n');
        
        style.innerHTML = cssRules;
        
        // Add the style as soon as possible
        const addStyle = () => {
          if (document.head) {
            document.head.appendChild(style);
          } else if (document.documentElement) {
            document.documentElement.appendChild(style);
          }
        };

        // Try to add immediately
        addStyle();
        
        // Also add on DOM ready if not already added
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', addStyle);
        }
        
        // Backup: add when head becomes available
        if (!document.head) {
          const observer = new MutationObserver((mutations) => {
            if (document.head) {
              addStyle();
              observer.disconnect();
            }
          });
          
          observer.observe(document.documentElement || document, {
            childList: true,
            subtree: true
          });
        }
      }, { selectors: validSelectors });

      return true;

    } catch (error) {
      console.warn(`[warn][css-blocker] Failed to apply pre-load CSS blocking for ${currentUrl}: ${error.message}`);
      return false;
    }
  }

  /**
   * Apply CSS blocking after page load as a fallback
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {Array} selectors - Array of CSS selectors to block
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async applyRuntimeBlocking(page, selectors, currentUrl = 'unknown') {
    if (!selectors || !Array.isArray(selectors) || selectors.length === 0) {
      return true; // No blocking needed
    }

    try {
      const validSelectors = this.validateSelectors(selectors);
      
      if (validSelectors.length === 0) {
        return true;
      }

      if (this.debugMode) {
        console.log(`[debug][css-blocker] Applying runtime CSS blocking for ${currentUrl}`);
      }

      await page.evaluate((selectors) => {
        // Check if pre-load style already exists
        const existingStyle = document.querySelector('#css-blocker-preload, #css-blocker-runtime');
        
        if (!existingStyle) {
          const style = document.createElement('style');
          style.id = 'css-blocker-runtime';
          style.type = 'text/css';
          
          const cssRules = selectors.map(selector => 
            `${selector} { display: none !important; visibility: hidden !important; opacity: 0 !important; }`
          ).join('\n');
          
          style.innerHTML = cssRules;
          
          if (document.head) {
            document.head.appendChild(style);
          } else if (document.documentElement) {
            document.documentElement.appendChild(style);
          }
        }

        // Also hide any currently visible matching elements
        selectors.forEach(selector => {
          try {
            const elements = document.querySelectorAll(selector);
            elements.forEach(el => {
              el.style.display = 'none';
              el.style.visibility = 'hidden';
              el.style.opacity = '0';
            });
          } catch (selectorError) {
            // Invalid selector, skip it
            console.warn('Invalid CSS selector:', selector);
          }
        });
      }, validSelectors);

      return true;

    } catch (error) {
      console.warn(`[warn][css-blocker] Failed to apply runtime CSS blocking for ${currentUrl}: ${error.message}`);
      return false;
    }
  }

  /**
   * Apply both pre-load and runtime CSS blocking
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {Array} selectors - Array of CSS selectors to block
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<{preLoad: boolean, runtime: boolean}>} Success status for both methods
   */
  async applyFullBlocking(page, selectors, currentUrl = 'unknown') {
    const preLoadResult = await this.applyPreLoadBlocking(page, selectors, currentUrl);
    const runtimeResult = await this.applyRuntimeBlocking(page, selectors, currentUrl);
    
    return {
      preLoad: preLoadResult,
      runtime: runtimeResult,
      success: preLoadResult || runtimeResult // At least one method succeeded
    };
  }

  /**
   * Get statistics about CSS blocking
   * @returns {object} Statistics object
   */
  getStats() {
    return {
      supportedMethods: ['preLoad', 'runtime', 'full'],
      validationEnabled: true
    };
  }

  /**
   * Test if CSS selectors are valid by attempting to use them
   * @param {Array} selectors - Array of CSS selectors to test
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @returns {Promise<Array>} Array of validation results
   */
  async testSelectors(selectors, page) {
    if (!selectors || !Array.isArray(selectors)) {
      return [];
    }

    try {
      const results = await page.evaluate((selectors) => {
        return selectors.map(selector => {
          try {
            document.querySelector(selector);
            return { selector, valid: true, error: null };
          } catch (error) {
            return { selector, valid: false, error: error.message };
          }
        });
      }, selectors);

      if (this.debugMode) {
        const validCount = results.filter(r => r.valid).length;
        console.log(`[debug][css-blocker] Tested ${selectors.length} selectors, ${validCount} valid`);
      }

      return results;
    } catch (error) {
      console.warn(`[warn][css-blocker] Failed to test selectors: ${error.message}`);
      return selectors.map(selector => ({ selector, valid: false, error: error.message }));
    }
  }
}

// Export the class and create a default instance
const cssBlocker = new CSSBlocker();

module.exports = {
  CSSBlocker,
  cssBlocker
};
