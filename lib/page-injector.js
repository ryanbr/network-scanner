// === Page Script Injection Module ===
// This module handles script injection into pages using evaluateOnNewDocument.
// It provides methods to inject various monitoring and interception scripts.

/**
 * PageInjector class handles script injection into pages before they load.
 * Supports fetch/XHR interception, custom script injection, and monitoring.
 */
class PageInjector {
  constructor() {
    this.debugMode = false;
    this.injectedScripts = new Map(); // Track what's been injected per page
  }

  /**
   * Initialize the page injector
   * @param {boolean} debugMode - Enable debug logging
   */
  initialize(debugMode = false) {
    this.debugMode = debugMode;
    
    if (this.debugMode) {
      console.log(`[debug][page-injector] Page injector initialized`);
    }
  }

  /**
   * Generate the fetch/XHR interception script
   * @param {object} options - Configuration options for the interceptor
   * @returns {string} The interceptor script as a string
   */
  generateFetchXHRInterceptor(options = {}) {
    const {
      logPrefix = '[evalOnDoc]',
      enableFetch = true,
      enableXHR = true,
      logToConsole = true,
      customHandler = null
    } = options;

    return `
      (function() {
        const logPrefix = '${logPrefix}';
        const enableFetch = ${enableFetch};
        const enableXHR = ${enableXHR};
        const logToConsole = ${logToConsole};
        
        // Fetch interception
        if (enableFetch && window.fetch) {
          const originalFetch = window.fetch;
          window.fetch = function(...args) {
            const url = args[0];
            if (logToConsole) {
              console.log(logPrefix + '[fetch]', url);
            }
            
            // Custom handler if provided
            ${customHandler ? `(${customHandler})(url, 'fetch');` : ''}
            
            return originalFetch.apply(this, args);
          };
        }
        
        // XHR interception
        if (enableXHR && window.XMLHttpRequest) {
          const originalXHROpen = XMLHttpRequest.prototype.open;
          XMLHttpRequest.prototype.open = function(method, xhrUrl) {
            if (logToConsole) {
              console.log(logPrefix + '[xhr]', xhrUrl);
            }
            
            // Custom handler if provided
            ${customHandler ? `(${customHandler})(xhrUrl, 'xhr');` : ''}
            
            return originalXHROpen.apply(this, arguments);
          };
        }
        
        // Mark as injected
        window.__pageInjectorActive = true;
      })();
    `;
  }

  /**
   * Generate a custom monitoring script
   * @param {object} options - Configuration options for monitoring
   * @returns {string} The monitoring script as a string
   */
  generateMonitoringScript(options = {}) {
    const {
      monitorDOMChanges = false,
      monitorWindowEvents = false,
      monitorErrors = false,
      logPrefix = '[monitor]'
    } = options;

    return `
      (function() {
        const logPrefix = '${logPrefix}';
        
        // DOM mutation monitoring
        if (${monitorDOMChanges}) {
          const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
              if (mutation.addedNodes.length > 0) {
                console.log(logPrefix + '[dom-added]', mutation.addedNodes.length, 'nodes');
              }
            });
          });
          
          if (document.body) {
            observer.observe(document.body, { childList: true, subtree: true });
          } else {
            document.addEventListener('DOMContentLoaded', function() {
              observer.observe(document.body, { childList: true, subtree: true });
            });
          }
        }
        
        // Window events monitoring
        if (${monitorWindowEvents}) {
          ['load', 'beforeunload', 'focus', 'blur'].forEach(function(eventType) {
            window.addEventListener(eventType, function() {
              console.log(logPrefix + '[window-event]', eventType);
            });
          });
        }
        
        // Error monitoring
        if (${monitorErrors}) {
          window.addEventListener('error', function(event) {
            console.log(logPrefix + '[error]', event.message, event.filename, event.lineno);
          });
          
          window.addEventListener('unhandledrejection', function(event) {
            console.log(logPrefix + '[promise-rejection]', event.reason);
          });
        }
      })();
    `;
  }

  /**
   * Inject fetch/XHR interception script into a page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {boolean|object} enabled - Enable interception or options object
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async injectFetchXHRInterceptor(page, enabled, currentUrl = 'unknown') {
    if (!enabled) {
      return true; // Not enabled, no injection needed
    }

    try {
      // Handle both boolean and object configurations
      const options = typeof enabled === 'object' ? enabled : {};
      
      if (this.debugMode) {
        console.log(`[debug][page-injector] Injecting Fetch/XHR interceptor for ${currentUrl}`);
      }

      const script = this.generateFetchXHRInterceptor(options);
      
      await page.evaluateOnNewDocument(script);
      
      // Track what was injected
      const pageId = this.getPageId(page);
      if (!this.injectedScripts.has(pageId)) {
        this.injectedScripts.set(pageId, []);
      }
      this.injectedScripts.get(pageId).push('fetchXHRInterceptor');
      
      return true;

    } catch (error) {
      console.warn(`[warn][page-injector] Failed to inject Fetch/XHR interceptor for ${currentUrl}: ${error.message}`);
      return false;
    }
  }

  /**
   * Inject custom monitoring script into a page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {object} options - Monitoring options
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async injectMonitoringScript(page, options = {}, currentUrl = 'unknown') {
    if (!options || Object.keys(options).length === 0) {
      return true; // No monitoring needed
    }

    try {
      if (this.debugMode) {
        console.log(`[debug][page-injector] Injecting monitoring script for ${currentUrl}`);
      }

      const script = this.generateMonitoringScript(options);
      
      await page.evaluateOnNewDocument(script);
      
      // Track what was injected
      const pageId = this.getPageId(page);
      if (!this.injectedScripts.has(pageId)) {
        this.injectedScripts.set(pageId, []);
      }
      this.injectedScripts.get(pageId).push('monitoringScript');
      
      return true;

    } catch (error) {
      console.warn(`[warn][page-injector] Failed to inject monitoring script for ${currentUrl}: ${error.message}`);
      return false;
    }
  }

  /**
   * Inject a custom script into a page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {string|function} script - The script to inject (string or function)
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @param {string} scriptName - Name for tracking purposes
   * @returns {Promise<boolean>} Success status
   */
  async injectCustomScript(page, script, currentUrl = 'unknown', scriptName = 'custom') {
    if (!script) {
      return true; // No script to inject
    }

    try {
      if (this.debugMode) {
        console.log(`[debug][page-injector] Injecting custom script '${scriptName}' for ${currentUrl}`);
      }

      // Handle both string scripts and functions
      if (typeof script === 'function') {
        await page.evaluateOnNewDocument(script);
      } else {
        await page.evaluateOnNewDocument(script);
      }
      
      // Track what was injected
      const pageId = this.getPageId(page);
      if (!this.injectedScripts.has(pageId)) {
        this.injectedScripts.set(pageId, []);
      }
      this.injectedScripts.get(pageId).push(scriptName);
      
      return true;

    } catch (error) {
      console.warn(`[warn][page-injector] Failed to inject custom script '${scriptName}' for ${currentUrl}: ${error.message}`);
      return false;
    }
  }

  /**
   * Apply all configured injections for a page based on site configuration
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {object} siteConfig - Site configuration object
   * @param {boolean} globalEvalOnDoc - Global eval on doc setting
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<{fetchXHR: boolean, monitoring: boolean, custom: boolean}>} Success status for each injection type
   */
  async applyPageInjections(page, siteConfig, globalEvalOnDoc, currentUrl = 'unknown') {
    const results = {
      fetchXHR: true,
      monitoring: true,
      custom: true
    };

    // Fetch/XHR interception
    const shouldInjectFetchXHR = siteConfig.evaluateOnNewDocument === true || globalEvalOnDoc;
    if (shouldInjectFetchXHR) {
      if (this.debugMode) {
        if (globalEvalOnDoc) {
          console.log(`[debug][page-injector] Global Fetch/XHR interception enabled, applying to: ${currentUrl}`);
        } else {
          console.log(`[debug][page-injector] Site-specific Fetch/XHR interception enabled for: ${currentUrl}`);
        }
      }
      
      results.fetchXHR = await this.injectFetchXHRInterceptor(page, true, currentUrl);
    }

    // Custom monitoring (if configured in site config)
    if (siteConfig.monitoring) {
      results.monitoring = await this.injectMonitoringScript(page, siteConfig.monitoring, currentUrl);
    }

    // Custom scripts (if configured in site config)
    if (siteConfig.customScripts) {
      const customScripts = Array.isArray(siteConfig.customScripts) ? siteConfig.customScripts : [siteConfig.customScripts];
      
      for (let i = 0; i < customScripts.length; i++) {
        const scriptResult = await this.injectCustomScript(page, customScripts[i], currentUrl, `custom-${i}`);
        results.custom = results.custom && scriptResult;
      }
    }

    return results;
  }

  /**
   * Check if scripts are active on a page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @returns {Promise<boolean>} True if injected scripts are active
   */
  async areScriptsActive(page) {
    try {
      const isActive = await page.evaluate(() => {
        return window.__pageInjectorActive === true;
      });
      return isActive;
    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][page-injector] Failed to check script status: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Get a unique identifier for a page (for tracking purposes)
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @returns {string} Unique page identifier
   */
  getPageId(page) {
    // Use page target ID as unique identifier
    try {
      return page.target()._targetId || `page-${Date.now()}-${Math.random()}`;
    } catch (error) {
      return `page-${Date.now()}-${Math.random()}`;
    }
  }

  /**
   * Clean up tracking for a page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   */
  cleanupPage(page) {
    try {
      const pageId = this.getPageId(page);
      if (this.injectedScripts.has(pageId)) {
        if (this.debugMode) {
          const scripts = this.injectedScripts.get(pageId);
          console.log(`[debug][page-injector] Cleaning up tracking for page with ${scripts.length} injected scripts`);
        }
        this.injectedScripts.delete(pageId);
      }
    } catch (error) {
      // Ignore cleanup errors
    }
  }

  /**
   * Get statistics about page injections
   * @returns {object} Statistics object
   */
  getStats() {
    const totalPages = this.injectedScripts.size;
    const totalScripts = Array.from(this.injectedScripts.values()).reduce((sum, scripts) => sum + scripts.length, 0);
    
    return {
      totalPages,
      totalScripts,
      supportedInjections: ['fetchXHRInterceptor', 'monitoringScript', 'customScript'],
      activePages: Array.from(this.injectedScripts.keys())
    };
  }

  /**
   * Create a preset configuration for common use cases
   * @param {string} preset - Preset name ('basic', 'monitoring', 'debug')
   * @returns {object} Configuration object
   */
  getPresetConfig(preset) {
    const presets = {
      basic: {
        evaluateOnNewDocument: true
      },
      monitoring: {
        evaluateOnNewDocument: true,
        monitoring: {
          monitorDOMChanges: true,
          monitorWindowEvents: true,
          monitorErrors: false
        }
      },
      debug: {
        evaluateOnNewDocument: true,
        monitoring: {
          monitorDOMChanges: true,
          monitorWindowEvents: true,
          monitorErrors: true
        }
      }
    };

    return presets[preset] || presets.basic;
  }
}

// Export the class and create a default instance
const pageInjector = new PageInjector();

module.exports = {
  PageInjector,
  pageInjector
};
