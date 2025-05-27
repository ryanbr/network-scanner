// === Chrome DevTools Protocol Manager Module ===
// This module handles CDP (Chrome DevTools Protocol) functionality for the network scanner script.
// It provides methods to monitor network requests, responses, and other browser events.

/**
 * CDPManager class handles Chrome DevTools Protocol sessions and monitoring.
 * Supports network monitoring, security state tracking, and custom event handling.
 */
class CDPManager {
  constructor() {
    this.debugMode = false;
    this.activeSessions = new Map(); // Track active CDP sessions per page
    this.eventHandlers = new Map(); // Custom event handlers
    this.sessionStats = {
      totalSessions: 0,
      activeConnections: 0,
      networkEvents: 0,
      securityEvents: 0,
      errors: 0
    };
  }

  /**
   * Initialize the CDP manager
   * @param {boolean} debugMode - Enable debug logging
   */
  initialize(debugMode = false) {
    this.debugMode = debugMode;
    
    if (this.debugMode) {
      console.log(`[debug][cdp] CDP manager initialized`);
    }
  }

  /**
   * Create and configure a CDP session for a page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {object} config - CDP configuration options
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<{session: object, success: boolean}>} CDP session and success status
   */
  async createCDPSession(page, config = {}, currentUrl = 'unknown') {
    const {
      enableNetwork = true,
      enableSecurity = false,
      enableRuntime = false,
      enablePerformance = false,
      customDomains = [],
      logRequests = true,
      logResponses = false,
      logErrors = true
    } = config;

    let cdpSession = null;

    try {
      if (this.debugMode) {
        console.log(`[debug][cdp] Creating CDP session for ${currentUrl}`);
      }

      // Create CDP session
      cdpSession = await page.target().createCDPSession();
      
      // Enable network monitoring if requested
      if (enableNetwork) {
        await cdpSession.send('Network.enable');
        
        if (logRequests) {
          this.setupNetworkRequestLogging(cdpSession, currentUrl, config);
        }
        
        if (logResponses) {
          this.setupNetworkResponseLogging(cdpSession, currentUrl, config);
        }
      }

      // Enable security monitoring if requested
      if (enableSecurity) {
        await cdpSession.send('Security.enable');
        this.setupSecurityLogging(cdpSession, currentUrl, config);
      }

      // Enable runtime monitoring if requested
      if (enableRuntime) {
        await cdpSession.send('Runtime.enable');
        this.setupRuntimeLogging(cdpSession, currentUrl, config);
      }

      // Enable performance monitoring if requested
      if (enablePerformance) {
        await cdpSession.send('Performance.enable');
        this.setupPerformanceLogging(cdpSession, currentUrl, config);
      }

      // Error handling
      if (logErrors) {
        this.setupErrorLogging(cdpSession, currentUrl);
      }

      // Track the session
      const pageId = this.getPageId(page);
      this.activeSessions.set(pageId, {
        session: cdpSession,
        url: currentUrl,
        config,
        createdAt: Date.now()
      });

      this.sessionStats.totalSessions++;
      this.sessionStats.activeConnections++;

      if (this.debugMode) {
        console.log(`[debug][cdp] CDP session created successfully for ${currentUrl}`);
      }

      return { session: cdpSession, success: true };

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][cdp] Failed to create CDP session for ${currentUrl}: ${error.message}`);
      }

      this.sessionStats.errors++;
      
      // Clean up on failure
      if (cdpSession) {
        try {
          await cdpSession.detach();
        } catch (cleanupError) {
          // Ignore cleanup errors
        }
      }

      return { session: null, success: false };
    }
  }

  /**
   * Setup network request logging
   * @param {object} cdpSession - The CDP session
   * @param {string} currentUrl - Current URL for logging context
   * @param {object} config - Configuration options
   */
  setupNetworkRequestLogging(cdpSession, currentUrl, config = {}) {
    const { filterDomains = [], logLevel = 'info' } = config;
    
    cdpSession.on('Network.requestWillBeSent', (params) => {
      try {
        const { url: requestUrl, method } = params.request;
        const initiator = params.initiator ? params.initiator.type : 'unknown';
        const requestId = params.requestId;

        // Apply domain filtering if configured
        if (filterDomains.length > 0) {
          const requestDomain = new URL(requestUrl).hostname;
          if (!filterDomains.some(domain => requestDomain.includes(domain))) {
            return;
          }
        }

        let hostnameForLog = 'unknown-host';
        try {
          hostnameForLog = new URL(currentUrl).hostname;
        } catch (_) { /* ignore if currentUrl is invalid */ }

        // Log the request
        const logMessage = `[cdp][${hostnameForLog}] ${method} ${requestUrl} (initiator: ${initiator}, id: ${requestId})`;
        
        if (logLevel === 'verbose') {
          console.log(logMessage, params);
        } else {
          console.log(logMessage);
        }

        this.sessionStats.networkEvents++;

        // Call custom handlers if registered
        this.callCustomHandlers('requestWillBeSent', params, currentUrl);

      } catch (error) {
        if (this.debugMode) {
          console.log(`[debug][cdp] Error in request logging: ${error.message}`);
        }
      }
    });
  }

  /**
   * Setup network response logging
   * @param {object} cdpSession - The CDP session
   * @param {string} currentUrl - Current URL for logging context
   * @param {object} config - Configuration options
   */
  setupNetworkResponseLogging(cdpSession, currentUrl, config = {}) {
    const { logLevel = 'info', logFailures = true } = config;

    cdpSession.on('Network.responseReceived', (params) => {
      try {
        const { url: responseUrl, status, statusText } = params.response;
        const requestId = params.requestId;

        let hostnameForLog = 'unknown-host';
        try {
          hostnameForLog = new URL(currentUrl).hostname;
        } catch (_) { /* ignore */ }

        // Log responses (especially failures if configured)
        if (logFailures && status >= 400) {
          console.log(`[cdp][${hostnameForLog}] RESPONSE FAILURE ${status} ${statusText} ${responseUrl} (id: ${requestId})`);
        } else if (logLevel === 'verbose') {
          console.log(`[cdp][${hostnameForLog}] RESPONSE ${status} ${responseUrl} (id: ${requestId})`);
        }

        this.sessionStats.networkEvents++;

        // Call custom handlers
        this.callCustomHandlers('responseReceived', params, currentUrl);

      } catch (error) {
        if (this.debugMode) {
          console.log(`[debug][cdp] Error in response logging: ${error.message}`);
        }
      }
    });

    // Handle request failures
    cdpSession.on('Network.loadingFailed', (params) => {
      try {
        const { errorText, blockedReason } = params;
        const requestId = params.requestId;

        let hostnameForLog = 'unknown-host';
        try {
          hostnameForLog = new URL(currentUrl).hostname;
        } catch (_) { /* ignore */ }

        console.log(`[cdp][${hostnameForLog}] LOADING FAILED ${errorText || 'Unknown error'} ${blockedReason || ''} (id: ${requestId})`);
        
        this.sessionStats.networkEvents++;
        this.callCustomHandlers('loadingFailed', params, currentUrl);

      } catch (error) {
        if (this.debugMode) {
          console.log(`[debug][cdp] Error in failure logging: ${error.message}`);
        }
      }
    });
  }

  /**
   * Setup security event logging
   * @param {object} cdpSession - The CDP session
   * @param {string} currentUrl - Current URL for logging context
   * @param {object} config - Configuration options
   */
  setupSecurityLogging(cdpSession, currentUrl, config = {}) {
    cdpSession.on('Security.securityStateChanged', (params) => {
      try {
        const { securityState, explanations } = params;
        
        let hostnameForLog = 'unknown-host';
        try {
          hostnameForLog = new URL(currentUrl).hostname;
        } catch (_) { /* ignore */ }

        console.log(`[cdp][${hostnameForLog}] SECURITY STATE: ${securityState}`);
        
        if (explanations && explanations.length > 0) {
          explanations.forEach(explanation => {
            console.log(`[cdp][${hostnameForLog}] SECURITY: ${explanation.description}`);
          });
        }

        this.sessionStats.securityEvents++;
        this.callCustomHandlers('securityStateChanged', params, currentUrl);

      } catch (error) {
        if (this.debugMode) {
          console.log(`[debug][cdp] Error in security logging: ${error.message}`);
        }
      }
    });
  }

  /**
   * Setup runtime event logging
   * @param {object} cdpSession - The CDP session
   * @param {string} currentUrl - Current URL for logging context
   * @param {object} config - Configuration options
   */
  setupRuntimeLogging(cdpSession, currentUrl, config = {}) {
    const { logConsole = true, logExceptions = true } = config;

    if (logConsole) {
      cdpSession.on('Runtime.consoleAPICalled', (params) => {
        try {
          const { type, args } = params;
          
          let hostnameForLog = 'unknown-host';
          try {
            hostnameForLog = new URL(currentUrl).hostname;
          } catch (_) { /* ignore */ }

          const message = args.map(arg => arg.value || arg.description || '[Object]').join(' ');
          console.log(`[cdp][${hostnameForLog}] CONSOLE ${type.toUpperCase()}: ${message}`);

          this.callCustomHandlers('consoleAPICalled', params, currentUrl);

        } catch (error) {
          if (this.debugMode) {
            console.log(`[debug][cdp] Error in console logging: ${error.message}`);
          }
        }
      });
    }

    if (logExceptions) {
      cdpSession.on('Runtime.exceptionThrown', (params) => {
        try {
          const { exceptionDetails } = params;
          
          let hostnameForLog = 'unknown-host';
          try {
            hostnameForLog = new URL(currentUrl).hostname;
          } catch (_) { /* ignore */ }

          console.log(`[cdp][${hostnameForLog}] EXCEPTION: ${exceptionDetails.text} at ${exceptionDetails.url}:${exceptionDetails.lineNumber}`);

          this.callCustomHandlers('exceptionThrown', params, currentUrl);

        } catch (error) {
          if (this.debugMode) {
            console.log(`[debug][cdp] Error in exception logging: ${error.message}`);
          }
        }
      });
    }
  }

  /**
   * Setup performance monitoring
   * @param {object} cdpSession - The CDP session
   * @param {string} currentUrl - Current URL for logging context
   * @param {object} config - Configuration options
   */
  setupPerformanceLogging(cdpSession, currentUrl, config = {}) {
    cdpSession.on('Performance.metrics', (params) => {
      try {
        const { metrics } = params;
        
        let hostnameForLog = 'unknown-host';
        try {
          hostnameForLog = new URL(currentUrl).hostname;
        } catch (_) { /* ignore */ }

        console.log(`[cdp][${hostnameForLog}] PERFORMANCE METRICS:`, metrics);
        this.callCustomHandlers('performanceMetrics', params, currentUrl);

      } catch (error) {
        if (this.debugMode) {
          console.log(`[debug][cdp] Error in performance logging: ${error.message}`);
        }
      }
    });
  }

  /**
   * Setup general error logging
   * @param {object} cdpSession - The CDP session
   * @param {string} currentUrl - Current URL for logging context
   */
  setupErrorLogging(cdpSession, currentUrl) {
    cdpSession.on('disconnect', () => {
      if (this.debugMode) {
        console.log(`[debug][cdp] CDP session disconnected for ${currentUrl}`);
      }
      this.sessionStats.activeConnections--;
    });

    cdpSession.on('error', (error) => {
      if (this.debugMode) {
        console.log(`[debug][cdp] CDP session error for ${currentUrl}: ${error.message}`);
      }
      this.sessionStats.errors++;
    });
  }

  /**
   * Apply CDP monitoring based on configuration
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {boolean} globalCDP - Global CDP enabled flag
   * @param {object} siteConfig - Site-specific configuration
   * @param {string} currentUrl - Current URL being processed
   * @returns {Promise<{session: object|null, success: boolean}>} CDP session and success status
   */
  async applyCDPMonitoring(page, globalCDP, siteConfig, currentUrl = 'unknown') {
    const cdpLoggingNeeded = globalCDP || siteConfig.cdp === true;
    
    if (!cdpLoggingNeeded) {
      return { session: null, success: true }; // No CDP needed
    }

    try {
      if (this.debugMode) {
        if (globalCDP) {
          console.log(`[debug][cdp] Global CDP logging enabled, applying to page: ${currentUrl}`);
        } else if (siteConfig.cdp === true) {
          console.log(`[debug][cdp] Site-specific CDP logging enabled for page: ${currentUrl}`);
        }
      }

      // Merge configuration
      const config = {
        enableNetwork: true,
        logRequests: true,
        logResponses: siteConfig.cdpLogResponses || false,
        logErrors: true,
        logLevel: siteConfig.cdpLogLevel || 'info',
        enableSecurity: siteConfig.cdpSecurity || false,
        enableRuntime: siteConfig.cdpRuntime || false,
        enablePerformance: siteConfig.cdpPerformance || false,
        filterDomains: siteConfig.cdpFilterDomains || []
      };

      const result = await this.createCDPSession(page, config, currentUrl);
      return result;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][cdp] Failed to apply CDP monitoring for ${currentUrl}: ${error.message}`);
      }
      return { session: null, success: false };
    }
  }

  /**
   * Cleanup CDP session for a page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {object} cdpSession - The CDP session to cleanup (optional)
   * @returns {Promise<boolean>} Success status
   */
  async cleanupCDPSession(page, cdpSession = null) {
    try {
      const pageId = this.getPageId(page);
      
      // If no session provided, try to get it from tracking
      if (!cdpSession && this.activeSessions.has(pageId)) {
        cdpSession = this.activeSessions.get(pageId).session;
      }

      if (cdpSession) {
        await cdpSession.detach();
        
        if (this.debugMode) {
          console.log(`[debug][cdp] CDP session detached for page ${pageId}`);
        }
      }

      // Remove from tracking
      if (this.activeSessions.has(pageId)) {
        this.activeSessions.delete(pageId);
        this.sessionStats.activeConnections--;
      }

      return true;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][cdp] Failed to cleanup CDP session: ${error.message}`);
      }
      this.sessionStats.errors++;
      return false;
    }
  }

  /**
   * Register a custom event handler
   * @param {string} eventName - The CDP event name
   * @param {function} handler - The handler function
   */
  registerEventHandler(eventName, handler) {
    if (!this.eventHandlers.has(eventName)) {
      this.eventHandlers.set(eventName, []);
    }
    this.eventHandlers.get(eventName).push(handler);
  }

  /**
   * Call custom handlers for an event
   * @param {string} eventName - The event name
   * @param {object} params - Event parameters
   * @param {string} currentUrl - Current URL context
   */
  callCustomHandlers(eventName, params, currentUrl) {
    if (this.eventHandlers.has(eventName)) {
      const handlers = this.eventHandlers.get(eventName);
      handlers.forEach(handler => {
        try {
          handler(params, currentUrl);
        } catch (error) {
          if (this.debugMode) {
            console.log(`[debug][cdp] Error in custom handler for ${eventName}: ${error.message}`);
          }
        }
      });
    }
  }

  /**
   * Get a unique identifier for a page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @returns {string} Unique page identifier
   */
  getPageId(page) {
    try {
      return page.target()._targetId || `page-${Date.now()}-${Math.random()}`;
    } catch (error) {
      return `page-${Date.now()}-${Math.random()}`;
    }
  }

  /**
   * Get CDP session statistics
   * @returns {object} Statistics object
   */
  getStats() {
    return {
      ...this.sessionStats,
      activeSessionsCount: this.activeSessions.size,
      registeredHandlers: this.eventHandlers.size
    };
  }

  /**
   * Get information about active sessions
   * @returns {Array} Array of active session info
   */
  getActiveSessions() {
    return Array.from(this.activeSessions.entries()).map(([pageId, sessionInfo]) => ({
      pageId,
      url: sessionInfo.url,
      createdAt: sessionInfo.createdAt,
      age: Date.now() - sessionInfo.createdAt
    }));
  }

  /**
   * Create a preset configuration for common CDP use cases
   * @param {string} preset - Preset name ('basic', 'network', 'full')
   * @returns {object} Configuration object
   */
  getPresetConfig(preset) {
    const presets = {
      basic: {
        cdp: true
      },
      network: {
        cdp: true,
        cdpLogResponses: true,
        cdpLogLevel: 'verbose'
      },
      full: {
        cdp: true,
        cdpLogResponses: true,
        cdpLogLevel: 'verbose',
        cdpSecurity: true,
        cdpRuntime: true,
        cdpPerformance: true
      }
    };

    return presets[preset] || presets.basic;
  }
}

// Export the class and create a default instance
const cdpManager = new CDPManager();

module.exports = {
  CDPManager,
  cdpManager
};
