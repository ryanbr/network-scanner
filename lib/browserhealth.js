/**
 * Browser health monitoring module for nwss.js
 * Provides health checks and recovery mechanisms to prevent protocol timeouts
 */

const { formatLogMessage, messageColors } = require('./colorize');

/**
 * Checks if browser instance is still responsive
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {number} timeout - Timeout in milliseconds (default: 5000)
 * @returns {Promise<object>} Health check result
 */
async function checkBrowserHealth(browserInstance, timeout = 8000) {
  const healthResult = {
    healthy: false,
    pageCount: 0,
    error: null,
    responseTime: 0,
    recommendations: [],
    criticalError: false
  };

  const startTime = Date.now();

  try {
    // Test 1: Check if browser is connected
    if (!browserInstance || browserInstance.process() === null) {
      healthResult.error = 'Browser process not running';
      healthResult.recommendations.push('Create new browser instance');
      healthResult.criticalError = true;
      return healthResult;
    }

    // Test 2: Try to get pages list with timeout
    const pages = await Promise.race([
      browserInstance.pages(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Browser unresponsive - pages() timeout')), timeout)
      )
    ]);

    healthResult.pageCount = pages.length;
    healthResult.responseTime = Date.now() - startTime;

    // Test 3: Check for excessive pages (memory leak indicator)
    if (pages.length > 30) {
      healthResult.recommendations.push('Too many open pages - consider browser restart');
    }

    // Test 4: Try to create a test page to verify browser functionality
    let testPage = null;
    try {
      testPage = await Promise.race([
        browserInstance.newPage(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Page creation timeout')), timeout)
        )
      ]);

      // Quick test navigation to about:blank
      await Promise.race([
        testPage.goto('about:blank'),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Navigation timeout')), timeout)
        )
      ]);

      await testPage.close();
      
    } catch (pageTestError) {
      if (testPage && !testPage.isClosed()) {
        try { await testPage.close(); } catch (e) { /* ignore */ }
      }
      healthResult.error = `Page creation/navigation failed: ${pageTestError.message}`;
      if (isCriticalProtocolError(pageTestError)) {
        healthResult.recommendations.push('Browser restart required - critical protocol error');
        healthResult.criticalError = true;
      } else {
        healthResult.recommendations.push('Browser restart recommended');
      }
      return healthResult;
    }

    // Test 5: Check response time performance
    if (healthResult.responseTime > 5000) {
      healthResult.recommendations.push('Slow browser response - consider restart');
    }

    // If all tests pass
    healthResult.healthy = true;

  } catch (error) {
    healthResult.error = error.message;
    healthResult.responseTime = Date.now() - startTime;
    
    // Categorize error types for better recommendations
    // Enhanced error categorization for Puppeteer 23.x
    if (isCriticalProtocolError(error)) {
      healthResult.recommendations.push('Browser restart required - critical protocol error');
      healthResult.criticalError = true;
    } else if (error.message.includes('WebSocket') || 
               error.message.includes('Connection terminated') ||
               error.message.includes('Network service crashed')) {
      // New error types more common in Puppeteer 23.x
      healthResult.recommendations.push('Browser restart required - connection error');
      healthResult.criticalError = true;
    } else if (error.message.includes('AbortError') || 
               error.message.includes('Operation was aborted')) {
      healthResult.recommendations.push('Browser restart recommended - operation aborted');
    } else if (error.message.includes('timeout') || error.message.includes('unresponsive')) {
      healthResult.recommendations.push('Browser restart required - unresponsive');
      healthResult.criticalError = true;
    } else {
      healthResult.recommendations.push('Browser restart recommended - unknown error');
    }
  }

  return healthResult;
}

/**
 * Checks memory usage of browser process (if available)
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @returns {Promise<object>} Memory usage information
 */
async function checkBrowserMemory(browserInstance) {
  const memoryResult = {
    available: false,
    usage: null,
    error: null,
    recommendations: []
  };

  try {
    const browserProcess = browserInstance.process();
    if (!browserProcess || !browserProcess.pid) {
      memoryResult.error = 'No browser process available';
      return memoryResult;
    }

    // Try to get process memory info (Linux/Unix)
    try {
      const { execSync } = require('child_process');
      const memInfo = execSync(`ps -p ${browserProcess.pid} -o rss=`, { encoding: 'utf8', timeout: 2000 });
      const memoryKB = parseInt(memInfo.trim());
      
      if (!isNaN(memoryKB)) {
        const memoryMB = Math.round(memoryKB / 1024);
        memoryResult.available = true;
        memoryResult.usage = {
          rss: memoryKB,
          rssMB: memoryMB
        };

        // Memory usage recommendations
        if (memoryMB > 1000) {
          memoryResult.recommendations.push(`High memory usage: ${memoryMB}MB - restart recommended`);
        } else if (memoryMB > 500) {
          memoryResult.recommendations.push(`Elevated memory usage: ${memoryMB}MB - monitor closely`);
        }
      }
    } catch (psError) {
      memoryResult.error = `Memory check failed: ${psError.message}`;
    }

  } catch (error) {
    memoryResult.error = error.message;
  }

  return memoryResult;
}

 /**
 * Detects critical protocol errors that require immediate browser restart
 */
function isCriticalProtocolError(error) {
  if (!error || !error.message) return false;
  
  const criticalErrors = [
    'Runtime.callFunctionOn timed out',
    'Protocol error',
    'Target closed',
    'Session closed',
    'Connection closed',
    'Browser has been closed',
    'Runtime.evaluate timed out',
    // New Puppeteer 23.x critical errors
    'WebSocket is not open',
    'WebSocket connection lost',
    'Connection terminated',
    'Network service crashed',
    'Browser disconnected',
    'CDP session invalid',
    'Browser process exited',
    'Navigation timeout of',
    'Page crashed',
    'Renderer process crashed'
  ];
  
  return criticalErrors.some(criticalError => 
    error.message.includes(criticalError)
  );
}

/**
 * Enhanced browser connectivity test for Puppeteer 23.x
 * Tests WebSocket connection and CDP session validity
 */
async function testBrowserConnectivity(browserInstance, timeout = 2500) {
  const connectivityResult = {
    connected: false,
    cdpResponsive: false,
    websocketHealthy: false,
    error: null
  };

  try {
    // Test 1: Basic browser connection
    const isConnected = browserInstance.isConnected();
    connectivityResult.connected = isConnected;
    
    if (!isConnected) {
      connectivityResult.error = 'Browser is not connected';
      return connectivityResult;
    }

    // Test 2: CDP responsiveness with version check
    try {
      const version = await Promise.race([
        browserInstance.version(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('CDP version check timeout')), timeout)
        )
      ]);
      
      connectivityResult.cdpResponsive = true;
      connectivityResult.websocketHealthy = true; // If version works, WebSocket is healthy
      
    } catch (cdpError) {
      connectivityResult.error = `CDP not responsive: ${cdpError.message}`;
      if (cdpError.message.includes('WebSocket')) {
        connectivityResult.websocketHealthy = false;
      }
    }
    
  } catch (error) {
    connectivityResult.error = error.message;
  }

  return connectivityResult;
}

/**
 * Performs comprehensive browser health assessment
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {object} options - Health check options
 * @returns {Promise<object>} Comprehensive health report
 */
async function performHealthAssessment(browserInstance, options = {}) {
  const {
    timeout = 8000,
    checkMemory = true,
    testConnectivity = true,
    forceDebug = false
  } = options;

  const assessment = {
    overall: 'unknown',
    timestamp: new Date().toISOString(),
    browser: {},
    memory: {},
    connectivity: {},
    recommendations: [],
    needsRestart: false
  };

  if (forceDebug) {
    console.log(formatLogMessage('debug', 'Starting browser health assessment...'));
  }

  // Browser responsiveness check
  assessment.browser = await checkBrowserHealth(browserInstance, timeout);
  
  // Enhanced connectivity check for Puppeteer 23.x
  if (testConnectivity) {
    assessment.connectivity = await testBrowserConnectivity(browserInstance, timeout);
  }
  
  // Memory usage check (if enabled and available)
  if (checkMemory) {
    assessment.memory = await checkBrowserMemory(browserInstance);
  }

  // Combine recommendations
  assessment.recommendations = [
    ...assessment.browser.recommendations,
    ...(assessment.connectivity.error ? [`Connectivity issue: ${assessment.connectivity.error}`] : []),
    ...(assessment.memory.recommendations || [])
  ];

  // Determine overall health and restart necessity
  if (!assessment.browser.healthy) {
    assessment.overall = 'unhealthy';
    assessment.needsRestart = true;
  } else if (assessment.browser.criticalError) {
    assessment.overall = 'critical';
    assessment.needsRestart = true;
  } else if (testConnectivity && (!assessment.connectivity.connected || !assessment.connectivity.cdpResponsive)) {
    assessment.overall = 'disconnected';
    assessment.needsRestart = true;
  } else if (assessment.recommendations.length > 0) {
    assessment.overall = 'degraded';
    assessment.needsRestart = assessment.recommendations.some(rec => 
      rec.includes('restart required') || 
      rec.includes('High memory usage')
    );
  } else {
    assessment.overall = 'healthy';
    assessment.needsRestart = false;
  }

  if (forceDebug) {
    console.log(formatLogMessage('debug', `Health assessment complete: ${assessment.overall}`));
    if (assessment.recommendations.length > 0) {
      console.log(formatLogMessage('debug', `Recommendations: ${assessment.recommendations.join(', ')}`));
    }
  }

  return assessment;
}

/**
 * Monitors browser health and suggests actions for nwss.js integration
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {object} context - Context information for logging
 * @param {object} options - Monitoring options
 * @returns {Promise<object>} Monitoring result with action suggestions
 */
async function monitorBrowserHealth(browserInstance, context = {}, options = {}) {
  const {
    siteIndex = 0,
    totalSites = 0,
    urlsSinceCleanup = 0,
    cleanupInterval = 40,
    forceDebug = false,
    silentMode = false
  } = options;

  const result = {
    shouldRestart: false,
    shouldContinue: true,
    reason: null,
    assessment: null
  };

  try {
    // Perform health assessment
    const assessment = await performHealthAssessment(browserInstance, {
      timeout: 8000,
      checkMemory: true,
      testConnectivity: true, // Enable enhanced connectivity testing
      forceDebug
    });

    result.assessment = assessment;

    // Decision logic for restart
    if (assessment.browser.criticalError) {
      result.shouldRestart = true;
      result.reason = `Critical protocol error detected - immediate restart required`;
    } else if (assessment.connectivity && (!assessment.connectivity.connected || !assessment.connectivity.cdpResponsive)) {
      result.shouldRestart = true;
      result.reason = `Browser connectivity lost - WebSocket/CDP failure`;
    } else if (assessment.needsRestart) {
      result.shouldRestart = true;
      result.reason = `Browser health: ${assessment.overall} - ${assessment.recommendations[0] || 'restart needed'}`;
    } else if (urlsSinceCleanup >= cleanupInterval) {
      result.shouldRestart = true;
      result.reason = `Scheduled cleanup after ${urlsSinceCleanup} URLs`;
    } else if (assessment.browser.responseTime > 6000) {
      result.shouldRestart = true;
      result.reason = `Slow browser response: ${assessment.browser.responseTime}ms (threshold: 6000ms)`;
    } else if (assessment.browser.pageCount > 40) {
      // More aggressive page count monitoring for Puppeteer 23.x
      result.shouldRestart = true;
      result.reason = `Too many open pages: ${assessment.browser.pageCount} (memory leak protection)`;
    }

    // Logging
    if (!silentMode && result.shouldRestart) {
      const progress = totalSites > 0 ? ` (${siteIndex + 1}/${totalSites})` : '';
      console.log(`\n${messageColors.fileOp('?? Browser restart needed')} before site${progress}: ${result.reason}`);
    }

    if (forceDebug && !result.shouldRestart) {
      const connectivity = assessment.connectivity.connected ? 'connected' : 'disconnected';
      const cdp = assessment.connectivity.cdpResponsive ? 'responsive' : 'unresponsive';
      console.log(formatLogMessage('debug', `Browser health OK - continuing (pages: ${assessment.browser.pageCount}, response: ${assessment.browser.responseTime}ms, ${connectivity}, CDP: ${cdp})`));
    }

  } catch (monitorError) {
    result.shouldRestart = true;
    result.reason = `Health monitoring failed: ${monitorError.message}`;
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Browser health monitoring error: ${monitorError.message}`));
    }
  }

  return result;
}

/**
 * Simple health check function for quick integration
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @returns {Promise<boolean>} True if browser is healthy, false otherwise
 */
async function isBrowserHealthy(browserInstance) {
  try {
    const health = await checkBrowserHealth(browserInstance, 5000); // Faster timeout
    const connectivity = await testBrowserConnectivity(browserInstance, 3000);
    return health.healthy && connectivity.connected && connectivity.cdpResponsive;
  } catch (error) {
    return false;
  }
}

module.exports = {
  checkBrowserHealth,
  checkBrowserMemory,
  testBrowserConnectivity,
  performHealthAssessment,
  monitorBrowserHealth,
  isBrowserHealthy,
  isCriticalProtocolError
};
