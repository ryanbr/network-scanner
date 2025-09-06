/**
 * Browser health monitoring module for nwss.js
 * Provides health checks and recovery mechanisms to prevent protocol timeouts
 */

const { formatLogMessage, messageColors } = require('./colorize');


// Window cleanup delay constant
const WINDOW_CLEANUP_DELAY_MS = 16000;

/**
 * Performs group-level window cleanup after all URLs in a site group complete
 * Closes all extra windows except the main browser window
 * @param {import('puppeteer').Browser} browserInstance - Browser instance
 * @param {string} groupDescription - Description of the group for logging
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Promise<Object>} Cleanup results
 */
async function performGroupWindowCleanup(browserInstance, groupDescription, forceDebug) {
  try {
    // Wait before cleanup to allow any final operations to complete
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[group_window_cleanup] Waiting ${WINDOW_CLEANUP_DELAY_MS}ms before cleanup for group: ${groupDescription}`));
    }
    await new Promise(resolve => setTimeout(resolve, WINDOW_CLEANUP_DELAY_MS));
    
    const allPages = await browserInstance.pages();
    const mainPage = allPages[0]; // Always keep the first page as main
    const extraPages = allPages.slice(1); // All other pages can be closed
    
    if (extraPages.length === 0) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[group_window_cleanup] No extra windows to close for group: ${groupDescription}`));
      }
      return { success: true, closedCount: 0, totalPages: allPages.length, estimatedMemoryFreed: 0 };
    }
    
    // Estimate memory usage before closing
    let totalEstimatedMemory = 0;
    const pageMemoryEstimates = [];
    
    for (let i = 0; i < extraPages.length; i++) {
      const page = extraPages[i];
      let pageMemoryEstimate = 0;
      
      try {
        if (!page.isClosed()) {
          // Get page metrics if available
          const metrics = await Promise.race([
            page.metrics(),
            new Promise((_, reject) => setTimeout(() => reject(new Error('metrics timeout')), 1000))
          ]);
          
          // Calculate memory estimate based on page metrics
          if (metrics) {
            // Puppeteer metrics provide various memory-related values
            pageMemoryEstimate = (
              (metrics.JSHeapUsedSize || 0) +           // JavaScript heap
              (metrics.JSHeapTotalSize || 0) * 0.1 +    // Estimated overhead
              (metrics.Nodes || 0) * 100 +              // DOM nodes (rough estimate)
              (metrics.JSEventListeners || 0) * 50      // Event listeners
            );
          } else {
            // Fallback: rough estimate based on page complexity
            pageMemoryEstimate = 8 * 1024 * 1024; // 8MB default estimate per page
          }
        }
      } catch (metricsErr) {
        // Fallback estimate if metrics fail
        pageMemoryEstimate = 8 * 1024 * 1024; // 8MB default
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[group_window_cleanup] Could not get metrics for page ${i + 1}, using default estimate: ${metricsErr.message}`));
        }
      }
      
      pageMemoryEstimates.push(pageMemoryEstimate);
      totalEstimatedMemory += pageMemoryEstimate;
    }
    
    // Close all extra pages since the entire group is complete
    const closePromises = extraPages.map(async (page, index) => {
      try {
        if (!page.isClosed()) {
          await page.close();
          return { success: true, url: page.url() || `page-${index}`, estimatedMemory: pageMemoryEstimates[index] };
        }
        return { success: false, reason: 'already_closed', estimatedMemory: 0 };
      } catch (closeErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[group_window_cleanup] Failed to close page ${index + 1}: ${closeErr.message}`));
        }
        return { success: false, error: closeErr.message, estimatedMemory: 0 };
      }
    });
    
    const closeResults = await Promise.all(closePromises);
    const successfulCloses = closeResults.filter(result => result.success === true).length;
    const actualMemoryFreed = closeResults
      .filter(result => result.success === true)
      .reduce((sum, result) => sum + (result.estimatedMemory || 0), 0);
    
    // Format memory for human readability
    const formatMemory = (bytes) => {
      if (bytes >= 1024 * 1024 * 1024) {
        return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}GB`;
      } else if (bytes >= 1024 * 1024) {
        return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
      } else if (bytes >= 1024) {
        return `${(bytes / 1024).toFixed(1)}KB`;
      } else {
        return `${bytes}B`;
      }
    };
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[group_window_cleanup] Closed ${successfulCloses}/${extraPages.length} windows for completed group: ${groupDescription} after ${WINDOW_CLEANUP_DELAY_MS}ms delay`));
      console.log(formatLogMessage('debug', `[group_window_cleanup] Estimated memory freed: ${formatMemory(actualMemoryFreed)}`));
    }
    
    return { 
      success: true, 
      closedCount: successfulCloses,
      totalPages: allPages.length,
      mainPageKept: !mainPage.isClosed(),
      delayUsed: WINDOW_CLEANUP_DELAY_MS,
      estimatedMemoryFreed: actualMemoryFreed,
      estimatedMemoryFreedFormatted: formatMemory(actualMemoryFreed)
    };
  } catch (cleanupErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[group_window_cleanup] Group cleanup failed for ${groupDescription}: ${cleanupErr.message}`));
    }
    return { success: false, error: cleanupErr.message, estimatedMemoryFreed: 0 };
  }
}

/**
 * Quick browser responsiveness test for use during page setup
 * Designed to catch browser degradation between operations
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {number} timeout - Timeout in milliseconds (default: 3000)
 * @returns {Promise<boolean>} True if browser responds quickly, false otherwise
 */
async function isQuicklyResponsive(browserInstance, timeout = 3000) {
  try {
    await Promise.race([
      browserInstance.version(), // Quick responsiveness test
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Quick responsiveness timeout')), timeout)
      )
    ]);
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Tests if browser can handle network operations (like Network.enable)
 * Creates a test page and attempts basic network setup
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {number} timeout - Timeout in milliseconds (default: 10000)
 * @returns {Promise<object>} Network capability test result
 */
async function testNetworkCapability(browserInstance, timeout = 10000) {
  const result = {
    capable: false,
    error: null,
    responseTime: 0
  };

  const startTime = Date.now();
  let testPage = null;

  try {
    // Create test page
    testPage = await Promise.race([
      browserInstance.newPage(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Test page creation timeout')), timeout)
      )
    ]);

    // Test network operations (the critical operation that's failing)
    await Promise.race([
      testPage.setRequestInterception(true),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Network.enable test timeout')), timeout)
      )
    ]);

    // Turn off interception and close
    await testPage.setRequestInterception(false);
    result.capable = true;
    result.responseTime = Date.now() - startTime;

  } catch (error) {
    result.error = error.message;
    result.responseTime = Date.now() - startTime;

    // Classify the error type
    if (error.message.includes('Network.enable') || 
        error.message.includes('timed out') ||
        error.message.includes('Protocol error')) {
      result.error = `Network capability test failed: ${error.message}`;
    }
  } finally {
    if (testPage && !testPage.isClosed()) {
      try { 
        await testPage.close(); 
      } catch (closeErr) { 
        /* ignore cleanup errors */ 
      }
    }
  }

  return result;
}

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
    criticalError: false,
    networkCapable: false
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

    // Test 5: Network capability test (critical for Network.enable issues)
    const networkTest = await testNetworkCapability(browserInstance, Math.min(timeout, 5000));
    healthResult.networkCapable = networkTest.capable;
    
    if (!networkTest.capable) {
      healthResult.recommendations.push(`Network operations failing: ${networkTest.error}`);
      if (networkTest.error && networkTest.error.includes('Network.enable')) {
        healthResult.criticalError = true;
      }
    }

    // Test 6: Check response time performance
    if (healthResult.responseTime > 5000) {
      healthResult.recommendations.push('Slow browser response - consider restart');
    }

    // If all tests pass (including network capability)
    healthResult.healthy = networkTest.capable; // Network capability is now critical for health


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
    'Renderer process crashed',
    // Network-specific critical errors
    'Network.enable timed out',
    'Network.disable timed out',
    'Network service not available'
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
 * Enhanced version that includes network capability testing
 * @param {import('puppeteer').Browser} browserInstance - Puppeteer browser instance
 * @param {boolean} includeNetworkTest - Whether to test network capabilities (default: true)
 * @returns {Promise<boolean>} True if browser is healthy, false otherwise
 */
async function isBrowserHealthy(browserInstance, includeNetworkTest = true) {
  try {
    // Quick responsiveness test first (fastest check)
    const quickCheck = await isQuicklyResponsive(browserInstance, 2500);
    if (!quickCheck) return false;
    
    // More comprehensive health check if quick test passes
    const health = await checkBrowserHealth(browserInstance, includeNetworkTest ? 8000 : 5000);
    const connectivity = await testBrowserConnectivity(browserInstance, 3000);
    
    const baseHealth = health.healthy && connectivity.connected && connectivity.cdpResponsive;
    
    // Include network capability in health assessment if requested
    return includeNetworkTest ? (baseHealth && health.networkCapable) : baseHealth;
  } catch (error) {
    return false;
  }
}

module.exports = {
  checkBrowserHealth,
  checkBrowserMemory,
  testBrowserConnectivity,
  performGroupWindowCleanup,
  testNetworkCapability,
  isQuicklyResponsive,
  performHealthAssessment,
  monitorBrowserHealth,
  isBrowserHealthy,
  isCriticalProtocolError
};
