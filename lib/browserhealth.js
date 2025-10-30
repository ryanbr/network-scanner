/**
 * Browser health monitoring module for nwss.js
 * Provides health checks and recovery mechanisms to prevent protocol timeouts
 */

const { formatLogMessage, messageColors } = require('./colorize');


// Window cleanup delay constant
const WINDOW_CLEANUP_DELAY_MS = 15000;
// window_clean REALTIME
const REALTIME_CLEANUP_BUFFER_MS = 25000; // Additional buffer time after site delay (increased for Cloudflare)
const REALTIME_CLEANUP_THRESHOLD = 12; // Default number of pages to keep
const REALTIME_CLEANUP_MIN_PAGES = 6; // Minimum pages before cleanup kicks in

// Track page creation order for realtime cleanup
const pageCreationTracker = new Map(); // Maps page -> creation timestamp
let pageCreationCounter = 0;

// Track page usage for realtime cleanup safety
const pageUsageTracker = new Map(); // Maps page -> { lastActivity: timestamp, isProcessing: boolean }
const PAGE_IDLE_THRESHOLD = 25000; // 25 seconds of inactivity before considering page safe to clean

/**
 * Performs group-level window cleanup after all URLs in a site group complete
 * Closes all extra windows except the main browser window
 * @param {import('puppeteer').Browser} browserInstance - Browser instance
 * @param {string} groupDescription - Description of the group for logging
 * @param {boolean} forceDebug - Debug logging flag
 * @param {string|boolean} cleanupMode - Cleanup mode: true/"default" (conservative), "all" (aggressive)
 * @returns {Promise<Object>} Cleanup results
 */
async function performGroupWindowCleanup(browserInstance, groupDescription, forceDebug, cleanupMode = true) {
  try {
    // Wait before cleanup to allow any final operations to complete
    // Initialize result object with ALL possible properties upfront for V8 optimization
    const result = {
      success: false,
      closedCount: 0,
      totalPages: 0,
      mainPagePreserved: false,
      delayUsed: 0,
      estimatedMemoryFreed: 0,
      estimatedMemoryFreedFormatted: '',
      cleanupMode: '',
      error: null
    };
    const modeText = cleanupMode === "all" ? "aggressive cleanup of old windows" : "conservative cleanup of extra windows"
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[group_window_cleanup] Waiting ${WINDOW_CLEANUP_DELAY_MS}ms before ${modeText} for group: ${groupDescription}`));

    }
    await new Promise(resolve => setTimeout(resolve, WINDOW_CLEANUP_DELAY_MS));
    
    const allPages = await browserInstance.pages();
    // Identify the main Puppeteer window (should be about:blank or the initial page)
    let mainPuppeteerPage = null;
    let pagesToClose = [];
    
    // Find the main page - typically the first page that's about:blank or has been there longest
    for (const page of allPages) {
      // Cache page.url() call to avoid repeated DOM/browser communication
      const pageUrl = page.url();
      if (pageUrl === 'about:blank' || pageUrl === '' || pageUrl.startsWith('chrome://')) {
        if (!mainPuppeteerPage) {
          mainPuppeteerPage = page; // First blank page is likely the main window
        } else {
          pagesToClose.push(page); // Additional blank pages can be closed
        }
      } else {
        // Any page with actual content should be evaluated for closure
        // Cache page state checks to avoid multiple browser calls
        const isPageClosed = page.isClosed();

        if (cleanupMode === "all") {
          // Aggressive mode: close all content pages
          pagesToClose.push(page);
        } else {
          // Conservative mode: only close pages that look like leftovers from previous scans
          // Keep pages that might still be actively used
          const isOldPage = await isPageFromPreviousScan(page, forceDebug);
          if (isOldPage) {
            pagesToClose.push(page);
          }
        }
      }
    }
    
    // Ensure we always have a main page
    if (!mainPuppeteerPage && allPages.length > 0) {
      mainPuppeteerPage = allPages[0]; // Fallback to first page
      pagesToClose = allPages.slice(1);
      if (forceDebug) {
        // Cache URL call for logging
        const mainPageUrl = mainPuppeteerPage.url();
        console.log(formatLogMessage('debug', `[group_window_cleanup] No blank page found, using first page as main: ${mainPageUrl}`));
      }
    }
    
    if (pagesToClose.length === 0) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[group_window_cleanup] No windows to close for group: ${groupDescription}`));
      }
      result.success = true;
      result.totalPages = allPages.length;
      result.mainPagePreserved = true;
      result.cleanupMode = cleanupMode === "all" ? "all" : "default";
      return result;
    }
    
    // Estimate memory usage before closing
    let totalEstimatedMemory = 0;
    const pageMemoryEstimates = [];
    
    for (let i = 0; i < pagesToClose.length; i++) {
      const page = pagesToClose[i];
      let pageMemoryEstimate = 0;
      
      try {
        // Cache page.isClosed() check to avoid repeated browser calls
        const isPageClosed = page.isClosed();
        if (!isPageClosed) {
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
    
    // Close identified old/unused pages
    const closePromises = pagesToClose.map(async (page, index) => {
      try {
        // Cache page state and URL for this operation
        const isPageClosed = page.isClosed();
        const pageUrl = page.url();
        if (!isPageClosed) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `[group_window_cleanup] Closing page: ${pageUrl}`));
          }
          await page.close();
          return { success: true, url: pageUrl || `page-${index}`, estimatedMemory: pageMemoryEstimates[index] };
        }
        return { success: false, reason: 'already_closed', estimatedMemory: 0 };
      } catch (closeErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[group_window_cleanup] Failed to close old page ${index + 1}: ${closeErr.message}`));
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
      console.log(formatLogMessage('debug', `[group_window_cleanup] Closed ${successfulCloses}/${pagesToClose.length} old windows for completed group: ${groupDescription} after ${WINDOW_CLEANUP_DELAY_MS}ms delay`));
      console.log(formatLogMessage('debug', `[group_window_cleanup] Estimated memory freed: ${formatMemory(actualMemoryFreed)}`));
      if (mainPuppeteerPage) {
        // Cache URL for final logging
        const mainPageUrl = mainPuppeteerPage.url();
        console.log(formatLogMessage('debug', `[group_window_cleanup] Main Puppeteer window preserved: ${mainPageUrl}`));
      }
    }
    
    // Update result object instead of creating new one
    result.success = true;
    result.closedCount = successfulCloses;
    result.totalPages = allPages.length;
    result.mainPagePreserved = mainPuppeteerPage && !mainPuppeteerPage.isClosed();
    result.delayUsed = WINDOW_CLEANUP_DELAY_MS;
    result.estimatedMemoryFreed = actualMemoryFreed;
    result.estimatedMemoryFreedFormatted = formatMemory(actualMemoryFreed);
    result.cleanupMode = cleanupMode === "all" ? "all" : "default";
    return result;
  } catch (cleanupErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[group_window_cleanup] Group cleanup failed for ${groupDescription}: ${cleanupErr.message}`));
    }
    // Initialize result object with consistent shape for error case
    const result = {
      success: false,
      closedCount: 0,
      totalPages: 0,
      mainPagePreserved: false,
      delayUsed: 0,
      estimatedMemoryFreed: 0,
      estimatedMemoryFreedFormatted: '',
      cleanupMode: '',
      error: cleanupErr.message
    };
    return result;
  }
}

/**
 * Checks if a page is safe to close (not actively processing)
 * @param {import('puppeteer').Page} page - Page to check
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Promise<boolean>} True if page is safe to close
 */
async function isPageSafeToClose(page, forceDebug) {
  try {
    // Cache page.isClosed() to avoid repeated browser communication
    const isPageClosed = page.isClosed();
    if (isPageClosed) {
      return true; // Already closed
    }

  // EXTRA SAFETY: Never close pages that might be in injection process
  try {
    // Cache page.url() for safety checks
    const pageUrl = page.url();
    if (pageUrl && pageUrl !== 'about:blank' && Date.now() - (pageCreationTracker.get(page) || 0) < 30000) {
      return false; // Don't close recently created pages (within 30 seconds)
    }
  } catch (err) { /* ignore */ }

    const usage = pageUsageTracker.get(page);
    if (!usage) {
      // No usage data - assume safe if page exists for a while
      return true;
    }

    // Check if page is actively processing
    if (usage.isProcessing) {
      if (forceDebug) {
        // Cache URL for debug logging
        const pageUrl = page.url();
        console.log(formatLogMessage('debug', `[realtime_cleanup] Page still processing: ${pageUrl.substring(0, 50)}...`));
      }
      return false;
    }

    // Check if page has been idle long enough
    const idleTime = Date.now() - usage.lastActivity;
    const isSafe = idleTime >= PAGE_IDLE_THRESHOLD;
    
    if (!isSafe && forceDebug) {
      console.log(formatLogMessage('debug', `[realtime_cleanup] Page not idle long enough: ${Math.round(idleTime/1000)}s < ${PAGE_IDLE_THRESHOLD/1000}s`));
    }

    return isSafe;
  } catch (err) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[realtime_cleanup] Error checking page safety: ${err.message}`));
    }
    return true; // Assume safe if we can't check
  }
}

/**
 * Updates page usage tracking
 * @param {import('puppeteer').Page} page - Page to update
 * @param {boolean} isProcessing - Whether page is actively processing
 */
function updatePageUsage(page, isProcessing = false) {
  try {
    // Cache page.isClosed() to avoid repeated calls
    const isPageClosed = page.isClosed();
    if (!isPageClosed) {
      pageUsageTracker.set(page, {
        lastActivity: Date.now(),
        isProcessing: isProcessing
      });
    }
  } catch (err) {
    // Ignore errors in usage tracking
  }
}

/**
 * Performs realtime window cleanup - removes oldest pages when threshold is exceeded
 * Waits for site delay + buffer before cleanup, with extended buffer for Cloudflare sites
 * @param {import('puppeteer').Browser} browserInstance - Browser instance
 * @param {number} threshold - Maximum number of pages to keep (default: 8)
 * @param {boolean} forceDebug - Debug logging flag
 * @param {number} totalDelay - Total delay including site delay and appropriate buffer (default: 4000 + 15000)
 * @returns {Promise<Object>} Cleanup results
 */
async function performRealtimeWindowCleanup(browserInstance, threshold = REALTIME_CLEANUP_THRESHOLD, forceDebug, totalDelay = 19000) {
  try {
    const allPages = await browserInstance.pages();
    
    // Initialize result object with consistent shape
    const result = {
      success: false,
      closedCount: 0,
      totalPages: 0,
      remainingPages: 0,
      threshold: 0,
      cleanupDelay: 0,
      reason: '',
      error: null
    };
    
    // Skip cleanup if we don't have enough pages to warrant it
    if (allPages.length <= Math.max(threshold, REALTIME_CLEANUP_MIN_PAGES)) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[realtime_cleanup] Only ${allPages.length} pages open, threshold is ${threshold} - no cleanup needed`));
      }
      result.success = true;
      result.totalPages = allPages.length;
      result.reason = 'below_threshold';
      return result;
    }

    // Use the provided total delay (already includes appropriate buffer)
    const cleanupDelay = totalDelay;
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[realtime_cleanup] Waiting ${cleanupDelay}ms before cleanup (threshold: ${threshold})`));
    }
    await new Promise(resolve => setTimeout(resolve, cleanupDelay));
    
    const allPagesAfterDelay = await browserInstance.pages();
    
    // Also check for and close any popup contexts
    try {
      const contexts = await browserInstance.browserContexts();
      for (const context of contexts) {
        if (context.isIncognito && context !== browserInstance.defaultBrowserContext()) {
          const contextPages = await context.pages();
          if (forceDebug) {
            console.log(formatLogMessage('debug', `[realtime_cleanup] Found ${contextPages.length} pages in popup context`));
          }
          // Close popup context pages
          for (const page of contextPages) {
            if (!page.isClosed()) {
              await page.close();
            }
          }
        }
      }
    } catch (contextErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[realtime_cleanup] Context cleanup error: ${contextErr.message}`));
      }
    }
    
    // Find main Puppeteer page (usually about:blank)
    let mainPage = allPagesAfterDelay.find(page => {
      // Cache page.url() for main page detection
      const pageUrl = page.url();
      return pageUrl === 'about:blank' || pageUrl === '' || pageUrl.startsWith('chrome://');
    }) || allPagesAfterDelay[0]; // Fallback to first page

    // Get pages sorted by creation time (oldest first)
    const sortedPages = allPagesAfterDelay
      .filter(page => {
        // Cache page.isClosed() for filtering
        const isPageClosed = page.isClosed();
        return page !== mainPage && !isPageClosed;
      })
      .sort((a, b) => {
        const timeA = pageCreationTracker.get(a) || 0;
        const timeB = pageCreationTracker.get(b) || 0;
        return timeA - timeB; // Oldest first
      });

    // Calculate how many pages to close
    const pagesToKeep = threshold - 1; // -1 for main page
    const pagesToClose = sortedPages.slice(0, Math.max(0, sortedPages.length - pagesToKeep));

    // Filter out pages that are still being used
    const safetyChecks = await Promise.all(
      pagesToClose.map(page => isPageSafeToClose(page, forceDebug))
    );
    
    const safePagesToClose = pagesToClose.filter((page, index) => safetyChecks[index]);
    const unsafePagesCount = pagesToClose.length - safePagesToClose.length;
    
    if (unsafePagesCount > 0 && forceDebug) {
      console.log(formatLogMessage('debug', `[realtime_cleanup] Skipping ${unsafePagesCount} active pages for safety`));
    }

    if (safePagesToClose.length === 0) {
      if (forceDebug) {
        const reason = pagesToClose.length === 0 ? 
          `${sortedPages.length} content pages, keeping ${pagesToKeep}` :
          `${pagesToClose.length} pages still active`;
        console.log(formatLogMessage('debug', `[realtime_cleanup] No pages need closing (${reason})`));
      }
      result.success = true;
      result.totalPages = allPagesAfterDelay.length;
      result.reason = 'no_cleanup_needed';
      return result;
    }

    // Close oldest pages
    let closedCount = 0;
    for (const page of safePagesToClose) {
      try {
        // Cache both page state and URL for this iteration
        const isPageClosed = page.isClosed();
        const pageUrl = page.url();
        
        if (!isPageClosed) {
          await page.close();
          pageCreationTracker.delete(page); // Remove from tracker
          closedCount++;
          
          if (forceDebug) {
            console.log(formatLogMessage('debug', `[realtime_cleanup] Closed old page: ${pageUrl.substring(0, 50)}...`));
          }
        }
      } catch (closeErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[realtime_cleanup] Failed to close page: ${closeErr.message}`));
        }
      }
    }

    const remainingPages = allPagesAfterDelay.length - closedCount;
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[realtime_cleanup] Closed ${closedCount}/${pagesToClose.length} oldest pages (${unsafePagesCount} skipped for safety), ${remainingPages} pages remaining`));
    }

    result.success = true;
    result.closedCount = closedCount;
    result.totalPages = allPagesAfterDelay.length;
    result.remainingPages = remainingPages;
    result.threshold = threshold;
    result.cleanupDelay = cleanupDelay;
    result.reason = 'cleanup_completed';
    return result;
  } catch (cleanupErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[realtime_cleanup] Cleanup failed: ${cleanupErr.message}`));
    }
    // Initialize result object with consistent shape for error case
    const result = {
      success: false,
      closedCount: 0,
      totalPages: 0,
      remainingPages: 0,
      threshold: 0,
      cleanupDelay: 0,
      reason: '',
      error: cleanupErr.message
    };
    return result;
  }
}

/**
 * Determines if a page appears to be from a previous scan and can be safely closed
 * @param {import('puppeteer').Page} page - Page to evaluate
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Promise<boolean>} True if page appears to be from previous scan
 */
async function isPageFromPreviousScan(page, forceDebug) {
  try {
    // FIX: Check page state first before any operations
    if (page.isClosed()) {
      return true; // Closed pages should be cleaned up
    }
    // Cache page.url() for all checks in this function
    const pageUrl = page.url();
    
    // Always consider these as old/closeable
    if (pageUrl === 'about:blank' || 
        pageUrl === '' || 
        pageUrl.startsWith('chrome://') ||
        pageUrl.startsWith('chrome-error://') ||
        pageUrl.startsWith('data:')) {
      return false; // Don't close blank pages here, handled separately
    }
    
    // Check if page has been idle (no recent navigation)
    // This is a heuristic - pages from previous scans are likely to be idle
    try {
      const title = await page.title();
      // Pages with generic titles or error states are likely old
      if (title.includes('404') || 
          title.includes('Error') || 
          title.includes('Not Found') ||
          title === '') {
        return true;
      }
    } catch (titleErr) {
      // If we can't get title, page might be in bad state
      return true;
    }
    
    // Default: consider most content pages as potentially old in conservative mode
    return false; // Conservative - don't close unless we're sure
  } catch (err) {
    if (forceDebug) {
      try {
        // Cache URL for error logging - wrap in try-catch as page might be closed
        const pageUrl = page.url();
        console.log(formatLogMessage('debug', `[isPageFromPreviousScan] Error evaluating page ${pageUrl}: ${err.message}`));
      } catch (urlErr) {
        console.log(formatLogMessage('debug', `[isPageFromPreviousScan] Error evaluating page: ${err.message}`));
      }
    }
    return false; // Conservative - don't close if we can't evaluate
  }
}

/**
 * Tracks a new page for realtime cleanup purposes
 * @param {import('puppeteer').Page} page - Page to track
 */
function trackPageForRealtime(page) {
  pageCreationTracker.set(page, ++pageCreationCounter);
  updatePageUsage(page, false); // Initialize usage tracking
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

/**
 * Performs comprehensive cleanup of page resources before operations that might cause detached frames
 * Also attempts to stop any pending navigations that might interfere
 * Used before reloads, navigations, and other operations that can trigger frame detachment
 * @param {import('puppeteer').Page} page - Page to clean up
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Promise<boolean>} True if cleanup succeeded
 */
async function cleanupPageBeforeReload(page, forceDebug = false) {
  try {
    // Cache page.isClosed() to avoid repeated browser calls
    const isPageClosed = page.isClosed();
    if (isPageClosed) {
      return false;
    }

    // First, try to stop any pending navigation
    try {
      await page.evaluate(() => {
        // Stop any ongoing navigation
        if (window.stop) {
          window.stop();
        }
      });
    } catch (e) {
      // Page might be mid-navigation, that's ok
    }

    // Wait a bit for navigation to stop
    await new Promise(resolve => setTimeout(resolve, 500));

    // FIX: Check if page is still open after delay before cleanup
    if (page.isClosed()) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', 'Page closed during cleanup delay'));
      }
      return false;
    }

    // Now do the full cleanup
    try {
      await page.evaluate(() => {
        // Stop all media elements
        document.querySelectorAll('video, audio').forEach(media => {
          try { 
            media.pause(); 
            media.src = ''; 
            media.load();
          } catch(e) {}
        });
      
      // Clear all timers and intervals
      const highestId = setTimeout(() => {}, 0);
      for (let i = highestId; i >= 0; i--) {
        clearTimeout(i);
        clearInterval(i);
      }
      
      // Stop all animations
      if (typeof cancelAnimationFrame !== 'undefined') {
        const highestRAF = requestAnimationFrame(() => {});
        for (let i = highestRAF; i >= 0; i--) {
          cancelAnimationFrame(i);
        }
      }
      
      // Clear all iframes properly
      document.querySelectorAll('iframe').forEach(iframe => {
        try {
          // Stop iframe content first
          if (iframe.contentWindow) {
            iframe.contentWindow.stop();
          }
          iframe.src = 'about:blank';
          iframe.remove();
        } catch(e) {}
      });
      
      // Force garbage collection if available
      if (window.gc) window.gc();
      });

    } catch (evalErr) {
      // Page closed during cleanup
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Page cleanup evaluation failed: ${evalErr.message}`));
      }
      return false;
    }

    if (forceDebug) {
      console.log(formatLogMessage('debug', 'Page resources cleaned before reload'));
    }

    return true;
  } catch (err) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Page cleanup error: ${err.message}`));
    }
    return false;
  }
}

module.exports = {
  checkBrowserHealth,
  checkBrowserMemory,
  testBrowserConnectivity,
  performGroupWindowCleanup,
  performRealtimeWindowCleanup,
  trackPageForRealtime,
  testNetworkCapability,
  isQuicklyResponsive,
  performHealthAssessment,
  monitorBrowserHealth,
  isBrowserHealthy,
  isCriticalProtocolError,
  updatePageUsage,
  cleanupPageBeforeReload
};

// Clean up tracking maps when pages are closed
const originalPageClose = require('puppeteer').Page.prototype.close;
if (originalPageClose) {
  require('puppeteer').Page.prototype.close = async function(...args) {
    try {
      // Clean up tracking data
      pageCreationTracker.delete(this);
      pageUsageTracker.delete(this);
    } catch (err) {
      // Ignore cleanup errors
    }
    return originalPageClose.apply(this, args);
  };
}
