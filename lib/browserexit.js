/**
 * Browser exit and cleanup handler module
 * Provides graceful and forced browser closure functionality
 */

/**
 * Attempts to gracefully close all browser pages and the browser instance
 * @param {import('puppeteer').Browser} browser - The Puppeteer browser instance
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<void>}
 */
async function gracefulBrowserCleanup(browser, forceDebug = false) {
  if (forceDebug) console.log(`[debug] Getting all browser pages...`);
  const pages = await browser.pages();
  if (forceDebug) console.log(`[debug] Found ${pages.length} pages to close`);
  
  await Promise.all(pages.map(async (page) => {
    if (!page.isClosed()) {
      try {
        if (forceDebug) console.log(`[debug] Closing page: ${page.url()}`);
        await page.close();
        if (forceDebug) console.log(`[debug] Page closed successfully`);
      } catch (err) {
        // Force close if normal close fails
        if (forceDebug) console.log(`[debug] Force closing page: ${err.message}`);
      }
    }
  }));
  
  if (forceDebug) console.log(`[debug] All pages closed, closing browser...`);
  await browser.close();
  if (forceDebug) console.log(`[debug] Browser closed successfully`);
}

/**
 * Force kills the browser process using system signals
 * @param {import('puppeteer').Browser} browser - The Puppeteer browser instance
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<void>}
 */
async function forceBrowserKill(browser, forceDebug = false) {
  try {
    if (forceDebug) console.log(`[debug] Attempting force closure of browser process...`);
    
    // Get the browser process
    const browserProcess = browser.process();
    
    if (browserProcess) {
      // First try SIGTERM (graceful)
      browserProcess.kill('SIGTERM');
      
      // Give it 2 seconds to terminate gracefully
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Check if process is still running
      if (!browserProcess.killed) {
        if (forceDebug) console.log(`[debug] Browser still running, sending SIGKILL...`);
        // Force kill with SIGKILL
        browserProcess.kill('SIGKILL');
      }
      
      if (forceDebug) console.log(`[debug] Browser process forcefully terminated`);
    }
  } catch (forceKillErr) {
    console.error(`[error] Failed to force kill browser: ${forceKillErr.message}`);
  }
  
  // Final cleanup - disconnect browser connection
  try {
    if (browser.isConnected()) {
      browser.disconnect();
      if (forceDebug) console.log(`[debug] Browser connection disconnected`);
    }
  } catch (disconnectErr) {
    if (forceDebug) console.log(`[debug] Failed to disconnect browser: ${disconnectErr.message}`);
  }
}

/**
 * Handles browser cleanup with timeout protection and force closure fallback
 * @param {import('puppeteer').Browser} browser - The Puppeteer browser instance
 * @param {Object} options - Cleanup options
 * @param {boolean} options.forceDebug - Whether to output debug logs
 * @param {number} options.timeout - Timeout in milliseconds before force closure (default: 10000)
 * @param {boolean} options.exitOnFailure - Whether to exit process on cleanup failure (default: true)
 * @returns {Promise<boolean>} - Returns true if cleanup was successful, false otherwise
 */
async function handleBrowserExit(browser, options = {}) {
  const {
    forceDebug = false,
    timeout = 10000,
    exitOnFailure = true
  } = options;
  
  if (forceDebug) console.log(`[debug] Starting browser cleanup...`);
  
  try {
    // Race cleanup against timeout
    await Promise.race([
      gracefulBrowserCleanup(browser, forceDebug),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Browser cleanup timeout')), timeout)
      )
    ]);
    
    return true;
  } catch (browserCloseErr) {
    console.warn(`[warn] Browser cleanup had issues: ${browserCloseErr.message}`);
    
    // Attempt force kill
    await forceBrowserKill(browser, forceDebug);
    
    if (exitOnFailure) {
      if (forceDebug) console.log(`[debug] Forcing process exit due to cleanup failure`);
      process.exit(1);
    }
    
    return false;
  }
}

module.exports = {
  handleBrowserExit,
  gracefulBrowserCleanup,
  forceBrowserKill
};