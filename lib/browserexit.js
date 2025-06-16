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
    
    const browserProcess = browser.process();
    if (!browserProcess || !browserProcess.pid) {
      if (forceDebug) console.log(`[debug] No browser process available`);
      return;
    }

    const mainPid = browserProcess.pid;
    if (forceDebug) console.log(`[debug] Main Chrome PID: ${mainPid}`);

    // Find and kill ALL related Chrome processes
    const { execSync } = require('child_process');
     
    
    try {
      // Find all Chrome processes with puppeteer in command line
      const psCmd = `ps -eo pid,cmd | grep "puppeteer.*chrome" | grep -v grep`;
      const psOutput = execSync(psCmd, { encoding: 'utf8', timeout: 5000 });
      const lines = psOutput.trim().split('\n').filter(line => line.trim());
      
      const pidsToKill = [];
      
      for (const line of lines) {
        const match = line.trim().match(/^\s*(\d+)/);
        if (match) {
          const pid = parseInt(match[1]);
          if (!isNaN(pid)) {
            pidsToKill.push(pid);
          }
        }
      }
      
      if (forceDebug) {
        console.log(`[debug] Found ${pidsToKill.length} Chrome processes to kill: [${pidsToKill.join(', ')}]`);
      }
      
      // Kill all processes with SIGTERM first (graceful)
      for (const pid of pidsToKill) {
        try {
          process.kill(pid, 'SIGTERM');
          if (forceDebug) console.log(`[debug] Sent SIGTERM to PID ${pid}`);
        } catch (killErr) {
          if (forceDebug) console.log(`[debug] Failed to send SIGTERM to PID ${pid}: ${killErr.message}`);
        }
      }
      
      // Wait for graceful termination
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      // Force kill any remaining processes with SIGKILL
      for (const pid of pidsToKill) {
        try {
          // Check if process still exists using signal 0
          process.kill(pid, 0);
          // If we reach here, process still exists - force kill it
          process.kill(pid, 'SIGKILL');
          if (forceDebug) console.log(`[debug] Force killed PID ${pid} with SIGKILL`);
        } catch (checkErr) {
          // Process already dead (ESRCH error is expected and good)
          if (forceDebug && checkErr.code !== 'ESRCH') {
            console.log(`[debug] Error checking/killing PID ${pid}: ${checkErr.message}`);
          }
        }
      }

      // Final verification - check if any processes are still alive
      if (forceDebug) {
        try {
          const verifyCmd = `ps -eo pid,cmd | grep "puppeteer.*chrome" | grep -v grep | wc -l`;
          const remainingCount = execSync(verifyCmd, { encoding: 'utf8', timeout: 2000 }).trim();
          console.log(`[debug] Remaining Chrome processes after cleanup: ${remainingCount}`);
        } catch (verifyErr) {
          console.log(`[debug] Could not verify process cleanup: ${verifyErr.message}`);
        }
      }
      
    } catch (psErr) {
      // Fallback to original method if ps command fails
      if (forceDebug) console.log(`[debug] ps command failed, using fallback method: ${psErr.message}`);
      
      try {
        browserProcess.kill('SIGTERM');
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Check if main process still exists and force kill if needed
        try {
          process.kill(mainPid, 0); // Check existence
          browserProcess.kill('SIGKILL'); // Force kill if still alive
          if (forceDebug) console.log(`[debug] Fallback: Force killed main PID ${mainPid}`);
        } catch (checkErr) {
          if (forceDebug && checkErr.code !== 'ESRCH') {
            console.log(`[debug] Fallback check error for PID ${mainPid}: ${checkErr.message}`);
          }
        }
      } catch (fallbackErr) {
        if (forceDebug) console.log(`[debug] Fallback kill failed: ${fallbackErr.message}`);
      }
    }
    
  } catch (forceKillErr) {
    console.error(`[error] Failed to force kill browser: ${forceKillErr.message}`);
  }
  
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
 * Kill all Chrome processes by command line pattern (nuclear option)
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<void>}
 */
async function killAllPuppeteerChrome(forceDebug = false) {
  try {
    const { execSync } = require('child_process');
    
    if (forceDebug) console.log(`[debug] Nuclear option: killing all puppeteer Chrome processes...`);
    
    try {
      execSync(`pkill -f "puppeteer.*chrome"`, { stdio: 'ignore', timeout: 5000 });
      if (forceDebug) console.log(`[debug] pkill completed`);
    } catch (pkillErr) {
      if (forceDebug && pkillErr.status !== 1) {
        console.log(`[debug] pkill failed with status ${pkillErr.status}: ${pkillErr.message}`);
      }
    }
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
  } catch (nuclearErr) {
    console.error(`[error] Nuclear Chrome kill failed: ${nuclearErr.message}`);
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

    // Nuclear option if force kill didn't work
    if (forceDebug) console.log(`[debug] Attempting nuclear cleanup...`);
    await killAllPuppeteerChrome(forceDebug);
    
    
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
  forceBrowserKill,
  killAllPuppeteerChrome
};