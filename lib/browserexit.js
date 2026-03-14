/**
 * Browser exit and cleanup handler module
 * Provides graceful and forced browser closure functionality with comprehensive temp file cleanup
 */


const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Constants for temp file cleanup
const CHROME_TEMP_PATHS = [
  '/tmp',
  '/dev/shm',
  '/tmp/snap-private-tmp/snap.chromium/tmp'
];

const CHROME_TEMP_PATTERNS = [
  /^\.?com\.google\.Chrome\./,
  /^\.?org\.chromium\.Chromium\./,
  /^puppeteer-/
];

/**
 * Count and remove matching Chrome/Puppeteer temp entries from a directory using fs
 * @param {string} basePath - Directory to scan
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {number} Number of items cleaned
 */
function cleanTempDir(basePath, forceDebug) {
  let entries;
  try {
    entries = fs.readdirSync(basePath);
  } catch {
    if (forceDebug) console.log(`[debug] [temp-cleanup] Cannot read ${basePath}`);
    return 0;
  }

  let cleaned = 0;
  for (const entry of entries) {
    let matched = false;
    for (const re of CHROME_TEMP_PATTERNS) {
      if (re.test(entry)) { matched = true; break; }
    }
    if (!matched) continue;

    try {
      fs.rmSync(path.join(basePath, entry), { recursive: true, force: true });
      cleaned++;
      if (forceDebug) console.log(`[debug] [temp-cleanup] Removed ${basePath}/${entry}`);
    } catch (rmErr) {
      if (forceDebug) console.log(`[debug] [temp-cleanup] Failed to remove ${basePath}/${entry}: ${rmErr.message}`);
    }
  }

  return cleaned;
}

/**
 * Clean Chrome temporary files and directories
 * @param {Object} options - Cleanup options
 * @param {boolean} options.includeSnapTemp - Whether to clean snap temp directories
 * @param {boolean} options.forceDebug - Whether to output debug logs
 * @param {boolean} options.comprehensive - Whether to perform comprehensive cleanup of all temp locations
 * @returns {Object} Cleanup results
 */
function cleanupChromeTempFiles(options = {}) {
  const {
    includeSnapTemp = false,
    forceDebug = false,
    comprehensive = false
  } = options;

  try {
    const paths = comprehensive || includeSnapTemp
      ? CHROME_TEMP_PATHS
      : CHROME_TEMP_PATHS.slice(0, 2); // /tmp and /dev/shm only

    let totalCleaned = 0;
    for (const basePath of paths) {
      totalCleaned += cleanTempDir(basePath, forceDebug);
    }

    if (forceDebug) {
      console.log(`[debug] [temp-cleanup] Cleanup completed (${totalCleaned} items)`);
    }

    return { success: true, itemsCleaned: totalCleaned };
  } catch (cleanupErr) {
    if (forceDebug) {
      console.log(`[debug] [temp-cleanup] Chrome cleanup error: ${cleanupErr.message}`);
    }
    return { success: false, error: cleanupErr.message, itemsCleaned: 0 };
  }
}

/**
 * Comprehensive temp file cleanup that checks all known Chrome temp locations
 * @param {Object} options - Cleanup options
 * @param {boolean} options.forceDebug - Whether to output debug logs
 * @param {boolean} options.verbose - Whether to show verbose output
 * @returns {Object} Cleanup results
 */
function comprehensiveChromeTempCleanup(options = {}) {
  const { forceDebug = false, verbose = false } = options;

  try {
    if (verbose && !forceDebug) {
      console.log(`[temp-cleanup] Scanning Chrome/Puppeteer temporary files...`);
    }

    let totalCleaned = 0;
    for (const basePath of CHROME_TEMP_PATHS) {
      totalCleaned += cleanTempDir(basePath, forceDebug);
    }

    if (verbose && totalCleaned > 0) {
      console.log(`[temp-cleanup] Removed ${totalCleaned} temporary file(s)/folder(s)`);
    } else if (verbose && totalCleaned === 0) {
      console.log(`[temp-cleanup] Clean - no remaining temporary files`);
    } else if (forceDebug) {
      console.log(`[debug] [temp-cleanup] Comprehensive cleanup completed (${totalCleaned} items)`);
    }

    return { success: true, itemsCleaned: totalCleaned };
  } catch (err) {
    const errorMsg = `Comprehensive temp file cleanup failed: ${err.message}`;
    if (verbose) {
      console.warn(`[temp-cleanup] ${errorMsg}`);
    } else if (forceDebug) {
      console.log(`[debug] [temp-cleanup] ${errorMsg}`);
    }
    return { success: false, error: err.message, itemsCleaned: 0 };
  }
}

/**
 * Cleanup specific user data directory (for browser instances)
 * @param {string} userDataDir - Path to user data directory to clean
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<Object>} Cleanup results
 */
async function cleanupUserDataDir(userDataDir, forceDebug = false) {
  if (!userDataDir) {
    return { success: true, cleaned: false, reason: 'No user data directory specified' };
  }

  try {
    
    if (!fs.existsSync(userDataDir)) {
      if (forceDebug) {
        console.log(`[debug] [user-data] User data directory does not exist: ${userDataDir}`);
      }
      return { success: true, cleaned: false, reason: 'Directory does not exist' };
    }

    fs.rmSync(userDataDir, { recursive: true, force: true });
    
    if (forceDebug) {
      console.log(`[debug] [user-data] Cleaned user data directory: ${userDataDir}`);
    }
    
    return { success: true, cleaned: true };
    
  } catch (rmErr) {
    if (forceDebug) {
      console.log(`[debug] [user-data] Failed to remove user data directory ${userDataDir}: ${rmErr.message}`);
    }
    return { success: false, error: rmErr.message, cleaned: false };
  }
}

/**
 * Attempts to gracefully close all browser pages and the browser instance
 * @param {import('puppeteer').Browser} browser - The Puppeteer browser instance
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<void>}
 */
async function gracefulBrowserCleanup(browser, forceDebug = false) {
  // FIX: Check browser connection before operations
  if (!browser || !browser.isConnected()) {
    if (forceDebug) console.log(`[debug] [browser] Browser not connected, skipping cleanup`);
    return;
  }
  if (forceDebug) console.log(`[debug] [browser] Getting all browser pages...`);
  let pages;
  try {
    pages = await browser.pages();
  } catch (pagesErr) {
    if (forceDebug) console.log(`[debug] [browser] Failed to get pages: ${pagesErr.message}`);
    return;
  }
  if (forceDebug) console.log(`[debug] [browser] Found ${pages.length} pages to close`);
  
  await Promise.all(pages.map(async (page) => {
    if (!page.isClosed()) {
      try {
        // FIX: Wrap page.url() in try-catch to handle race condition
        let pageUrl = 'unknown';
        try {
          pageUrl = page.url();
        } catch (urlErr) {
          // Page closed between check and url call
        }
        
        if (forceDebug) console.log(`[debug] [browser] Closing page: ${pageUrl}`);
        await page.close();
        if (forceDebug) console.log(`[debug] [browser] Page closed successfully`);
      } catch (err) {
        // Force close if normal close fails
        if (forceDebug) console.log(`[debug] [browser] Force closing page: ${err.message}`);
      }
    }
  }));
  
  if (forceDebug) console.log(`[debug] [browser] All pages closed, closing browser...`);
  
  // FIX: Check browser is still connected before closing
  try {
    if (browser.isConnected()) {
      await browser.close();
      if (forceDebug) console.log(`[debug] [browser] Browser closed successfully`);
    } else {
      if (forceDebug) console.log(`[debug] [browser] Browser already disconnected`);
    }
  } catch (closeErr) {
    if (forceDebug) console.log(`[debug] [browser] Browser close failed: ${closeErr.message}`);
  }
}

/**
 * Force kills the browser process using system signals
 * @param {import('puppeteer').Browser} browser - The Puppeteer browser instance
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<void>}
 */
async function forceBrowserKill(browser, forceDebug = false) {
  try {
    if (forceDebug) console.log(`[debug] [browser] Attempting force closure of browser process...`);
    
    const browserProcess = browser.process();
    if (!browserProcess || !browserProcess.pid) {
      if (forceDebug) console.log(`[debug] [browser] No browser process available`);
      return;
    }

    const mainPid = browserProcess.pid;
    if (forceDebug) console.log(`[debug] [browser] Main Chrome PID: ${mainPid}`);

    // Find and kill ALL related Chrome processes    
    
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
        console.log(`[debug] [browser] Found ${pidsToKill.length} Chrome processes to kill: [${pidsToKill.join(', ')}]`);
      }
      
      // Kill all processes with SIGTERM first (graceful)
      for (const pid of pidsToKill) {
        try {
          process.kill(pid, 'SIGTERM');
          if (forceDebug) console.log(`[debug] [browser] Sent SIGTERM to PID ${pid}`);
        } catch (killErr) {
          if (forceDebug) console.log(`[debug] [browser] Failed to send SIGTERM to PID ${pid}: ${killErr.message}`);
        }
      }
      
      // Wait for graceful termination
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Force kill any remaining processes with SIGKILL
      for (const pid of pidsToKill) {
        try {
          // Check if process still exists using signal 0
          process.kill(pid, 0);
          // If we reach here, process still exists - force kill it
          process.kill(pid, 'SIGKILL');
          if (forceDebug) console.log(`[debug] [browser] Force killed PID ${pid} with SIGKILL`);
        } catch (checkErr) {
          // Process already dead (ESRCH error is expected and good)
          if (forceDebug && checkErr.code !== 'ESRCH') {
            console.log(`[debug] [browser] Error checking/killing PID ${pid}: ${checkErr.message}`);
          }
        }
      }

      // Final verification - check if any processes are still alive
      if (forceDebug) {
        try {
          const verifyCmd = `ps -eo pid,cmd | grep "puppeteer.*chrome" | grep -v grep | wc -l`;
          const remainingCount = execSync(verifyCmd, { encoding: 'utf8', timeout: 2000 }).trim();
          console.log(`[debug] [browser] Remaining Chrome processes after cleanup: ${remainingCount}`);
        } catch (verifyErr) {
          console.log(`[debug] [browser] Could not verify process cleanup: ${verifyErr.message}`);
        }
      }
      
    } catch (psErr) {
      // Fallback to original method if ps command fails
      if (forceDebug) console.log(`[debug] [browser] ps command failed, using fallback method: ${psErr.message}`);
      
      try {
        browserProcess.kill('SIGTERM');
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Check if main process still exists and force kill if needed
        try {
          process.kill(mainPid, 0); // Check existence
          browserProcess.kill('SIGKILL'); // Force kill if still alive
          if (forceDebug) console.log(`[debug] [browser] Fallback: Force killed main PID ${mainPid}`);
        } catch (checkErr) {
          if (forceDebug && checkErr.code !== 'ESRCH') {
            console.log(`[debug] [browser] Fallback check error for PID ${mainPid}: ${checkErr.message}`);
          }
        }
      } catch (fallbackErr) {
        if (forceDebug) console.log(`[debug] [browser] Fallback kill failed: ${fallbackErr.message}`);
      }
    }
    
  } catch (forceKillErr) {
    console.error(`[error] [browser] Failed to force kill browser: ${forceKillErr.message}`);
  }
  
  try {
    if (browser.isConnected()) {
      browser.disconnect();
      if (forceDebug) console.log(`[debug] [browser] Browser connection disconnected`);
    }
  } catch (disconnectErr) {
    if (forceDebug) console.log(`[debug] [browser] Failed to disconnect browser: ${disconnectErr.message}`);
  }
}

/**
 * Kill all Chrome processes by command line pattern (nuclear option)
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<void>}
 */
async function killAllPuppeteerChrome(forceDebug = false) {
  try {    
    if (forceDebug) console.log(`[debug] [browser] Nuclear option: killing all puppeteer Chrome processes...`);
    
    try {
      execSync(`pkill -f "puppeteer.*chrome"`, { stdio: 'ignore', timeout: 5000 });
      if (forceDebug) console.log(`[debug] [browser] pkill completed`);
    } catch (pkillErr) {
      if (forceDebug && pkillErr.status !== 1) {
        console.log(`[debug] [browser] pkill failed with status ${pkillErr.status}: ${pkillErr.message}`);
      }
    }
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
  } catch (nuclearErr) {
    console.error(`[error] [browser] Nuclear Chrome kill failed: ${nuclearErr.message}`);
  }
}

/**
 * Handles comprehensive browser cleanup including processes, temp files, and user data
 * @param {import('puppeteer').Browser} browser - The Puppeteer browser instance
 * @param {Object} options - Cleanup options
 * @param {boolean} options.forceDebug - Whether to output debug logs
 * @param {number} options.timeout - Timeout in milliseconds before force closure (default: 10000)
 * @param {boolean} options.exitOnFailure - Whether to exit process on cleanup failure (default: true)
 * @param {boolean} options.cleanTempFiles - Whether to clean standard temp files (default: true)
 * @param {boolean} options.comprehensiveCleanup - Whether to perform comprehensive temp file cleanup (default: false)
 * @param {string} options.userDataDir - User data directory to clean (optional)
 * @param {boolean} options.verbose - Whether to show verbose cleanup output (default: false)
 * @returns {Promise<Object>} - Returns cleanup results object
 */
async function handleBrowserExit(browser, options = {}) {
  const {
    forceDebug = false,
    timeout = 10000,
    exitOnFailure = true,
    cleanTempFiles = true,
    comprehensiveCleanup = false,
    userDataDir = null,
    verbose = false
  } = options;
  
  if (forceDebug) console.log(`[debug] [browser] Starting comprehensive browser cleanup...`);
  
  const results = {
    browserClosed: false,
    tempFilesCleanedCount: 0,
    userDataCleaned: false,
    success: false,
    errors: []
  };
  
  try {
    // Step 1: Browser process cleanup
    try {
      // Race cleanup against timeout
      await Promise.race([
        gracefulBrowserCleanup(browser, forceDebug),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Browser cleanup timeout')), timeout)
        )
      ]);
      
      results.browserClosed = true;
      
    } catch (browserCloseErr) {
      results.errors.push(`Browser cleanup failed: ${browserCloseErr.message}`);
      
      if (forceDebug || verbose) {
        console.warn(`[warn] [browser] Browser cleanup had issues: ${browserCloseErr.message}`);
      }
      
      // Attempt force kill
      await forceBrowserKill(browser, forceDebug);

      // Nuclear option if force kill didn't work
      if (forceDebug) console.log(`[debug] [browser] Attempting nuclear cleanup...`);
      await killAllPuppeteerChrome(forceDebug);
      
      results.browserClosed = true; // Assume success after nuclear option
    }
    
    // Step 2: User data directory cleanup
    if (userDataDir) {
      const userDataResult = await cleanupUserDataDir(userDataDir, forceDebug);
      results.userDataCleaned = userDataResult.cleaned;
      if (!userDataResult.success) {
        results.errors.push(`User data cleanup failed: ${userDataResult.error}`);
      }
    }
    
    // Step 3: Temp file cleanup
    if (cleanTempFiles) {
      if (comprehensiveCleanup) {
        const tempResult = await comprehensiveChromeTempCleanup({ forceDebug, verbose });
        results.tempFilesCleanedSuccess = tempResult.success;
        results.tempFilesCleanedComprehensive = true;
        
        if (tempResult.success) {
          results.tempFilesCleanedCount = tempResult.itemsCleaned;
        } else {
          results.errors.push(`Comprehensive temp cleanup failed: ${tempResult.error}`);
        }
      } else {
        const tempResult = await cleanupChromeTempFiles({ 
          includeSnapTemp: true, 
          forceDebug,
          comprehensive: false 
        });
        results.tempFilesCleanedSuccess = tempResult.success;
        
        if (tempResult.success) {
          results.tempFilesCleanedCount = tempResult.itemsCleaned;
        } else {
          results.errors.push(`Standard temp cleanup failed: ${tempResult.error}`);
        }
      }
    }
    
    // Determine overall success
    results.success = results.browserClosed && 
                     (results.errors.length === 0 || !exitOnFailure);
    
    if (forceDebug) {
      console.log(`[debug] [browser] Cleanup completed - Browser: ${results.browserClosed}, ` +
                  `Temp files: ${results.tempFilesCleanedCount || 0}, ` +
                  `User data: ${results.userDataCleaned}, ` +
                  `Errors: ${results.errors.length}`);
    }
    
    return results;
    
  } catch (overallErr) {
    results.errors.push(`Overall cleanup failed: ${overallErr.message}`);
    results.success = false;
    
    if (exitOnFailure) {
      if (forceDebug) console.log(`[debug] [browser] Forcing process exit due to cleanup failure`);
      process.exit(1);
    }
    
    return results;
  }
}

module.exports = {
  handleBrowserExit,
  gracefulBrowserCleanup,
  forceBrowserKill,
  killAllPuppeteerChrome,
  cleanupChromeTempFiles,
  comprehensiveChromeTempCleanup,
  cleanupUserDataDir,
  CHROME_TEMP_PATHS,
  CHROME_TEMP_PATTERNS
};
