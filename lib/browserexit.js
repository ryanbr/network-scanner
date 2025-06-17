/**
 * Browser exit and cleanup handler module
 * Provides graceful and forced browser closure functionality with comprehensive temp file cleanup
 */

// Constants for temp file cleanup
const CHROME_TEMP_PATHS = [
  '/tmp',
  '/dev/shm',
  '/tmp/snap-private-tmp/snap.chromium/tmp'
];

const CHROME_TEMP_PATTERNS = [
  '.com.google.Chrome.*',        // Google Chrome temp files
  '.org.chromium.Chromium.*',
  'puppeteer-*',
  '.com.google.Chrome.*'         // Ensure Google Chrome pattern is included
];

/**
 * Clean Chrome temporary files and directories
 * @param {Object} options - Cleanup options
 * @param {boolean} options.includeSnapTemp - Whether to clean snap temp directories
 * @param {boolean} options.forceDebug - Whether to output debug logs
 * @param {boolean} options.comprehensive - Whether to perform comprehensive cleanup of all temp locations
 * @returns {Promise<Object>} Cleanup results
 */
async function cleanupChromeTempFiles(options = {}) {
  const {
    includeSnapTemp = false,
    forceDebug = false,
    comprehensive = false
  } = options;

  try {
    const { execSync } = require('child_process');

    // Base cleanup commands for standard temp directories
    const cleanupCommands = [
      'rm -rf /tmp/.com.google.Chrome.* 2>/dev/null || true',
      'rm -rf /tmp/.org.chromium.Chromium.* 2>/dev/null || true',
      'rm -rf /tmp/puppeteer-* 2>/dev/null || true',
      'rm -rf /dev/shm/.com.google.Chrome.* 2>/dev/null || true',
      'rm -rf /dev/shm/.org.chromium.Chromium.* 2>/dev/null || true'
    ];

    // Add snap-specific cleanup if requested
    if (includeSnapTemp || comprehensive) {
      cleanupCommands.push(
        'rm -rf /tmp/snap-private-tmp/snap.chromium/tmp/.org.chromium.Chromium.* 2>/dev/null || true',
        'rm -rf /tmp/snap-private-tmp/snap.chromium/tmp/puppeteer-* 2>/dev/null || true'
      );
    }

    let totalCleaned = 0;
    
    for (const command of cleanupCommands) {
      try {
        // Get file count before cleanup for reporting
        const listCommand = command.replace('rm -rf', 'ls -1d').replace(' 2>/dev/null || true', ' 2>/dev/null | wc -l || echo 0');
        const fileCount = parseInt(execSync(listCommand, { stdio: 'pipe' }).toString().trim()) || 0;
        
        if (fileCount > 0) {
          execSync(command, { stdio: 'ignore' });
          totalCleaned += fileCount;
          
          if (forceDebug) {
            const pathPattern = command.match(/rm -rf ([^ ]+)/)?.[1] || 'unknown';
            console.log(`[debug] [temp-cleanup] Cleaned ${fileCount} items from ${pathPattern}`);
          }
        }
      } catch (cmdErr) {
        // Ignore individual command errors but log in debug mode
        if (forceDebug) {
          console.log(`[debug] [temp-cleanup] Cleanup command failed: ${command} (${cmdErr.message})`);
        }
      }
    }

    if (forceDebug) {
      console.log(`[debug] [temp-cleanup] Standard cleanup completed (${totalCleaned} items)`);
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
 * Comprehensive temp file cleanup that systematically checks all known Chrome temp locations
 * @param {Object} options - Cleanup options
 * @param {boolean} options.forceDebug - Whether to output debug logs
 * @param {boolean} options.verbose - Whether to show verbose output
 * @returns {Promise<Object>} Cleanup results
 */
async function comprehensiveChromeTempCleanup(options = {}) {
  const { forceDebug = false, verbose = false } = options;
  
  try {
    const { execSync } = require('child_process');
    let totalCleaned = 0;
    
    if (verbose && !forceDebug) {
      console.log(`[temp-cleanup] Scanning Chrome/Puppeteer temporary files...`);
    }
    
    for (const basePath of CHROME_TEMP_PATHS) {
      // Check if the base path exists before trying to clean it
      try {
        const pathExists = execSync(`test -d "${basePath}" && echo "exists" || echo "missing"`, { stdio: 'pipe' })
          .toString().trim() === 'exists';
        
        if (!pathExists) {
          if (forceDebug) {
            console.log(`[debug] [temp-cleanup] Skipping non-existent path: ${basePath}`);
          }
          continue;
        }
        
        for (const pattern of CHROME_TEMP_PATTERNS) {
          const fullPattern = `${basePath}/${pattern}`;
          
          // Count items before deletion
          const countCommand = `ls -1d ${fullPattern} 2>/dev/null | wc -l || echo 0`;
          const itemCount = parseInt(execSync(countCommand, { stdio: 'pipe' }).toString().trim()) || 0;
          
          if (itemCount > 0) {
            const deleteCommand = `rm -rf ${fullPattern} 2>/dev/null || true`;
            execSync(deleteCommand, { stdio: 'ignore' });
            totalCleaned += itemCount;
            
            if (forceDebug) {
              console.log(`[debug] [temp-cleanup] Removed ${itemCount} items matching ${fullPattern}`);
            }
          }
        }
      } catch (pathErr) {
        if (forceDebug) {
          console.log(`[debug] [temp-cleanup] Error checking path ${basePath}: ${pathErr.message}`);
        }
      }
    }
    
    if (verbose && totalCleaned > 0) {
      console.log(`[temp-cleanup] ? Removed ${totalCleaned} temporary file(s)/folder(s)`);
    } else if (verbose && totalCleaned === 0) {
      console.log(`[temp-cleanup] ??  No temporary files found to remove`);
    } else if (forceDebug) {
      console.log(`[debug] [temp-cleanup] Comprehensive cleanup completed (${totalCleaned} items)`);
    }
    
    return { success: true, itemsCleaned: totalCleaned };
    
  } catch (err) {
    const errorMsg = `Comprehensive temp file cleanup failed: ${err.message}`;
    if (verbose) {
      console.warn(`[temp-cleanup] ? ${errorMsg}`);
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
    const fs = require('fs');
    
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
  if (forceDebug) console.log(`[debug] [browser] Getting all browser pages...`);
  const pages = await browser.pages();
  if (forceDebug) console.log(`[debug] [browser] Found ${pages.length} pages to close`);
  
  await Promise.all(pages.map(async (page) => {
    if (!page.isClosed()) {
      try {
        if (forceDebug) console.log(`[debug] [browser] Closing page: ${page.url()}`);
        await page.close();
        if (forceDebug) console.log(`[debug] [browser] Page closed successfully`);
      } catch (err) {
        // Force close if normal close fails
        if (forceDebug) console.log(`[debug] [browser] Force closing page: ${err.message}`);
      }
    }
  }));
  
  if (forceDebug) console.log(`[debug] [browser] All pages closed, closing browser...`);
  await browser.close();
  if (forceDebug) console.log(`[debug] [browser] Browser closed successfully`);
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
      await new Promise(resolve => setTimeout(resolve, 3000));
      
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
    const { execSync } = require('child_process');
    
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
    tempFilescleaned: 0,
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
