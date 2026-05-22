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
 * @param {boolean} options.comprehensive - Equivalent to includeSnapTemp; kept
 *   for source compatibility with prior callers that distinguished the two.
 * @param {boolean} options.verbose - Whether to print a user-facing summary
 *   (in addition to forceDebug's developer logs)
 * @returns {Object} Cleanup results
 */
function cleanupChromeTempFiles(options = {}) {
  const {
    includeSnapTemp = false,
    forceDebug = false,
    comprehensive = false,
    verbose = false
  } = options;

  try {
    if (verbose && !forceDebug) {
      console.log(`[temp-cleanup] Scanning Chrome/Puppeteer temporary files...`);
    }

    const paths = comprehensive || includeSnapTemp
      ? CHROME_TEMP_PATHS
      : CHROME_TEMP_PATHS.slice(0, 2); // /tmp and /dev/shm only

    let totalCleaned = 0;
    for (const basePath of paths) {
      totalCleaned += cleanTempDir(basePath, forceDebug);
    }

    if (verbose) {
      console.log(totalCleaned > 0
        ? `[temp-cleanup] Removed ${totalCleaned} temporary file(s)/folder(s)`
        : `[temp-cleanup] Clean - no remaining temporary files`);
    } else if (forceDebug) {
      console.log(`[debug] [temp-cleanup] Cleanup completed (${totalCleaned} items)`);
    }

    return { success: true, itemsCleaned: totalCleaned };
  } catch (cleanupErr) {
    const errorMsg = `Chrome temp cleanup failed: ${cleanupErr.message}`;
    if (verbose) {
      console.warn(`[temp-cleanup] ${errorMsg}`);
    } else if (forceDebug) {
      console.log(`[debug] [temp-cleanup] ${errorMsg}`);
    }
    return { success: false, error: cleanupErr.message, itemsCleaned: 0 };
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

  // fs.rmSync({force: true}) treats ENOENT as a no-op, so an existsSync
  // pre-check is two syscalls where one would do (and a TOCTOU besides).
  // If the dir was already gone we just report cleaned:true without drama.
  try {
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

    // PRIMARY PATH: kill OUR browser process tree only.
    //
    // The previous primary path ran `ps | grep "puppeteer.*chrome"` and
    // SIGTERM'd every match, which kills puppeteer-chrome processes spawned
    // by ANY other process on the machine (concurrent nwss runs, automate
    // scripts, other tools). The fix is to walk the live process table once
    // and filter to PIDs whose ancestor chain leads back to OUR mainPid.
    // The broad sweep stays as the fallback only if ps fails or the targeted
    // kill doesn't take down the main PID.
    let killedTargeted = false;
    try {
      const psOutput = execSync(`ps -eo pid,ppid,cmd`, { encoding: 'utf8', timeout: 5000 });
      const psLines = psOutput.trim().split('\n').slice(1); // drop header

      // pid -> ppid map for ancestry walks; collect chrome-ish candidates.
      const ppidOf = new Map();
      const chromeCandidates = new Set();
      for (const line of psLines) {
        const m = line.trim().match(/^\s*(\d+)\s+(\d+)\s+(.*)$/);
        if (!m) continue;
        const pid = parseInt(m[1], 10);
        const ppid = parseInt(m[2], 10);
        if (Number.isNaN(pid) || Number.isNaN(ppid)) continue;
        ppidOf.set(pid, ppid);
        // Chrome's helpers (gpu, renderer, utility) don't all carry the
        // 'puppeteer' substring; rely on ancestry instead of cmd matching.
        // 'chrom' covers both 'chrome' and 'chromium' in one substring scan.
        if (m[3].includes('chrom')) {
          chromeCandidates.add(pid);
        }
      }

      // Filter candidates to descendants of (or equal to) mainPid.
      const ourPids = [mainPid];
      for (const pid of chromeCandidates) {
        if (pid === mainPid) continue;
        let cur = ppidOf.get(pid);
        let hops = 0;
        while (cur && cur > 1 && hops < 128) {
          if (cur === mainPid) { ourPids.push(pid); break; }
          cur = ppidOf.get(cur);
          hops++;
        }
      }

      if (forceDebug) {
        console.log(`[debug] [browser] Targeted kill: ${ourPids.length} PIDs in mainPid=${mainPid}'s tree: [${ourPids.join(', ')}]`);
      }

      // SIGTERM the tree gracefully.
      for (const pid of ourPids) {
        try { process.kill(pid, 'SIGTERM'); }
        catch (killErr) {
          if (forceDebug && killErr.code !== 'ESRCH') {
            console.log(`[debug] [browser] SIGTERM to PID ${pid} failed: ${killErr.message}`);
          }
        }
      }
      await new Promise(resolve => setTimeout(resolve, 2000));

      // SIGKILL stragglers.
      for (const pid of ourPids) {
        try {
          process.kill(pid, 0); // existence probe
          process.kill(pid, 'SIGKILL');
          if (forceDebug) console.log(`[debug] [browser] Force-killed PID ${pid}`);
        } catch (checkErr) {
          if (forceDebug && checkErr.code !== 'ESRCH') {
            console.log(`[debug] [browser] Probe/kill PID ${pid} error: ${checkErr.message}`);
          }
        }
      }

      // Confirm mainPid is gone — if not, the targeted kill is considered
      // not-effective and we fall through to the broad sweep below.
      try { process.kill(mainPid, 0); }
      catch (e) { if (e.code === 'ESRCH') killedTargeted = true; }
    } catch (psErr) {
      if (forceDebug) console.log(`[debug] [browser] ps -eo pid,ppid,cmd failed: ${psErr.message}`);
    }

    // FALLBACK PATH: targeted kill failed or ps wasn't available. Try the
    // spawned-process handle directly, then last-resort the broad pkill.
    // (killAllPuppeteerChrome in the next module is the truly nuclear option.)
    if (!killedTargeted) {
      if (forceDebug) console.log(`[debug] [browser] Targeted kill did not confirm mainPid death; trying browserProcess handle`);
      try {
        browserProcess.kill('SIGTERM');
        await new Promise(resolve => setTimeout(resolve, 2000));
        try {
          process.kill(mainPid, 0);
          browserProcess.kill('SIGKILL');
          if (forceDebug) console.log(`[debug] [browser] Fallback: Force-killed main PID ${mainPid}`);
        } catch (checkErr) {
          if (forceDebug && checkErr.code !== 'ESRCH') {
            console.log(`[debug] [browser] Fallback probe PID ${mainPid} error: ${checkErr.message}`);
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
  
  // All fields declared upfront so step 3 doesn't extend the object shape at
  // runtime (V8 hidden-class transition); the result shape is also fully
  // documented in one place this way.
  const results = {
    browserClosed: false,
    tempFilesCleanedCount: 0,
    tempFilesCleanedSuccess: false,
    tempFilesCleanedComprehensive: false,
    userDataCleaned: false,
    success: false,
    errors: []
  };
  
  try {
    // Step 1: Browser process cleanup
    try {
      // Race cleanup against a timeout. Attach a no-op .catch to the racing
      // cleanup promise so that when the timeout wins the eventual rejection
      // from the still-running graceful cleanup (page.close / browser.close
      // failing after we move on to forceBrowserKill) doesn't surface as an
      // unhandledRejection warning.
      const cleanupPromise = gracefulBrowserCleanup(browser, forceDebug);
      cleanupPromise.catch(() => {});
      await Promise.race([
        cleanupPromise,
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

      // Attempt targeted force kill of OUR process tree.
      await forceBrowserKill(browser, forceDebug);

      // Only escalate to the broad pkill if our browser is still up. A
      // successful targeted kill breaks the CDP WebSocket, which flips
      // isConnected() to false — in that case the nuclear path would just
      // murder other people's puppeteer-chrome instances for no gain.
      let stillConnected = false;
      try { stillConnected = browser.isConnected(); } catch (_) {}
      if (stillConnected) {
        if (forceDebug) console.log(`[debug] [browser] Targeted force kill didn't take — escalating to nuclear cleanup`);
        await killAllPuppeteerChrome(forceDebug);
      } else if (forceDebug) {
        console.log(`[debug] [browser] Targeted force kill succeeded; skipping nuclear cleanup`);
      }

      results.browserClosed = true; // Assume success after force/nuclear path
    }
    
    // Step 2: User data directory cleanup
    if (userDataDir) {
      const userDataResult = await cleanupUserDataDir(userDataDir, forceDebug);
      results.userDataCleaned = userDataResult.cleaned;
      if (!userDataResult.success) {
        results.errors.push(`User data cleanup failed: ${userDataResult.error}`);
      }
    }
    
    // Step 3: Temp file cleanup. Both branches of the prior code ended up
    // walking all three CHROME_TEMP_PATHS (comprehensive used all 3 directly;
    // standard set includeSnapTemp:true which expands to all 3 too) — the
    // only meaningful difference was the verbose summary log. One call now.
    if (cleanTempFiles) {
      const tempResult = await cleanupChromeTempFiles({
        includeSnapTemp: true,
        comprehensive: comprehensiveCleanup,
        forceDebug,
        verbose
      });
      results.tempFilesCleanedSuccess = tempResult.success;
      results.tempFilesCleanedComprehensive = comprehensiveCleanup;

      if (tempResult.success) {
        results.tempFilesCleanedCount = tempResult.itemsCleaned;
      } else {
        results.errors.push(`${comprehensiveCleanup ? 'Comprehensive' : 'Standard'} temp cleanup failed: ${tempResult.error}`);
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
  cleanupUserDataDir,
  CHROME_TEMP_PATHS,
  CHROME_TEMP_PATTERNS
};
