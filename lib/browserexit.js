/**
 * Browser exit and cleanup handler module
 * Provides graceful and forced browser closure functionality with comprehensive temp file cleanup
 */


const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');
const { formatLogMessage, messageColors } = require('./colorize');

// How old a matching entry must be before the sweep will remove it, when it is
// not one of OUR paths. The sweep used to delete every match outright, which is
// indiscriminate: these patterns match any Chrome on the machine, not just ours.
// Measured -- a decoy standing in for another run and one for a user's browser
// were both deleted, and a plain `google-chrome-stable` (nothing to do with
// puppeteer) creates /tmp/com.google.Chrome.XXXXXX while it runs. Two nwss runs
// started in parallel therefore deleted each other's live profile directories.
const LEFTOVER_MIN_AGE_MS = 15 * 60 * 1000;

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

// Precomputed colored subsystem prefixes — used so debug/temp-cleanup/user-data
// log lines look the same as the rest of the codebase's colorized output.
// Previously these were raw template literals like `[debug] [browser] ...`
// which printed uncolored, while formatLogMessage-routed messages elsewhere
// in the codebase had colored [debug] tags. That produced inconsistent
// 'sometimes colored, sometimes not' output in scan logs.
const BROWSER_TAG = messageColors.fileOp('[browser]');
const TEMP_CLEANUP_TAG = messageColors.cleanup('[temp-cleanup]');
const USER_DATA_TAG = messageColors.fileOp('[user-data]');

/**
 * Is this pid alive? EPERM counts as alive: the process exists, it just is not
 * ours to signal. Only ESRCH means gone -- the same distinction lib/openvpn_vpn.js
 * had to learn when a bare catch read EPERM as "exited".
 * @param {number} pid
 * @returns {boolean}
 */
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

// Profile locations outside /tmp whose singleton files can point INTO /tmp. A
// desktop Chrome keeps its profile here while its singleton socket lives in
// /tmp/com.google.Chrome.XXXXXX, so without checking these we would happily
// delete the /tmp half of a running browser's plumbing.
const WELL_KNOWN_PROFILE_DIRS = Object.freeze([
  path.join(os.homedir(), '.config', 'google-chrome'),
  path.join(os.homedir(), '.config', 'chromium')
]);

/**
 * Absolute paths under the temp roots that a LIVE browser is using, so the sweep
 * can leave them alone.
 *
 * Chrome writes `SingletonLock` as a symlink to `<hostname>-<pid>`, which is an
 * exact liveness test -- verified against a running headless Chrome
 * (SingletonLock -> mp3geek-1782455, pid alive). Its `SingletonSocket` symlink
 * points at the /tmp/com.google.Chrome.XXXXXX directory that instance depends on,
 * so a live profile also pins that directory.
 *
 * Not /proc/net/unix: Chrome's singleton socket does not appear there (checked --
 * an ordinary listener does, so the mechanism works and Chrome simply binds it
 * some other way), which would have made "is anyone listening" look answerable
 * when it is not.
 *
 * @param {string[]} basePaths - Temp roots being swept
 * @returns {Set<string>} Absolute paths to skip
 */
function collectLivePaths(basePaths) {
  const live = new Set();

  const inspectProfile = (profileDir) => {
    let lockTarget;
    try {
      lockTarget = fs.readlinkSync(path.join(profileDir, 'SingletonLock'));
    } catch (_) {
      return;                      // no lock: not a running profile
    }
    const pid = parseInt(lockTarget.slice(lockTarget.lastIndexOf('-') + 1), 10);
    if (!pidAlive(pid)) return;     // stale lock from a crashed browser

    live.add(profileDir);
    // Whatever /tmp directory this instance's socket lives in is in use too.
    try {
      const sock = fs.readlinkSync(path.join(profileDir, 'SingletonSocket'));
      if (path.isAbsolute(sock)) live.add(path.dirname(sock));
    } catch (_) {
      // No socket link; the profile itself is still pinned.
    }
  };

  for (const profileDir of WELL_KNOWN_PROFILE_DIRS) inspectProfile(profileDir);

  for (const basePath of basePaths) {
    let entries;
    try {
      entries = fs.readdirSync(basePath);
    } catch (_) {
      continue;
    }
    for (const entry of entries) {
      if (!CHROME_TEMP_PATTERNS.some(re => re.test(entry))) continue;
      inspectProfile(path.join(basePath, entry));
    }
  }

  return live;
}

/**
 * Count and remove matching Chrome/Puppeteer temp entries from a directory using fs
 * @param {string} basePath - Directory to scan
 * @param {boolean} forceDebug - Whether to output debug logs
 * @param {object} guards
 * @param {Set<string>} guards.livePaths - Paths a live browser is using
 * @param {Set<string>} guards.ownPaths - Paths this run created; always removable
 * @param {number} guards.minAgeMs - Minimum age for anything not in ownPaths
 * @returns {{cleaned: number, skippedLive: number, skippedFresh: number}}
 */
function cleanTempDir(basePath, forceDebug, guards) {
  const { livePaths, ownPaths, minAgeMs } = guards;
  let entries;
  try {
    entries = fs.readdirSync(basePath);
  } catch {
    if (forceDebug) console.log(formatLogMessage('debug', `${TEMP_CLEANUP_TAG} Cannot read ${basePath}`));
    return { cleaned: 0, skippedLive: 0, skippedFresh: 0 };
  }

  let cleaned = 0;
  let skippedLive = 0;
  let skippedFresh = 0;
  const now = Date.now();

  for (const entry of entries) {
    let matched = false;
    for (const re of CHROME_TEMP_PATTERNS) {
      if (re.test(entry)) { matched = true; break; }
    }
    if (!matched) continue;

    const full = path.join(basePath, entry);
    const ours = ownPaths.has(full);

    if (!ours) {
      if (livePaths.has(full)) {
        skippedLive++;
        if (forceDebug) console.log(formatLogMessage('debug', `${TEMP_CLEANUP_TAG} Kept ${full}: a live browser is using it`));
        continue;
      }
      // mtime, NOT max(mtime, ctime). ctime moves on any inode change -- including
      // a plain `touch` -- so taking the newer of the two reported a three-hour-old
      // leftover as "0s old" and kept it, which is how this was caught. Liveness is
      // what protects a running browser here; age is only the backstop for an entry
      // with no lock to read.
      let age = Infinity;
      try {
        age = now - fs.lstatSync(full).mtimeMs;
      } catch (_) {
        // Vanished between readdir and stat; nothing to remove.
        continue;
      }
      if (age < minAgeMs) {
        skippedFresh++;
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${TEMP_CLEANUP_TAG} Kept ${full}: only ${Math.round(age / 1000)}s old, could belong to another run`));
        }
        continue;
      }
    }

    try {
      fs.rmSync(full, { recursive: true, force: true });
      cleaned++;
      if (forceDebug) console.log(formatLogMessage('debug', `${TEMP_CLEANUP_TAG} Removed ${full}${ours ? ' (ours)' : ''}`));
    } catch (rmErr) {
      if (forceDebug) console.log(formatLogMessage('debug', `${TEMP_CLEANUP_TAG} Failed to remove ${full}: ${rmErr.message}`));
    }
  }

  return { cleaned, skippedLive, skippedFresh };
}

/**
 * Clean Chrome temporary files and directories
 * @param {Object} options - Cleanup options
 * @param {boolean} options.includeSnapTemp - Whether to clean snap temp directories
 * @param {boolean} options.forceDebug - Whether to output debug logs
 * @param {boolean} options.verbose - Whether to print a user-facing summary
 *   (in addition to forceDebug's developer logs)
 * @param {string[]} [options.ownPaths] - Paths this run created. These are removed
 *   regardless of age, because we know nobody else is using them.
 * @param {number} [options.minAgeMs] - How old anything NOT in ownPaths must be
 *   before it is treated as a leftover. Defaults to LEFTOVER_MIN_AGE_MS.
 * @returns {Object} Cleanup results
 */
function cleanupChromeTempFiles(options = {}) {
  const {
    includeSnapTemp = false,
    forceDebug = false,
    verbose = false,
    ownPaths = [],
    minAgeMs = LEFTOVER_MIN_AGE_MS
  } = options;

  try {
    if (verbose && !forceDebug) {
      console.log(`${TEMP_CLEANUP_TAG} Scanning Chrome/Puppeteer temporary files...`);
    }

    // `comprehensive` used to sit alongside includeSnapTemp and meant exactly the
    // same thing, so with every caller passing includeSnapTemp:true it selected
    // nothing and its result field was written but never read. Removed.
    const paths = includeSnapTemp
      ? CHROME_TEMP_PATHS
      : CHROME_TEMP_PATHS.slice(0, 2); // /tmp and /dev/shm only

    // Resolved once for the whole sweep: the answer cannot change mid-pass, and
    // re-deriving it per directory would re-read every profile's lock.
    const livePaths = collectLivePaths(paths);
    const ownSet = new Set((Array.isArray(ownPaths) ? ownPaths : [ownPaths])
      .filter(Boolean)
      .map(p => path.resolve(p)));

    let totalCleaned = 0;
    let totalLive = 0;
    let totalFresh = 0;
    for (const basePath of paths) {
      const r = cleanTempDir(basePath, forceDebug, { livePaths, ownPaths: ownSet, minAgeMs });
      totalCleaned += r.cleaned;
      totalLive += r.skippedLive;
      totalFresh += r.skippedFresh;
    }

    // Say what was LEFT as well as what went: "0 removed" on a machine with a
    // running browser should not read like a failure.
    const kept = totalLive + totalFresh
      ? ` (kept ${totalLive} in use, ${totalFresh} too recent to attribute)`
      : '';
    if (verbose) {
      console.log(totalCleaned > 0
        ? `${TEMP_CLEANUP_TAG} Removed ${totalCleaned} temporary file(s)/folder(s)${kept}`
        : `${TEMP_CLEANUP_TAG} Clean - no leftover temporary files${kept}`);
    } else if (forceDebug) {
      console.log(formatLogMessage('debug', `${TEMP_CLEANUP_TAG} Cleanup completed (${totalCleaned} items)${kept}`));
    }

    return { success: true, itemsCleaned: totalCleaned, keptInUse: totalLive, keptRecent: totalFresh };
  } catch (cleanupErr) {
    const errorMsg = `Chrome temp cleanup failed: ${cleanupErr.message}`;
    if (verbose) {
      console.warn(`${TEMP_CLEANUP_TAG} ${errorMsg}`);
    } else if (forceDebug) {
      console.log(formatLogMessage('debug', `${TEMP_CLEANUP_TAG} ${errorMsg}`));
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
      console.log(formatLogMessage('debug', `${USER_DATA_TAG} Cleaned user data directory: ${userDataDir}`));
    }

    return { success: true, cleaned: true };

  } catch (rmErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${USER_DATA_TAG} Failed to remove user data directory ${userDataDir}: ${rmErr.message}`));
    }
    return { success: false, error: rmErr.message, cleaned: false };
  }
}

/**
 * Attempts to gracefully close all browser pages and the browser instance.
 *
 * Reports whether the browser is actually gone, because the caller records that in
 * its result and nwss prints it. It used to return nothing and the caller assumed
 * success: verified with a stub whose pages() throws, the result said
 * `browserClosed=true success=true` while the browser was still connected.
 *
 * @param {import('puppeteer').Browser} browser - The Puppeteer browser instance
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<{closed: boolean}>} closed is true only when the browser is
 *   no longer connected by the time this returns.
 */
async function gracefulBrowserCleanup(browser, forceDebug = false) {
  // FIX: Check browser connection before operations
  if (!browser || !browser.connected) {
    if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Browser not connected, skipping cleanup`));
    return { closed: true };          // nothing to close: already gone
  }
  if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Getting all browser pages...`));
  let pages = [];
  try {
    pages = await browser.pages();
  } catch (pagesErr) {
    // Not a reason to skip closing the browser -- that was the old behaviour, and
    // it left a connected browser behind while reporting success. Close it anyway.
    if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Failed to get pages (${pagesErr.message}); closing the browser anyway`));
  }
  if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Found ${pages.length} pages to close`));

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

        if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Closing page: ${pageUrl}`));
        await page.close();
        if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Page closed successfully`));
      } catch (err) {
        // Nothing to do but note it: the browser close below is what actually
        // disposes of a page that will not close on its own. (This used to claim
        // it was force-closing the page, which it never did.)
        if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Page would not close: ${err.message}`));
      }
    }
  }));

  if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} All pages closed, closing browser...`));

  // FIX: Check browser is still connected before closing
  try {
    if (browser.connected) {
      await browser.close();
      if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Browser closed successfully`));
    } else {
      if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Browser already disconnected`));
    }
  } catch (closeErr) {
    if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Browser close failed: ${closeErr.message}`));
  }

  // The verdict is what the browser says, not what we attempted.
  let stillConnected = false;
  try { stillConnected = !!browser.connected; } catch (_) { stillConnected = false; }
  return { closed: !stillConnected };
}

/**
 * Force kills the browser process using system signals
 * @param {import('puppeteer').Browser} browser - The Puppeteer browser instance
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<void>}
 */
async function forceBrowserKill(browser, forceDebug = false) {
  try {
    if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Attempting force closure of browser process...`));

    const browserProcess = browser.process();
    if (!browserProcess || !browserProcess.pid) {
      if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} No browser process available`));
      return;
    }

    const mainPid = browserProcess.pid;
    if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Main Chrome PID: ${mainPid}`));

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
        console.log(formatLogMessage('debug', `${BROWSER_TAG} Targeted kill: ${ourPids.length} PIDs in mainPid=${mainPid}'s tree: [${ourPids.join(', ')}]`));
      }

      // SIGTERM the tree gracefully.
      for (const pid of ourPids) {
        try { process.kill(pid, 'SIGTERM'); }
        catch (killErr) {
          if (forceDebug && killErr.code !== 'ESRCH') {
            console.log(formatLogMessage('debug', `${BROWSER_TAG} SIGTERM to PID ${pid} failed: ${killErr.message}`));
          }
        }
      }
      await new Promise(resolve => setTimeout(resolve, 2000));

      // SIGKILL stragglers.
      for (const pid of ourPids) {
        try {
          process.kill(pid, 0); // existence probe
          process.kill(pid, 'SIGKILL');
          if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Force-killed PID ${pid}`));
        } catch (checkErr) {
          if (forceDebug && checkErr.code !== 'ESRCH') {
            console.log(formatLogMessage('debug', `${BROWSER_TAG} Probe/kill PID ${pid} error: ${checkErr.message}`));
          }
        }
      }

      // Confirm mainPid is gone — if not, the targeted kill is considered
      // not-effective and we fall through to the broad sweep below.
      try { process.kill(mainPid, 0); }
      catch (e) { if (e.code === 'ESRCH') killedTargeted = true; }
    } catch (psErr) {
      if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} ps -eo pid,ppid,cmd failed: ${psErr.message}`));
    }

    // FALLBACK PATH: targeted kill failed or ps wasn't available. Try the
    // spawned-process handle directly, then last-resort the broad pkill.
    // (killAllPuppeteerChrome in the next module is the truly nuclear option.)
    if (!killedTargeted) {
      if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Targeted kill did not confirm mainPid death; trying browserProcess handle`));
      try {
        browserProcess.kill('SIGTERM');
        await new Promise(resolve => setTimeout(resolve, 2000));
        try {
          process.kill(mainPid, 0);
          browserProcess.kill('SIGKILL');
          if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Fallback: Force-killed main PID ${mainPid}`));
        } catch (checkErr) {
          if (forceDebug && checkErr.code !== 'ESRCH') {
            console.log(formatLogMessage('debug', `${BROWSER_TAG} Fallback probe PID ${mainPid} error: ${checkErr.message}`));
          }
        }
      } catch (fallbackErr) {
        if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Fallback kill failed: ${fallbackErr.message}`));
      }
    }

  } catch (forceKillErr) {
    console.error(formatLogMessage('error', `${BROWSER_TAG} Failed to force kill browser: ${forceKillErr.message}`));
  }

  try {
    if (browser.connected) {
      browser.disconnect();
      if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Browser connection disconnected`));
    }
  } catch (disconnectErr) {
    if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Failed to disconnect browser: ${disconnectErr.message}`));
  }
}

/**
 * Kill all Chrome processes by command line pattern (nuclear option)
 * @param {boolean} forceDebug - Whether to output debug logs
 * @returns {Promise<void>}
 */
async function killAllPuppeteerChrome(forceDebug = false) {
  try {
    if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Nuclear option: killing all puppeteer Chrome processes...`));

    try {
      execSync(`pkill -f "puppeteer.*chrome"`, { stdio: 'ignore', timeout: 5000 });
      if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} pkill completed`));
    } catch (pkillErr) {
      if (forceDebug && pkillErr.status !== 1) {
        console.log(formatLogMessage('debug', `${BROWSER_TAG} pkill failed with status ${pkillErr.status}: ${pkillErr.message}`));
      }
    }

    await new Promise(resolve => setTimeout(resolve, 2000));

  } catch (nuclearErr) {
    console.error(formatLogMessage('error', `${BROWSER_TAG} Nuclear Chrome kill failed: ${nuclearErr.message}`));
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
    userDataDir = null,
    verbose = false
  } = options;
  
  if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Starting comprehensive browser cleanup...`));

  // Ask the browser where its profile actually is, before anything closes it.
  // The caller's userDataDir covers the directory NWSS created, but Chrome may be
  // running on one puppeteer made instead, and that one is just as much ours --
  // measured, a scan left a /tmp/puppeteer-* profile behind because only the
  // caller-supplied path was declared. spawnargs stays readable after exit, since
  // it is a plain array on the ChildProcess.
  let launchedProfileDir = null;
  try {
    const spawnArgs = (browser && browser.process() && browser.process().spawnargs) || [];
    const arg = spawnArgs.find(a => typeof a === 'string' && a.startsWith('--user-data-dir='));
    if (arg) launchedProfileDir = arg.slice('--user-data-dir='.length);
  } catch (_) {
    // No process handle (a connected-over-websocket browser); the caller's path
    // is still declared below.
  }
  
  // All fields declared upfront so step 3 doesn't extend the object shape at
  // runtime (V8 hidden-class transition); the result shape is also fully
  // documented in one place this way.
  const results = {
    browserClosed: false,
    tempFilesCleanedCount: 0,
    tempFilesCleanedSuccess: false,
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
      const graceful = await Promise.race([
        cleanupPromise,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Browser cleanup timeout')), timeout)
        )
      ]);

      // What the browser reports, not what we attempted. A graceful pass that
      // could not close it is a failure with a specific cause, and saying so is
      // the difference between "Browser closed: true" being information and being
      // noise.
      results.browserClosed = !!(graceful && graceful.closed);
      if (!results.browserClosed) {
        results.errors.push('Browser cleanup completed but the browser is still connected');
        if (forceDebug || verbose) {
          console.warn(formatLogMessage('warn', `${BROWSER_TAG} Graceful cleanup finished but the browser is still connected`));
        }
      }

    } catch (browserCloseErr) {
      results.errors.push(`Browser cleanup failed: ${browserCloseErr.message}`);

      if (forceDebug || verbose) {
        console.warn(formatLogMessage('warn', `${BROWSER_TAG} Browser cleanup had issues: ${browserCloseErr.message}`));
      }

      // Attempt targeted force kill of OUR process tree.
      await forceBrowserKill(browser, forceDebug);

      // Only escalate to the broad pkill if our browser is still up. A
      // successful targeted kill breaks the CDP WebSocket, which flips
      // isConnected() to false — in that case the nuclear path would just
      // murder other people's puppeteer-chrome instances for no gain.
      let stillConnected = false;
      try { stillConnected = browser.connected; } catch (_) {}
      if (stillConnected) {
        if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Targeted force kill didn't take — escalating to nuclear cleanup`));
        await killAllPuppeteerChrome(forceDebug);
      } else if (forceDebug) {
        console.log(formatLogMessage('debug', `${BROWSER_TAG} Targeted force kill succeeded; skipping nuclear cleanup`));
      }

      // Verify rather than assume. This line used to read
      // `results.browserClosed = true; // Assume success after force/nuclear path`,
      // which reported a closed browser even when the force path had failed.
      let connectedAfterForce = false;
      try { connectedAfterForce = !!browser.connected; } catch (_) { connectedAfterForce = false; }
      results.browserClosed = !connectedAfterForce;
      if (!results.browserClosed) {
        results.errors.push('Browser still connected after force and nuclear cleanup');
      }
    }
    
    // Step 2: User data directory cleanup
    if (userDataDir) {
      const userDataResult = await cleanupUserDataDir(userDataDir, forceDebug);
      results.userDataCleaned = userDataResult.cleaned;
      if (!userDataResult.success) {
        results.errors.push(`User data cleanup failed: ${userDataResult.error}`);
      }
    }
    
    // Step 3: Temp file cleanup, always across all three CHROME_TEMP_PATHS.
    if (cleanTempFiles) {
      const tempResult = await cleanupChromeTempFiles({
        includeSnapTemp: true,
        forceDebug,
        verbose,
        // Ours by construction, and the browser using them has just been closed, so
        // they do not have to wait out the leftover age guard.
        ownPaths: [userDataDir, launchedProfileDir].filter(Boolean)
      });
      results.tempFilesCleanedSuccess = tempResult.success;

      if (tempResult.success) {
        results.tempFilesCleanedCount = tempResult.itemsCleaned;
      } else {
        results.errors.push(`Temp cleanup failed: ${tempResult.error}`);
      }
    }
    
    // Determine overall success
    results.success = results.browserClosed && 
                     (results.errors.length === 0 || !exitOnFailure);
    
    if (forceDebug) {
      console.log(formatLogMessage('debug',
        `${BROWSER_TAG} Cleanup completed - Browser: ${results.browserClosed}, ` +
        `Temp files: ${results.tempFilesCleanedCount || 0}, ` +
        `User data: ${results.userDataCleaned}, ` +
        `Errors: ${results.errors.length}`));
    }

    return results;

  } catch (overallErr) {
    results.errors.push(`Overall cleanup failed: ${overallErr.message}`);
    results.success = false;

    if (exitOnFailure) {
      if (forceDebug) console.log(formatLogMessage('debug', `${BROWSER_TAG} Forcing process exit due to cleanup failure`));
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
