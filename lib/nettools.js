/**
 * Network tools module for whois and dig lookups - COMPLETE FIXED VERSION
 * Provides domain analysis capabilities with proper timeout handling, custom whois servers, and retry logic
 */

// execFile (no shell) for whois/dig invocations -- arguments are passed
// directly to the executable as an argv array, so shell metacharacters in
// config-supplied hostnames or server names CANNOT execute commands. The
// prior `exec(string)` approach interpolated tainted values into a shell
// string protected only by double-quoting, which doesn't stop $()/backticks.
// execSync is retained ONLY for the version-probe helpers below, where
// commands are constant string literals with no user-controlled inputs.
const { execFile, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { formatLogMessage, messageColors } = require('./colorize');
const ANSI_REGEX = /\x1b\[[0-9;]*m/g;

// Cycling index for whois server rotation
let whoisServerCycleIndex = 0;

// Global dig result cache — shared across ALL handler instances and processUrl calls
// Key: `${domain}-${recordType}`, Value: { result, timestamp }
// DNS records don't change based on what terms you're searching for,
// so we cache the raw dig output and let each handler check its own terms against it
const globalDigResultCache = new Map();
const GLOBAL_DIG_CACHE_TTL = 72000000; // 20 hours (persisted to disk between runs)
const GLOBAL_DIG_CACHE_MAX = 2000;

// Global whois result cache — shared across ALL handler instances and processUrl calls
// Whois data is per root domain and doesn't change based on search terms
const globalWhoisResultCache = new Map();
const GLOBAL_WHOIS_CACHE_TTL = 72000000; // 20 hours (persisted to disk between runs)
const GLOBAL_WHOIS_CACHE_MAX = 2000;

// Persistent disk cache file paths
const DIG_CACHE_FILE = path.join(__dirname, '..', '.digcache');
const WHOIS_CACHE_FILE = path.join(__dirname, '..', '.whoiscache');

// Index of hostnames known to resolve, populated as a side effect of
// positive dig/whois cache writes AND cache hits. nwss.js's DNS pre-check
// reads this via domainKnownToResolve() so it can skip its own resolve4
// call on hosts that dig or whois have already proven live within the
// 20-hour TTL window. Populating on cache HITS (not just writes) handles
// the --dns-cache disk-load case where entries arrive without going
// through the in-process write path. Stale entries -- hostname in Set but
// the dig/whois entry has since been evicted -- are harmless: worst case
// is one wasted pre-check next time the hostname comes through.
const knownResolvedHostnames = new Set();
const MAX_RESOLVED_HOSTNAMES = 5000;

function markResolved(hostname) {
  if (!hostname) return;
  if (knownResolvedHostnames.size >= MAX_RESOLVED_HOSTNAMES) {
    // FIFO eviction -- Set iteration order is insertion order.
    knownResolvedHostnames.delete(knownResolvedHostnames.values().next().value);
  }
  knownResolvedHostnames.add(hostname);
}

/**
 * Returns true if dig or whois has produced a verifiable-positive result
 * for this hostname during the current process lifetime. nwss.js's DNS
 * pre-check uses this to skip resolve4 calls on hosts we already know
 * are live. False does NOT mean "unresolvable" -- it means "we have no
 * recent evidence either way; do the pre-check".
 */
function domainKnownToResolve(hostname) {
  return knownResolvedHostnames.has(hostname);
}

// Dig responses with success:true can still represent NXDOMAIN -- the dig
// COMMAND succeeded but the DNS RESPONSE is "no such name". The output
// string is the only reliable signal. NOERROR + non-zero answer count =
// the hostname genuinely resolved.
function digOutputIndicatesResolution(output) {
  if (!output) return false;
  if (!output.includes('status: NOERROR')) return false;
  // ANSWER: 0 means NOERROR but no records of the requested type -- the
  // hostname exists at this label but doesn't have THIS record type.
  // For our purposes (proving the name is live) that's still useful, but
  // strictly "domain has nameservers and returned authoritative empty"
  // is weaker than "domain returned an actual A/AAAA". Conservative
  // choice: require non-zero answer count.
  if (/ANSWER:\s*0\b/.test(output)) return false;
  return true;
}

/**
 * Load persistent cache from disk into in-memory Map
 * Skips expired entries and enforces max size
 * @param {string} filePath - Path to cache file
 * @param {Map} cache - In-memory cache Map to populate
 * @param {number} ttl - TTL in milliseconds
 * @param {number} maxSize - Maximum cache entries
 */
function loadDiskCache(filePath, cache, ttl, maxSize) {
  // Also clean up any stray .tmp files from a prior interrupted save.
  // The atomic-write path (saveDiskCache below) writes to `${filePath}.tmp`
  // then renames; a process killed mid-write leaves the .tmp behind. The
  // real file remains intact (rename is atomic), so we just sweep the
  // stray on load.
  try {
    const tmpPath = filePath + '.tmp';
    if (fs.existsSync(tmpPath)) {
      try { fs.unlinkSync(tmpPath); } catch {}
    }
  } catch {}

  try {
    if (!fs.existsSync(filePath)) return;
    const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    const now = Date.now();
    let loaded = 0;
    for (const [key, entry] of Object.entries(data)) {
      if (loaded >= maxSize) break;
      if (now - entry.timestamp < ttl) {
        cache.set(key, entry);
        loaded++;
      }
    }
  } catch (err) {
    // Corrupt or unreadable cache file — delete and start fresh.
    // Surface the event so the user knows they lost their warm cache;
    // previously this was a silent reset, which made "why did my dns
    // cache stop helping?" hard to diagnose.
    // eslint-disable-next-line no-console
    console.warn(`${messageColors.highlight('[dns-cache]')} ${path.basename(filePath)} was unreadable (${err.message}); starting fresh`);
    try { fs.unlinkSync(filePath); } catch {}
  }
}

/**
 * Save in-memory cache to disk, evicting oldest entries if over max size
 * @param {string} filePath - Path to cache file
 * @param {Map} cache - In-memory cache Map to persist
 * @param {number} ttl - TTL in milliseconds
 * @param {number} maxSize - Maximum cache entries
 */
function saveDiskCache(filePath, cache, ttl, maxSize) {
  try {
    const now = Date.now();
    const entries = {};
    let count = 0;

    // Collect valid entries, skip expired
    for (const [key, entry] of cache) {
      if (now - entry.timestamp < ttl) {
        entries[key] = entry;
        count++;
      }
    }

    // Build the final payload (with trimming if over cap). Compact JSON
    // -- saveDiskCache runs on the synchronous 'exit' handler when
    // --dns-cache is set, so any work here directly delays scan exit.
    // Several times faster than pretty-print on multi-megabyte caches
    // and the file is not intended for human reading.
    let payload;
    if (count > maxSize) {
      const sorted = Object.entries(entries)
        .sort((a, b) => b[1].timestamp - a[1].timestamp)
        .slice(0, maxSize);
      const trimmed = {};
      for (const [key, entry] of sorted) {
        trimmed[key] = entry;
      }
      payload = JSON.stringify(trimmed);
    } else {
      payload = JSON.stringify(entries);
    }

    // Atomic write: writeFileSync to a sibling .tmp path, then rename.
    // If the process is killed mid-write (SIGKILL, OOM, power loss) the
    // .tmp is left as garbage but the real filePath is either complete
    // or absent -- never half-written. loadDiskCache sweeps stray .tmp
    // files on next startup.
    // Matches the pattern already used in lib/adblock-rust.js per the
    // CLAUDE.md convention. We deliberately omit the pid suffix used
    // there because saveDiskCache only ever runs from the single 'exit'
    // handler -- no concurrent-process race to disambiguate.
    const tmpPath = filePath + '.tmp';
    fs.writeFileSync(tmpPath, payload);
    fs.renameSync(tmpPath, filePath);
  } catch {
    // Disk write failed -- non-fatal, in-memory cache still works.
    // Best-effort cleanup of any stray tmp file from this attempt so
    // it doesn't accumulate over repeated failures.
    try { fs.unlinkSync(filePath + '.tmp'); } catch {}
  }
}

// Track in-flight lookups to prevent duplicate concurrent requests
const pendingDigLookups = new Map();
const pendingWhoisLookups = new Map();

/**
 * Enforce a hard size cap on the dig/whois global caches. Evicts expired
 * entries first; if the cache is still over cap after that (i.e. every
 * remaining entry is within its TTL but there are simply too many),
 * deletes the oldest entries by timestamp until size <= max. Without the
 * second pass the caches could grow unbounded on scans of many unique
 * hostnames whose entries hadn't expired yet.
 *
 * @param {Map} cache - cache Map to prune
 * @param {number} maxSize - desired hard cap
 * @param {number} ttl - TTL in ms; entries older than this are evicted first
 * @returns {{expired: number, overflow: number}} eviction counts
 */
function enforceCacheCap(cache, maxSize, ttl) {
  if (cache.size <= maxSize) return { expired: 0, overflow: 0 };
  const now = Date.now();
  let expired = 0;
  for (const [key, entry] of cache.entries()) {
    if (now - entry.timestamp > ttl) {
      cache.delete(key);
      expired++;
    }
  }
  let overflow = 0;
  if (cache.size > maxSize) {
    // Snapshot timestamps and sort ascending, evict the oldest few.
    const byAge = Array.from(cache.entries())
      .sort((a, b) => a[1].timestamp - b[1].timestamp);
    const toDrop = cache.size - maxSize;
    for (let i = 0; i < toDrop; i++) {
      cache.delete(byAge[i][0]);
      overflow++;
    }
  }
  return { expired, overflow };
}

// DNS cache statistics. freshDig / freshWhois are sample lists for
// end-of-scan visibility; capped at MAX_FRESH_LIST entries (FIFO) so
// they can't grow unbounded on scans with thousands of unique fresh
// lookups. digMisses/whoisMisses retain the full count, so callers
// who want totals can read those; freshDig/freshWhois are intended as
// "show me which domains" diagnostic samples.
const MAX_FRESH_LIST = 1000;
const dnsCacheStats = { digHits: 0, digMisses: 0, whoisHits: 0, whoisMisses: 0, freshDig: [], freshWhois: [] };

function pushFreshSample(arr, item) {
  if (arr.length >= MAX_FRESH_LIST) arr.shift();
  arr.push(item);
}

/**
 * Get DNS cache statistics for end-of-scan reporting
 * @returns {Object} Cache hit/miss counts and fresh domain lists
 */
function getDnsCacheStats() {
  return { ...dnsCacheStats };
}

// Disk cache is opt-in via --dns-cache flag
let diskCacheEnabled = false;

/**
 * Enable persistent disk caching for dig/whois results.
 * Call this when --dns-cache flag is set. Idempotent — repeated calls
 * are no-ops, which prevents double-loading the cache files and double-
 * registering the 'exit' handler that flushes them on shutdown.
 */
function enableDiskCache() {
  if (diskCacheEnabled) return;
  diskCacheEnabled = true;
  loadDiskCache(DIG_CACHE_FILE, globalDigResultCache, GLOBAL_DIG_CACHE_TTL, GLOBAL_DIG_CACHE_MAX);
  loadDiskCache(WHOIS_CACHE_FILE, globalWhoisResultCache, GLOBAL_WHOIS_CACHE_TTL, GLOBAL_WHOIS_CACHE_MAX);

  // Warm knownResolvedHostnames from disk-loaded entries so the very
  // first URL per cached domain also skips the c-ares pre-check (instead
  // of waiting for the cache-hit handler to fire later in the URL's
  // pipeline). Entries written by older versions of this module lack the
  // `hostname` field -- they're skipped here and fall back to lazy
  // on-hit population. Same positive-resolution gates apply as the live
  // write/hit paths (dig: NOERROR + non-zero answers; whois: success).
  let digWarm = 0;
  let whoisWarm = 0;
  for (const entry of globalDigResultCache.values()) {
    if (entry.hostname && entry.result && entry.result.success &&
        digOutputIndicatesResolution(entry.result.output)) {
      markResolved(entry.hostname);
      digWarm++;
    }
  }
  for (const entry of globalWhoisResultCache.values()) {
    if (entry.hostname && entry.result && entry.result.success) {
      markResolved(entry.hostname);
      whoisWarm++;
    }
  }
  // Debug log only if anything was actually warmed; silent on fresh
  // installs / empty disk caches.
  if (digWarm > 0 || whoisWarm > 0) {
    // eslint-disable-next-line no-console
    console.log(`${messageColors.highlight('[dns-cache]')} Warmed resolved-hostnames index from disk: ${digWarm} dig + ${whoisWarm} whois entries`);
  }

  // Save caches to disk once on process exit instead of per-lookup. The
  // 'exit' handler fires synchronously regardless of how the process exits
  // (normal completion, signal, uncaught exception), so a separate signal
  // handler is redundant. We deliberately do NOT install SIGINT/SIGTERM
  // handlers here — nwss.js installs its own async ones that perform
  // browser/VPN cleanup, and a sync handler here would call process.exit(0)
  // first and skip that cleanup entirely.
  const flushCaches = () => {
    saveDiskCache(DIG_CACHE_FILE, globalDigResultCache, GLOBAL_DIG_CACHE_TTL, GLOBAL_DIG_CACHE_MAX);
    saveDiskCache(WHOIS_CACHE_FILE, globalWhoisResultCache, GLOBAL_WHOIS_CACHE_TTL, GLOBAL_WHOIS_CACHE_MAX);
  };
  process.on('exit', flushCaches);
}

/**
 * Strips ANSI color codes from a string for clean file logging
 * @param {string} text - Text that may contain ANSI codes
 * @returns {string} Text with ANSI codes removed
 */
function stripAnsiColors(text) {
  // Remove ANSI escape sequences (color codes)
  ANSI_REGEX.lastIndex = 0;
  return text.replace(ANSI_REGEX, '');
}

/**
 * Validates if whois command is available on the system
 * @returns {Object} Object with isAvailable boolean and version/error info
 */
function validateWhoisAvailability() {
  if (validateWhoisAvailability._cached) return validateWhoisAvailability._cached;
  try {
    const result = execSync('whois --version 2>&1', { encoding: 'utf8' });
    validateWhoisAvailability._cached = {
      isAvailable: true,
      version: result.trim()
    };
  } catch (error) {
    try {
      execSync('which whois', { encoding: 'utf8' });
      validateWhoisAvailability._cached = {
        isAvailable: true,
        version: 'whois (version unknown)'
      };
    } catch (e) {
      validateWhoisAvailability._cached = {
        isAvailable: false,
        error: 'whois command not found'
      };
    }
  }
  return validateWhoisAvailability._cached;
}

/**
 * Validates if dig command is available on the system
 * @returns {Object} Object with isAvailable boolean and version/error info
 */
function validateDigAvailability() {
  if (validateDigAvailability._cached) return validateDigAvailability._cached;
  try {
    const result = execSync('dig -v 2>&1', { encoding: 'utf8' });
    validateDigAvailability._cached = {
      isAvailable: true,
      version: result.split('\n')[0].trim()
    };
  } catch (error) {
    validateDigAvailability._cached = {
      isAvailable: false,
      error: 'dig command not found'
    };
  }
  return validateDigAvailability._cached;
}

/**
 * Spawn a process with execFile (no shell) and a hard timeout. Arguments
 * are passed directly as argv -- shell metacharacters in any element
 * cannot execute commands. Replaces the prior exec(string)-based helper
 * whose double-quote-only protection failed against $()/backticks.
 *
 * @param {string} cmd - Executable name or path
 * @param {string[]} args - Argument vector (each element a separate arg)
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<{stdout:string, stderr:string}>} -- rejects on timeout/error
 */
function execFileWithTimeout(cmd, args, timeout = 10000) {
  return new Promise((resolve, reject) => {
    // Hoisted before the callbacks that reference it. Previously `const
    // timer = setTimeout(...)` was declared after the exec callback /
    // 'error' listener that both did `if (timer) clearTimeout(timer)` —
    // worked in practice because exec defers callbacks via nextTick, but
    // structurally fragile (a synchronous exec failure would TDZ-throw).
    let timer = null;

    const child = execFile(cmd, args, { encoding: 'utf8' }, (error, stdout, stderr) => {
      if (timer) clearTimeout(timer);

      if (error) {
        reject(error);
      } else {
        resolve({ stdout, stderr });
      }
    });

    timer = setTimeout(() => {
      child.kill('SIGTERM');

      // Force kill after 2 seconds if SIGTERM doesn't work. unref() so this
      // tail timer doesn't keep the event loop alive past scan completion —
      // a dig that times out near the end of a scan would otherwise delay
      // exit by ~2 seconds.
      const killTimer = setTimeout(() => {
        if (!child.killed) {
          child.kill('SIGKILL');
        }
      }, 2000);
      killTimer.unref();

      reject(new Error(`Command timeout after ${timeout}ms: ${cmd} ${args.join(' ')}`));
    }, timeout);
    // unref the outer timeout too — a hung dig/whois firing AFTER the
    // per-URL drain (3s cap) already returned would otherwise hold the
    // event loop alive for up to `timeout` (5-10s) on scan exit. The exec
    // callback / 'error' handler still clear it via the existing
    // clearTimeout, so this only matters for the genuinely-hung case.
    if (typeof timer.unref === 'function') timer.unref();

    // Handle child process errors
    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * Selects a whois server from the configuration
 * @param {string|Array<string>} whoisServer - Single server string or array of servers
 * @param {string} mode - Selection mode: 'random' (default) or 'cycle'
 * @returns {string|null} Selected whois server or null if none specified
 */
function selectWhoisServer(whoisServer = '', mode = 'random'){
  if (!whoisServer) {
    return null; // Use default whois behavior
  }
  
  if (typeof whoisServer === 'string') {
    return whoisServer;
  }
  
  if (Array.isArray(whoisServer) && whoisServer.length > 0) {
    if (mode === 'cycle') {
      const selectedServer = whoisServer[whoisServerCycleIndex % whoisServer.length];
      whoisServerCycleIndex = (whoisServerCycleIndex + 1) % whoisServer.length;
      
      return selectedServer;
    } else {
      // Random selection (default behavior)
      const randomIndex = Math.floor(Math.random() * whoisServer.length);
      return whoisServer[randomIndex];
    }
  }
  
  return null;
}

/**
 * Gets common whois servers for debugging/fallback suggestions
 * @returns {Array<string>} List of common whois servers
 */
function getCommonWhoisServers() {
  return [
    'whois.iana.org',
    'whois.internic.net', 
    'whois.verisign-grs.com',
    'whois.markmonitor.com',
    'whois.godaddy.com',
    'whois.namecheap.com',
    'whois.1and1.com'
  ];
}

/**
 * Suggests alternative whois servers based on domain TLD
 * @param {string} domain - Domain to get suggestions for
 * @param {string} failedServer - Server that failed (to exclude from suggestions)
 * @returns {Array<string>} Suggested whois servers
 */
function suggestWhoisServers(domain, failedServer = null) {
  const tld = domain.split('.').pop().toLowerCase();
  const suggestions = [];
  
  // TLD-specific servers
  const tldServers = {
    'com': ['whois.verisign-grs.com', 'whois.internic.net'],
    'net': ['whois.verisign-grs.com', 'whois.internic.net'],
    'org': ['whois.pir.org'],
    'info': ['whois.afilias.net'],
    'biz': ['whois.neulevel.biz'],
    'uk': ['whois.nominet.uk'],
    'de': ['whois.denic.de'],
    'fr': ['whois.afnic.fr'],
    'it': ['whois.nic.it'],
    'nl': ['whois.domain-registry.nl']
  };
  
  if (tldServers[tld]) {
    suggestions.push(...tldServers[tld]);
  }
  
  // Add common servers
  suggestions.push(...getCommonWhoisServers());
  
  // Remove duplicates and failed server
  const uniqueSuggestions = [...new Set(suggestions)];
  return failedServer ? uniqueSuggestions.filter(s => s !== failedServer) : uniqueSuggestions;
}

/**
 * Performs a whois lookup on a domain with proper timeout handling and custom server support (basic version)
 * @param {string} domain - Domain to lookup
 * @param {number} timeout - Timeout in milliseconds (default: 10000)
 * @param {string|Array<string>} whoisServer - Custom whois server(s) to use
 * @param {boolean} debugMode - Enable debug logging (default: false)
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function whoisLookup(domain = '', timeout = 10000, whoisServer = '', debugMode = false, logFunc = null) {
  const startTime = Date.now();
  let cleanDomain, selectedServer, whoisCommand;
  
  try {
    // Clean domain (remove protocol, path, etc)
    cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');

    // Select whois server if provided
    selectedServer = selectWhoisServer(whoisServer);

    // Build whois argv. Pass each token as a separate argv element --
    // execFile does NOT spawn a shell, so neither cleanDomain nor
    // selectedServer can inject commands no matter what they contain.
    // The leading `--` is preserved so dashes in `cleanDomain` don't get
    // re-interpreted as flags by the whois binary itself.
    let whoisArgs;
    if (selectedServer) {
      whoisArgs = ['-h', selectedServer, '--', cleanDomain];
    } else {
      whoisArgs = ['--', cleanDomain];
    }
    // Kept as a display string for debug logging only -- never executed.
    whoisCommand = `whois ${whoisArgs.join(' ')}`;

    if (debugMode) {
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois]')} Starting lookup for ${cleanDomain} (timeout: ${timeout}ms)`);
        logFunc(`${messageColors.highlight('[whois]')} Command: ${whoisCommand}`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Starting lookup for ${cleanDomain} (timeout: ${timeout}ms)`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Command: ${whoisCommand}`));
      }
    }

    const { stdout, stderr } = await execFileWithTimeout('whois', whoisArgs, timeout);
    const duration = Date.now() - startTime;
    
    if (stderr && stderr.trim()) {
      if (debugMode) {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois]')} Lookup failed for ${cleanDomain} after ${duration}ms`);
          logFunc(`${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`);
          logFunc(`${messageColors.highlight('[whois]')} Error: ${stderr.trim()}`);
          logFunc(`${messageColors.highlight('[whois]')} Command executed: ${whoisCommand}`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Lookup failed for ${cleanDomain} after ${duration}ms`));
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`));
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Error: ${stderr.trim()}`));
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Command executed: ${whoisCommand}`));
        }
      if (selectedServer) {
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois]')} Custom server used: ${selectedServer}`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Custom server used: ${selectedServer}`));
          }
        }
      }
      
      return {
        success: false,
        error: stderr.trim(),
        domain: cleanDomain,
        whoisServer: selectedServer,
        duration: duration,
        command: whoisCommand
      };
    }
    
    if (debugMode) {
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois]')} Lookup successful for ${cleanDomain} after ${duration}ms`);
        logFunc(`${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`);
        logFunc(`${messageColors.highlight('[whois]')} Output length: ${stdout.length} characters`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Lookup successful for ${cleanDomain} after ${duration}ms`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Output length: ${stdout.length} characters`));
      }
    }
    
    return {
      success: true,
      output: stdout,
      domain: cleanDomain,
      whoisServer: selectedServer,
      duration: duration,
      command: whoisCommand
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    const isTimeout = error.message.includes('timeout') || error.message.includes('Command timeout');
    const errorType = isTimeout ? 'timeout' : 'error';
    
    if (debugMode) {
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois]')} Lookup ${errorType} for ${cleanDomain || domain} after ${duration}ms`);
        logFunc(`${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`);
        logFunc(`${messageColors.highlight('[whois]')} Command: ${whoisCommand || 'command not built'}`);
        logFunc(`${messageColors.highlight('[whois]')} ${errorType === 'timeout' ? 'Timeout' : 'Error'}: ${error.message}`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Lookup ${errorType} for ${cleanDomain || domain} after ${duration}ms`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Command: ${whoisCommand || 'command not built'}`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} ${errorType === 'timeout' ? 'Timeout' : 'Error'}: ${error.message}`));
      }
      
       if (selectedServer) {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois]')} Failed server: ${selectedServer} (custom)`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Failed server: ${selectedServer} (custom)`));
        }
      } else {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois]')} Failed server: system default whois server`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Failed server: system default whois server`));
        }
      }
      
      if (isTimeout) {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois]')} Timeout exceeded ${timeout}ms limit`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Timeout exceeded ${timeout}ms limit`));
        }
        if (selectedServer) {
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois]')} Consider using a different whois server or increasing timeout`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Consider using a different whois server or increasing timeout`));
          }
        }
      }
    }
    
    return {
      success: false,
      error: error.message,
      domain: cleanDomain || domain,
      whoisServer: selectedServer,
      duration: duration,
      command: whoisCommand,
      isTimeout: isTimeout,
      errorType: errorType
    };
  }
}

/**
 * Performs a whois lookup with retry logic and fallback servers
 * @param {string} domain - Domain to lookup
 * @param {number} timeout - Timeout in milliseconds (default: 10000)
 * @param {string|Array<string>} whoisServer - Custom whois server(s) to use
 * @param {boolean} debugMode - Enable debug logging (default: false)
 * @param {Object} retryOptions - Retry configuration options
 * @param {number} whoisDelay - Delay in milliseconds before whois requests (default: 2000)
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function whoisLookupWithRetry(domain = '', timeout = 10000, whoisServer = '', debugMode = false, retryOptions = {}, whoisDelay = 8000, logFunc = null) {
  const {
    maxRetries = 3,
    timeoutMultiplier = 1.5,
    useFallbackServers = true,
    retryOnTimeout = true,
    retryOnError = true
  } = retryOptions;

  let serversToTry = [];
  
  // Build list of servers to try
  if (whoisServer && whoisServer !== '') {
    if (Array.isArray(whoisServer)) {
      serversToTry = [...whoisServer]; // Copy array to avoid modifying original
    } else {
      serversToTry = [whoisServer];
    }
  } else {
    serversToTry = ['']; // Default server (empty string instead of null)
  }
  
  // Add fallback servers if enabled and we have custom servers
  if (useFallbackServers && whoisServer && whoisServer !== '') {
    const fallbacks = suggestWhoisServers(domain).slice(0, 3);
    // Only add fallbacks that aren't already in our list
    const existingServers = serversToTry.filter(s => s !== '');
        const existingServerCount = existingServers.length;
        const newFallbacks = fallbacks.filter(fb => {
          for (let i = 0; i < existingServerCount; i++) {
            if (existingServers[i] === fb) return false;
          }
          return true;
        });
    serversToTry.push(...newFallbacks);
  }
  
  let lastError = null;
  let totalAttempts = 0;
  let serversAttempted = [];
  
  if (debugMode) {
      const totalServers = serversToTry.length;
    if (logFunc) {
        logFunc(`${messageColors.highlight('[whois-retry]')} Starting whois lookup for ${domain} with ${totalServers} server(s) to try`);
      logFunc(`${messageColors.highlight('[whois-retry]')} Servers: [${serversToTry.map(s => s || 'default').join(', ')}]`);
      logFunc(`${messageColors.highlight('[whois-retry]')} Retry settings: maxRetries=${maxRetries} per server, timeoutMultiplier=${timeoutMultiplier}, retryOnTimeout=${retryOnTimeout}, retryOnError=${retryOnError}`);
    } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Starting whois lookup for ${domain} with ${totalServers} server(s) to try`));
      console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Servers: [${serversToTry.map(s => s || 'default').join(', ')}]`));
      console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Retry settings: maxRetries=${maxRetries} per server, timeoutMultiplier=${timeoutMultiplier}, retryOnTimeout=${retryOnTimeout}, retryOnError=${retryOnError}`));
    }
  }
  
  // Try each server with retry logic
  const serverCount = serversToTry.length;
  for (let serverIndex = 0; serverIndex < serverCount; serverIndex++) {
    const server = serversToTry[serverIndex];
    let currentTimeout = timeout;
    let retryCount = 0;
    serversAttempted.push(server);
    
    if (debugMode) {
      const serverName = (server && server !== '') ? server : 'default';
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois-retry]')} Server ${serverIndex + 1}/${serverCount}: ${serverName} (max ${maxRetries} attempts)`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Server ${serverIndex + 1}/${serverCount}: ${serverName} (max ${maxRetries} attempts)`));
      }
    }
    
    // Retry this server up to maxRetries times
    while (retryCount < maxRetries) {
      totalAttempts++;
      const attemptNum = retryCount + 1;
      
      if (debugMode) {
        const serverName = (server && server !== '') ? server : 'default';
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois-retry]')} Attempt ${attemptNum}/${maxRetries} on server ${serverName} (timeout: ${currentTimeout}ms)`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Attempt ${attemptNum}/${maxRetries} on server ${serverName} (timeout: ${currentTimeout}ms)`));
        }
      }
      
      // Add progressive delay between retries (but not before first attempt on any server)
      if (retryCount > 0 && whoisDelay > 0) {
        // Progressive delay: base delay * retry attempt number + extra delay
        // Attempt 2: base delay * 1 + 4000ms = 8000ms + 4000ms = 12000ms
        // Attempt 3: base delay * 2 + 6000ms = 16000ms + 6000ms = 22000ms
        // Attempt 4+: base delay * 3 + 6000ms = 24000ms + 6000ms = 30000ms (if maxRetries > 3)
        const delayMultiplier = Math.min(retryCount, 3);
        const baseDelay = whoisDelay * delayMultiplier;
        
        // Add extra delay based on retry attempt
        let extraDelay = 0;
        if (retryCount === 1) {
          extraDelay = 4000; // Extra 4 seconds for 2nd attempt
        } else if (retryCount >= 2) {
          extraDelay = 6000; // Extra 6 seconds for 3rd+ attempts
        }
        
        const actualDelay = baseDelay + extraDelay;
        
        if (debugMode) {
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois-retry]')} Adding ${actualDelay}ms progressive delay before retry ${retryCount + 1} (base: ${baseDelay}ms + extra: ${extraDelay}ms)...`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Adding ${actualDelay}ms progressive delay before retry ${retryCount + 1} (base: ${baseDelay}ms + extra: ${extraDelay}ms)...`));
          }
        }
        await new Promise(resolve => setTimeout(resolve, actualDelay));
      } else if (serverIndex > 0 && retryCount === 0 && whoisDelay > 0) {
        // Add delay before trying a new server (but not the very first server)
        if (debugMode) {
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois-retry]')} Adding ${whoisDelay}ms delay before trying new server...`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Adding ${whoisDelay}ms delay before trying new server...`));
          }
        }
        await new Promise(resolve => setTimeout(resolve, whoisDelay));
      } else if (debugMode && whoisDelay === 0) {
        // Log when delay is skipped due to whoisDelay being 0
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois-retry]')} Skipping delay (whoisDelay: ${whoisDelay}ms)`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Skipping delay (whoisDelay: ${whoisDelay}ms)`));
        }
      }
      
      try {
        const result = await whoisLookup(domain, currentTimeout, server || '', debugMode, logFunc);
        
        if (result.success) {
          if (debugMode) {
            if (logFunc) {
              logFunc(`${messageColors.highlight('[whois-retry]')} SUCCESS on attempt ${attemptNum}/${maxRetries} for server ${result.whoisServer || 'default'} (total attempts: ${totalAttempts})`);
            } else {
              console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} SUCCESS on attempt ${attemptNum}/${maxRetries} for server ${result.whoisServer || 'default'} (total attempts: ${totalAttempts})`));
            }
          }
          
          // Add retry info to result
          // V8 Optimized: Object.assign performs better than spread
          return Object.assign({}, result, {
            retryInfo: {
              totalAttempts: totalAttempts,
              maxAttempts: serverCount * maxRetries,
              serversAttempted: serversAttempted,
              finalServer: result.whoisServer,
              retriedAfterFailure: totalAttempts > 1,
              serverRetries: retryCount,
              serverIndex: serverIndex
            }
          });
        }
        
        // Determine if we should retry based on error type
        const shouldRetry = (result.isTimeout && retryOnTimeout) || (!result.isTimeout && retryOnError);
        
        if (debugMode) {
          const serverName = (result.whoisServer && result.whoisServer !== '') ? result.whoisServer : 'default';
          const errorType = result.isTimeout ? 'TIMEOUT' : 'ERROR';
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois-retry]')} ${errorType} on attempt ${attemptNum}/${maxRetries} with server ${serverName}: ${result.error}`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} ${errorType} on attempt ${attemptNum}/${maxRetries} with server ${serverName}: ${result.error}`));
          }
          
          if (retryCount < maxRetries - 1) {
            if (shouldRetry) {
              if (logFunc) {
                logFunc(`${messageColors.highlight('[whois-retry]')} Will retry attempt ${attemptNum + 1}/${maxRetries} on same server...`);
              } else {
                console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Will retry attempt ${attemptNum + 1}/${maxRetries} on same server...`));
              }
            } else {
              if (logFunc) {
                logFunc(`${messageColors.highlight('[whois-retry]')} Skipping retry on same server (retryOn${result.isTimeout ? 'Timeout' : 'Error'}=${shouldRetry})`);
              } else {
                console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Skipping retry on same server (retryOn${result.isTimeout ? 'Timeout' : 'Error'}=${shouldRetry})`));
              }
            }
          } else if (serverIndex < serverCount - 1) {
            if (logFunc) {
              logFunc(`${messageColors.highlight('[whois-retry]')} Max retries reached for server${serverIndex < serverCount - 1 ? ', will try next server...' : ', no more servers to try'}`);
            } else {
              console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Max retries reached for server${serverIndex < serverCount - 1 ? ', will try next server...' : ', no more servers to try'}`));            }
          }
        }
        
        lastError = result;
        
        // If this is the last retry for this server or we shouldn't retry this error type, break to next server
        if (retryCount >= maxRetries - 1 || !shouldRetry) {
          break;
        }
        
        // Increase timeout for next retry attempt on same server
        retryCount++;
        currentTimeout = Math.round(currentTimeout * timeoutMultiplier);
        
      } catch (error) {
        if (debugMode) {
          const serverName = (server && server !== '') ? server : 'default'
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois-retry]')} EXCEPTION on attempt ${attemptNum}/${maxRetries} with server ${serverName}: ${error.message}`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} EXCEPTION on attempt ${attemptNum}/${maxRetries} with server ${serverName}: ${error.message}`));
          }
        }
        
        lastError = {
          success: false,
          error: error.message,
          domain: domain,
          whoisServer: server || '',
          isTimeout: error.message.includes('timeout'),
          duration: 0
        };
        
        // For exceptions, only retry if it's a retryable error type
        const isRetryableException = error.message.includes('timeout') || 
                                   error.message.includes('ECONNRESET') || 
                                   error.message.includes('ENOTFOUND');
        
        if (retryCount >= maxRetries - 1 || !isRetryableException) {
          break;
        }
        
        retryCount++;
        currentTimeout = Math.round(currentTimeout * timeoutMultiplier);
      }
    }
  }
  
  // All attempts failed
  if (debugMode) {
    const attemptedServerCount = serversAttempted.length;
    if (logFunc) {
      logFunc(`${messageColors.highlight('[whois-retry]')} FINAL FAILURE: All ${totalAttempts} attempts failed for ${domain} across ${attemptedServerCount} server(s)`);
    } else {
      console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} FINAL FAILURE: All ${totalAttempts} attempts failed for ${domain} across ${attemptedServerCount} server(s)`));
    }
    if (lastError) {
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois-retry]')} Last error: ${lastError.error} (${lastError.isTimeout ? 'timeout' : 'error'})`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Last error: ${lastError.error} (${lastError.isTimeout ? 'timeout' : 'error'})`));
      }
    }
  }
  
  // Return the last error with retry info
  // V8 Optimized: Object.assign instead of spread operator
  return Object.assign({}, lastError, {
    retryInfo: {
      totalAttempts: totalAttempts,
      maxAttempts: serverCount * maxRetries,
      serversAttempted: serversAttempted,
      finalServer: lastError?.whoisServer || '',
      retriedAfterFailure: totalAttempts > 1,
      allAttemptsFailed: true
    }
  });
}

/**
 * Performs a dig lookup on a domain with proper timeout handling
 * @param {string} domain - Domain to lookup
 * @param {string} recordType - DNS record type (A, AAAA, MX, TXT, etc.) default: 'A'
 * @param {number} timeout - Timeout in milliseconds (default: 5000)
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function digLookup(domain = '', recordType = 'A', timeout = 5000) {
  try {
    // Clean domain
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');

    // Single dig command — full output contains everything including short
    // answers. execFile (no shell) so cleanDomain / recordType can contain
    // any chars without injection risk.
    const { stdout: fullOutput, stderr } = await execFileWithTimeout('dig', [cleanDomain, recordType], timeout);
    
    if (stderr && stderr.trim()) {
      return {
        success: false,
        error: stderr.trim(),
        domain: cleanDomain,
        recordType
      };
    }
    
    // Extract short output from ANSWER SECTION of full dig output
    const answerMatch = fullOutput.match(/;; ANSWER SECTION:\n([\s\S]*?)(?:\n;;|\n*$)/);
    let shortOutput = '';
    if (answerMatch) {
      shortOutput = answerMatch[1]
        .split('\n')
        .map(line => line.split(/\s+/).pop())
        .filter(Boolean)
        .join('\n');
    }
    
    return {
      success: true,
      output: fullOutput,
      shortOutput,
      domain: cleanDomain,
      recordType
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      domain: domain,
      recordType
    };
  }
}

/**
 * Checks if whois output contains all specified search terms (AND logic)
 * @param {string} whoisOutput - The whois lookup output
 * @param {Array<string>} searchTerms - Array of terms that must all be present
 * @returns {boolean} True if all terms are found
 */
function checkWhoisTerms(whoisOutput, searchTerms) {
  if (!searchTerms || !Array.isArray(searchTerms) || searchTerms.length === 0) {
    return false;
  }
  
  const lowerOutput = whoisOutput.toLowerCase();
  return searchTerms.every(term => lowerOutput.includes(term.toLowerCase()));
}

/**
 * Checks if whois output contains any of the specified search terms (OR logic)
 * @param {string} whoisOutput - The whois lookup output
 * @param {Array<string>} searchTerms - Array of terms where at least one must be present
 * @returns {boolean} True if any term is found
 */
function checkWhoisTermsOr(whoisOutput, searchTerms) {
  if (!searchTerms || !Array.isArray(searchTerms) || searchTerms.length === 0) {
    return false;
  }
  
  const lowerOutput = whoisOutput.toLowerCase();
  return searchTerms.some(term => lowerOutput.includes(term.toLowerCase()));
}

/**
 * Checks if dig output contains all specified search terms (AND logic)
 * @param {string} digOutput - The dig lookup output
 * @param {Array<string>} searchTerms - Array of terms that must all be present
 * @returns {boolean} True if all terms are found
 */
function checkDigTerms(digOutput, searchTerms) {
  if (!searchTerms || !Array.isArray(searchTerms) || searchTerms.length === 0) {
    return false;
  }
  
  const lowerOutput = digOutput.toLowerCase();
  return searchTerms.every(term => lowerOutput.includes(term.toLowerCase()));
}

/**
 * Checks if dig output contains any of the specified search terms (OR logic)
 * @param {string} digOutput - The dig lookup output
 * @param {Array<string>} searchTerms - Array of terms where at least one must be present
 * @returns {boolean} True if any term is found
 */
function checkDigTermsOr(digOutput, searchTerms) {
  if (!searchTerms || !Array.isArray(searchTerms) || searchTerms.length === 0) {
    return false;
  }
  
  const lowerOutput = digOutput.toLowerCase();
  return searchTerms.some(term => lowerOutput.includes(term.toLowerCase()));
}

/**
 * Enhanced dry run callback factory for better nettools reporting
 * @param {Map} matchedDomains - The matched domains collection
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Function} Enhanced dry run callback
 */
function createEnhancedDryRunCallback(matchedDomains, forceDebug) {
  return (domain, tool, matchType, matchedTerm, details, additionalInfo = {}) => {
    const result = { 
      domain, 
      tool, 
      matchType, 
      matchedTerm, 
      details, 
      ...additionalInfo 
    };
    
    matchedDomains.get('dryRunNetTools').push(result);
    
    if (forceDebug) {
      const serverInfo = additionalInfo.server ? ` (server: ${additionalInfo.server})` : '';
      const timingInfo = additionalInfo.duration ? ` [${additionalInfo.duration}ms]` : '';
      console.log(formatLogMessage('debug', `[DRY RUN] NetTools match: ${domain} via ${tool.toUpperCase()} (${matchType})${serverInfo}${timingInfo}`));
    }
  };
}

/**
 * Creates a handler for network tools checks with enhanced error handling
 * @param {Object} config - Configuration object
 * @returns {Function} Async function that handles network tool lookups
 */
function createNetToolsHandler(config) {
  const {
    whoisTerms,
    whoisOrTerms,
    whoisDelay = 4000,
    whoisServer,
    whoisServerMode = 'random',
    debugLogFile = null,
    digTerms,
    digOrTerms,
    digRecordType = 'A',
    digSubdomain = false,
    dryRunCallback = null,
    matchedDomains,
    addMatchedDomain,
    isDomainAlreadyDetected,
    getRootDomain,
    siteConfig,
    processedWhoisDomains = new Set(), // Accept global sets, fallback to new for backward compatibility
    processedDigDomains = new Set(),
    dumpUrls,
    matchedUrlsLogFile,
    forceDebug,
    fs,
    // ignoreDomains guard: callers pass the live ignoreDomains list + matcher
    // so a domain that became ignored AFTER the request fired (e.g. via
    // ignoreDomainsByUrl on a sibling request, or _dynamicallyIgnoredDomains)
    // doesn't slip into matchedDomains during the async whois/dig window.
    // Both default to no-op so older callers without the kwargs still work.
    ignoreDomains = null,
    matchesIgnoreDomain = null
  } = config;
  
  const hasWhois = whoisTerms && Array.isArray(whoisTerms) && whoisTerms.length > 0;
  const hasWhoisOr = whoisOrTerms && Array.isArray(whoisOrTerms) && whoisOrTerms.length > 0;
  const hasDig = digTerms && Array.isArray(digTerms) && digTerms.length > 0;
  const hasDigOr = digOrTerms && Array.isArray(digOrTerms) && digOrTerms.length > 0;

  // Pre-lowercase search terms once per handler so the per-domain check loop
  // doesn't re-lowercase the same constants for every output it scans.
  const whoisTermsLower   = hasWhois   ? whoisTerms.map(t => t.toLowerCase())   : null;
  const whoisOrTermsLower = hasWhoisOr ? whoisOrTerms.map(t => t.toLowerCase()) : null;
  const digTermsLower     = hasDig     ? digTerms.map(t => t.toLowerCase())     : null;
  const digOrTermsLower   = hasDigOr   ? digOrTerms.map(t => t.toLowerCase())   : null;

  // Hoisted out of handleNetToolsCheck so the closure is constructed once per
  // handler rather than once per invocation. References forceDebug, debugLogFile,
  // and fs from the destructured config above.
  function logToConsoleAndFile(message) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', message));
    }
    if (debugLogFile && fs) {
      try {
        const timestamp = new Date().toISOString();
        const cleanMessage = stripAnsiColors(message);
        fs.appendFileSync(debugLogFile, `${timestamp} [debug nettools] ${cleanMessage}\n`);
      } catch (_) {
        // Silently fail file logging to avoid disrupting whois operations
      }
    }
  }
  
  // Create config-aware cache keys for deduplication
  // Whois: Only include search terms + server (domain registry data is consistent across subdomains)
  const whoisConfigKey = JSON.stringify({
    terms: whoisTerms || [],
    orTerms: whoisOrTerms || [],
    server: whoisServer || 'default',
    serverMode: whoisServerMode || 'random'
  });
  // Dig: Include all config (DNS records can vary by specific subdomain)
  const digConfigKey = JSON.stringify({
    terms: digTerms || [],
    orTerms: digOrTerms || [],
    recordType: digRecordType,
    subdomain: digSubdomain
  });

  // Whois cache is global (globalWhoisResultCache) — shared across all handler instances
  // Whois data is per root domain and doesn't change based on search terms
  // Dig cache is global (globalDigResultCache) — shared across all handler instances
  // DNS results are the same regardless of search terms
  
  return async function handleNetToolsCheck(domain, fullSubdomain) {
    const originalDomain = fullSubdomain;

    // Check if domain was already detected (skip expensive operations)
    if (typeof isDomainAlreadyDetected === 'function' && isDomainAlreadyDetected(fullSubdomain)) {
      if (forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Skipping already detected subdomain: ${fullSubdomain} (output domain: ${domain})`);
      }
      return;
    }

    // Determine which domain will be used for dig lookup
    const digDomain = digSubdomain && originalDomain ? originalDomain : domain;

    // For whois: use root domain only (whois data is consistent for entire domain)
    const whoisRootDomain = getRootDomain ? getRootDomain(`http://${domain}`) : domain;
    
    // Check if we need to perform any lookups with appropriate deduplication
    // Whois: root domain + config (whois data same for sub.example.com and example.com)
    const whoisDedupeKey = `${whoisRootDomain}:${whoisConfigKey}`;
    // Dig: specific subdomain + config (DNS records can differ between subdomains)
    const digDedupeKey = `${digDomain}:${digConfigKey}`;
    const needsWhoisLookup = (hasWhois || hasWhoisOr) && !processedWhoisDomains.has(whoisDedupeKey);
    const needsDigLookup = (hasDig || hasDigOr) && !processedDigDomains.has(digDedupeKey);
    
    // Skip if we don't need to perform any lookups
    if (!needsWhoisLookup && !needsDigLookup) {
      if (forceDebug) {
        const whoisSkipped = (hasWhois || hasWhoisOr) ? `cached(${whoisRootDomain})` : 'n/a';
        const digSkipped = (hasDig || hasDigOr) ? `cached(${digDomain})` : 'n/a';
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Skipping duplicate lookups for ${domain} (whois: ${whoisSkipped}, dig: ${digSkipped})`);
      }
      return;
    }
    

    if (forceDebug) {
      const totalProcessed = processedWhoisDomains.size + processedDigDomains.size;
      logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Processing domain: ${domain} (whois: ${needsWhoisLookup ? whoisRootDomain : 'skip'}, dig: ${needsDigLookup ? digDomain : 'skip'}) (${totalProcessed} total processed)`);
    }

      // Log site-specific whois delay if different from default
      if (forceDebug && whoisDelay !== 3000) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Using site-specific whois delay: ${whoisDelay}ms`);
      }

    // Wrap entire function in timeout protection (single timer)
    let overallTimeoutId;
    return Promise.race([
      (async () => {
        try { return await executeNetToolsLookup(); }
        finally { clearTimeout(overallTimeoutId); }
      })(),
      new Promise((_, reject) => {
        overallTimeoutId = setTimeout(() => reject(new Error('NetTools overall timeout')), 65000);
        // unref so a still-pending overall timeout (handler returned via
        // drain at 3s but the lookup is technically still in-flight) can't
        // hold the event loop alive for the full 65s on scan exit. The
        // finally on the inner promise still clearTimeouts on natural
        // completion, so this only matters for the genuinely-hung case.
        if (typeof overallTimeoutId.unref === 'function') overallTimeoutId.unref();
      })
    ]).catch(err => {
      if (forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} ${err.message} for ${domain}, continuing...`);
      }
    });
    
    async function executeNetToolsLookup() {
    
    try {
      let whoisMatched = false;
      let whoisOrMatched = false;
      let digMatched = false;
      let digOrMatched = false;
      
      // Debug logging for digSubdomain logic
      if (forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} digSubdomain setting: ${digSubdomain}`);
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} domain parameter: ${domain}`);
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} originalDomain parameter: ${originalDomain}`);
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Final digDomain will be: ${digDomain}`);
        if (whoisServer) {
          const serverInfo = Array.isArray(whoisServer) 
            ? `randomized from [${whoisServer.join(', ')}]` 
            : whoisServer;
          logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Custom whois server: ${serverInfo}`);
        }
      }
      
      // Enhanced dry run logging
      if (dryRunCallback && forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools-dryrun]')} Processing ${domain} (original: ${originalDomain})`);

        // Show what checks will be performed
        const checksToPerform = [];
        if (hasWhois) checksToPerform.push('whois-and');
        if (hasWhoisOr) checksToPerform.push('whois-or');
        if (hasDig) checksToPerform.push('dig-and');
        if (hasDigOr) checksToPerform.push('dig-or');
        logToConsoleAndFile(`${messageColors.highlight('[nettools-dryrun]')} Will perform: ${checksToPerform.join(', ')}`);
        
        // Show which domain will be used for dig
        if (hasDig || hasDigOr) {
          logToConsoleAndFile(`${messageColors.highlight('[dig-dryrun]')} Will check ${digDomain} (${digSubdomain ? 'subdomain mode' : 'root domain mode'})`);
        }
        
        // Show whois server selection
        if (hasWhois || hasWhoisOr) {
          const selectedServer = selectWhoisServer(whoisServer, whoisServerMode);
          const serverInfo = selectedServer ? selectedServer : 'system default';
          logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} Will use server: ${serverInfo}`);
        }
        
        // Show retry configuration in dry-run
        if (hasWhois || hasWhoisOr) {
          const maxRetries = siteConfig.whois_max_retries || 2;
          logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} Max retries: ${maxRetries}, timeout multiplier: ${siteConfig.whois_timeout_multiplier || 1.5}`);
        }
      }
      
      // Perform whois lookup if either whois or whois-or is configured
      if (needsWhoisLookup) {
        // Mark whois root domain+config as being processed
        processedWhoisDomains.add(whoisDedupeKey);
        
        // Check whois cache first - cache key includes server for accuracy
        const selectedServer = selectWhoisServer(whoisServer, whoisServerMode);
        const whoisCacheKey = `${whoisRootDomain}-${(selectedServer && selectedServer !== '') ? selectedServer : 'default'}`;
        const now = Date.now();
        let whoisResult = null;
        
        if (globalWhoisResultCache.has(whoisCacheKey)) {
          const cachedEntry = globalWhoisResultCache.get(whoisCacheKey);
          if (now - cachedEntry.timestamp < GLOBAL_WHOIS_CACHE_TTL) {
            if (forceDebug) {
              const age = Math.round((now - cachedEntry.timestamp) / 1000);
              const serverInfo = (selectedServer && selectedServer !== '') ? ` (server: ${selectedServer})` : ' (default server)';
              logToConsoleAndFile(`${messageColors.highlight('[whois-cache]')} Using cached result for ${whoisRootDomain}${serverInfo} [age: ${age}s]`);
            }
            // V8 Optimized: Object.assign is faster than spread for object merging
            whoisResult = Object.assign({}, cachedEntry.result, {
              fromCache: true,
              cacheAge: now - cachedEntry.timestamp,
              originalTimestamp: cachedEntry.timestamp
            });
            dnsCacheStats.whoisHits++;
            // Warm the resolved-hostnames index from disk-loaded entries.
            // Cached whois entries are pre-filtered for network errors at
            // write time, so every cached entry implies the domain has a
            // registrar record -- strong resolution signal.
            markResolved(whoisRootDomain);
          } else {
            // Cache expired, remove it
            globalWhoisResultCache.delete(whoisCacheKey);
            if (forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[whois-cache]')} Cache expired for ${whoisRootDomain}, performing fresh lookup`);
            }
          }
        }
        
        // Perform fresh lookup if not cached
        if (!whoisResult) {
          // Deduplicate concurrent lookups — wait for in-flight request instead of starting a new one
          if (pendingWhoisLookups.has(whoisCacheKey)) {
            whoisResult = await pendingWhoisLookups.get(whoisCacheKey);
          } else {
            if (forceDebug) {
              const serverInfo = (selectedServer && selectedServer !== '') ? ` using server ${selectedServer}` : ' using default server';
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Performing fresh whois lookup for ${whoisRootDomain}${serverInfo}`);
            }

            // Configure retry options based on site config or use defaults
            const retryOptions = {
              maxRetries: siteConfig.whois_max_retries || 3,
              timeoutMultiplier: siteConfig.whois_timeout_multiplier || 1.5,
              useFallbackServers: siteConfig.whois_use_fallback !== false, // Default true
              retryOnTimeout: siteConfig.whois_retry_on_timeout !== false, // Default true
              retryOnError: siteConfig.whois_retry_on_error === true // Default false
            };

            try {
              const lookupPromise = whoisLookupWithRetry(whoisRootDomain, 8000, whoisServer, forceDebug, retryOptions, whoisDelay, logToConsoleAndFile);
              pendingWhoisLookups.set(whoisCacheKey, lookupPromise);
              // try/finally so a rejected lookup still clears the pending
              // entry — see matching comment on pendingDigLookups below.
              try {
                whoisResult = await lookupPromise;
              } finally {
                pendingWhoisLookups.delete(whoisCacheKey);
              }

              // Cache successful results (and certain types of failures)
              if (whoisResult.success ||
                  (whoisResult.error && !whoisResult.isTimeout &&
                   !whoisResult.error.toLowerCase().includes('connection') &&
                   !whoisResult.error.toLowerCase().includes('network'))) {

                // `hostname` field is backwards-compat additive (see dig
                // write site for details).
                globalWhoisResultCache.set(whoisCacheKey, {
                  result: whoisResult,
                timestamp: now,
                hostname: whoisRootDomain
              });
              dnsCacheStats.whoisMisses++;
              pushFreshSample(dnsCacheStats.freshWhois, whoisRootDomain);
              // Only mark resolved on actual whois success -- a cached
              // "not found" / "no match" failure shouldn't claim resolution.
              if (whoisResult.success) markResolved(whoisRootDomain);

              if (forceDebug) {
                const cacheType = whoisResult.success ? 'successful' : 'failed';
                const serverInfo = selectedServer ? ` (server: ${selectedServer})` : ' (default server)';
                logToConsoleAndFile(`${messageColors.highlight('[whois-cache]')} Cached ${cacheType} result for ${whoisRootDomain}${serverInfo}`);
              }
            }
          } catch (whoisError) {
            // Handle exceptions from whois lookup
            if (forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Exception during lookup for ${whoisRootDomain}: ${whoisError.message}`);
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Exception type: ${whoisError.constructor.name}`);
              if (whoisError.stack) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Stack trace: ${whoisError.stack.split('\n').slice(0, 3).join(' -> ')}`);
              }
            }
            
            // Log whois exceptions in dry run mode
            if (dryRunCallback && forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} Exception for ${whoisRootDomain}: ${whoisError.message}`);
            }
            // Continue with dig if configured
            whoisResult = null; // Ensure we don't process a null result
          }
          }
        }
        
        // Process whois result (whether from cache or fresh lookup)
        if (whoisResult) {

          if (whoisResult.success) {
            // Lowercase the output ONCE — checkWhoisTerms / checkWhoisTermsOr
            // each call .toLowerCase() on their input independently, which
            // re-allocates a multi-KB lowercased string per call. Pre-lowering
            // here lets the AND check, OR check, and matched-term find share
            // a single allocation.
            const whoisOutputLower = whoisResult.output.toLowerCase();

            // Check AND terms if configured
            if (hasWhois) {
              whoisMatched = whoisTermsLower.every(t => whoisOutputLower.includes(t));
              if (whoisMatched && dryRunCallback) {
                dryRunCallback(domain, 'whois', 'AND logic', whoisTerms.join(', '), 'All terms found in whois data', {
                  server: whoisResult.whoisServer || 'default',
                  duration: whoisResult.duration,
                  fromCache: whoisResult.fromCache || false,
                  retryAttempts: whoisResult.retryInfo?.totalAttempts || 1
                });
              }
              if (forceDebug && siteConfig.verbose === 1) {
                logToConsoleAndFile(`${messageColors.highlight('[whois-and]')} Terms checked: ${whoisTerms.join(' AND ')}, matched: ${whoisMatched}`);
              }

            }

            // Check OR terms if configured
            if (hasWhoisOr) {
              whoisOrMatched = whoisOrTermsLower.some(t => whoisOutputLower.includes(t));
              if (whoisOrMatched && dryRunCallback) {
                const matchedIdx = whoisOrTermsLower.findIndex(t => whoisOutputLower.includes(t));
                const matchedTerm = whoisOrTerms[matchedIdx];
                dryRunCallback(domain, 'whois', 'OR logic', matchedTerm, 'Term found in whois data', {
                  server: whoisResult.whoisServer || 'default',
                  duration: whoisResult.duration,
                  fromCache: whoisResult.fromCache || false,
                  retryAttempts: whoisResult.retryInfo?.totalAttempts || 1
                });
              }

              if (forceDebug && siteConfig.verbose === 1) {
                logToConsoleAndFile(`${messageColors.highlight('[whois-or]')} Terms checked: ${whoisOrTerms.join(' OR ')}, matched: ${whoisOrMatched}`);
              }
            }
            
            if (forceDebug) {
              const serverUsed = whoisResult.whoisServer ? ` (server: ${whoisResult.whoisServer})` : ' (default server)';
              const retryInfo = whoisResult.retryInfo ? ` [${whoisResult.retryInfo.totalAttempts}/${whoisResult.retryInfo.maxAttempts} attempts]` : '';
              const cacheInfo = whoisResult.fromCache ? ` [CACHED - ${Math.round(whoisResult.cacheAge / 1000)}s old]` : '';
              const duration = whoisResult.fromCache ? `cached in 0ms` : `in ${whoisResult.duration}ms`;
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Lookup completed for ${whoisRootDomain}${serverUsed} ${duration}${retryInfo}${cacheInfo}`);            
              
              if (whoisResult.retryInfo && whoisResult.retryInfo.retriedAfterFailure) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Success after retry - servers attempted: [${whoisResult.retryInfo.serversAttempted.map(s => s || 'default').join(', ')}]`);
              }
            }
          } else {
            // Enhanced error logging for failed whois lookups
            if (forceDebug) {
              const serverUsed = whoisResult.whoisServer ? ` (server: ${whoisResult.whoisServer})` : ' (default server)';
              const errorContext = whoisResult.isTimeout ? 'TIMEOUT' : 'ERROR';
              const retryInfo = whoisResult.retryInfo ? ` [${whoisResult.retryInfo.totalAttempts}/${whoisResult.retryInfo.maxAttempts} attempts]` : '';
              
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} ${errorContext}: Lookup failed for ${whoisRootDomain}${serverUsed} after ${whoisResult.duration}ms${retryInfo}`);
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Command executed: ${whoisResult.command || 'unknown'}`);
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Error details: ${whoisResult.error}`);
              
              // Enhanced server debugging for failures
              if (whoisResult.whoisServer) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Failed server: ${whoisResult.whoisServer} (custom)`);
              } else {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Failed server: system default whois server`);
              }
              
              
              if (whoisResult.retryInfo) {
                if (whoisResult.retryInfo.allAttemptsFailed) {
                  logToConsoleAndFile(`${messageColors.highlight('[whois]')} All retry attempts failed. Servers tried: [${whoisResult.retryInfo.serversAttempted.map(s => s || 'default').join(', ')}]`);
                }
                
                if (whoisResult.retryInfo.retriedAfterFailure) {
                  logToConsoleAndFile(`${messageColors.highlight('[whois]')} Retries were attempted but ultimately failed`);
                }
              }
              
              if (whoisResult.isTimeout) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Timeout exceeded limit after all retry attempts`);
                if (Array.isArray(whoisServer) && whoisServer.length > 1) {
                  const remainingServers = whoisServer.filter(s => !whoisResult.retryInfo?.serversAttempted.includes(s));
                  if (remainingServers.length > 0) {
                    logToConsoleAndFile(`${messageColors.highlight('[whois]')} Unused servers from config: ${remainingServers.join(', ')}`);
                  }
                } else {
                  // Suggest alternative servers based on domain TLD
                  const suggestions = suggestWhoisServers(domain, whoisResult.whoisServer).slice(0, 3);
                  if (suggestions.length > 0) {
                    logToConsoleAndFile(`${messageColors.highlight('[whois]')} Suggested alternative servers: ${suggestions.join(', ')}`);
                  }
                }
                // Show specific rate limiting advice
                if (whoisResult.error.toLowerCase().includes('too fast') || whoisResult.error.toLowerCase().includes('rate limit')) {
                  logToConsoleAndFile(`${messageColors.highlight('[whois]')} Rate limiting detected - consider increasing delays or using different servers`);
                  logToConsoleAndFile(`${messageColors.highlight('[whois]')} Current server: ${whoisResult.whoisServer || 'default'} may be overloaded`);
                }
              }
              
              // Log specific error patterns
              if (whoisResult.error.toLowerCase().includes('connection refused')) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Connection refused - server may be down or blocking requests`);
              } else if (whoisResult.error.toLowerCase().includes('no route to host')) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Network connectivity issue to whois server`);
              } else if (whoisResult.error.toLowerCase().includes('name or service not known')) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} DNS resolution failed for whois server`);
              }
            }
            
            // Log whois failures in dry run mode  
            if (dryRunCallback && forceDebug) {
              const errorType = whoisResult.isTimeout ? 'TIMEOUT' : 'ERROR';
              logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} ${errorType}: ${whoisResult.error}`);
              if (whoisResult.retryInfo?.allAttemptsFailed) {
                logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} All ${whoisResult.retryInfo.totalAttempts} retry attempts failed`);
              }
            }
            // Don't return early - continue with dig if configured
          }
        }
        
        // Periodic whois cache cleanup. enforceCacheCap evicts expired
        // entries first; if still over MAX (all entries still within TTL
        // but too many), evicts the oldest by timestamp so the cap is
        // strictly enforced.
        {
          const ev = enforceCacheCap(globalWhoisResultCache, GLOBAL_WHOIS_CACHE_MAX, GLOBAL_WHOIS_CACHE_TTL);
          if (forceDebug && (ev.expired + ev.overflow) > 0) {
            logToConsoleAndFile(`${messageColors.highlight('[whois-cache]')} Pruned ${ev.expired} expired + ${ev.overflow} overflow entries, cache size: ${globalWhoisResultCache.size}`);
          }
        }
      }
      
      // Perform dig lookup if configured
      if (needsDigLookup) {
        // Mark dig domain+config as being processed (includes specific subdomain)
        processedDigDomains.add(digDedupeKey);
        
        if (forceDebug) {
          const digTypes = [];
          if (hasDig) digTypes.push('dig-and');
          if (hasDigOr) digTypes.push('dig-or');
          logToConsoleAndFile(`${messageColors.highlight('[dig]')} Performing dig lookup for ${digDomain} (${digRecordType}) [${digTypes.join(' + ')}]${digSubdomain ? ' [subdomain mode]' : ''}`);
        }
        
        try {
          // Check dig cache first to avoid redundant dig operations
          const digCacheKey = `${digDomain}-${digRecordType}`;
          const now = Date.now();
          let digResult = null;
          
          if (globalDigResultCache.has(digCacheKey)) {
            const cachedEntry = globalDigResultCache.get(digCacheKey);
            if (now - cachedEntry.timestamp < GLOBAL_DIG_CACHE_TTL) {
              if (forceDebug) {
                logToConsoleAndFile(`${messageColors.highlight('[dig-cache]')} Using cached result for ${digDomain} (${digRecordType}) [age: ${Math.round((now - cachedEntry.timestamp) / 1000)}s]`);
              }
              digResult = cachedEntry.result;
              dnsCacheStats.digHits++;
              // Warm the resolved-hostnames index from disk-loaded entries.
              // No-op if already present.
              if (digResult.success && digOutputIndicatesResolution(digResult.output)) {
                markResolved(digDomain);
              }
            } else {
              // Cache expired, remove it
              globalDigResultCache.delete(digCacheKey);
            }
          }
          
          if (!digResult) {
            // Deduplicate concurrent lookups — wait for in-flight request instead of starting a new one
            if (pendingDigLookups.has(digCacheKey)) {
              digResult = await pendingDigLookups.get(digCacheKey);
            } else {
              const lookupPromise = digLookup(digDomain, digRecordType, 5000);
              pendingDigLookups.set(digCacheKey, lookupPromise);
              // try/finally so a rejected lookup still clears the pending
              // entry — otherwise the Map would retain a rejected-Promise
              // entry forever and any subsequent caller for the same key
              // would await that rejection.
              try {
                digResult = await lookupPromise;
              } finally {
                pendingDigLookups.delete(digCacheKey);
              }

              // Cache the result for future use. `hostname` field is
              // backwards-compat additive: old code reading new cache
              // ignores it; new code reading old cache (no field) falls
              // back to lazy on-hit population in the cache-hit branch.
              globalDigResultCache.set(digCacheKey, {
                result: digResult,
                timestamp: now,
                hostname: digDomain
              });
              dnsCacheStats.digMisses++;
              pushFreshSample(dnsCacheStats.freshDig, `${digDomain} (${digRecordType})`);
              // Index hostname IF dig actually proved resolution -- NXDOMAIN
              // responses arrive as success:true with NXDOMAIN in the body,
              // so digOutputIndicatesResolution is the real gate.
              if (digResult.success && digOutputIndicatesResolution(digResult.output)) {
                markResolved(digDomain);
              }

              if (forceDebug && digResult.success) {
                logToConsoleAndFile(`${messageColors.highlight('[dig-cache]')} Cached new result for ${digDomain} (${digRecordType})`);
              }
            }
          }
          
          if (digResult.success) {
            // Lowercase the output ONCE — see matching comment in the whois
            // branch above for rationale.
            const digOutputLower = digResult.output.toLowerCase();

            // Check AND terms if configured
            if (hasDig) {
              digMatched = digTermsLower.every(t => digOutputLower.includes(t));
              if (digMatched && dryRunCallback) {
                dryRunCallback(domain, 'dig', 'AND logic', digTerms.join(', '), `All terms found in ${digRecordType} records`, {
                  queriedDomain: digDomain,
                  recordType: digRecordType,
                  subdomainMode: digSubdomain
                });
              }
            }

            // Check OR terms if configured
            if (hasDigOr) {
              digOrMatched = digOrTermsLower.some(t => digOutputLower.includes(t));
              if (digOrMatched && dryRunCallback) {
                const matchedIdx = digOrTermsLower.findIndex(t => digOutputLower.includes(t));
                const matchedTerm = digOrTerms[matchedIdx];
                dryRunCallback(domain, 'dig', 'OR logic', matchedTerm, `Term found in ${digRecordType} records`, {
                  queriedDomain: digDomain,
                  recordType: digRecordType,
                  subdomainMode: digSubdomain
                });
              }
            }
            
            if (forceDebug) {
              if (siteConfig.verbose === 1) {
                if (hasDig) logToConsoleAndFile(`${messageColors.highlight('[dig-and]')} Terms checked: ${digTerms.join(' AND ')}, matched: ${digMatched}`);
                if (hasDigOr) logToConsoleAndFile(`${messageColors.highlight('[dig-or]')} Terms checked: ${digOrTerms.join(' OR ')}, matched: ${digOrMatched}`);
              }
              logToConsoleAndFile(`${messageColors.highlight('[dig]')} Lookup completed for ${digDomain}, dig-and: ${digMatched}, dig-or: ${digOrMatched}`);
              if (siteConfig.verbose === 1) {
                if (hasDig) logToConsoleAndFile(`${messageColors.highlight('[dig]')} AND terms: ${digTerms.join(', ')}`);
                if (hasDigOr) logToConsoleAndFile(`${messageColors.highlight('[dig]')} OR terms: ${digOrTerms.join(', ')}`);
                logToConsoleAndFile(`${messageColors.highlight('[dig]')} Short output: ${digResult.shortOutput}`);
              }
            }
          } else {
            if (forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[dig]')} Lookup failed for ${digDomain}: ${digResult.error}`);
            }
            
            // Log dig failures in dry run mode
            if (dryRunCallback && forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[dig-dryrun]')} Failed: ${digResult.error}`);
            }
          }
        } catch (digError) {
          if (forceDebug) {
            logToConsoleAndFile(`${messageColors.highlight('[dig]')} Exception during lookup for ${digDomain}: ${digError.message}`);
          }
          
          // Log dig exceptions in dry run mode
          if (dryRunCallback && forceDebug) {
            logToConsoleAndFile(`${messageColors.highlight('[dig-dryrun]')} Exception: ${digError.message}`);
          }
        }
        
        // Periodic dig cache cleanup. Same enforce-cap pattern as whois.
        {
          const ev = enforceCacheCap(globalDigResultCache, GLOBAL_DIG_CACHE_MAX, GLOBAL_DIG_CACHE_TTL);
          if (forceDebug && (ev.expired + ev.overflow) > 0) {
            logToConsoleAndFile(`${messageColors.highlight('[dig-cache]')} Pruned ${ev.expired} expired + ${ev.overflow} overflow entries, cache size: ${globalDigResultCache.size}`);
          }
        }
      }
      
      // Domain matches if any of these conditions are true:
      let shouldMatch = false;
      
      if (hasWhois && !hasWhoisOr && !hasDig && !hasDigOr) {
        shouldMatch = whoisMatched;
      } else if (!hasWhois && hasWhoisOr && !hasDig && !hasDigOr) {
        shouldMatch = whoisOrMatched;
      } else if (!hasWhois && !hasWhoisOr && hasDig && !hasDigOr) {
        shouldMatch = digMatched;
      } else if (!hasWhois && !hasWhoisOr && !hasDig && hasDigOr) {
        shouldMatch = digOrMatched;
      } else {
        // Multiple checks configured - ALL must pass
        shouldMatch = true;
        if (hasWhois) shouldMatch = shouldMatch && whoisMatched;
        if (hasWhoisOr) shouldMatch = shouldMatch && whoisOrMatched;
        if (hasDig) shouldMatch = shouldMatch && digMatched;
        if (hasDigOr) shouldMatch = shouldMatch && digOrMatched;
      }
      
      if (shouldMatch) {
        // Add to matched domains only if not in dry run mode
        if (dryRunCallback) {
          // In dry run mode, the callback has already been called above
          // Add comprehensive dry run logging
          if (forceDebug) {
            const matchType = [];
            if (hasWhois && whoisMatched) matchType.push('whois-and');
            if (hasWhoisOr && whoisOrMatched) matchType.push('whois-or');
            if (hasDig && digMatched) matchType.push(digSubdomain ? 'dig-and-subdomain' : 'dig-and');
            if (hasDigOr && digOrMatched) matchType.push(digSubdomain ? 'dig-or-subdomain' : 'dig-or');
            logToConsoleAndFile(`${messageColors.highlight('[nettools-dryrun]')} ${domain} would match via ${matchType.join(' + ')}`);
          }

          // Show what adblock rule would be generated
          if (forceDebug) {
            const adblockRule = `||${domain}^`;
            logToConsoleAndFile(`${messageColors.highlight('[nettools-dryrun]')} Would generate adblock rule: ${adblockRule}`);
          }
          // No need to add to matched domains
        } else {
          // Re-check ignoreDomains right before adding — the async whois/dig
          // window may have classified this domain as ignored since the
          // request-time gate ran. Mirrors curl.js/grep.js/searchstring.js.
          if (typeof matchesIgnoreDomain === 'function' && matchesIgnoreDomain(domain, ignoreDomains)) {
            if (forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Skipping ${domain}: now in ignoreDomains (post-whois/dig)`);
            }
          } else if (typeof addMatchedDomain === 'function') {
            addMatchedDomain(domain, null, fullSubdomain);
          } else {
            matchedDomains.add(domain);
          }
        }
        
        const simplifiedUrl = config.currentUrl ? getRootDomain(config.currentUrl) : 'unknown';
        
        if (siteConfig.verbose === 1) {
          const matchType = [];
          if (hasWhois && whoisMatched) matchType.push('whois-and');
          if (hasWhoisOr && whoisOrMatched) matchType.push('whois-or');
          if (hasDig && digMatched) matchType.push(digSubdomain ? 'dig-and-subdomain' : 'dig-and');
          if (hasDigOr && digOrMatched) matchType.push(digSubdomain ? 'dig-or-subdomain' : 'dig-or');
          logToConsoleAndFile(`[${simplifiedUrl}] ${domain} matched via ${matchType.join(' + ')}`);
        }
        
        if (dumpUrls && matchedUrlsLogFile && fs) {
          const timestamp = new Date().toISOString();
          const matchType = [];
          if (hasWhois && whoisMatched) matchType.push('whois-and');
          if (hasWhoisOr && whoisOrMatched) matchType.push('whois-or');
          if (hasDig && digMatched) matchType.push(digSubdomain ? 'dig-and-subdomain' : 'dig-and');
          if (hasDigOr && digOrMatched) matchType.push(digSubdomain ? 'dig-or-subdomain' : 'dig-or');
          
          // Add whois server info to log if custom server was used
          const serverInfo = whoisServer ? ` (whois-server: ${selectWhoisServer(whoisServer)})` : '';
          fs.appendFileSync(matchedUrlsLogFile, `${timestamp} [match][${simplifiedUrl}] ${domain} (${matchType.join(' + ')})${serverInfo}\n`);
        }
      }
      
    } catch (timeoutError) {
      if (timeoutError.message.includes('NetTools overall timeout')) {
        if (forceDebug) {
          logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Overall timeout for domain ${domain}: ${timeoutError.message}`);
        }
        return;
      }
      if (forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Error processing ${domain}: ${timeoutError.message}`);
      }
   }
      

   } // End of executeNetToolsLookup function
  };
}

// Public surface kept narrow on purpose -- only what nwss.js actually
// imports (verified via repo-wide grep). Internal helpers
// (whoisLookup, whoisLookupWithRetry, digLookup, checkWhoisTerms,
// checkWhoisTermsOr, checkDigTerms, checkDigTermsOr, selectWhoisServer,
// getCommonWhoisServers, suggestWhoisServers, execFileWithTimeout,
// markResolved, digOutputIndicatesResolution, loadDiskCache,
// saveDiskCache, enforceCacheCap, stripAnsiColors) stay as module-local
// functions -- move back to module.exports only if a new external
// consumer appears. The dropped `execWithTimeout` was also the
// "// Export for testing" entry; there's no test suite, so the export
// was load-bearing for nothing.
module.exports = {
  createNetToolsHandler,
  createEnhancedDryRunCallback,
  validateWhoisAvailability,
  validateDigAvailability,
  enableDiskCache,
  getDnsCacheStats,
  // Resolved-hostnames index for the DNS pre-check optimization.
  // nwss.js's per-task pre-check consults this BEFORE calling resolve4
  // so hosts already proven live by dig or whois (within their 20h
  // cache TTL) skip the c-ares call entirely.
  domainKnownToResolve
};