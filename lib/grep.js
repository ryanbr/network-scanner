// === grep.js - Grep-based Content Search Module ===
// Alternative to searchstring.js using grep for pattern matching

const fs = require('fs');
// spawn for grepContent + downloadAndGrep (async — see comments in
// those functions). spawnSync only used for validateGrepAvailability
// (runs once at startup; blocking briefly is fine).
const { spawn, spawnSync } = require('child_process');
const { messageColors, formatLogMessage } = require('./colorize');
const GREP_TAG = messageColors.processing('[grep]');

// === Constants ===
const GREP_DEFAULTS = {
  TIMEOUT_SECONDS: 30,
  MAX_REDIRECTS: 5,
  // 50MB to match lib/curl.js and lib/searchstring.js — the three
  // download paths previously had two different caps (10MB here, 50MB
  // there) so the same URL could succeed via one path and fail via
  // another.
  MAX_SIZE_BYTES: 50 * 1024 * 1024,
  // Cap grep's stdout collection at the input size — output can in
  // theory exceed input (overlapping match contexts) but in practice
  // matching lines from 50MB of content max out around that. Replaces
  // the old 1MB MAX_BUFFER_SIZE that silently killed grep with ENOBUFS
  // on pages with many matching lines, making the pattern silently
  // report "not found" despite thousands of matches.
  MAX_GREP_OUTPUT_BYTES: 50 * 1024 * 1024,
  VALIDATION_TIMEOUT: 5000,
  GREP_TIMEOUT: 10000,
  DEFAULT_MAX_MATCHES: 1000,
  GREP_SUCCESS_STATUS: 0,
  GREP_NOT_FOUND_STATUS: 1,
  CURL_SUCCESS_STATUS: 0,
  VERSION_LINE_INDEX: 0
};

/**
 * Run a single grep pattern against `content`, returning the result
 * asynchronously. Uses spawn (NOT spawnSync) — same rationale as
 * downloadAndGrep — and handles stdout buffering ourselves so we can
 * accept output up to MAX_GREP_OUTPUT_BYTES instead of being capped
 * at spawnSync's `maxBuffer` (which silently killed grep with ENOBUFS
 * on pages with many matching lines).
 *
 * @param {string} content - Stdin content for grep
 * @param {string} pattern - The pattern to search for
 * @param {string[]} baseArgs - Pre-computed grep flags (-i, -F, etc.)
 * @returns {Promise<{status: number|null, stdout: string, truncated: boolean, signal: string|null, error?: string}>}
 */
function grepOne(content, pattern, baseArgs) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn('grep', [...baseArgs, pattern]);
    } catch (spawnErr) {
      resolve({ status: -1, stdout: '', truncated: false, signal: null, error: spawnErr.message });
      return;
    }

    const stdoutChunks = [];
    let stdoutBytes = 0;
    let truncated = false;

    child.stdout.on('data', (chunk) => {
      if (truncated) return;
      if (stdoutBytes + chunk.length > GREP_DEFAULTS.MAX_GREP_OUTPUT_BYTES) {
        truncated = true;
        try { child.kill('SIGTERM'); } catch (_) {}
        return;
      }
      stdoutBytes += chunk.length;
      stdoutChunks.push(chunk);
    });
    // Drain stderr but don't retain — the result object doesn't expose
    // it and accumulating chunks for the call lifetime was pure waste.
    // (Unconsumed streams pause data flow, so the listener must exist.)
    child.stderr.on('data', () => {});

    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, GREP_DEFAULTS.GREP_TIMEOUT + 5000);
    if (typeof killTimer.unref === 'function') killTimer.unref();

    child.on('error', (err) => {
      clearTimeout(killTimer);
      resolve({ status: -1, stdout: '', truncated, signal: null, error: err.message });
    });

    child.on('close', (code, signal) => {
      clearTimeout(killTimer);
      resolve({
        status: code,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        truncated,
        signal
      });
    });

    // Feed content via stdin. EPIPE if grep exits before we finish
    // writing (e.g. grep -m or early SIGTERM from truncation) — swallow
    // so it doesn't surface as an unhandled error on the stream.
    child.stdin.on('error', () => {});
    child.stdin.end(content);
  });
}

/**
 * Searches content using grep with the provided patterns.
 *
 * Async — runs one spawn per pattern (sequential, not concurrent, to
 * avoid spiking memory with N copies of `content` on grep's stdin
 * simultaneously). The previous spawnSync-per-pattern implementation
 * blocked the event loop for the duration of every grep call; the
 * outer downloadAndGrep's switch to async spawn was undone by this
 * sync inner step.
 *
 * @param {string} content - The content to search
 * @param {Array<string>} searchPatterns - Array of grep patterns to search for
 * @param {object} options - Grep options (ignoreCase, wholeWord, regex, maxMatches)
 * @returns {Promise<{found: boolean, matchedPattern: string|null, allMatches: Array<{pattern: string, matches: string[]}>}>}
 */
async function grepContent(content, searchPatterns, options = {}) {
  const {
    ignoreCase = true,
    wholeWord = false,
    regex = false,
    maxMatches = GREP_DEFAULTS.DEFAULT_MAX_MATCHES
  } = options;

  // Pre-filter empty/whitespace patterns at the top instead of doing
  // `if (!pattern || ...) continue` inside the loop. `typeof === 'string'`
  // guard rejects non-string entries (numbers, booleans, etc.) so we
  // don't trip TypeError on `p.trim()` for misconfigured input.
  const validPatterns = Array.isArray(searchPatterns)
    ? searchPatterns.filter(p => typeof p === 'string' && p.trim().length > 0)
    : [];

  if (!content || validPatterns.length === 0) {
    return { found: false, matchedPattern: null, allMatches: [] };
  }

  const baseArgs = ['--text', '--color=never'];
  if (ignoreCase) baseArgs.push('-i');
  if (wholeWord) baseArgs.push('-w');
  if (!regex) baseArgs.push('-F');

  const allMatches = [];
  let firstMatch = null;

  for (const pattern of validPatterns) {
    const result = await grepOne(content, pattern, baseArgs);
    if (result.error) {
      console.warn(formatLogMessage('warn', `${GREP_TAG} Pattern "${pattern}" failed: ${result.error}`));
      continue;
    }
    // Surface truncation so admins can see when grep output hit the
    // 50MB cap — previously this was silent (the SIGTERM-on-truncation
    // path looks the same as a normal exit to the caller).
    if (result.truncated) {
      console.warn(formatLogMessage('warn', `${GREP_TAG} Pattern "${pattern}" output truncated at ${GREP_DEFAULTS.MAX_GREP_OUTPUT_BYTES} bytes; results may be incomplete`));
    }
    // grep exit codes: 0 = found, 1 = not found, 2+ = error.
    // Also accept truncated output — we collected enough to slice to
    // maxMatches even though more existed beyond the cap.
    if (result.status === GREP_DEFAULTS.GREP_SUCCESS_STATUS && result.stdout) {
      const lines = result.stdout.split('\n').filter(line => line.trim().length > 0).slice(0, maxMatches);
      allMatches.push({ pattern, matches: lines });
      if (!firstMatch) firstMatch = pattern;
    }
  }

  return {
    found: allMatches.length > 0,
    matchedPattern: firstMatch,
    allMatches
  };
}

/**
 * Downloads content using curl and searches with grep
 * @param {string} url - The URL to download
 * @param {Array<string>} searchPatterns - Grep patterns to search for
 * @param {string} userAgent - User agent string to use
 * @param {object} grepOptions - Grep search options
 * @param {number} timeout - Timeout in seconds (default: 30)
 * @returns {Promise<object>} Object with found boolean, matchedPattern, and content
 */
function downloadAndGrep(url, searchPatterns, userAgent = '', grepOptions = {}, timeout = GREP_DEFAULTS.TIMEOUT_SECONDS) {
  // Returns a Promise. Uses spawn (async) NOT spawnSync — the old
  // spawnSync blocked the entire Node event loop for up to `timeout`
  // seconds, and under concurrent scans every other Promise resolution
  // stalled. Same fix pattern as lib/curl.js and lib/searchstring.js's
  // downloadWithCurl.
  return new Promise((resolve, reject) => {
    const curlArgs = [
      '-s',
      '-L',
      '--max-time', timeout.toString(),
      '--max-redirs', GREP_DEFAULTS.MAX_REDIRECTS.toString(),
      '--fail-with-body',
      '--compressed'
    ];
    if (userAgent) curlArgs.push('-H', `User-Agent: ${userAgent}`);
    curlArgs.push(
      '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      '-H', 'Accept-Language: en-US,en;q=0.5',
      '-H', 'Accept-Encoding: gzip, deflate',
      '-H', 'Connection: keep-alive',
      '-H', 'Upgrade-Insecure-Requests: 1'
    );
    curlArgs.push(url);

    let child;
    try {
      child = spawn('curl', curlArgs);
    } catch (spawnErr) {
      reject(new Error(`Download and grep failed for ${url}: ${spawnErr.message}`));
      return;
    }

    // Streamed collection with a hard cap on stdout so a misbehaving
    // server can't blow memory past MAX_SIZE_BYTES.
    let stdoutBytes = 0;
    let truncated = false;
    const stdoutChunks = [];
    const stderrChunks = [];

    child.stdout.on('data', (chunk) => {
      if (truncated) return;
      if (stdoutBytes + chunk.length > GREP_DEFAULTS.MAX_SIZE_BYTES) {
        truncated = true;
        try { child.kill('SIGTERM'); } catch (_) {}
        return;
      }
      stdoutBytes += chunk.length;
      stdoutChunks.push(chunk);
    });
    child.stderr.on('data', (chunk) => { stderrChunks.push(chunk); });

    // Belt-and-braces hard timeout — curl's --max-time is primary.
    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, (timeout + 5) * 1000);
    if (typeof killTimer.unref === 'function') killTimer.unref();

    child.on('error', (err) => {
      clearTimeout(killTimer);
      reject(new Error(`Download and grep failed for ${url}: ${err.message}`));
    });

    child.on('close', async (code, signal) => {
      clearTimeout(killTimer);
      if (truncated) { reject(new Error(`Output exceeded ${GREP_DEFAULTS.MAX_SIZE_BYTES} bytes for ${url}`)); return; }
      if (signal) { reject(new Error(`Curl killed by signal ${signal} for ${url}`)); return; }
      if (code !== GREP_DEFAULTS.CURL_SUCCESS_STATUS) {
        const stderr = Buffer.concat(stderrChunks).toString('utf8');
        reject(new Error(`Curl exited with status ${code}: ${stderr}`));
        return;
      }

      const content = Buffer.concat(stdoutChunks).toString('utf8');
      try {
        const grepResult = await grepContent(content, searchPatterns, grepOptions);
        resolve({
          found: grepResult.found,
          matchedPattern: grepResult.matchedPattern,
          allMatches: grepResult.allMatches,
          content,
          contentLength: content.length
        });
      } catch (grepErr) {
        reject(new Error(`Download and grep failed for ${url}: ${grepErr.message}`));
      }
    });
  });
}

/**
 * Creates a grep-based URL handler for downloading and searching content.
 *
 * @param {object} config
 * @param {string[]} config.searchStrings - OR-logic patterns (any match)
 * @param {string[]} config.searchStringsAnd - AND-logic patterns (all must match)
 * @param {boolean} config.hasSearchString - True if searchStrings is non-empty
 * @param {boolean} config.hasSearchStringAnd - True if searchStringsAnd is non-empty;
 *   when true, AND-logic is applied to the combined grep result
 * @param {RegExp[]} config.regexes - URL regex patterns for the first-pass filter
 * @param {Function} config.addMatchedDomain - Sink for matched domains
 * @param {Function} config.isDomainAlreadyDetected - Skip-if-true predicate
 * @param {Function} [config.onContentFetched] - Optional cache hook
 * @param {string} config.currentUrl - The page URL being scanned
 * @param {boolean} config.perSiteSubDomains - Track at subdomain granularity
 * @param {string[]} config.ignoreDomains - Domain ignore list
 * @param {Function} config.matchesIgnoreDomain - Ignore-list matcher
 * @param {Function} config.getRootDomain - URL → registrable root domain
 * @param {object} config.siteConfig - Per-site config (verbose, firstParty, thirdParty)
 * @param {boolean} config.dumpUrls - Write matched URLs to file
 * @param {string} config.matchedUrlsLogFile - Path for dumpUrls output
 * @param {boolean} config.forceDebug
 * @param {string} config.userAgent - Curl user agent
 * @param {string|null} config.resourceType - Resource type for adblock-rules mode
 * @param {object} [config.grepOptions] - Passed through to grepContent
 *   (ignoreCase, wholeWord, regex, maxMatches)
 * @returns {Function} URL handler: async (requestUrl) => void
 */
function createGrepHandler(config) {
  const {
    searchStrings,
    searchStringsAnd,
    regexes,
    addMatchedDomain,
    isDomainAlreadyDetected,
    onContentFetched,
    currentUrl,
    perSiteSubDomains,
    ignoreDomains,
    matchesIgnoreDomain,
    getRootDomain,
    siteConfig,
    dumpUrls,
    matchedUrlsLogFile,
    forceDebug,
    userAgent,
    resourceType,
    hasSearchString,
    hasSearchStringAnd,
    grepOptions = {}
  } = config;

  // Hoisted: currentUrl doesn't change for this handler's lifetime.
  // Previously parsed on every single request.
  let currentRootDomain = '';
  let currentUrlHostname = '';
  try { currentRootDomain = getRootDomain(currentUrl); } catch (_) {}
  try { currentUrlHostname = new URL(currentUrl).hostname; } catch (_) {}

  return async function grepHandler(requestUrl) {
    // Regex check FIRST — cheap filter that skips ~99% of requests.
    // Previously this ran AFTER URL parses and a domain-cache lookup,
    // paying for parses on requests we then immediately drop.
    const matchesRegex = regexes.some(re => re.test(requestUrl));
    if (!matchesRegex) return;

    // Parse requestUrl ONCE and reuse. Was parsed 4 times previously
    // (two hostname parses + two for currentUrlHostname/requestHostname).
    let requestHostname;
    try { requestHostname = new URL(requestUrl).hostname; } catch (_) { return; }
    const fullSubdomain = requestHostname;
    const respDomain = perSiteSubDomains ? requestHostname : getRootDomain(requestUrl);

    if (isDomainAlreadyDetected(fullSubdomain)) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${GREP_TAG} Skipping already detected subdomain: ${fullSubdomain}`));
      }
      return;
    }

    const isFirstParty = currentUrlHostname === requestHostname;

    if (isFirstParty && siteConfig.firstParty === false) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${GREP_TAG} Skipping first-party request (firstParty=false): ${requestUrl}`));
      }
      return;
    }
    if (!isFirstParty && siteConfig.thirdParty === false) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${GREP_TAG} Skipping third-party request (thirdParty=false): ${requestUrl}`));
      }
      return;
    }

    try {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${GREP_TAG} Downloading and searching content from: ${requestUrl}`));
      }

      // No searchstring at all → match immediately on regex alone.
      if (!hasSearchString && !hasSearchStringAnd) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) return;
        addMatchedDomain(respDomain, resourceType, fullSubdomain);

        const partyType = isFirstParty ? 'first-party' : 'third-party';
        if (siteConfig.verbose === 1) {
          console.log(formatLogMessage('match', `[${currentRootDomain}] ${requestUrl} (${partyType}, grep) matched regex`));
        }
        if (dumpUrls && matchedUrlsLogFile) {
          const timestamp = new Date().toISOString();
          try {
            fs.appendFileSync(matchedUrlsLogFile,
              `${timestamp} [match][${currentRootDomain}] ${requestUrl} (${partyType}, grep)\n`);
          } catch (logErr) {
            console.warn(formatLogMessage('warn', `Failed to write to matched URLs log: ${logErr.message}`));
          }
        }
        return;
      }

      // Combine OR + AND patterns into one grep pass. The AND-logic
      // check below uses per-pattern attribution from
      // grepContent.allMatches. Previously createGrepHandler only
      // destructured `searchStrings` and ignored `searchStringsAnd`
      // entirely — users configuring AND-only patterns with grep mode
      // got silent zero matches.
      const allPatterns = [
        ...(searchStrings || []),
        ...(searchStringsAnd || [])
      ];
      const result = await downloadAndGrep(requestUrl, allPatterns, userAgent, grepOptions, GREP_DEFAULTS.TIMEOUT_SECONDS);

      if (onContentFetched && result.content) {
        try {
          onContentFetched(requestUrl, result.content);
        } catch (cacheErr) {
          if (forceDebug) console.log(formatLogMessage('debug', `${GREP_TAG} Content caching failed: ${cacheErr.message}`));
        }
      }

      // Apply OR vs AND logic. AND requires every searchStringsAnd
      // pattern to appear in grepResult.allMatches; OR just needs
      // anything found.
      let matched = false;
      let matchDescription = null;

      if (hasSearchStringAnd && searchStringsAnd && searchStringsAnd.length > 0) {
        const foundPatterns = new Set(result.allMatches.map(m => m.pattern));
        if (searchStringsAnd.every(p => foundPatterns.has(p))) {
          matched = true;
          matchDescription = `patterns: ${searchStringsAnd.length}/${searchStringsAnd.length} (AND)`;
        }
      } else if (result.found) {
        matched = true;
        matchDescription = `pattern: "${result.matchedPattern}"`;
      }

      if (matched) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) return;
        addMatchedDomain(respDomain, resourceType, fullSubdomain);

        const partyType = isFirstParty ? 'first-party' : 'third-party';
        const matchCount = result.allMatches.reduce((sum, m) => sum + m.matches.length, 0);

        if (siteConfig.verbose === 1) {
          console.log(formatLogMessage('match', `[${currentRootDomain}] ${requestUrl} (${partyType}, grep) contains ${matchDescription} (${matchCount} matches)`));
        }
        if (dumpUrls && matchedUrlsLogFile) {
          const timestamp = new Date().toISOString();
          try {
            fs.appendFileSync(matchedUrlsLogFile,
              `${timestamp} [match][${currentRootDomain}] ${requestUrl} (${partyType}, grep, ${matchDescription}, matches: ${matchCount})\n`);
          } catch (logErr) {
            console.warn(formatLogMessage('warn', `Failed to write to matched URLs log: ${logErr.message}`));
          }
        }
      } else if (forceDebug) {
        const partyType = isFirstParty ? 'first-party' : 'third-party';
        console.log(formatLogMessage('debug', `${GREP_TAG} ${requestUrl} (${partyType}) matched regex but no patterns found`));
      }

    } catch (err) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${GREP_TAG} Failed to download/grep content for ${requestUrl}: ${err.message}`));
      }
    }
  };
}

/**
 * Validates that grep is available on the system
 * @returns {object} Validation result with isAvailable boolean and version info
 */
function validateGrepAvailability() {
  try {
    const result = spawnSync('grep', ['--version'], { 
      encoding: 'utf8',
      timeout: GREP_DEFAULTS.VALIDATION_TIMEOUT 
    });
    
    if (result.status === GREP_DEFAULTS.GREP_SUCCESS_STATUS) {
      const version = result.stdout.split('\n')[GREP_DEFAULTS.VERSION_LINE_INDEX] || 'Unknown version';
      return { 
        isAvailable: true, 
        version: version.trim(),
        error: null 
      };
    } else {
      return { 
        isAvailable: false, 
        version: null,
        error: 'grep command failed' 
      };
    }
  } catch (error) {
    return { 
      isAvailable: false, 
      version: null,
      error: `grep not found: ${error.message}` 
    };
  }
}

// Public surface. downloadAndGrep is module-internal (only called by
// createGrepHandler) — was exported but no external caller imported it.
module.exports = {
  grepContent,
  createGrepHandler,
  validateGrepAvailability
};