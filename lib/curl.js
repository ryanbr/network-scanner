// === curl.js - Curl-based Content Download Module ===
// Handles HTTP content downloading using curl for searchstring analysis

const fs = require('fs');
// spawn (async) for downloadWithCurl — see comments in that function.
// spawnSync only kept for validateCurlAvailability (runs once at startup).
const { spawn, spawnSync } = require('child_process');
const { messageColors, formatLogMessage } = require('./colorize');
const { getReferrerForUrl } = require('./referrer');
const CURL_TAG = messageColors.processing('[curl]');

// === Constants ===
const CURL_DEFAULTS = {
  TIMEOUT_SECONDS: 30,
  MAX_REDIRECTS: 5,
  // 50MB to match lib/searchstring.js's downloadWithCurl cap — the two
  // modules previously had different defaults (10MB vs 50MB) so the same
  // URL could succeed or fail depending on which code path fetched it.
  MAX_SIZE_BYTES: 50 * 1024 * 1024,
  VALIDATION_TIMEOUT: 5000,
  CURL_SUCCESS_STATUS: 0,
  VERSION_LINE_INDEX: 0
};

/**
 * Downloads content using curl with browser-like headers
 * @param {string} url - The URL to download
 * @param {string} userAgent - User agent string to use
 * @param {object} options - Download options
 * @returns {Promise<object>} Object with content, status, and metadata
 */
async function downloadWithCurl(url, userAgent = '', options = {}) {
  const {
    timeout = CURL_DEFAULTS.TIMEOUT_SECONDS,
    maxRedirects = CURL_DEFAULTS.MAX_REDIRECTS,
    maxSize = CURL_DEFAULTS.MAX_SIZE_BYTES,
    followRedirects = true,
    customHeaders = {}
  } = options;

  const errResult = (msg) => ({
    content: '', httpCode: 0, contentType: 'unknown', downloadSize: 0,
    success: false, error: msg
  });

  return new Promise((resolve) => {
    const curlArgs = [
      '-s',
      '--max-time', timeout.toString(),
      '--max-redirs', maxRedirects.toString(),
      '--fail-with-body',
      '--compressed',
      // Leading '\n' guarantees the metadata sits on its own line even
      // when content has no trailing newline. The old format had no
      // separator, so content like '<html>...</html>' (no trailing \n)
      // concatenated directly with metadata as '<html>...</html>200|text/html|12345'
      // and the split-on-pipe parse failed.
      '--write-out', '\n%{http_code}|%{content_type}|%{size_download}'
    ];

    if (followRedirects) curlArgs.push('-L');
    if (userAgent) curlArgs.push('-H', `User-Agent: ${userAgent}`);

    curlArgs.push(
      '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      '-H', 'Accept-Language: en-US,en;q=0.5',
      '-H', 'Accept-Encoding: gzip, deflate, br',
      '-H', 'Connection: keep-alive',
      '-H', 'Upgrade-Insecure-Requests: 1',
      '-H', 'Sec-Fetch-Dest: document',
      '-H', 'Sec-Fetch-Mode: navigate',
      '-H', 'Sec-Fetch-Site: none',
      '-H', 'Cache-Control: no-cache'
    );

    Object.entries(customHeaders).forEach(([key, value]) => {
      curlArgs.push('-H', `${key}: ${value}`);
    });
    curlArgs.push(url);

    // Use spawn (async) NOT spawnSync — the old spawnSync blocked the
    // entire Node event loop for up to `timeout` seconds. This is the
    // production curl path (createCurlHandler), so under concurrent
    // scans every download stalled every other Promise resolution in
    // the process. Wrapping spawnSync in `new Promise` does NOT make
    // it async; the work still runs to completion before the Promise
    // constructor returns.
    let child;
    try {
      child = spawn('curl', curlArgs);
    } catch (spawnErr) {
      resolve(errResult(spawnErr.message));
      return;
    }

    // Streamed collection with a hard cap on stdout so a misbehaving
    // server can't blow memory past maxSize. Buffers (not strings) so
    // we don't decode UTF-8 mid-multibyte during streaming.
    let stdoutBytes = 0;
    let truncated = false;
    const stdoutChunks = [];
    const stderrChunks = [];

    child.stdout.on('data', (chunk) => {
      if (truncated) return;
      if (stdoutBytes + chunk.length > maxSize) {
        truncated = true;
        try { child.kill('SIGTERM'); } catch (_) {}
        return;
      }
      stdoutBytes += chunk.length;
      stdoutChunks.push(chunk);
    });
    child.stderr.on('data', (chunk) => { stderrChunks.push(chunk); });

    // Belt-and-braces hard timeout — curl's --max-time is the primary
    // limit. This catches the rare case where curl itself hangs.
    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, (timeout + 5) * 1000);
    if (typeof killTimer.unref === 'function') killTimer.unref();

    child.on('error', (err) => {
      clearTimeout(killTimer);
      resolve(errResult(err.message));
    });

    child.on('close', (code, signal) => {
      clearTimeout(killTimer);
      if (truncated) { resolve(errResult(`Output exceeded ${maxSize} bytes`)); return; }
      if (signal) { resolve(errResult(`Killed by signal ${signal}`)); return; }
      if (code !== CURL_DEFAULTS.CURL_SUCCESS_STATUS) {
        const stderr = Buffer.concat(stderrChunks).toString('utf8');
        resolve(errResult(`Curl exited with status ${code}: ${stderr}`));
        return;
      }

      const output = Buffer.concat(stdoutChunks).toString('utf8');
      // lastIndexOf('\n') is a single O(n) scan from the end vs the old
      // split('\n') + slice(0,-1) + join('\n') which was three full
      // passes plus two allocations of arrays of all lines. For 50MB
      // content, an order-of-magnitude less work.
      const sepIdx = output.lastIndexOf('\n');
      if (sepIdx === -1) { resolve(errResult('No metadata separator in curl output')); return; }

      const content = output.slice(0, sepIdx);
      const metadata = output.slice(sepIdx + 1);

      // Split on the FIRST and LAST pipe instead of a naive split('|').
      // The middle field is content-type, which can legitimately contain
      // pipes (rare but per RFC). Old split-on-pipe-then-count-parts
      // dropped the whole response with 'Invalid metadata format' if
      // content-type contained a pipe. Now we anchor on the outermost
      // pipes and let the middle be whatever's between them.
      const firstPipe = metadata.indexOf('|');
      const lastPipe = metadata.lastIndexOf('|');
      if (firstPipe === -1 || firstPipe === lastPipe) {
        resolve(errResult(`Invalid metadata format: missing pipes in "${metadata}"`));
        return;
      }
      const httpCode = metadata.slice(0, firstPipe);
      const contentType = metadata.slice(firstPipe + 1, lastPipe);
      const downloadSize = metadata.slice(lastPipe + 1);

      resolve({
        content,
        httpCode: parseInt(httpCode, 10) || 0,
        contentType: contentType || 'unknown',
        downloadSize: parseInt(downloadSize, 10) || content.length,
        success: true
      });
    });
  });
}

/**
 * Searches content for patterns using JavaScript (case-insensitive)
 * @param {string} content - Content to search
 * @param {Array<string>} searchStrings - OR patterns (any can match)
 * @param {Array<string>} searchStringsAnd - AND patterns (all must match)
 * @param {boolean} hasSearchStringAnd - Whether AND logic is being used
 * @returns {object} Search result with found status and matched pattern
 */
function searchContent(content, searchStrings = [], searchStringsAnd = [], hasSearchStringAnd = false) {
  if (!content || content.length === 0) {
    return { found: false, matchedPattern: null, matchType: null };
  }

  const lowerContent = content.toLowerCase();
  
  // Handle AND logic searchstring_and (all patterns must be present)
  if (hasSearchStringAnd && searchStringsAnd.length > 0) {
    const missingPatterns = [];
    const foundPatterns = [];
    
    for (const pattern of searchStringsAnd) {
      const lowerPattern = pattern.toLowerCase();
      if (lowerContent.includes(lowerPattern)) {
        foundPatterns.push(pattern);
      } else {
        missingPatterns.push(pattern);
      }
    }
    
    // All patterns must be found for AND logic
    if (missingPatterns.length === 0) {
      return { 
        found: true, 
        matchedPattern: foundPatterns.join(' AND '), 
        matchType: 'AND',
        foundPatterns,
        missingPatterns: []
      };
    } else {
      return { 
        found: false, 
        matchedPattern: null, 
        matchType: 'AND',
        foundPatterns,
        missingPatterns
      };
    }
  }
  
  // Handle OR logic searchstring (any pattern can match)
  if (searchStrings.length > 0) {
    for (const pattern of searchStrings) {
      const lowerPattern = pattern.toLowerCase();
      if (lowerContent.includes(lowerPattern)) {
        return { 
          found: true, 
          matchedPattern: pattern, 
          matchType: 'OR'
        };
      }
    }
  }
  
  return { found: false, matchedPattern: null, matchType: null };
}

/**
 * Creates a curl-based URL handler for downloading and searching content
 * @param {object} config - Configuration object containing all necessary parameters
 * @returns {Function} URL handler function for curl-based content analysis
 */
function createCurlHandler(config) {
  const {
    searchStrings,
    searchStringsAnd,
    hasSearchStringAnd,
    regexes,
    matchedDomains,
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
    hasSearchString
  } = config;

  // Hoisted: currentUrl doesn't change for this handler's lifetime, so
  // parsing its root domain once at handler-creation eliminates the
  // per-request parse + getRootDomain call.
  let currentRootDomain = '';
  try { currentRootDomain = getRootDomain(currentUrl); } catch (_) {}

  return async function curlHandler(requestUrl) {
    try {
      // Regex check FIRST — cheap filter that skips ~99% of requests.
      // Previously this ran AFTER a URL parse + domain-cache lookup,
      // paying for parses on requests we then immediately drop.
      const matchesRegex = regexes.some(re => re.test(requestUrl));
      if (!matchesRegex) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${CURL_TAG} URL ${requestUrl} doesn't match any regex patterns`));
        }
        return;
      }

      // Parse requestUrl ONCE and reuse. Was parsed 4-6 times: line 221
      // hostname, line 222 hostname, lines 242-243 dead-var hostnames,
      // plus getRootDomain calls. Removed the two dead hostname vars
      // (currentUrlHostname / requestHostname were computed and never
      // read) and reused the single parse for cache key + first-party.
      let requestHostname;
      try { requestHostname = new URL(requestUrl).hostname; } catch (_) { return; }
      const fullSubdomain = requestHostname; // always the full subdomain

      // Compute requestRootDomain ONCE — derive respDomain from it when
      // perSiteSubDomains is false, and reuse it for the first-party
      // check. Previously getRootDomain(requestUrl) was called twice in
      // that path.
      const requestRootDomain = getRootDomain(requestUrl);
      const respDomain = perSiteSubDomains ? requestHostname : requestRootDomain;

      // Skip if already detected to avoid duplicates
      if (isDomainAlreadyDetected(fullSubdomain)) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${CURL_TAG} Skipping already detected subdomain: ${fullSubdomain}`));
        }
        return;
      }

      // First-party = same registrable root domain. Same definition the
      // main request handler uses; matches what searchstring.js's
      // responseHandler does too (post the cross-module unification).
      const isFirstParty = currentRootDomain === requestRootDomain;

      // Apply first-party/third-party filtering
      if (isFirstParty && (siteConfig.firstParty === false || siteConfig.firstParty === 0)) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${CURL_TAG} Skipping first-party request (firstParty disabled): ${requestUrl}`));
        }
        return;
      }

      if (!isFirstParty && (siteConfig.thirdParty === false || siteConfig.thirdParty === 0)) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${CURL_TAG} Skipping third-party request (thirdParty disabled): ${requestUrl}`));
        }
        return;
      }

      if (forceDebug) {
        console.log(formatLogMessage('debug', `${CURL_TAG} Processing ${isFirstParty ? 'first-party' : 'third-party'} request: ${requestUrl}`));
      }

      // If NO searchstring is defined, match immediately (like browser
      // behavior). Simplified from the prior convoluted condition
      // (hasSearchString being true while both arrays are empty is
      // impossible given parseSearchStrings, so the OR was redundant).
      if (!hasSearchString && !hasSearchStringAnd) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${CURL_TAG} Domain ${respDomain} is in ignore list`));
          }
          return;
        }
        
        addMatchedDomain(respDomain, resourceType, fullSubdomain);
        const simplifiedUrl = currentRootDomain;
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const resourceInfo = resourceType ? ` (${resourceType})` : '';
          console.log(formatLogMessage('match', `[${simplifiedUrl}] ${requestUrl} (${partyType}, curl) matched regex${resourceInfo}`));
        }
        
        if (dumpUrls && matchedUrlsLogFile) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const resourceInfo = resourceType ? ` (${resourceType})` : '';
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${requestUrl} (${partyType}, curl)${resourceInfo}\n`);
          } catch (logErr) {
            console.warn(formatLogMessage('warn', `Failed to write to matched URLs log: ${logErr.message}`));
          }
        }
        return;
      }
      
      // If searchstring IS defined, download and search content
      if ((hasSearchString || hasSearchStringAnd) && forceDebug) {
        console.log(formatLogMessage('debug', `${CURL_TAG} Downloading content for pattern matching: ${requestUrl}`));
      }

      // Prepare custom headers from site config. SHALLOW-COPY so the
      // Referer assignment below doesn't mutate the underlying siteConfig
      // object — the old `siteConfig.custom_headers || {}` was a reference
      // (when present), so setting customHeaders['Referer'] persisted the
      // first URL's random-mode referrer onto siteConfig.custom_headers,
      // and every subsequent URL inherited that pinned value. Silent
      // breakage of {mode:'random_search'} variation across a site's URLs.
      //
      // Uses getReferrerForUrl so ALL referrer modes work — the old
      // inline string/array logic dropped object modes silently.
      const customHeaders = { ...(siteConfig.custom_headers || {}) };
      if (siteConfig.referrer_headers) {
        const referrerUrl = getReferrerForUrl(
          requestUrl,
          siteConfig.referrer_headers,
          siteConfig.referrer_disable,
          forceDebug
        );
        if (referrerUrl) customHeaders['Referer'] = referrerUrl;
      }
      
      const downloadResult = await downloadWithCurl(requestUrl, userAgent, {
        timeout: CURL_DEFAULTS.TIMEOUT_SECONDS,
        maxRedirects: CURL_DEFAULTS.MAX_REDIRECTS,
        customHeaders
      });
      
      if (!downloadResult.success) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${CURL_TAG} Failed to download ${requestUrl}: ${downloadResult.error}`));
        }
        return;
      }
      
      // Cache the fetched content if callback provided
      if (onContentFetched) {
        try {
          onContentFetched(requestUrl, downloadResult.content);
        } catch (cacheErr) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${CURL_TAG} Content caching failed: ${cacheErr.message}`));
          }
        }
      }
      
      // Search content for patterns
      const searchResult = searchContent(
        downloadResult.content, 
        searchStrings, 
        searchStringsAnd, 
        hasSearchStringAnd
      );
      
      if (searchResult.found) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${CURL_TAG} Domain ${respDomain} matches but is in ignore list`));
          }
          return;
        }
        
        addMatchedDomain(respDomain, resourceType, fullSubdomain);
        const simplifiedUrl = currentRootDomain;
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const resourceInfo = resourceType ? ` (${resourceType})` : '';
          const matchInfo = searchResult.matchType === 'AND' 
            ? `patterns: ${searchResult.foundPatterns.length}/${searchStringsAnd.length}`
            : `pattern: "${searchResult.matchedPattern}"`;
          console.log(formatLogMessage('match', 
            `[${simplifiedUrl}] ${requestUrl} (${partyType}, curl) contains ${matchInfo}${resourceInfo}`));
        }
        
        if (dumpUrls && matchedUrlsLogFile) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const resourceInfo = resourceType ? ` (${resourceType})` : '';
          const matchInfo = searchResult.matchType === 'AND' 
            ? `patterns: ${searchResult.foundPatterns.length}/${searchStringsAnd.length}`
            : `pattern: "${searchResult.matchedPattern}"`;
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${requestUrl} (${partyType}, curl, ${matchInfo})${resourceInfo}\n`);
          } catch (logErr) {
            console.warn(formatLogMessage('warn', `Failed to write to matched URLs log: ${logErr.message}`));
          }
        }
      } else {
        if (forceDebug) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          if (searchResult.matchType === 'AND' && searchResult.missingPatterns) {
            console.log(formatLogMessage('debug', 
              `${CURL_TAG} ${requestUrl} (${partyType}) matched regex but missing AND patterns: ${searchResult.missingPatterns.join(', ')}`));
          } else {
            console.log(formatLogMessage('debug', 
              `${CURL_TAG} ${requestUrl} (${partyType}) matched regex but no search patterns found`));
          }
        }
      }
      
    } catch (err) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${CURL_TAG} Handler failed for ${requestUrl}: ${err.message}`));
      }
    }
  };
}

/**
 * Validates that curl is available on the system
 * @returns {object} Validation result with isAvailable boolean and version info
 */
function validateCurlAvailability() {
  try {
    const result = spawnSync('curl', ['--version'], { 
      encoding: 'utf8',
      timeout: CURL_DEFAULTS.VALIDATION_TIMEOUT 
    });
    
    if (result.status === CURL_DEFAULTS.CURL_SUCCESS_STATUS) {
      const version = result.stdout.split('\n')[CURL_DEFAULTS.VERSION_LINE_INDEX] || 'Unknown version';
      return { 
        isAvailable: true, 
        version: version.trim(),
        error: null 
      };
    } else {
      return { 
        isAvailable: false, 
        version: null,
        error: 'curl command failed' 
      };
    }
  } catch (error) {
    return { 
      isAvailable: false, 
      version: null,
      error: `curl not found: ${error.message}` 
    };
  }
}

// Public surface used by nwss.js (createCurlHandler + validateCurlAvailability).
// downloadWithCurl and searchContent are module-internal helpers — no external
// caller imports them from here. lib/searchstring.js has its own independently-
// defined functions of the same names, which is why a naive grep showed
// false-positive 'external uses'.
module.exports = {
  createCurlHandler,
  validateCurlAvailability
};