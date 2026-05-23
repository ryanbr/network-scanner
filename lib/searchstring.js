// === searchstring.js - Content Search Module ===
// Handles response content analysis for searchstring functionality

const fs = require('fs');
const { formatLogMessage, messageColors } = require('./colorize');
const CURL_TAG = messageColors.processing('[curl]');
// responseHandler is a separate code path (Puppeteer response listener,
// not curl) — its debug output gets its own subsystem prefix so it's
// distinguishable from curl-handler logs.
const SEARCHSTRING_TAG = messageColors.processing('[searchstring]');
const { runProcess } = require('./spawn-async');
const { grepContent } = require('./grep');

// Configuration constants for search logic
const SEARCH_CONFIG = {
  MAX_CONTENT_SIZE: 50 * 1024 * 1024, // 50MB max content size
  MAX_SEARCH_STRING_LENGTH: 1000
};

/**
 * Parses searchstring configuration into a normalized format
 * @param {string|Array<string>|undefined} searchstring - The searchstring config value (OR logic)
 * @param {string|Array<string>|undefined} searchstringAnd - The searchstring_and config value (AND logic)
 * @returns {object} Object with searchStrings array, searchStringsAnd array, hasSearchString boolean, and hasSearchStringAnd boolean
 */
function parseSearchStrings(searchstring, searchstringAnd) {
  let searchStrings = Array.isArray(searchstring)
    ? searchstring
    : searchstring
      ? [searchstring]
      : [];
  
  let searchStringsAnd = Array.isArray(searchstringAnd)
    ? searchstringAnd
    : searchstringAnd
      ? [searchstringAnd]
      : [];
  
  // Filter out empty strings to prevent matching everything
  searchStrings = searchStrings.filter(str => str && str.trim().length > 0);
  searchStringsAnd = searchStringsAnd.filter(str => str && str.trim().length > 0);
  
  const hasSearchString = searchStrings.length > 0;
  const hasSearchStringAnd = searchStringsAnd.length > 0;
  
  return { 
    searchStrings, 
    searchStringsAnd, 
    hasSearchString, 
    hasSearchStringAnd 
  };
}

/**
 * Downloads content using curl with appropriate headers and timeout
 * @param {string} url - The URL to download
 * @param {string} userAgent - User agent string to use
 * @param {number} timeout - Timeout in seconds (default: 30)
 * @returns {Promise<string>} The downloaded content
 */
async function downloadWithCurl(url, userAgent = '', timeout = 30) {
  const MAX_STDOUT_BYTES = 52428800; // 50MB, matches --max-filesize below

  const curlArgs = [
    '-s',
    '-L',
    '--max-time', timeout.toString(),
    '--max-redirs', '5',
    '--fail-with-body',
    '--max-filesize', '52428800',
    '--range', '0-52428799',
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

  // Shared async-spawn helper — same streaming/cap/timeout/kill plumbing
  // that used to be ~80 lines of inline boilerplate here.
  const result = await runProcess('curl', curlArgs, {
    timeout: timeout * 1000,
    maxStdout: MAX_STDOUT_BYTES
  });

  if (result.error) throw new Error(`Curl failed for ${url}: ${result.error}`);
  if (result.truncated) throw new Error(`Curl output exceeded ${MAX_STDOUT_BYTES} bytes for ${url}`);
  if (result.signal) throw new Error(`Curl killed by signal ${result.signal} for ${url}`);
  if (result.code !== 0) {
    throw new Error(`Curl exited with status ${result.code}: ${result.stderr.toString('utf8')}`);
  }
  return result.stdout.toString('utf8');
}

/**
 * Downloads content with retry logic for transient failures
 * @param {string} url - The URL to download
 * @param {string} userAgent - User agent string to use
 * @param {number} timeout - Timeout in seconds
 * @param {number} retries - Number of retry attempts (default: 2)
 * @returns {Promise<string>} The downloaded content
 */
async function downloadWithRetry(url, userAgent = '', timeout = 30, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await downloadWithCurl(url, userAgent, timeout);
    } catch (err) {
      // Don't retry on final attempt
      if (attempt === retries) throw err;
      
      // Only retry on specific transient errors
      const shouldRetry = err.message.includes('timeout') || 
                         err.message.includes('Connection refused') ||
                         err.message.includes('502') || 
                         err.message.includes('503') ||
                         err.message.includes('Connection reset');
      
      if (!shouldRetry) throw err;
      
      // Exponential backoff: 1s, 2s, 4s...
      await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, attempt)));
    }
  }
}

// Lookup table for the 6 named entities the previous chained-replace
// handled. Hoisted out of safeDecodeXmlEntities so the object isn't
// reallocated per call.
const NAMED_ENTITIES = Object.freeze({
  '&lt;': '<', '&gt;': '>', '&amp;': '&',
  '&quot;': '"', '&apos;': "'", '&#39;': "'"
});

/**
 * Safely decodes XML entities (named + numeric decimal + numeric hex)
 * in a SINGLE regex pass. The old implementation chained 8 separate
 * .replace() calls, each allocating a full intermediate string — for
 * 50MB content that was ~8 × 50MB ≈ 400MB of throwaway allocations per
 * XML response. Also drops the previous "timeout" check, which only
 * fired between regex passes (not during them) so it never actually
 * bounded runtime on pathological input.
 * @param {string} content - Content to decode
 * @returns {string} Decoded content or original if processing fails
 */
function safeDecodeXmlEntities(content) {
  try {
    return content.replace(
      /&lt;|&gt;|&amp;|&quot;|&apos;|&#39;|&#\d+;|&#x[0-9a-fA-F]+;/g,
      (match) => {
        // Named entity — exact match in the lookup table.
        const named = NAMED_ENTITIES[match];
        if (named) return named;
        // Numeric entity — &#xNN; (hex) or &#NN; (decimal).
        const isHex = match[2] === 'x' || match[2] === 'X';
        const numStr = isHex ? match.slice(3, -1) : match.slice(2, -1);
        const num = parseInt(numStr, isHex ? 16 : 10);
        // String.fromCodePoint (NOT fromCharCode) — fromCharCode truncates
        // to 16 bits, so &#128512; (😀, codepoint 0x1F600) would decode to
        // '' (a single garbage BMP char) instead of the emoji.
        // fromCodePoint handles the full Unicode range up to 0x10FFFF.
        if (num >= 0 && num <= 0x10FFFF) return String.fromCodePoint(num);
        return match; // out-of-range — keep original
      }
    );
  } catch (xmlErr) {
    console.warn(formatLogMessage('warn', `XML entity decoding failed: ${xmlErr.message}`));
    return content;
  }
}

/**
 * Safely strips XML/HTML tags with size limits
 * @param {string} content - Content to strip tags from
 * @returns {string} Content with tags removed
 */
function safeStripTags(content) {
  try {
    // No content-size cap here — searchContent already truncated to
    // MAX_CONTENT_SIZE before calling, so the previous cap was a no-op.
    // Replace tags with spaces to preserve word boundaries.
    return content.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
  } catch (stripErr) {
    console.warn(formatLogMessage('warn', `Tag stripping failed: ${stripErr.message}`));
    return content;
  }
}

/**
 * Checks if response content contains any of the search strings (OR logic)
 * or all of the AND search strings (AND logic)
 * Handles both raw text search and basic XML content extraction
 * @param {string} content - The response content to search
 * @param {Array<string>} searchStrings - Array of strings to search for (OR logic)
 * @param {Array<string>} searchStringsAnd - Array of strings that must all be present (AND logic)
 * @param {string} contentType - Content type for specialized handling
 * @param {string} url - URL for debugging context (optional)
 * @returns {{found: boolean, matchedString: string|null, logicType: 'AND'|'OR'|'NONE', error?: string}}
 */
function searchContent(content, searchStrings, searchStringsAnd = [], contentType = '', url = '') {
  // Input validation. Return shape carries only what callers actually
  // destructure ({found, matchedString, logicType, error}); the old
  // matchedStrings/allMatches/contentSize/searchableSize/processedAsXml
  // fields were computed and returned but never read by any caller.
  if (!content || typeof content !== 'string') {
    return { found: false, matchedString: null, logicType: 'NONE', error: 'Invalid or empty content' };
  }
  
  // Validate search strings FIRST — before paying for content truncation,
  // XML entity decoding, tag stripping, and 3× lowercase. Previously these
  // ran first, so a config with zero valid search strings still burned
  // ~150MB of allocations on a 50MB XML response before returning empty.
  const validSearchStrings = searchStrings.filter(str =>
    str && typeof str === 'string' && str.length > 0 && str.length <= SEARCH_CONFIG.MAX_SEARCH_STRING_LENGTH
  );
  const validSearchStringsAnd = searchStringsAnd.filter(str =>
    str && typeof str === 'string' && str.length > 0 && str.length <= SEARCH_CONFIG.MAX_SEARCH_STRING_LENGTH
  );

  if (validSearchStrings.length !== searchStrings.length) {
    console.warn(formatLogMessage('warn', `Filtered ${searchStrings.length - validSearchStrings.length} invalid search strings`));
  }
  if (validSearchStringsAnd.length !== searchStringsAnd.length) {
    console.warn(formatLogMessage('warn', `Filtered ${searchStringsAnd.length - validSearchStringsAnd.length} invalid AND search strings`));
  }

  if (validSearchStrings.length === 0 && validSearchStringsAnd.length === 0) {
    return { found: false, matchedString: null, logicType: 'NONE', error: 'No valid search strings provided' };
  }

  // Size check and truncation with warning
  const originalLength = content.length;
  if (originalLength > SEARCH_CONFIG.MAX_CONTENT_SIZE) {
    content = content.substring(0, SEARCH_CONFIG.MAX_CONTENT_SIZE);
    console.warn(formatLogMessage('warn', `Content truncated from ${originalLength} to ${SEARCH_CONFIG.MAX_CONTENT_SIZE} chars for ${url || 'unknown URL'}`));
  }

  // For XML/HTML we search across three views — original, entity-decoded,
  // tag-stripped — so encoded strings ("&amp;") and DOM-text strings
  // ("body text") and raw-source strings (attribute values) all match.
  //
  // The previous implementation joined all three into a single 3× string
  // then .toLowerCase()'d it. For a 50MB response that allocated a 150MB
  // intermediate plus a 150MB lowercase copy. Now we lowercase each
  // version independently and probe with `versionsIncludes()` — same
  // matching semantics (a string found in ANY version still counts) but
  // ~half the peak memory.
  const ct = contentType.toLowerCase();
  const isXmlContent = ct.includes('xml') || ct.includes('html');

  let lowerVersions;
  if (isXmlContent) {
    try {
      const decodedContent = safeDecodeXmlEntities(content);
      const strippedContent = safeStripTags(decodedContent);
      lowerVersions = [
        content.toLowerCase(),
        decodedContent.toLowerCase(),
        strippedContent.toLowerCase()
      ];
    } catch (xmlProcessingErr) {
      console.warn(formatLogMessage('warn', `XML processing failed for ${url || 'unknown URL'}: ${xmlProcessingErr.message}`));
      lowerVersions = [content.toLowerCase()];
    }
  } else {
    lowerVersions = [content.toLowerCase()];
  }

  const versionsIncludes = (needleLower) => {
    for (let i = 0; i < lowerVersions.length; i++) {
      if (lowerVersions[i].includes(needleLower)) return true;
    }
    return false;
  };
  
  // Check AND logic first (more restrictive) — ALL strings must be present
  // in at least one of the searchable versions. Loop exits early on first
  // NOT-found.
  if (validSearchStringsAnd.length > 0) {
    let allFound = true;
    for (const searchStr of validSearchStringsAnd) {
      if (!versionsIncludes(searchStr.toLowerCase())) {
        allFound = false;
        break;
      }
    }
    if (allFound) {
      return { found: true, matchedString: validSearchStringsAnd.join(' AND '), logicType: 'AND' };
    }
  }

  // OR logic: ANY string can match. Early-exit on first hit since the
  // caller only reads matchedString (the first match). Previously the
  // loop ran to completion to fill an `allMatches` array no caller read.
  for (const searchStr of validSearchStrings) {
    if (versionsIncludes(searchStr.toLowerCase())) {
      return { found: true, matchedString: searchStr, logicType: 'OR' };
    }
  }

  return { found: false, matchedString: null, logicType: validSearchStrings.length > 0 ? 'OR' : 'NONE' };
}

/**
 * Determines if a content type should be analyzed for search strings
 * @param {string} contentType - The response content-type header
 * @returns {boolean} True if content should be analyzed
 */
function shouldAnalyzeContentType(contentType) {
  if (!contentType) return false;

  // Normalize content type (remove charset and other parameters)
  const normalizedType = contentType.toLowerCase().split(';')[0].trim();
  
  const textTypes = [
    'text/',                    // text/html, text/plain, text/xml, etc.
    'application/json',
    'application/javascript',
    'application/xml',          // Standard XML
    'application/x-javascript',
    'application/soap+xml',     // SOAP XML
    'application/rss+xml',      // RSS feeds
    'application/atom+xml',     // Atom feeds
    'application/xhtml+xml',    // XHTML
    'application/ld+json',      // JSON-LD structured data
    'application/manifest+json', // Web App Manifest
    'application/feed+xml',     // Generic XML feeds
    'application/vnd.api+json', // JSON API specification
    'application/hal+json',     // HAL (Hypertext Application Language)
    'application/problem+json'  // Problem Details for HTTP APIs
  ];
  
  return textTypes.some(type => normalizedType.startsWith(type));
}

/**
 * Creates a curl-based URL handler for downloading and optionally searching content
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
    addMatchedDomain, // Helper function for adding domains
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
    resourceType, // Resource type from request
    hasSearchString
  } = config;

  // Hoisted: currentUrl doesn't change for this handler's lifetime, so
  // parsing its hostname once at handler-creation eliminates the
  // per-request URL allocation.
  let currentUrlHostname = '';
  try { currentUrlHostname = new URL(currentUrl).hostname; } catch (_) {}

  return async function curlHandler(requestUrl) {
    // Regex check FIRST — cheap filter that skips ~99% of requests.
    // Previously this ran AFTER a URL parse + domain-cache lookup;
    // the parse is the expensive bit, so doing it after the cheap
    // gate moves the cost off the hot path.
    const matchesRegex = regexes.some(re => re.test(requestUrl));
    if (!matchesRegex) return;

    // Parse requestUrl ONCE and reuse. Was parsed 2-3 times.
    let requestHostname;
    try { requestHostname = new URL(requestUrl).hostname; } catch (_) { return; }
    const reqDomain = perSiteSubDomains ? requestHostname : getRootDomain(requestUrl);

    if (typeof config.isDomainAlreadyDetected === 'function' && config.isDomainAlreadyDetected(reqDomain)) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${CURL_TAG} Skipping already detected domain: ${reqDomain}`));
      }
      return;
    }

    const isFirstParty = currentUrlHostname === requestHostname;
    
    // Apply first-party/third-party filtering
    if (isFirstParty && siteConfig.firstParty === false) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${CURL_TAG} Skipping first-party request (firstParty=false): ${requestUrl}`));
      }
      return;
    }
    
    if (!isFirstParty && siteConfig.thirdParty === false) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${CURL_TAG} Skipping third-party request (thirdParty=false): ${requestUrl}`));
      }
      return;
    }
    
    try {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${CURL_TAG} Downloading content from: ${requestUrl}`));
      }
      
      // If NO searchstring is defined, match immediately (like browser behavior)
      if (!hasSearchString && !hasSearchStringAnd) {
        if (!reqDomain || matchesIgnoreDomain(reqDomain, ignoreDomains)) {
          return;
        }
        
        addMatchedDomain(reqDomain, resourceType);
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const resourceInfo = resourceType ? ` (${resourceType})` : '';
          console.log(`[match][${simplifiedUrl}] ${requestUrl} (${partyType}, curl) matched regex${resourceInfo}`);
        }
        
        if (dumpUrls) {
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
      const content = await downloadWithRetry(requestUrl, userAgent, 30);
      
      // Check if content contains search strings (OR or AND logic)
      const { found, matchedString, logicType, error } = searchContent(content, searchStrings, searchStringsAnd, '', requestUrl);
      
      if (found) {
        if (!reqDomain || matchesIgnoreDomain(reqDomain, ignoreDomains)) {
          return;
        }
        
        addMatchedDomain(reqDomain, resourceType);
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const resourceInfo = resourceType ? ` (${resourceType})` : '';
          console.log(`[match][${simplifiedUrl}] ${requestUrl} (${partyType}, curl) contains searchstring (${logicType}): "${matchedString}"${resourceInfo}`);
        }
        
        if (dumpUrls) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const resourceInfo = resourceType ? ` (${resourceType})` : '';
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${requestUrl} (${partyType}, curl, searchstring (${logicType}): "${matchedString}")${resourceInfo}\n`);
          } catch (logErr) {
            console.warn(formatLogMessage('warn', `Failed to write to matched URLs log: ${logErr.message}`));
          }
        }
      } else if (forceDebug) {
        const partyType = isFirstParty ? 'first-party' : 'third-party';
        console.log(formatLogMessage('debug', `${CURL_TAG} ${requestUrl} (${partyType}) matched regex but no searchstring found`));
        if (error) {
          console.log(formatLogMessage('debug', `${CURL_TAG} Search error: ${error}`));
        }
      }
      
    } catch (err) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${CURL_TAG} Failed to download content for ${requestUrl}: ${err.message}`));
      }
    }
  };
}

/**
 * Creates a response handler function for the given configuration
 * @param {object} config - Configuration object containing all necessary parameters
 * @returns {Function} Response handler function for page.on('response', handler)
 */
function createResponseHandler(config) {
  const {
    searchStrings,
    searchStringsAnd,
    hasSearchStringAnd,
    regexes,
    matchedDomains,
    addMatchedDomain, // Helper function for adding domains
    currentUrl,
    perSiteSubDomains,
    ignoreDomains,
    matchesIgnoreDomain,
    getRootDomain,
    siteConfig,
    dumpUrls,
    matchedUrlsLogFile,
    useGrep = false,
    forceDebug,
    resourceType // Will be null for response handler
  } = config;

  // Hoisted: currentUrl doesn't change for this handler's lifetime.
  // Root domain (not bare hostname) so first-party matches the definition
  // used by nwss.js's main request handler AND lib/curl.js — previously
  // this module used hostname equality, so cdn.example.com and
  // static.example.com were classified third-party here but first-party
  // by the main handler. Unified to the registrable-root rule.
  let currentRootDomain = '';
  try { currentRootDomain = getRootDomain(currentUrl); } catch (_) {}

  return async function responseHandler(response) {
    const respUrl = response.url();

    // Regex check FIRST — cheapest filter, eliminates ~99% of responses
    // before paying for URL parses + domain-cache lookup. Previously this
    // ran AFTER 2× URL parses + isDomainAlreadyDetected; reordering moves
    // the parse cost off the hot path of every subresource response.
    const matchesRegex = regexes.some(re => re.test(respUrl));
    if (!matchesRegex) return;

    // Parse respUrl ONCE and reuse. Was parsed 2-3 times per response.
    let respHostname;
    try { respHostname = new URL(respUrl).hostname; } catch (_) { return; }
    const fullSubdomain = respHostname; // hostname is always the full subdomain

    if (typeof config.isDomainAlreadyDetected === 'function' && config.isDomainAlreadyDetected(fullSubdomain)) {
      return;
    }
    // respDomain (root domain) is only needed inside the `if (found)` block
    // below. Deferring the getRootDomain call avoids the URL re-parse for
    // every regex-matched response whose content doesn't contain the
    // searchstring — the common case on most pages.

    // First-party / third-party gate. Root-domain comparison matches the
    // main handler and curl.js — old hostname comparison disagreed.
    const respRootDomain = getRootDomain(respUrl);
    const isFirstParty = currentRootDomain === respRootDomain;
    if (isFirstParty && siteConfig.firstParty === false) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${SEARCHSTRING_TAG} Skipping first-party response for searchstring analysis (firstParty=false): ${respUrl}`));
      }
      return;
    }

    if (!isFirstParty && siteConfig.thirdParty === false) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${SEARCHSTRING_TAG} Skipping third-party response for searchstring analysis (thirdParty=false): ${respUrl}`));
      }
      return;
    }

    try {
      // Only capture appropriate content types to avoid binary data
      const contentType = response.headers()['content-type'] || '';
      if (!shouldAnalyzeContentType(contentType)) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${SEARCHSTRING_TAG} Skipping content analysis for ${respUrl} (content-type: ${contentType})`));
        }
        return;
      }

      const content = await response.text();

      // Cache the fetched content if callback provided
      if (config.onContentFetched) {
        try {
          config.onContentFetched(respUrl, content);
        } catch (cacheErr) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${SEARCHSTRING_TAG} Content caching failed: ${cacheErr.message}`));
          }
        }
      }
      
      // Check if content contains search strings (OR or AND logic)
      let searchResult;
      
      if (useGrep && (searchStrings.length > 0 || searchStringsAnd.length > 0)) {
        // Use grep for pattern matching
        try {
          const allPatterns = [...(searchStrings || []), ...(searchStringsAnd || [])];
          const grepResult = await grepContent(content, allPatterns, {
            ignoreCase: true,
            wholeWord: false,
            regex: false
          });
          
          if (hasSearchStringAnd && searchStringsAnd.length > 0) {
            // For AND logic, check that all patterns were found
            const foundPatterns = grepResult.allMatches.map(match => match.pattern);
            const allFound = searchStringsAnd.every(pattern => foundPatterns.includes(pattern));
            searchResult = {
              found: allFound,
              matchedString: allFound ? foundPatterns.join(' AND ') : null,
              logicType: 'AND'
            };
          } else {
            // For OR logic, any match is sufficient
            searchResult = {
              found: grepResult.found,
              matchedString: grepResult.matchedPattern,
              logicType: 'OR'
            };
          }
        } catch (grepErr) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${SEARCHSTRING_TAG} Grep failed for ${respUrl}, falling back to JavaScript: ${grepErr.message}`));
          }
          // Fallback to JavaScript search
          searchResult = searchContent(content, searchStrings, searchStringsAnd, contentType, respUrl);
        }
      } else {
        // Use JavaScript search
        searchResult = searchContent(content, searchStrings, searchStringsAnd, contentType, respUrl);
      }
      
      const { found, matchedString, logicType, error } = searchResult;
      
      if (found) {
        // Reuse respRootDomain from the first-party check — was already
        // computed above. Saves a second getRootDomain call per match.
        const respDomain = perSiteSubDomains ? respHostname : respRootDomain;
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          return;
        }

        // Response handler doesn't have access to specific resource type
        // Use the addMatchedDomain helper which handles fullSubdomain properly
        addMatchedDomain(respDomain, null, fullSubdomain);
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const searchMethod = useGrep ? 'grep' : 'js';
          console.log(`[match][${simplifiedUrl}] ${respUrl} (${partyType}, ${searchMethod}) contains searchstring (${logicType}): "${matchedString}"`);
        }
        
        if (dumpUrls) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const searchMethod = useGrep ? 'grep' : 'js';
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${respUrl} (${partyType}, ${searchMethod}, searchstring (${logicType}): "${matchedString}")\n`);
          } catch (logErr) {
            console.warn(formatLogMessage('warn', `Failed to write to matched URLs log: ${logErr.message}`));
          }
        }
      } else if (forceDebug) {
        const partyType = isFirstParty ? 'first-party' : 'third-party';
        const searchMethod = useGrep ? 'grep' : 'js';
        console.log(formatLogMessage('debug', `${SEARCHSTRING_TAG} ${respUrl} (${partyType}, ${searchMethod}) matched regex but no searchstring found`));
        if (error) {
          console.log(formatLogMessage('debug', `${SEARCHSTRING_TAG} Search error: ${error}`));
        }
      }

    } catch (err) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${SEARCHSTRING_TAG} Failed to read response content for ${respUrl}: ${err.message}`));
      }
    }
  };
}

/**
 * Validates a single string-or-array-of-strings value against the
 * shared rules: type, non-empty, per-element type/non-empty, length cap.
 * Used by validateSearchString for both searchstring and searchstring_and.
 *
 * @param {string|Array<string>} value
 * @param {string} fieldName - e.g. 'searchstring' or 'searchstring_and'
 * @returns {{isValid: boolean, error: string|null}}
 */
function validateSearchValue(value, fieldName) {
  if (typeof value === 'string') {
    if (value.length === 0) {
      return { isValid: false, error: `${fieldName} cannot be empty string` };
    }
    if (value.length > SEARCH_CONFIG.MAX_SEARCH_STRING_LENGTH) {
      return { isValid: false, error: `${fieldName} too long (max ${SEARCH_CONFIG.MAX_SEARCH_STRING_LENGTH} chars)` };
    }
    return { isValid: true, error: null };
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return { isValid: false, error: `${fieldName} array cannot be empty` };
    }
    for (let i = 0; i < value.length; i++) {
      if (typeof value[i] !== 'string') {
        return { isValid: false, error: `${fieldName}[${i}] must be a string` };
      }
      if (value[i].length === 0) {
        return { isValid: false, error: `${fieldName}[${i}] cannot be empty string` };
      }
      if (value[i].length > SEARCH_CONFIG.MAX_SEARCH_STRING_LENGTH) {
        return { isValid: false, error: `${fieldName}[${i}] too long (max ${SEARCH_CONFIG.MAX_SEARCH_STRING_LENGTH} chars)` };
      }
    }
    return { isValid: true, error: null };
  }
  return { isValid: false, error: `${fieldName} must be string or array of strings` };
}

/**
 * Validates searchstring configuration. The old structure returned
 * early on valid string/array searchstring, so 60+ lines of validation
 * below (the both-defined check, length caps, searchstring_and type
 * check) were unreachable for valid inputs — e.g. passing both
 * searchstring AND searchstring_and would have passed validation
 * despite the documented mutual-exclusion rule. Rewritten as a linear
 * sequence of independent checks via the shared validateSearchValue
 * helper so every rule actually runs.
 *
 * @param {any} searchstring - The searchstring value (OR logic)
 * @param {any} searchstringAnd - The searchstring_and value (AND logic)
 * @returns {{isValid: boolean, error: string|null}}
 */
function validateSearchString(searchstring, searchstringAnd) {
  const hasOR = searchstring !== undefined && searchstring !== null;
  const hasAND = searchstringAnd !== undefined && searchstringAnd !== null;

  // Both unset is fine — no searchstring filtering will be applied.
  if (!hasOR && !hasAND) {
    return { isValid: true, error: null };
  }

  // Mutual exclusion: can't combine OR and AND logic in one site config.
  if (hasOR && hasAND) {
    return { isValid: false, error: 'Cannot use both searchstring (OR) and searchstring_and (AND) simultaneously. Choose one logic type.' };
  }

  if (hasOR) {
    const check = validateSearchValue(searchstring, 'searchstring');
    if (!check.isValid) return check;
  }

  if (hasAND) {
    const check = validateSearchValue(searchstringAnd, 'searchstring_and');
    if (!check.isValid) return check;
  }

  return { isValid: true, error: null };
}

module.exports = {
  parseSearchStrings,
  searchContent,
  safeDecodeXmlEntities,
  shouldAnalyzeContentType,
  createResponseHandler,
  createCurlHandler,
  downloadWithCurl,
  validateSearchString,
  downloadWithRetry
};