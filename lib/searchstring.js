// === searchstring.js - Content Search Module ===
// Handles response content analysis for searchstring functionality

const fs = require('fs');
const { formatLogMessage, messageColors } = require('./colorize');
const CURL_TAG = messageColors.processing('[curl]');
const { spawn } = require('child_process');
const { grepContent } = require('./grep');

// Configuration constants for search logic
const SEARCH_CONFIG = {
  MAX_CONTENT_SIZE: 50 * 1024 * 1024, // 50MB max content size
  MAX_SEARCH_STRING_LENGTH: 1000,
  XML_ENTITY_TIMEOUT: 5000 // 5 second timeout for XML processing
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
  return new Promise((resolve, reject) => {
    const curlArgs = [
      '-s', // Silent mode
      '-L', // Follow redirects
      '--max-time', timeout.toString(),
      '--max-redirs', '5',
      '--fail-with-body', // Return body even on HTTP errors
      '--max-filesize', '52428800', // 50MB limit
      '--range', '0-52428799', // Limit download size
      '--compressed' // Accept compressed responses
    ];

    if (userAgent) {
      curlArgs.push('-H', `User-Agent: ${userAgent}`);
    }

    // Add common headers to appear more browser-like
    curlArgs.push(
      '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      '-H', 'Accept-Language: en-US,en;q=0.5',
      '-H', 'Accept-Encoding: gzip, deflate',
      '-H', 'Connection: keep-alive',
      '-H', 'Upgrade-Insecure-Requests: 1'
    );

    curlArgs.push(url);

    // Use spawn (async) NOT spawnSync — the old spawnSync blocked the
    // entire Node event loop for up to `timeout` seconds. Under concurrent
    // scans (multiple curl handlers firing simultaneously) that stalled
    // every other Promise resolution in the process. Wrapping spawnSync
    // in `new Promise` doesn't make it async; the work still runs to
    // completion before the Promise constructor returns.
    let child;
    try {
      child = spawn('curl', curlArgs);
    } catch (spawnErr) {
      reject(new Error(`Curl failed for ${url}: ${spawnErr.message}`));
      return;
    }

    // Streamed stdout/stderr collection with a hard cap on stdout so a
    // misbehaving server can't blow memory past --max-filesize.
    const MAX_STDOUT_BYTES = 52428800; // 50MB, matches --max-filesize
    let stdoutBytes = 0;
    let truncated = false;
    const stdoutChunks = [];
    const stderrChunks = [];

    child.stdout.on('data', (chunk) => {
      if (truncated) return;
      if (stdoutBytes + chunk.length > MAX_STDOUT_BYTES) {
        truncated = true;
        try { child.kill('SIGTERM'); } catch (_) {}
        return;
      }
      stdoutBytes += chunk.length;
      stdoutChunks.push(chunk);
    });
    child.stderr.on('data', (chunk) => { stderrChunks.push(chunk); });

    // Belt-and-braces hard timeout — curl's --max-time is the primary
    // limit. This catches cases where curl itself hangs (very rare).
    // Unref'd so it doesn't keep the event loop alive on its own.
    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, (timeout + 5) * 1000);
    if (typeof killTimer.unref === 'function') killTimer.unref();

    child.on('error', (err) => {
      clearTimeout(killTimer);
      reject(new Error(`Curl failed for ${url}: ${err.message}`));
    });

    child.on('close', (code, signal) => {
      clearTimeout(killTimer);
      if (truncated) {
        reject(new Error(`Curl output exceeded ${MAX_STDOUT_BYTES} bytes for ${url}`));
        return;
      }
      if (signal) {
        reject(new Error(`Curl killed by signal ${signal} for ${url}`));
        return;
      }
      if (code !== 0) {
        const stderr = Buffer.concat(stderrChunks).toString('utf8');
        reject(new Error(`Curl exited with status ${code}: ${stderr}`));
        return;
      }
      resolve(Buffer.concat(stdoutChunks).toString('utf8'));
    });
  });
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

/**
 * Safely decodes XML entities with timeout protection
 * @param {string} content - Content to decode
 * @returns {string} Decoded content or original if processing fails
 */
function safeDecodeXmlEntities(content) {
  const startTime = Date.now();
  
  try {
    let decoded = content
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&apos;/g, "'");
    
    // Check timeout before expensive regex operations
    if (Date.now() - startTime > SEARCH_CONFIG.XML_ENTITY_TIMEOUT) {
      console.warn('[warn] XML entity decoding timeout, using partial result');
      return decoded;
    }
    
    // Decode numeric entities (decimal)
    decoded = decoded.replace(/&#(\d+);/g, (match, dec) => {
      const num = parseInt(dec, 10);
      // Validate range for safety (valid Unicode range)
      if (num >= 0 && num <= 0x10FFFF) {
        return String.fromCharCode(num);
      }
      return match; // Keep original if invalid
    });
    
    // Check timeout again
    if (Date.now() - startTime > SEARCH_CONFIG.XML_ENTITY_TIMEOUT) {
      console.warn('[warn] XML entity decoding timeout, using partial result');
      return decoded;
    }
    
    // Decode numeric entities (hexadecimal)
    decoded = decoded.replace(/&#x([0-9a-f]+);/gi, (match, hex) => {
      const num = parseInt(hex, 16);
      // Validate range for safety (valid Unicode range)
      if (num >= 0 && num <= 0x10FFFF) {
        return String.fromCharCode(num);
      }
      return match; // Keep original if invalid
    });
    
    return decoded;
  } catch (xmlErr) {
    console.warn(formatLogMessage('warn', `XML entity decoding failed: ${xmlErr.message}`));
    return content; // Return original content if decoding fails
  }
}

/**
 * Safely strips XML/HTML tags with size limits
 * @param {string} content - Content to strip tags from
 * @returns {string} Content with tags removed
 */
function safeStripTags(content) {
  try {
    // Limit content size for tag stripping to prevent excessive memory usage
    const limitedContent = content.length > SEARCH_CONFIG.MAX_CONTENT_SIZE 
      ? content.substring(0, SEARCH_CONFIG.MAX_CONTENT_SIZE)
      : content;
    
    // Replace tags with spaces to preserve word boundaries
    return limitedContent.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
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
 * @returns {object} Object with found boolean, matchedString/matchedStrings, allMatches array, and logic type
 */
function searchContent(content, searchStrings, searchStringsAnd = [], contentType = '', url = '') {
  // Input validation
  if (!content || typeof content !== 'string') {
    return { 
      found: false, 
      matchedString: null, 
      matchedStrings: [], 
      allMatches: [], 
      logicType: 'NONE',
      error: 'Invalid or empty content'
    };
  }
  
  // Size check and truncation with warning
  const originalLength = content.length;
  if (originalLength > SEARCH_CONFIG.MAX_CONTENT_SIZE) {
    content = content.substring(0, SEARCH_CONFIG.MAX_CONTENT_SIZE);
    console.warn(formatLogMessage('warn', `Content truncated from ${originalLength} to ${SEARCH_CONFIG.MAX_CONTENT_SIZE} chars for ${url || 'unknown URL'}`));
  }
  let searchableContent = content;

  const isXmlContent = contentType.toLowerCase().includes('xml') || 
                      contentType.toLowerCase().includes('html');
  
  if (isXmlContent) {
    try {
      // Safely decode XML entities
      const decodedContent = safeDecodeXmlEntities(content);
      
      // Safely strip tags to extract text content
      const strippedContent = safeStripTags(decodedContent);
      
      // Search in: original + decoded + stripped content
      // Use newlines as separators to prevent false matches across content types
      searchableContent = [content, decodedContent, strippedContent].join('\n');
      
    } catch (xmlProcessingErr) {
      console.warn(formatLogMessage('warn', `XML processing failed for ${url || 'unknown URL'}: ${xmlProcessingErr.message}`));
      // Fall back to original content
      searchableContent = content;
    }
  }
  
  // Input validation for search strings
  const validSearchStrings = searchStrings.filter(str => 
    str && typeof str === 'string' && str.length > 0 && str.length <= SEARCH_CONFIG.MAX_SEARCH_STRING_LENGTH
  );
  const validSearchStringsAnd = searchStringsAnd.filter(str => 
    str && typeof str === 'string' && str.length > 0 && str.length <= SEARCH_CONFIG.MAX_SEARCH_STRING_LENGTH
  );
  
  // Warn about filtered search strings
  if (validSearchStrings.length !== searchStrings.length) {
    console.warn(formatLogMessage('warn', `Filtered ${searchStrings.length - validSearchStrings.length} invalid search strings`));
  }
  if (validSearchStringsAnd.length !== searchStringsAnd.length) {
    console.warn(formatLogMessage('warn', `Filtered ${searchStringsAnd.length - validSearchStringsAnd.length} invalid AND search strings`));
  }
  
  // Early return if no valid search strings
  if (validSearchStrings.length === 0 && validSearchStringsAnd.length === 0) {
    return {
      found: false,
      matchedString: null,
      matchedStrings: [],
      allMatches: [],
      logicType: 'NONE',
      error: 'No valid search strings provided'
    };
  }
  
  // Pre-compute lowercase content once for better performance
  const lowerContent = searchableContent.toLowerCase();
  
  // Check AND logic first (more restrictive) - ALL strings must be present
  if (validSearchStringsAnd && validSearchStringsAnd.length > 0) {
    const foundAndStrings = [];
    
    for (const searchStr of validSearchStringsAnd) {
      const lowerSearchStr = searchStr.toLowerCase();
      if (lowerContent.includes(lowerSearchStr)) {
        foundAndStrings.push(searchStr);
      } else {
        // Early exit if any AND string is not found
        break;
      }
    }
    
    // AND logic: ALL valid strings must be found
    if (foundAndStrings.length === validSearchStringsAnd.length) {
      return {
        found: true,
        matchedString: foundAndStrings.join(' AND '),
        matchedStrings: foundAndStrings,
        allMatches: foundAndStrings,
        logicType: 'AND',
        contentSize: originalLength,
        searchableSize: searchableContent.length
      };
    }
  }
  
  // OR logic: ANY string can match
  const allMatches = [];
  let firstMatch = null;
  
  for (const searchStr of validSearchStrings) {
    const lowerSearchStr = searchStr.toLowerCase();
    if (lowerContent.includes(lowerSearchStr)) {
      allMatches.push(searchStr);
      if (!firstMatch) {
        firstMatch = searchStr;
      }
    }
  }
  
  return {
    found: allMatches.length > 0,
    matchedString: firstMatch,
    matchedStrings: allMatches,
    allMatches: allMatches,
    logicType: validSearchStrings.length > 0 ? 'OR' : 'NONE',
    contentSize: originalLength,
    searchableSize: searchableContent.length,
    processedAsXml: isXmlContent
  };
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

  return async function curlHandler(requestUrl) {
    
    // Only process URLs that match our regex patterns
    const matchesRegex = regexes.some(re => re.test(requestUrl));
    if (!matchesRegex) return;

    // Extract domain and check if already detected (skip expensive operations)
    const reqDomain = perSiteSubDomains ? (new URL(requestUrl)).hostname : getRootDomain(requestUrl);
    if (typeof config.isDomainAlreadyDetected === 'function' && config.isDomainAlreadyDetected(reqDomain)) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${CURL_TAG} Skipping already detected domain: ${reqDomain}`));
      }
      return;
    }
    
    // Check if this is a first-party request (same domain as the URL being scanned)
    const currentUrlHostname = new URL(currentUrl).hostname;
    const requestHostname = new URL(requestUrl).hostname;
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

  return async function responseHandler(response) {
    const respUrl = response.url();
    const respDomain = perSiteSubDomains ? (new URL(respUrl)).hostname : getRootDomain(respUrl);
    
    // Only process responses that match our regex patterns
    const fullSubdomain = (new URL(respUrl)).hostname; // Always get full subdomain for cache tracking
    
    // Skip if already detected to avoid duplicates
    if (typeof config.isDomainAlreadyDetected === 'function' && config.isDomainAlreadyDetected(fullSubdomain)) {
      return;
    }
    const matchesRegex = regexes.some(re => re.test(respUrl));
    if (!matchesRegex) return;
    
    // Extract domain and check if already detected (skip expensive operations)   
    // The main request handler already filtered first-party/third-party requests
    // This response handler only runs for requests that passed that filter
    // However, we need to apply the same first-party/third-party logic here for searchstring analysis
    // because the response handler analyzes content, not just URLs
    
    // Apply first-party/third-party filtering for searchstring analysis
    // Use the exact same logic as the main request handler

    const currentUrlHostname = new URL(currentUrl).hostname;
    const responseHostname = new URL(respUrl).hostname;
    const isFirstParty = currentUrlHostname === responseHostname;
    if (isFirstParty && siteConfig.firstParty === false) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Skipping first-party response for searchstring analysis (firstParty=false): ${respUrl}`));
      }
      return;
    }
    
    if (!isFirstParty && siteConfig.thirdParty === false) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Skipping third-party response for searchstring analysis (thirdParty=false): ${respUrl}`));
      }
      return;
    }
    
    try {
      // Only capture appropriate content types to avoid binary data
      const contentType = response.headers()['content-type'] || '';
      if (!shouldAnalyzeContentType(contentType)) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Skipping content analysis for ${respUrl} (content-type: ${contentType})`));
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
            console.log(formatLogMessage('debug', `Content caching failed: ${cacheErr.message}`));
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
            console.log(formatLogMessage('debug', `Grep failed for ${respUrl}, falling back to JavaScript: ${grepErr.message}`));
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
        console.log(formatLogMessage('debug', `${respUrl} (${partyType}, ${searchMethod}) matched regex but no searchstring found`));
        if (error) {
          console.log(formatLogMessage('debug', `Search error: ${error}`));
        }
      }
      
    } catch (err) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Failed to read response content for ${respUrl}: ${err.message}`));
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