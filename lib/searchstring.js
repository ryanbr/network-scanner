// === searchstring.js - Content Search Module ===
// Handles response content analysis for searchstring functionality

const fs = require('fs');
const { spawnSync } = require('child_process');

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
 * Helper function to add domain to matched collection (handles both Set and Map)
 * @param {Set|Map} matchedDomains - The matched domains collection
 * @param {Function} addMatchedDomain - Optional helper function for adding domains
 * @param {string} domain - Domain to add
 * @param {string} resourceType - Resource type (for --adblock-rules mode)
 */
function addDomainToCollection(matchedDomains, addMatchedDomain, domain, resourceType = null) {
  // Use helper function if provided (preferred method)
  if (typeof addMatchedDomain === 'function') {
    addMatchedDomain(domain, resourceType);
    return;
  }
  
  // Fallback: handle different collection types directly
  if (matchedDomains instanceof Set) {
    matchedDomains.add(domain);
  } else if (matchedDomains instanceof Map) {
    if (!matchedDomains.has(domain)) {
      matchedDomains.set(domain, new Set());
    }
    if (resourceType) {
      matchedDomains.get(domain).add(resourceType);
    }
  } else {
    console.warn('[warn] Unknown matchedDomains type, skipping domain addition');
  }
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
    try {
      const curlArgs = [
        '-s', // Silent mode
        '-L', // Follow redirects
        '--max-time', timeout.toString(),
        '--max-redirs', '5',
        '--fail-with-body', // Return body even on HTTP errors
        '--compressed', // Accept compressed responses
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

      // Use spawnSync with proper argument separation
      const result = spawnSync('curl', curlArgs, { 
        encoding: 'utf8',
        timeout: timeout * 1000,
        maxBuffer: 10 * 1024 * 1024 // 10MB max buffer
      });
      
      if (result.error) {
        throw result.error;
      }
      
      if (result.status !== 0) {
        throw new Error(`Curl exited with status ${result.status}: ${result.stderr}`);
      }
      
      resolve(result.stdout);
    } catch (error) {
      reject(new Error(`Curl failed for ${url}: ${error.message}`));
    }
  });
}

/**
 * Checks if response content contains any of the search strings (OR logic)
 * or all of the AND search strings (AND logic)
 * Handles both raw text search and basic XML content extraction
 * @param {string} content - The response content to search
 * @param {Array<string>} searchStrings - Array of strings to search for (OR logic)
 * @param {Array<string>} searchStringsAnd - Array of strings that must all be present (AND logic)
 * @param {string} contentType - Content type for specialized handling
 * @returns {object} Object with found boolean, matchedString/matchedStrings, allMatches array, and logic type
 */
function searchContent(content, searchStrings, searchStringsAnd = [], contentType = '') {
  let searchableContent = content;
  
  // For XML content, also search decoded entities and stripped tags for better matching
  if (contentType.includes('xml')) {
    // Decode common XML entities
    const decodedContent = content
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
    
    // Create version with XML tags stripped for text content search
    const strippedContent = decodedContent.replace(/<[^>]*>/g, ' ');
    
    // Search in: original + decoded + stripped content
    searchableContent = content + '\n' + decodedContent + '\n' + strippedContent;
  }
  
  // Check AND logic first (more restrictive)
  if (searchStringsAnd && searchStringsAnd.length > 0) {
    const lowerContent = searchableContent.toLowerCase();
    const foundAndStrings = [];
    
    for (const searchStr of searchStringsAnd) {
      if (lowerContent.includes(searchStr.toLowerCase())) {
        foundAndStrings.push(searchStr);
      }
    }
    
    // AND logic: ALL strings must be found
    if (foundAndStrings.length === searchStringsAnd.length) {
      return {
        found: true,
        matchedString: foundAndStrings.join(' AND '), // Show all matched strings
        matchedStrings: foundAndStrings,
        allMatches: foundAndStrings,
        logicType: 'AND'
      };
    }
  }
  
  // Fall back to OR logic if AND logic didn't match or wasn't specified
  const lowerContent = searchableContent.toLowerCase();
  const allMatches = [];
  let firstMatch = null;
  
  for (const searchStr of searchStrings) {
    if (lowerContent.includes(searchStr.toLowerCase())) {
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
    logicType: 'OR'
  };
}

/**
 * Determines if a content type should be analyzed for search strings
 * @param {string} contentType - The response content-type header
 * @returns {boolean} True if content should be analyzed
 */
function shouldAnalyzeContentType(contentType) {
  if (!contentType) return false;
  
  const textTypes = [
    'text/',                    // text/html, text/plain, text/xml, etc.
    'application/json',
    'application/javascript',
    'application/xml',          // Standard XML
    'application/x-javascript',
    'application/soap+xml',     // SOAP XML
    'application/rss+xml',      // RSS feeds
    'application/atom+xml',     // Atom feeds
    'application/xhtml+xml'     // XHTML
  ];
  
  return textTypes.some(type => contentType.includes(type));
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
    const respDomain = perSiteSubDomains ? (new URL(requestUrl)).hostname : getRootDomain(requestUrl);
    
    // Only process URLs that match our regex patterns
    const matchesRegex = regexes.some(re => re.test(requestUrl));
    if (!matchesRegex) return;
    
    // Check if this is a first-party request (same domain as the URL being scanned)
    const currentUrlHostname = new URL(currentUrl).hostname;
    const requestHostname = new URL(requestUrl).hostname;
    const isFirstParty = currentUrlHostname === requestHostname;
    
    // Apply first-party/third-party filtering
    if (isFirstParty && siteConfig.firstParty === false) {
      if (forceDebug) {
        console.log(`[debug][curl] Skipping first-party request (firstParty=false): ${requestUrl}`);
      }
      return;
    }
    
    if (!isFirstParty && siteConfig.thirdParty === false) {
      if (forceDebug) {
        console.log(`[debug][curl] Skipping third-party request (thirdParty=false): ${requestUrl}`);
      }
      return;
    }
    
    try {
      if (forceDebug) {
        console.log(`[debug][curl] Downloading content from: ${requestUrl}`);
      }
      
      // If NO searchstring is defined, match immediately (like browser behavior)
      if (!hasSearchString && !hasSearchStringAnd) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          return;
        }
        
        addDomainToCollection(matchedDomains, addMatchedDomain, respDomain, resourceType);
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
            console.warn(`[warn] Failed to write to matched URLs log: ${logErr.message}`);
          }
        }
        return;
      }
      
      // If searchstring IS defined, download and search content
      const content = await downloadWithCurl(requestUrl, userAgent, 30);
      
      // Check if content contains search strings (OR or AND logic)
      const { found, matchedString, logicType } = searchContent(content, searchStrings, searchStringsAnd, '');
      
      if (found) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          return;
        }
        
        addDomainToCollection(matchedDomains, addMatchedDomain, respDomain, resourceType);
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
            console.warn(`[warn] Failed to write to matched URLs log: ${logErr.message}`);
          }
        }
      } else if (forceDebug) {
        const partyType = isFirstParty ? 'first-party' : 'third-party';
        console.log(`[debug][curl] ${requestUrl} (${partyType}) matched regex but no searchstring found`);
      }
      
    } catch (err) {
      if (forceDebug) {
        console.log(`[debug][curl] Failed to download content for ${requestUrl}: ${err.message}`);
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
    forceDebug,
    resourceType // Will be null for response handler
  } = config;

  return async function responseHandler(response) {
    const respUrl = response.url();
    const respDomain = perSiteSubDomains ? (new URL(respUrl)).hostname : getRootDomain(respUrl);
    
    // Only process responses that match our regex patterns
    const matchesRegex = regexes.some(re => re.test(respUrl));
    if (!matchesRegex) return;
    
    // Check if this is a first-party response (same domain as the URL being scanned)
    const currentUrlHostname = new URL(currentUrl).hostname;
    const responseHostname = new URL(respUrl).hostname;
    const isFirstParty = currentUrlHostname === responseHostname;
    
    // The main request handler already filtered first-party/third-party requests
    // This response handler only runs for requests that passed that filter
    // However, we need to apply the same first-party/third-party logic here for searchstring analysis
    // because the response handler analyzes content, not just URLs
    
    // Apply first-party/third-party filtering for searchstring analysis
    // Use the exact same logic as the main request handler
    if (isFirstParty && siteConfig.firstParty === false) {
      if (forceDebug) {
        console.log(`[debug] Skipping first-party response for searchstring analysis (firstParty=false): ${respUrl}`);
      }
      return;
    }
    
    if (!isFirstParty && siteConfig.thirdParty === false) {
      if (forceDebug) {
        console.log(`[debug] Skipping third-party response for searchstring analysis (thirdParty=false): ${respUrl}`);
      }
      return;
    }
    
    try {
      // Only capture appropriate content types to avoid binary data
      const contentType = response.headers()['content-type'] || '';
      if (!shouldAnalyzeContentType(contentType)) {
        if (forceDebug) {
          console.log(`[debug] Skipping content analysis for ${respUrl} (content-type: ${contentType})`);
        }
        return;
      }
      
      const content = await response.text();
      
      // Check if content contains search strings (OR or AND logic)
      const { found, matchedString, logicType } = searchContent(content, searchStrings, searchStringsAnd, contentType);
      
      if (found) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          return;
        }
        
        // Response handler doesn't have access to specific resource type
        addDomainToCollection(matchedDomains, addMatchedDomain, respDomain, null);
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          console.log(`[match][${simplifiedUrl}] ${respUrl} (${partyType}) contains searchstring (${logicType}): "${matchedString}"`);
        }
        
        if (dumpUrls) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${respUrl} (${partyType}, searchstring (${logicType}): "${matchedString}")\n`);
          } catch (logErr) {
            console.warn(`[warn] Failed to write to matched URLs log: ${logErr.message}`);
          }
        }
      } else if (forceDebug) {
        const partyType = isFirstParty ? 'first-party' : 'third-party';
        console.log(`[debug] ${respUrl} (${partyType}) matched regex but no searchstring found`);
      }
      
    } catch (err) {
      if (forceDebug) {
        console.log(`[debug] Failed to read response content for ${respUrl}: ${err.message}`);
      }
    }
  };
}

/**
 * Validates searchstring configuration
 * @param {any} searchstring - The searchstring value to validate
 * @param {any} searchstringAnd - The searchstring_and value to validate
 * @returns {object} Validation result with isValid boolean and error message
 */
function validateSearchString(searchstring, searchstringAnd) {
  if (searchstring === undefined || searchstring === null) {
    return { isValid: true, error: null };
  }
  
  if (typeof searchstring === 'string') {
    if (searchstring.length === 0) {
      return { isValid: false, error: 'searchstring cannot be empty string' };
    }
    return { isValid: true, error: null };
  }
  
  if (Array.isArray(searchstring)) {
    if (searchstring.length === 0) {
      return { isValid: false, error: 'searchstring array cannot be empty' };
    }
    
    for (let i = 0; i < searchstring.length; i++) {
      if (typeof searchstring[i] !== 'string') {
        return { isValid: false, error: `searchstring[${i}] must be a string` };
      }
      if (searchstring[i].length === 0) {
        return { isValid: false, error: `searchstring[${i}] cannot be empty string` };
      }
    }
    
    return { isValid: true, error: null };
  }
  
  // Validate searchstring_and
  if (searchstringAnd !== undefined && searchstringAnd !== null) {
    if (typeof searchstringAnd === 'string') {
      if (searchstringAnd.length === 0) {
        return { isValid: false, error: 'searchstring_and cannot be empty string' };
      }
    } else if (Array.isArray(searchstringAnd)) {
      if (searchstringAnd.length === 0) {
        return { isValid: false, error: 'searchstring_and array cannot be empty' };
      }
      
      for (let i = 0; i < searchstringAnd.length; i++) {
        if (typeof searchstringAnd[i] !== 'string') {
          return { isValid: false, error: `searchstring_and[${i}] must be a string` };
        }
        if (searchstringAnd[i].length === 0) {
          return { isValid: false, error: `searchstring_and[${i}] cannot be empty string` };
        }
      }
    } else {
      return { isValid: false, error: 'searchstring_and must be string or array of strings' };
    }
  }
  
  // Check that both searchstring and searchstring_and aren't defined simultaneously
  if (searchstring && searchstringAnd) {
    return { isValid: false, error: 'Cannot use both searchstring (OR) and searchstring_and (AND) simultaneously. Choose one logic type.' };
  }
  
  return { isValid: false, error: 'searchstring must be string or array of strings' };
}

/**
 * Gets statistics about search string matches
 * @param {Set|Map} matchedDomains - Set or Map of matched domains
 * @param {Array<string>} searchStrings - Array of search strings used
 * @returns {object} Statistics object
 */
function getSearchStats(matchedDomains, searchStrings) {
  const totalMatches = matchedDomains instanceof Map ? matchedDomains.size : matchedDomains.size;
  
  return {
    totalMatches,
    searchStringCount: searchStrings.length,
    searchStrings: [...searchStrings]
  };
}

module.exports = {
  parseSearchStrings,
  searchContent,
  shouldAnalyzeContentType,
  createResponseHandler,
  createCurlHandler,
  downloadWithCurl,
  validateSearchString,
  getSearchStats,
  addDomainToCollection
};