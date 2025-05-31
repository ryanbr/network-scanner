// === searchstring.js - Content Search Module ===
// Handles response content analysis for searchstring functionality

const fs = require('fs');
const { spawnSync } = require('child_process');

/**
 * Parses searchstring configuration into a normalized format
 * @param {string|Array<string>|undefined} searchstring - The searchstring config value
 * @returns {object} Object with searchStrings array and hasSearchString boolean
 */
function parseSearchStrings(searchstring) {
  let searchStrings = Array.isArray(searchstring)
    ? searchstring
    : searchstring
      ? [searchstring]
      : [];
  
  // Filter out empty strings to prevent matching everything
  searchStrings = searchStrings.filter(str => str && str.trim().length > 0);
  
  const hasSearchString = searchStrings.length > 0;
  
  return { searchStrings, hasSearchString };
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
 * Handles both raw text search and basic XML content extraction
 * @param {string} content - The response content to search
 * @param {Array<string>} searchStrings - Array of strings to search for
 * @param {string} contentType - Content type for specialized handling
 * @returns {object} Object with found boolean, matchedString (first found), and allMatches array
 */
function searchContent(content, searchStrings, contentType = '') {
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
    allMatches: allMatches
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
    regexes,
    matchedDomains,
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
      if (!hasSearchString) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          return;
        }
        
        matchedDomains.add(respDomain);
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          console.log(`[match][${simplifiedUrl}] ${requestUrl} (${partyType}, curl) matched regex`);
        }
        
        if (dumpUrls) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${requestUrl} (${partyType}, curl)\n`);
          } catch (logErr) {
            console.warn(`[warn] Failed to write to matched URLs log: ${logErr.message}`);
          }
        }
        return;
      }
      
      // If searchstring IS defined, download and search content
      const content = await downloadWithCurl(requestUrl, userAgent, 30);
      
      // Check if content contains any of our search strings (OR logic)
      const { found, matchedString } = searchContent(content, searchStrings, '');
      
      if (found) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          return;
        }
        
        matchedDomains.add(respDomain);
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          console.log(`[match][${simplifiedUrl}] ${requestUrl} (${partyType}, curl) contains searchstring: "${matchedString}"`);
        }
        
        if (dumpUrls) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${requestUrl} (${partyType}, curl, searchstring: "${matchedString}")\n`);
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
    regexes,
    matchedDomains,
    currentUrl,
    perSiteSubDomains,
    ignoreDomains,
    matchesIgnoreDomain,
    getRootDomain,
    siteConfig,
    dumpUrls,
    matchedUrlsLogFile,
    forceDebug
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
      
      // Check if content contains any of our search strings (OR logic)
      const { found, matchedString } = searchContent(content, searchStrings, contentType);
      
      if (found) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          return;
        }
        
        matchedDomains.add(respDomain);
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          console.log(`[match][${simplifiedUrl}] ${respUrl} (${partyType}) contains searchstring: "${matchedString}"`);
        }
        
        if (dumpUrls) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${respUrl} (${partyType}, searchstring: "${matchedString}")\n`);
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
 * @returns {object} Validation result with isValid boolean and error message
 */
function validateSearchString(searchstring) {
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
  
  return { isValid: false, error: 'searchstring must be string or array of strings' };
}

/**
 * Gets statistics about search string matches
 * @param {Set} matchedDomains - Set of matched domains
 * @param {Array<string>} searchStrings - Array of search strings used
 * @returns {object} Statistics object
 */
function getSearchStats(matchedDomains, searchStrings) {
  return {
    totalMatches: matchedDomains.size,
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
  getSearchStats
};