// === searchstring.js - Content Search Module ===
// Handles response content analysis for searchstring functionality

const fs = require('fs');

/**
 * Parses searchstring configuration into a normalized format
 * @param {string|Array<string>|undefined} searchstring - The searchstring config value
 * @returns {object} Object with searchStrings array and hasSearchString boolean
 */
function parseSearchStrings(searchstring) {
  const searchStrings = Array.isArray(searchstring)
    ? searchstring
    : searchstring
      ? [searchstring]
      : [];
  
  const hasSearchString = searchStrings.length > 0;
  
  return { searchStrings, hasSearchString };
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
          console.log(`[match][${simplifiedUrl}] ${respUrl} contains searchstring: "${matchedString}"`);
        }
        
        if (dumpUrls) {
          const timestamp = new Date().toISOString();
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${respUrl} (searchstring: "${matchedString}")\n`);
          } catch (logErr) {
            console.warn(`[warn] Failed to write to matched URLs log: ${logErr.message}`);
          }
        }
      } else if (forceDebug) {
        console.log(`[debug] ${respUrl} matched regex but no searchstring found`);
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
  validateSearchString,
  getSearchStats
};
