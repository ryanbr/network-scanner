// === curl.js - Curl-based Content Download Module ===
// Handles HTTP content downloading using curl for searchstring analysis

const fs = require('fs');
const { spawnSync } = require('child_process');
const { colorize, colors, messageColors, tags, formatLogMessage } = require('./colorize');

// === Constants ===
const CURL_DEFAULTS = {
  TIMEOUT_SECONDS: 30,
  MAX_REDIRECTS: 5,
  MAX_SIZE_BYTES: 10 * 1024 * 1024, // 10MB
  VALIDATION_TIMEOUT: 5000, // 5 seconds
  SPAWN_TIMEOUT_MULTIPLIER: 1000, // Convert seconds to milliseconds
  HTTP_SUCCESS_CODE: 200,
  CURL_SUCCESS_STATUS: 0,
  METADATA_PIPE_PARTS: 3, // http_code|content_type|size_download
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

  try {
    const curlArgs = [
      '-s', // Silent mode
      '--max-time', timeout.toString(),
      '--max-redirs', maxRedirects.toString(),
      '--fail-with-body', // Return body even on HTTP errors
      '--compressed', // Accept compressed responses
      '--write-out', '%{http_code}|%{content_type}|%{size_download}', // Output metadata
    ];

    if (followRedirects) {
      curlArgs.push('-L'); // Follow redirects
    }

    // Add user agent if provided
    if (userAgent) {
      curlArgs.push('-H', `User-Agent: ${userAgent}`);
    }

    // Add common browser headers
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

    // Add custom headers
    Object.entries(customHeaders).forEach(([key, value]) => {
      curlArgs.push('-H', `${key}: ${value}`);
    });

    curlArgs.push(url);

    // Execute curl
    const curlResult = spawnSync('curl', curlArgs, { 
      encoding: 'utf8',
      timeout: timeout * CURL_DEFAULTS.SPAWN_TIMEOUT_MULTIPLIER,
      maxBuffer: maxSize
    });
    
    if (curlResult.error) {
      throw curlResult.error;
    }
    
    if (curlResult.status !== CURL_DEFAULTS.CURL_SUCCESS_STATUS) {
      throw new Error(`Curl exited with status ${curlResult.status}: ${curlResult.stderr}`);
    }
    
    const output = curlResult.stdout;
    const lines = output.split('\n');
    const metadata = lines[lines.length - 1]; // Last line contains write-out data
    const content = lines.slice(0, -1).join('\n'); // Everything except last line
    
    // Parse metadata
    const metadataParts = metadata.split('|');
    if (metadataParts.length !== CURL_DEFAULTS.METADATA_PIPE_PARTS) {
      throw new Error(`Invalid metadata format: expected ${CURL_DEFAULTS.METADATA_PIPE_PARTS} parts, got ${metadataParts.length}`);
    }
    const [httpCode, contentType, downloadSize] = metadataParts;
    
    return {
      content,
      httpCode: parseInt(httpCode) || 0,
      contentType: contentType || 'unknown',
      downloadSize: parseInt(downloadSize) || content.length,
      success: true
    };
    
  } catch (error) {
    return {
      content: '',
      httpCode: 0,
      contentType: 'unknown',
      downloadSize: 0,
      success: false,
      error: error.message
    };
  }
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

  return async function curlHandler(requestUrl) {
    try {
      const respDomain = perSiteSubDomains ? (new URL(requestUrl)).hostname : getRootDomain(requestUrl);
      const fullSubdomain = (new URL(requestUrl)).hostname; // Always get full subdomain for cache tracking
      
      // Skip if already detected to avoid duplicates
      if (isDomainAlreadyDetected(fullSubdomain)) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[curl] Skipping already detected subdomain: ${fullSubdomain}`));
        }
        return;
      }
      
      // Only process URLs that match our regex patterns
      const matchesRegex = regexes.some(re => re.test(requestUrl));
      if (!matchesRegex) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[curl] URL ${requestUrl} doesn't match any regex patterns`));
        }
        return;
      }
      
      // Check if this is a first-party request (same domain as the URL being scanned)
      const currentUrlHostname = new URL(currentUrl).hostname;
      const requestHostname = new URL(requestUrl).hostname;
      const currentRootDomain = getRootDomain(currentUrl);
      const requestRootDomain = getRootDomain(requestUrl);
      const isFirstParty = currentRootDomain === requestRootDomain;
      
      // Apply first-party/third-party filtering
      if (isFirstParty && (siteConfig.firstParty === false || siteConfig.firstParty === 0)) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[curl] Skipping first-party request (firstParty disabled): ${requestUrl}`));
        }
        return;
      }
      
      if (!isFirstParty && (siteConfig.thirdParty === false || siteConfig.thirdParty === 0)) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[curl] Skipping third-party request (thirdParty disabled): ${requestUrl}`));
        }
        return;
      }
      
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[curl] Processing ${isFirstParty ? 'first-party' : 'third-party'} request: ${requestUrl}`));
      }
      
      // If NO searchstring is defined, match immediately (like browser behavior)
      if (!hasSearchString || ((!searchStrings || !searchStrings.length) && (!searchStringsAnd || !searchStringsAnd.length))) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `[curl] Domain ${respDomain} is in ignore list`));
          }
          return;
        }
        
        addMatchedDomain(respDomain, resourceType, fullSubdomain);
        const simplifiedUrl = getRootDomain(currentUrl);
        
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
      if (hasSearchString && ((searchStrings && searchStrings.length > 0) || (searchStringsAnd && searchStringsAnd.length > 0)) && forceDebug) {
        console.log(formatLogMessage('debug', `[curl] Downloading content for pattern matching: ${requestUrl}`));
      }
      
      // Prepare custom headers from site config
      const customHeaders = siteConfig.custom_headers || {};
      if (siteConfig.referrer_headers) {
        const referrerUrl = Array.isArray(siteConfig.referrer_headers) 
          ? siteConfig.referrer_headers[Math.floor(Math.random() * siteConfig.referrer_headers.length)]
          : siteConfig.referrer_headers;
        
        if (typeof referrerUrl === 'string' && referrerUrl.startsWith('http')) {
          customHeaders['Referer'] = referrerUrl;
        }
      }
      
      const downloadResult = await downloadWithCurl(requestUrl, userAgent, {
        timeout: CURL_DEFAULTS.TIMEOUT_SECONDS,
        maxRedirects: CURL_DEFAULTS.MAX_REDIRECTS,
        customHeaders
      });
      
      if (!downloadResult.success) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[curl] Failed to download ${requestUrl}: ${downloadResult.error}`));
        }
        return;
      }
      
      // Cache the fetched content if callback provided
      if (onContentFetched) {
        try {
          onContentFetched(requestUrl, downloadResult.content);
        } catch (cacheErr) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `[curl] Content caching failed: ${cacheErr.message}`));
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
            console.log(formatLogMessage('debug', `[curl] Domain ${respDomain} matches but is in ignore list`));
          }
          return;
        }
        
        addMatchedDomain(respDomain, resourceType, fullSubdomain);
        const simplifiedUrl = getRootDomain(currentUrl);
        
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
              `[curl] ${requestUrl} (${partyType}) matched regex but missing AND patterns: ${searchResult.missingPatterns.join(', ')}`));
          } else {
            console.log(formatLogMessage('debug', 
              `[curl] ${requestUrl} (${partyType}) matched regex but no search patterns found`));
          }
        }
      }
      
    } catch (err) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[curl] Handler failed for ${requestUrl}: ${err.message}`));
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

module.exports = {
  downloadWithCurl,
  searchContent,
  createCurlHandler,
  validateCurlAvailability
};