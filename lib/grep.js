// === grep.js - Grep-based Content Search Module ===
// Alternative to searchstring.js using grep for pattern matching

const fs = require('fs');
const { spawnSync } = require('child_process');
const path = require('path');
const os = require('os');
const { colorize, colors, messageColors, tags, formatLogMessage } = require('./colorize');

// === Constants ===
const GREP_DEFAULTS = {
  TIMEOUT_SECONDS: 30,
  MAX_REDIRECTS: 5,
  MAX_SIZE_BYTES: 10 * 1024 * 1024, // 10MB
  VALIDATION_TIMEOUT: 5000, // 5 seconds
  SPAWN_TIMEOUT_MULTIPLIER: 1000, // Convert seconds to milliseconds
  GREP_TIMEOUT: 10000, // 10 seconds for grep operations
  MAX_BUFFER_SIZE: 1024 * 1024, // 1MB max buffer
  DEFAULT_MAX_MATCHES: 1000,
  GREP_SUCCESS_STATUS: 0,
  GREP_NOT_FOUND_STATUS: 1,
  CURL_SUCCESS_STATUS: 0,
  VERSION_LINE_INDEX: 0,
  RANDOM_STRING_LENGTH: 9
};

/**
 * Creates a temporary file with content for grep processing
 * @param {string} content - The content to write to temp file
 * @param {string} prefix - Prefix for temp filename
 * @returns {string} Path to the created temporary file
 */
function createTempFile(content, prefix = 'scanner_grep') {
  const tempDir = os.tmpdir();
  const tempFile = path.join(tempDir, `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, GREP_DEFAULTS.RANDOM_STRING_LENGTH)}.tmp`);
  
  try {
    fs.writeFileSync(tempFile, content, 'utf8');
    return tempFile;
  } catch (error) {
    throw new Error(`Failed to create temp file: ${error.message}`);
  }
}

/**
 * Searches content using grep with the provided patterns
 * @param {string} content - The content to search
 * @param {Array<string>} searchPatterns - Array of grep patterns to search for
 * @param {object} options - Grep options
 * @returns {Promise<object>} Object with found boolean, matchedPattern, and allMatches array
 */
async function grepContent(content, searchPatterns, options = {}) {
  const {
    ignoreCase = true,
    wholeWord = false,
    regex = false,
    maxMatches = GREP_DEFAULTS.DEFAULT_MAX_MATCHES
  } = options;

  if (!content || searchPatterns.length === 0) {
    return { found: false, matchedPattern: null, allMatches: [] };
  }

  let tempFile = null;
  
  try {
    // Create temporary file with content
    tempFile = createTempFile(content, 'grep_search');
    
    const allMatches = [];
    let firstMatch = null;
    
    for (const pattern of searchPatterns) {
      if (!pattern || pattern.trim().length === 0) continue;
      
      const grepArgs = [
        '--text', // Treat file as text
        '--color=never', // Disable color output
      ];
      
      if (ignoreCase) grepArgs.push('-i');
      if (wholeWord) grepArgs.push('-w');
      if (!regex) grepArgs.push('-F'); // Fixed strings (literal)
      
      // Add pattern and file
      grepArgs.push(pattern, tempFile);
      
      try {
        const result = spawnSync('grep', grepArgs, {
          encoding: 'utf8',
          timeout: GREP_DEFAULTS.GREP_TIMEOUT,
          maxBuffer: GREP_DEFAULTS.MAX_BUFFER_SIZE
        });
        
        // grep returns 0 if found, 1 if not found, 2+ for errors
        if (result.status === GREP_DEFAULTS.GREP_SUCCESS_STATUS && result.stdout) {
          allMatches.push({
            pattern: pattern,
            matches: result.stdout.split('\n').filter(line => line.trim().length > 0).slice(0, maxMatches)
          });
          
          if (!firstMatch) {
            firstMatch = pattern;
          }
        }
        
      } catch (grepErr) {
        // Continue with next pattern if this one fails
        console.warn(formatLogMessage('warn', `[grep] Pattern "${pattern}" failed: ${grepErr.message}`));
      }
    }
    
    return {
      found: allMatches.length > 0,
      matchedPattern: firstMatch,
      allMatches: allMatches
    };
    
  } catch (error) {
    throw new Error(`Grep search failed: ${error.message}`);
  } finally {
    // Clean up temporary file
    if (tempFile) {
      try {
        fs.unlinkSync(tempFile);
      } catch (cleanupErr) {
        console.warn(formatLogMessage('warn', `[grep] Failed to cleanup temp file ${tempFile}: ${cleanupErr.message}`));
      }
    }
  }
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
async function downloadAndGrep(url, searchPatterns, userAgent = '', grepOptions = {}, timeout = GREP_DEFAULTS.TIMEOUT_SECONDS) {
  try {
    const curlArgs = [
      '-s', // Silent mode
      '-L', // Follow redirects
      '--max-time', timeout.toString(),
      '--max-redirs', GREP_DEFAULTS.MAX_REDIRECTS.toString(),
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

    // Download content with curl
    const curlResult = spawnSync('curl', curlArgs, { 
      encoding: 'utf8',
      timeout: timeout * GREP_DEFAULTS.SPAWN_TIMEOUT_MULTIPLIER,
      maxBuffer: GREP_DEFAULTS.MAX_SIZE_BYTES
    });
    
    if (curlResult.error) {
      throw curlResult.error;
    }
    
    if (curlResult.status !== GREP_DEFAULTS.CURL_SUCCESS_STATUS) {
      throw new Error(`Curl exited with status ${curlResult.status}: ${curlResult.stderr}`);
    }
    
    const content = curlResult.stdout;
    
    // Search content with grep
    const grepResult = await grepContent(content, searchPatterns, grepOptions);
    
    return {
      found: grepResult.found,
      matchedPattern: grepResult.matchedPattern,
      allMatches: grepResult.allMatches,
      content: content,
      contentLength: content.length
    };
    
  } catch (error) {
    throw new Error(`Download and grep failed for ${url}: ${error.message}`);
  }
}

/**
 * Creates a grep-based URL handler for downloading and searching content
 * @param {object} config - Configuration object containing all necessary parameters
 * @returns {Function} URL handler function for grep-based content analysis
 */
function createGrepHandler(config) {
  const {
    searchStrings,
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
    hasSearchString,
    grepOptions = {}
  } = config;

  return async function grepHandler(requestUrl) {
    const respDomain = perSiteSubDomains ? (new URL(requestUrl)).hostname : getRootDomain(requestUrl);
    const fullSubdomain = (new URL(requestUrl)).hostname; // Always get full subdomain for cache tracking
    
    // Skip if already detected to avoid duplicates
    if (isDomainAlreadyDetected(fullSubdomain)) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[grep] Skipping already detected subdomain: ${fullSubdomain}`));
      }
      return;
    }
 
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
        console.log(formatLogMessage('debug', `[grep] Skipping first-party request (firstParty=false): ${requestUrl}`));
      }
      return;
    }
    
    if (!isFirstParty && siteConfig.thirdParty === false) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[grep] Skipping third-party request (thirdParty=false): ${requestUrl}`));
      }
      return;
    }
    
    try {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[grep] Downloading and searching content from: ${requestUrl}`));
      }
      
      // If NO searchstring is defined, match immediately (like browser behavior)
      if (!hasSearchString) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          return;
        }
        
        addMatchedDomain(respDomain, resourceType, fullSubdomain);
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          console.log(formatLogMessage('match', `[${simplifiedUrl}] ${requestUrl} (${partyType}, grep) matched regex`));
        }
        
        if (dumpUrls) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${requestUrl} (${partyType}, grep)\n`);
          } catch (logErr) {
            console.warn(formatLogMessage('warn', `Failed to write to matched URLs log: ${logErr.message}`));
          }
        }
        return;
      }
      
      // If searchstring IS defined, download and grep content
      const result = await downloadAndGrep(requestUrl, searchStrings, userAgent, grepOptions, GREP_DEFAULTS.TIMEOUT_SECONDS);

      // Cache the fetched content if callback provided
      if (onContentFetched && result.content) {
        try {
          onContentFetched(requestUrl, result.content);
        } catch (cacheErr) {
          if (forceDebug) console.log(formatLogMessage('debug', `[grep] Content caching failed: ${cacheErr.message}`));
        }
      }
   
      if (result.found) {
        if (!respDomain || matchesIgnoreDomain(respDomain, ignoreDomains)) {
          return;
        }
        
        addMatchedDomain(respDomain, resourceType, fullSubdomain);
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const matchCount = result.allMatches.reduce((sum, match) => sum + match.matches.length, 0);
          console.log(formatLogMessage('match', `[${simplifiedUrl}] ${requestUrl} (${partyType}, grep) contains pattern: "${result.matchedPattern}" (${matchCount} matches)`));
        }
        
        if (dumpUrls) {
          const timestamp = new Date().toISOString();
          const partyType = isFirstParty ? 'first-party' : 'third-party';
          const matchCount = result.allMatches.reduce((sum, match) => sum + match.matches.length, 0);
          try {
            fs.appendFileSync(matchedUrlsLogFile, 
              `${timestamp} [match][${simplifiedUrl}] ${requestUrl} (${partyType}, grep, pattern: "${result.matchedPattern}", matches: ${matchCount})\n`);
          } catch (logErr) {
            console.warn(formatLogMessage('warn', `Failed to write to matched URLs log: ${logErr.message}`));
          }
        }
      } else if (forceDebug) {
        const partyType = isFirstParty ? 'first-party' : 'third-party';
        console.log(formatLogMessage('debug', `[grep] ${requestUrl} (${partyType}) matched regex but no patterns found`));
      }
      
    } catch (err) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[grep] Failed to download/grep content for ${requestUrl}: ${err.message}`));
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

module.exports = {
  grepContent,
  downloadAndGrep,
  createGrepHandler,
  validateGrepAvailability,
  createTempFile
};