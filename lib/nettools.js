/**
 * Network tools module for whois and dig lookups
 * Provides domain analysis capabilities for the scanner
 */

const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

/**
 * Validates if whois command is available on the system
 * @returns {Object} Object with isAvailable boolean and version/error info
 */
function validateWhoisAvailability() {
  try {
    const result = require('child_process').execSync('whois --version 2>&1', { encoding: 'utf8' });
    return {
      isAvailable: true,
      version: result.trim()
    };
  } catch (error) {
    // Some systems don't have --version, try just whois
    try {
      require('child_process').execSync('which whois', { encoding: 'utf8' });
      return {
        isAvailable: true,
        version: 'whois (version unknown)'
      };
    } catch (e) {
      return {
        isAvailable: false,
        error: 'whois command not found'
      };
    }
  }
}

/**
 * Validates if dig command is available on the system
 * @returns {Object} Object with isAvailable boolean and version/error info
 */
function validateDigAvailability() {
  try {
    const result = require('child_process').execSync('dig -v 2>&1', { encoding: 'utf8' });
    return {
      isAvailable: true,
      version: result.split('\n')[0].trim()
    };
  } catch (error) {
    return {
      isAvailable: false,
      error: 'dig command not found'
    };
  }
}

/**
 * Performs a whois lookup on a domain
 * @param {string} domain - Domain to lookup
 * @param {number} timeout - Timeout in milliseconds (default: 10000)
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function whoisLookup(domain, timeout = 10000) {
  try {
    // Clean domain (remove protocol, path, etc)
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
    
    const { stdout, stderr } = await execPromise(`whois -- "${cleanDomain}"`, {
      timeout,
      encoding: 'utf8'
    });
    
    if (stderr && stderr.trim()) {
      return {
        success: false,
        error: stderr.trim(),
        domain: cleanDomain
      };
    }
    
    return {
      success: true,
      output: stdout,
      domain: cleanDomain
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      domain: domain
    };
  }
}

/**
 * Performs a dig lookup on a domain
 * @param {string} domain - Domain to lookup
 * @param {string} recordType - DNS record type (A, AAAA, MX, TXT, etc.) default: 'A'
 * @param {number} timeout - Timeout in milliseconds (default: 5000)
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function digLookup(domain, recordType = 'A', timeout = 5000) {
  try {
    // Clean domain
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
    
    const { stdout, stderr } = await execPromise(`dig +short "${cleanDomain}" ${recordType}`, {
      timeout,
      encoding: 'utf8'
    });
    
    if (stderr && stderr.trim()) {
      return {
        success: false,
        error: stderr.trim(),
        domain: cleanDomain,
        recordType
      };
    }
    
    // Also get full dig output for detailed analysis
    const { stdout: fullOutput } = await execPromise(`dig "${cleanDomain}" ${recordType}`, {
      timeout,
      encoding: 'utf8'
    });
    
    return {
      success: true,
      output: fullOutput,
      shortOutput: stdout.trim(),
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
 * Creates a handler for network tools checks
 * @param {Object} config - Configuration object
 * @returns {Function} Async function that handles network tool lookups
 */
function createNetToolsHandler(config) {
  const {
    whoisTerms,
    whoisOrTerms,
    digTerms,
    digRecordType = 'A',
    matchedDomains,
    addMatchedDomain,
    currentUrl,
    getRootDomain,
    siteConfig,
    dumpUrls,
    matchedUrlsLogFile,
    forceDebug,
    fs
  } = config;
  
  const hasWhois = whoisTerms && Array.isArray(whoisTerms) && whoisTerms.length > 0;
  const hasWhoisOr = whoisOrTerms && Array.isArray(whoisOrTerms) && whoisOrTerms.length > 0;
  const hasDig = digTerms && Array.isArray(digTerms) && digTerms.length > 0;
  
  return async function handleNetToolsCheck(domain) {
    try {
      let whoisMatched = false;
      let whoisOrMatched = false;
      let digMatched = false;
      
      // Perform whois lookup if either whois or whois-or is configured
      if (hasWhois || hasWhoisOr) {
        if (forceDebug) {
          console.log(`[debug][whois] Performing whois lookup for ${domain}`);
        }
        
        const whoisResult = await whoisLookup(domain);
        
        if (whoisResult.success) {
          // Check AND terms if configured
          if (hasWhois) {
            whoisMatched = checkWhoisTerms(whoisResult.output, whoisTerms);
            if (forceDebug && siteConfig.verbose === 1) {
              console.log(`[debug][whois-and] Terms checked: ${whoisTerms.join(' AND ')}, matched: ${whoisMatched}`);
            }
          }
          
          // Check OR terms if configured
          if (hasWhoisOr) {
            whoisOrMatched = checkWhoisTermsOr(whoisResult.output, whoisOrTerms);
            if (forceDebug && siteConfig.verbose === 1) {
              console.log(`[debug][whois-or] Terms checked: ${whoisOrTerms.join(' OR ')}, matched: ${whoisOrMatched}`);
            }
          }
          
          if (forceDebug) {
            console.log(`[debug][whois] Lookup completed for ${domain}`);
          }
        } else {
          if (forceDebug) {
            console.log(`[debug][whois] Lookup failed for ${domain}: ${whoisResult.error}`);
          }
          // Don't process further if whois is required but failed
          return;
        }
      }
      
      // Perform dig lookup if configured
      if (hasDig) {
        if (forceDebug) {
          console.log(`[debug][dig] Performing dig lookup for ${domain} (${digRecordType})`);
        }
        
        const digResult = await digLookup(domain, digRecordType);
        
        if (digResult.success) {
          digMatched = checkDigTerms(digResult.output, digTerms);
          
          if (forceDebug) {
            console.log(`[debug][dig] Lookup completed for ${domain}, matched: ${digMatched}`);
            if (siteConfig.verbose === 1) {
              console.log(`[debug][dig] Terms checked: ${digTerms.join(', ')}`);
              console.log(`[debug][dig] Short output: ${digResult.shortOutput}`);
            }
          }
        } else {
          if (forceDebug) {
            console.log(`[debug][dig] Lookup failed for ${domain}: ${digResult.error}`);
          }
          // Don't process further if dig is required but failed
          return;
        }
      }
      
      // Domain matches if any of these conditions are true:
      // - Only whois AND is configured and it matches
      // - Only whois OR is configured and it matches
      // - Only dig is configured and it matches
      // - Multiple are configured and ALL configured checks match
      let shouldMatch = false;
      
      if (hasWhois && !hasWhoisOr && !hasDig) {
        shouldMatch = whoisMatched;
      } else if (!hasWhois && hasWhoisOr && !hasDig) {
        shouldMatch = whoisOrMatched;
      } else if (!hasWhois && !hasWhoisOr && hasDig) {
        shouldMatch = digMatched;
      } else {
        // Multiple checks configured - ALL must pass
        shouldMatch = true;
        if (hasWhois) shouldMatch = shouldMatch && whoisMatched;
        if (hasWhoisOr) shouldMatch = shouldMatch && whoisOrMatched;
        if (hasDig) shouldMatch = shouldMatch && digMatched;
      }
      
      if (shouldMatch) {
        // Add to matched domains
        if (typeof addMatchedDomain === 'function') {
          addMatchedDomain(domain);
        } else {
          matchedDomains.add(domain);
        }
        
        const simplifiedUrl = getRootDomain(currentUrl);
        
        if (siteConfig.verbose === 1) {
          const matchType = [];
          if (hasWhois && whoisMatched) matchType.push('whois-and');
          if (hasWhoisOr && whoisOrMatched) matchType.push('whois-or');
          if (hasDig && digMatched) matchType.push('dig');
          console.log(`[match][${simplifiedUrl}] ${domain} matched via ${matchType.join(' + ')}`);
        }
        
        if (dumpUrls && matchedUrlsLogFile && fs) {
          const timestamp = new Date().toISOString();
          const matchType = [];
          if (hasWhois && whoisMatched) matchType.push('whois-and');
          if (hasWhoisOr && whoisOrMatched) matchType.push('whois-or');
          if (hasDig && digMatched) matchType.push('dig');
          fs.appendFileSync(matchedUrlsLogFile, `${timestamp} [match][${simplifiedUrl}] ${domain} (${matchType.join(' + ')})\n`);
        }
      }
      
    } catch (error) {
      if (forceDebug) {
        console.log(`[debug][nettools] Error processing ${domain}: ${error.message}`);
      }
      // Silently fail and continue - don't block other processing
    }
  };
}

module.exports = {
  validateWhoisAvailability,
  validateDigAvailability,
  whoisLookup,
  digLookup,
  checkWhoisTerms,
  checkWhoisTermsOr,
  checkDigTerms,
  createNetToolsHandler
};
