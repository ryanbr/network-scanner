/**
 * Network tools module for whois and dig lookups - FIXED VERSION
 * Provides domain analysis capabilities with proper timeout handling
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
 * Executes a command with proper timeout handling
 * @param {string} command - Command to execute
 * @param {number} timeout - Timeout in milliseconds
 * @returns {Promise<Object>} Promise that resolves with stdout/stderr or rejects on timeout/error
 */
function execWithTimeout(command, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const child = exec(command, { encoding: 'utf8' }, (error, stdout, stderr) => {
      if (timer) clearTimeout(timer);
      
      if (error) {
        reject(error);
      } else {
        resolve({ stdout, stderr });
      }
    });
    
    // Set up timeout
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      
      // Force kill after 2 seconds if SIGTERM doesn't work
      setTimeout(() => {
        if (!child.killed) {
          child.kill('SIGKILL');
        }
      }, 2000);
      
      reject(new Error(`Command timeout after ${timeout}ms: ${command}`));
    }, timeout);
    
    // Handle child process errors
    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * Performs a whois lookup on a domain with proper timeout handling
 * @param {string} domain - Domain to lookup
 * @param {number} timeout - Timeout in milliseconds (default: 10000)
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function whoisLookup(domain, timeout = 10000) {
  try {
    // Clean domain (remove protocol, path, etc)
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
    
    const { stdout, stderr } = await execWithTimeout(`whois -- "${cleanDomain}"`, timeout);
    
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
 * Performs a dig lookup on a domain with proper timeout handling
 * @param {string} domain - Domain to lookup
 * @param {string} recordType - DNS record type (A, AAAA, MX, TXT, etc.) default: 'A'
 * @param {number} timeout - Timeout in milliseconds (default: 5000)
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function digLookup(domain, recordType = 'A', timeout = 5000) {
  try {
    // Clean domain
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
    
    // Get short output first
    const { stdout, stderr } = await execWithTimeout(`dig +short "${cleanDomain}" ${recordType}`, timeout);


    
    if (stderr && stderr.trim()) {
      return {
        success: false,
        error: stderr.trim(),
        domain: cleanDomain,
        recordType
      };
    }
    
    // Also get full dig output for detailed analysis
    const { stdout: fullOutput } = await execWithTimeout(`dig "${cleanDomain}" ${recordType}`, timeout);



    
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
 * Checks if dig output contains any of the specified search terms (OR logic)
 * @param {string} digOutput - The dig lookup output
 * @param {Array<string>} searchTerms - Array of terms where at least one must be present
 * @returns {boolean} True if any term is found
 */
function checkDigTermsOr(digOutput, searchTerms) {
  if (!searchTerms || !Array.isArray(searchTerms) || searchTerms.length === 0) {
    return false;
  }
  
  const lowerOutput = digOutput.toLowerCase();
  return searchTerms.some(term => lowerOutput.includes(term.toLowerCase()));
}

/**
 * Creates a handler for network tools checks with enhanced error handling
 * @param {Object} config - Configuration object
 * @returns {Function} Async function that handles network tool lookups
 */
function createNetToolsHandler(config) {
  const {
    whoisTerms,
    whoisOrTerms,
    digTerms,
    digOrTerms,
    digRecordType = 'A',
    digSubdomain = false,
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
  const hasDigOr = digOrTerms && Array.isArray(digOrTerms) && digOrTerms.length > 0;
  
  return async function handleNetToolsCheck(domain, originalDomain) {
    // Add overall timeout for the entire nettools check
    const netlookupTimeout = setTimeout(() => {
      if (forceDebug) {
        console.log(`[debug][nettools] Overall timeout for domain ${domain}, continuing with next...`);
      }
    }, 15000); // 15 second overall timeout
    
    try {
      let whoisMatched = false;
      let whoisOrMatched = false;
      let digMatched = false;
      let digOrMatched = false;
      
      // Debug logging for digSubdomain logic
      if (forceDebug) {
        console.log(`[debug][nettools] digSubdomain setting: ${digSubdomain}`);
        console.log(`[debug][nettools] domain parameter: ${domain}`);
        console.log(`[debug][nettools] originalDomain parameter: ${originalDomain}`);
      }
      
      // Determine which domain to use for dig lookup
      const digDomain = digSubdomain && originalDomain ? originalDomain : domain;
      
      if (forceDebug) {
        console.log(`[debug][nettools] Final digDomain will be: ${digDomain}`);
      }
      
      // Perform whois lookup if either whois or whois-or is configured
      if (hasWhois || hasWhoisOr) {
        if (forceDebug) {
          console.log(`[debug][whois] Performing whois lookup for ${domain}`);
        }
        
        try {
          const whoisResult = await whoisLookup(domain, 8000); // 8 second timeout for whois
          
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
            // Don't return early - continue with dig if configured
          }
        } catch (whoisError) {
          if (forceDebug) {
            console.log(`[debug][whois] Exception during lookup for ${domain}: ${whoisError.message}`);
          }
          // Continue with dig if configured
        }
      }
      
      // Perform dig lookup if configured
      if (hasDig || hasDigOr) {
        if (forceDebug) {
          const digTypes = [];
          if (hasDig) digTypes.push('dig-and');
          if (hasDigOr) digTypes.push('dig-or');
          console.log(`[debug][dig] Performing dig lookup for ${digDomain} (${digRecordType}) [${digTypes.join(' + ')}]${digSubdomain ? ' [subdomain mode]' : ''}`);
        }
        
        try {
          const digResult = await digLookup(digDomain, digRecordType, 5000); // 5 second timeout for dig
          
          if (digResult.success) {
            // Check AND terms if configured
            if (hasDig) {
              digMatched = checkDigTerms(digResult.output, digTerms);
              if (forceDebug && siteConfig.verbose === 1) {
                console.log(`[debug][dig-and] Terms checked: ${digTerms.join(' AND ')}, matched: ${digMatched}`);
              }
            }
            
            // Check OR terms if configured
            if (hasDigOr) {
              digOrMatched = checkDigTermsOr(digResult.output, digOrTerms);
              if (forceDebug && siteConfig.verbose === 1) {
                console.log(`[debug][dig-or] Terms checked: ${digOrTerms.join(' OR ')}, matched: ${digOrMatched}`);
              }
            }
            
            if (forceDebug) {
              console.log(`[debug][dig] Lookup completed for ${digDomain}, dig-and: ${digMatched}, dig-or: ${digOrMatched}`);
              if (siteConfig.verbose === 1) {
                if (hasDig) console.log(`[debug][dig] AND terms: ${digTerms.join(', ')}`);
                if (hasDigOr) console.log(`[debug][dig] OR terms: ${digOrTerms.join(', ')}`);
                console.log(`[debug][dig] Short output: ${digResult.shortOutput}`);
              }
            }
          } else {
            if (forceDebug) {
              console.log(`[debug][dig] Lookup failed for ${digDomain}: ${digResult.error}`);
            }
          }
        } catch (digError) {
          if (forceDebug) {
            console.log(`[debug][dig] Exception during lookup for ${digDomain}: ${digError.message}`);
          }
        }
      }
      
      // Domain matches if any of these conditions are true:





      let shouldMatch = false;
      
      if (hasWhois && !hasWhoisOr && !hasDig && !hasDigOr) {
        shouldMatch = whoisMatched;
      } else if (!hasWhois && hasWhoisOr && !hasDig && !hasDigOr) {
        shouldMatch = whoisOrMatched;
      } else if (!hasWhois && !hasWhoisOr && hasDig && !hasDigOr) {
        shouldMatch = digMatched;
      } else if (!hasWhois && !hasWhoisOr && !hasDig && hasDigOr) {
        shouldMatch = digOrMatched;
      } else {
        // Multiple checks configured - ALL must pass
        shouldMatch = true;
        if (hasWhois) shouldMatch = shouldMatch && whoisMatched;
        if (hasWhoisOr) shouldMatch = shouldMatch && whoisOrMatched;
        if (hasDig) shouldMatch = shouldMatch && digMatched;
        if (hasDigOr) shouldMatch = shouldMatch && digOrMatched;
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
          if (hasDig && digMatched) matchType.push(digSubdomain ? 'dig-and-subdomain' : 'dig-and');
          if (hasDigOr && digOrMatched) matchType.push(digSubdomain ? 'dig-or-subdomain' : 'dig-or');
          console.log(`[match][${simplifiedUrl}] ${domain} matched via ${matchType.join(' + ')}`);
        }
        
        if (dumpUrls && matchedUrlsLogFile && fs) {
          const timestamp = new Date().toISOString();
          const matchType = [];
          if (hasWhois && whoisMatched) matchType.push('whois-and');
          if (hasWhoisOr && whoisOrMatched) matchType.push('whois-or');
          if (hasDig && digMatched) matchType.push(digSubdomain ? 'dig-and-subdomain' : 'dig-and');
          if (hasDigOr && digOrMatched) matchType.push(digSubdomain ? 'dig-or-subdomain' : 'dig-or');
          fs.appendFileSync(matchedUrlsLogFile, `${timestamp} [match][${simplifiedUrl}] ${domain} (${matchType.join(' + ')})\n`);
        }
      }
      
    } catch (error) {
      if (forceDebug) {
        console.log(`[debug][nettools] Error processing ${domain}: ${error.message}`);
      }
      // Silently fail and continue - don't block other processing
    } finally {
      // Clear the overall timeout
      clearTimeout(netlookupTimeout);
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
  checkDigTermsOr,
  createNetToolsHandler,
  execWithTimeout // Export for testing
};
