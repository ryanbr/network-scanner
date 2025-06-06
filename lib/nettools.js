/**
 * Network tools module for whois and dig lookups - COMPLETE FIXED VERSION
 * Provides domain analysis capabilities with proper timeout handling, custom whois servers, and retry logic
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
 * Selects a whois server from the configuration
 * @param {string|Array<string>} whoisServer - Single server string or array of servers
 * @returns {string|null} Selected whois server or null if none specified
 */
function selectWhoisServer(whoisServer) {
  if (!whoisServer) {
    return null; // Use default whois behavior
  }
  
  if (typeof whoisServer === 'string') {
    return whoisServer;
  }
  
  if (Array.isArray(whoisServer) && whoisServer.length > 0) {
    // Randomly select from the array
    const randomIndex = Math.floor(Math.random() * whoisServer.length);
    return whoisServer[randomIndex];
  }
  
  return null;
}

/**
 * Gets common whois servers for debugging/fallback suggestions
 * @returns {Array<string>} List of common whois servers
 */
function getCommonWhoisServers() {
  return [
    'whois.iana.org',
    'whois.internic.net', 
    'whois.verisign-grs.com',
    'whois.markmonitor.com',
    'whois.godaddy.com',
    'whois.namecheap.com',
    'whois.1and1.com'
  ];
}

/**
 * Suggests alternative whois servers based on domain TLD
 * @param {string} domain - Domain to get suggestions for
 * @param {string} failedServer - Server that failed (to exclude from suggestions)
 * @returns {Array<string>} Suggested whois servers
 */
function suggestWhoisServers(domain, failedServer = null) {
  const tld = domain.split('.').pop().toLowerCase();
  const suggestions = [];
  
  // TLD-specific servers
  const tldServers = {
    'com': ['whois.verisign-grs.com', 'whois.internic.net'],
    'net': ['whois.verisign-grs.com', 'whois.internic.net'],
    'org': ['whois.pir.org'],
    'info': ['whois.afilias.net'],
    'biz': ['whois.neulevel.biz'],
    'uk': ['whois.nominet.uk'],
    'de': ['whois.denic.de'],
    'fr': ['whois.afnic.fr'],
    'it': ['whois.nic.it'],
    'nl': ['whois.domain-registry.nl']
  };
  
  if (tldServers[tld]) {
    suggestions.push(...tldServers[tld]);
  }
  
  // Add common servers
  suggestions.push(...getCommonWhoisServers());
  
  // Remove duplicates and failed server
  const uniqueSuggestions = [...new Set(suggestions)];
  return failedServer ? uniqueSuggestions.filter(s => s !== failedServer) : uniqueSuggestions;
}

/**
 * Performs a whois lookup on a domain with proper timeout handling and custom server support (basic version)
 * @param {string} domain - Domain to lookup
 * @param {number} timeout - Timeout in milliseconds (default: 10000)
 * @param {string|Array<string>} whoisServer - Custom whois server(s) to use
 * @param {boolean} debugMode - Enable debug logging (default: false)
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function whoisLookup(domain, timeout = 10000, whoisServer = null, debugMode = false) {
  const startTime = Date.now();
  let cleanDomain, selectedServer, whoisCommand;
  
  try {
    // Clean domain (remove protocol, path, etc)
    cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
    
    // Select whois server if provided
    selectedServer = selectWhoisServer(whoisServer);
    
    // Build whois command
    if (selectedServer) {
      // Use custom whois server with -h flag
      whoisCommand = `whois -h "${selectedServer}" -- "${cleanDomain}"`;
    } else {
      // Use default whois behavior
      whoisCommand = `whois -- "${cleanDomain}"`;
    }
    
    if (debugMode) {
      console.log(`[debug][whois] Starting lookup for ${cleanDomain} (timeout: ${timeout}ms)`);
      console.log(`[debug][whois] Command: ${whoisCommand}`);
    }
    
    const { stdout, stderr } = await execWithTimeout(whoisCommand, timeout);
    const duration = Date.now() - startTime;
    
    if (stderr && stderr.trim()) {
      if (debugMode) {
        console.log(`[debug][whois] Lookup failed for ${cleanDomain} after ${duration}ms`);
        console.log(`[debug][whois] Server: ${selectedServer || 'default'}`);
        console.log(`[debug][whois] Error: ${stderr.trim()}`);
      }
      
      return {
        success: false,
        error: stderr.trim(),
        domain: cleanDomain,
        whoisServer: selectedServer,
        duration: duration,
        command: whoisCommand
      };
    }
    
    if (debugMode) {
      console.log(`[debug][whois] Lookup successful for ${cleanDomain} after ${duration}ms`);
      console.log(`[debug][whois] Server: ${selectedServer || 'default'}`);
      console.log(`[debug][whois] Output length: ${stdout.length} characters`);
    }
    
    return {
      success: true,
      output: stdout,
      domain: cleanDomain,
      whoisServer: selectedServer,
      duration: duration,
      command: whoisCommand
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    const isTimeout = error.message.includes('timeout') || error.message.includes('Command timeout');
    const errorType = isTimeout ? 'timeout' : 'error';
    
    if (debugMode) {
      console.log(`[debug][whois] Lookup ${errorType} for ${cleanDomain || domain} after ${duration}ms`);
      console.log(`[debug][whois] Server: ${selectedServer || 'default'}`);
      console.log(`[debug][whois] Command: ${whoisCommand || 'command not built'}`);
      console.log(`[debug][whois] ${errorType === 'timeout' ? 'Timeout' : 'Error'}: ${error.message}`);
      
      if (isTimeout) {
        console.log(`[debug][whois] Timeout exceeded ${timeout}ms limit`);
        if (selectedServer) {
          console.log(`[debug][whois] Consider using a different whois server or increasing timeout`);
        }
      }
    }
    
    return {
      success: false,
      error: error.message,
      domain: cleanDomain || domain,
      whoisServer: selectedServer,
      duration: duration,
      command: whoisCommand,
      isTimeout: isTimeout,
      errorType: errorType
    };
  }
}

/**
 * Performs a whois lookup with retry logic and fallback servers
 * @param {string} domain - Domain to lookup
 * @param {number} timeout - Timeout in milliseconds (default: 10000)
 * @param {string|Array<string>} whoisServer - Custom whois server(s) to use
 * @param {boolean} debugMode - Enable debug logging (default: false)
 * @param {Object} retryOptions - Retry configuration options
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function whoisLookupWithRetry(domain, timeout = 10000, whoisServer = null, debugMode = false, retryOptions = {}) {
  const {
    maxRetries = 2,
    timeoutMultiplier = 1.5,
    useFallbackServers = true,
    retryOnTimeout = true,
    retryOnError = false
  } = retryOptions;

  let serversToTry = [];
  let currentTimeout = timeout;
  
  // Build list of servers to try
  if (whoisServer) {
    if (Array.isArray(whoisServer)) {
      serversToTry = [...whoisServer]; // Copy array to avoid modifying original
    } else {
      serversToTry = [whoisServer];
    }
  } else {
    serversToTry = [null]; // Default server
  }
  
  // Add fallback servers if enabled and we have custom servers
  if (useFallbackServers && whoisServer) {
    const fallbacks = suggestWhoisServers(domain).slice(0, 3);
    // Only add fallbacks that aren't already in our list
    const existingServers = serversToTry.filter(s => s !== null);
    const newFallbacks = fallbacks.filter(fb => !existingServers.includes(fb));
    serversToTry.push(...newFallbacks);
  }
  
  let lastError = null;
  let attemptCount = 0;
  
  if (debugMode) {
    console.log(`[debug][whois-retry] Starting whois lookup for ${domain} with ${serversToTry.length} server(s) to try`);
    console.log(`[debug][whois-retry] Servers: [${serversToTry.map(s => s || 'default').join(', ')}]`);
    console.log(`[debug][whois-retry] Retry settings: maxRetries=${maxRetries}, timeoutMultiplier=${timeoutMultiplier}, retryOnTimeout=${retryOnTimeout}, retryOnError=${retryOnError}`);
  }
  
  for (const server of serversToTry) {
    attemptCount++;
    
    if (debugMode) {
      const serverName = server || 'default';
      console.log(`[debug][whois-retry] Attempt ${attemptCount}/${serversToTry.length}: trying server ${serverName} (timeout: ${currentTimeout}ms)`);
    }
    
    try {
      const result = await whoisLookup(domain, currentTimeout, server, debugMode);
      
      if (result.success) {
        if (debugMode) {
          console.log(`[debug][whois-retry] SUCCESS on attempt ${attemptCount}/${serversToTry.length} using server ${result.whoisServer || 'default'}`);
        }
        
        // Add retry info to result
        return {
          ...result,
          retryInfo: {
            totalAttempts: attemptCount,
            maxAttempts: serversToTry.length,
            serversAttempted: serversToTry.slice(0, attemptCount),
            finalServer: result.whoisServer,
            retriedAfterFailure: attemptCount > 1
          }
        };
      } else {
        // Determine if we should retry based on error type
        const shouldRetry = (result.isTimeout && retryOnTimeout) || (!result.isTimeout && retryOnError);
        
        if (debugMode) {
          const serverName = result.whoisServer || 'default';
          const errorType = result.isTimeout ? 'TIMEOUT' : 'ERROR';
          console.log(`[debug][whois-retry] ${errorType} on attempt ${attemptCount}/${serversToTry.length} with server ${serverName}: ${result.error}`);
          
          if (attemptCount < serversToTry.length) {
            if (shouldRetry) {
              console.log(`[debug][whois-retry] Will retry with next server...`);
            } else {
              console.log(`[debug][whois-retry] Skipping retry (retryOn${result.isTimeout ? 'Timeout' : 'Error'}=${shouldRetry})`);
            }
          }
        }
        
        lastError = result;
        
        // If this is the last server or we shouldn't retry this error type, break
        if (attemptCount >= serversToTry.length || !shouldRetry) {
          break;
        }
        
        // Increase timeout for next attempt
        currentTimeout = Math.round(currentTimeout * timeoutMultiplier);
      }
    } catch (error) {
      if (debugMode) {
        const serverName = server || 'default';
        console.log(`[debug][whois-retry] EXCEPTION on attempt ${attemptCount}/${serversToTry.length} with server ${serverName}: ${error.message}`);
      }
      
      lastError = {
        success: false,
        error: error.message,
        domain: domain,
        whoisServer: server,
        isTimeout: error.message.includes('timeout'),
        duration: 0
      };
      
      // Continue to next server unless this is the last one
      if (attemptCount >= serversToTry.length) {
        break;
      }
      
      currentTimeout = Math.round(currentTimeout * timeoutMultiplier);
    }
  }
  
  // All attempts failed
  if (debugMode) {
    console.log(`[debug][whois-retry] FINAL FAILURE: All ${attemptCount} attempts failed for ${domain}`);
    if (lastError) {
      console.log(`[debug][whois-retry] Last error: ${lastError.error} (${lastError.isTimeout ? 'timeout' : 'error'})`);
    }
  }
  
  // Return the last error with retry info
  return {
    ...lastError,
    retryInfo: {
      totalAttempts: attemptCount,
      maxAttempts: serversToTry.length,
      serversAttempted: serversToTry.slice(0, attemptCount),
      finalServer: lastError?.whoisServer || null,
      retriedAfterFailure: attemptCount > 1,
      allAttemptsFailed: true
    }
  };
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
    whoisServer,
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
        if (whoisServer) {
          const serverInfo = Array.isArray(whoisServer) 
            ? `randomized from [${whoisServer.join(', ')}]` 
            : whoisServer;
          console.log(`[debug][nettools] Custom whois server: ${serverInfo}`);
        }
      }
      
      // Determine which domain to use for dig lookup
      const digDomain = digSubdomain && originalDomain ? originalDomain : domain;
      
      if (forceDebug) {
        console.log(`[debug][nettools] Final digDomain will be: ${digDomain}`);
      }
      
      // Perform whois lookup if either whois or whois-or is configured
      if (hasWhois || hasWhoisOr) {
        const selectedServer = selectWhoisServer(whoisServer);
        
        if (forceDebug) {
          const serverInfo = selectedServer ? ` using server ${selectedServer}` : ' using default server';
          console.log(`[debug][whois] Performing whois lookup for ${domain}${serverInfo}`);
        }
        
        try {
          // Configure retry options based on site config or use defaults
          const retryOptions = {
            maxRetries: siteConfig.whois_max_retries || 2,
            timeoutMultiplier: siteConfig.whois_timeout_multiplier || 1.5,
            useFallbackServers: siteConfig.whois_use_fallback !== false, // Default true
            retryOnTimeout: siteConfig.whois_retry_on_timeout !== false, // Default true
            retryOnError: siteConfig.whois_retry_on_error === true // Default false
          };
          
          const whoisResult = await whoisLookupWithRetry(domain, 8000, whoisServer, forceDebug, retryOptions);
          
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
              const serverUsed = whoisResult.whoisServer ? ` (server: ${whoisResult.whoisServer})` : ' (default server)';
              const retryInfo = whoisResult.retryInfo ? ` [${whoisResult.retryInfo.totalAttempts}/${whoisResult.retryInfo.maxAttempts} attempts]` : '';
              console.log(`[debug][whois] Lookup completed for ${domain}${serverUsed} in ${whoisResult.duration}ms${retryInfo}`);
              
              if (whoisResult.retryInfo && whoisResult.retryInfo.retriedAfterFailure) {
                console.log(`[debug][whois] Success after retry - servers attempted: [${whoisResult.retryInfo.serversAttempted.map(s => s || 'default').join(', ')}]`);
              }
            }
          } else {
            // Enhanced error logging for failed whois lookups
            if (forceDebug) {
              const serverUsed = whoisResult.whoisServer ? ` (server: ${whoisResult.whoisServer})` : ' (default server)';
              const errorContext = whoisResult.isTimeout ? 'TIMEOUT' : 'ERROR';
              const retryInfo = whoisResult.retryInfo ? ` [${whoisResult.retryInfo.totalAttempts}/${whoisResult.retryInfo.maxAttempts} attempts]` : '';
              
              console.log(`[debug][whois] ${errorContext}: Lookup failed for ${domain}${serverUsed} after ${whoisResult.duration}ms${retryInfo}`);
              console.log(`[debug][whois] Command executed: ${whoisResult.command || 'unknown'}`);
              console.log(`[debug][whois] Error details: ${whoisResult.error}`);
              
              if (whoisResult.retryInfo) {
                if (whoisResult.retryInfo.allAttemptsFailed) {
                  console.log(`[debug][whois] All retry attempts failed. Servers tried: [${whoisResult.retryInfo.serversAttempted.map(s => s || 'default').join(', ')}]`);
                }
                
                if (whoisResult.retryInfo.retriedAfterFailure) {
                  console.log(`[debug][whois] Retries were attempted but ultimately failed`);
                }
              }
              
              if (whoisResult.isTimeout) {
                console.log(`[debug][whois] Timeout exceeded limit after all retry attempts`);
                if (Array.isArray(whoisServer) && whoisServer.length > 1) {
                  const remainingServers = whoisServer.filter(s => !whoisResult.retryInfo?.serversAttempted.includes(s));
                  if (remainingServers.length > 0) {
                    console.log(`[debug][whois] Unused servers from config: ${remainingServers.join(', ')}`);
                  }
                } else {
                  // Suggest alternative servers based on domain TLD
                  const suggestions = suggestWhoisServers(domain, whoisResult.whoisServer).slice(0, 3);
                  if (suggestions.length > 0) {
                    console.log(`[debug][whois] Suggested alternative servers: ${suggestions.join(', ')}`);
                  }
                }
              }
              
              // Log specific error patterns
              if (whoisResult.error.toLowerCase().includes('connection refused')) {
                console.log(`[debug][whois] Connection refused - server may be down or blocking requests`);
              } else if (whoisResult.error.toLowerCase().includes('no route to host')) {
                console.log(`[debug][whois] Network connectivity issue to whois server`);
              } else if (whoisResult.error.toLowerCase().includes('name or service not known')) {
                console.log(`[debug][whois] DNS resolution failed for whois server`);
              }
            }
            // Don't return early - continue with dig if configured
          }
        } catch (whoisError) {
          if (forceDebug) {
            console.log(`[debug][whois] Exception during lookup for ${domain}: ${whoisError.message}`);
            console.log(`[debug][whois] Exception type: ${whoisError.constructor.name}`);
            if (whoisError.stack) {
              console.log(`[debug][whois] Stack trace: ${whoisError.stack.split('\n').slice(0, 3).join(' -> ')}`);
            }
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
          
          // Add whois server info to log if custom server was used
          const serverInfo = whoisServer ? ` (whois-server: ${selectWhoisServer(whoisServer)})` : '';
          fs.appendFileSync(matchedUrlsLogFile, `${timestamp} [match][${simplifiedUrl}] ${domain} (${matchType.join(' + ')})${serverInfo}\n`);
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
  whoisLookupWithRetry,
  digLookup,
  checkWhoisTerms,
  checkWhoisTermsOr,
  checkDigTerms,
  checkDigTermsOr,
  createNetToolsHandler,
  selectWhoisServer,
  getCommonWhoisServers,
  suggestWhoisServers,
  execWithTimeout // Export for testing
};