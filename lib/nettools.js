/**
 * Network tools module for whois and dig lookups - COMPLETE FIXED VERSION
 * Provides domain analysis capabilities with proper timeout handling, custom whois servers, and retry logic
 */

const { exec } = require('child_process');
const util = require('util');
const { formatLogMessage, messageColors } = require('./colorize');
const execPromise = util.promisify(exec);

/**
 * Strips ANSI color codes from a string for clean file logging
 * @param {string} text - Text that may contain ANSI codes
 * @returns {string} Text with ANSI codes removed
 */
function stripAnsiColors(text) {
  // Remove ANSI escape sequences (color codes)
  return text.replace(/\x1b\[[0-9;]*m/g, '');
}

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
 * @param {string} mode - Selection mode: 'random' (default) or 'cycle'
 * @returns {string|null} Selected whois server or null if none specified
 */
function selectWhoisServer(whoisServer, mode = 'random'){
  if (!whoisServer) {
    return null; // Use default whois behavior
  }
  
  if (typeof whoisServer === 'string') {
    return whoisServer;
  }
  
  if (Array.isArray(whoisServer) && whoisServer.length > 0) {
    if (mode === 'cycle') {
      // Use global cycling index
      if (typeof global.globalWhoisServerIndex === 'undefined') {
        global.globalWhoisServerIndex = 0;
      }
      
      const selectedServer = whoisServer[global.globalWhoisServerIndex % whoisServer.length];
      global.globalWhoisServerIndex = (global.globalWhoisServerIndex + 1) % whoisServer.length;
      
      return selectedServer;
    } else {
      // Random selection (default behavior)
      const randomIndex = Math.floor(Math.random() * whoisServer.length);
      return whoisServer[randomIndex];
    }
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
async function whoisLookup(domain, timeout = 10000, whoisServer = null, debugMode = false, logFunc = null) {
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
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois]')} Starting lookup for ${cleanDomain} (timeout: ${timeout}ms)`);
        logFunc(`${messageColors.highlight('[whois]')} Command: ${whoisCommand}`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Starting lookup for ${cleanDomain} (timeout: ${timeout}ms)`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Command: ${whoisCommand}`));
      }
    }
    
    const { stdout, stderr } = await execWithTimeout(whoisCommand, timeout);
    const duration = Date.now() - startTime;
    
    if (stderr && stderr.trim()) {
      if (debugMode) {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois]')} Lookup failed for ${cleanDomain} after ${duration}ms`);
          logFunc(`${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`);
          logFunc(`${messageColors.highlight('[whois]')} Error: ${stderr.trim()}`);
          logFunc(`${messageColors.highlight('[whois]')} Command executed: ${whoisCommand}`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Lookup failed for ${cleanDomain} after ${duration}ms`));
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`));
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Error: ${stderr.trim()}`));
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Command executed: ${whoisCommand}`));
        }
      if (selectedServer) {
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois]')} Custom server used: ${selectedServer}`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Custom server used: ${selectedServer}`));
          }
        }
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
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois]')} Lookup successful for ${cleanDomain} after ${duration}ms`);
        logFunc(`${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`);
        logFunc(`${messageColors.highlight('[whois]')} Output length: ${stdout.length} characters`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Lookup successful for ${cleanDomain} after ${duration}ms`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Output length: ${stdout.length} characters`));
      }
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
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois]')} Lookup ${errorType} for ${cleanDomain || domain} after ${duration}ms`);
        logFunc(`${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`);
        logFunc(`${messageColors.highlight('[whois]')} Command: ${whoisCommand || 'command not built'}`);
        logFunc(`${messageColors.highlight('[whois]')} ${errorType === 'timeout' ? 'Timeout' : 'Error'}: ${error.message}`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Lookup ${errorType} for ${cleanDomain || domain} after ${duration}ms`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Server: ${selectedServer || 'default'}`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Command: ${whoisCommand || 'command not built'}`));
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} ${errorType === 'timeout' ? 'Timeout' : 'Error'}: ${error.message}`));
      }
      
       if (selectedServer) {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois]')} Failed server: ${selectedServer} (custom)`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Failed server: ${selectedServer} (custom)`));
        }
      } else {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois]')} Failed server: system default whois server`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Failed server: system default whois server`));
        }
      }
      
      if (isTimeout) {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois]')} Timeout exceeded ${timeout}ms limit`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Timeout exceeded ${timeout}ms limit`));
        }
        if (selectedServer) {
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois]')} Consider using a different whois server or increasing timeout`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois]')} Consider using a different whois server or increasing timeout`));
          }
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
 * @param {number} whoisDelay - Delay in milliseconds before whois requests (default: 2000)
 * @returns {Promise<Object>} Object with success status and output/error
 */
async function whoisLookupWithRetry(domain, timeout = 10000, whoisServer = null, debugMode = false, retryOptions = {}, whoisDelay = 2000, logFunc = null) {
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
    if (logFunc) {
      logFunc(`${messageColors.highlight('[whois-retry]')} Starting whois lookup for ${domain} with ${serversToTry.length} server(s) to try`);
      logFunc(`${messageColors.highlight('[whois-retry]')} Servers: [${serversToTry.map(s => s || 'default').join(', ')}]`);
      logFunc(`${messageColors.highlight('[whois-retry]')} Retry settings: maxRetries=${maxRetries}, timeoutMultiplier=${timeoutMultiplier}, retryOnTimeout=${retryOnTimeout}, retryOnError=${retryOnError}`);
    } else {
      console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Starting whois lookup for ${domain} with ${serversToTry.length} server(s) to try`));
      console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Servers: [${serversToTry.map(s => s || 'default').join(', ')}]`));
      console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Retry settings: maxRetries=${maxRetries}, timeoutMultiplier=${timeoutMultiplier}, retryOnTimeout=${retryOnTimeout}, retryOnError=${retryOnError}`));
    }
  }
  
  for (const server of serversToTry) {
    attemptCount++;
    
    if (debugMode) {
      const serverName = server || 'default';
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois-retry]')} Attempt ${attemptCount}/${serversToTry.length}: trying server ${serverName} (timeout: ${currentTimeout}ms)`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Attempt ${attemptCount}/${serversToTry.length}: trying server ${serverName} (timeout: ${currentTimeout}ms)`));
      }
    }
    
    // Add delay between retry attempts to prevent rate limiting
    if (attemptCount > 1) {
      if (debugMode) {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois-retry]')} Adding ${whoisDelay}ms delay before retry attempt...`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Adding ${whoisDelay}ms delay before retry attempt...`));
        }
      }
      
      await new Promise(resolve => setTimeout(resolve, whoisDelay));
    } else if (whoisDelay > 0) {
      // Add initial delay on first attempt if configured
      if (debugMode) {
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois-retry]')} Adding ${whoisDelay}ms delay to prevent rate limiting...`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Adding ${whoisDelay}ms delay to prevent rate limiting...`));
        }
      }
      await new Promise(resolve => setTimeout(resolve, whoisDelay));
   }
    
    try {
      const result = await whoisLookup(domain, currentTimeout, server, debugMode, logFunc);
      
      if (result.success) {
        if (debugMode) {
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois-retry]')} SUCCESS on attempt ${attemptCount}/${serversToTry.length} using server ${result.whoisServer || 'default'}`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} SUCCESS on attempt ${attemptCount}/${serversToTry.length} using server ${result.whoisServer || 'default'}`));
          }
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
          if (logFunc) {
            logFunc(`${messageColors.highlight('[whois-retry]')} ${errorType} on attempt ${attemptCount}/${serversToTry.length} with server ${serverName}: ${result.error}`);
          } else {
            console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} ${errorType} on attempt ${attemptCount}/${serversToTry.length} with server ${serverName}: ${result.error}`));
          }
          
          if (attemptCount < serversToTry.length) {
            if (shouldRetry) {
              if (logFunc) {
                logFunc(`${messageColors.highlight('[whois-retry]')} Will retry with next server...`);
              } else {
                console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Will retry with next server...`));
              }
            } else {
              if (logFunc) {
                logFunc(`${messageColors.highlight('[whois-retry]')} Skipping retry (retryOn${result.isTimeout ? 'Timeout' : 'Error'}=${shouldRetry})`);
              } else {
                console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Skipping retry (retryOn${result.isTimeout ? 'Timeout' : 'Error'}=${shouldRetry})`));
              }
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
        if (logFunc) {
          logFunc(`${messageColors.highlight('[whois-retry]')} EXCEPTION on attempt ${attemptCount}/${serversToTry.length} with server ${serverName}: ${error.message}`);
        } else {
          console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} EXCEPTION on attempt ${attemptCount}/${serversToTry.length} with server ${serverName}: ${error.message}`));
        }
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
    if (logFunc) {
      logFunc(`${messageColors.highlight('[whois-retry]')} FINAL FAILURE: All ${attemptCount} attempts failed for ${domain}`);
    } else {
      console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} FINAL FAILURE: All ${attemptCount} attempts failed for ${domain}`));
    }
    if (lastError) {
      if (logFunc) {
        logFunc(`${messageColors.highlight('[whois-retry]')} Last error: ${lastError.error} (${lastError.isTimeout ? 'timeout' : 'error'})`);
      } else {
        console.log(formatLogMessage('debug', `${messageColors.highlight('[whois-retry]')} Last error: ${lastError.error} (${lastError.isTimeout ? 'timeout' : 'error'})`));
      }
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
 * Enhanced dry run callback factory for better nettools reporting
 * @param {Map} matchedDomains - The matched domains collection
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Function} Enhanced dry run callback
 */
function createEnhancedDryRunCallback(matchedDomains, forceDebug) {
  return (domain, tool, matchType, matchedTerm, details, additionalInfo = {}) => {
    const result = { 
      domain, 
      tool, 
      matchType, 
      matchedTerm, 
      details, 
      ...additionalInfo 
    };
    
    matchedDomains.get('dryRunNetTools').push(result);
    
    if (forceDebug) {
      const serverInfo = additionalInfo.server ? ` (server: ${additionalInfo.server})` : '';
      const timingInfo = additionalInfo.duration ? ` [${additionalInfo.duration}ms]` : '';
      console.log(formatLogMessage('debug', `[DRY RUN] NetTools match: ${domain} via ${tool.toUpperCase()} (${matchType})${serverInfo}${timingInfo}`));
    }
  };
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
    whoisDelay = 2000,
    whoisServer,
    whoisServerMode = 'random',
    debugLogFile = null,
    digTerms,
    digOrTerms,
    digRecordType = 'A',
    digSubdomain = false,
    dryRunCallback = null,
    matchedDomains,
    addMatchedDomain,
    isDomainAlreadyDetected,
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
  
  // Add separate deduplication caches for different lookup types
  const processedWhoisDomains = new Set();
  const processedDigDomains = new Set();
  // Add whois resolution caching to avoid redundant whois lookups
  const whoisResultCache = new Map();
  const WHOIS_CACHE_TTL = 900000; // 15 minutes cache TTL (whois data changes less frequently)
  const MAX_CACHE_SIZE = 400; // Larger cache for whois due to longer TTL
  // Size          Memory
  // 100          ~900KB
  // 200          1.8MB
  // 300          2.6MB
  // 400          3.4MB
  // 500          4.2MB  
  // Add DNS resolution caching to avoid redundant dig lookups
  const digResultCache = new Map();
  const DIG_CACHE_TTL = 300000; // 5 minutes cache TTL
  const DIG_MAX_CACHE_SIZE = 400; // Smaller cache for dig due to shorter TTL
  
  return async function handleNetToolsCheck(domain, fullSubdomain) {
    // Use fullSubdomain parameter instead of originalDomain to maintain consistency
    // with the domain cache fix approach
    const originalDomain = fullSubdomain;
    // Helper function to log to BOTH console and debug file

    // Check if domain was already detected (skip expensive operations)
    if (typeof isDomainAlreadyDetected === 'function' && isDomainAlreadyDetected(fullSubdomain)) {
      if (forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Skipping already detected subdomain: ${fullSubdomain} (output domain: ${domain})`);
      }
      return;
    }
    
    // NOTE: The logToConsoleAndFile function needs to be declared INSIDE this function
    // so it has access to the closure variables (forceDebug, debugLogFile, fs) from the 
    // createNetToolsHandler config. This function was being called but not declared
    // within the scope where whoisLookup and whoisLookupWithRetry try to use it.
    // This is why we were getting "logToConsoleAndFile is not defined" errors.

    // Move the logToConsoleAndFile function declaration from later in the file to here:
    function logToConsoleAndFile(message) {
      // Note: This function needs access to forceDebug, debugLogFile, and fs from the parent scope
      // These are passed in via the config object to createNetToolsHandler
      // forceDebug, debugLogFile, and fs are available in this closure

      // Always log to console when in debug mode
      if (forceDebug) {
        console.log(formatLogMessage('debug', message));
      }
      
      // Also log to file if debug file logging is enabled
      if (debugLogFile && fs) {
        try {
          const timestamp = new Date().toISOString();
          const cleanMessage = stripAnsiColors(message);
          fs.appendFileSync(debugLogFile, `${timestamp} [debug nettools] ${cleanMessage}\n`);
        } catch (logErr) {
          // Silently fail file logging to avoid disrupting whois operations
        }
      }
    }
    
    // Determine which domain will be used for dig lookup
    const digDomain = digSubdomain && originalDomain ? originalDomain : domain;
    
    // Check if we need to perform any lookups
    const needsWhoisLookup = (hasWhois || hasWhoisOr) && !processedWhoisDomains.has(domain);
    const needsDigLookup = (hasDig || hasDigOr) && !processedDigDomains.has(digDomain);
    
    // Skip if we don't need to perform any lookups
    if (!needsWhoisLookup && !needsDigLookup) {
      if (forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Skipping duplicate lookups for ${domain} (whois: ${!needsWhoisLookup}, dig: ${!needsDigLookup})`);
      }
      return;
    }
    

    if (forceDebug) {
      const totalProcessed = processedWhoisDomains.size + processedDigDomains.size;
      logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Processing domain: ${domain} (whois: ${needsWhoisLookup}, dig: ${needsDigLookup}) (${totalProcessed} total processed)`);
    }

      // Log site-specific whois delay if different from default
      if (forceDebug && whoisDelay !== 3000) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Using site-specific whois delay: ${whoisDelay}ms`);
      }

    // Add overall timeout for the entire nettools check
    const netlookupTimeout = setTimeout(() => {
      if (forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Overall timeout for domain ${domain}, continuing with next...`);
      }
    }, 30000); // 30 second overall timeout
    
    // Wrap entire function in timeout protection
    return Promise.race([
      (async () => {
        try {
          return await executeNetToolsLookup();
        } finally {
          clearTimeout(netlookupTimeout);
        }
      })(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('NetTools overall timeout')), 30000))
    ]).catch(err => {
      if (forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} ${err.message} for ${domain}, continuing...`);
      }
    });
    
    async function executeNetToolsLookup() {
    
    try {
      let whoisMatched = false;
      let whoisOrMatched = false;
      let digMatched = false;
      let digOrMatched = false;
      
      // Debug logging for digSubdomain logic
      if (forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} digSubdomain setting: ${digSubdomain}`);
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} domain parameter: ${domain}`);
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} originalDomain parameter: ${originalDomain}`);
        logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Final digDomain will be: ${digDomain}`);
        if (whoisServer) {
          const serverInfo = Array.isArray(whoisServer) 
            ? `randomized from [${whoisServer.join(', ')}]` 
            : whoisServer;
          logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Custom whois server: ${serverInfo}`);
        }
      }
      
      // Enhanced dry run logging
      if (dryRunCallback && forceDebug) {
        logToConsoleAndFile(`${messageColors.highlight('[nettools-dryrun]')} Processing ${domain} (original: ${originalDomain})`);

        // Show what checks will be performed
        const checksToPerform = [];
        if (hasWhois) checksToPerform.push('whois-and');
        if (hasWhoisOr) checksToPerform.push('whois-or');
        if (hasDig) checksToPerform.push('dig-and');
        if (hasDigOr) checksToPerform.push('dig-or');
        logToConsoleAndFile(`${messageColors.highlight('[nettools-dryrun]')} Will perform: ${checksToPerform.join(', ')}`);
        
        // Show which domain will be used for dig
        if (hasDig || hasDigOr) {
          logToConsoleAndFile(`${messageColors.highlight('[dig-dryrun]')} Will check ${digDomain} (${digSubdomain ? 'subdomain mode' : 'root domain mode'})`);
        }
        
        // Show whois server selection
        if (hasWhois || hasWhoisOr) {
          const selectedServer = selectWhoisServer(whoisServer, whoisServerMode);
          const serverInfo = selectedServer ? selectedServer : 'system default';
          logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} Will use server: ${serverInfo}`);
        }
        
        // Show retry configuration in dry-run
        if (hasWhois || hasWhoisOr) {
          const maxRetries = siteConfig.whois_max_retries || 2;
          logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} Max retries: ${maxRetries}, timeout multiplier: ${siteConfig.whois_timeout_multiplier || 1.5}`);
        }
      }
      
      // Perform whois lookup if either whois or whois-or is configured
      if (needsWhoisLookup) {
        // Mark whois domain as being processed
        processedWhoisDomains.add(domain);
        
        // Check whois cache first - cache key includes server for accuracy
        const selectedServer = selectWhoisServer(whoisServer, whoisServerMode);
        const whoisCacheKey = `${domain}-${selectedServer || 'default'}`;
        const now = Date.now();
        let whoisResult = null;
        
        if (whoisResultCache.has(whoisCacheKey)) {
          const cachedEntry = whoisResultCache.get(whoisCacheKey);
          if (now - cachedEntry.timestamp < WHOIS_CACHE_TTL) {
            if (forceDebug) {
              const age = Math.round((now - cachedEntry.timestamp) / 1000);
              const serverInfo = selectedServer ? ` (server: ${selectedServer})` : ' (default server)';
              logToConsoleAndFile(`${messageColors.highlight('[whois-cache]')} Using cached result for ${domain}${serverInfo} [age: ${age}s]`);
            }
            whoisResult = { 
              ...cachedEntry.result,
              // Add cache metadata
              fromCache: true,
              cacheAge: now - cachedEntry.timestamp,
              originalTimestamp: cachedEntry.timestamp
            };
          } else {
            // Cache expired, remove it
            whoisResultCache.delete(whoisCacheKey);
            if (forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[whois-cache]')} Cache expired for ${domain}, performing fresh lookup`);
            }
          }
        }
        
        // Perform fresh lookup if not cached
        if (!whoisResult) {
          if (forceDebug) {
            const serverInfo = selectedServer ? ` using server ${selectedServer}` : ' using default server';
            logToConsoleAndFile(`${messageColors.highlight('[whois]')} Performing fresh whois lookup for ${domain}${serverInfo}`);
          }
        
          // Configure retry options based on site config or use defaults
          const retryOptions = {
            maxRetries: siteConfig.whois_max_retries || 2,
            timeoutMultiplier: siteConfig.whois_timeout_multiplier || 1.5,
            useFallbackServers: siteConfig.whois_use_fallback !== false, // Default true
            retryOnTimeout: siteConfig.whois_retry_on_timeout !== false, // Default true
            retryOnError: siteConfig.whois_retry_on_error === true // Default false
          };
          
          try {
            whoisResult = await whoisLookupWithRetry(domain, 8000, whoisServer, forceDebug, retryOptions, whoisDelay, logToConsoleAndFile);
            
            // Cache successful results (and certain types of failures)
            if (whoisResult.success || 
                (whoisResult.error && !whoisResult.isTimeout && 
                 !whoisResult.error.toLowerCase().includes('connection') &&
                 !whoisResult.error.toLowerCase().includes('network'))) {
              
              whoisResultCache.set(whoisCacheKey, {
                result: whoisResult,
                timestamp: now
              });
              
              if (forceDebug) {
                const cacheType = whoisResult.success ? 'successful' : 'failed';
                const serverInfo = selectedServer ? ` (server: ${selectedServer})` : ' (default server)';
                logToConsoleAndFile(`${messageColors.highlight('[whois-cache]')} Cached ${cacheType} result for ${domain}${serverInfo}`);
              }
            }
          } catch (whoisError) {
            // Handle exceptions from whois lookup
            if (forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Exception during lookup for ${domain}: ${whoisError.message}`);
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Exception type: ${whoisError.constructor.name}`);
              if (whoisError.stack) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Stack trace: ${whoisError.stack.split('\n').slice(0, 3).join(' -> ')}`);
              }
            }
            
            // Log whois exceptions in dry run mode
            if (dryRunCallback && forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} Exception: ${whoisError.message}`);
            }
            // Continue with dig if configured
            whoisResult = null; // Ensure we don't process a null result
          }
        }
        
        // Process whois result (whether from cache or fresh lookup)
        if (whoisResult) {
          
          if (whoisResult.success) {
            // Check AND terms if configured
            if (hasWhois) {
              whoisMatched = checkWhoisTerms(whoisResult.output, whoisTerms);
              if (whoisMatched && dryRunCallback) {
                dryRunCallback(domain, 'whois', 'AND logic', whoisTerms.join(', '), 'All terms found in whois data', {
                  server: whoisResult.whoisServer || 'default',
                  duration: whoisResult.duration,
                  fromCache: whoisResult.fromCache || false,
                  retryAttempts: whoisResult.retryInfo?.totalAttempts || 1
                });
              }
              if (forceDebug && siteConfig.verbose === 1) {
                logToConsoleAndFile(`${messageColors.highlight('[whois-and]')} Terms checked: ${whoisTerms.join(' AND ')}, matched: ${whoisMatched}`);
              }

            }
          
            // Check OR terms if configured
            if (hasWhoisOr) {
              whoisOrMatched = checkWhoisTermsOr(whoisResult.output, whoisOrTerms);
              if (whoisOrMatched && dryRunCallback) {
                const matchedTerm = whoisOrTerms.find(term => whoisResult.output.toLowerCase().includes(term.toLowerCase()));
                dryRunCallback(domain, 'whois', 'OR logic', matchedTerm, 'Term found in whois data', {
                  server: whoisResult.whoisServer || 'default',
                  duration: whoisResult.duration,
                  fromCache: whoisResult.fromCache || false,
                  retryAttempts: whoisResult.retryInfo?.totalAttempts || 1
                });
              }

              if (forceDebug && siteConfig.verbose === 1) {
                logToConsoleAndFile(`${messageColors.highlight('[whois-or]')} Terms checked: ${whoisOrTerms.join(' OR ')}, matched: ${whoisOrMatched}`);
              }
            }
            
            if (forceDebug) {
              const serverUsed = whoisResult.whoisServer ? ` (server: ${whoisResult.whoisServer})` : ' (default server)';
              const retryInfo = whoisResult.retryInfo ? ` [${whoisResult.retryInfo.totalAttempts}/${whoisResult.retryInfo.maxAttempts} attempts]` : '';
              const cacheInfo = whoisResult.fromCache ? ` [CACHED - ${Math.round(whoisResult.cacheAge / 1000)}s old]` : '';
              const duration = whoisResult.fromCache ? `cached in 0ms` : `in ${whoisResult.duration}ms`;
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Lookup completed for ${domain}${serverUsed} ${duration}${retryInfo}${cacheInfo}`);            
              
              if (whoisResult.retryInfo && whoisResult.retryInfo.retriedAfterFailure) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Success after retry - servers attempted: [${whoisResult.retryInfo.serversAttempted.map(s => s || 'default').join(', ')}]`);
              }
            }
          } else {
            // Enhanced error logging for failed whois lookups
            if (forceDebug) {
              const serverUsed = whoisResult.whoisServer ? ` (server: ${whoisResult.whoisServer})` : ' (default server)';
              const errorContext = whoisResult.isTimeout ? 'TIMEOUT' : 'ERROR';
              const retryInfo = whoisResult.retryInfo ? ` [${whoisResult.retryInfo.totalAttempts}/${whoisResult.retryInfo.maxAttempts} attempts]` : '';
              
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} ${errorContext}: Lookup failed for ${domain}${serverUsed} after ${whoisResult.duration}ms${retryInfo}`);
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Command executed: ${whoisResult.command || 'unknown'}`);
              logToConsoleAndFile(`${messageColors.highlight('[whois]')} Error details: ${whoisResult.error}`);
              
              // Enhanced server debugging for failures
              if (whoisResult.whoisServer) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Failed server: ${whoisResult.whoisServer} (custom)`);
              } else {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Failed server: system default whois server`);
              }
              
              
              if (whoisResult.retryInfo) {
                if (whoisResult.retryInfo.allAttemptsFailed) {
                  logToConsoleAndFile(`${messageColors.highlight('[whois]')} All retry attempts failed. Servers tried: [${whoisResult.retryInfo.serversAttempted.map(s => s || 'default').join(', ')}]`);
                }
                
                if (whoisResult.retryInfo.retriedAfterFailure) {
                  logToConsoleAndFile(`${messageColors.highlight('[whois]')} Retries were attempted but ultimately failed`);
                }
              }
              
              if (whoisResult.isTimeout) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Timeout exceeded limit after all retry attempts`);
                if (Array.isArray(whoisServer) && whoisServer.length > 1) {
                  const remainingServers = whoisServer.filter(s => !whoisResult.retryInfo?.serversAttempted.includes(s));
                  if (remainingServers.length > 0) {
                    logToConsoleAndFile(`${messageColors.highlight('[whois]')} Unused servers from config: ${remainingServers.join(', ')}`);
                  }
                } else {
                  // Suggest alternative servers based on domain TLD
                  const suggestions = suggestWhoisServers(domain, whoisResult.whoisServer).slice(0, 3);
                  if (suggestions.length > 0) {
                    logToConsoleAndFile(`${messageColors.highlight('[whois]')} Suggested alternative servers: ${suggestions.join(', ')}`);
                  }
                }
                // Show specific rate limiting advice
                if (whoisResult.error.toLowerCase().includes('too fast') || whoisResult.error.toLowerCase().includes('rate limit')) {
                  logToConsoleAndFile(`${messageColors.highlight('[whois]')} Rate limiting detected - consider increasing delays or using different servers`);
                  logToConsoleAndFile(`${messageColors.highlight('[whois]')} Current server: ${whoisResult.whoisServer || 'default'} may be overloaded`);
                }
              }
              
              // Log specific error patterns
              if (whoisResult.error.toLowerCase().includes('connection refused')) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Connection refused - server may be down or blocking requests`);
              } else if (whoisResult.error.toLowerCase().includes('no route to host')) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} Network connectivity issue to whois server`);
              } else if (whoisResult.error.toLowerCase().includes('name or service not known')) {
                logToConsoleAndFile(`${messageColors.highlight('[whois]')} DNS resolution failed for whois server`);
              }
            }
            
            // Log whois failures in dry run mode  
            if (dryRunCallback && forceDebug) {
              const errorType = whoisResult.isTimeout ? 'TIMEOUT' : 'ERROR';
              logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} ${errorType}: ${whoisResult.error}`);
              if (whoisResult.retryInfo?.allAttemptsFailed) {
                logToConsoleAndFile(`${messageColors.highlight('[whois-dryrun]')} All ${whoisResult.retryInfo.totalAttempts} retry attempts failed`);
              }
            }
            // Don't return early - continue with dig if configured
          }
        }
        
        // Periodic whois cache cleanup to prevent memory leaks
        if (whoisResultCache.size > MAX_CACHE_SIZE) {
          const now = Date.now();
          let cleanedCount = 0;
          for (const [key, entry] of whoisResultCache.entries()) {
            if (now - entry.timestamp > WHOIS_CACHE_TTL) {
              whoisResultCache.delete(key);
              cleanedCount++;
            }
          }
          if (forceDebug && cleanedCount > 0) {
            logToConsoleAndFile(`${messageColors.highlight('[whois-cache]')} Cleaned ${cleanedCount} expired entries, cache size: ${whoisResultCache.size}`);
          }
        }
      }
      
      // Perform dig lookup if configured
      if (needsDigLookup) {
        // Mark dig domain as being processed
        processedDigDomains.add(digDomain);
        
        if (forceDebug) {
          const digTypes = [];
          if (hasDig) digTypes.push('dig-and');
          if (hasDigOr) digTypes.push('dig-or');
          logToConsoleAndFile(`${messageColors.highlight('[dig]')} Performing dig lookup for ${digDomain} (${digRecordType}) [${digTypes.join(' + ')}]${digSubdomain ? ' [subdomain mode]' : ''}`);
        }
        
        try {
          // Check dig cache first to avoid redundant dig operations
          const digCacheKey = `${digDomain}-${digRecordType}`;
          const now = Date.now();
          let digResult = null;
          
          if (digResultCache.has(digCacheKey)) {
            const cachedEntry = digResultCache.get(digCacheKey);
            if (now - cachedEntry.timestamp < DIG_CACHE_TTL) {
              if (forceDebug) {
                logToConsoleAndFile(`${messageColors.highlight('[dig-cache]')} Using cached result for ${digDomain} (${digRecordType}) [age: ${Math.round((now - cachedEntry.timestamp) / 1000)}s]`);
              }
              digResult = cachedEntry.result;
            } else {
              // Cache expired, remove it
              digResultCache.delete(digCacheKey);
            }
          }
          
          if (!digResult) {
          digResult = await digLookup(digDomain, digRecordType, 5000); // 5 second timeout for dig
            
            // Cache the result for future use
            digResultCache.set(digCacheKey, {
              result: digResult,
              timestamp: now
            });
            
            if (forceDebug && digResult.success) {
              logToConsoleAndFile(`${messageColors.highlight('[dig-cache]')} Cached new result for ${digDomain} (${digRecordType})`);
            }
          }
          
          if (digResult.success) {
            // Check AND terms if configured
            if (hasDig) {
              digMatched = checkDigTerms(digResult.output, digTerms);
              if (digMatched && dryRunCallback) {
                dryRunCallback(domain, 'dig', 'AND logic', digTerms.join(', '), `All terms found in ${digRecordType} records`, {
                  queriedDomain: digDomain,
                  recordType: digRecordType,
                  subdomainMode: digSubdomain
                });
              }
            }
            
            // Check OR terms if configured
            if (hasDigOr) {
              digOrMatched = checkDigTermsOr(digResult.output, digOrTerms);
              if (digOrMatched && dryRunCallback) {
                const matchedTerm = digOrTerms.find(term => digResult.output.toLowerCase().includes(term.toLowerCase()));
                dryRunCallback(domain, 'dig', 'OR logic', matchedTerm, `Term found in ${digRecordType} records`, {
                  queriedDomain: digDomain,
                  recordType: digRecordType,
                  subdomainMode: digSubdomain
                });
              }
            }
            
            if (forceDebug) {
              if (siteConfig.verbose === 1) {
                if (hasDig) logToConsoleAndFile(`${messageColors.highlight('[dig-and]')} Terms checked: ${digTerms.join(' AND ')}, matched: ${digMatched}`);
                if (hasDigOr) logToConsoleAndFile(`${messageColors.highlight('[dig-or]')} Terms checked: ${digOrTerms.join(' OR ')}, matched: ${digOrMatched}`);
              }
              logToConsoleAndFile(`${messageColors.highlight('[dig]')} Lookup completed for ${digDomain}, dig-and: ${digMatched}, dig-or: ${digOrMatched}`);
              if (siteConfig.verbose === 1) {
                if (hasDig) logToConsoleAndFile(`${messageColors.highlight('[dig]')} AND terms: ${digTerms.join(', ')}`);
                if (hasDigOr) logToConsoleAndFile(`${messageColors.highlight('[dig]')} OR terms: ${digOrTerms.join(', ')}`);
                logToConsoleAndFile(`${messageColors.highlight('[dig]')} Short output: ${digResult.shortOutput}`);
              }
            }
          } else {
            if (forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[dig]')} Lookup failed for ${digDomain}: ${digResult.error}`);
            }
            
            // Log dig failures in dry run mode
            if (dryRunCallback && forceDebug) {
              logToConsoleAndFile(`${messageColors.highlight('[dig-dryrun]')} Failed: ${digResult.error}`);
            }
          }
        } catch (digError) {
          if (forceDebug) {
            logToConsoleAndFile(`${messageColors.highlight('[dig]')} Exception during lookup for ${digDomain}: ${digError.message}`);
          }
          
          // Log dig exceptions in dry run mode
          if (dryRunCallback && forceDebug) {
            logToConsoleAndFile(`${messageColors.highlight('[dig-dryrun]')} Exception: ${digError.message}`);
          }
        }
        
        // Periodic dig cache cleanup to prevent memory leaks
        if (digResultCache.size > DIG_MAX_CACHE_SIZE) {
          const now = Date.now();
          let cleanedCount = 0;
          for (const [key, entry] of digResultCache.entries()) {
            if (now - entry.timestamp > DIG_CACHE_TTL) {
              digResultCache.delete(key);
              cleanedCount++;
            }
          }
          if (forceDebug && cleanedCount > 0) {
            logToConsoleAndFile(`${messageColors.highlight('[dig-cache]')} Cleaned ${cleanedCount} expired entries, cache size: ${digResultCache.size}`);
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
        // Add to matched domains only if not in dry run mode
        if (dryRunCallback) {
          // In dry run mode, the callback has already been called above
          // Add comprehensive dry run logging
          if (forceDebug) {
            const matchType = [];
            if (hasWhois && whoisMatched) matchType.push('whois-and');
            if (hasWhoisOr && whoisOrMatched) matchType.push('whois-or');
            if (hasDig && digMatched) matchType.push(digSubdomain ? 'dig-and-subdomain' : 'dig-and');
            if (hasDigOr && digOrMatched) matchType.push(digSubdomain ? 'dig-or-subdomain' : 'dig-or');
            logToConsoleAndFile(`${messageColors.highlight('[nettools-dryrun]')} ${domain} would match via ${matchType.join(' + ')}`);
          }

          // Show what adblock rule would be generated
          if (forceDebug) {
            const adblockRule = `||${domain}^`;
            logToConsoleAndFile(`${messageColors.highlight('[nettools-dryrun]')} Would generate adblock rule: ${adblockRule}`);
          }
          // No need to add to matched domains
        } else {
          if (typeof addMatchedDomain === 'function') {
            addMatchedDomain(domain, null, fullSubdomain);
          } else {
            matchedDomains.add(domain);
          }
        }
        
        const simplifiedUrl = config.currentUrl ? getRootDomain(config.currentUrl) : 'unknown';
        
        if (siteConfig.verbose === 1) {
          const matchType = [];
          if (hasWhois && whoisMatched) matchType.push('whois-and');
          if (hasWhoisOr && whoisOrMatched) matchType.push('whois-or');
          if (hasDig && digMatched) matchType.push(digSubdomain ? 'dig-and-subdomain' : 'dig-and');
          if (hasDigOr && digOrMatched) matchType.push(digSubdomain ? 'dig-or-subdomain' : 'dig-or');
          logToConsoleAndFile(`[${simplifiedUrl}] ${domain} matched via ${matchType.join(' + ')}`);
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
      
    } catch (timeoutError) {
      if (timeoutError.message.includes('NetTools overall timeout')) {
        if (forceDebug) {
          logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Overall timeout for domain ${domain}: ${timeoutError.message}`);
        }
        // Don't rethrow - continue processing other domains
        return;
      }
     try {
       throw timeoutError; // Re-throw other errors
     } catch (error) {
       if (forceDebug) {
         logToConsoleAndFile(`${messageColors.highlight('[nettools]')} Error processing ${domain}: ${error.message}`);
       }
       // Silently fail and continue - don't block other processing
     }
   }
      

   } // End of executeNetToolsLookup function
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
  createEnhancedDryRunCallback,
  selectWhoisServer,
  getCommonWhoisServers,
  suggestWhoisServers,
  execWithTimeout // Export for testing
};
