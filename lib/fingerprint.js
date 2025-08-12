// === Enhanced Fingerprint Protection Module - Puppeteer 23.x Compatible ===
// This module handles advanced browser fingerprint spoofing, user agent changes,
// and comprehensive bot detection evasion techniques.

// Default values for fingerprint spoofing if not set to 'random'
const DEFAULT_PLATFORM = 'Win32';
const DEFAULT_TIMEZONE = 'America/New_York';

 /**
 * Built-in properties that should not be modified to avoid browser detection
 */
const BUILT_IN_PROPERTIES = [
  'href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash',
  'constructor', 'prototype', '__proto__', 'toString', 'valueOf',
  'assign', 'reload', 'replace' // Additional location object methods
];

/**
 * Checks if a property is a built-in that shouldn't be modified
 */
function isBuiltInProperty(target, property) {
  
  // Special handling for Location object properties
  if (target === window.location || (target.constructor && target.constructor.name === 'Location')) {
    return ['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash'].includes(property);
  }
  
  return BUILT_IN_PROPERTIES.includes(property);
}

/**
 * Creates a safe property descriptor for Puppeteer 23.x
 */
function createSafeDescriptor(descriptor, existingDescriptor) {
  const safeDescriptor = { ...descriptor };
  
  // Always ensure configurable is true unless specifically set to false
  if (safeDescriptor.configurable !== false) {
    safeDescriptor.configurable = true;
  }
  
  // Preserve existing enumerable state if not specified
  if (safeDescriptor.enumerable === undefined && existingDescriptor) {
    safeDescriptor.enumerable = existingDescriptor.enumerable;
  }
  
  // Ensure writable is properly set for data descriptors
  if ('value' in safeDescriptor && safeDescriptor.writable === undefined) {
    safeDescriptor.writable = true;
  }
  
  return safeDescriptor;
}

/**
 * Safely defines or redefines a property with error handling for Puppeteer 23.x
 * @param {Object} target - Target object 
 * @param {string} property - Property name
 * @param {Object} descriptor - Property descriptor
 * @param {boolean} forceDebug - Debug logging flag
 */
function safeDefineProperty(target, property, descriptor, forceDebug = false) {
  try {
    // Enhanced validation before attempting to modify
    if (!canModifyProperty(target, property, forceDebug)) {
      return false;
    }
    const existingDescriptor = Object.getOwnPropertyDescriptor(target, property);

    // Enhanced validation for Puppeteer 23.x
    if (existingDescriptor) {
      // Check if it's a built-in property that shouldn't be modified
      if (isBuiltInProperty(target, property)) {
        if (forceDebug) {
          console.log(`[fingerprint] Skipping built-in property: ${property}`);
        }
        return false;
      }
      
      // Check if property is truly non-configurable
      if (existingDescriptor.configurable === false) {
        if (forceDebug) {
          console.log(`[fingerprint] Cannot redefine non-configurable property: ${property}`);
        }
        return false;
      }
    }
    
    // Enhanced descriptor validation
    const safeDescriptor = createSafeDescriptor(descriptor, existingDescriptor);
    
    Object.defineProperty(target, property, safeDescriptor);
    return true;
  } catch (defineErr) {
    if (forceDebug) {
      console.log(`[fingerprint] Property definition failed for ${property}: ${defineErr.message}`);
    }
    return false;
  }
}

/**
 * Enhanced validation for property modification with location object handling
 * Consolidated from canSafelyModifyProperty to avoid duplication
 */
function canModifyProperty(target, property, forceDebug = false) {
  try {
    // COMPREHENSIVE DEBUG: Log every canModifyProperty check
    if (forceDebug) {
      console.log(`[fingerprint] canModifyProperty called for: ${property} on target:`, target.constructor?.name || 'unknown');
      if (property === 'href') {
        console.log(`[fingerprint] CRITICAL: Checking if href can be modified!`);
        console.log(`[fingerprint] Target details:`, {
          isWindow: target === window,
          isLocation: target === window.location,
          constructorName: target.constructor?.name
        });
      }
    }
    
    // Check if it's a built-in property that shouldn't be modified
    if (isBuiltInProperty(target, property)) {
      if (forceDebug) {
        console.log(`[fingerprint] Skipping built-in property: ${property}`);
      }
      return false;
    }
    
    const descriptor = Object.getOwnPropertyDescriptor(target, property);
    if (!descriptor) return true; // Property doesn't exist, can be added
    
    return descriptor.configurable !== false;
  } catch (checkErr) {
    if (forceDebug) {
      console.log(`[fingerprint] Property check failed for ${property}: ${checkErr.message}`);
    }
    return false; // If we can't check, assume we can't modify
  }
}

/**
 * Safely executes fingerprint spoofing code with comprehensive error handling
 * @param {Function} spoofFunction - Function to execute
 * @param {string} description - Description of the spoofing operation
 * @param {boolean} forceDebug - Debug logging flag
 */
function safeExecuteSpoofing(spoofFunction, description, forceDebug = false) {
  try {
    spoofFunction();
    return true;
  } catch (spoofErr) {
    // Enhanced error categorization for Puppeteer 23.x
    const isCriticalError = spoofErr.message.includes('Cannot redefine property') ||
                           spoofErr.message.includes('non-configurable') ||
                           spoofErr.message.includes('Invalid property descriptor');
    
    if (forceDebug) {
      const errorLevel = isCriticalError ? 'CRITICAL' : 'WARNING';
      console.log(`[fingerprint] ${errorLevel} - ${description} failed: ${spoofErr.message}`);
    }
    // Continue execution - don't let spoofing failures break the scan
    return false;
  }
}

/**
 * Generates realistic screen resolutions based on common monitor sizes
 * @returns {object} Screen resolution object with width and height
 */
function getRealisticScreenResolution() {
  const commonResolutions = [
    { width: 1920, height: 1080 }, // Full HD - most common
    { width: 1366, height: 768 },  // Common laptop
    { width: 1440, height: 900 },  // MacBook Air
    { width: 1536, height: 864 },  // Scaled HD
    { width: 1600, height: 900 },  // 16:9 widescreen
    { width: 2560, height: 1440 }, // 1440p
    { width: 1280, height: 720 },  // 720p
    { width: 3440, height: 1440 }  // Ultrawide
  ];
  
  return commonResolutions[Math.floor(Math.random() * commonResolutions.length)];
}

/**
 * Generates an object with randomized but realistic browser fingerprint values.
 * This is used to spoof various navigator and screen properties to make
 * the headless browser instance appear more like a regular user's browser
 * and bypass fingerprint-based bot detection.
 *
 * @returns {object} An object containing the spoofed fingerprint properties
 */
function getRandomFingerprint() {
  const resolution = getRealisticScreenResolution();
  
  return {
    deviceMemory: [4, 8, 16, 32][Math.floor(Math.random() * 4)],
    hardwareConcurrency: [2, 4, 6, 8, 12, 16][Math.floor(Math.random() * 6)],
    screen: {
      width: resolution.width,
      height: resolution.height,
      availWidth: resolution.width,
      availHeight: resolution.height - 40, // Account for taskbar
      colorDepth: 24,
      pixelDepth: 24
    },
    platform: Math.random() > 0.3 ? 'Win32' : 'MacIntel',
    timezone: ['America/New_York', 'America/Los_Angeles', 'Europe/London', 'America/Chicago'][Math.floor(Math.random() * 4)],
    language: ['en-US', 'en-GB', 'en-CA'][Math.floor(Math.random() * 3)],
    cookieEnabled: true,
    doNotTrack: Math.random() > 0.7 ? '1' : null
  };
}

/**
 * Enhanced user agent spoofing with latest browser versions and comprehensive stealth protection
 * Compatible with Puppeteer 23.x
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.userAgent) return;

  if (forceDebug) console.log(`[debug] Enhanced userAgent spoofing enabled for ${currentUrl}: ${siteConfig.userAgent}`);
  
  // Updated user agents with latest browser versions
  const userAgents = {
    chrome: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ],
    firefox: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
      "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
    ],
    safari: [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
    ]
  };
  
  const selectedUserAgents = userAgents[siteConfig.userAgent.toLowerCase()];
  const ua = selectedUserAgents ? selectedUserAgents[Math.floor(Math.random() * selectedUserAgents.length)] : null;
  
  if (ua) {
    await page.setUserAgent(ua);
    
    // Apply comprehensive stealth protection when userAgent is set
    if (forceDebug) console.log(`[debug] Applying enhanced stealth protection for ${currentUrl}`);
    
    try {
      await page.evaluateOnNewDocument((userAgent, debugEnabled) => {
      
        // Helper function for safe property operations (local scope)
        function safeExecuteSpoofing(spoofFunction, description) {
          try {
            spoofFunction();
            return true;
          } catch (spoofErr) {
            if (debugEnabled) {
              console.log(`[fingerprint] ${description} failed: ${spoofErr.message}`);
            }
            return false;
          }
        }
        
        // Helper function for safe property definition (local scope)
        function safeDefineProperty(target, property, descriptor) {
          try {
            // COMPREHENSIVE DEBUG: Log every property definition attempt
            if (debugEnabled) {
              console.log(`[fingerprint] safeDefineProperty called for: ${property} on target:`, target.constructor?.name || 'unknown');
              if (property === 'href') {
                console.log(`[fingerprint] CRITICAL: Attempting to define href property!`);
              }
            }

            // Enhanced built-in property protection using global constant
            if (property === 'href' || ['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash', 'constructor', 'prototype', '__proto__', 'toString', 'valueOf', 'assign', 'reload', 'replace'].includes(property)) {
              if (debugEnabled) {
                console.log(`[fingerprint] BLOCKED: Built-in property ${property} blocked in safeDefineProperty`);
              }
              return false;
            }

            const existingDescriptor = Object.getOwnPropertyDescriptor(target, property);
            
            if (existingDescriptor && existingDescriptor.configurable === false) {
              if (debugEnabled) {
                console.log(`[fingerprint] Cannot redefine non-configurable property: ${property}`);
              }
              return false;
            }
            
            const safeDescriptor = {
              ...descriptor,
              configurable: true // Always use configurable: true for Puppeteer 23.x compatibility
            };
            
            Object.defineProperty(target, property, safeDescriptor);
            return true;
          } catch (defineErr) {
            if (debugEnabled) {
              console.log(`[fingerprint] Property definition failed for ${property}: ${defineErr.message}`);
            }
            return false;
          }
        }

        // Validate properties before attempting to modify them (local scope)
        function canModifyProperty(target, property) {
          try {
            // COMPREHENSIVE DEBUG: Log every canModifyProperty check
            if (debugEnabled) {
              console.log(`[fingerprint] canModifyProperty called for: ${property} on target:`, target.constructor?.name || 'unknown');
              if (property === 'href') {
                console.log(`[fingerprint] CRITICAL: Checking if href can be modified!`);
                console.log(`[fingerprint] Target details:`, {
                  isWindow: target === window,
                  isLocation: target === window.location,
                  constructorName: target.constructor?.name
                });
              }
            }
            
            // Enhanced built-in property check with location object handling
            const builtInProperties = ['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash', 'constructor', 'prototype', '__proto__', 'toString', 'valueOf', 'assign', 'reload', 'replace'];

            // Special handling for Location object properties
            if (target === window.location || (target.constructor && target.constructor.name === 'Location')) {
              const locationProperties = ['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash'];
              if (locationProperties.includes(property)) {
                if (debugEnabled) {
                  console.log(`[fingerprint] Skipping location property: ${property}`);
                }
                return false;
              }
            }
            
            if (builtInProperties.includes(property)) {
              if (debugEnabled) {
                console.log(`[fingerprint] Skipping built-in property: ${property}`);
              }
              return false;
            }
            
            const descriptor = Object.getOwnPropertyDescriptor(target, property);
            if (!descriptor) return true; // Property doesn't exist, can be added
            
            return descriptor.configurable !== false;
          } catch (checkErr) {
            return false; // If we can't check, assume we can't modify
          }
        }
      
        // GLOBAL HREF PROTECTION: Override Object.defineProperty to block ALL href modifications
        const originalDefineProperty = Object.defineProperty;
        Object.defineProperty = function(target, property, descriptor) {
          // Block ALL attempts to redefine href anywhere
          if (property === 'href') {
            if (debugEnabled) {
              console.log(`[fingerprint] GLOBAL BLOCK: Prevented ${property} redefinition on:`, target.constructor?.name || 'unknown');
              console.trace('[fingerprint] Call stack for blocked href:');
            }
            // Return false to indicate failure, but don't throw
            return false;
          }
          
          // Block other location properties too
          const locationProps = ['origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash'];
          if (locationProps.includes(property)) {
            if (debugEnabled) {
              console.log(`[fingerprint] GLOBAL BLOCK: Prevented location property ${property} redefinition on:`, target.constructor?.name || 'unknown');
            }
            return false;
          }
          
          // For all other properties, use the original function
          try {
            return originalDefineProperty.apply(this, arguments);
          } catch (err) {
            if (debugEnabled) {
              console.log(`[fingerprint] Original defineProperty failed for ${property}:`, err.message);
            }
            return false;
          }
        };
        
        // GLOBAL NULL PROTECTION: Prevent "Cannot read properties of null" errors
        const originalGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
        Object.getOwnPropertyDescriptor = function(target, property) {
          if (!target) {
            if (debugEnabled) {
              console.log(`[fingerprint] NULL TARGET: Prevented property access on null target for property: ${property}`);
            }
            return undefined;
          }
          return originalGetOwnPropertyDescriptor.apply(this, arguments);
        };
        
        // Add safe property access wrapper
        window.safePropertyAccess = function(obj, property, defaultValue = null) {
          try {
            return (obj && obj[property] !== undefined) ? obj[property] : defaultValue;
          } catch (err) {
            return defaultValue;
          }
        };
        
        // Enhanced null object protection for property access
        const originalHasOwnProperty = Object.prototype.hasOwnProperty;
        Object.prototype.hasOwnProperty = function(property) {
          if (this === null || this === undefined) {
            if (debugEnabled && property === 'fp') {
              console.log(`[fingerprint] NULL OBJECT: Prevented hasOwnProperty('${property}') on null/undefined`);
            }
            return false;
          }
          return originalHasOwnProperty.call(this, property);
        };
        
        // Enhanced undefined object protection for method access
        const originalPropertyAccess = Object.getOwnPropertyDescriptor;
        
        // Global protection against undefined method access
        const createSafeMethodProxy = (methodName) => {
          return function(...args) {
            if (debugEnabled) {
              console.log(`[fingerprint] Safe ${methodName} proxy called with args:`, args);
            }
            // For alert specifically, show the message safely
            if (methodName === 'alert' && args.length > 0) {
              try {
                window.alert(args[0]);
              } catch (alertErr) {
                if (debugEnabled) {
                  console.log(`[fingerprint] Safe alert failed, logging instead: ${args[0]}`);
                }
                console.log(`[Alert] ${args[0]}`);
              }
            }
            // For other methods, just return a safe empty function
            return undefined;
          };
        };
        
        // Create safe global methods that might be accessed on undefined objects
        window.safeAlert = createSafeMethodProxy('alert');
        window.safeConfirm = createSafeMethodProxy('confirm');
        window.safePrompt = createSafeMethodProxy('prompt');

        // Global error handler for fingerprinting access errors
        const originalErrorHandler = window.onerror;
        window.onerror = function(message, source, lineno, colno, error) {
          // Handle fingerprinting-related null access errors
          if (typeof message === 'string' && (
              message.includes("Cannot read properties of null (reading 'fp')") ||
              message.includes("Cannot read property 'fp' of null") ||
              message.includes("Cannot read properties of undefined (reading 'alert')") ||
              message.includes("Cannot read property 'alert' of undefined") ||
              message.includes("Cannot read properties of undefined (reading 'confirm')") ||
              message.includes("Cannot read properties of undefined (reading 'prompt')") ||
              message.includes("fp is not defined") ||
              message.includes("alert is not defined") ||
              message.includes("is not a function") ||
              message.includes("Cannot read properties of undefined (reading") ||
              message.includes("Cannot read properties of null (reading") ||
              message.includes("fingerprint") && message.includes("null")
            )) {
            if (debugEnabled) {
              console.log(`[fingerprint] Suppressed fingerprinting null access error: ${message}`);
            }
            return true; // Prevent error from showing in console
          }
          
          // Call original error handler for other errors
          if (originalErrorHandler) {
            return originalErrorHandler.apply(this, arguments);
          }
          return false;
        };

     // CRITICAL: Simplified CDP Detection Prevention
     // Prevents detection via Chrome DevTools Protocol Error.stack analysis
     safeExecuteSpoofing(() => {
       // Store original Error constructor
       const OriginalError = window.Error;
       
       // Override Error constructor to prevent CDP detection
       window.Error = function(...args) {
         const error = new OriginalError(...args);
         
         // Get original stack descriptor to preserve behavior
         const originalStackDescriptor = Object.getOwnPropertyDescriptor(error, 'stack') ||
                                       Object.getOwnPropertyDescriptor(OriginalError.prototype, 'stack');
         
         // Override stack property to prevent CDP detection via Error.stack getter
         Object.defineProperty(error, 'stack', {
           get: function() {
             // This is the critical part - prevent CDP detection flag from being set
             // Anti-bot systems set a flag when Error.stack getter is accessed
             
             let stack;
             if (originalStackDescriptor && originalStackDescriptor.get) {
               try {
                 stack = originalStackDescriptor.get.call(this);
               } catch (stackErr) {
                 stack = 'Error\n    at unknown location';
               }
             } else if (originalStackDescriptor && originalStackDescriptor.value) {
               stack = originalStackDescriptor.value;
             } else {
               // Fallback stack trace
               stack = `${this.name || 'Error'}: ${this.message || ''}\n    at unknown location`;
             }
             
             // Clean automation traces from stack if present
             if (typeof stack === 'string') {
               stack = stack
                 .replace(/.*puppeteer.*\n?/gi, '')
                 .replace(/.*chrome-devtools.*\n?/gi, '')
                 .replace(/.*webdriver.*\n?/gi, '')
                 .replace(/.*automation.*\n?/gi, '')
                 .replace(/\n\s*\n/g, '\n')
                 .trim();
               
               // Ensure we always have a valid stack
               if (!stack) {
                 stack = `${this.name || 'Error'}: ${this.message || ''}\n    at unknown location`;
               }
             }
             
             return stack;
           },
           set: function(value) {
             // Allow stack to be set normally
             if (originalStackDescriptor && originalStackDescriptor.set) {
               originalStackDescriptor.set.call(this, value);
             } else {
               // Create internal property if no setter exists
               Object.defineProperty(this, '_internalStack', {
                 value: value,
                 writable: true,
                 configurable: true
               });
             }
           },
           configurable: true,
           enumerable: false
         });
         
         return error;
       };
       
       // Preserve Error prototype and constructor properties
       window.Error.prototype = OriginalError.prototype;
       Object.setPrototypeOf(window.Error, OriginalError);
       
       // Copy essential static properties
       ['captureStackTrace', 'stackTraceLimit', 'prepareStackTrace'].forEach(prop => {
         if (OriginalError[prop]) {
           try {
             window.Error[prop] = OriginalError[prop];
           } catch (propErr) {
             // Ignore if property can't be copied
           }
         }
       });
       
       // Enhanced Error.captureStackTrace protection
       if (OriginalError.captureStackTrace) {
         window.Error.captureStackTrace = function(targetObject, constructorOpt) {
           try {
             const result = OriginalError.captureStackTrace.call(this, targetObject, constructorOpt);
             
             // Clean captured stack trace
             if (targetObject && targetObject.stack && typeof targetObject.stack === 'string') {
               targetObject.stack = targetObject.stack
                 .replace(/.*puppeteer.*\n?/gi, '')
                 .replace(/.*chrome-devtools.*\n?/gi, '')
                 .replace(/.*webdriver.*\n?/gi, '')
                 .replace(/.*automation.*\n?/gi, '')
                 .replace(/\n\s*\n/g, '\n')
                 .trim();
             }
             
             return result;
           } catch (captureErr) {
             if (debugEnabled) {
               console.log('[fingerprint] captureStackTrace error handled:', captureErr.message);
             }
             return undefined;
           }
         };
       }
       
       // Prevent global CDP detection flag
       try {
         Object.defineProperty(window, 'cdpDetected', {
           get: () => false,
           set: () => false,
           configurable: false,
           enumerable: false
         });
       } catch (cdpPropErr) {
         // Ignore if property already exists
       }
       
       // Additional protection: prevent common CDP detection patterns
       const cdpDetectionStrings = ['cdpDetected', 'chromeDevtools', 'runtimeEvaluate'];
       cdpDetectionStrings.forEach(str => {
         try {
           if (!window[str]) {
             Object.defineProperty(window, str, {
               get: () => false,
               set: () => false,
               configurable: false,
               enumerable: false
             });
           }
         } catch (strErr) {
           // Ignore property definition errors
         }
       });
       
       if (debugEnabled) {
         console.log('[fingerprint] Simplified CDP detection prevention installed - Error constructor protected');
       }
       
     }, 'Simplified CDP Detection Prevention');
     
     // Test function for CDP detection (only in debug mode)
     if (debugEnabled) {
       try {
         let testCdpDetected = false;
         const testError = new Error('test');
         
         // Simulate anti-bot CDP detection attempt
         Object.defineProperty(testError, 'stack', {
           get() {
             testCdpDetected = true;
             return 'test stack trace';
           }
         });
         
         // Access stack - should NOT trigger detection with our patch
         const testStack = testError.stack;
         
         console.log(`[fingerprint] CDP protection test: ${testCdpDetected ? 'FAILED - Detection triggered!' : 'PASSED - Protection working'}`);
       } catch (testErr) {
         console.log('[fingerprint] CDP test error:', testErr.message);
       }
     }

        // COMPREHENSIVE FINGERPRINTING MOCK OBJECTS
        // Create enhanced mock fingerprinting objects that might be expected
        window.fp = window.fp || {
          getResult: (callback) => {
            const result = {
              visitorId: 'mock_visitor_id_' + Math.random().toString(36).substring(7),
              confidence: { score: 0.99 },
              components: {
                screen: { value: { width: 1920, height: 1080 } },
                timezone: { value: 'America/New_York' },
                language: { value: 'en-US' }
              }
            };
            if (typeof callback === 'function') {
              try {
                setTimeout(() => callback(result), 0);
              } catch (callbackErr) {
                if (debugEnabled) console.log(`[fingerprint] FP callback error: ${callbackErr.message}`);
              }
            }
            return result;
          },
          get: (callback) => {
            const result = {
              visitorId: 'mock_visitor_id_' + Math.random().toString(36).substring(7),
              confidence: { score: 0.99 },
              components: {}
            };
            if (typeof callback === 'function') {
              try {
                setTimeout(() => callback(result), 0);
              } catch (callbackErr) {
                if (debugEnabled) console.log(`[fingerprint] FP.get callback error: ${callbackErr.message}`);
              }
            }
            return Promise.resolve(result);
          },
          load: () => Promise.resolve(window.fp),
          components: {
            screen: { value: { width: 1920, height: 1080 } }
          },
          x64hash128: () => 'mock_hash',
          tz: 'America/New_York', // Mock timezone
          timezone: 'America/New_York'
        };
        
        // Enhanced timezone protection - create comprehensive timezone objects
        window.timezone = window.timezone || 'America/New_York';
        // Create comprehensive FingerprintJS mock objects
        window.FingerprintJS = window.FingerprintJS || {
          load: (options) => Promise.resolve({
            get: (getOptions) => Promise.resolve({
              visitorId: 'mock_visitor_id_' + Math.random().toString(36).substring(7),
              confidence: { score: 0.99 },
              components: {}
            })
          })
        };
        
        // Mock other common fingerprinting libraries that might access .fp
        window.ClientJS = window.ClientJS || function() {
          this.getFingerprint = () => 'mock_fingerprint_' + Math.random().toString(36).substring(7);
          this.getBrowser = () => 'Chrome';
          this.getOS = () => 'Windows';
          this.fp = {}; // Prevent null access
        };
        
        // Create safe proxy wrapper for fingerprinting objects
        const createFingerprintProxy = (targetName) => {
          if (!window[targetName]) {
            window[targetName] = new Proxy({}, {
              get: (target, prop) => {
                if (debugEnabled && prop === 'fp') {
                  console.log(`[fingerprint] Safe proxy accessed: ${targetName}.fp`);
                }
                if (prop === 'fp') {
                  return {}; // Return safe empty object for .fp access
                }
                // Handle common method access on undefined objects
                if (prop === 'alert') {
                  return window.safeAlert;
                }
                if (prop === 'confirm') {
                  return window.safeConfirm;
                }
                if (prop === 'prompt') {
                  return window.safePrompt;
                }
                // Return safe empty function for other method-like properties
                if (typeof target[prop] === 'undefined' && prop.endsWith && (prop.endsWith('alert') || prop.endsWith('confirm') || prop.endsWith('prompt'))) {
                  return createSafeMethodProxy(prop);
                }
                return target[prop] || undefined;
              }
            });
          }
        };
        
        // Create safe proxies for common fingerprinting object names
        ['fpjs', 'fingerprint', 'deviceFingerprint', 'browserFingerprint', 'fpCollector'].forEach(createFingerprintProxy);

        // Enhanced protection for common undefined object method access patterns
        const commonObjectNames = ['popup', 'modal', 'dialog', 'notification', 'banner', 'overlay', 'widget'];
        commonObjectNames.forEach(objName => {
          if (!window[objName]) {
            window[objName] = new Proxy({}, {
              get: (target, prop) => {
                if (debugEnabled && ['alert', 'confirm', 'prompt'].includes(prop)) {
                  console.log(`[fingerprint] Safe proxy method accessed: ${objName}.${prop}`);
                }
                if (prop === 'alert') {
                  return window.safeAlert;
                }
                if (prop === 'confirm') {
                  return window.safeConfirm;
                }
                if (prop === 'prompt') {
                  return window.safePrompt;
                }
                // Return safe function for any other method access
                return () => undefined;
              }
            });
          }
        });
        
        // Global protection for undefined objects accessing dialog methods
        const originalAlert = window.alert;
        const originalConfirm = window.confirm;
        const originalPrompt = window.prompt;
        
        // Ensure these methods are always available and safe
        window.alert = window.alert || function(message) {
          console.log(`[Alert] ${message}`);
        };
        window.confirm = window.confirm || function(message) {
          console.log(`[Confirm] ${message}`);
          return false;
        };
        window.prompt = window.prompt || function(message, defaultValue) {
          console.log(`[Prompt] ${message}`);
          return defaultValue || null;
        };
       

        window.timeZone = window.timeZone || 'America/New_York';
        
        // Comprehensive Date prototype protection
        const originalDateToString = Date.prototype.toString;
        Date.prototype.toString = function() {
          try {
            return originalDateToString.call(this);
          } catch (err) {
            return new Date().toISOString();
          }
        };
        
        const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
        Date.prototype.getTimezoneOffset = function() {
          try {
            return originalGetTimezoneOffset.call(this);
          } catch (err) {
            return 300; // EST offset as fallback
          }
        };
        
        // Override navigator.timezone related properties
        if (navigator && !navigator.timezone) {
          Object.defineProperty(navigator, 'timezone', {
            get: () => 'America/New_York',
            configurable: true
          });
        }
        
        // Protect common timezone detection methods
        window.getTimezone = window.getTimezone || (() => 'America/New_York');
        window.getTimezoneOffset = window.getTimezoneOffset || (() => 300);
        
        // Create jstz-like object (common timezone detection library)
        window.jstz = window.jstz || {
          determine: () => ({ name: () => 'America/New_York' }),
          olson: { timezones: { 'America/New_York': true } }
        };
        
        // Create mock timezone object
        window.tz = window.tz || {
          name: 'America/New_York',
          offset: -300,
          abbr: 'EST',
          dst: false,
          getTimezoneOffset: () => 300
        };
        
        // Ensure Intl.DateTimeFormat resolvedOptions returns safe values
        if (window.Intl && window.Intl.DateTimeFormat) {
          const OriginalDateTimeFormat = window.Intl.DateTimeFormat;
          window.Intl.DateTimeFormat = function(...args) {
            const instance = new OriginalDateTimeFormat(...args);
            const originalResolvedOptions = instance.resolvedOptions;
            
            instance.resolvedOptions = function() {
              try {
                const options = originalResolvedOptions.call(this);
                // Ensure timezone is always set to prevent null errors
                if (!options.timeZone) {
                  options.timeZone = 'America/New_York';
                }
                return options;
              } catch (err) {
                // Return safe default options if resolvedOptions fails
                return {
                  locale: 'en-US',
                  timeZone: 'America/New_York',
                  calendar: 'gregory',
                  numberingSystem: 'latn'
                };
              }
            };
            return instance;
          };
          
          // Copy static methods
          Object.setPrototypeOf(window.Intl.DateTimeFormat, OriginalDateTimeFormat);
        };

        
        // JavaScript Library Protection - Create mock objects for common libraries
        // jQuery protection
        if (typeof window.$ === 'undefined') {
          window.$ = function(selector) {
            // Return a minimal jQuery-like object
            return {
              ready: function(fn) { if (typeof fn === 'function') setTimeout(fn, 0); return this; },
              on: function() { return this; },
              off: function() { return this; },
              click: function() { return this; },
              hide: function() { return this; },
              show: function() { return this; },
              css: function() { return this; },
              attr: function() { return this; },
              html: function() { return this; },
              text: function() { return this; },
              val: function() { return this; },
              addClass: function() { return this; },
              removeClass: function() { return this; },
              length: 0,
              each: function() { return this; }
            };
          };
          // Common jQuery aliases
          window.jQuery = window.$;
        }
        
        // Other common library protections
        window._ = window._ || { // Lodash/Underscore
          forEach: function() {},
          map: function() { return []; },
          filter: function() { return []; },
          find: function() { return undefined; }
        };
        
        window.moment = window.moment || function() { // Moment.js
          return {
            format: function() { return new Date().toISOString(); },
            valueOf: function() { return Date.now(); }
          };
        };
        
        // Enhanced console error handling for library errors
        const originalConsoleError = console.error;
        console.error = function(...args) {
          const message = args.join(' ');
          // Suppress common library error messages
          if (typeof message === 'string' && (
              message.includes('$ is not defined') ||
              message.includes('jQuery is not defined') ||
              message.includes('_ is not defined') ||
              message.includes('moment is not defined') ||
              message.includes('bootstrap is not defined') ||
              message.includes('is not a function') ||
              message.includes('Cannot read property') ||
              message.includes('Cannot read properties of undefined') ||
              message.includes('Cannot read properties of null') ||
              message.includes('.closest is not a function') ||
              message.includes('.toLowerCase') ||
              message.includes('is not valid JSON')
            )) {
            if (debugEnabled) {
              console.log(`[fingerprint] Suppressed library error: ${message}`);
            }
            return; // Don't log the error
          }
          // For all other errors, use original console.error
          return originalConsoleError.apply(this, arguments);
        };

        // Enhanced TZ Check Protection - Handle timezone validation functions
        window.tzCheck = window.tzCheck || function() {
          return 'America/New_York';
        };
        
        window.checkTimezone = window.checkTimezone || function() {
          return true;
        };
        
        window.validateTimezone = window.validateTimezone || function() {
          return { valid: true, timezone: 'America/New_York' };
        };
        
        // Mock common timezone libraries and their methods
        window.momentTimezone = window.momentTimezone || {
          tz: {
            guess: () => 'America/New_York',
            names: () => ['America/New_York'],
            zone: () => ({ name: 'America/New_York', abbr: 'EST' })
          }
        };
        
        // Enhanced Intl timezone protection
        if (window.Intl) {
          // Override supportedLocalesOf to always return safe values
          if (window.Intl.DateTimeFormat && window.Intl.DateTimeFormat.supportedLocalesOf) {
            const originalSupportedLocales = window.Intl.DateTimeFormat.supportedLocalesOf;
            window.Intl.DateTimeFormat.supportedLocalesOf = function(locales, options) {
              try {
                return originalSupportedLocales.call(this, locales, options);
              } catch (err) {
                return ['en-US'];
              }
            };
          }
          
          // Add resolvedOptions protection to all Intl objects
          ['DateTimeFormat', 'NumberFormat', 'Collator'].forEach(intlType => {
            if (window.Intl[intlType]) {
              const OriginalIntl = window.Intl[intlType];
              window.Intl[intlType] = function(...args) {
                try {
                  return new OriginalIntl(...args);
                } catch (err) {
                  // Return basic mock object for any Intl constructor failures
                  return {
                    resolvedOptions: () => ({
                      locale: 'en-US',
                      timeZone: 'America/New_York',
                      calendar: 'gregory'
                    }),
                    format: () => new Date().toLocaleDateString()
                  };
                }
              };
              Object.setPrototypeOf(window.Intl[intlType], OriginalIntl);
            }
          });
        }
        
        // Global error handler enhancement for timezone-specific errors
        const originalWindowError = window.onerror;
        window.onerror = function(message, source, lineno, colno, error) {
          // Handle timezone-specific errors
          if (typeof message === 'string' && (
              message.includes('tz check') ||
              message.includes('timezone check') ||
              message.includes('tz is not defined') ||
              message.includes('timezone is not defined') ||
              message.includes('Invalid timezone') ||
              message.includes('TimeZone') ||
              message.includes('getTimezoneOffset')
            )) {
            if (debugEnabled) {
              console.log(`[fingerprint] Suppressed timezone error: ${message}`);
            }
            return true; // Prevent the error from showing
          }
          
          // Call original error handler for non-timezone errors
          if (originalWindowError) {
            return originalWindowError.apply(this, arguments);
          }
          return false;
        };

 

        // 1. Enhanced webdriver removal with safe descriptor manipulation
        safeExecuteSpoofing(() => {
          // Skip if navigator.webdriver is non-configurable
          if (!canModifyProperty(navigator, 'webdriver', debugEnabled)) {
            if (debugEnabled) {
              console.log('[fingerprint] Skipping non-configurable navigator.webdriver');
            }
            return;
          }

          try {
            delete navigator.webdriver;
          } catch (delErr) {
            // Deletion might fail, try to set to undefined
            try {
              navigator.webdriver = undefined;
            } catch (assignErr) {
              // Both deletion and assignment failed, skip
              if (debugEnabled) {
                console.log('[fingerprint] Cannot modify navigator.webdriver, skipping');
              }
              return;
            }
          }
          
          safeDefineProperty(navigator, 'webdriver', {
            get: () => undefined,
            enumerable: false,
            configurable: true
          }, debugEnabled);
        }, 'webdriver removal');
        
        // 2. Enhanced automation detection removal with safe handling
        const automationProps = [
          'callPhantom', '_phantom', '__nightmare', '_selenium',
          '__selenium_unwrapped', '__webdriver_evaluate', '__driver_evaluate',
          '__webdriver_script_function', '__webdriver_script_func',
          '__webdriver_script_fn', '__fxdriver_evaluate', '__driver_unwrapped',
          '__webdriver_unwrapped', '__selenium_evaluate', '__fxdriver_unwrapped',
          'spawn', 'emit', 'Buffer', 'domAutomation',
          'domAutomationController', '__lastWatirAlert', '__lastWatirConfirm',
          '__lastWatirPrompt', '_Selenium_IDE_Recorder', '_selenium', 'calledSelenium'
        ];
        
        safeExecuteSpoofing(() => {
          automationProps.forEach(prop => {
          
              // Debug: Log which property is being processed
              if (debugEnabled && (prop === 'href' || prop.includes('href'))) {
                console.log(`[fingerprint] WARNING: Processing href-related property: ${prop}`);
              }
            try {
              // Skip built-in properties immediately
             if (['href', 'origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash', 'constructor', 'prototype', '__proto__', 'toString', 'valueOf', 'assign', 'reload', 'replace'].includes(prop)) {
                if (debugEnabled) {
                  console.log(`[fingerprint] Skipping built-in automation property: ${prop}`);
                }
                return;
              }
              
                // Additional safety check specifically for href
              if (prop === 'href') {
                if (debugEnabled) console.log(`[fingerprint] BLOCKING href property modification attempt`);
                return;
              }

              if (!canModifyProperty(window, prop, debugEnabled) && !canModifyProperty(navigator, prop, debugEnabled)) {
                if (debugEnabled) {
                  console.log(`[fingerprint] Skipping non-configurable automation property ${prop}`);
                }
                return;
              }

              // Try to delete from both window and navigator
              try { delete window[prop]; } catch(e) {}
              try { delete navigator[prop]; } catch(e) {}
              
              // Only try to redefine if we can
              if (canModifyProperty(window, prop, debugEnabled)) {
                safeDefineProperty(window, prop, {
                  get: () => undefined,
                  enumerable: false
                }, debugEnabled);
              }
              
              if (canModifyProperty(navigator, prop, debugEnabled)) {
                safeDefineProperty(navigator, prop, {
                  get: () => undefined,
                  enumerable: false
                }, debugEnabled);
              }
            } catch (propErr) {
              // Skip problematic properties
              if (debugEnabled) {
                console.log(`[fingerprint] Skipped automation property ${prop}: ${propErr.message}`);
              }
            }
          });
        }, 'automation properties removal');

        // 3. Enhanced Chrome runtime simulation with safe property handling

        safeExecuteSpoofing(() => {
          if (!window.chrome || !window.chrome.runtime) {
            window.chrome = {
              runtime: {
                onConnect: { addListener: () => {}, removeListener: () => {} },
                onMessage: { addListener: () => {}, removeListener: () => {} },
                sendMessage: () => {},
                connect: () => ({
                  onMessage: { addListener: () => {}, removeListener: () => {} },
                  postMessage: () => {},
                  disconnect: () => {}
                }),
                getManifest: () => ({
                  name: "Chrome",
                  version: "131.0.0.0"
                }),
                getURL: (path) => `chrome-extension://invalid/${path}`,
                id: undefined
              },
              loadTimes: () => ({
                commitLoadTime: performance.now() - Math.random() * 1000,
                connectionInfo: 'http/1.1',
                finishDocumentLoadTime: performance.now() - Math.random() * 500,
                finishLoadTime: performance.now() - Math.random() * 100,
                firstPaintAfterLoadTime: performance.now() - Math.random() * 50,
                firstPaintTime: performance.now() - Math.random() * 200,
                navigationType: 'Navigation',
                npnNegotiatedProtocol: 'unknown',
                requestTime: performance.now() - Math.random() * 2000,
                startLoadTime: performance.now() - Math.random() * 1500,
                wasAlternateProtocolAvailable: false,
                wasFetchedViaSpdy: false,
                wasNpnNegotiated: false
              }),
              csi: () => ({
                onloadT: Date.now(),
                pageT: Math.random() * 1000,
                startE: Date.now() - Math.random() * 2000,
                tran: Math.floor(Math.random() * 20)
              }),
              app: {
                isInstalled: false,
                InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
                RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }
              }
            };
          }
        }, 'Chrome runtime simulation');
        
        // 4. Realistic plugins based on user agent with safe property handling
        safeExecuteSpoofing(() => {
          const isChrome = userAgent.includes('Chrome');
          const isFirefox = userAgent.includes('Firefox');
          const isSafari = userAgent.includes('Safari') && !userAgent.includes('Chrome');
          
          let plugins = [];
          if (isChrome) {
            plugins = [
              { name: 'Chrome PDF Plugin', length: 1, description: 'Portable Document Format', filename: 'internal-pdf-viewer' },
              { name: 'Chrome PDF Viewer', length: 1, description: 'PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
              { name: 'Native Client', length: 2, description: 'Native Client Executable', filename: 'internal-nacl-plugin' }
            ];
          } else if (isFirefox) {
            plugins = [
              { name: 'PDF.js', length: 2, description: 'Portable Document Format', filename: 'internal-pdf-js' }
            ];
          } else if (isSafari) {
            plugins = [
              { name: 'WebKit built-in PDF', length: 1, description: 'Portable Document Format', filename: 'internal-pdf-viewer' }
            ];
          }
          
          safeDefineProperty(navigator, 'plugins', {
            get: () => plugins
          }, debugEnabled);
        }, 'plugins spoofing');
        
        // 5. Enhanced language spoofing with safe property handling
        safeExecuteSpoofing(() => {
          const languages = ['en-US', 'en'];
          
          safeDefineProperty(navigator, 'languages', {
            get: () => languages
          }, debugEnabled);
          
          safeDefineProperty(navigator, 'language', {
            get: () => languages[0]
          }, debugEnabled);
        }, 'language spoofing');
        
        // 6. Vendor and product info based on user agent with safe handling
        safeExecuteSpoofing(() => {
          const isFirefox = userAgent.includes('Firefox');
          const isSafari = userAgent.includes('Safari') && !userAgent.includes('Chrome');
          
          let vendor = 'Google Inc.';
          let product = 'Gecko';
          
          if (isFirefox) {
            vendor = '';
            product = 'Gecko';
          } else if (isSafari) {
            vendor = 'Apple Computer, Inc.';
            product = 'Gecko';
          }
          
          safeDefineProperty(navigator, 'vendor', {
            get: () => vendor
          }, debugEnabled);
          
          safeDefineProperty(navigator, 'product', {
            get: () => product
          }, debugEnabled);
        }, 'vendor/product spoofing');
        
        // 7. Add realistic mimeTypes with safe handling
        safeExecuteSpoofing(() => {
          const isChrome = userAgent.includes('Chrome');
          
          safeDefineProperty(navigator, 'mimeTypes', {
            get: () => {
              if (isChrome) {
                return [
                  { type: 'application/pdf', description: 'Portable Document Format', suffixes: 'pdf', enabledPlugin: navigator.plugins[0] },
                  { type: 'application/x-google-chrome-pdf', description: 'Portable Document Format', suffixes: 'pdf', enabledPlugin: navigator.plugins[1] },
                  { type: 'application/x-nacl', description: 'Native Client Executable', suffixes: '', enabledPlugin: navigator.plugins[2] }
                ];
              }
              return [];
            }
          }, debugEnabled);
        }, 'mimeTypes spoofing');
        
        // 8. Enhanced permission API spoofing with safe handling
        safeExecuteSpoofing(() => {
          if (navigator.permissions && navigator.permissions.query) {
            const originalQuery = navigator.permissions.query;
            navigator.permissions.query = function(parameters) {
              const granted = ['camera', 'microphone', 'notifications'];
              const denied = ['midi', 'push', 'speaker'];
              const prompt = ['geolocation'];
              
              if (granted.includes(parameters.name)) {
                return Promise.resolve({ state: 'granted', onchange: null });
              } else if (denied.includes(parameters.name)) {
                return Promise.resolve({ state: 'denied', onchange: null });
              } else if (prompt.includes(parameters.name)) {
                return Promise.resolve({ state: 'prompt', onchange: null });
              }
              return originalQuery.apply(this, arguments);
            };
          }
        }, 'permissions API spoofing');
        
        // 9. Spoof iframe contentWindow access with safe handling
        safeExecuteSpoofing(() => {
          const originalContentWindow = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
          if (originalContentWindow && originalContentWindow.configurable !== false) {
            safeDefineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
              get: function() {
                const win = originalContentWindow.get.call(this);
                if (win) {
                  // Remove automation properties from iframe windows too
                  const automationProps = [
                    'callPhantom', '_phantom', '__nightmare', '_selenium',
                    '__selenium_unwrapped', '__webdriver_evaluate', '__driver_evaluate'
                  ];
                  automationProps.forEach(prop => {
                    try { 
                // Use the same built-in property check for iframe context
                if (!canModifyProperty(win, prop, debugEnabled)) return;
                      delete win[prop];
                      safeDefineProperty(win, prop, {
                        get: () => undefined,
                        enumerable: false
                      }, debugEnabled);
                    } catch(e) {}
                  });
                }
                return win;
              }
            }, debugEnabled);
          }
        }, 'iframe contentWindow spoofing');
        
        // 10. Enhanced connection information spoofing with safe handling
        safeExecuteSpoofing(() => {
          if (navigator.connection) {
            // Check if connection properties can be modified
            try {
              const connectionTest = Object.getOwnPropertyDescriptor(navigator.connection, 'rtt');
              if (connectionTest && connectionTest.configurable === false) {
                if (debugEnabled) {
                  console.log('[fingerprint] Connection properties are non-configurable, skipping');
                }
                return;
              }
            } catch (connTestErr) {
              if (debugEnabled) {
                console.log('[fingerprint] Cannot test connection properties, skipping connection spoofing');
              }
              return;
            }
            safeDefineProperty(navigator.connection, 'rtt', {
              get: () => Math.floor(Math.random() * 100) + 50
            }, debugEnabled);
            safeDefineProperty(navigator.connection, 'downlink', {
              get: () => Math.random() * 10 + 1
            }, debugEnabled);
            safeDefineProperty(navigator.connection, 'effectiveType', {
              get: () => '4g'
            }, debugEnabled);
            safeDefineProperty(navigator.connection, 'saveData', {
              get: () => false
            }, debugEnabled);
          }
        }, 'connection info spoofing');
        
        // 11. Spoof WebGL fingerprinting with safe handling
        safeExecuteSpoofing(() => {
          if (window.WebGLRenderingContext) {
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
              if (parameter === 37445) { // UNMASKED_VENDOR_WEBGL
                return 'Intel Inc.';
              }
              if (parameter === 37446) { // UNMASKED_RENDERER_WEBGL
                return 'Intel Iris OpenGL Engine';
              }
              return getParameter.call(this, parameter);
            };
          }
        }, 'WebGL fingerprinting');
        
        // 12. Spoof canvas fingerprinting with subtle noise and safe handling
        safeExecuteSpoofing(() => {
          const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
          HTMLCanvasElement.prototype.toDataURL = function(...args) {
            const context = this.getContext('2d');
            if (context) {
              // Add subtle noise to canvas to prevent fingerprinting
              const imageData = context.getImageData(0, 0, this.width, this.height);
              for (let i = 0; i < imageData.data.length; i += 4) {
                imageData.data[i] = imageData.data[i] + Math.floor(Math.random() * 3) - 1;
              }
              context.putImageData(imageData, 0, 0);
            }
            return originalToDataURL.apply(this, args);
          };
        }, 'canvas fingerprinting');
        
        // 13. Enhanced Error.captureStackTrace with safe handling
        safeExecuteSpoofing(() => {
          if (Error.captureStackTrace) {
            const originalCaptureStackTrace = Error.captureStackTrace;
            Error.captureStackTrace = function(targetObject, constructorOpt) {
              const result = originalCaptureStackTrace.call(this, targetObject, constructorOpt);
              if (targetObject.stack) {
                // Remove puppeteer-related stack traces
                targetObject.stack = targetObject.stack
                  .split('\n')
                  .filter(line => !line.includes('puppeteer') && !line.includes('DevTools') && !line.includes('chrome-devtools'))
                  .join('\n');
              }
              return result;
            };
          }
        }, 'stack trace cleaning');
        
        // 14. Patch toString methods with safe handling
        safeExecuteSpoofing(() => {
          Function.prototype.toString = new Proxy(Function.prototype.toString, {
            apply: function(target, thisArg, argumentsList) {
              const result = target.apply(thisArg, argumentsList);
              return result.replace(/puppeteer/gi, 'browser').replace(/headless/gi, 'chrome');
            }
          });
        }, 'toString method patching');
        
        // 15. Spoof battery API with safe handling
        safeExecuteSpoofing(() => {
          if (navigator.getBattery) {
            const originalGetBattery = navigator.getBattery;
            navigator.getBattery = function() {
              return Promise.resolve({
                charging: Math.random() > 0.5,
                chargingTime: Math.random() > 0.5 ? Infinity : Math.random() * 3600,
                dischargingTime: Math.random() * 7200,
                level: Math.random() * 0.99 + 0.01,
                addEventListener: () => {},
                removeEventListener: () => {},
                dispatchEvent: () => true
              });
            };
          }
        }, 'battery API spoofing');
        
        // 16. Add realistic timing to console methods with safe handling
        safeExecuteSpoofing(() => {
          ['debug', 'error', 'info', 'log', 'warn'].forEach(method => {
            const original = console[method];
            console[method] = function(...args) {
              // Add tiny random delay to mimic human-like console timing
              setTimeout(() => original.apply(console, args), Math.random() * 5);
            };
          });
        }, 'console timing');

        // 18. Enhanced service worker handling to prevent registration errors
        safeExecuteSpoofing(() => {
          if ('serviceWorker' in navigator) {
            const originalRegister = navigator.serviceWorker.register;
            const originalGetRegistration = navigator.serviceWorker.getRegistration;
            const originalGetRegistrations = navigator.serviceWorker.getRegistrations;
            
            // Wrap register method to handle errors gracefully
            navigator.serviceWorker.register = function(scriptURL, options) {
              try {
                if (debugEnabled) {
                  console.log('[fingerprint] Service worker registration intercepted:', scriptURL);
                }
                
                // Return a resolved promise to prevent registration errors
                return Promise.resolve({
                  installing: null,
                  waiting: null,
                  active: {
                    scriptURL: scriptURL,
                    state: 'activated'
                  },
                  scope: options?.scope || '/',
                  update: () => Promise.resolve(),
                  unregister: () => Promise.resolve(true),
                  addEventListener: () => {},
                  removeEventListener: () => {},
                  dispatchEvent: () => true
                });
              } catch (registerErr) {
                if (debugEnabled) {
                  console.log('[fingerprint] Service worker register error handled:', registerErr.message);
                }
                // Return rejected promise to maintain normal error flow for sites that expect it
                return Promise.reject(new Error('ServiceWorker registration failed'));
              }
            };
            
            // Wrap getRegistration to return mock registration
            navigator.serviceWorker.getRegistration = function(scope) {
              try {
                return Promise.resolve(null); // No existing registrations
              } catch (getRegErr) {
                return Promise.reject(getRegErr);
              }
            };
            
            // Wrap getRegistrations to return empty array
            navigator.serviceWorker.getRegistrations = function() {
              try {
                return Promise.resolve([]); // No existing registrations
              } catch (getRegsErr) {
                return Promise.reject(getRegsErr);
              }
            };
          }
        }, 'service worker handling');

        // 17. Enhanced network error handling and fetch/XHR safety
        safeExecuteSpoofing(() => {
          // HTTP status code error suppression only
          const originalConsoleError = console.error;
          console.error = function(...args) {
            const message = args.join(' ').toString();
            
            // Only suppress HTTP status code errors
            const isHttpStatusError = typeof message === 'string' && 
              /Failed to load resource.*server responded with a status of [45]\d{2}(\s*\(\))?/i.test(message);
            
            if (isHttpStatusError) {
              if (debugEnabled) {
                console.log(`[fingerprint] Suppressed HTTP status error: ${message}`);
              }
              return; // Suppress the error
            }
            // For all other errors, use original console.error
            return originalConsoleError.apply(this, arguments);
          };

          // Safely wrap fetch to prevent network errors from propagating to page
          if (window.fetch) {
            const originalFetch = window.fetch;
            window.fetch = function(...args) {
              try {
                const result = originalFetch.apply(this, args);
                
                // Handle fetch promise rejections to prevent uncaught network errors
                if (result && typeof result.catch === 'function') {
                  return result.catch(fetchErr => {
                    // Log network errors silently without throwing to page
                    if (debugEnabled && fetchErr.name === 'TypeError' && fetchErr.message.includes('fetch')) {
                      console.log('[fingerprint] Fetch network error handled:', fetchErr.message);
                    }
                    // Re-throw the error so normal error handling still works
                    throw fetchErr;
                  });
                }
                
                return result;
              } catch (fetchWrapErr) {
                if (debugEnabled) {
                  console.log('[fingerprint] Fetch wrapper error:', fetchWrapErr.message);
                }
                return originalFetch.apply(this, args);
              }
            };
            
            // Preserve fetch properties
            Object.setPrototypeOf(window.fetch, originalFetch);
          }
          
          // Safely wrap XMLHttpRequest to prevent network errors
          if (window.XMLHttpRequest) {
            const OriginalXHR = window.XMLHttpRequest;
            
            window.XMLHttpRequest = function() {
              const xhr = new OriginalXHR();
              const originalOpen = xhr.open;
              const originalSend = xhr.send;
              
              // Wrap open method
              xhr.open = function(...args) {
                try {
                  return originalOpen.apply(this, args);
                } catch (openErr) {
                  if (debugEnabled) {
                    console.log('[fingerprint] XHR open error handled:', openErr.message);
                  }
                  throw openErr;
                }
              };
              
              // Wrap send method
              xhr.send = function(...args) {
                try {
                  return originalSend.apply(this, args);
                } catch (sendErr) {
                  if (debugEnabled) {
                    console.log('[fingerprint] XHR send error handled:', sendErr.message);
                  }
                  throw sendErr;
                }
              };
              
              // Add error event listener to prevent uncaught network errors
              xhr.addEventListener('error', function(event) {
                if (debugEnabled) {
                  console.log('[fingerprint] XHR network error event handled');
                }
                // Don't prevent default - let normal error handling work
              });
              
              return xhr;
            };
            
            // Preserve XMLHttpRequest properties
            Object.setPrototypeOf(window.XMLHttpRequest, OriginalXHR);
            window.XMLHttpRequest.prototype = OriginalXHR.prototype;
          }
          
          // Global error handler for HTTP status code errors only
          const originalErrorHandler = window.onerror;
          window.onerror = function(message, source, lineno, colno, error) {
            const messageStr = String(message || '');
            
            // Only handle HTTP status code errors
            const isHttpStatusError = /Failed to load resource.*server responded with a status of [45]\d{2}(\s*\(\))?/i.test(messageStr);
            
            if (isHttpStatusError) {
              if (debugEnabled) {
                console.log(`[fingerprint] HTTP status error handled by global handler: ${message}`);
              }
              // Return true to suppress the error
              return true;
            }
            
            // Call original error handler for all other errors
            if (originalErrorHandler) {
              return originalErrorHandler.apply(this, arguments);
            }
            
            return false;
          };
          
          // Unhandled promise rejection handler for HTTP status errors only 
          const originalUnhandledRejection = window.onunhandledrejection;
          window.onunhandledrejection = function(event) {
            const reason = event.reason;
            let shouldSuppress = false;
            
            if (reason) {
              const reasonMessage = String(reason.message || reason || '');
              // Only suppress HTTP status code related promise rejections
              shouldSuppress = /Failed to load resource.*server responded with a status of [45]\d{2}(\s*\(\))?/i.test(reasonMessage);
            }
            
            if (shouldSuppress) {
              if (debugEnabled) {
                console.log('[fingerprint] HTTP status promise rejection handled:', reason);
              }
              event.preventDefault();
              return;
            }
            
            // Call original handler for non-network rejections
            if (originalUnhandledRejection) {
              return originalUnhandledRejection.apply(this, arguments);
            }
          };
          
        }, 'network error handling');
        

      }, ua, forceDebug);
    } catch (stealthErr) {
      console.warn(`[enhanced stealth protection failed] ${currentUrl}: ${stealthErr.message}`);
    }
  }
}

/**
 * Enhanced Brave browser spoofing with more realistic implementation
 * Compatible with Puppeteer 23.x
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyBraveSpoofing(page, siteConfig, forceDebug, currentUrl) {
  if (!siteConfig.isBrave) return;

  if (forceDebug) console.log(`[debug] Enhanced Brave spoofing enabled for ${currentUrl}`);
  
  await page.evaluateOnNewDocument((debugEnabled) => {
    
    function safeDefinePropertyLocal(target, property, descriptor) {
      try {
        const existingDescriptor = Object.getOwnPropertyDescriptor(target, property);
        
        if (existingDescriptor && existingDescriptor.configurable === false) {
          if (debugEnabled) {
            console.log(`[fingerprint] Cannot redefine non-configurable property: ${property}`);
          }
          return false;
        }
        
        const safeDescriptor = {
          ...descriptor,
          configurable: true
        };
        
        Object.defineProperty(target, property, safeDescriptor);
        return true;
      } catch (defineErr) {
        if (debugEnabled) {
          console.log(`[fingerprint] Property definition failed for ${property}: ${defineErr.message}`);
        }
        return false;
      }
    }
    
    // More comprehensive Brave spoofing with safe property handling
    safeDefinePropertyLocal(navigator, 'brave', {
      get: () => ({
        isBrave: () => Promise.resolve(true),
        setBadge: () => {},
        clearBadge: () => {},
        getAdBlockEnabled: () => Promise.resolve(true),
        getShieldsEnabled: () => Promise.resolve(true)
      })
    });
    
    // Brave-specific user agent adjustments with safe handling
    if (navigator.userAgent && !navigator.userAgent.includes('Brave')) {
      safeDefinePropertyLocal(navigator, 'userAgent', {
        get: () => navigator.userAgent.replace('Chrome/', 'Brave/').replace('Safari/537.36', 'Safari/537.36 Brave/1.60')
      });
    }
  }, forceDebug);
}

/**
 * Enhanced fingerprint protection with more realistic and varied spoofing
 * Compatible with Puppeteer 23.x
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl) {
  const fingerprintSetting = siteConfig.fingerprint_protection;
  if (!fingerprintSetting) return;

  if (forceDebug) console.log(`[debug] Enhanced fingerprint_protection enabled for ${currentUrl}`);
  
  const spoof = fingerprintSetting === 'random' ? getRandomFingerprint() : {
    deviceMemory: 8, 
    hardwareConcurrency: 4,
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 },
    platform: DEFAULT_PLATFORM, 
    timezone: DEFAULT_TIMEZONE,
    language: 'en-US',
    cookieEnabled: true,
    doNotTrack: null
  };

  try {
    await page.evaluateOnNewDocument(({ spoof, debugEnabled }) => {
      
      // Use local versions of helper functions for this context
      function safeDefinePropertyLocal(target, property, descriptor) {
        try {
          const existingDescriptor = Object.getOwnPropertyDescriptor(target, property);
          
          if (existingDescriptor && existingDescriptor.configurable === false) {
            if (debugEnabled) {
              console.log(`[fingerprint] Cannot redefine non-configurable property: ${property}`);
            }
            return false;
          }
          
          const safeDescriptor = {
            ...descriptor,
            configurable: true,
            enumerable: descriptor.enumerable !== false
          };
          
          Object.defineProperty(target, property, safeDescriptor);
          return true;
        } catch (defineErr) {
          if (debugEnabled) {
            console.log(`[fingerprint] Property definition failed for ${property}: ${defineErr.message}`);
          }
          return false;
        }
      }
      
      function safeExecuteSpoofingLocal(spoofFunction, description) {
        try {
          spoofFunction();
          return true;
        } catch (spoofErr) {
          if (debugEnabled) {
            console.log(`[fingerprint] ${description} failed: ${spoofErr.message}`);
          }
          return false;
        }
      }
      
      // Enhanced property spoofing with more realistic values and safe handling
      safeExecuteSpoofingLocal(() => {
        safeDefinePropertyLocal(navigator, 'platform', { 
          get: () => spoof.platform
        });
      }, 'platform spoofing');
      
     safeExecuteSpoofingLocal(() => {
       safeDefinePropertyLocal(navigator, 'deviceMemory', { 
         get: () => spoof.deviceMemory
       });
     }, 'deviceMemory spoofing');
     
     safeExecuteSpoofingLocal(() => {
       safeDefinePropertyLocal(navigator, 'hardwareConcurrency', { 
         get: () => spoof.hardwareConcurrency
       });
     }, 'hardwareConcurrency spoofing');
     
     // Enhanced screen properties with safe handling
     safeExecuteSpoofingLocal(() => {
       ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'].forEach(prop => {
         if (spoof.screen[prop] !== undefined) {
           safeDefinePropertyLocal(window.screen, prop, {
             get: () => spoof.screen[prop]
           });
         }
       });
     }, 'screen properties spoofing');
     
     // Enhanced language spoofing in fingerprint protection
     safeExecuteSpoofingLocal(() => {
       const languages = Array.isArray(spoof.language) ? spoof.language : [spoof.language, spoof.language.split('-')[0]];
       
       safeDefinePropertyLocal(navigator, 'languages', {
         get: () => languages
       });
       
       safeDefinePropertyLocal(navigator, 'language', {
         get: () => languages[0]
       });
     }, 'language spoofing in fingerprint protection');

      
      // Enhanced timezone spoofing with safe handling
      safeExecuteSpoofingLocal(() => {
        // Validate timezone value before proceeding
        if (!spoof.timezone || typeof spoof.timezone !== 'string') {
          if (debugEnabled) {
            console.log('[fingerprint] Invalid timezone value, skipping timezone spoofing');
          }
          return;
        }
        
        // Check if Intl.DateTimeFormat is available and configurable
        try {
          const intlDescriptor = Object.getOwnPropertyDescriptor(window, 'Intl');
          if (intlDescriptor && intlDescriptor.configurable === false) {
            if (debugEnabled) {
              console.log('[fingerprint] Intl object is non-configurable, skipping timezone spoofing');
            }
            return;
          }
        } catch (intlCheckErr) {
          if (debugEnabled) {
            console.log('[fingerprint] Cannot check Intl configurability, skipping timezone spoofing');
          }
          return;
        }
        
        const originalDateTimeFormat = Intl.DateTimeFormat;

        // Safely override DateTimeFormat
        try {
          Intl.DateTimeFormat = function(...args) {
            try {
              const instance = new originalDateTimeFormat(...args);
              const originalResolvedOptions = instance.resolvedOptions;
              
              instance.resolvedOptions = function() {
                try {
                  const options = originalResolvedOptions.call(this);
                  // Validate timezone before setting
                  if (spoof.timezone && typeof spoof.timezone === 'string') {
                    options.timeZone = spoof.timezone;
                  }
                  return options;
                } catch (optionsErr) {
                  if (debugEnabled) {
                    console.log('[fingerprint] resolvedOptions error, using original:', optionsErr.message);
                  }
                  return originalResolvedOptions.call(this);
                }
              };
              return instance;
            } catch (instanceErr) {
              if (debugEnabled) {
                console.log('[fingerprint] DateTimeFormat instance error, using original:', instanceErr.message);
              }
              return new originalDateTimeFormat(...args);
            }
          };
          
          // Copy static properties from original
          Object.setPrototypeOf(Intl.DateTimeFormat, originalDateTimeFormat);
          Object.getOwnPropertyNames(originalDateTimeFormat).forEach(prop => {
            if (prop !== 'length' && prop !== 'name' && prop !== 'prototype') {
              try {
                Intl.DateTimeFormat[prop] = originalDateTimeFormat[prop];
              } catch (propErr) {
                // Ignore property copy errors
              }
            }
          });
        } catch (dateTimeFormatErr) {
          if (debugEnabled) {
            console.log('[fingerprint] DateTimeFormat override failed:', dateTimeFormatErr.message);
          }
        }
        
        // Spoof Date.getTimezoneOffset with safe handling
        try {
          const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
          
          // Check if getTimezoneOffset can be overridden
          const tzDescriptor = Object.getOwnPropertyDescriptor(Date.prototype, 'getTimezoneOffset');
          if (tzDescriptor && tzDescriptor.configurable === false) {
            if (debugEnabled) {
              console.log('[fingerprint] getTimezoneOffset is non-configurable, skipping');
            }
          } else {
            Date.prototype.getTimezoneOffset = function() {
              try {
                // Validate timezone and return appropriate offset
                const timezoneOffsets = {
                  'America/New_York': 300,    // EST offset
                  'America/Los_Angeles': 480, // PST offset
                  'Europe/London': 0,         // GMT offset
                  'America/Chicago': 360      // CST offset
                };
                
                if (spoof.timezone && timezoneOffsets.hasOwnProperty(spoof.timezone)) {
                  return timezoneOffsets[spoof.timezone];
                }
                
                // Fallback to original if timezone not recognized
                return originalGetTimezoneOffset.call(this);
              } catch (tzOffsetErr) {
                if (debugEnabled) {
                  console.log('[fingerprint] getTimezoneOffset error, using original:', tzOffsetErr.message);
                }
                return originalGetTimezoneOffset.call(this);
              }
            };
          }
        } catch (timezoneOffsetErr) {
          if (debugEnabled) {
            console.log('[fingerprint] Timezone offset spoofing failed:', timezoneOffsetErr.message);
          }
        }
      }, 'timezone spoofing');
      
      // Enhanced cookie and DNT spoofing with safe handling
      safeExecuteSpoofingLocal(() => {
        if (spoof.cookieEnabled !== undefined) {
          safeDefinePropertyLocal(navigator, 'cookieEnabled', {
            get: () => spoof.cookieEnabled
          });
        }
        
        if (spoof.doNotTrack !== undefined) {
          safeDefinePropertyLocal(navigator, 'doNotTrack', {
            get: () => spoof.doNotTrack
          });
        }
      }, 'cookie/DNT spoofing');
      
    }, { spoof, debugEnabled: forceDebug });
  } catch (err) {
    console.warn(`[enhanced fingerprint spoof failed] ${currentUrl}: ${err.message}`);
  }
}

/**
 * Add mouse movement simulation to appear more human-like
 * Compatible with Puppeteer 23.x
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @returns {Promise<void>}
 */
async function simulateHumanBehavior(page, forceDebug) {
  try {
    await page.evaluateOnNewDocument((debugEnabled) => {
      
      function safeExecuteSpoofingLocal(spoofFunction, description) {
        try {
          spoofFunction();
          return true;
        } catch (spoofErr) {
          if (debugEnabled) {
            console.log(`[fingerprint] ${description} failed: ${spoofErr.message}`);
          }
          return false;
        }
      }
      
      // Simulate human-like mouse movements with safe handling
      safeExecuteSpoofingLocal(() => {
        let mouseX = Math.random() * window.innerWidth;
        let mouseY = Math.random() * window.innerHeight;
        
        const moveInterval = setInterval(() => {
          mouseX += (Math.random() - 0.5) * 20;
          mouseY += (Math.random() - 0.5) * 20;
          
          mouseX = Math.max(0, Math.min(window.innerWidth, mouseX));
          mouseY = Math.max(0, Math.min(window.innerHeight, mouseY));
          
          try {
            document.dispatchEvent(new MouseEvent('mousemove', {
              clientX: mouseX,
              clientY: mouseY,
              bubbles: true
            }));
          } catch (mouseErr) {
            // Ignore mouse event errors
          }
        }, 1000 + Math.random() * 2000);
        
        // Simulate occasional clicks and scrolls with safe handling
        setTimeout(() => {
          try {
            if (Math.random() > 0.7) {
              document.dispatchEvent(new MouseEvent('click', {
                clientX: mouseX,
                clientY: mouseY,
                bubbles: true
              }));
            }
            
            // Simulate scroll events
            if (Math.random() > 0.8) {
              window.scrollBy(0, Math.random() * 100 - 50);
            }
          } catch (interactionErr) {
            // Ignore interaction errors
          }
        }, 5000 + Math.random() * 10000);
        
        // Stop simulation after 30 seconds to avoid detection
        setTimeout(() => {
          try {
            clearInterval(moveInterval);
          } catch (clearErr) {
            // Ignore clear errors
          }
        }, 30000);
      }, 'human behavior simulation');
      
    }, forceDebug);
  } catch (err) {
    if (forceDebug) console.log(`[debug] Human behavior simulation failed: ${err.message}`);
  }
}

/**
 * Enhanced main function that applies all fingerprint spoofing techniques
 * Compatible with Puppeteer 23.x
 * @param {import('puppeteer').Page} page - The Puppeteer page instance
 * @param {object} siteConfig - The site configuration object
 * @param {boolean} forceDebug - Whether debug logging is enabled
 * @param {string} currentUrl - The current URL being processed (for logging)
 * @returns {Promise<void>}
 */
async function applyAllFingerprintSpoofing(page, siteConfig, forceDebug, currentUrl) {
  // Apply all spoofing techniques with enhanced error handling
  try {
    await applyUserAgentSpoofing(page, siteConfig, forceDebug, currentUrl);
  } catch (uaErr) {
    if (forceDebug) console.log(`[debug] User agent spoofing failed for ${currentUrl}: ${uaErr.message}`);
  }
  
  try {
    await applyBraveSpoofing(page, siteConfig, forceDebug, currentUrl);
  } catch (braveErr) {
    if (forceDebug) console.log(`[debug] Brave spoofing failed for ${currentUrl}: ${braveErr.message}`);
  }
  
  try {
    await applyFingerprintProtection(page, siteConfig, forceDebug, currentUrl);
  } catch (fpErr) {
    if (forceDebug) console.log(`[debug] Fingerprint protection failed for ${currentUrl}: ${fpErr.message}`);
  }
  
  // Add human behavior simulation if user agent spoofing is enabled
  if (siteConfig.userAgent) {
    try {
      await simulateHumanBehavior(page, forceDebug);
    } catch (behaviorErr) {
      if (forceDebug) console.log(`[debug] Human behavior simulation failed for ${currentUrl}: ${behaviorErr.message}`);
    }
  }
}

module.exports = {
  getRandomFingerprint,
  getRealisticScreenResolution,
  applyUserAgentSpoofing,
  applyBraveSpoofing,
  applyFingerprintProtection,
  applyAllFingerprintSpoofing,
  simulateHumanBehavior,
  safeDefineProperty,
  safeExecuteSpoofing,
  DEFAULT_PLATFORM,
  DEFAULT_TIMEZONE
};