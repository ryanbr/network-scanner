// === Post-Processing Module for Network Scanner ===
// Handles cleanup and validation of scan results after scanning is complete

const { formatLogMessage, messageColors } = require('./colorize');

/**
 * Safely extracts hostname from a URL, handling malformed URLs gracefully
 * @param {string} url - The URL string to parse
 * @param {boolean} getFullHostname - If true, returns full hostname; if false, returns root domain
 * @returns {string} The hostname/domain, or empty string if URL is invalid
 */
function safeGetDomain(url, getFullHostname = false) {
  try {
    const psl = require('psl');
    const parsedUrl = new URL(url);
    if (getFullHostname) {
      return parsedUrl.hostname;
    } else {
      // Extract root domain using psl library
      const parsed = psl.parse(parsedUrl.hostname);
      return parsed.domain || parsedUrl.hostname;
    }
  } catch (urlError) {
    return '';
  }
}

/**
 * Enhanced domain matching for ignoreDomains patterns (including wildcards)
 * @param {string} domain - Domain to check
 * @param {Array} ignorePatterns - Array of ignore patterns (supports wildcards)
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Object} Match result with shouldIgnore flag and reason
 */
function shouldIgnoreAsIgnoreDomain(domain, ignorePatterns, forceDebug) {
  if (!domain || !ignorePatterns || ignorePatterns.length === 0) {
    return { shouldIgnore: false, reason: 'No ignore patterns' };
  }

  for (const pattern of ignorePatterns) {
    if (pattern.includes('*')) {
      // Handle wildcard patterns
      if (pattern.startsWith('*.')) {
        // Pattern: *.example.com
        const wildcardDomain = pattern.substring(2); // Remove "*."
        const wildcardRoot = safeGetDomain(`http://${wildcardDomain}`, false);
        const domainRoot = safeGetDomain(`http://${domain}`, false);
        
        if (wildcardRoot === domainRoot) {
          return { 
            shouldIgnore: true, 
            reason: `Matches wildcard ignore pattern: ${pattern}` 
          };
        }
      } else if (pattern.endsWith('.*')) {
        // Pattern: example.*
        const baseDomain = pattern.slice(0, -2); // Remove ".*"
        if (domain.startsWith(baseDomain + '.')) {
          return { 
            shouldIgnore: true, 
            reason: `Matches wildcard TLD ignore pattern: ${pattern}` 
          };
        }
      } else {
        // Complex wildcard pattern
        const wildcardRegex = new RegExp('^' + pattern.replace(/\*/g, '.*').replace(/\./g, '\\.') + '$');
        if (wildcardRegex.test(domain)) {
          return { 
            shouldIgnore: true, 
            reason: `Matches complex wildcard ignore pattern: ${pattern}` 
          };
        }
      }
    } else {
      // Exact pattern matching
      if (domain === pattern || domain.endsWith('.' + pattern)) {
        return { 
          shouldIgnore: true, 
          reason: `Matches exact ignore pattern: ${pattern}` 
        };
      }
    }
  }

  return { shouldIgnore: false, reason: 'No ignore pattern matches' };
}

/**
 * Enhanced domain matching that handles wildcards and first-party detection
 * @param {string} extractedDomain - Domain extracted from rule
 * @param {string} scannedRootDomain - Root domain of the scanned site
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Object} Match result with shouldRemove flag and reason
 */
function shouldRemoveAsFirstParty(extractedDomain, scannedRootDomain, forceDebug) {
  if (!extractedDomain || !scannedRootDomain) {
    return { shouldRemove: false, reason: 'Missing domain data' };
  }

  // Handle wildcard patterns
  if (extractedDomain.includes('*')) {
    // Common wildcard patterns
    if (extractedDomain.startsWith('*.')) {
      // Pattern: *.example.com
      const wildcardDomain = extractedDomain.substring(2); // Remove "*."
      const wildcardRoot = safeGetDomain(`http://${wildcardDomain}`, false);
      
      if (wildcardRoot === scannedRootDomain) {
        return { 
          shouldRemove: true, 
          reason: `Wildcard subdomain pattern matches root domain (*.${wildcardRoot})` 
        };
      }
    } else if (extractedDomain.endsWith('.*')) {
      // Pattern: example.*
      const baseDomain = extractedDomain.slice(0, -2); // Remove ".*"
      if (scannedRootDomain.startsWith(baseDomain + '.')) {
        return { 
          shouldRemove: true, 
          reason: `Wildcard TLD pattern matches base domain (${baseDomain}.*)` 
        };
      }
    } else if (extractedDomain.includes('*')) {
      // Pattern: sub*.example.com or other wildcard positions
      const wildcardRegex = new RegExp('^' + extractedDomain.replace(/\*/g, '.*').replace(/\./g, '\\.') + '$');
      if (wildcardRegex.test(scannedRootDomain)) {
        return { 
          shouldRemove: true, 
          reason: `Complex wildcard pattern matches root domain (${extractedDomain})` 
        };
      }
    }
  }

  // Standard exact root domain matching
  const extractedRoot = safeGetDomain(`http://${extractedDomain}`, false);
  if (extractedRoot === scannedRootDomain) {
    return { 
      shouldRemove: true, 
      reason: `Exact root domain match (${extractedRoot})` 
    };
  }

  return { shouldRemove: false, reason: 'No first-party match detected' };
}

/**
 * Post-scan cleanup function to remove ignoreDomains from results
 * This is a final safety net to catch any domains that should have been ignored
 * 
 * @param {Array} results - Array of scan results from all sites
 * @param {Array} ignoreDomains - Array of domains/patterns to ignore
 * @param {Object} options - Options object
 * @param {boolean} options.forceDebug - Debug logging flag
 * @param {boolean} options.silentMode - Silent mode flag
 * @returns {Array} Cleaned results with ignoreDomains removed
 */
function cleanupIgnoreDomains(results, ignoreDomains, options = {}) {
  const { forceDebug = false, silentMode = false } = options;
  
  if (!results || results.length === 0 || !ignoreDomains || ignoreDomains.length === 0) {
    return results;
  }

  if (forceDebug) {
    console.log(formatLogMessage('debug', `[ignoreDomains cleanup] Processing ${results.length} results against ${ignoreDomains.length} ignore patterns`));
  }

  const cleanedResults = [];
  let totalRulesRemoved = 0;
  let sitesAffected = 0;

  results.forEach(result => {
    if (!result.rules || result.rules.length === 0) {
      cleanedResults.push(result);
      return;
    }

    const originalRulesCount = result.rules.length;
    const cleanedRules = [];
    const removedRules = [];

    // Filter out rules that match ignoreDomains patterns
    result.rules.forEach(rule => {
      let extractedDomain = null;

      try {
        // Extract domain from different rule formats (same logic as first-party cleanup)
        if (rule.startsWith('||') && rule.includes('^')) {
          // ||domain.com^ format (adblock)
          const match = rule.match(/^\|\|([^/\^]+)/);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.startsWith('127.0.0.1 ') || rule.startsWith('0.0.0.0 ')) {
          // hosts file format
          const parts = rule.split(/\s+/);
          if (parts.length >= 2) {
            extractedDomain = parts[1];
          }
        } else if (rule.includes('local=/') && rule.includes('/')) {
          // dnsmasq format: local=/domain.com/
          const match = rule.match(/local=\/([^/]+)\//);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.includes('server=/') && rule.includes('/')) {
          // dnsmasq old format: server=/domain.com/
          const match = rule.match(/server=\/([^/]+)\//);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.includes('local-zone:') && rule.includes('always_null')) {
          // unbound format: local-zone: "domain.com." always_null
          const match = rule.match(/local-zone:\s*"([^"]+)\.?"/);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.includes('+block') && rule.includes('.')) {
          // privoxy format: { +block } .domain.com
          const match = rule.match(/\{\s*\+block\s*\}\s*\.?([^\s]+)/);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.match(/^\(\^\|\\\.\).*\\\.\w+\$$/)) {
          // pi-hole regex format: (^|\.)domain\.com$
          const match = rule.match(/^\(\^\|\\\.\)(.+)\\\.\w+\$$/);
          if (match) {
            // Unescape the domain
            extractedDomain = match[1].replace(/\\\./g, '.');
          }
        } else {
          // Try to extract any domain-like pattern as fallback
          const domainMatch = rule.match(/([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})/);
          if (domainMatch) {
            extractedDomain = domainMatch[1];
          }
        }
        // Check if extracted domain should be ignored
        if (extractedDomain) {
          const ignoreResult = shouldIgnoreAsIgnoreDomain(extractedDomain, ignoreDomains, forceDebug);
          
          if (ignoreResult.shouldIgnore) {
            removedRules.push({
              rule: rule,
              domain: extractedDomain,
              reason: `ignoreDomains: ${ignoreResult.reason}`,
              matchType: ignoreResult.reason.includes('wildcard') ? 'wildcard' : 'exact'
            });
            return; // Exit early - rule should be removed
          }
        }
      } catch (parseErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[ignoreDomains cleanup] Failed to parse rule: ${rule} - ${parseErr.message}`));
        }
      }

      // If we reach here, the rule should be kept
      cleanedRules.push(rule);
    });

    cleanedResults.push({ ...result, rules: cleanedRules });

    if (removedRules.length > 0) {
      sitesAffected++;
      totalRulesRemoved += removedRules.length;
      
      if (!silentMode) {
        const wildcardCount = removedRules.filter(r => r.matchType === 'wildcard').length;
        const exactCount = removedRules.filter(r => r.matchType === 'exact').length;
        
        let cleanupMessage = `?? Removed ${removedRules.length} ignoreDomains rule(s) from ${safeGetDomain(result.url)} (final cleanup)`;
        if (wildcardCount > 0) {
          cleanupMessage += ` [${wildcardCount} wildcard, ${exactCount} exact]`;
        }
        
        if (messageColors && messageColors.cleanup) {
          console.log(messageColors.cleanup(cleanupMessage));
        } else {
          console.log(cleanupMessage);
        }
      }
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[ignoreDomains cleanup] Removed rules from ${result.url}:`));
        removedRules.forEach((removed, idx) => {
          console.log(formatLogMessage('debug', `  [${idx + 1}] ${removed.rule} (${removed.reason}) [${removed.matchType}]`));
        });
      }
    }
  });

  // Summary
  if (totalRulesRemoved > 0 && !silentMode) {
    const allRemovedRules = cleanedResults.reduce((acc, result) => {
      if (result.removedIgnoreDomains) {
        acc.push(...result.removedIgnoreDomains);
      }
      return acc;
    }, []);
    
    const totalWildcardCount = allRemovedRules.filter(r => r.matchType === 'wildcard').length;
    const totalExactCount = allRemovedRules.filter(r => r.matchType === 'exact').length;
    
    const summaryMessage = `\n?? ignoreDomains cleanup completed: Removed ${totalRulesRemoved} rules from ${sitesAffected} site(s)` +
      (totalWildcardCount > 0 ? ` [${totalWildcardCount} wildcard patterns, ${totalExactCount} exact matches]` : '');
    if (messageColors && messageColors.cleanup) {
      console.log(messageColors.cleanup(summaryMessage));
    } else {
      console.log(summaryMessage);
    }
  } else if (forceDebug) {
    console.log(formatLogMessage('debug', '[ignoreDomains cleanup] No ignoreDomains rules found to remove'));
  }

  return cleanedResults;
}

/**
 * Enhanced domain extraction helper that reuses existing parsing logic
 * @param {string} rule - Rule string in various formats
 * @returns {string|null} Extracted domain or null if not found
 */
function extractDomainFromRule(rule) {
  if (!rule || typeof rule !== 'string') {
    return null;
  }

  try {
    // Reuse the existing parsing logic from cleanupFirstPartyDomains
    let extractedDomain = null;
    
    if (rule.startsWith('||') && rule.includes('^')) {
      // ||domain.com^ format (adblock)
      const match = rule.match(/^\|\|([^/\^]+)/);
      if (match) {
        extractedDomain = match[1];
      }
    } else if (rule.startsWith('127.0.0.1 ') || rule.startsWith('0.0.0.0 ')) {
      // hosts file format
      const parts = rule.split(/\s+/);
      if (parts.length >= 2) {
        extractedDomain = parts[1];
      }
    } else if (rule.includes('local=/') && rule.includes('/')) {
      // dnsmasq format: local=/domain.com/
      const match = rule.match(/local=\/([^/]+)\//);
      if (match) {
        extractedDomain = match[1];
      }
    } else if (rule.includes('server=/') && rule.includes('/')) {
      // dnsmasq old format: server=/domain.com/
      const match = rule.match(/server=\/([^/]+)\//);
      if (match) {
        extractedDomain = match[1];
      }
    } else if (rule.includes('local-zone:') && rule.includes('always_null')) {
      // unbound format: local-zone: "domain.com." always_null
      const match = rule.match(/local-zone:\s*"([^"]+)\.?"/);
      if (match) {
        extractedDomain = match[1];
      }
    } else if (rule.includes('+block') && rule.includes('.')) {
      // privoxy format: { +block } .domain.com
      const match = rule.match(/\{\s*\+block\s*\}\s*\.?([^\s]+)/);
      if (match) {
        extractedDomain = match[1];
      }
    } else if (rule.match(/^\(\^\|\\\.\).*\\\.\w+\$$/)) {
      // pi-hole regex format: (^|\.)domain\.com$
      const match = rule.match(/^\(\^\|\\\.\)(.+)\\\.\w+\$$/);
      if (match) {
        // Unescape the domain
        extractedDomain = match[1].replace(/\\\./g, '.');
      }
    } else {
      // Try to extract any domain-like pattern as fallback
      const domainMatch = rule.match(/([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})/);
      if (domainMatch) {
        extractedDomain = domainMatch[1];
      }
    }
    
    return extractedDomain;
  } catch (parseErr) {
    return null;
  }
}

/**
 * Post-scan cleanup function to remove first-party domains from results
 * Only processes sites that have firstParty: false in their configuration
 * 
 * @param {Array} results - Array of scan results from all sites
 * @param {Array} sites - Array of site configurations
 * @param {Object} options - Options object
 * @param {boolean} options.forceDebug - Debug logging flag
 * @param {boolean} options.silentMode - Silent mode flag
 * @returns {Array} Cleaned results with conditional first-party removal
 */
function cleanupFirstPartyDomains(results, sites, options = {}) {
  const { forceDebug = false, silentMode = false } = options;
  
  if (!results || results.length === 0) {
    return results;
  }

  // Build mapping of URLs to their site configs
  const urlToSiteConfig = new Map();
  sites.forEach(site => {
    const urls = Array.isArray(site.url) ? site.url : [site.url];
    urls.forEach(url => {
      urlToSiteConfig.set(url, site);
    });
  });

  const cleanedResults = [];
  let totalRulesRemoved = 0;
  let sitesAffected = 0;

  results.forEach(result => {
    // Find the site config for this result
    const siteConfig = urlToSiteConfig.get(result.url);
    
    // Only clean if firstParty is explicitly set to false
    const shouldCleanFirstParty = siteConfig && siteConfig.firstParty === false;
    
    if (!shouldCleanFirstParty || !result.rules || result.rules.length === 0) {
      cleanedResults.push(result);
      return;
    }

    if (forceDebug) {
      console.log(formatLogMessage('debug', `[cleanup] Processing ${result.url} (firstParty: false detected)`));
    }

    // Get the scanned domain for this specific result
    const scannedDomain = safeGetDomain(result.url, false);
    if (!scannedDomain) {
      cleanedResults.push(result);
      return;
    }

    const originalRulesCount = result.rules.length;
    const cleanedRules = [];
    const removedRules = [];

    // Filter out rules that match the scanned domain
    result.rules.forEach(rule => {
      let shouldRemove = false;
      let extractedDomain = null;

      try {
        // Extract domain from different rule formats
        if (rule.startsWith('||') && rule.includes('^')) {
          // ||domain.com^ format (adblock)
          const match = rule.match(/^\|\|([^/\^]+)/);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.startsWith('127.0.0.1 ') || rule.startsWith('0.0.0.0 ')) {
          // hosts file format
          const parts = rule.split(/\s+/);
          if (parts.length >= 2) {
            extractedDomain = parts[1];
          }
        } else if (rule.includes('local=/') && rule.includes('/')) {
          // dnsmasq format: local=/domain.com/
          const match = rule.match(/local=\/([^/]+)\//);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.includes('server=/') && rule.includes('/')) {
          // dnsmasq old format: server=/domain.com/
          const match = rule.match(/server=\/([^/]+)\//);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.includes('local-zone:') && rule.includes('always_null')) {
          // unbound format: local-zone: "domain.com." always_null
          const match = rule.match(/local-zone:\s*"([^"]+)\.?"/);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.includes('+block') && rule.includes('.')) {
          // privoxy format: { +block } .domain.com
          const match = rule.match(/\{\s*\+block\s*\}\s*\.?([^\s]+)/);
          if (match) {
            extractedDomain = match[1];
          }
        } else if (rule.match(/^\(\^\|\\\.\).*\\\.\w+\$$/)) {
          // pi-hole regex format: (^|\.)domain\.com$
          const match = rule.match(/^\(\^\|\\\.\)(.+)\\\.\w+\$$/);
          if (match) {
            // Unescape the domain
            extractedDomain = match[1].replace(/\\\./g, '.');
          }
        } else {
          // Try to extract any domain-like pattern as fallback
          const domainMatch = rule.match(/([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})/);
          if (domainMatch) {
            extractedDomain = domainMatch[1];
          }
        }

        // Check if extracted domain is a first-party domain
        if (extractedDomain) {
          const matchResult = shouldRemoveAsFirstParty(extractedDomain, scannedDomain, forceDebug);
          
          if (matchResult.shouldRemove) {
            removedRules.push({
              rule: rule,
              domain: extractedDomain,
              rootDomain: scannedDomain,
              reason: `First-party: ${matchResult.reason} (firstParty: false)`,
              matchType: matchResult.reason.includes('Wildcard') ? 'wildcard' : 'exact'
            });
            return; // Exit early - rule should be removed
          }
        }
      } catch (parseErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[cleanup] Failed to parse rule: ${rule} - ${parseErr.message}`));
        }
      }

      // If we reach here, the rule should be kept
      cleanedRules.push(rule);
    });

    cleanedResults.push({ ...result, rules: cleanedRules });

    if (removedRules.length > 0) {
      sitesAffected++;
      totalRulesRemoved += removedRules.length;
      
      if (!silentMode) {
        const wildcardCount = removedRules.filter(r => r.matchType === 'wildcard').length;
        const exactCount = removedRules.filter(r => r.matchType === 'exact').length;
        
        let cleanupMessage = `?? Cleaned ${removedRules.length} first-party rule(s) from ${scannedDomain} (firstParty: false)`;
        if (wildcardCount > 0) {
          cleanupMessage += ` [${wildcardCount} wildcard, ${exactCount} exact]`;
        }
        if (messageColors && messageColors.cleanup) {
          console.log(messageColors.cleanup(cleanupMessage));
        } else {
          console.log(cleanupMessage);
        }
      }

      if (forceDebug) {
        console.log(formatLogMessage('debug', `[cleanup] Removed rules from ${result.url}:`));
        removedRules.forEach((removed, idx) => {
          console.log(formatLogMessage('debug', `  [${idx + 1}] ${removed.rule} (${removed.reason}) [${removed.matchType}]`));
        });
      }
    }
  });

  // Summary
  if (totalRulesRemoved > 0 && !silentMode) {
    const summaryMessage = `\n?? First-party cleanup completed: Removed ${totalRulesRemoved} rules from ${sitesAffected} site(s) with firstParty: false`;
    if (messageColors && messageColors.cleanup) {
      console.log(messageColors.cleanup(summaryMessage));
    } else {
      console.log(summaryMessage);
    }
  } else if (forceDebug) {
    console.log(formatLogMessage('debug', '[cleanup] No first-party rules found to remove'));
  }

  return cleanedResults;
}

/**
 * Validates scan results and removes any obvious false positives
 * 
 * @param {Array} results - Array of scan results
 * @param {Object} options - Options object
 * @param {boolean} options.forceDebug - Debug logging flag
 * @param {Array} options.ignoreDomains - Domains to ignore
 * @returns {Array} Validated results
 */
function validateScanResults(results, options = {}) {
  const { forceDebug = false, ignoreDomains = [] } = options;
  
  if (!results || results.length === 0) {
    return results;
  }

  let totalValidated = 0;
  let totalRemoved = 0;

  const validatedResults = results.map(result => {
    if (!result.rules || result.rules.length === 0) {
      return result;
    }

    const originalCount = result.rules.length;
    const validRules = result.rules.filter(rule => {
      // Basic validation - ensure rule isn't empty or malformed
      if (!rule || typeof rule !== 'string' || rule.trim().length === 0) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `[validation] Removed empty/invalid rule`));
        }
        totalRemoved++;
        return false;
      }

      // Check against ignore domains if provided
      if (ignoreDomains.length > 0) {
        for (const ignorePattern of ignoreDomains) {
          if (rule.includes(ignorePattern.replace('*', ''))) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `[validation] Removed rule matching ignore pattern: ${ignorePattern}`));
            }
            totalRemoved++;
            return false;
          }
        }
      }

      return true;
    });

    totalValidated += originalCount;
    return { ...result, rules: validRules };
  });

  if (forceDebug && totalRemoved > 0) {
    console.log(formatLogMessage('debug', `[validation] Validated ${totalValidated} rules, removed ${totalRemoved} invalid rules`));
  }

  return validatedResults;
}


/**
 * Final validation check for firstParty: false violations
 * Reuses existing domain extraction and matching logic
 * 
 * @param {Array} results - Array of scan results
 * @param {Array} sites - Array of site configurations  
 * @param {Object} options - Options object
 * @returns {Array} Results with any remaining first-party domains removed
 */
function finalFirstPartyValidation(results, sites, options = {}) {
  const { forceDebug = false, silentMode = false } = options;
  
  if (!results || results.length === 0) {
    return results;
  }

  // Reuse the URL-to-config mapping pattern from cleanupFirstPartyDomains
  const urlToSiteConfig = new Map();
  sites.forEach(site => {
    const urls = Array.isArray(site.url) ? site.url : [site.url];
    urls.forEach(url => {
      urlToSiteConfig.set(url, site);
    });
  });

  const finalResults = [];
  let totalViolationsFound = 0;
  let sitesWithViolations = 0;

  results.forEach(result => {
    const siteConfig = urlToSiteConfig.get(result.url);
    
    // Only validate sites with firstParty: false
    const shouldValidate = siteConfig && siteConfig.firstParty === false;
    
    if (!shouldValidate || !result.rules || result.rules.length === 0) {
      finalResults.push(result);
      return;
    }

    const scannedDomain = safeGetDomain(result.url, false);
    if (!scannedDomain) {
      finalResults.push(result);
      return;
    }

    // Reuse the same filtering logic pattern from cleanupFirstPartyDomains
    const cleanedRules = [];
    const violatingRules = [];

    result.rules.forEach(rule => {
      const extractedDomain = extractDomainFromRule(rule);
      if (extractedDomain) {
        // Reuse the shouldRemoveAsFirstParty logic
        const matchResult = shouldRemoveAsFirstParty(extractedDomain, scannedDomain, forceDebug);
        
        if (matchResult.shouldRemove) {
          violatingRules.push({
            rule: rule,
            domain: extractedDomain,
            reason: `VALIDATION FAILURE: ${matchResult.reason}`
          });
          totalViolationsFound++;
          return;
        }
      }
      cleanedRules.push(rule);
    });

    if (violatingRules.length > 0) {
      sitesWithViolations++;
      
      if (!silentMode) {
        const errorMessage = `? CONFIG VIOLATION: Found ${violatingRules.length} first-party rule(s) in ${scannedDomain} (firstParty: false)`;
        if (messageColors && messageColors.error) {
          console.log(messageColors.error(errorMessage));
        } else {
          console.log(errorMessage);
        }
      }

      if (forceDebug) {
        console.log(formatLogMessage('debug', `[final-validation] Violations found for ${result.url}:`));
        violatingRules.forEach((violation, idx) => {
          console.log(formatLogMessage('debug', `  [${idx + 1}] ${violation.rule} -> ${violation.domain}`));
        });
      }
    }

    finalResults.push({ ...result, rules: cleanedRules });
  });

  // Summary using existing message patterns
  if (totalViolationsFound > 0 && !silentMode) {
    const summaryMessage = `\n? SCAN FILTERING FAILURE: Removed ${totalViolationsFound} first-party rules from ${sitesWithViolations} site(s) in post-processing`;
    console.log(summaryMessage);
    console.log('??  This indicates firstParty: false filtering failed during scan - consider investigating root cause.');
  } else if (forceDebug) {
    console.log(formatLogMessage('debug', '[final-validation] No first-party violations found - filtering working correctly'));
  }

  return finalResults;
}

/**
 * Main post-processing function that runs all cleanup and validation steps
 * 
 * @param {Array} results - Array of scan results from all sites
 * @param {Array} sites - Array of site configurations
 * @param {Object} options - Options object
 * @param {boolean} options.forceDebug - Debug logging flag
 * @param {boolean} options.silentMode - Silent mode flag
 * @param {Array} options.ignoreDomains - Domains to ignore during validation
 * @returns {Array} Fully processed and cleaned results
 */
function processResults(results, sites, options = {}) {
  const { forceDebug = false, silentMode = false } = options;
  
  if (forceDebug) {
    console.log(formatLogMessage('debug', `[post-processing] Starting post-processing of ${results.length} results`));
  }

  // Step 1: Clean up first-party domains
  let processedResults = cleanupFirstPartyDomains(results, sites, options);
  
  // Step 2: Clean up ignoreDomains (final safety net)
  processedResults = cleanupIgnoreDomains(processedResults, options.ignoreDomains || [], options);
  
  // Step 3: Final validation for firstParty: false configurations
  processedResults = finalFirstPartyValidation(processedResults, sites, options);

  // Step 4: Validate results
  processedResults = validateScanResults(processedResults, options);
  
  if (forceDebug) {
    const totalRules = processedResults.reduce((sum, r) => sum + (r.rules ? r.rules.length : 0), 0);
    console.log(formatLogMessage('debug', `[post-processing] Completed: ${totalRules} total rules remaining`));
  }

  return processedResults;
}

module.exports = {
  cleanupFirstPartyDomains,
  cleanupIgnoreDomains,
  finalFirstPartyValidation,
  extractDomainFromRule,
  validateScanResults,
  processResults
};