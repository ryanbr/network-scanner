// === Post-Processing Module for Network Scanner ===
// Handles cleanup and validation of scan results after scanning is complete

const { formatLogMessage, messageColors } = require('./colorize');
const psl = require('psl');

// Precompiled regex patterns (avoids recompilation per rule)
const REGEX_ADBLOCK = /^\|\|([^/\^]+)/;
const REGEX_DNSMASQ_LOCAL = /local=\/([^/]+)\//;
const REGEX_DNSMASQ_SERVER = /server=\/([^/]+)\//;
const REGEX_UNBOUND = /local-zone:\s*"([^"]+)\.?"/;
const REGEX_PRIVOXY = /\{\s*\+block\s*\}\s*\.?([^\s]+)/;
const REGEX_PIHOLE = /^\(\^\|\\\.\)(.+)\\\.\w+\$$/;
const REGEX_DOMAIN_FALLBACK = /([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})/;
const REGEX_WHITESPACE = /\s+/;
const REGEX_UNESCAPE_DOT = /\\\./g;

// Cache for compiled wildcard regex patterns
const wildcardRegexCache = new Map();

/**
 * Get or compile a wildcard pattern regex (cached)
 * @param {string} pattern - Wildcard pattern string
 * @returns {RegExp} Compiled regex
 */
function getWildcardRegex(pattern) {
  let regex = wildcardRegexCache.get(pattern);
  if (!regex) {
    regex = new RegExp('^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
    wildcardRegexCache.set(pattern, regex);
    // Cap cache size
    if (wildcardRegexCache.size > 200) {
      const firstKey = wildcardRegexCache.keys().next().value;
      wildcardRegexCache.delete(firstKey);
    }
  }
  return regex;
}

/**
 * Safely extracts hostname from a URL, handling malformed URLs gracefully
 * @param {string} url - The URL string to parse
 * @param {boolean} getFullHostname - If true, returns full hostname; if false, returns root domain
 * @returns {string} The hostname/domain, or empty string if URL is invalid
 */
function safeGetDomain(url, getFullHostname = false) {
  try {
    const parsedUrl = new URL(url);
    if (getFullHostname) {
      return parsedUrl.hostname;
    }
    const parsed = psl.parse(parsedUrl.hostname);
    return parsed.domain || parsedUrl.hostname;
  } catch (urlError) {
    return '';
  }
}

/**
 * Enhanced domain extraction helper - single source of truth for all rule formats
 * (Was duplicated inline in cleanupIgnoreDomains and cleanupFirstPartyDomains)
 * @param {string} rule - Rule string in various formats
 * @returns {string|null} Extracted domain or null if not found
 */
function extractDomainFromRule(rule) {
  if (!rule || typeof rule !== 'string') {
    return null;
  }

  // Adblock: ||domain.com^
  if (rule.charCodeAt(0) === 124 && rule.charCodeAt(1) === 124 && rule.includes('^')) { // '||' + '^'
    const match = REGEX_ADBLOCK.exec(rule);
    return match ? match[1] : null;
  }

  // Hosts file: 127.0.0.1 domain / 0.0.0.0 domain
  if (rule.charCodeAt(0) === 49 || rule.charCodeAt(0) === 48) { // '1' or '0'
    if (rule.startsWith('127.0.0.1 ') || rule.startsWith('0.0.0.0 ')) {
      const parts = rule.split(REGEX_WHITESPACE);
      return parts.length >= 2 ? parts[1] : null;
    }
  }

  // dnsmasq: local=/domain.com/
  if (rule.includes('local=/')) {
    const match = REGEX_DNSMASQ_LOCAL.exec(rule);
    return match ? match[1] : null;
  }

  // dnsmasq old: server=/domain.com/
  if (rule.includes('server=/')) {
    const match = REGEX_DNSMASQ_SERVER.exec(rule);
    return match ? match[1] : null;
  }

  // Unbound: local-zone: "domain.com." always_null
  if (rule.includes('local-zone:') && rule.includes('always_null')) {
    const match = REGEX_UNBOUND.exec(rule);
    return match ? match[1] : null;
  }

  // Privoxy: { +block } .domain.com
  if (rule.includes('+block') && rule.includes('.')) {
    const match = REGEX_PRIVOXY.exec(rule);
    return match ? match[1] : null;
  }

  // Pi-hole regex: (^|\.)domain\.com$ -- single match (was tested then matched separately)
  if (rule.charCodeAt(0) === 40) { // '('
    const match = REGEX_PIHOLE.exec(rule);
    return match ? match[1].replace(REGEX_UNESCAPE_DOT, '.') : null;
  }

  // Fallback: any domain-like pattern
  const domainMatch = REGEX_DOMAIN_FALLBACK.exec(rule);
  return domainMatch ? domainMatch[1] : null;
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

  for (let i = 0; i < ignorePatterns.length; i++) {
    const pattern = ignorePatterns[i];
    if (pattern.includes('*')) {
      if (pattern.startsWith('*.')) {
        // Pattern: *.example.com
        const wildcardDomain = pattern.substring(2);
        const wildcardRoot = safeGetDomain('http://' + wildcardDomain, false);
        const domainRoot = safeGetDomain('http://' + domain, false);
        
        if (wildcardRoot === domainRoot) {
          return { shouldIgnore: true, reason: 'Matches wildcard ignore pattern: ' + pattern };
        }
      } else if (pattern.endsWith('.*')) {
        // Pattern: example.*
        const baseDomain = pattern.slice(0, -2);
        if (domain.startsWith(baseDomain + '.')) {
          return { shouldIgnore: true, reason: 'Matches wildcard TLD ignore pattern: ' + pattern };
        }
      } else {
        // Complex wildcard -- use cached regex
        const wildcardRegex = getWildcardRegex(pattern);
        if (wildcardRegex.test(domain)) {
          return { shouldIgnore: true, reason: 'Matches complex wildcard ignore pattern: ' + pattern };
        }
      }
    } else {
      // Exact pattern matching
      if (domain === pattern || domain.endsWith('.' + pattern)) {
        return { shouldIgnore: true, reason: 'Matches exact ignore pattern: ' + pattern };
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

  if (extractedDomain.includes('*')) {
    if (extractedDomain.startsWith('*.')) {
      const wildcardDomain = extractedDomain.substring(2);
      const wildcardRoot = safeGetDomain('http://' + wildcardDomain, false);
      
      if (wildcardRoot === scannedRootDomain) {
        return { shouldRemove: true, reason: 'Wildcard subdomain pattern matches root domain (*.' + wildcardRoot + ')' };
      }
    } else if (extractedDomain.endsWith('.*')) {
      const baseDomain = extractedDomain.slice(0, -2);
      if (scannedRootDomain.startsWith(baseDomain + '.')) {
        return { shouldRemove: true, reason: 'Wildcard TLD pattern matches base domain (' + baseDomain + '.*)' };
      }
    } else {
      // Complex wildcard -- use cached regex
      const wildcardRegex = getWildcardRegex(extractedDomain);
      if (wildcardRegex.test(scannedRootDomain)) {
        return { shouldRemove: true, reason: 'Complex wildcard pattern matches root domain (' + extractedDomain + ')' };
      }
    }
  }

  // Standard exact root domain matching
  const extractedRoot = safeGetDomain('http://' + extractedDomain, false);
  if (extractedRoot === scannedRootDomain) {
    return { shouldRemove: true, reason: 'Exact root domain match (' + extractedRoot + ')' };
  }

  return { shouldRemove: false, reason: 'No first-party match detected' };
}

/**
 * Build URL-to-site-config mapping (shared between cleanup functions)
 * @param {Array} sites - Array of site configurations
 * @returns {Map} URL to site config mapping
 */
function buildUrlToSiteConfig(sites) {
  const map = new Map();
  for (let i = 0; i < sites.length; i++) {
    const site = sites[i];
    const urls = Array.isArray(site.url) ? site.url : [site.url];
    for (let j = 0; j < urls.length; j++) {
      map.set(urls[j], site);
    }
  }
  return map;
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
    console.log(formatLogMessage('debug', '[ignoreDomains cleanup] Processing ' + results.length + ' results against ' + ignoreDomains.length + ' ignore patterns'));
  }

  const cleanedResults = [];
  let totalRulesRemoved = 0;
  let sitesAffected = 0;

  for (let ri = 0; ri < results.length; ri++) {
    const result = results[ri];
    if (!result.rules || result.rules.length === 0) {
      cleanedResults.push(result);
      continue;
    }

    const cleanedRules = [];
    const removedRules = [];

    for (let j = 0; j < result.rules.length; j++) {
      const rule = result.rules[j];
      let kept = true;

      try {
        // Use shared extractDomainFromRule (was duplicated inline)
        const extractedDomain = extractDomainFromRule(rule);
        
        if (extractedDomain) {
          const ignoreResult = shouldIgnoreAsIgnoreDomain(extractedDomain, ignoreDomains, forceDebug);
          
          if (ignoreResult.shouldIgnore) {
            removedRules.push({
              rule: rule,
              domain: extractedDomain,
              reason: 'ignoreDomains: ' + ignoreResult.reason,
              matchType: ignoreResult.reason.includes('wildcard') ? 'wildcard' : 'exact'
            });
            kept = false;
          }
        }
      } catch (parseErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', '[ignoreDomains cleanup] Failed to parse rule: ' + rule + ' - ' + parseErr.message));
        }
      }

      if (kept) {
        cleanedRules.push(rule);
      }
    }

    // Mutate rules directly instead of spreading entire result object
    result.rules = cleanedRules;
    cleanedResults.push(result);

    if (removedRules.length > 0) {
      sitesAffected++;
      totalRulesRemoved += removedRules.length;
      
      if (!silentMode) {
        // Single-pass count instead of two .filter() calls
        let wildcardCount = 0;
        for (let k = 0; k < removedRules.length; k++) {
          if (removedRules[k].matchType === 'wildcard') wildcardCount++;
        }
        const exactCount = removedRules.length - wildcardCount;
        
        let cleanupMessage = '?? Removed ' + removedRules.length + ' ignoreDomains rule(s) from ' + safeGetDomain(result.url) + ' (final cleanup)';
        if (wildcardCount > 0) {
          cleanupMessage += ' [' + wildcardCount + ' wildcard, ' + exactCount + ' exact]';
        }
        
        if (messageColors && messageColors.cleanup) {
          console.log(messageColors.cleanup(cleanupMessage));
        } else {
          console.log(cleanupMessage);
        }
      }
      if (forceDebug) {
        console.log(formatLogMessage('debug', '[ignoreDomains cleanup] Removed rules from ' + result.url + ':'));
        for (let k = 0; k < removedRules.length; k++) {
          console.log(formatLogMessage('debug', '  [' + (k + 1) + '] ' + removedRules[k].rule + ' (' + removedRules[k].reason + ') [' + removedRules[k].matchType + ']'));
        }
      }
    }
  }

  // Summary
  if (totalRulesRemoved > 0 && !silentMode) {
    const summaryMessage = '\n?? ignoreDomains cleanup completed: Removed ' + totalRulesRemoved + ' rules from ' + sitesAffected + ' site(s)';

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
 * Post-scan cleanup function to remove first-party domains from results
 * Only processes sites that have firstParty: false in their configuration
 * 
 * @param {Array} results - Array of scan results from all sites
 * @param {Array} sites - Array of site configurations
 * @param {Object} options - Options object
 * @param {boolean} options.forceDebug - Debug logging flag
 * @param {boolean} options.silentMode - Silent mode flag
 * @param {Map} [options._urlToSiteConfig] - Pre-built URL mapping (internal optimization)
 * @returns {Array} Cleaned results with conditional first-party removal
 */
function cleanupFirstPartyDomains(results, sites, options = {}) {
  const { forceDebug = false, silentMode = false } = options;
  
  if (!results || results.length === 0) {
    return results;
  }

  // Use pre-built map if passed, otherwise build it
  const urlToSiteConfig = options._urlToSiteConfig || buildUrlToSiteConfig(sites);

  const cleanedResults = [];
  let totalRulesRemoved = 0;
  let sitesAffected = 0;

  for (let ri = 0; ri < results.length; ri++) {
    const result = results[ri];
    const siteConfig = urlToSiteConfig.get(result.url);
    const shouldCleanFirstParty = siteConfig && siteConfig.firstParty === false;
    
    if (!shouldCleanFirstParty || !result.rules || result.rules.length === 0) {
      cleanedResults.push(result);
      continue;
    }

    if (forceDebug) {
      console.log(formatLogMessage('debug', '[cleanup] Processing ' + result.url + ' (firstParty: false detected)'));
    }

    const scannedDomain = safeGetDomain(result.url, false);
    if (!scannedDomain) {
      cleanedResults.push(result);
      continue;
    }

    const cleanedRules = [];
    const removedRules = [];

    for (let j = 0; j < result.rules.length; j++) {
      const rule = result.rules[j];
      let kept = true;

      try {
        // Use shared extractDomainFromRule (was duplicated inline)
        const extractedDomain = extractDomainFromRule(rule);

        if (extractedDomain) {
          const matchResult = shouldRemoveAsFirstParty(extractedDomain, scannedDomain, forceDebug);
          
          if (matchResult.shouldRemove) {
            removedRules.push({
              rule: rule,
              domain: extractedDomain,
              rootDomain: scannedDomain,
              reason: 'First-party: ' + matchResult.reason + ' (firstParty: false)',
              matchType: matchResult.reason.includes('Wildcard') ? 'wildcard' : 'exact'
            });
            kept = false;
          }
        }
      } catch (parseErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', '[cleanup] Failed to parse rule: ' + rule + ' - ' + parseErr.message));
        }
      }

      if (kept) {
        cleanedRules.push(rule);
      }
    }

    // Mutate rules directly instead of { ...result, rules: cleanedRules }
    result.rules = cleanedRules;
    cleanedResults.push(result);

    if (removedRules.length > 0) {
      sitesAffected++;
      totalRulesRemoved += removedRules.length;
      
      if (!silentMode) {
        // Single-pass count
        let wildcardCount = 0;
        for (let k = 0; k < removedRules.length; k++) {
          if (removedRules[k].matchType === 'wildcard') wildcardCount++;
        }
        const exactCount = removedRules.length - wildcardCount;
        
        let cleanupMessage = '?? Cleaned ' + removedRules.length + ' first-party rule(s) from ' + scannedDomain + ' (firstParty: false)';
        if (wildcardCount > 0) {
          cleanupMessage += ' [' + wildcardCount + ' wildcard, ' + exactCount + ' exact]';
        }
        if (messageColors && messageColors.cleanup) {
          console.log(messageColors.cleanup(cleanupMessage));
        } else {
          console.log(cleanupMessage);
        }
      }

      if (forceDebug) {
        console.log(formatLogMessage('debug', '[cleanup] Removed rules from ' + result.url + ':'));
        for (let k = 0; k < removedRules.length; k++) {
          console.log(formatLogMessage('debug', '  [' + (k + 1) + '] ' + removedRules[k].rule + ' (' + removedRules[k].reason + ') [' + removedRules[k].matchType + ']'));
        }
      }
    }
  }

  // Summary
  if (totalRulesRemoved > 0 && !silentMode) {
    const summaryMessage = '\n?? First-party cleanup completed: Removed ' + totalRulesRemoved + ' rules from ' + sitesAffected + ' site(s) with firstParty: false';
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

  // Pre-strip wildcards from ignore patterns once (was done per rule per pattern)
  let strippedIgnorePatterns = null;
  if (ignoreDomains.length > 0) {
    strippedIgnorePatterns = new Array(ignoreDomains.length);
    for (let i = 0; i < ignoreDomains.length; i++) {
      strippedIgnorePatterns[i] = ignoreDomains[i].replace('*', '');
    }
  }

  for (let ri = 0; ri < results.length; ri++) {
    const result = results[ri];
    if (!result.rules || result.rules.length === 0) {
      continue;
    }

    const originalCount = result.rules.length;
    const validRules = [];
    
    for (let j = 0; j < result.rules.length; j++) {
      const rule = result.rules[j];
      
      // Basic validation
      if (!rule || typeof rule !== 'string' || rule.trim().length === 0) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', '[validation] Removed empty/invalid rule'));
        }
        totalRemoved++;
        continue;
      }

      // Check against stripped ignore patterns
      let ignored = false;
      if (strippedIgnorePatterns) {
        for (let k = 0; k < strippedIgnorePatterns.length; k++) {
          if (rule.includes(strippedIgnorePatterns[k])) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', '[validation] Removed rule matching ignore pattern: ' + ignoreDomains[k]));
            }
            totalRemoved++;
            ignored = true;
            break;
          }
        }
      }

      if (!ignored) {
        validRules.push(rule);
      }
    }

    totalValidated += originalCount;
    // Mutate in place instead of spread
    result.rules = validRules;
  }

  if (forceDebug && totalRemoved > 0) {
    console.log(formatLogMessage('debug', '[validation] Validated ' + totalValidated + ' rules, removed ' + totalRemoved + ' invalid rules'));
  }

  return results;
}


/**
 * Final validation check for firstParty: false violations
 * Reuses existing domain extraction and matching logic
 * 
 * @param {Array} results - Array of scan results
 * @param {Array} sites - Array of site configurations  
 * @param {Object} options - Options object
 * @param {Map} [options._urlToSiteConfig] - Pre-built URL mapping (internal optimization)
 * @returns {Array} Results with any remaining first-party domains removed
 */
function finalFirstPartyValidation(results, sites, options = {}) {
  const { forceDebug = false, silentMode = false } = options;
  
  if (!results || results.length === 0) {
    return results;
  }

  // Use pre-built map if passed, otherwise build it
  const urlToSiteConfig = options._urlToSiteConfig || buildUrlToSiteConfig(sites);

  const finalResults = [];
  let totalViolationsFound = 0;
  let sitesWithViolations = 0;

  for (let ri = 0; ri < results.length; ri++) {
    const result = results[ri];
    const siteConfig = urlToSiteConfig.get(result.url);
    const shouldValidate = siteConfig && siteConfig.firstParty === false;
    
    if (!shouldValidate || !result.rules || result.rules.length === 0) {
      finalResults.push(result);
      continue;
    }

    const scannedDomain = safeGetDomain(result.url, false);
    if (!scannedDomain) {
      finalResults.push(result);
      continue;
    }

    const cleanedRules = [];
    const violatingRules = [];

    for (let j = 0; j < result.rules.length; j++) {
      const rule = result.rules[j];
      const extractedDomain = extractDomainFromRule(rule);
      
      if (extractedDomain) {
        const matchResult = shouldRemoveAsFirstParty(extractedDomain, scannedDomain, forceDebug);
        
        if (matchResult.shouldRemove) {
          violatingRules.push({
            rule: rule,
            domain: extractedDomain,
            reason: 'VALIDATION FAILURE: ' + matchResult.reason
          });
          totalViolationsFound++;
          continue;
        }
      }
      cleanedRules.push(rule);
    }

    if (violatingRules.length > 0) {
      sitesWithViolations++;
      
      if (!silentMode) {
        const errorMessage = '? CONFIG VIOLATION: Found ' + violatingRules.length + ' first-party rule(s) in ' + scannedDomain + ' (firstParty: false)';
        if (messageColors && messageColors.error) {
          console.log(messageColors.error(errorMessage));
        } else {
          console.log(errorMessage);
        }
      }

      if (forceDebug) {
        console.log(formatLogMessage('debug', '[final-validation] Violations found for ' + result.url + ':'));
        for (let k = 0; k < violatingRules.length; k++) {
          console.log(formatLogMessage('debug', '  [' + (k + 1) + '] ' + violatingRules[k].rule + ' -> ' + violatingRules[k].domain));
        }
      }
    }

    // Mutate in place
    result.rules = cleanedRules;
    finalResults.push(result);
  }

  // Summary
  if (totalViolationsFound > 0 && !silentMode) {
    const summaryMessage = '\n? SCAN FILTERING FAILURE: Removed ' + totalViolationsFound + ' first-party rules from ' + sitesWithViolations + ' site(s) in post-processing';
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
    console.log(formatLogMessage('debug', '[post-processing] Starting post-processing of ' + results.length + ' results'));
  }

  // Build URL-to-config map once, share across all steps
  const urlToSiteConfig = buildUrlToSiteConfig(sites);
  const sharedOptions = Object.assign({}, options, { _urlToSiteConfig: urlToSiteConfig });

  // Step 1: Clean up first-party domains
  let processedResults = cleanupFirstPartyDomains(results, sites, sharedOptions);
  
  // Step 2: Clean up ignoreDomains (final safety net)
  processedResults = cleanupIgnoreDomains(processedResults, options.ignoreDomains || [], options);
  
  // Step 3: Final validation for firstParty: false configurations
  processedResults = finalFirstPartyValidation(processedResults, sites, sharedOptions);

  // Step 4: Validate results
  processedResults = validateScanResults(processedResults, options);
  
  if (forceDebug) {
    let totalRules = 0;
    for (let i = 0; i < processedResults.length; i++) {
      totalRules += processedResults[i].rules ? processedResults[i].rules.length : 0;
    }
    console.log(formatLogMessage('debug', '[post-processing] Completed: ' + totalRules + ' total rules remaining'));
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
