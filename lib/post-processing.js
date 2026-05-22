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
// Pi-hole prefix detect + strip (tolerates optional backslash before the dot,
// matching how output.js writes both). The old single-regex with a trailing
// `\.\w+$` was capturing everything up to (but not including) the TLD, so
// 'example.com' came out as 'example' and downstream filters never matched.
const REGEX_PIHOLE_PREFIX = /^\(\^\|\\?\.\)/;
const REGEX_TRAILING_DOLLAR = /\$$/;
const REGEX_DOMAIN_FALLBACK = /([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})/;
const REGEX_WHITESPACE = /\s+/;
const REGEX_UNESCAPE_DOT = /\\\./g;
// Regex meta-chars we must escape in a wildcard pattern before turning '*'
// into '.*'. Without this, a pattern like 'foo+bar.com' would treat '+' as
// a quantifier, and 'foo(bar.com' would throw on RegExp construction.
const REGEX_META_ESCAPE = /[.+?^${}()|[\]\\]/g;
// Sentinel regex that never matches — used when a pattern is so malformed
// that even our escaped version fails to compile.
const NEVER_MATCH = /(?!)/;

// Cache for compiled wildcard regex patterns
const wildcardRegexCache = new Map();

/**
 * Get or compile a wildcard pattern regex (cached). Escapes every regex
 * metacharacter except '*' before turning '*' into '.*'. The previous
 * version only escaped '.', so patterns with '+', '(', '[', etc. would
 * either silently misbehave or throw synchronously out of the caller.
 * @param {string} pattern - Wildcard pattern string
 * @returns {RegExp} Compiled regex
 */
function getWildcardRegex(pattern) {
  let regex = wildcardRegexCache.get(pattern);
  if (!regex) {
    try {
      regex = new RegExp(
        '^' +
        pattern.replace(REGEX_META_ESCAPE, '\\$&').replace(/\*/g, '.*') +
        '$'
      );
    } catch (_) {
      // Defensive belt-and-braces: a still-malformed pattern becomes
      // never-match instead of crashing the calling cleanup loop.
      regex = NEVER_MATCH;
    }
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
 * Extract the registrable root domain from an already-parsed hostname,
 * skipping the URL-parse round-trip that safeGetDomain pays. Use when the
 * caller already knows the input is a bare hostname (no scheme, path, port).
 * @param {string} hostname - Bare hostname (e.g. 'sub.example.com')
 * @returns {string} Registrable root domain ('example.com'), or hostname back
 *   on psl parse failure, or '' on bad input
 */
function getDomainFromHostname(hostname) {
  if (!hostname || typeof hostname !== 'string') return '';
  try {
    const parsed = psl.parse(hostname);
    return parsed.domain || hostname;
  } catch (_) {
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

  // Pi-hole regex: (^|\.)domain\.com$
  // Strip the leading '(^|\.)' (or '(^|.)') prefix, unescape '\.' to '.',
  // and drop the trailing '$'. Matches output.js's extractDomainFromRule
  // shape — the old regex-based capture here lost the TLD.
  if (rule.charCodeAt(0) === 40 && REGEX_PIHOLE_PREFIX.test(rule)) { // '('
    return rule
      .replace(REGEX_PIHOLE_PREFIX, '')
      .replace(REGEX_UNESCAPE_DOT, '.')
      .replace(REGEX_TRAILING_DOLLAR, '');
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
    return { shouldIgnore: false, reason: 'No ignore patterns', matchType: null };
  }

  // domain is loop-invariant — its registrable root only needs computing once
  // (and only if at least one '*.' pattern is encountered). Previously we
  // called getDomainFromHostname(domain) once per '*.'-shaped pattern.
  let domainRoot = null;
  let domainRootComputed = false;

  for (let i = 0; i < ignorePatterns.length; i++) {
    const pattern = ignorePatterns[i];
    if (pattern.includes('*')) {
      if (pattern.startsWith('*.')) {
        // Pattern: *.example.com — both sides are already bare hostnames,
        // skip the 'http://' wrap + URL parse.
        const wildcardDomain = pattern.substring(2);
        const wildcardRoot = getDomainFromHostname(wildcardDomain);
        if (!domainRootComputed) {
          domainRoot = getDomainFromHostname(domain);
          domainRootComputed = true;
        }

        if (wildcardRoot === domainRoot) {
          if (forceDebug) console.log(formatLogMessage('debug', '[ignoreDomains] ' + domain + ' matches wildcard pattern ' + pattern + ' (root=' + wildcardRoot + ')'));
          return { shouldIgnore: true, reason: 'Matches wildcard ignore pattern: ' + pattern, matchType: 'wildcard' };
        }
      } else if (pattern.endsWith('.*')) {
        // Pattern: example.*
        const baseDomain = pattern.slice(0, -2);
        if (domain.startsWith(baseDomain + '.')) {
          if (forceDebug) console.log(formatLogMessage('debug', '[ignoreDomains] ' + domain + ' matches TLD-wildcard pattern ' + pattern));
          return { shouldIgnore: true, reason: 'Matches wildcard TLD ignore pattern: ' + pattern, matchType: 'wildcard' };
        }
      } else {
        // Complex wildcard -- use cached regex
        const wildcardRegex = getWildcardRegex(pattern);
        if (wildcardRegex.test(domain)) {
          if (forceDebug) console.log(formatLogMessage('debug', '[ignoreDomains] ' + domain + ' matches complex wildcard pattern ' + pattern));
          return { shouldIgnore: true, reason: 'Matches complex wildcard ignore pattern: ' + pattern, matchType: 'wildcard' };
        }
      }
    } else {
      // Exact pattern matching
      if (domain === pattern || domain.endsWith('.' + pattern)) {
        if (forceDebug) console.log(formatLogMessage('debug', '[ignoreDomains] ' + domain + ' matches exact pattern ' + pattern));
        return { shouldIgnore: true, reason: 'Matches exact ignore pattern: ' + pattern, matchType: 'exact' };
      }
    }
  }

  return { shouldIgnore: false, reason: 'No ignore pattern matches', matchType: null };
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
    return { shouldRemove: false, reason: 'Missing domain data', matchType: null };
  }

  if (extractedDomain.includes('*')) {
    if (extractedDomain.startsWith('*.')) {
      const wildcardDomain = extractedDomain.substring(2);
      const wildcardRoot = getDomainFromHostname(wildcardDomain);

      if (wildcardRoot === scannedRootDomain) {
        if (forceDebug) console.log(formatLogMessage('debug', '[firstParty] ' + extractedDomain + ' matches root domain via wildcard subdomain (*.' + wildcardRoot + ')'));
        return { shouldRemove: true, reason: 'Wildcard subdomain pattern matches root domain (*.' + wildcardRoot + ')', matchType: 'wildcard' };
      }
    } else if (extractedDomain.endsWith('.*')) {
      const baseDomain = extractedDomain.slice(0, -2);
      if (scannedRootDomain.startsWith(baseDomain + '.')) {
        if (forceDebug) console.log(formatLogMessage('debug', '[firstParty] ' + extractedDomain + ' matches root domain via TLD-wildcard (' + baseDomain + '.*)'));
        return { shouldRemove: true, reason: 'Wildcard TLD pattern matches base domain (' + baseDomain + '.*)', matchType: 'wildcard' };
      }
    } else {
      // Complex wildcard -- use cached regex
      const wildcardRegex = getWildcardRegex(extractedDomain);
      if (wildcardRegex.test(scannedRootDomain)) {
        if (forceDebug) console.log(formatLogMessage('debug', '[firstParty] ' + extractedDomain + ' matches root domain via complex wildcard'));
        return { shouldRemove: true, reason: 'Complex wildcard pattern matches root domain (' + extractedDomain + ')', matchType: 'wildcard' };
      }
    }
  }

  // Standard exact root domain matching — extractedDomain is already a bare
  // hostname out of extractDomainFromRule.
  const extractedRoot = getDomainFromHostname(extractedDomain);
  if (extractedRoot === scannedRootDomain) {
    if (forceDebug) console.log(formatLogMessage('debug', '[firstParty] ' + extractedDomain + ' matches root domain ' + scannedRootDomain + ' exactly (root=' + extractedRoot + ')'));
    return { shouldRemove: true, reason: 'Exact root domain match (' + extractedRoot + ')', matchType: 'exact' };
  }

  return { shouldRemove: false, reason: 'No first-party match detected', matchType: null };
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

  // We mutate result.rules in place and return `results` directly — the
  // previous version allocated a separate cleanedResults array but pushed
  // every original result reference into it unchanged, which was pure waste
  // (and gave callers a false sense of immutability when the input was
  // being mutated anyway).
  let totalRulesRemoved = 0;
  let sitesAffected = 0;
  // The per-rule detail objects in removedRules are only consumed by the
  // forceDebug per-rule list — skip allocating them on the silent/non-debug
  // path. Counts (wildcard/exact) are tracked separately because the
  // !silentMode summary still needs them.
  const needsDetails = forceDebug;

  for (let ri = 0; ri < results.length; ri++) {
    const result = results[ri];
    if (!result.rules || result.rules.length === 0) continue;

    const cleanedRules = [];
    const removedRules = needsDetails ? [] : null;
    let removedCount = 0;
    let wildcardCount = 0;

    for (let j = 0; j < result.rules.length; j++) {
      const rule = result.rules[j];
      let kept = true;

      try {
        // Use shared extractDomainFromRule (was duplicated inline)
        const extractedDomain = extractDomainFromRule(rule);

        if (extractedDomain) {
          const ignoreResult = shouldIgnoreAsIgnoreDomain(extractedDomain, ignoreDomains, forceDebug);

          if (ignoreResult.shouldIgnore) {
            removedCount++;
            if (ignoreResult.matchType === 'wildcard') wildcardCount++;
            if (needsDetails) {
              removedRules.push({
                rule: rule,
                domain: extractedDomain,
                reason: 'ignoreDomains: ' + ignoreResult.reason,
                matchType: ignoreResult.matchType
              });
            }
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

    if (removedCount > 0) {
      sitesAffected++;
      totalRulesRemoved += removedCount;

      if (!silentMode) {
        const exactCount = removedCount - wildcardCount;
        let cleanupMessage = 'Removed ' + removedCount + ' ignoreDomains rule(s) from ' + safeGetDomain(result.url) + ' (final cleanup)';
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

  // Summary. When silentMode hides the visible message but rules WERE
  // removed, the debug log used to claim "no rules found" — fixed by
  // gating the "no rules" message on the actual count.
  if (totalRulesRemoved > 0 && !silentMode) {
    const summaryMessage = '\nignoreDomains cleanup completed: Removed ' + totalRulesRemoved + ' rules from ' + sitesAffected + ' site(s)';

    if (messageColors && messageColors.cleanup) {
      console.log(messageColors.cleanup(summaryMessage));
    } else {
      console.log(summaryMessage);
    }
  } else if (forceDebug) {
    console.log(formatLogMessage('debug', totalRulesRemoved > 0
      ? '[ignoreDomains cleanup] (silentMode) Removed ' + totalRulesRemoved + ' rules from ' + sitesAffected + ' site(s)'
      : '[ignoreDomains cleanup] No ignoreDomains rules found to remove'));
  }

  return results;
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

  // Mutate result.rules in place; return `results` directly.
  let totalRulesRemoved = 0;
  let sitesAffected = 0;
  const needsDetails = forceDebug;

  for (let ri = 0; ri < results.length; ri++) {
    const result = results[ri];
    const siteConfig = urlToSiteConfig.get(result.url);
    const shouldCleanFirstParty = siteConfig && siteConfig.firstParty === false;

    if (!shouldCleanFirstParty || !result.rules || result.rules.length === 0) continue;

    if (forceDebug) {
      console.log(formatLogMessage('debug', '[cleanup] Processing ' + result.url + ' (firstParty: false detected)'));
    }

    const scannedDomain = safeGetDomain(result.url, false);
    if (!scannedDomain) continue;

    const cleanedRules = [];
    const removedRules = needsDetails ? [] : null;
    let removedCount = 0;
    let wildcardCount = 0;

    for (let j = 0; j < result.rules.length; j++) {
      const rule = result.rules[j];
      let kept = true;

      try {
        // Use shared extractDomainFromRule (was duplicated inline)
        const extractedDomain = extractDomainFromRule(rule);

        if (extractedDomain) {
          const matchResult = shouldRemoveAsFirstParty(extractedDomain, scannedDomain, forceDebug);

          if (matchResult.shouldRemove) {
            removedCount++;
            if (matchResult.matchType === 'wildcard') wildcardCount++;
            if (needsDetails) {
              removedRules.push({
                rule: rule,
                domain: extractedDomain,
                rootDomain: scannedDomain,
                reason: 'First-party: ' + matchResult.reason + ' (firstParty: false)',
                matchType: matchResult.matchType
              });
            }
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

    if (removedCount > 0) {
      sitesAffected++;
      totalRulesRemoved += removedCount;

      if (!silentMode) {
        const exactCount = removedCount - wildcardCount;
        let cleanupMessage = 'Cleaned ' + removedCount + ' first-party rule(s) from ' + scannedDomain + ' (firstParty: false)';
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

  // Summary (see ignoreDomains cleanup for the silentMode/forceDebug gating logic).
  if (totalRulesRemoved > 0 && !silentMode) {
    const summaryMessage = '\nFirst-party cleanup completed: Removed ' + totalRulesRemoved + ' rules from ' + sitesAffected + ' site(s) with firstParty: false';
    if (messageColors && messageColors.cleanup) {
      console.log(messageColors.cleanup(summaryMessage));
    } else {
      console.log(summaryMessage);
    }
  } else if (forceDebug) {
    console.log(formatLogMessage('debug', totalRulesRemoved > 0
      ? '[cleanup] (silentMode) Removed ' + totalRulesRemoved + ' first-party rules from ' + sitesAffected + ' site(s)'
      : '[cleanup] No first-party rules found to remove'));
  }

  return results;
}

/**
 * Validates scan results and prunes structurally invalid rules
 * (empty strings, non-strings, whitespace-only). Does NOT filter by
 * ignoreDomains — that's cleanupIgnoreDomains's job and it runs earlier.
 *
 * @param {Array} results - Array of scan results
 * @param {Object} options - Options object
 * @param {boolean} options.forceDebug - Debug logging flag
 * @returns {Array} Validated results
 */
function validateScanResults(results, options = {}) {
  const { forceDebug = false } = options;

  if (!results || results.length === 0) {
    return results;
  }

  // NOTE: this function used to also filter rules whose text contained any
  // wildcard-stripped ignoreDomains pattern as a literal substring. Two bugs
  // stacked: (a) .replace('*', '') only stripped the FIRST '*' (so '*.x.*'
  // stayed wildcarded), (b) substring matching was semantically wrong — a
  // pattern of 'ads' would silently kill any rule containing 'headstart'.
  // cleanupIgnoreDomains already runs before this step with the correct
  // extract-and-match logic, so the ignore-pattern branch here is both
  // redundant AND unsafe. Now this function does only what it should: prune
  // structurally invalid rules.
  let totalValidated = 0;
  let totalRemoved = 0;

  for (let ri = 0; ri < results.length; ri++) {
    const result = results[ri];
    if (!result.rules || result.rules.length === 0) {
      continue;
    }

    const originalCount = result.rules.length;
    const validRules = [];

    for (let j = 0; j < result.rules.length; j++) {
      const rule = result.rules[j];
      if (!rule || typeof rule !== 'string' || rule.trim().length === 0) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', '[validation] Removed empty/invalid rule'));
        }
        totalRemoved++;
        continue;
      }
      validRules.push(rule);
    }

    totalValidated += originalCount;
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

  // Mutate result.rules in place; return `results` directly.
  let totalViolationsFound = 0;
  let sitesWithViolations = 0;
  const needsDetails = forceDebug;

  for (let ri = 0; ri < results.length; ri++) {
    const result = results[ri];
    const siteConfig = urlToSiteConfig.get(result.url);
    const shouldValidate = siteConfig && siteConfig.firstParty === false;

    if (!shouldValidate || !result.rules || result.rules.length === 0) continue;

    const scannedDomain = safeGetDomain(result.url, false);
    if (!scannedDomain) continue;

    const cleanedRules = [];
    const violatingRules = needsDetails ? [] : null;
    let violationCount = 0;

    for (let j = 0; j < result.rules.length; j++) {
      const rule = result.rules[j];
      const extractedDomain = extractDomainFromRule(rule);

      if (extractedDomain) {
        const matchResult = shouldRemoveAsFirstParty(extractedDomain, scannedDomain, forceDebug);

        if (matchResult.shouldRemove) {
          violationCount++;
          totalViolationsFound++;
          if (needsDetails) {
            violatingRules.push({
              rule: rule,
              domain: extractedDomain,
              reason: 'VALIDATION FAILURE: ' + matchResult.reason
            });
          }
          continue;
        }
      }
      cleanedRules.push(rule);
    }

    if (violationCount > 0) {
      sitesWithViolations++;

      if (!silentMode) {
        const errorMessage = 'CONFIG VIOLATION: Found ' + violationCount + ' first-party rule(s) in ' + scannedDomain + ' (firstParty: false)';
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
  }

  // Summary (see ignoreDomains cleanup for the silentMode/forceDebug gating logic).
  if (totalViolationsFound > 0 && !silentMode) {
    const summaryMessage = '\nSCAN FILTERING FAILURE: Removed ' + totalViolationsFound + ' first-party rules from ' + sitesWithViolations + ' site(s) in post-processing';
    console.log(summaryMessage);
    console.log('This indicates firstParty: false filtering failed during scan - consider investigating root cause.');
  } else if (forceDebug) {
    console.log(formatLogMessage('debug', totalViolationsFound > 0
      ? '[final-validation] (silentMode) Removed ' + totalViolationsFound + ' first-party violations from ' + sitesWithViolations + ' site(s)'
      : '[final-validation] No first-party violations found - filtering working correctly'));
  }

  return results;
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

  // Step 2: Clean up ignoreDomains (final safety net). sharedOptions carries
  // _urlToSiteConfig which this step ignores, but using sharedOptions keeps
  // the four calls visually consistent.
  processedResults = cleanupIgnoreDomains(processedResults, options.ignoreDomains || [], sharedOptions);

  // Step 3: Final validation for firstParty: false configurations
  processedResults = finalFirstPartyValidation(processedResults, sites, sharedOptions);

  // Step 4: Validate results
  processedResults = validateScanResults(processedResults, sharedOptions);
  
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
