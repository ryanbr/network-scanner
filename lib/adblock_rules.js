// === Adblock Rules Parser (adblock_rules.js) ===
// Supports EasyList/AdBlock Plus filter syntax

const fs = require('fs');
const path = require('path');

/**
 * Parses adblock filter list and creates matcher
 * @param {string} filePath - Path to filter list file
 * @param {Object} options - Parser options
 * @returns {Object} Rule matcher with matching functions
 */
function parseAdblockRules(filePath, options = {}) {
  const {
    enableLogging = false,
    caseSensitive = false
  } = options;

  if (!fs.existsSync(filePath)) {
    throw new Error(`Adblock rules file not found: ${filePath}`);
  }

  const fileContent = fs.readFileSync(filePath, 'utf-8');
  const lines = fileContent.split('\n');
  
  const rules = {
    domainRules: [],           // ||domain.com^
    thirdPartyRules: [],       // ||domain.com^$third-party
    pathRules: [],             // /ads/*
    scriptRules: [],           // .js$script
    regexRules: [],            // /regex/
    whitelist: [],             // @@||domain.com^
    elementHiding: [],         // ##.ad-class (not used for network blocking)
    stats: {
      total: 0,
      domain: 0,
      thirdParty: 0,
      path: 0,
      script: 0,
      regex: 0,
      whitelist: 0,
      elementHiding: 0,
      comments: 0,
      invalid: 0
    }
  };

  for (let line of lines) {
    line = line.trim();
    
    // Skip empty lines
    if (!line) continue;
    
    // Skip comments
    if (line.startsWith('!') || line.startsWith('#')) {
      rules.stats.comments++;
      continue;
    }
    
    // Skip element hiding rules (cosmetic filters)
    if (line.includes('##') || line.includes('#@#')) {
      rules.stats.elementHiding++;
      continue;
    }

    rules.stats.total++;

    try {
      // Whitelist rules (exception rules)
      if (line.startsWith('@@')) {
        const cleanLine = line.substring(2);
        rules.whitelist.push(parseRule(cleanLine, true));
        rules.stats.whitelist++;
        continue;
      }

      // Regular blocking rules
      const parsedRule = parseRule(line, false);
      
      // Categorize based on rule type
      if (parsedRule.isThirdParty) {
        rules.thirdPartyRules.push(parsedRule);
        rules.stats.thirdParty++;
      } else if (parsedRule.isDomain) {
        rules.domainRules.push(parsedRule);
        rules.stats.domain++;
      } else if (parsedRule.isScript) {
        rules.scriptRules.push(parsedRule);
        rules.stats.script++;
      } else if (parsedRule.isRegex) {
        rules.regexRules.push(parsedRule);
        rules.stats.regex++;
      } else {
        rules.pathRules.push(parsedRule);
        rules.stats.path++;
      }
    } catch (err) {
      rules.stats.invalid++;
      if (enableLogging) {
        console.log(`[Adblock] Failed to parse rule: ${line} - ${err.message}`);
      }
    }
  }

  if (enableLogging) {
    console.log(`[Adblock] Loaded ${rules.stats.total} rules:`);
    console.log(`  - Domain rules: ${rules.stats.domain}`);
    console.log(`  - Third-party rules: ${rules.stats.thirdParty}`);
    console.log(`  - Path rules: ${rules.stats.path}`);
    console.log(`  - Script rules: ${rules.stats.script}`);
    console.log(`  - Regex rules: ${rules.stats.regex}`);
    console.log(`  - Whitelist rules: ${rules.stats.whitelist}`);
    console.log(`  - Comments/Element hiding: ${rules.stats.comments + rules.stats.elementHiding}`);
    console.log(`  - Invalid rules: ${rules.stats.invalid}`);
  }

  return createMatcher(rules, { enableLogging, caseSensitive });
}

/**
 * Parses individual adblock rule
 * @param {string} rule - Raw rule string
 * @param {boolean} isWhitelist - Whether this is a whitelist rule
 * @returns {Object} Parsed rule object
 */
function parseRule(rule, isWhitelist) {
  const parsed = {
    raw: rule,
    isWhitelist,
    isDomain: false,
    isThirdParty: false,
    isScript: false,
    isRegex: false,
    pattern: '',
    options: {},
    matcher: null
  };

  // Split rule and options ($option1,option2)
  let [pattern, optionsStr] = rule.split('$');
  parsed.pattern = pattern;

  // Parse options
  if (optionsStr) {
    const options = optionsStr.split(',');
    for (const opt of options) {
      const [key, value] = opt.split('=');
      parsed.options[key.trim()] = value ? value.trim() : true;
    }
    
    // Check for third-party option
    if (parsed.options['third-party'] || parsed.options['3p']) {
      parsed.isThirdParty = true;
    }
    
    // Check for script option
    if (parsed.options['script']) {
      parsed.isScript = true;
    }
  }

  // Domain rules: ||domain.com^ or ||domain.com
  if (pattern.startsWith('||')) {
    parsed.isDomain = true;
    const domain = pattern.substring(2).replace(/\^.*$/, '').replace(/\*$/, '');
    parsed.domain = domain;
    parsed.matcher = createDomainMatcher(domain);
  }
  // Regex rules: /pattern/
  else if (pattern.startsWith('/') && pattern.endsWith('/')) {
    parsed.isRegex = true;
    const regexPattern = pattern.substring(1, pattern.length - 1);
    parsed.matcher = new RegExp(regexPattern, 'i');
  }
  // Path/wildcard rules: /ads/* or ad.js
  else {
    parsed.matcher = createPatternMatcher(pattern);
  }

  return parsed;
}

/**
 * Creates a domain matcher function
 * @param {string} domain - Domain to match
 * @returns {Function} Matcher function
 */
function createDomainMatcher(domain) {
  const lowerDomain = domain.toLowerCase();
  return (url, hostname) => {
    const lowerHostname = hostname.toLowerCase();
    // Exact match or subdomain match
    return lowerHostname === lowerDomain || 
           lowerHostname.endsWith('.' + lowerDomain);
  };
}

/**
 * Creates a pattern matcher for path/wildcard rules
 * @param {string} pattern - Pattern with wildcards
 * @returns {Function} Matcher function
 */
function createPatternMatcher(pattern) {
  // Convert adblock pattern to regex
  // * matches anything
  // ^ matches separator (/, ?, &, =, :)
  // | matches start/end of URL
  
  let regexPattern = pattern
    .replace(/[.+?{}()[\]\\]/g, '\\$&')  // Escape regex special chars
    .replace(/\*/g, '.*')                 // * -> .*
    .replace(/\^/g, '[/?&=:]')            // ^ -> separator chars
    .replace(/^\|/, '^')                  // | at start -> ^
    .replace(/\|$/, '$');                 // | at end -> $
  
  const regex = new RegExp(regexPattern, 'i');
  return (url) => regex.test(url);
}

/**
 * Creates rule matcher with shouldBlock function
 * @param {Object} rules - Parsed rules object
 * @param {Object} options - Matcher options
 * @returns {Object} Matcher with shouldBlock function
 */
function createMatcher(rules, options = {}) {
  const { enableLogging = false, caseSensitive = false } = options;
  
  return {
    rules,
    
    /**
     * Check if URL should be blocked
     * @param {string} url - URL to check
     * @param {string} sourceUrl - Source page URL (for third-party detection)
     * @param {string} resourceType - Type of resource (script, image, etc)
     * @returns {Object} { blocked: boolean, rule: string|null, reason: string }
     */
    shouldBlock(url, sourceUrl = '', resourceType = '') {
      try {
        // Extract hostname from URL
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const isThirdParty = sourceUrl ? isThirdPartyRequest(url, sourceUrl) : false;

        // Check whitelist first (exception rules take precedence)
        for (const rule of rules.whitelist) {
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType)) {
            if (enableLogging) {
              console.log(`[Adblock] Whitelisted: ${url} (${rule.raw})`);
            }
            return { 
              blocked: false, 
              rule: rule.raw, 
              reason: 'whitelisted' 
            };
          }
        }

        // Check domain rules (most common, check first)
        for (const rule of rules.domainRules) {
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType)) {
            if (enableLogging) {
              console.log(`[Adblock] Blocked domain: ${url} (${rule.raw})`);
            }
            return { 
              blocked: true, 
              rule: rule.raw, 
              reason: 'domain_rule' 
            };
          }
        }

        // Check third-party rules
        if (isThirdParty) {
          for (const rule of rules.thirdPartyRules) {
            if (matchesRule(rule, url, hostname, isThirdParty, resourceType)) {
              if (enableLogging) {
                console.log(`[Adblock] Blocked third-party: ${url} (${rule.raw})`);
              }
              return { 
                blocked: true, 
                rule: rule.raw, 
                reason: 'third_party_rule' 
              };
            }
          }
        }

        // Check script rules
        if (resourceType === 'script' || url.endsWith('.js')) {
          for (const rule of rules.scriptRules) {
            if (matchesRule(rule, url, hostname, isThirdParty, resourceType)) {
              if (enableLogging) {
                console.log(`[Adblock] Blocked script: ${url} (${rule.raw})`);
              }
              return { 
                blocked: true, 
                rule: rule.raw, 
                reason: 'script_rule' 
              };
            }
          }
        }

        // Check path rules
        for (const rule of rules.pathRules) {
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType)) {
            if (enableLogging) {
              console.log(`[Adblock] Blocked path: ${url} (${rule.raw})`);
            }
            return { 
              blocked: true, 
              rule: rule.raw, 
              reason: 'path_rule' 
              };
          }
        }

        // Check regex rules (most expensive, check last)
        for (const rule of rules.regexRules) {
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType)) {
            if (enableLogging) {
              console.log(`[Adblock] Blocked regex: ${url} (${rule.raw})`);
            }
            return { 
              blocked: true, 
              rule: rule.raw, 
              reason: 'regex_rule' 
            };
          }
        }

        // No match - allow request
        return { 
          blocked: false, 
          rule: null, 
          reason: 'no_match' 
        };

      } catch (err) {
        if (enableLogging) {
          console.log(`[Adblock] Error checking ${url}: ${err.message}`);
        }
        // On error, allow request
        return { 
          blocked: false, 
          rule: null, 
          reason: 'error' 
        };
      }
    },

    /**
     * Get statistics about loaded rules
     * @returns {Object} Statistics object
     */
    getStats() {
      return { ...rules.stats };
    }
  };
}

/**
 * Check if rule matches the given URL
 * @param {Object} rule - Parsed rule object
 * @param {string} url - URL to check
 * @param {string} hostname - Hostname of URL
 * @param {boolean} isThirdParty - Whether request is third-party
 * @param {string} resourceType - Resource type
 * @returns {boolean} True if rule matches
 */
function matchesRule(rule, url, hostname, isThirdParty, resourceType) {
  // Check third-party option
  if (rule.isThirdParty && !isThirdParty) {
    return false;
  }

  // Check script option
  if (rule.isScript && resourceType !== 'script' && !url.endsWith('.js')) {
    return false;
  }

  // Apply matcher function
  if (rule.isDomain) {
    return rule.matcher(url, hostname);
  } else {
    return rule.matcher(url);
  }
}

/**
 * Determine if request is third-party
 * @param {string} requestUrl - URL being requested
 * @param {string} sourceUrl - URL of the page making the request
 * @returns {boolean} True if third-party request
 */
function isThirdPartyRequest(requestUrl, sourceUrl) {
  try {
    const requestHostname = new URL(requestUrl).hostname;
    const sourceHostname = new URL(sourceUrl).hostname;
    
    // Extract base domain (handle subdomains)
    const requestDomain = getBaseDomain(requestHostname);
    const sourceDomain = getBaseDomain(sourceHostname);
    
    return requestDomain !== sourceDomain;
  } catch (err) {
    return false;
  }
}

/**
 * Extract base domain from hostname
 * @param {string} hostname - Full hostname
 * @returns {string} Base domain
 */
function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) {
    return hostname;
  }
  // Return last two parts (example.com from sub.example.com)
  return parts.slice(-2).join('.');
}

module.exports = {
  parseAdblockRules,
  isThirdPartyRequest,
  getBaseDomain
};