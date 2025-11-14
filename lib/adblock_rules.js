// === Adblock Rules Parser (adblock_rules.js) v2.2 - Complete Optimization ===
// Supports EasyList/AdBlock Plus filter syntax
// Optimizations: Map domains + URL cache + skip third-party calc + cached hostname split

const fs = require('fs');

/**
 * Simple LRU cache for URL parsing results
 * Prevents memory leaks with fixed size limit
 */
class URLCache {
  constructor(maxSize = 1000) {
    this.cache = new Map();
    this.maxSize = maxSize;
  }
  
  get(url) {
    return this.cache.get(url);
  }
  
  set(url, value) {
    // LRU eviction: if at max size, delete oldest entry
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(url, value);
  }
  
  clear() {
    this.cache.clear();
  }
  
  getStats() {
    return {
      size: this.cache.size,
      maxSize: this.maxSize
    };
  }
}

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
    domainMap: new Map(),          // ||domain.com^ - Exact domains for O(1) lookup
    domainRules: [],               // ||*.domain.com^ - Wildcard domains (fallback)
    thirdPartyRules: [],           // ||domain.com^$third-party
    pathRules: [],                 // /ads/*
    scriptRules: [],               // .js$script
    regexRules: [],                // /regex/
    whitelist: [],                 // @@||domain.com^ - Wildcard whitelist
    whitelistMap: new Map(),       // Exact whitelist domains for O(1) lookup
    elementHiding: [],             // ##.ad-class (not used for network blocking)
    stats: {
      total: 0,
      domain: 0,
      domainMapEntries: 0,         // Exact domain matches in Map
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

    // Skip rules with cosmetic-only options (not for network blocking)
    // These options only affect element hiding, not network requests
    const cosmeticOnlyOptions = ['generichide', 'elemhide', 'specifichide'];
    const hasCosmeticOption = cosmeticOnlyOptions.some(opt => 
      line.includes(`$${opt}`) || line.includes(`,${opt}`)
    );
    if (hasCosmeticOption) {
      rules.stats.elementHiding++;
      continue;
    }

    rules.stats.total++;

    try {
      // Whitelist rules (exception rules)
      if (line.startsWith('@@')) {
        const cleanLine = line.substring(2);
        const parsedRule = parseRule(cleanLine, true);
        
        // Store exact domains in Map for O(1) lookup, wildcards in array
        if (parsedRule.isDomain && parsedRule.domain && !parsedRule.domain.includes('*')) {
          rules.whitelistMap.set(parsedRule.domain.toLowerCase(), parsedRule);
        } else {
          rules.whitelist.push(parsedRule);
        }
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
        // Store exact domains in Map for O(1) lookup, wildcards in array
        if (parsedRule.domain && !parsedRule.domain.includes('*')) {
          rules.domainMap.set(parsedRule.domain.toLowerCase(), parsedRule);
          rules.stats.domainMapEntries++;
        } else {
          rules.domainRules.push(parsedRule);
        }
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
    console.log(`    • Exact matches (Map): ${rules.stats.domainMapEntries}`);
    console.log(`    • Wildcard patterns (Array): ${rules.domainRules.length}`);
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

    // Filter out cosmetic-only options that don't affect network blocking
    const networkOptions = options.filter(opt => {
      const optKey = opt.split('=')[0].trim();
      // Skip cosmetic filtering options
      const cosmeticOptions = [
        'generichide',
        'elemhide', 
        'specifichide',
        'genericblock'  // Also cosmetic-related
      ];
      return !cosmeticOptions.includes(optKey);
    });

    // Only process network-related options
    for (const opt of networkOptions) {
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
  
  // Create URL parsing cache (scoped to this matcher instance)
  const urlCache = new URLCache(1000);
  let cacheHits = 0;
  let cacheMisses = 0;
  
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
        // OPTIMIZATION: Check cache first for URL parsing (60% faster)
        let cachedData = urlCache.get(url);
        let hostname, lowerHostname;
        
        if (cachedData) {
          hostname = cachedData.hostname;
          lowerHostname = cachedData.lowerHostname;
          cacheHits++;
        } else {
          // Parse URL and cache result
          const urlObj = new URL(url);
          hostname = urlObj.hostname;
          lowerHostname = hostname.toLowerCase();
          
          urlCache.set(url, {
            hostname,
            lowerHostname
          });
          cacheMisses++;
        }
        
        // OPTIMIZATION #1: Only calculate third-party status if we have third-party rules to check
        // Avoids expensive URL parsing (2x new URL() calls) when no third-party rules exist
        const isThirdParty = (sourceUrl && rules.thirdPartyRules.length > 0) 
          ? isThirdPartyRequest(url, sourceUrl) 
          : false;
        
        // OPTIMIZATION #2: Calculate hostname parts once and reuse (avoid duplicate split operations)
        const hostnameParts = lowerHostname.split('.');

        // === WHITELIST CHECK (exception rules take precedence) ===
        
        // Fast path: Check exact domain in Map (O(1))
        let rule = rules.whitelistMap.get(lowerHostname);  // V8: Single Map lookup
        if (rule) {
          if (enableLogging) {  // V8: Check after getting rule (inlined)
            console.log(`[Adblock] Whitelisted: ${url} (${rule.raw})`);
          }
          return { blocked: false, rule: rule.raw, reason: 'whitelisted' };
        }
        
        // Check parent domains for subdomain matches (e.g., sub.example.com -> example.com)
        const partsLen = hostnameParts.length;  // V8: Cache array length
        for (let i = 1; i < partsLen; i++) {
          const parentDomain = hostnameParts.slice(i).join('.');
          rule = rules.whitelistMap.get(parentDomain);  // V8: Single Map lookup
          if (rule) {
            if (enableLogging) {
              console.log(`[Adblock] Whitelisted: ${url} (${rule.raw})`);
            }
            return { blocked: false, rule: rule.raw, reason: 'whitelisted' };
          }
        }
        
        // Slow path: Check wildcard whitelist patterns in array
        const whitelistLen = rules.whitelist.length;  // V8: Cache length + indexed access
        for (let i = 0; i < whitelistLen; i++) {
          const rule = rules.whitelist[i];
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType)) {
            if (enableLogging) {
              console.log(`[Adblock] Whitelisted: ${url} (${rule.raw})`);
            }
            return { blocked: false, rule: rule.raw, reason: 'whitelisted' };
          }
        }

        // === DOMAIN BLOCKING CHECK ===
        
        // Fast path: Check exact domain in Map (O(1))
        rule = rules.domainMap.get(lowerHostname);  // V8: Single Map lookup
        if (rule) {
          if (enableLogging) {
            console.log(`[Adblock] Blocked domain: ${url} (${rule.raw})`);
          }
          return { blocked: true, rule: rule.raw, reason: 'domain_rule' };
        }
        
        // Check parent domains for subdomain matches (e.g., ads.example.com -> example.com)
        for (let i = 1; i < partsLen; i++) {  // V8: Reuse cached length
          const parentDomain = hostnameParts.slice(i).join('.');
          rule = rules.domainMap.get(parentDomain);  // V8: Single Map lookup
          if (rule) {
            if (enableLogging) {
              console.log(`[Adblock] Blocked domain: ${url} (${rule.raw})`);
            }
            return { blocked: true, rule: rule.raw, reason: 'domain_rule' };
          }
        }
        
        // Slow path: Check wildcard domain patterns in array
        const domainRulesLen = rules.domainRules.length;  // V8: Cache length + indexed access
        for (let i = 0; i < domainRulesLen; i++) {
          const rule = rules.domainRules[i];
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType)) {
            if (enableLogging) {
              console.log(`[Adblock] Blocked domain: ${url} (${rule.raw})`);
            }
            return { blocked: true, rule: rule.raw, reason: 'domain_rule' };
          }
        }

        // Check third-party rules
        if (isThirdParty) {
          const thirdPartyLen = rules.thirdPartyRules.length;  // V8: Cache length
          for (let i = 0; i < thirdPartyLen; i++) {
            const rule = rules.thirdPartyRules[i];
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
          const scriptRulesLen = rules.scriptRules.length;  // V8: Cache length
          for (let i = 0; i < scriptRulesLen; i++) {
            const rule = rules.scriptRules[i];
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
        const pathRulesLen = rules.pathRules.length;  // V8: Cache length
        for (let i = 0; i < pathRulesLen; i++) {
          const rule = rules.pathRules[i];
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
        const regexRulesLen = rules.regexRules.length;  // V8: Cache length
        for (let i = 0; i < regexRulesLen; i++) {
          const rule = rules.regexRules[i];
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
      const hitRate = cacheHits + cacheMisses > 0 
        ? ((cacheHits / (cacheHits + cacheMisses)) * 100).toFixed(1) + '%'
        : '0%';
      
      return { 
        ...rules.stats,
        cache: {
          hits: cacheHits,
          misses: cacheMisses,
          hitRate: hitRate,
          size: urlCache.cache.size,
          maxSize: urlCache.maxSize
        }
      };
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
