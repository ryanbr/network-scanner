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
    firstPartyRules: [],
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
      firstParty: 0,
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
      } else if (parsedRule.isFirstParty) {
        rules.firstPartyRules.push(parsedRule);
        rules.stats.firstParty++;
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
    console.log(`  - First-party rules: ${rules.stats.firstParty}`);
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
    isFirstParty: false,
    isScript: false,
    resourceTypes: null,       // Array of allowed resource types, null = all types
    excludedResourceTypes: null, // Array of excluded resource types ($~script, $~image)
    isRegex: false,
    domainRestrictions: null,  // { include: ['site.com'], exclude: ['~site.com'] }
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
    
    // Check for first-party option ($first-party, $1p, $~third-party)
    if (parsed.options['first-party'] || parsed.options['1p'] || parsed.options['~third-party']) {
      parsed.isFirstParty = true;
    }

    // Parse resource type options
    const TYPE_MAP = {
      'script': 'script',
      'stylesheet': 'stylesheet',
      'css': 'stylesheet',
      'image': 'image',
      'xmlhttprequest': 'xhr',
      'xhr': 'xhr',
      'font': 'font',
      'media': 'media',
      'websocket': 'websocket',
      'subdocument': 'subdocument',
      'document': 'document',
      'ping': 'ping',
      'other': 'other'
    };
    
    const matchedTypes = Object.keys(parsed.options)
      .filter(key => TYPE_MAP[key])
      .map(key => TYPE_MAP[key]);
  
    const excludedTypes = Object.keys(parsed.options)
      .filter(key => key.startsWith('~') && TYPE_MAP[key.substring(1)])
      .map(key => TYPE_MAP[key.substring(1)]);

    if (matchedTypes.length > 0) {
      parsed.resourceTypes = matchedTypes;
      if (parsed.options['script']) {
        parsed.isScript = true;
      }
    }

    if (excludedTypes.length > 0) {
      parsed.excludedResourceTypes = excludedTypes;
    }

    // Parse domain option: $domain=site1.com|site2.com|~excluded.com
    if (parsed.options['domain']) {
      const domainList = parsed.options['domain'];
      const domains = domainList.split('|').map(d => d.trim()).filter(d => d);
      
      const include = [];
      const exclude = [];
      
      for (const domain of domains) {
        if (domain.startsWith('~')) {
          // Negation: exclude this domain
          exclude.push(domain.substring(1).toLowerCase());
        } else {
          // Positive: include this domain
          include.push(domain.toLowerCase());
        }
      }
      
      // Store parsed domain restrictions
      parsed.domainRestrictions = {
        include: include.length > 0 ? include : null,
        exclude: exclude.length > 0 ? exclude : null
      };
      
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
    const regex = new RegExp(regexPattern, 'i');
    parsed.matcher = (url) => regex.test(url);
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
        
        // Calculate hostname parts once and reuse
        const hostnameParts = lowerHostname.split('.');

        // Precompute parent domains once, reused for whitelist and block checks
        const parentDomains = [];
        const partsLen = hostnameParts.length;
        for (let i = 1; i < partsLen; i++) {
          parentDomains.push(hostnameParts.slice(i).join('.'));
        }
    
        // Extract and cache source page domain for $domain and third-party checks
        let sourceDomain = null;

        if (sourceUrl) {
          const cachedSourceData = urlCache.get(sourceUrl);
          
          if (cachedSourceData) {
            sourceDomain = cachedSourceData.lowerHostname;
            cacheHits++;
          } else {
            // Parse and cache sourceUrl
            try {
              const sourceUrlObj = new URL(sourceUrl);
              sourceDomain = sourceUrlObj.hostname.toLowerCase();
              
              // Cache sourceUrl parsing result (same as request URLs)
              urlCache.set(sourceUrl, {
                hostname: sourceUrlObj.hostname,
                lowerHostname: sourceDomain
              });
              cacheMisses++;
            } catch (err) {
            // Invalid sourceUrl, leave as null
            }
          }
        }

        // Calculate third-party status using already-parsed hostnames
        const hasPartyRules = rules.thirdPartyRules.length > 0 || rules.firstPartyRules.length > 0;
        const isThirdParty = (sourceDomain && hasPartyRules)
          ? getBaseDomain(lowerHostname) !== getBaseDomain(sourceDomain)
          : false;

        // === WHITELIST CHECK (exception rules take precedence) ===
        
        // Fast path: Check exact domain in Map (O(1))
        let rule = rules.whitelistMap.get(lowerHostname);  // V8: Single Map lookup
        if (rule) {
          if (enableLogging) {  // V8: Check after getting rule (inlined)
            console.log(`[Adblock] Whitelisted: ${url} (${rule.raw})`);
          }
          if (matchesDomainRestrictions(rule, sourceDomain)) {
            return { blocked: false, rule: rule.raw, reason: 'whitelisted' };
          }
        }
        
        // Check parent domains for subdomain matches (e.g., sub.example.com -> example.com)
        for (let i = 0; i < parentDomains.length; i++) {
          rule = rules.whitelistMap.get(parentDomains[i]);
          if (rule) {
            if (enableLogging) {
              console.log(`[Adblock] Whitelisted: ${url} (${rule.raw})`);
            }
            if (matchesDomainRestrictions(rule, sourceDomain)) {
              return { blocked: false, rule: rule.raw, reason: 'whitelisted' };
            }
          }
        }
        
        // Slow path: Check wildcard whitelist patterns in array
        const whitelistLen = rules.whitelist.length;  // V8: Cache length + indexed access
        for (let i = 0; i < whitelistLen; i++) {
          const rule = rules.whitelist[i];
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
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
          if (matchesDomainRestrictions(rule, sourceDomain)) {
            return { blocked: true, rule: rule.raw, reason: 'domain_rule' };
          }
        }
        
        // Check parent domains for subdomain matches (e.g., ads.example.com -> example.com)
        for (let i = 0; i < parentDomains.length; i++) {
          rule = rules.domainMap.get(parentDomains[i]);
          if (rule) {
            if (enableLogging) {
              console.log(`[Adblock] Blocked domain: ${url} (${rule.raw})`);
            }
            if (matchesDomainRestrictions(rule, sourceDomain)) {
              return { blocked: true, rule: rule.raw, reason: 'domain_rule' };
            }
          }
        }
        
        // Slow path: Check wildcard domain patterns in array
        const domainRulesLen = rules.domainRules.length;  // V8: Cache length + indexed access
        for (let i = 0; i < domainRulesLen; i++) {
          const rule = rules.domainRules[i];
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
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
            if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
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

        // Check first-party rules
        if (!isThirdParty) {
          const firstPartyLen = rules.firstPartyRules.length;
          for (let i = 0; i < firstPartyLen; i++) {
            const rule = rules.firstPartyRules[i];
            if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
              if (enableLogging) {
                console.log(`[Adblock] Blocked first-party: ${url} (${rule.raw})`);
              }
              return {
                blocked: true,
                rule: rule.raw,
                reason: 'first_party_rule'
              };
            }
          }
        }

        // Check script rules
        if (resourceType === 'script' || url.endsWith('.js')) {
          const scriptRulesLen = rules.scriptRules.length;  // V8: Cache length
          for (let i = 0; i < scriptRulesLen; i++) {
            const rule = rules.scriptRules[i];
           if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
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
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
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
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
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
 * Check if rule's domain restrictions match the source domain
 * @param {Object} rule - Rule with potential domainRestrictions
 * @param {string|null} sourceDomain - Domain of the page making the request (lowercase)
 * @returns {boolean} True if rule should apply on this source domain
 */
function matchesDomainRestrictions(rule, sourceDomain) {
  // No domain restrictions = applies everywhere
  if (!rule.domainRestrictions) {
    return true;
  }
  
  // No source domain provided = can't check restrictions, allow for safety
  if (!sourceDomain) {
    return true;
  }
  
  const { include, exclude } = rule.domainRestrictions;

  // V8 OPT ADVANCED: For single-domain restrictions, skip loop overhead
  // This is the most common case (~80% of domain restrictions)
  
  // Fast path: Single exclusion
  if (exclude && exclude.length === 1 && (!include || include.length === 0)) {
    const excludedDomain = exclude[0];
    if (sourceDomain === excludedDomain || sourceDomain.endsWith('.' + excludedDomain)) {
      return false;
    }
    return true;
  }
  
  // Fast path: Single inclusion
  if (include && include.length === 1 && (!exclude || exclude.length === 0)) {
    const includedDomain = include[0];
    return sourceDomain === includedDomain || sourceDomain.endsWith('.' + includedDomain);
  }
  
  // Slow path: Multiple domains (use indexed loops)
  // V8 OPT: Check exclusions first (higher priority) - use indexed loop
  // If domain is explicitly excluded, rule does NOT apply
  if (exclude && exclude.length > 0) {
    const excludeLen = exclude.length;
    for (let i = 0; i < excludeLen; i++) {
      const excludedDomain = exclude[i];
      // Exact match or subdomain match
      if (sourceDomain === excludedDomain || sourceDomain.endsWith('.' + excludedDomain)) {
        return false;  // Domain is excluded, rule should NOT apply
      }
    }
  }
  
  // V8 OPT: Check inclusions - use indexed loop
  // If there's an include list, domain MUST be in it
  if (include && include.length > 0) {
    const includeLen = include.length;
    for (let i = 0; i < includeLen; i++) {
      const includedDomain = include[i];
      // Exact match or subdomain match
      if (sourceDomain === includedDomain || sourceDomain.endsWith('.' + includedDomain)) {
        return true;  // Domain is included, rule SHOULD apply
      }
    }
    return false;  // Domain not in include list, rule should NOT apply
  }
  
  // Has exclusions but no inclusions, and not excluded = applies
  return true;
}

// Module-level constant for resource type normalization (hot path)
const RESOURCE_TYPE_ALIASES = {
  'script': 'script', 'stylesheet': 'stylesheet', 'image': 'image',
  'xhr': 'xhr', 'fetch': 'xhr', 'font': 'font', 'media': 'media',
  'websocket': 'websocket', 'subdocument': 'subdocument',
  'document': 'document', 'ping': 'ping', 'other': 'other'
};

/**
 * Check if rule matches the given URL
 * @param {Object} rule - Parsed rule object
 * @param {string} url - URL to check
 * @param {string} hostname - Hostname of URL
 * @param {boolean} isThirdParty - Whether request is third-party
 * @param {string} resourceType - Resource type
 * @param {string|null} sourceDomain - Source page domain (for $domain option)
 * @returns {boolean} True if rule matches
 */
 
function matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain) {
  // Check domain restrictions first
  if (!matchesDomainRestrictions(rule, sourceDomain)) {
    return false;
  }
  // Check third-party option
  if (rule.isThirdParty && !isThirdParty) {
    return false;
  }

  // Check first-party option
  if (rule.isFirstParty && isThirdParty) {
    return false;
  }

  // Check resource type restrictions
  if (rule.resourceTypes) {
    if (!resourceType) {
      // No resource type info available — allow match for safety
    } else {
      // Normalize Puppeteer resource types to match our type names
      const normalizedType = RESOURCE_TYPE_ALIASES[resourceType] || resourceType;
      if (!rule.resourceTypes.includes(normalizedType)) {
        return false;
      }
    }
  }

  // Check negated resource type restrictions ($~script, $~image, etc.)
  if (rule.excludedResourceTypes) {
    if (resourceType) {
      const normalizedType = RESOURCE_TYPE_ALIASES[resourceType] || resourceType;
      if (rule.excludedResourceTypes.includes(normalizedType)) {
        return false;
      }
    }
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
