// === Adblock Rules Parser (adblock_rules.js) v2.2 - Complete Optimization ===
// Supports EasyList/AdBlock Plus filter syntax
// Optimizations: Map domains + URL cache + skip third-party calc + cached hostname split

const fs = require('fs');
const psl = require('psl');
const { formatLogMessage, messageColors } = require('./colorize');
// Subsystem tag matches the project convention (other modules use
// flowproxy/cloudflare/curl/grep/etc. precomputed tags).
const ADBLOCK_TAG = messageColors.processing('[adblock]');

// Hoisted constants — avoid recreating per rule (~80K times for EasyList)
const COSMETIC_OPTIONS = new Set(['generichide', 'elemhide', 'specifichide', 'genericblock']);
const PARSE_TYPE_MAP = {
  'script': 'script', 'stylesheet': 'stylesheet', 'css': 'stylesheet',
  'image': 'image', 'xmlhttprequest': 'xhr', 'xhr': 'xhr', 'font': 'font',
  'media': 'media', 'websocket': 'websocket', 'subdocument': 'subdocument',
  'document': 'document', 'ping': 'ping', 'other': 'other'
};

/**
 * FIFO cache with a hard size cap. Evicts the OLDEST-inserted entry on
 * overflow (not the least-recently-used) — this is FIFO, not LRU, despite
 * the original "Simple LRU cache" naming. Proper LRU would require
 * deleting-and-reinserting on every .get() hit to bubble accessed keys
 * to the end, which adds per-hit Map.delete + Map.set overhead. In hot
 * paths (32k-entry result cache hit thousands of times per scan), that
 * overhead is real; FIFO with a generous cap is the simpler trade.
 *
 * If access-pattern shifts become a real problem (a few "always hot"
 * URLs evicted while never-used entries survive), implement move-on-get
 * here — the API stays compatible.
 */
class FIFOCache {
  constructor(maxSize = 1000) {
    this.cache = new Map();
    this.maxSize = maxSize;
  }

  get(url) {
    return this.cache.get(url);
  }

  set(url, value) {
    // FIFO eviction: drop the oldest-inserted entry when full.
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
  // caseSensitive option removed — it was destructured here and threaded
  // through to createMatcher, then never actually read. All hostname/
  // pattern comparisons are case-insensitive (lowercased explicitly or
  // via /i regex flag), so the option would have been a substantial
  // refactor to honor. Removed rather than left as a documented lie.
  const { enableLogging = false } = options;

  let fileContent;
  try {
    fileContent = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    throw new Error(`Adblock rules file not found: ${filePath}`);
  }
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
    let hasCosmeticOption = false;
    for (const opt of COSMETIC_OPTIONS) {
      if (line.includes(`$${opt}`) || line.includes(`,${opt}`)) { hasCosmeticOption = true; break; }
    }
    if (hasCosmeticOption) {
      rules.stats.elementHiding++;
      continue;
    }

    rules.stats.total++;

    try {
      // Whitelist rules (exception rules)
      if (line.startsWith('@@')) {
        const cleanLine = line.substring(2);
        const parsedRule = parseRule(cleanLine, true, enableLogging);
        
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
      const parsedRule = parseRule(line, false, enableLogging);
      
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
        console.log(formatLogMessage('warn', `${ADBLOCK_TAG} Failed to parse rule: ${line} - ${err.message}`));
      }
    }
  }

  if (enableLogging) {
    console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Loaded ${rules.stats.total} rules:`));
    console.log(formatLogMessage('debug', `  - Domain rules: ${rules.stats.domain}`));
    console.log(formatLogMessage('debug', `    • Exact matches (Map): ${rules.stats.domainMapEntries}`));
    console.log(formatLogMessage('debug', `    • Wildcard patterns (Array): ${rules.domainRules.length}`));
    console.log(formatLogMessage('debug', `  - Third-party rules: ${rules.stats.thirdParty}`));
    console.log(formatLogMessage('debug', `  - First-party rules: ${rules.stats.firstParty}`));
    console.log(formatLogMessage('debug', `  - Path rules: ${rules.stats.path}`));
    console.log(formatLogMessage('debug', `  - Script rules: ${rules.stats.script}`));
    console.log(formatLogMessage('debug', `  - Regex rules: ${rules.stats.regex}`));
    console.log(formatLogMessage('debug', `  - Whitelist rules: ${rules.stats.whitelist}`));
    console.log(formatLogMessage('debug', `  - Comments/Element hiding: ${rules.stats.comments + rules.stats.elementHiding}`));
    console.log(formatLogMessage('debug', `  - Invalid rules: ${rules.stats.invalid}`));
  }

  return createMatcher(rules, { enableLogging });
}

/**
 * Parses individual adblock rule
 * @param {string} rule - Raw rule string
 * @param {boolean} isWhitelist - Whether this is a whitelist rule
 * @returns {Object} Parsed rule object
 */
function parseRule(rule, isWhitelist, enableLogging = false) {
  const parsed = {
    raw: enableLogging ? rule : null, // Only store for logging — saves memory on large lists
    isWhitelist,
    isDomain: false,
    isThirdParty: false,
    isFirstParty: false,
    isScript: false,
    resourceTypes: null,       // Set of allowed resource types, null = all types
    excludedResourceTypes: null, // Set of excluded resource types ($~script, $~image)
    isRegex: false,
    domainRestrictions: null,  // { include: ['site.com'], exclude: ['~site.com'] }
    pattern: '',
    matcher: null
  };

  // Split rule and options ($option1,option2)
  let [pattern, optionsStr] = rule.split('$');
  parsed.pattern = pattern;

  // Parse options into local object (not stored on parsed — freed after this block)
  if (optionsStr) {
    const options = optionsStr.split(',');
    const parsedOptions = {};

    // No cosmetic-option guard here — the line-level filter at lines
    // ~126-135 already drops any rule containing $generichide/$elemhide/
    // etc. before parseRule is ever called. The previous in-loop
    // COSMETIC_OPTIONS.has() guard was unreachable.
    for (const opt of options) {
      const [key, value] = opt.split('=');
      parsedOptions[key.trim()] = value ? value.trim() : true;
    }

    // Check for third-party option
    if (parsedOptions['third-party'] || parsedOptions['3p']) {
      parsed.isThirdParty = true;
    }

    // Check for first-party option ($first-party, $1p, $~third-party)
    if (parsedOptions['first-party'] || parsedOptions['1p'] || parsedOptions['~third-party']) {
      parsed.isFirstParty = true;
    }

    // Parse resource type options using module-level PARSE_TYPE_MAP
    const matchedTypes = Object.keys(parsedOptions)
      .filter(key => PARSE_TYPE_MAP[key])
      .map(key => PARSE_TYPE_MAP[key]);

    const excludedTypes = Object.keys(parsedOptions)
      .filter(key => key.startsWith('~') && PARSE_TYPE_MAP[key.substring(1)])
      .map(key => PARSE_TYPE_MAP[key.substring(1)]);

    if (matchedTypes.length > 0) {
      // $document rules act as full domain blocks — no resource type restriction
      if (matchedTypes.length === 1 && matchedTypes[0] === 'document') {
        // Don't set resourceTypes — treat as standard block matching all types
      } else {
        parsed.resourceTypes = new Set(matchedTypes);
      }
      if (parsedOptions['script']) {
        parsed.isScript = true;
      }
    }

    if (excludedTypes.length > 0) {
      parsed.excludedResourceTypes = new Set(excludedTypes);
    }

    // Parse domain option: $domain=site1.com|site2.com|~excluded.com
    if (parsedOptions['domain']) {
      const domainList = parsedOptions['domain'];
      const domains = domainList.split('|').map(d => d.trim()).filter(d => d);

      const include = [];
      const exclude = [];

      for (const domain of domains) {
        if (domain.startsWith('~')) {
          exclude.push(domain.substring(1).toLowerCase());
        } else {
          include.push(domain.toLowerCase());
        }
      }

      parsed.domainRestrictions = {
        include: include.length > 0 ? include : null,
        exclude: exclude.length > 0 ? exclude : null
      };
    }
    // parsedOptions goes out of scope here — GC can reclaim
  }

  // Domain rules: ||domain.com^ or ||domain.com
  if (pattern.startsWith('||')) {
    const domain = pattern.substring(2).replace(/[\^\/\*].*$/, '');
    const afterDomain = pattern.substring(2 + domain.length);
    if (!afterDomain || afterDomain === '^') {
      // Pure domain rule: ||domain.com^ or ||domain.com
      parsed.isDomain = true;
      parsed.domain = domain;
      parsed.matcher = createDomainMatcher(domain);
    } else {
      // Domain + path rule: ||domain.com/path or ||domain.com^*path
      // Split into fast domain check + path pattern to avoid full-URL regex
      parsed.isDomain = true;
      parsed.domain = domain;
      const domainMatcher = createDomainMatcher(domain);
      const pathMatcher = createPatternMatcher(afterDomain);
      parsed.matcher = (url, hostname) => {
        if (!domainMatcher(url, hostname)) return false;
        // Extract path portion after hostname for path matching
        const hostIdx = url.indexOf(hostname);
        if (hostIdx === -1) return false;
        const pathPart = url.substring(hostIdx + hostname.length);
        return pathMatcher(pathPart);
      };
    }
  }
  // Regex rules: /pattern/
  else if (pattern.startsWith('/') && pattern.endsWith('/')) {
    parsed.isRegex = true;
    const cached = _regexCache.get(pattern);
    if (cached) {
      parsed.matcher = cached;
    } else {
      const regexPattern = pattern.substring(1, pattern.length - 1);
      const regex = new RegExp(regexPattern, 'i');
      parsed.matcher = (url) => regex.test(url);
      _regexCache.set(pattern, parsed.matcher);
    }
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
  const dotDomain = '.' + lowerDomain;
  // hostname is already lowercased by shouldBlock() before being passed here
  return (url, hostname) => {
    return hostname === lowerDomain ||
           hostname.endsWith(dotDomain);
  };
}

/**
 * Shared regex cache — deduplicates identical compiled patterns across rules.
 * Large lists (EasyList ~80K rules) often have thousands of duplicate
 * patterns. Bounded via FIFOCache (was a bare Map with no size cap; for
 * giant lists with many unique patterns it could grow unbounded).
 */
const _regexCache = new FIFOCache(20000);

/**
 * Creates a pattern matcher for path/wildcard rules
 * @param {string} pattern - Pattern with wildcards
 * @returns {Function} Matcher function
 */
function createPatternMatcher(pattern) {
  // Capture the ORIGINAL pattern as the cache key — the local `pattern`
  // var gets mutated by the anchor-strip below, so previously the get()
  // used the pre-strip key but set() stored under the post-strip key,
  // making every anchored pattern miss its own cache on the next lookup.
  const cacheKey = pattern;
  const cached = _regexCache.get(cacheKey);
  if (cached) return cached;

  // Convert adblock pattern to regex
  // * matches anything
  // ^ matches separator (/, ?, &, =, :)
  // | matches start/end of URL

  // Handle | anchors before escaping — only at very start/end of pattern
  let anchorStart = false;
  let anchorEnd = false;
  if (pattern.startsWith('|') && !pattern.startsWith('||')) {
    anchorStart = true;
    pattern = pattern.substring(1);
  }
  if (pattern.endsWith('|')) {
    anchorEnd = true;
    pattern = pattern.slice(0, -1);
  }

  let regexPattern = pattern
    .replace(/[.+?{}()[\]\\|]/g, '\\$&')  // Escape regex special chars including literal |
    .replace(/\*/g, '.*')                 // * -> .*
    .replace(/\^/g, '[/?&=:]');           // ^ -> separator chars

  if (anchorStart) regexPattern = '^' + regexPattern;
  if (anchorEnd) regexPattern = regexPattern + '$';

  const regex = new RegExp(regexPattern, 'i');
  const matcher = (url) => regex.test(url);
  _regexCache.set(cacheKey, matcher);
  return matcher;
}

/**
 * Creates rule matcher with shouldBlock function
 * @param {Object} rules - Parsed rules object
 * @param {Object} options - Matcher options
 * @returns {Object} Matcher with shouldBlock function
 */
function createMatcher(rules, options = {}) {
  const { enableLogging = false } = options;
  
  const urlCache = new FIFOCache(16000);
  // Per-cache counters split out. Previously ONE counter pair received
  // hits/misses from THREE caches: the result cache, the request-URL
  // parse cache, AND the source-URL parse cache — getStats().hitRate
  // was the average of three different cache behaviors and not
  // interpretable for diagnosing performance.
  let resultCacheHits = 0, resultCacheMisses = 0;
  let urlCacheHits = 0, urlCacheMisses = 0;
  let sourceCacheHits = 0, sourceCacheMisses = 0;
  const hasPartyRules = rules.thirdPartyRules.length > 0 || rules.firstPartyRules.length > 0;
  // Result cache uses FIFO eviction (see FIFOCache class comment) —
  // evicts oldest entries one at a time instead of clearing everything.
  const resultCache = new FIFOCache(32000);

  function resultCacheGet(url, sourceUrl, resourceType) {
    return resultCache.get(url + '\0' + sourceUrl + '\0' + resourceType);
  }

  function resultCacheSet(url, sourceUrl, resourceType, result) {
    resultCache.set(url + '\0' + sourceUrl + '\0' + resourceType, result);
  }

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
        // Check result cache — same URL+source+type always produces same result
        const cachedResult = resultCacheGet(url, sourceUrl, resourceType);
        if (cachedResult) {
          resultCacheHits++;
          return cachedResult;
        }
        resultCacheMisses++;

        // OPTIMIZATION: Check cache first for URL parsing (60% faster)
        let cachedData = urlCache.get(url);
        let hostname, lowerHostname;

        if (cachedData) {
          hostname = cachedData.hostname;
          lowerHostname = cachedData.lowerHostname;
          urlCacheHits++;
        } else {
          // Parse URL and cache result
          const urlObj = new URL(url);
          hostname = urlObj.hostname;
          lowerHostname = hostname.toLowerCase();

          urlCache.set(url, {
            hostname,
            lowerHostname
          });
          urlCacheMisses++;
        }
        
        // Lazy parent domain computation — only built when exact Map lookup misses
        let parentDomains = null;
        function getParentDomains() {
          if (parentDomains) return parentDomains;
          parentDomains = [];
          const hostnameParts = lowerHostname.split('.');
          for (let i = 1; i < hostnameParts.length; i++) {
            parentDomains.push(hostnameParts.slice(i).join('.'));
          }
          return parentDomains;
        }
    
        // Extract and cache source page domain for $domain and third-party checks
        let sourceDomain = null;

        if (sourceUrl) {
          const cachedSourceData = urlCache.get(sourceUrl);
          
          if (cachedSourceData) {
            sourceDomain = cachedSourceData.lowerHostname;
            sourceCacheHits++;
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
              sourceCacheMisses++;
            } catch (err) {
            // Invalid sourceUrl, leave as null
            }
          }
        }

        // Calculate third-party status using already-parsed hostnames
        const isThirdParty = (sourceDomain && hasPartyRules)
          ? getBaseDomain(lowerHostname) !== getBaseDomain(sourceDomain)
          : false;

        // === WHITELIST CHECK (exception rules take precedence) ===
        
        // Fast path: Check exact domain in Map (O(1))
        let rule = rules.whitelistMap.get(lowerHostname);  // V8: Single Map lookup
        if (rule) {
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
            if (enableLogging) {
              console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Whitelisted: ${url} (${rule.raw || rule.pattern})`));
            }
            const r = { blocked: false, rule: rule.raw || rule.pattern, reason: 'whitelisted' };
            resultCacheSet(url, sourceUrl, resourceType, r);
            return r;
          }
        }

        // Check parent domains for subdomain matches (e.g., sub.example.com -> example.com)
        const parents = getParentDomains();
        for (let i = 0; i < parents.length; i++) {
          rule = rules.whitelistMap.get(parents[i]);
          if (rule) {
            if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
              if (enableLogging) {
                console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Whitelisted: ${url} (${rule.raw || rule.pattern})`));
              }
              const r = { blocked: false, rule: rule.raw || rule.pattern, reason: 'whitelisted' };
              resultCacheSet(url, sourceUrl, resourceType, r);
              return r;
            }
          }
        }
        
        // Slow path: Check wildcard whitelist patterns in array
        const whitelistLen = rules.whitelist.length;  // V8: Cache length + indexed access
        for (let i = 0; i < whitelistLen; i++) {
          const rule = rules.whitelist[i];
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
            if (enableLogging) {
              console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Whitelisted: ${url} (${rule.raw || rule.pattern})`));
            }
              const r = { blocked: false, rule: rule.raw || rule.pattern, reason: 'whitelisted' };
              resultCacheSet(url, sourceUrl, resourceType, r);
              return r;
          }
        }

        // === DOMAIN BLOCKING CHECK ===

        // Fast path: Check exact domain in Map (O(1))
        rule = rules.domainMap.get(lowerHostname);  // V8: Single Map lookup
        if (rule) {
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
            if (enableLogging) {
              console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Blocked domain: ${url} (${rule.raw || rule.pattern})`));
            }
            const r = { blocked: true, rule: rule.raw || rule.pattern, reason: 'domain_rule' };
            resultCacheSet(url, sourceUrl, resourceType, r);
            return r;
          }
        }

        // Check parent domains for subdomain matches (e.g., ads.example.com -> example.com)
        for (let i = 0; i < parents.length; i++) {
          rule = rules.domainMap.get(parents[i]);
          if (rule) {
            if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
              if (enableLogging) {
                console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Blocked domain: ${url} (${rule.raw || rule.pattern})`));
              }
              const r = { blocked: true, rule: rule.raw || rule.pattern, reason: 'domain_rule' };
              resultCacheSet(url, sourceUrl, resourceType, r);
              return r;
            }
          }
        }
        
        // Slow path: Check wildcard domain patterns in array
        const domainRulesLen = rules.domainRules.length;  // V8: Cache length + indexed access
        for (let i = 0; i < domainRulesLen; i++) {
          const rule = rules.domainRules[i];
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
            if (enableLogging) {
              console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Blocked domain: ${url} (${rule.raw || rule.pattern})`));
            }
            const r = { blocked: true, rule: rule.raw || rule.pattern, reason: 'domain_rule' };
            resultCacheSet(url, sourceUrl, resourceType, r);
            return r;
          }
        }

        // Check third-party rules
        if (isThirdParty) {
          const thirdPartyLen = rules.thirdPartyRules.length;  // V8: Cache length
          for (let i = 0; i < thirdPartyLen; i++) {
            const rule = rules.thirdPartyRules[i];
            if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
              if (enableLogging) {
                console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Blocked third-party: ${url} (${rule.raw || rule.pattern})`));
              }
              const r = { blocked: true, rule: rule.raw || rule.pattern, reason: 'third_party_rule' };
              resultCacheSet(url, sourceUrl, resourceType, r);
              return r;
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
                console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Blocked first-party: ${url} (${rule.raw || rule.pattern})`));
              }
              const r = { blocked: true, rule: rule.raw || rule.pattern, reason: 'first_party_rule' };
              resultCacheSet(url, sourceUrl, resourceType, r);
              return r;
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
                console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Blocked script: ${url} (${rule.raw || rule.pattern})`));
              }
              const r = { blocked: true, rule: rule.raw || rule.pattern, reason: 'script_rule' };
              resultCacheSet(url, sourceUrl, resourceType, r);
              return r;
            }
          }
        }

        // Check path rules
        const pathRulesLen = rules.pathRules.length;  // V8: Cache length
        for (let i = 0; i < pathRulesLen; i++) {
          const rule = rules.pathRules[i];
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
            if (enableLogging) {
              console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Blocked path: ${url} (${rule.raw || rule.pattern})`));
            }
            const r = { blocked: true, rule: rule.raw || rule.pattern, reason: 'path_rule' };
            resultCacheSet(url, sourceUrl, resourceType, r);
            return r;
          }
        }

        // Check regex rules (most expensive, check last)
        const regexRulesLen = rules.regexRules.length;  // V8: Cache length
        for (let i = 0; i < regexRulesLen; i++) {
          const rule = rules.regexRules[i];
          if (matchesRule(rule, url, hostname, isThirdParty, resourceType, sourceDomain)) {
            if (enableLogging) {
              console.log(formatLogMessage('debug', `${ADBLOCK_TAG} Blocked regex: ${url} (${rule.raw || rule.pattern})`));
            }
            const r = { blocked: true, rule: rule.raw || rule.pattern, reason: 'regex_rule' };
            resultCacheSet(url, sourceUrl, resourceType, r);
            return r;
          }
        }

        // No match - allow request
        const r = { blocked: false, rule: null, reason: 'no_match' };
        resultCacheSet(url, sourceUrl, resourceType, r);
        return r;

      } catch (err) {
        if (enableLogging) {
          console.log(formatLogMessage('warn', `${ADBLOCK_TAG} Error checking ${url}: ${err.message}`));
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
      // Per-cache hit rates instead of one lumped figure. The previous
      // single `hitRate` averaged three different cache behaviors and
      // wasn't actionable for diagnosing performance.
      const rate = (hits, misses) =>
        hits + misses > 0 ? ((hits / (hits + misses)) * 100).toFixed(1) + '%' : '0%';

      return {
        ...rules.stats,
        cache: {
          result: {
            hits: resultCacheHits,
            misses: resultCacheMisses,
            hitRate: rate(resultCacheHits, resultCacheMisses),
            size: resultCache.cache.size,
            maxSize: resultCache.maxSize
          },
          url: {
            hits: urlCacheHits,
            misses: urlCacheMisses,
            hitRate: rate(urlCacheHits, urlCacheMisses),
            size: urlCache.cache.size,
            maxSize: urlCache.maxSize
          },
          source: {
            hits: sourceCacheHits,
            misses: sourceCacheMisses,
            hitRate: rate(sourceCacheHits, sourceCacheMisses)
          }
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

  // Normalize resource type once for both checks
  if (resourceType && (rule.resourceTypes || rule.excludedResourceTypes)) {
    const normalizedType = RESOURCE_TYPE_ALIASES[resourceType] || resourceType;

    // Check resource type restrictions
    if (rule.resourceTypes && !rule.resourceTypes.has(normalizedType)) {
      return false;
    }

    // Check negated resource type restrictions ($~script, $~image, etc.)
    if (rule.excludedResourceTypes && rule.excludedResourceTypes.has(normalizedType)) {
      return false;
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
 * Extract base domain from hostname using Public Suffix List.
 * Correctly handles multi-part TLDs like .co.uk, .com.au, .com.br.
 * @param {string} hostname - Full hostname
 * @returns {string} Base domain
 */
// FIFOCache (not the previous clear-all-when-full Map). The old code
// nuked all 10000 cached entries on overflow, forcing the next 10000
// hosts to re-pay the psl.parse cost. FIFO evicts one entry at a time.
const _baseDomainCache = new FIFOCache(10000);
function getBaseDomain(hostname) {
  const cached = _baseDomainCache.get(hostname);
  if (cached) return cached;
  const parsed = psl.parse(hostname);
  const result = (parsed && parsed.domain) ? parsed.domain : hostname;
  _baseDomainCache.set(hostname, result);
  return result;
}

// Public surface. getBaseDomain stays internal — used by createMatcher's
// third-party check but no external caller ever imported it.
module.exports = {
  parseAdblockRules
};
