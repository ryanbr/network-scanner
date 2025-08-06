/**
 * Smart Cache Module - Intelligent multi-layer caching system for network scanner
 * Provides context-aware caching for domains, patterns, responses, and network tools
 */

const { LRUCache } = require('lru-cache');
const fs = require('fs');
const path = require('path');
const { formatLogMessage } = require('./colorize');

/**
 * SmartCache - Intelligent caching system with multiple cache layers
 * @class
 */
class SmartCache {
  constructor(options = {}) {
    this.options = {
      maxSize: options.maxSize || 5000,
      ttl: options.ttl || 1000 * 60 * 60, // 1 hour default
      enablePatternCache: options.enablePatternCache !== false,
      enableResponseCache: options.enableResponseCache !== false,
      enableWhoisCache: options.enableWhoisCache !== false,
      enablePersistence: options.enablePersistence === true,
      persistencePath: options.persistencePath || '.cache',
      forceDebug: options.forceDebug || false,
      autoSave: options.autoSave !== false,
      autoSaveInterval: options.autoSaveInterval || 60000 // 1 minute
    };
    
    // Initialize cache layers
    this._initializeCaches();
    
    // Initialize statistics
    this._initializeStats();
    
    // Load persistent cache if enabled
    if (this.options.enablePersistence) {
      this._loadPersistentCache();
    }
    
    // Set up auto-save if enabled
    if (this.options.enablePersistence && this.options.autoSave) {
      this._setupAutoSave();
    }
  }
  
  /**
   * Initialize all cache layers
   * @private
   */
  _initializeCaches() {
    // Domain detection cache with TTL
    this.domainCache = new LRUCache({
      max: this.options.maxSize,
      ttl: this.options.ttl,
      updateAgeOnGet: true,
      updateAgeOnHas: false
    });
    
    // Pattern matching results cache
    this.patternCache = new LRUCache({
      max: 1000,
      ttl: this.options.ttl * 2 // Patterns are more stable
    });
    
    // Response content cache for searchstring operations
    this.responseCache = new LRUCache({
      max: 200,
      ttl: 1000 * 60 * 30, // 30 minutes for response content
      maxSize: 50 * 1024 * 1024, // 50MB max cache size
      sizeCalculation: (value) => value.length
    });
    
    // WHOIS/DNS results cache
    this.netToolsCache = new LRUCache({
      max: 500,
      ttl: 1000 * 60 * 60 * 24 // 24 hours for WHOIS/DNS
    });
    
    // Similarity cache for expensive string comparisons
    this.similarityCache = new LRUCache({
      max: 2000,
      ttl: this.options.ttl
    });
    
    // Regex compilation cache
    this.regexCache = new Map();
  }
  
  /**
   * Initialize statistics tracking
   * @private
   */
  _initializeStats() {
    this.stats = {
      hits: 0,
      misses: 0,
      patternHits: 0,
      patternMisses: 0,
      responseHits: 0,
      responseMisses: 0,
      netToolsHits: 0,
      netToolsMisses: 0,
      similarityHits: 0,
      similarityMisses: 0,
      regexCompilations: 0,
      regexCacheHits: 0,
      persistenceLoads: 0,
      persistenceSaves: 0,
      startTime: Date.now()
    };
  }
  
  /**
   * Check if domain should be skipped based on smart caching
   * @param {string} domain - Domain to check
   * @param {Object} context - Processing context
   * @returns {boolean} True if domain should be skipped
   */
  shouldSkipDomain(domain, context = {}) {
    const cacheKey = this._generateCacheKey(domain, context);
    
    if (this.domainCache.has(cacheKey)) {
      this.stats.hits++;
      if (this.options.forceDebug) {
        const cached = this.domainCache.get(cacheKey);
        const age = Date.now() - cached.timestamp;
        console.log(formatLogMessage('debug', 
          `[SmartCache] Cache hit for ${domain} (age: ${Math.round(age/1000)}s, context: ${JSON.stringify(context)})`
        ));
      }
      return true;
    }
    
    this.stats.misses++;
    return false;
  }
  
  /**
   * Mark domain as processed with context
   * @param {string} domain - Domain to mark
   * @param {Object} context - Processing context
   * @param {Object} metadata - Additional metadata to store
   */
  markDomainProcessed(domain, context = {}, metadata = {}) {
    const cacheKey = this._generateCacheKey(domain, context);
    this.domainCache.set(cacheKey, {
      timestamp: Date.now(),
      metadata,
      context,
      domain
    });
    
    if (this.options.forceDebug) {
      console.log(formatLogMessage('debug', 
        `[SmartCache] Marked ${domain} as processed (context: ${JSON.stringify(context)})`
      ));
    }
  }
  
  /**
   * Generate cache key with context awareness
   * @param {string} domain - Domain
   * @param {Object} context - Context object
   * @returns {string} Cache key
   * @private
   */
  _generateCacheKey(domain, context) {
    const { filterRegex, searchString, resourceType, nettools } = context;
    const components = [
      domain,
      filterRegex || '',
      searchString || '',
      resourceType || '',
      nettools ? 'nt' : ''
    ].filter(Boolean);
    
    return components.join(':');
  }
  
  /**
   * Get or compile regex pattern with caching
   * @param {string} pattern - Regex pattern string
   * @returns {RegExp} Compiled regex
   */
  getCompiledRegex(pattern) {
    if (!this.regexCache.has(pattern)) {
      this.stats.regexCompilations++;
      try {
        const regex = new RegExp(pattern.replace(/^\/(.*)\/$/, '$1'));
        this.regexCache.set(pattern, regex);
      } catch (err) {
        if (this.options.forceDebug) {
          console.log(formatLogMessage('debug', 
            `[SmartCache] Failed to compile regex: ${pattern}`
          ));
        }
        return null;
      }
    } else {
      this.stats.regexCacheHits++;
    }
    
    return this.regexCache.get(pattern);
  }
  
  /**
   * Check pattern matching cache
   * @param {string} url - URL to check
   * @param {string} pattern - Regex pattern
   * @returns {boolean|null} Cached result or null if not cached
   */
  getCachedPatternMatch(url, pattern) {
    if (!this.options.enablePatternCache) return null;
    
    const cacheKey = `${url}:${pattern}`;
    const cached = this.patternCache.get(cacheKey);
    
    if (cached !== undefined) {
      this.stats.patternHits++;
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Pattern cache hit for ${url.substring(0, 50)}...`
        ));
      }
      return cached;
    }
    
    this.stats.patternMisses++;
    return null;
  }
  
  /**
   * Cache pattern matching result
   * @param {string} url - URL
   * @param {string} pattern - Regex pattern
   * @param {boolean} result - Match result
   */
  cachePatternMatch(url, pattern, result) {
    if (!this.options.enablePatternCache) return;
    
    const cacheKey = `${url}:${pattern}`;
    this.patternCache.set(cacheKey, result);
  }
  
  /**
   * Get cached response content
   * @param {string} url - URL
   * @returns {string|null} Cached content or null
   */
  getCachedResponse(url) {
    if (!this.options.enableResponseCache) return null;
    
    const cached = this.responseCache.get(url);
    if (cached) {
      this.stats.responseHits++;
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Response cache hit for ${url.substring(0, 50)}...`
        ));
      }
      return cached;
    }
    
    this.stats.responseMisses++;
    return null;
  }
  
  /**
   * Cache response content
   * @param {string} url - URL
   * @param {string} content - Response content
   */
  cacheResponse(url, content) {
    if (!this.options.enableResponseCache) return;
    
    // Only cache if content is reasonable size
    if (content && content.length < 5 * 1024 * 1024) { // 5MB limit per response
      this.responseCache.set(url, content);
    }
  }
  
  /**
   * Get cached WHOIS/DNS results
   * @param {string} domain - Domain
   * @param {string} tool - Tool name (whois/dig)
   * @param {string} recordType - Record type for dig
   * @returns {Object|null} Cached result or null
   */
  getCachedNetTools(domain, tool, recordType = null) {
    if (!this.options.enableWhoisCache) return null;
    
    const cacheKey = `${tool}:${domain}${recordType ? ':' + recordType : ''}`;
    const cached = this.netToolsCache.get(cacheKey);
    
    if (cached) {
      this.stats.netToolsHits++;
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] ${tool.toUpperCase()} cache hit for ${domain}`
        ));
      }
      return cached;
    }
    
    this.stats.netToolsMisses++;
    return null;
  }
  
  /**
   * Cache WHOIS/DNS results
   * @param {string} domain - Domain
   * @param {string} tool - Tool name
   * @param {Object} result - Result to cache
   * @param {string} recordType - Record type for dig
   */
  cacheNetTools(domain, tool, result, recordType = null) {
    if (!this.options.enableWhoisCache) return;
    
    const cacheKey = `${tool}:${domain}${recordType ? ':' + recordType : ''}`;
    this.netToolsCache.set(cacheKey, result);
  }
  
  /**
   * Cache similarity comparison result
   * @param {string} domain1 - First domain
   * @param {string} domain2 - Second domain
   * @param {number} similarity - Similarity score
   */
  cacheSimilarity(domain1, domain2, similarity) {
    const key = [domain1, domain2].sort().join('|');
    this.similarityCache.set(key, similarity);
  }
  
  /**
   * Get cached similarity score
   * @param {string} domain1 - First domain
   * @param {string} domain2 - Second domain
   * @returns {number|null} Cached similarity or null
   */
  getCachedSimilarity(domain1, domain2) {
    const key = [domain1, domain2].sort().join('|');
    const cached = this.similarityCache.get(key);
    
    if (cached !== undefined) {
      this.stats.similarityHits++;
      return cached;
    }
    
    this.stats.similarityMisses++;
    return null;
  }
  
  /**
   * Get cache statistics
   * @returns {Object} Statistics object
   */
  getStats() {
    const runtime = Date.now() - this.stats.startTime;
    const hitRate = this.stats.hits / (this.stats.hits + this.stats.misses) || 0;
    const patternHitRate = this.stats.patternHits / 
      (this.stats.patternHits + this.stats.patternMisses) || 0;
    const responseHitRate = this.stats.responseHits / 
      (this.stats.responseHits + this.stats.responseMisses) || 0;
    const netToolsHitRate = this.stats.netToolsHits / 
      (this.stats.netToolsHits + this.stats.netToolsMisses) || 0;
    
    return {
      ...this.stats,
      runtime: Math.round(runtime / 1000), // seconds
      hitRate: (hitRate * 100).toFixed(2) + '%',
      patternHitRate: (patternHitRate * 100).toFixed(2) + '%',
      responseHitRate: (responseHitRate * 100).toFixed(2) + '%',
      netToolsHitRate: (netToolsHitRate * 100).toFixed(2) + '%',
      domainCacheSize: this.domainCache.size,
      patternCacheSize: this.patternCache.size,
      responseCacheSize: this.responseCache.size,
      netToolsCacheSize: this.netToolsCache.size,
      similarityCacheSize: this.similarityCache.size,
      regexCacheSize: this.regexCache.size,
      totalCacheEntries: this.domainCache.size + this.patternCache.size + 
        this.responseCache.size + this.netToolsCache.size + 
        this.similarityCache.size + this.regexCache.size
    };
  }
  
  /**
   * Clear all caches
   */
  clear() {
    this.domainCache.clear();
    this.patternCache.clear();
    this.responseCache.clear();
    this.netToolsCache.clear();
    this.similarityCache.clear();
    this.regexCache.clear();
    this._initializeStats();
    
    if (this.options.forceDebug) {
      console.log(formatLogMessage('debug', '[SmartCache] All caches cleared'));
    }
  }
  
  /**
   * Load persistent cache from disk
   * @private
   */
  _loadPersistentCache() {
    const cacheFile = path.join(this.options.persistencePath, 'smart-cache.json');
    
    if (!fs.existsSync(cacheFile)) {
      return;
    }
    
    try {
      const data = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
      const now = Date.now();
      
      // Validate cache age
      if (data.timestamp && now - data.timestamp > 24 * 60 * 60 * 1000) {
        if (this.options.forceDebug) {
          console.log(formatLogMessage('debug', 
            '[SmartCache] Persistent cache too old, ignoring'
          ));
        }
        return;
      }
      
      // Load domain cache
      if (data.domainCache && Array.isArray(data.domainCache)) {
        data.domainCache.forEach(([key, value]) => {
          // Only load if not expired
          if (now - value.timestamp < this.options.ttl) {
            this.domainCache.set(key, value);
          }
        });
      }
      
      // Load nettools cache
      if (data.netToolsCache && Array.isArray(data.netToolsCache)) {
        data.netToolsCache.forEach(([key, value]) => {
          this.netToolsCache.set(key, value);
        });
      }
      
      this.stats.persistenceLoads++;
      
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Loaded persistent cache: ${this.domainCache.size} domains, ${this.netToolsCache.size} nettools`
        ));
      }
    } catch (err) {
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Failed to load persistent cache: ${err.message}`
        ));
      }
    }
  }
  
  /**
   * Save cache to disk
   */
  savePersistentCache() {
    if (!this.options.enablePersistence) return;
    
    const cacheDir = this.options.persistencePath;
    const cacheFile = path.join(cacheDir, 'smart-cache.json');
    
    try {
      // Create cache directory if it doesn't exist
      if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
      }
      
      const data = {
        timestamp: Date.now(),
        domainCache: Array.from(this.domainCache.entries()),
        netToolsCache: Array.from(this.netToolsCache.entries()),
        stats: this.stats
      };
      
      fs.writeFileSync(cacheFile, JSON.stringify(data, null, 2));
      this.stats.persistenceSaves++;
      
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Saved cache to disk: ${cacheFile}`
        ));
      }
    } catch (err) {
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Failed to save cache: ${err.message}`
        ));
      }
    }
  }
  
  /**
   * Set up auto-save interval
   * @private
   */
  _setupAutoSave() {
    this.autoSaveInterval = setInterval(() => {
      this.savePersistentCache();
    }, this.options.autoSaveInterval);
  }
  
  /**
   * Clean up resources
   */
  destroy() {
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
    }
    
    // Save cache one last time
    if (this.options.enablePersistence) {
      this.savePersistentCache();
    }
    
    this.clear();
  }
}

/**
 * Factory function to create SmartCache instance with config
 * @param {Object} config - Configuration object
 * @returns {SmartCache} SmartCache instance
 */
function createSmartCache(config = {}) {
  return new SmartCache({
    maxSize: config.cache_max_size,
    ttl: (config.cache_ttl_minutes || 60) * 60 * 1000,
    enablePatternCache: config.cache_patterns !== false,
    enableResponseCache: config.cache_responses !== false,
    enableWhoisCache: config.cache_nettools !== false,
    enablePersistence: config.cache_persistence === true,
    persistencePath: config.cache_path || '.cache',
    forceDebug: config.forceDebug || false,
    autoSave: config.cache_autosave !== false,
    autoSaveInterval: (config.cache_autosave_minutes || 1) * 60 * 1000
  });
}

module.exports = {
  SmartCache,
  createSmartCache
};