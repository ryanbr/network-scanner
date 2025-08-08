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
    // Calculate dynamic values first
    const concurrency = options.concurrency || 6;
    const optimalHeapLimit = this._calculateOptimalHeapLimit(concurrency);
    const checkInterval = this._calculateCheckInterval(concurrency);

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
      autoSaveInterval: options.autoSaveInterval || 60000, // 1 minute
      maxHeapUsage: options.maxHeapUsage || optimalHeapLimit,
      memoryCheckInterval: options.memoryCheckInterval || checkInterval,
      concurrency: concurrency,
      aggressiveMode: options.aggressiveMode || false
    };

    // Add save debouncing
    this.lastSaveTime = 0;
    this.saveInProgress = false;
    this.saveTimeout = null;
    this.pendingSave = false;
    
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
    
    // Set up memory monitoring
    this.memoryCheckInterval = setInterval(() => {
      this._checkMemoryPressure();
    }, this.options.memoryCheckInterval);
  }
  
  /**
   * Calculate optimal heap limit based on concurrency
   * @private
   */
  _calculateOptimalHeapLimit(concurrency) {
    // Base cache needs: 100MB
    // Per concurrent connection: ~75MB average
    // Safety margin: 50%
    const baseCacheMemory = 100 * 1024 * 1024; // 100MB
    const perConnectionMemory = 75 * 1024 * 1024; // 75MB
    const totalEstimated = baseCacheMemory + (concurrency * perConnectionMemory);
    return Math.round(totalEstimated * 0.4); // Cache should use max 40% of estimated total
  }
  
  /**
   * Calculate check interval based on concurrency
   * @private
   */
  _calculateCheckInterval(concurrency) {
    // Higher concurrency = more frequent checks
    return Math.max(5000, 30000 - (concurrency * 1000)); // 5s min, scales down with concurrency
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
    
    // Pattern matching results cache - reduce size for high concurrency
    const patternCacheSize = this.options.concurrency > 10 ? 500 : 1000;
    this.patternCache = new LRUCache({
      max: patternCacheSize,
      ttl: this.options.ttl * 2 // Patterns are more stable
    });
    
    // Response content cache - aggressive limits for high concurrency
    const responseCacheSize = this.options.concurrency > 10 ? 50 : 200;
    const responseCacheMemory = this.options.concurrency > 10 ? 20 * 1024 * 1024 : 50 * 1024 * 1024;
    this.responseCache = new LRUCache({
      max: responseCacheSize,
      ttl: 1000 * 60 * 30, // 30 minutes for response content
      maxSize: responseCacheMemory,
      sizeCalculation: (value) => value.length
    });
    
    // Disable response cache entirely for very high concurrency
    if (this.options.concurrency > 15 || this.options.aggressiveMode) {
      this.options.enableResponseCache = false;
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Response cache disabled for high concurrency (${this.options.concurrency})`
        ));
      }
    }

    // WHOIS/DNS results cache
    this.netToolsCache = new LRUCache({
      max: 500,
      ttl: 1000 * 60 * 60 * 24 // 24 hours for WHOIS/DNS
    });
    
    // Similarity cache - reduce for high concurrency
    const similarityCacheSize = this.options.concurrency > 10 ? 1000 : 2000;
    this.similarityCache = new LRUCache({
      max: similarityCacheSize,
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
      memoryPressureEvents: 0,
      memoryWarnings: 0,
      responseCacheSkips: 0,
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
    
    // Skip response caching entirely for very high concurrency
    if (this.options.concurrency > 12) {
      this.stats.responseCacheSkips++;
      return;
    }
    
    // Check memory before caching large content
    const memUsage = process.memoryUsage();
    const threshold = this.options.concurrency > 10 ? 0.7 : 0.8; // Lower threshold for high concurrency
    if (memUsage.heapUsed > this.options.maxHeapUsage * threshold) {
      this.stats.responseCacheSkips++;
      this._logMemorySkip('response cache');
      return;
    }
    
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
   * Monitor memory usage and proactively manage caches
   * @private
   */
  _checkMemoryPressure() {
    const memUsage = process.memoryUsage();
    const heapUsedMB = Math.round(memUsage.heapUsed / 1024 / 1024);
    const maxHeapMB = Math.round(this.options.maxHeapUsage / 1024 / 1024);
    const usagePercent = (memUsage.heapUsed / this.options.maxHeapUsage) * 100;
    
    // Adjust thresholds based on concurrency
    const criticalThreshold = this.options.concurrency > 10 ? 0.85 : 1.0;
    const warningThreshold = this.options.concurrency > 10 ? 0.70 : 0.85;
    const infoThreshold = this.options.concurrency > 10 ? 0.60 : 0.75;
    
    // Critical threshold - aggressive cleanup
    if (memUsage.heapUsed > this.options.maxHeapUsage * criticalThreshold) {
      this._performMemoryCleanup('critical', heapUsedMB, maxHeapMB);
      return true;
    }
    
    // Warning threshold - moderate cleanup
    if (memUsage.heapUsed > this.options.maxHeapUsage * warningThreshold) {
      this._performMemoryCleanup('warning', heapUsedMB, maxHeapMB);
      return true;
    }
    
    // Info threshold - log only
    if (memUsage.heapUsed > this.options.maxHeapUsage * infoThreshold) {
      this.stats.memoryWarnings++;
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Memory info: ${heapUsedMB}MB/${maxHeapMB}MB (${usagePercent.toFixed(1)}%)`
        ));
      }
    }
    
    return false;
  }
  
  /**
   * Perform memory cleanup based on severity
   * @private
   */
  _performMemoryCleanup(level, heapUsedMB, maxHeapMB) {
    this.stats.memoryPressureEvents++;
    
    if (this.options.forceDebug) {
      console.log(formatLogMessage('debug', 
        `[SmartCache] Memory ${level}: ${heapUsedMB}MB/${maxHeapMB}MB, performing cleanup...`
      ));
    }
    
    if (level === 'critical' || this.options.concurrency > 12) {
      // Aggressive cleanup - clear volatile caches
      this.responseCache.clear();
      this.patternCache.clear();
      this.similarityCache.clear();
      
      // For very high concurrency, also trim domain cache
      if (this.options.concurrency > 15) {
        const currentSize = this.domainCache.size;
        this.domainCache.clear();
        if (this.options.forceDebug) {
          console.log(formatLogMessage('debug', `[SmartCache] Cleared ${currentSize} domain cache entries`));
        }
      }
    } else if (level === 'warning') {
      // Moderate cleanup - clear largest cache
      this.responseCache.clear();
    }
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
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
      
    
    const memUsage = process.memoryUsage();
    
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
        this.similarityCache.size + this.regexCache.size,
      memoryUsageMB: Math.round(memUsage.heapUsed / 1024 / 1024),
      memoryMaxMB: Math.round(this.options.maxHeapUsage / 1024 / 1024),
      memoryUsagePercent: ((memUsage.heapUsed / this.options.maxHeapUsage) * 100).toFixed(1) + '%',
      responseCacheMemoryMB: Math.round((this.responseCache.calculatedSize || 0) / 1024 / 1024)
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
   * Helper method to log memory-related cache skips
   * @private
   */
  _logMemorySkip(operation) {
    if (this.options.forceDebug) {
      console.log(formatLogMessage('debug', 
        `[SmartCache] Skipping ${operation} due to memory pressure`
      ));
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

    // Prevent concurrent saves
    if (this.saveInProgress) {
      this.pendingSave = true;
      if (this.options.forceDebug) {
        console.log(formatLogMessage('debug', '[SmartCache] Save in progress, marking pending...'));
      }
      return;
    }
    
    // Debounce saves - don't save more than once every 10 seconds
    const now = Date.now();
    if (now - this.lastSaveTime < 10000) {
      // Schedule a delayed save if none is pending
      if (!this.saveTimeout && !this.pendingSave) {
        this.pendingSave = true;
        this.saveTimeout = setTimeout(() => {
          this.saveTimeout = null;
          if (this.pendingSave) {
            this.pendingSave = false;
            this.savePersistentCache();
          }
        }, 10000 - (now - this.lastSaveTime));
      }
      return;
    }
    this.saveInProgress = true;
    this.lastSaveTime = now;
    
    const cacheDir = this.options.persistencePath;
    const cacheFile = path.join(cacheDir, 'smart-cache.json');
    
    try {
      // Create cache directory if it doesn't exist
      if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
      }
      
      const data = {
        timestamp: now,
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
    } finally {
      this.saveInProgress = false;
      
      // Process any pending saves
      if (this.pendingSave && !this.saveTimeout) {
        this.pendingSave = false;
        setTimeout(() => this.savePersistentCache(), 1000);
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
    if (this.memoryCheckInterval) {
      clearInterval(this.memoryCheckInterval);
    }
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
    }
    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
      this.saveTimeout = null;
    }
    
    // Save cache one last time
    if (this.options.enablePersistence) {
      this.savePersistentCache();
    }
    
    this.clear();
  }
  
  /**
   * Clear persistent cache files and directories
   * @param {Object} options - Clear options
   * @param {boolean} options.silent - Suppress console output
   * @param {boolean} options.forceDebug - Enable debug logging
   * @returns {Object} Clear operation results
   */
  static clearPersistentCache(options = {}) {
    const { silent = false, forceDebug = false, cachePath = '.cache' } = options;
    
    const cachePaths = [
      cachePath,
      path.join(cachePath, 'smart-cache.json'),
      // Add other potential cache files here if needed
    ];
    
    let clearedItems = 0;
    let totalSize = 0;
    const clearedFiles = [];
    const errors = [];
    
    if (!silent) {
      console.log(`\n???  Clearing cache...`);
    }
    
    for (const currentCachePath of cachePaths) {
      if (fs.existsSync(currentCachePath)) {
        try {
          const stats = fs.statSync(currentCachePath);
          if (stats.isDirectory()) {
            // Calculate total size of directory contents
            const files = fs.readdirSync(currentCachePath);
            for (const file of files) {
              const filePath = path.join(currentCachePath, file);
              if (fs.existsSync(filePath)) {
                totalSize += fs.statSync(filePath).size;
              }
            }
            fs.rmSync(currentCachePath, { recursive: true, force: true });
            clearedItems++;
            clearedFiles.push({ type: 'directory', path: currentCachePath, size: totalSize });
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Cleared cache directory: ${currentCachePath}`));
            }
          } else {
            totalSize += stats.size;
            fs.unlinkSync(currentCachePath);
            clearedItems++;
            clearedFiles.push({ type: 'file', path: currentCachePath, size: stats.size });
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Cleared cache file: ${currentCachePath}`));
            }
          }
        } catch (clearErr) {
          errors.push({ path: currentCachePath, error: clearErr.message });
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Failed to clear ${currentCachePath}: ${clearErr.message}`));
          }
        }
      }
    }
    
    const result = {
      success: errors.length === 0,
      clearedItems,
      totalSize,
      sizeMB: (totalSize / 1024 / 1024).toFixed(2),
      clearedFiles,
      errors
    };
    
    if (!silent) {
      if (clearedItems > 0) {
        console.log(`? Cache cleared: ${clearedItems} item(s), ${result.sizeMB}MB freed`);
      } else {
        console.log(`??  No cache files found to clear`);
      }
      
      if (errors.length > 0) {
        console.warn(`??  ${errors.length} error(s) occurred during cache clearing`);
      }
    }
    
    return result;
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
    autoSaveInterval: (config.cache_autosave_minutes || 1) * 60 * 1000,
    maxHeapUsage: config.cache_max_heap_mb ? config.cache_max_heap_mb * 1024 * 1024 : undefined,
    memoryCheckInterval: (config.cache_memory_check_seconds || 30) * 1000,
    concurrency: config.max_concurrent_sites || 6,
    aggressiveMode: config.cache_aggressive_mode === true
  });
}

module.exports = {
  SmartCache,
  createSmartCache,
  clearPersistentCache: SmartCache.clearPersistentCache
};