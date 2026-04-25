/**
 * Smart Cache Module - Intelligent multi-layer caching system for network scanner
 * Provides context-aware caching for domains, patterns, responses, and network tools
 */

const { LRUCache } = require('lru-cache');
const fs = require('fs');
const path = require('path');
const { formatLogMessage } = require('./colorize');

// Shared frozen empty object -- avoids allocating new {} for every default param
const EMPTY = Object.freeze({});

/**
 * SmartCache - Intelligent caching system with multiple cache layers
 * @class
 */
class SmartCache {
  constructor(options = EMPTY) {
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
      enableRequestCache: options.enableRequestCache === true, // NEW: Request caching feature
      enablePersistence: options.enablePersistence === true,
      persistencePath: options.persistencePath || '.cache',
      forceDebug: options.forceDebug || false,
      autoSave: options.autoSave !== false,
      autoSaveInterval: options.autoSaveInterval || 60000, // 1 minute
      maxHeapUsage: options.maxHeapUsage || optimalHeapLimit,
      memoryCheckInterval: options.memoryCheckInterval || checkInterval,
      concurrency: concurrency,
      aggressiveMode: options.aggressiveMode || false,
      requestCacheMaxSize: options.requestCacheMaxSize || 1000, // NEW: Max cached requests
      requestCacheMaxMemory: options.requestCacheMaxMemory || 100 * 1024 * 1024 // NEW: 100MB for request cache
    };

    // Add save debouncing
    this.lastSaveTime = 0;
    this.saveInProgress = false;
    this.saveTimeout = null;
    this.pendingSave = false;

    // Cache hot-path flags BEFORE _initializeCaches uses them
    this._debug = this.options.forceDebug;
    this._highConcurrency = this.options.concurrency > 10;
    this._criticalThreshold = this._highConcurrency ? 0.85 : 1.0;
    this._warningThreshold = this._highConcurrency ? 0.70 : 0.85;
    this._infoThreshold = this._highConcurrency ? 0.60 : 0.75;
    
    // Initialize cache layers (may disable responseCache for high concurrency)
    this._initializeCaches();

    // Cache enable flags AFTER _initializeCaches which may modify options
    this._enablePattern = this.options.enablePatternCache;
    this._enableResponse = this.options.enableResponseCache;
    this._enableWhois = this.options.enableWhoisCache;
    this._enableRequest = this.options.enableRequestCache;
    
    // Initialize statistics
    this._initializeStats();

    // Cached memory usage (updated by _checkMemoryPressure interval)
    this._lastHeapUsed = 0;
    this._memoryPressure = false;

    
    // NEW: Clear request cache
    if (this._enableRequest) {
      this.clearRequestCache();
    }
    
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
    const patternCacheSize = this._highConcurrency ? 500 : 1000;
    this.patternCache = new LRUCache({
      max: patternCacheSize,
      ttl: this.options.ttl * 2 // Patterns are more stable
    });
    
    // Response content cache - aggressive limits for high concurrency
    const responseCacheSize = this._highConcurrency ? 50 : 200;
    const responseCacheMemory = this._highConcurrency ? 20 * 1024 * 1024 : 50 * 1024 * 1024;
    this.responseCache = new LRUCache({
      max: responseCacheSize,
      ttl: 1000 * 60 * 30, // 30 minutes for response content
      maxSize: responseCacheMemory,
      sizeCalculation: (value) => value.length
    });

    // NEW: Request-level cache for --cache-requests feature
    if (this._enableRequest) {
      this.requestCache = new LRUCache({
        max: this.options.requestCacheMaxSize,
        ttl: 1000 * 60 * 15, // 15 minutes for request cache (shorter than response cache)
        maxSize: this.options.requestCacheMaxMemory,
        sizeCalculation: (value) => {
          let size = 100; // Base overhead for object shell + metadata fields
          if (value.headers) {
            // Estimate header size without JSON.stringify (each header ~50 bytes avg)
            const keys = Object.keys(value.headers);
            size += keys.length * 50;
          }
          if (value.body) size += value.body.length;
          return size;
        }
      });
      
      if (this._debug) {
        console.log(formatLogMessage('debug', `[SmartCache] Request cache initialized: ${this.options.requestCacheMaxSize} entries`));
      }
    }

    // Disable response cache entirely for very high concurrency
    if (this.options.concurrency > 15 || this.options.aggressiveMode) {
      this.options.enableResponseCache = false;
      if (this._debug) {
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
    const similarityCacheSize = this._highConcurrency ? 1000 : 2000;
    this.similarityCache = new LRUCache({
      max: similarityCacheSize,
      ttl: this.options.ttl
    });
    
    // Regex compilation cache (bounded to prevent unbounded growth)
    this.regexCache = new LRUCache({ max: 500 });
    
    // Precompile the regex-stripping pattern (used in getCompiledRegex)
    this._regexStripPattern = /^\/(.*)\/$/;
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
      startTime: Date.now(),
      requestCacheHits: 0,
      requestCacheMisses: 0,
      requestCacheSkips: 0,
      requestCacheClears: 0
    };
  }
  
  /**
   * Check if domain should be skipped based on smart caching
   * @param {string} domain - Domain to check
   * @param {Object} context - Processing context
   * @returns {boolean} True if domain should be skipped
   */
  shouldSkipDomain(domain, context = EMPTY) {
    const cacheKey = this._generateCacheKey(domain, context);
    const cached = this.domainCache.get(cacheKey);
    
    if (cached !== undefined) {
      this.stats.hits++;
      if (this._debug) {
        const age = Date.now() - cached.timestamp;
        console.log(formatLogMessage('debug', 
          `[SmartCache] Cache hit for ${domain} (age: ${Math.round(age/1000)}s)`
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
  markDomainProcessed(domain, context = EMPTY, metadata = EMPTY) {
    const cacheKey = this._generateCacheKey(domain, context);
    // Consistent property order ensures V8 reuses the same hidden class
    const entry = { timestamp: 0, domain: '', context: null, metadata: null };
    entry.timestamp = Date.now();
    entry.domain = domain;
    entry.context = context;
    entry.metadata = metadata;
    this.domainCache.set(cacheKey, entry);
    
    if (this._debug) {
      console.log(formatLogMessage('debug', 
        `[SmartCache] Marked ${domain} as processed`
      ));
    }
  }

  /**
   * Normalize URL for consistent caching while preserving path distinctions
   * @param {string} url - URL to normalize
   * @returns {string} Normalized URL
   * @private
   */
  _normalizeUrl(url) {
    // Fast path: strip fragment with indexOf (avoids new URL() for most URLs)
    const hashIdx = url.indexOf('#');
    let normalized = hashIdx !== -1 ? url.substring(0, hashIdx) : url;
    
    // Strip trailing slash (but not root path '/')
    if (normalized.length > 1 && normalized.charCodeAt(normalized.length - 1) === 47) { // '/'
      // Make sure we're not stripping query string trailing slash
      const qIdx = normalized.indexOf('?');
      if (qIdx === -1 || normalized.length - 1 < qIdx) {
        normalized = normalized.slice(0, -1);
      }
    }
    
    return normalized;
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
    let key = domain;
    if (filterRegex) key += ':' + filterRegex;
    if (searchString) key += ':' + searchString;
    if (resourceType) key += ':' + resourceType;
    if (nettools) key += ':nt';
    return key;
  }
  
  /**
   * Check if URL should bypass all caching
   * @param {string} url - URL to check
   * @param {Object} siteConfig - Site configuration
   * @returns {boolean} True if should bypass cache
   * @private
   */
  _shouldBypassCache(url, siteConfig = EMPTY) {
    if (!siteConfig.bypass_cache) return false;
    
    const bypassPatterns = Array.isArray(siteConfig.bypass_cache) 
      ? siteConfig.bypass_cache 
      : [siteConfig.bypass_cache];
    
    return bypassPatterns.some(pattern => {
      const regex = this.getCompiledRegex(pattern);
      return regex ? regex.test(url) : pattern === url;
    });
  }
  
  /**
   * Generate request cache key for HTTP requests
   * @param {string} url - Request URL
   * @param {Object} options - Request options (method, headers, etc.)
   * @returns {string} Cache key
   * @private
   */
  _generateRequestCacheKey(url, options = EMPTY, normalizedUrl = null) {
    const method = options.method || 'GET';
    const normUrl = normalizedUrl || this._normalizeUrl(url);
    const headers = options.headers || {};
    const importantHeaders = ['accept', 'accept-encoding', 'accept-language', 'user-agent'];
    
    // Build header portion of key by direct concat (avoids JSON.stringify + intermediate array)
    let headerKey = '';
    for (const header of importantHeaders) {
      const val = headers[header];
      if (val) headerKey += header + '=' + val + '&';
    }
    
    return method + '|' + normUrl + '|' + headerKey;
  }
  
  /**
   * Get cached HTTP request result
   * @param {string} url - Request URL
   * @param {Object} options - Request options
   * @returns {Object|null} Cached request result or null
   */
  getCachedRequest(url, options = EMPTY) {
    if (!this._enableRequest) return null;
    
    // Check bypass_cache setting
    if (options.siteConfig && this._shouldBypassCache(url, options.siteConfig)) {
      return null; // Force cache miss
    }

    const cacheKey = this._generateRequestCacheKey(url, options);
    const cached = this.requestCache.get(cacheKey);
    
    if (cached) {
      this.stats.requestCacheHits++;
      if (this._debug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Request cache hit for ${url.substring(0, 50)}... (${cached.status || 'unknown status'})`
        ));
      }
      // Set directly on cached object (avoids spread allocation per hit)
      cached.fromCache = true;
      cached.cacheAge = Date.now() - cached.timestamp;
      return cached;
    }
    
    this.stats.requestCacheMisses++;
    return null;
  }
  
  /**
   * Cache HTTP request result
   * @param {string} url - Request URL
   * @param {Object} options - Request options
   * @param {Object} result - Request result (status, headers, body)
   */
  cacheRequest(url, options = EMPTY, result = EMPTY) {
    if (!this._enableRequest) return;
    
    // Check bypass_cache setting
    if (options.siteConfig && this._shouldBypassCache(url, options.siteConfig)) {
      return; // Don't cache this URL
    }

    // Skip caching for very high concurrency or memory pressure
    if (this.options.concurrency > 15) {
      this.stats.requestCacheSkips++;
      return;
    }
    
    // Use cached memory pressure flag (updated by periodic _checkMemoryPressure)
    if (this._memoryPressure) {
      this.stats.requestCacheSkips++;
      this._logMemorySkip('request cache');
      return;
    }
    
    // Don't cache error responses unless explicitly requested
    if (result.status && result.status >= 400 && !options.cacheErrors) {
      return;
    }
    
    // Check size limit BEFORE building cache value object (avoids wasted allocation)
    const method = options.method || 'GET';
    const isHeadRequest = method.toUpperCase() === 'HEAD';
    if (!isHeadRequest && result.body && result.body.length >= 10485760) {
      return; // Over 10MB, skip
    }

    const normalizedUrl = this._normalizeUrl(url);
    const cacheKey = this._generateRequestCacheKey(url, options, normalizedUrl);
    
    this.requestCache.set(cacheKey, {
      timestamp: Date.now(),
      status: result.status,
      statusText: result.statusText,
      headers: result.headers,
      body: result.body,
      url: normalizedUrl,
      originalUrl: url,
      requestOptions: { method: method, headers: options.headers || {} }
    });
    
    if (this._debug) {
      const bodySize = result.body ? result.body.length : 0;
      console.log(formatLogMessage('debug', 
        `[SmartCache] Cached request: ${normalizedUrl.substring(0, 50)}... (${result.status || 'unknown'}, ${Math.round(bodySize / 1024)}KB)`
      ));
      if (normalizedUrl !== url) {
        console.log(formatLogMessage('debug', `[SmartCache] URL normalized: ${url} -> ${normalizedUrl}`));
      }
    }
  }
  
  /**
   * Clear all request cache entries
   * Useful when switching between different JSON configs
   */
  clearRequestCache() {
    if (!this._enableRequest || !this.requestCache) return;
    
    const clearedCount = this.requestCache.size;
    this.requestCache.clear();
    this.stats.requestCacheClears++;
    
    if (this._debug) {
      console.log(formatLogMessage('debug', 
        `[SmartCache] Cleared request cache: ${clearedCount} entries removed`
      ));
    }
    
    return clearedCount;
  }
  
  /**
   * Get request cache statistics
   */
  getRequestCacheStats() {
    if (!this._enableRequest || !this.requestCache) {
      return { enabled: false, size: 0, hitRate: '0%', memoryUsage: 0 };
    }
    
    const hitRate = this.stats.requestCacheHits / 
      (this.stats.requestCacheHits + this.stats.requestCacheMisses) || 0;
    
    return {
      enabled: true,
      size: this.requestCache.size,
      maxSize: this.options.requestCacheMaxSize,
      hitRate: (hitRate * 100).toFixed(2) + '%',
      hits: this.stats.requestCacheHits,
      misses: this.stats.requestCacheMisses,
      skips: this.stats.requestCacheSkips,
      clears: this.stats.requestCacheClears,
      memoryUsage: this.requestCache.calculatedSize || 0,
      memoryUsageMB: Math.round((this.requestCache.calculatedSize || 0) / 1024 / 1024),
      maxMemoryMB: Math.round(this.options.requestCacheMaxMemory / 1024 / 1024)
    };
  }

  /**
   * Get cache statistics with path-aware insights
   * @returns {Object} Enhanced statistics including path distribution
   */
  getEnhancedRequestCacheStats() {
    if (!this._enableRequest || !this.requestCache) {
      return this.getRequestCacheStats();
    }
    
    const basicStats = this.getRequestCacheStats();
    
    // Analyze path distribution using string split (avoids new URL() per entry)
    const pathDistribution = {};
    for (const [key, value] of this.requestCache.entries()) {
      const rawUrl = value.url || value.originalUrl;
      if (!rawUrl) continue;
      // Extract hostname+path: skip protocol, find first '/' after '://', take up to '?'
      const protoEnd = rawUrl.indexOf('://');
      if (protoEnd === -1) continue;
      const pathStart = rawUrl.indexOf('/', protoEnd + 3);
      const qIdx = rawUrl.indexOf('?', pathStart);
      const pathKey = pathStart !== -1 
        ? rawUrl.substring(protoEnd + 3, qIdx !== -1 ? qIdx : rawUrl.length)
        : rawUrl.substring(protoEnd + 3);
      pathDistribution[pathKey] = (pathDistribution[pathKey] || 0) + 1;
    }
    
    // Assign directly instead of spread
    basicStats.pathDistribution = pathDistribution;
    return basicStats;
  }

  /**
   * Get or compile regex pattern with caching
   * @param {string} pattern - Regex pattern string
   * @returns {RegExp} Compiled regex
   */
  getCompiledRegex(pattern) {
    const cached = this.regexCache.get(pattern);
    if (cached !== undefined) {
      this.stats.regexCacheHits++;
      return cached;
    }
    
    this.stats.regexCompilations++;
    try {
      const regex = new RegExp(pattern.replace(this._regexStripPattern, '$1'));
      this.regexCache.set(pattern, regex);
      return regex;
    } catch (err) {
      if (this._debug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Failed to compile regex: ${pattern}`
        ));
      }
      return null;
    }
  }
  
  /**
   * Check pattern matching cache
   * @param {string} url - URL to check
   * @param {string} pattern - Regex pattern
   * @returns {boolean|null} Cached result or null if not cached
   */
  getCachedPatternMatch(url, pattern) {
    if (!this._enablePattern) return null;
    
    const cacheKey = url + ':' + pattern;
    const cached = this.patternCache.get(cacheKey);
    
    if (cached !== undefined) {
      this.stats.patternHits++;
      if (this._debug) {
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
    if (!this._enablePattern) return;
    
    const cacheKey = url + ':' + pattern;
    this.patternCache.set(cacheKey, result);
  }
  
  /**
   * Get cached response content
   * @param {string} url - URL
   * @returns {string|null} Cached content or null
   */
  getCachedResponse(url) {
    if (!this._enableResponse) return null;
    
    // Note: Response cache doesn't have direct access to siteConfig
    // bypass_cache primarily affects request cache, not response cache
    // This is intentional - response cache is content-based, request cache is URL-based
    
    const cached = this.responseCache.get(url);
    if (cached) {
      this.stats.responseHits++;
      if (this._debug) {
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
    if (!this._enableResponse) return;
    
    // Skip response caching entirely for very high concurrency
    if (this._highConcurrency) {
      this.stats.responseCacheSkips++;
      return;
    }
    
    // Check memory before caching large content (use cached flag from periodic check)
    if (this._memoryPressure) {
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
    if (!this._enableWhois) return null;
    
    const cacheKey = recordType ? tool + ':' + domain + ':' + recordType : tool + ':' + domain;
    const cached = this.netToolsCache.get(cacheKey);
    
    if (cached) {
      this.stats.netToolsHits++;
      if (this._debug) {
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
    if (!this._enableWhois) return;
    
    const cacheKey = recordType ? tool + ':' + domain + ':' + recordType : tool + ':' + domain;
    this.netToolsCache.set(cacheKey, result);
  }
  
  /**
   * Cache similarity comparison result
   * @param {string} domain1 - First domain
   * @param {string} domain2 - Second domain
   * @param {number} similarity - Similarity score
   */
  cacheSimilarity(domain1, domain2, similarity) {
    // Consistent key without array allocation: alphabetically smaller domain first
    const key = domain1 < domain2 ? domain1 + '|' + domain2 : domain2 + '|' + domain1;
    this.similarityCache.set(key, similarity);
  }
  
  /**
   * Get cached similarity score
   * @param {string} domain1 - First domain
   * @param {string} domain2 - Second domain
   * @returns {number|null} Cached similarity or null
   */
  getCachedSimilarity(domain1, domain2) {
    const key = domain1 < domain2 ? domain1 + '|' + domain2 : domain2 + '|' + domain1;
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
    this._lastHeapUsed = memUsage.heapUsed;
    const maxHeap = this.options.maxHeapUsage;
    const heapUsedMB = Math.round(memUsage.heapUsed / 1048576);
    const maxHeapMB = Math.round(maxHeap / 1048576);
    const usagePercent = (memUsage.heapUsed / maxHeap) * 100;
    
    // Critical threshold - aggressive cleanup
    if (memUsage.heapUsed > maxHeap * this._criticalThreshold) {
      this._memoryPressure = true;
      this._performMemoryCleanup('critical', heapUsedMB, maxHeapMB);
      return true;
    }
    
    // Warning threshold - moderate cleanup
    if (memUsage.heapUsed > maxHeap * this._warningThreshold) {
      this._memoryPressure = true;
      this._performMemoryCleanup('warning', heapUsedMB, maxHeapMB);
      return true;
    }
    
    this._memoryPressure = false;
    
    // Info threshold - log only
    if (memUsage.heapUsed > maxHeap * this._infoThreshold) {
      this.stats.memoryWarnings++;
      if (this._debug) {
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
    
    if (this._debug) {
      console.log(formatLogMessage('debug', 
        `[SmartCache] Memory ${level}: ${heapUsedMB}MB/${maxHeapMB}MB, performing cleanup...`
      ));
    }
    
    if (level === 'critical' || this._highConcurrency) {
      // Aggressive cleanup - clear volatile caches
      this.responseCache.clear();
      this.patternCache.clear();
      this.similarityCache.clear();

      // NEW: Clear request cache during critical cleanup
      if (this._enableRequest) this.clearRequestCache();
      
      // For very high concurrency, also trim domain cache
      if (this.options.concurrency > 15) {
        const currentSize = this.domainCache.size;
        this.domainCache.clear();
        if (this._debug) {
          console.log(formatLogMessage('debug', `[SmartCache] Cleared ${currentSize} domain cache entries`));
        }
      }
    } else if (level === 'warning') {
      // Moderate cleanup - clear largest cache
      this.responseCache.clear();

      // NEW: Clear request cache during warning cleanup if it's large
      if (this._enableRequest && this.requestCache.size > this.options.requestCacheMaxSize * 0.8) {
        this.clearRequestCache();
      }
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
    const s = this.stats;
    const runtime = Date.now() - s.startTime;
    const hitRate = s.hits / (s.hits + s.misses) || 0;
    const patternHitRate = s.patternHits / (s.patternHits + s.patternMisses) || 0;
    const responseHitRate = s.responseHits / (s.responseHits + s.responseMisses) || 0;
    const netToolsHitRate = s.netToolsHits / (s.netToolsHits + s.netToolsMisses) || 0;
    const requestHitRate = s.requestCacheHits / (s.requestCacheHits + s.requestCacheMisses) || 0;

    // Use cached heap value from periodic _checkMemoryPressure (avoids syscall)
    const heapUsed = this._lastHeapUsed;
    const maxHeap = this.options.maxHeapUsage;
    
    return {
      hits: s.hits,
      misses: s.misses,
      patternHits: s.patternHits,
      patternMisses: s.patternMisses,
      responseHits: s.responseHits,
      responseMisses: s.responseMisses,
      netToolsHits: s.netToolsHits,
      netToolsMisses: s.netToolsMisses,
      similarityHits: s.similarityHits,
      similarityMisses: s.similarityMisses,
      regexCompilations: s.regexCompilations,
      regexCacheHits: s.regexCacheHits,
      persistenceLoads: s.persistenceLoads,
      persistenceSaves: s.persistenceSaves,
      memoryPressureEvents: s.memoryPressureEvents,
      memoryWarnings: s.memoryWarnings,
      responseCacheSkips: s.responseCacheSkips,
      requestCacheHits: s.requestCacheHits,
      requestCacheMisses: s.requestCacheMisses,
      requestCacheSkips: s.requestCacheSkips,
      requestCacheClears: s.requestCacheClears,
      runtime: Math.round(runtime / 1000),
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
      requestHitRate: (this._enableRequest && this.requestCache) ?
        (requestHitRate * 100).toFixed(2) + '%' : '0% (disabled)',
      requestCacheSize: (this._enableRequest && this.requestCache) ? this.requestCache.size : 0,
      requestCacheMemoryMB: (this._enableRequest && this.requestCache) ?
        Math.round((this.requestCache.calculatedSize || 0) / 1048576) : 0,
      totalCacheEntries: this.domainCache.size + this.patternCache.size +
        this.responseCache.size + this.netToolsCache.size +
        this.similarityCache.size + this.regexCache.size + ((this._enableRequest && this.requestCache) ? this.requestCache.size : 0),
      memoryUsageMB: Math.round(heapUsed / 1048576),
      memoryMaxMB: Math.round(maxHeap / 1048576),
      memoryUsagePercent: ((heapUsed / maxHeap) * 100).toFixed(1) + '%',
      responseCacheMemoryMB: Math.round((this.responseCache.calculatedSize || 0) / 1048576)
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
    if (this._enableRequest && this.requestCache) {
      this.requestCache.clear();
    }
    this._initializeStats();
    
    if (this._debug) {
      console.log(formatLogMessage('debug', '[SmartCache] All caches cleared'));
    }
  }
  
   /**
   * Helper method to log memory-related cache skips
   * @private
   */
  _logMemorySkip(operation) {
    if (this._debug) {
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
    
    let raw;
    try {
      raw = fs.readFileSync(cacheFile, 'utf8');
    } catch (readErr) {
      // File doesn't exist or unreadable -- nothing to load
      return;
    }
    
    try {
      const data = JSON.parse(raw);
      const now = Date.now();
      
      // Validate cache age
      if (data.timestamp && now - data.timestamp > 24 * 60 * 60 * 1000) {
        if (this._debug) {
          console.log(formatLogMessage('debug', 
            '[SmartCache] Persistent cache too old, ignoring'
          ));
        }
        return;
      }
      
      // Load domain cache
      if (data.domainCache && Array.isArray(data.domainCache)) {
        const entries = data.domainCache;
        for (let i = 0; i < entries.length; i++) {
          if (now - entries[i][1].timestamp < this.options.ttl) {
            this.domainCache.set(entries[i][0], entries[i][1]);
          }
        }
      }
      
      // Load nettools cache
      if (data.netToolsCache && Array.isArray(data.netToolsCache)) {
        const entries = data.netToolsCache;
        for (let i = 0; i < entries.length; i++) {
          this.netToolsCache.set(entries[i][0], entries[i][1]);
        }
      }
      
      this.stats.persistenceLoads++;
      
      if (this._debug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Loaded persistent cache: ${this.domainCache.size} domains, ${this.netToolsCache.size} nettools`
        ));
      }
    } catch (err) {
      if (this._debug) {
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
      if (this._debug) {
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
    const tmpFile = cacheFile + '.tmp';
    
    try {
      // recursive:true is a no-op if dir exists -- no need for existsSync check
      fs.mkdirSync(cacheDir, { recursive: true });
      
      const data = {
        timestamp: now,
        domainCache: Array.from(this.domainCache.entries()),
        netToolsCache: Array.from(this.netToolsCache.entries()),
        stats: this.stats
      };
      
      // Async write to temp file, then atomic rename (no pretty-print -- saves ~30% serialization time)
      const jsonStr = JSON.stringify(data);
      fs.writeFile(tmpFile, jsonStr, (writeErr) => {
        if (writeErr) {
          if (this._debug) {
            console.log(formatLogMessage('debug', 
              `[SmartCache] Failed to write cache temp file: ${writeErr.message}`
            ));
          }
          this.saveInProgress = false;
          return;
        }
        
        fs.rename(tmpFile, cacheFile, (renameErr) => {
          if (renameErr) {
            if (this._debug) {
              console.log(formatLogMessage('debug', 
                `[SmartCache] Failed to rename cache file: ${renameErr.message}`
              ));
            }
          } else {
            this.stats.persistenceSaves++;
            if (this._debug) {
              console.log(formatLogMessage('debug', 
                `[SmartCache] Saved cache to disk: ${cacheFile}`
              ));
            }
          }
          
          this.saveInProgress = false;
          
          // Process any pending saves
          if (this.pendingSave && !this.saveTimeout) {
            this.pendingSave = false;
            setTimeout(() => this.savePersistentCache(), 1000);
          }
        });
      });
      return; // Async -- don't fall through to finally
      
    } catch (err) {
      if (this._debug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Failed to save cache: ${err.message}`
        ));
      }
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
  static clearPersistentCache(options = EMPTY) {
    const { silent = false, forceDebug = false, cachePath = '.cache' } = options;
    
    let clearedItems = 0;
    let totalSize = 0;
    const clearedFiles = [];
    const errors = [];
    
    if (!silent) {
      console.log(`\n???  Clearing cache...`);
    }
    
    // Try the directory first -- rmSync recursive handles all files inside
    const cacheFile = path.join(cachePath, 'smart-cache.json');
    let dirHandled = false;
    
    try {
      const stats = fs.statSync(cachePath);
      if (stats.isDirectory()) {
        // Sum file sizes (readdirSync proves they exist -- no existsSync needed)
        try {
          const files = fs.readdirSync(cachePath);
          for (const file of files) {
            try {
              totalSize += fs.statSync(path.join(cachePath, file)).size;
            } catch (e) { /* file disappeared between readdir and stat */ }
          }
        } catch (e) { /* empty dir or read error */ }
        fs.rmSync(cachePath, { recursive: true, force: true });
        dirHandled = true;
        clearedItems++;
        clearedFiles.push({ type: 'directory', path: cachePath, size: totalSize });
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Cleared cache directory: ${cachePath}`));
        }
      } else {
        totalSize += stats.size;
        fs.unlinkSync(cachePath);
        dirHandled = true;
        clearedItems++;
        clearedFiles.push({ type: 'file', path: cachePath, size: stats.size });
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Cleared cache file: ${cachePath}`));
        }
      }
    } catch (clearErr) {
      if (clearErr.code !== 'ENOENT') {
        errors.push({ path: cachePath, error: clearErr.message });
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Failed to clear ${cachePath}: ${clearErr.message}`));
        }
      }
    }
    
    // Fallback: if directory was missing or failed, try the json file directly (orphaned file safety net)
    if (!dirHandled) {
      try {
        const fileStats = fs.statSync(cacheFile);
        totalSize += fileStats.size;
        fs.unlinkSync(cacheFile);
        clearedItems++;
        clearedFiles.push({ type: 'file', path: cacheFile, size: fileStats.size });
      } catch (e) {
        // ENOENT = nothing to clean, any other error is ignorable
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
    enableRequestCache: config.cache_requests === true, // NEW: Enable request caching
    requestCacheMaxSize: config.cache_requests_max_size || 1000,
    requestCacheMaxMemory: (config.cache_requests_max_memory_mb || 100) * 1024 * 1024,
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