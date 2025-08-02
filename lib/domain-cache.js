/**
 * Domain Cache Module - Tracks detected domains to prevent duplicate processing
 * Provides performance optimization by skipping already detected domains
 */

const { formatLogMessage } = require('./colorize');

/**
 * Domain detection cache class for tracking processed domains
 */
class DomainCache {
  constructor(options = {}) {
    this.cache = new Set();
    this.stats = {
      totalDetected: 0,
      totalSkipped: 0,
      cacheHits: 0,
      cacheMisses: 0
    };
    this.options = {
      enableLogging: options.enableLogging || false,
      logPrefix: options.logPrefix || '[domain-cache]',
      maxCacheSize: options.maxCacheSize || 10000 // Prevent memory leaks
    };
  }

  /**
   * Check if a domain was already detected in a previous scan
   * @param {string} domain - Domain to check
   * @returns {boolean} True if domain was already detected
   */
  isDomainAlreadyDetected(domain) {
    if (!domain || typeof domain !== 'string') {
      return false;
    }

    const isDetected = this.cache.has(domain);
    
    if (isDetected) {
      this.stats.totalSkipped++;
      this.stats.cacheHits++;
      
      if (this.options.enableLogging) {
        console.log(formatLogMessage('debug', `${this.options.logPrefix} Cache HIT: ${domain} (skipped)`));
      }
    } else {
      this.stats.cacheMisses++;
      
      if (this.options.enableLogging) {
        console.log(formatLogMessage('debug', `${this.options.logPrefix} Cache MISS: ${domain} (processing)`));
      }
    }
    
    return isDetected;
  }

  /**
   * Mark a domain as detected for future reference
   * @param {string} domain - Domain to mark as detected
   */
  markDomainAsDetected(domain) {
    if (!domain || typeof domain !== 'string') {
      return false;
    }

    // Prevent cache from growing too large
    if (this.cache.size >= this.options.maxCacheSize) {
      this.clearOldestEntries(Math.floor(this.options.maxCacheSize * 0.1)); // Remove 10% of entries
    }

    const wasNew = !this.cache.has(domain);
    this.cache.add(domain);
    
    if (wasNew) {
      this.stats.totalDetected++;
      
      if (this.options.enableLogging) {
        console.log(formatLogMessage('debug', `${this.options.logPrefix} Marked as detected: ${domain} (cache size: ${this.cache.size})`));
      }
    }
    
    return wasNew;
  }

  /**
   * Clear oldest entries from cache (basic LRU simulation)
   * Note: Set doesn't maintain insertion order in all Node.js versions,
   * so this is a simple implementation that clears a portion of the cache
   * @param {number} count - Number of entries to remove
   */
  clearOldestEntries(count) {
    if (count <= 0) return;
    
    const entries = Array.from(this.cache);
    const toRemove = entries.slice(0, count);
    
    toRemove.forEach(domain => this.cache.delete(domain));
    
    if (this.options.enableLogging) {
      console.log(formatLogMessage('debug', `${this.options.logPrefix} Cleared ${toRemove.length} old entries, cache size now: ${this.cache.size}`));
    }
  }

  /**
   * Get cache statistics
   * @returns {object} Cache statistics
   */
  getStats() {
    return {
      ...this.stats,
      cacheSize: this.cache.size,
      hitRate: this.stats.cacheHits > 0 ? 
        (this.stats.cacheHits / (this.stats.cacheHits + this.stats.cacheMisses) * 100).toFixed(2) + '%' : 
        '0%'
    };
  }

  /**
   * Clear all cached domains
   */
  clear() {
    const previousSize = this.cache.size;
    this.cache.clear();
    this.stats = {
      totalDetected: 0,
      totalSkipped: 0,
      cacheHits: 0,
      cacheMisses: 0
    };
    
    if (this.options.enableLogging) {
      console.log(formatLogMessage('debug', `${this.options.logPrefix} Cache cleared (${previousSize} entries removed)`));
    }
  }

  /**
   * Get all cached domains (for debugging)
   * @returns {Array<string>} Array of cached domains
   */
  getAllCachedDomains() {
    return Array.from(this.cache);
  }

  /**
   * Check if cache contains a specific domain (without updating stats)
   * @param {string} domain - Domain to check
   * @returns {boolean} True if domain exists in cache
   */
  has(domain) {
    return this.cache.has(domain);
  }

  /**
   * Remove a specific domain from cache
   * @param {string} domain - Domain to remove
   * @returns {boolean} True if domain was removed, false if it wasn't in cache
   */
  removeDomain(domain) {
    const wasRemoved = this.cache.delete(domain);
    
    if (wasRemoved && this.options.enableLogging) {
      console.log(formatLogMessage('debug', `${this.options.logPrefix} Removed from cache: ${domain}`));
    }
    
    return wasRemoved;
  }

  /**
   * Add multiple domains to cache at once
   * @param {Array<string>} domains - Array of domains to add
   * @returns {number} Number of domains actually added (excludes duplicates)
   */
  markMultipleDomainsAsDetected(domains) {
    if (!Array.isArray(domains)) {
      return 0;
    }

    let addedCount = 0;
    domains.forEach(domain => {
      if (this.markDomainAsDetected(domain)) {
        addedCount++;
      }
    });

    return addedCount;
  }

  /**
   * Create bound helper functions for easy integration with existing code
   * @returns {object} Object with bound helper functions
   */
  createHelpers() {
    return {
      isDomainAlreadyDetected: this.isDomainAlreadyDetected.bind(this),
      markDomainAsDetected: this.markDomainAsDetected.bind(this),
      getSkippedCount: () => this.stats.totalSkipped,
      getCacheSize: () => this.cache.size,
      getStats: this.getStats.bind(this)
    };
  }
}

/**
 * Create a global domain cache instance (singleton pattern)
 */
let globalDomainCache = null;

/**
 * Get or create the global domain cache instance
 * @param {object} options - Cache options
 * @returns {DomainCache} Global cache instance
 */
function getGlobalDomainCache(options = {}) {
  if (!globalDomainCache) {
    globalDomainCache = new DomainCache(options);
  }
  return globalDomainCache;
}

/**
 * Create helper functions that use the global cache
 * @param {object} options - Cache options (only used if global cache doesn't exist)
 * @returns {object} Helper functions bound to global cache
 */
function createGlobalHelpers(options = {}) {
  const cache = getGlobalDomainCache(options);
  return cache.createHelpers();
}

/**
 * Reset the global cache (useful for testing or manual resets)
 */
function resetGlobalCache() {
  if (globalDomainCache) {
    globalDomainCache.clear();
  }
  globalDomainCache = null;
}

/**
 * Legacy wrapper functions for backward compatibility
 * These match the original function signatures from nwss.js
 */

/**
 * Check if a domain was already detected (legacy wrapper)
 * @param {string} domain - Domain to check
 * @returns {boolean} True if domain was already detected
 */
function isDomainAlreadyDetected(domain) {
  const cache = getGlobalDomainCache();
  return cache.isDomainAlreadyDetected(domain);
}

/**
 * Mark a domain as detected (legacy wrapper)
 * @param {string} domain - Domain to mark as detected
 */
function markDomainAsDetected(domain) {
  const cache = getGlobalDomainCache();
  cache.markDomainAsDetected(domain);
}

/**
 * Get total domains skipped (legacy wrapper)
 * @returns {number} Number of domains skipped
 */
function getTotalDomainsSkipped() {
  const cache = getGlobalDomainCache();
  return cache.stats.totalSkipped;
}

/**
 * Get detected domains cache size (legacy wrapper)
 * @returns {number} Size of the detected domains cache
 */
function getDetectedDomainsCount() {
  const cache = getGlobalDomainCache();
  return cache.cache.size;
}

module.exports = {
  // Main class
  DomainCache,
  
  // Global cache functions
  getGlobalDomainCache,
  createGlobalHelpers,
  resetGlobalCache,
  
  // Legacy wrapper functions for backward compatibility
  isDomainAlreadyDetected,
  markDomainAsDetected,
  getTotalDomainsSkipped,
  getDetectedDomainsCount
};
