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
    // V8 Optimization: Initialize all properties in constructor for stable hidden class
    this.cache = new Set();

    // V8 Optimization: Use consistent object shape (no dynamic property addition)
    this.stats = this._freshStats();

    // V8 Optimization: Store options directly instead of nested object for faster property access
    this.enableLogging = options.enableLogging || false;
    this.logPrefix = options.logPrefix || '[domain-cache]';
    this.maxCacheSize = options.maxCacheSize || 10000; // Prevent memory leaks

    // V8 Optimization: Pre-calculate 90% target to avoid repeated Math.floor
    this.targetCacheSize = Math.floor(this.maxCacheSize * 0.9);
  }

  /**
   * Canonical stats shape. Centralized so the constructor and clear() can't
   * drift if a new counter is added later.
   * @private
   */
  _freshStats() {
    return {
      totalDetected: 0,
      totalSkipped: 0,
      cacheHits: 0,
      cacheMisses: 0
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
      
      if (this.enableLogging) {
        console.log(formatLogMessage('debug', `${this.logPrefix} Cache HIT: ${domain} (skipped)`));
      }
    } else {
      this.stats.cacheMisses++;
      
      if (this.enableLogging) {
        console.log(formatLogMessage('debug', `${this.logPrefix} Cache MISS: ${domain} (processing)`));
      }
    }
    
    return isDetected;
  }

  /**
   * Mark a domain as detected for future reference.
   * @param {string} domain - Domain to mark as detected
   * @returns {boolean} True if the domain was newly added; false if it was
   *   already present or the input was invalid (not a non-empty string)
   */
  markDomainAsDetected(domain) {
    if (!domain || typeof domain !== 'string') {
      return false;
    }

    const wasNew = !this.cache.has(domain);
    this.cache.add(domain);
    
    if (wasNew) {
      this.stats.totalDetected++;
      
      if (this.enableLogging) {
        console.log(formatLogMessage('debug', `${this.logPrefix} Marked as detected: ${domain} (cache size: ${this.cache.size})`));
      }
    }
    
    // Check size after the add so an overflow only fires eviction once per
    // overflowing call (using targetCacheSize precomputed in the constructor).
    if (this.cache.size > this.maxCacheSize) {
      const toRemove = this.cache.size - this.targetCacheSize;
      if (toRemove > 0) {
        this.clearOldestEntries(toRemove);
      }
    }

    return wasNew;
  }

  /**
   * Clear oldest entries from cache (FIFO eviction). Set iteration order is
   * guaranteed insertion order per ES2015, so this genuinely evicts oldest-
   * first on every supported Node version.
   * @param {number} count - Number of entries to remove
   */
  clearOldestEntries(count) {
    if (count <= 0) return;

    let removed = 0;
    for (const domain of this.cache) {
      if (removed >= count) break;
      this.cache.delete(domain);
      removed++;
    }

    if (this.enableLogging) {
      console.log(formatLogMessage('debug', `${this.logPrefix} Cleared ${removed} old entries, cache size now: ${this.cache.size}`));
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
    this.stats = this._freshStats();

    if (this.enableLogging) {
      console.log(formatLogMessage('debug', `${this.logPrefix} Cache cleared (${previousSize} entries removed)`));
    }
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
 * Get or create the global domain cache instance.
 *
 * NOTE: `options` is honored ONLY on the first call (the call that actually
 * constructs the singleton). Subsequent calls return the existing instance
 * regardless of what's passed; options are fixed at first construction.
 *
 * Under debug logging, a warning fires if a later caller passes options
 * that don't match the live instance — silent drift is a recurring source
 * of "why isn't my maxCacheSize taking effect?" confusion.
 *
 * @param {object} options - Cache options (first-call-only)
 * @returns {DomainCache} Global cache instance
 */
function getGlobalDomainCache(options = {}) {
  if (!globalDomainCache) {
    globalDomainCache = new DomainCache(options);
    return globalDomainCache;
  }
  // Singleton already exists — warn if the caller is trying to reconfigure it.
  if (globalDomainCache.enableLogging) {
    const drifted =
      (options.maxCacheSize !== undefined && options.maxCacheSize !== globalDomainCache.maxCacheSize) ||
      (options.enableLogging !== undefined && options.enableLogging !== globalDomainCache.enableLogging) ||
      (options.logPrefix !== undefined && options.logPrefix !== globalDomainCache.logPrefix);
    if (drifted) {
      console.log(formatLogMessage('debug', `${globalDomainCache.logPrefix} getGlobalDomainCache called with options that differ from the live singleton; ignored (options are fixed at first construction)`));
    }
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
 * Legacy wrapper for backward compatibility.
 *
 * getDetectedDomainsCount is the only one kept — nwss.js reads it for the
 * end-of-scan "unique domains cached" stat. getTotalDomainsSkipped was
 * removed: its value was always 0 because the global cache's skip-check
 * (isDomainAlreadyDetected) is never called — cross-URL dedup is handled by
 * nettools' processed-domain sets / smart-cache / the per-URL set — so the
 * stat was misleading. The isDomainAlreadyDetected / markDomainAsDetected /
 * checkAndMark wrappers were likewise removed; nwss.js uses createGlobalHelpers().
 */

/**
 * Get detected domains cache size (legacy wrapper)
 * @returns {number} Size of the detected domains cache
 */
function getDetectedDomainsCount() {
  const cache = getGlobalDomainCache();
  return cache.cache.size;
}

module.exports = {
  // Global cache helpers — createGlobalHelpers feeds nwss.js's per-domain
  // marking; getDetectedDomainsCount feeds the end-of-scan "unique domains
  // cached" stat. (DomainCache / getGlobalDomainCache stay internal — no
  // external consumer; construct via createGlobalHelpers.)
  createGlobalHelpers,
  getDetectedDomainsCount
};
