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
   * Combined check-and-mark in one pass. Functionally equivalent to
   * isDomainAlreadyDetected() followed by markDomainAsDetected(), but with
   * one Set.has() call instead of two. (JS is single-threaded so all three
   * variants are individually atomic; this one is just cheaper.)
   * @param {string} domain - Domain to check and potentially mark
   * @returns {boolean} True if domain was ALREADY detected (should skip), false if NEW (should process)
   */
  checkAndMark(domain) {
    if (!domain || typeof domain !== 'string') {
      return false;
    }

    const wasAlreadyDetected = this.cache.has(domain);
    
    if (wasAlreadyDetected) {
      // Domain already exists - update skip stats and return true (should skip)
      this.stats.totalSkipped++;
      this.stats.cacheHits++;
      
      if (this.enableLogging) {
        console.log(formatLogMessage('debug', `${this.logPrefix} Cache HIT: ${domain} (skipped)`));
      }
      return true; // Already detected, should skip
    }
    
    // Domain is NEW - mark it as detected
    this.stats.cacheMisses++;
    
    this.cache.add(domain);
    this.stats.totalDetected++;
    
    if (this.enableLogging) {
      console.log(formatLogMessage('debug', `${this.logPrefix} Cache MISS: ${domain} (processing and marked, cache size: ${this.cache.size})`));
    }
    
    // Check size after the add so an overflow only fires eviction once per
    // overflowing call (using targetCacheSize precomputed in the constructor).
    if (this.cache.size > this.maxCacheSize) {
      const toRemove = this.cache.size - this.targetCacheSize;
      if (toRemove > 0) {
        this.clearOldestEntries(toRemove);
      }
    }

    return false; // New domain, should process
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
    
    if (wasRemoved && this.enableLogging) {
      console.log(formatLogMessage('debug', `${this.logPrefix} Removed from cache: ${domain}`));
    }
    
    return wasRemoved;
  }

  /**
   * Add multiple domains to cache at once. Uses a single .size delta to
   * count actually-new entries (skipping per-domain .has() calls), and
   * runs the size-overflow eviction check once after the batch instead of
   * per-domain. For a batch of N domains this is N .has() calls saved and
   * up to N redundant cap checks collapsed to one.
   * @param {Array<string>} domains - Array of domains to add
   * @returns {number} Number of domains actually added (excludes duplicates)
   */
  markMultipleDomainsAsDetected(domains) {
    if (!Array.isArray(domains) || domains.length === 0) {
      return 0;
    }

    const startSize = this.cache.size;
    for (let i = 0; i < domains.length; i++) {
      const d = domains[i];
      if (d && typeof d === 'string') {
        this.cache.add(d);
      }
    }
    const addedCount = this.cache.size - startSize;
    this.stats.totalDetected += addedCount;

    if (this.enableLogging && addedCount > 0) {
      console.log(formatLogMessage('debug', `${this.logPrefix} Batch added ${addedCount} new domains (cache size: ${this.cache.size})`));
    }

    // One eviction sweep at the end, mirroring the single-add overflow check.
    if (this.cache.size > this.maxCacheSize) {
      const toRemove = this.cache.size - this.targetCacheSize;
      if (toRemove > 0) {
        this.clearOldestEntries(toRemove);
      }
    }

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
      checkAndMark: this.checkAndMark.bind(this),
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
 * regardless of what's passed. If you need different settings, call
 * resetGlobalCache() first or use `new DomainCache(options)` directly.
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
      console.log(formatLogMessage('debug', `${globalDomainCache.logPrefix} getGlobalDomainCache called with options that differ from the live singleton; ignored (call resetGlobalCache() first to apply new options)`));
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
 * Combined check-and-mark in one pass — one Set.has() call instead of the
 * two you'd pay for isDomainAlreadyDetected() + markDomainAsDetected().
 * @param {string} domain - Domain to check and mark
 * @returns {boolean} True if already detected (skip), false if new (process)
 */
function checkAndMark(domain) {
  const cache = getGlobalDomainCache();
  return cache.checkAndMark(domain);
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
  checkAndMark,
  getTotalDomainsSkipped,
  getDetectedDomainsCount
};
