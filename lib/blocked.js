// === Request Blocking Module ===
// This module handles URL blocking functionality for the network scanner script.
// It supports both global and site-specific blocking patterns using regex.

const fs = require('fs');

/**
 * BlockedManager class handles loading and matching of blocked URL patterns.
 * Supports both global patterns (applied to all sites) and site-specific patterns.
 */
class BlockedManager {
  constructor() {
    this.globalBlockedRegexes = [];
    this.debugMode = false;
  }

  /**
   * Initialize the blocked manager with global patterns from config
   * @param {Array} globalBlocked - Array of global blocked regex patterns from config.json
   * @param {boolean} debugMode - Enable debug logging
   */
  initialize(globalBlocked = [], debugMode = false) {
    this.debugMode = debugMode;
    
    try {
      this.globalBlockedRegexes = Array.isArray(globalBlocked) 
        ? globalBlocked.map(pattern => new RegExp(pattern))
        : [];
      
      if (this.debugMode && this.globalBlockedRegexes.length > 0) {
        console.log(`[debug][blocked] Loaded ${this.globalBlockedRegexes.length} global blocked patterns`);
      }
    } catch (error) {
      console.warn(`[warn][blocked] Failed to initialize global blocked patterns: ${error.message}`);
      this.globalBlockedRegexes = [];
    }
  }

  /**
   * Compile site-specific blocked patterns into regex objects
   * @param {Array|undefined} siteBlockedPatterns - Site-specific blocked patterns from site config
   * @returns {Array} Array of compiled RegExp objects
   */
  compileSitePatterns(siteBlockedPatterns = []) {
    if (!Array.isArray(siteBlockedPatterns)) {
      return [];
    }

    try {
      const compiled = siteBlockedPatterns.map(pattern => new RegExp(pattern));
      
      if (this.debugMode && compiled.length > 0) {
        console.log(`[debug][blocked] Compiled ${compiled.length} site-specific blocked patterns`);
      }
      
      return compiled;
    } catch (error) {
      console.warn(`[warn][blocked] Failed to compile site blocked patterns: ${error.message}`);
      return [];
    }
  }

  /**
   * Check if a URL should be blocked based on global and site-specific patterns
   * @param {string} url - The URL to check
   * @param {Array} siteBlockedRegexes - Compiled site-specific regex patterns
   * @returns {boolean} True if URL should be blocked
   */
  shouldBlock(url, siteBlockedRegexes = []) {
    try {
      // Check global blocked patterns first
      for (const regex of this.globalBlockedRegexes) {
        if (regex.test(url)) {
          if (this.debugMode) {
            console.log(`[debug][blocked] URL blocked by global pattern: ${url}`);
          }
          return true;
        }
      }

      // Check site-specific blocked patterns
      for (const regex of siteBlockedRegexes) {
        if (regex.test(url)) {
          if (this.debugMode) {
            console.log(`[debug][blocked] URL blocked by site pattern: ${url}`);
          }
          return true;
        }
      }

      return false;
    } catch (error) {
      console.warn(`[warn][blocked] Error checking blocked status for ${url}: ${error.message}`);
      return false; // Don't block on error
    }
  }

  /**
   * Get statistics about loaded blocking patterns
   * @returns {Object} Statistics object
   */
  getStats() {
    return {
      globalPatterns: this.globalBlockedRegexes.length,
      hasGlobalPatterns: this.globalBlockedRegexes.length > 0
    };
  }

  /**
   * Load blocked patterns from an external file
   * @param {string} filePath - Path to the blocked patterns file
   * @returns {Array} Array of patterns loaded from file
   */
  static loadFromFile(filePath) {
    try {
      if (!fs.existsSync(filePath)) {
        console.warn(`[warn][blocked] Blocked patterns file not found: ${filePath}`);
        return [];
      }

      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#')); // Remove empty lines and comments

      console.log(`[info][blocked] Loaded ${lines.length} blocked patterns from ${filePath}`);
      return lines;
    } catch (error) {
      console.error(`[error][blocked] Failed to load blocked patterns from ${filePath}: ${error.message}`);
      return [];
    }
  }

  /**
   * Save current global patterns to a file
   * @param {string} filePath - Path where to save the patterns
   */
  saveGlobalPatternsToFile(filePath) {
    try {
      const patterns = this.globalBlockedRegexes.map(regex => regex.source);
      const content = [
        '# Global blocked patterns',
        '# Each line should contain a regex pattern',
        '# Lines starting with # are comments',
        '',
        ...patterns
      ].join('\n');

      fs.writeFileSync(filePath, content);
      console.log(`[info][blocked] Saved ${patterns.length} global patterns to ${filePath}`);
    } catch (error) {
      console.error(`[error][blocked] Failed to save patterns to ${filePath}: ${error.message}`);
    }
  }
}

// Export the class and create a default instance
const blockedManager = new BlockedManager();

module.exports = {
  BlockedManager,
  blockedManager
};
