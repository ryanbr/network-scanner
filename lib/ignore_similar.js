const { formatLogMessage } = require('./colorize');

/**
 * IGNORE_SIMILAR MODULE
 * 
 * This module implements domain similarity detection to prevent collecting
 * domains that are too similar to ones already found. It uses Levenshtein
 * distance algorithm to calculate similarity between domain base names.
 * 
 * Main use case: When scanning for ad/tracker domains, prevent collecting
 * both "googleads.com" and "googlevds.com" since they're 89% similar.
 * 
 * Performance consideration: This runs on every potential domain match,
 * so the algorithms need to be efficient for high-volume scanning.
 */

/**
 * Extracts the base domain name without TLD for similarity comparison
 * 
 * Examples:
 * - "ads.google.com" -> "google" 
 * - "tracker.facebook.co.uk" -> "facebook"
 * - "cdn.example.org" -> "example"
 * 
 * Why we do this: We want to compare the actual brand/company name part
 * of domains, not be fooled by different TLDs or subdomains.
 * 
 * @param {string} domain - The domain to process
 * @returns {string} The base domain name
 */
function getBaseDomainName(domain) {
  if (!domain || typeof domain !== 'string') {
    return '';
  }
  
  // Remove protocol if present (handles cases where full URLs are passed)
  domain = domain.replace(/^https?:\/\//, '');
  
  // Remove www prefix (standardize domain format)
  domain = domain.replace(/^www\./, '');
  
  // Split by dots and get the part before the last dot (TLD)
  const parts = domain.split('.');
  if (parts.length < 2) {
    return domain; // Single part, return as-is (localhost, IP addresses, etc.)
  }
  
  /**
   * MULTI-PART TLD HANDLING
   * 
   * Many countries use multi-part TLDs like "co.uk", "com.au", etc.
   * We need to account for these when extracting the base domain name.
   * 
   * Without this logic:
   * - "example.co.uk" would incorrectly return "co" instead of "example"
   * - "google.com.au" would return "com" instead of "google"
   * 
   * This extensive list covers most common multi-part TLDs worldwide.
   */
  const multiPartTLDs = [
    // Common Anglo countries
    'co.uk', 'co.nz', 'com.au', 'co.za', 'co.in', 'co.jp', 'co.kr',
    
    // Latin America
    'com.br', 'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve',
    
    // Asia-Pacific  
    'co.th', 'co.id', 'co.il', 'co.ke', 'co.tz', 'co.zw', 'co.bw',
    'com.sg', 'com.my', 'com.hk', 'com.tw', 'com.ph', 'com.vn',
    
    // Central America & Africa
    'co.cr', 'co.ug', 'co.zm', 'co.ao', 'co.mz', 'co.ls',
    
    // Europe extensions
    'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'gov.uk', 'ac.uk', 'sch.uk',
    'com.de', 'org.de', 'com.fr', 'org.fr', 'com.es', 'org.es',
    'com.it', 'org.it', 'com.pl', 'org.pl', 'com.nl', 'org.nl',
    'com.ru', 'org.ru', 'com.ua', 'org.ua', 'com.tr', 'org.tr',
    
    // Asia-Pacific extensions detailed
    'or.jp', 'ne.jp', 'ac.jp', 'ed.jp', 'go.jp',
    'or.kr', 'ne.kr', 'com.cn', 'org.cn', 'net.cn', 'edu.cn', 'gov.cn',
    'org.in', 'net.in', 'org.au', 'net.au', 'edu.au', 'gov.au',
    'org.nz', 'net.nz', 'org.il', 'net.il', 'org.za', 'net.za',
    
    // Americas extensions detailed
    'org.br', 'net.br', 'edu.br', 'gov.br', 'org.ar', 'org.mx',
    'org.co', 'org.pe', 'com.cl', 'org.cl', 'com.uy', 'org.uy',
    'org.ve', 'com.do', 'org.do', 'com.pr', 'org.pr',
    
    // Central America & Caribbean
    'com.gt', 'org.gt', 'com.pa', 'org.pa', 'com.sv', 'org.sv',
    'com.ni', 'org.ni', 'com.hn', 'org.hn', 'org.cr',
    
    // Middle East & Africa extensions
    'com.eg', 'org.eg', 'or.ke'
  ];
  
  // Check if domain ends with a multi-part TLD
  const lastTwoParts = parts.slice(-2).join('.');      // e.g., "co.uk"
  const lastThreeParts = parts.length >= 3 ? parts.slice(-3).join('.') : ''; // e.g., "com.au.com"
  
  // Handle 2-part TLDs (most common case)
  // Example: "google.co.uk" -> parts = ["google", "co", "uk"] -> return "google"
  if (multiPartTLDs.includes(lastTwoParts)) {
    return parts.length >= 3 ? parts[parts.length - 3] : parts[0];
  }
  
  // Handle rare 3-part TLDs (future-proofing)
  // This is mostly theoretical but good to have for completeness
  if (parts.length >= 4 && lastThreeParts && 
      ['com.au.com', 'co.uk.com'].includes(lastThreeParts)) {
    return parts[parts.length - 4];
  }
  
  // For standard TLDs, take the second-to-last part
  // Example: "google.com" -> parts = ["google", "com"] -> return "google"
  return parts[parts.length - 2];
}

/**
 * Calculates similarity between two domain base names using Levenshtein distance
 * 
 * The Levenshtein distance is the minimum number of single-character edits 
 * (insertions, deletions, substitutions) needed to transform one string into another.
 * 
 * We convert this to a percentage similarity for easier threshold comparison.
 * 
 * Examples:
 * - "google" vs "googl" = 83% similar (1 deletion needed)
 * - "facebook" vs "facebo0k" = 87% similar (1 substitution needed)  
 * - "amazon" vs "amaz0n" = 83% similar (1 substitution needed)
 * 
 * Why this matters: Malicious domains often use typosquatting techniques
 * like character substitution, insertion, or deletion to appear legitimate.
 * 
 * @param {string} domain1 - First domain base name
 * @param {string} domain2 - Second domain base name
 * @returns {number} Similarity percentage (0-100)
 */
function calculateSimilarity(domain1, domain2) {
  // Exact match = 100% similar (optimization for common case)
  if (domain1 === domain2) return 100;
  
  // Empty strings have no similarity
  if (!domain1 || !domain2) return 0;
  
  // Identify longer and shorter strings for algorithm efficiency
  const longer = domain1.length > domain2.length ? domain1 : domain2;
  const shorter = domain1.length > domain2.length ? domain2 : domain1;
  
  // Edge case: empty longer string means both are empty (100% similar)
  if (longer.length === 0) return 100;
  
  // Calculate edit distance using dynamic programming algorithm
  const distance = levenshteinDistance(longer, shorter);
  
  // Convert to percentage: (max_length - edits_needed) / max_length * 100
  // Higher percentage = more similar
  return Math.round(((longer.length - distance) / longer.length) * 100);
}

/**
 * Calculates Levenshtein distance between two strings using dynamic programming
 * 
 * This is the core algorithm that powers our similarity detection.
 * Time complexity: O(m*n) where m and n are string lengths
 * Space complexity: O(m*n) for the matrix
 * 
 * The algorithm builds a matrix where each cell [i,j] represents the minimum
 * edit distance between the first i characters of str1 and first j characters of str2.
 * 
 * Dynamic programming recurrence relation:
 * - If characters match: matrix[i][j] = matrix[i-1][j-1] (no edit needed)
 * - If different: matrix[i][j] = 1 + min(substitution, insertion, deletion)
 * 
 * @param {string} str1 - First string
 * @param {string} str2 - Second string  
 * @returns {number} Edit distance (number of edits needed to transform str1 to str2)
 */
function levenshteinDistance(str1, str2) {
  // Initialize matrix with base cases
  const matrix = [];
  
  // Base case: transforming empty string to str2 requires str2.length insertions
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  
  // Base case: transforming str1 to empty string requires str1.length deletions
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  
  // Fill matrix using dynamic programming
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      // If characters match, no additional cost
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        // Take minimum cost operation:
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution: replace char in str1
          matrix[i][j - 1] + 1,     // insertion: add char to str1  
          matrix[i - 1][j] + 1      // deletion: remove char from str1
        );
      }
    }
  }
  
  // Bottom-right cell contains the final edit distance
  return matrix[str2.length][str1.length];
}

/**
 * Main function: Checks if a domain should be ignored based on similarity to existing domains
 * 
 * This is called for every potential domain match during scanning, so it needs to be
 * efficient. The function uses early returns and optimizations to minimize processing.
 * 
 * Usage workflow:
 * 1. New domain found: "g00gleads.com"
 * 2. Extract base: "g00gleads" 
 * 3. Compare to existing: ["googleads", "facebook", "amazon"]
 * 4. Find "googleads" is 89% similar (above 80% threshold)
 * 5. Return shouldIgnore: true
 * 
 * @param {string} newDomain - The domain to check for similarity
 * @param {Set|Array} existingDomains - Collection of already found domains
 * @param {object} options - Configuration options
 * @param {boolean} options.enabled - Whether similarity checking is enabled
 * @param {number} options.threshold - Similarity percentage threshold (0-100)
 * @param {boolean} options.forceDebug - Whether to log debug information
 * @returns {object} Result object with shouldIgnore boolean and metadata
 */
function shouldIgnoreSimilarDomain(newDomain, existingDomains, options = {}) {
  const {
    enabled = true,
    threshold = 80, // Default: ignore domains that are 80%+ similar
    forceDebug = false
  } = options;
  
  // Quick exit if feature is disabled (performance optimization)
  if (!enabled) {
    return { shouldIgnore: false, reason: 'ignore_similar disabled' };
  }
  
  // Validate input domain
  if (!newDomain) {
    return { shouldIgnore: false, reason: 'invalid domain' };
  }
  
  // Extract base domain name for comparison
  const newBaseDomain = getBaseDomainName(newDomain);
  if (!newBaseDomain) {
    return { shouldIgnore: false, reason: 'could not extract base domain' };
  }
  
  // Convert Set to Array if needed (handles both data structures)
  const domainsArray = Array.isArray(existingDomains) ? existingDomains : Array.from(existingDomains);
  
  // Compare against each existing domain
  for (const existingDomain of domainsArray) {
    // Skip invalid, empty, or identical domains (optimization)
    if (!existingDomain || existingDomain === newDomain) {
      continue;
    }
    
    // Extract base domain for comparison
    const existingBaseDomain = getBaseDomainName(existingDomain);
    if (!existingBaseDomain || existingBaseDomain === newBaseDomain) {
      continue; // Skip if same base domain or extraction failed
    }
    
    // Calculate similarity percentage
    const similarity = calculateSimilarity(newBaseDomain, existingBaseDomain);
    
    // Check if similarity exceeds threshold
    if (similarity >= threshold) {
      // Debug logging for similarity matches (helps tune thresholds)
      if (forceDebug) {
        console.log(formatLogMessage('debug', 
          `[ignore_similar] ${newDomain} (${newBaseDomain}) is ${similarity}% similar to ${existingDomain} (${existingBaseDomain}) - ignoring`
        ));
      }
      
      // Return detailed similarity information for debugging/analysis
      return {
        shouldIgnore: true,
        reason: `${similarity}% similar to ${existingDomain}`,
        similarity,
        similarDomain: existingDomain,
        newBaseDomain,
        existingBaseDomain
      };
    }
  }
  
  // No similar domains found - safe to add this domain
  return { shouldIgnore: false, reason: 'no similar domains found' };
}

/**
 * Utility function: Filters out similar domains from a collection
 * 
 * This is useful for post-processing existing domain lists to remove
 * similar entries. It processes the array sequentially, comparing each
 * domain against the already-accepted domains.
 * 
 * Use case: Clean up an existing blocklist by removing similar domains
 * Example: ["googleads.com", "g00gleads.com", "facebook.com"] 
 *         -> ["googleads.com", "facebook.com"] (removed g00gleads as similar)
 * 
 * @param {Array} domains - Array of domains to filter
 * @param {object} options - Filtering options (same as shouldIgnoreSimilarDomain)
 * @returns {object} Result with filtered domains and information about removed domains
 */
function filterSimilarDomains(domains, options = {}) {
  const {
    enabled = true,
    threshold = 80,
    forceDebug = false
  } = options;
  
  // Quick exit if disabled or invalid input
  if (!enabled || !Array.isArray(domains)) {
    return { filtered: domains, removed: [] };
  }
  
  const filtered = [];   // Domains to keep
  const removed = [];    // Domains that were filtered out (for reporting)
  
  // Process each domain sequentially
  for (const domain of domains) {
    // Check if this domain is similar to any already-accepted domain
    const result = shouldIgnoreSimilarDomain(domain, filtered, { enabled, threshold, forceDebug });
    
    if (result.shouldIgnore) {
      // Domain is too similar - add to removed list with metadata
      removed.push({
        domain,
        reason: result.reason,
        similarTo: result.similarDomain
      });
    } else {
      // Domain is unique enough - add to filtered list
      filtered.push(domain);
    }
  }
  
  // Debug reporting for filtering results
  if (forceDebug && removed.length > 0) {
    console.log(formatLogMessage('debug', 
      `[ignore_similar] Filtered out ${removed.length} similar domains`
    ));
  }
  
  return { filtered, removed };
}

/**
 * MODULE EXPORTS
 * 
 * Public API for the ignore_similar module:
 * - getBaseDomainName: Extract base domain from full domain
 * - calculateSimilarity: Get similarity percentage between two domains  
 * - shouldIgnoreSimilarDomain: Main function for real-time similarity checking
 * - filterSimilarDomains: Batch processing function for existing lists
 */
module.exports = {
  getBaseDomainName,
  calculateSimilarity,
  shouldIgnoreSimilarDomain,
  filterSimilarDomains
};
