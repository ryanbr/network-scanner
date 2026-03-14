const { formatLogMessage } = require('./colorize');

// Precompiled regex (avoids recompilation per getBaseDomainName call)
const REGEX_PROTOCOL = /^https?:\/\//;
const REGEX_WWW = /^www\./;

// Multi-part TLD lookup (module-level Set, O(1) instead of per-call array + O(n) .includes)
const MULTI_PART_TLDS = new Set([
  'co.uk', 'co.nz', 'com.au', 'co.za', 'co.in', 'co.jp', 'co.kr',
  'com.br', 'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve',
  'co.th', 'co.id', 'co.il', 'co.ke', 'co.tz', 'co.zw', 'co.bw',
  'com.sg', 'com.my', 'com.hk', 'com.tw', 'com.ph', 'com.vn',
  'co.cr', 'co.ug', 'co.zm', 'co.ao', 'co.mz', 'co.ls',
  'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'gov.uk', 'ac.uk', 'sch.uk',
  'com.de', 'org.de', 'com.fr', 'org.fr', 'com.es', 'org.es',
  'com.it', 'org.it', 'com.pl', 'org.pl', 'com.nl', 'org.nl',
  'com.ru', 'org.ru', 'com.ua', 'org.ua', 'com.tr', 'org.tr',
  'or.jp', 'ne.jp', 'ac.jp', 'ed.jp', 'go.jp',
  'or.kr', 'ne.kr', 'com.cn', 'org.cn', 'net.cn', 'edu.cn', 'gov.cn',
  'org.in', 'net.in', 'org.au', 'net.au', 'edu.au', 'gov.au',
  'org.nz', 'net.nz', 'org.il', 'net.il', 'org.za', 'net.za',
  'org.br', 'net.br', 'edu.br', 'gov.br', 'org.ar', 'org.mx',
  'org.co', 'org.pe', 'com.cl', 'org.cl', 'com.uy', 'org.uy',
  'org.ve', 'com.do', 'org.do', 'com.pr', 'org.pr',
  'com.gt', 'org.gt', 'com.pa', 'org.pa', 'com.sv', 'org.sv',
  'com.ni', 'org.ni', 'com.hn', 'org.hn', 'org.cr',
  'com.eg', 'org.eg', 'or.ke'
]);

// 3-part TLD lookup
const THREE_PART_TLDS = new Set(['com.au.com', 'co.uk.com']);

/**
 * Extracts the base domain name without TLD for similarity comparison
 * @param {string} domain - The domain to process
 * @returns {string} The base domain name
 */
function getBaseDomainName(domain) {
  if (!domain || typeof domain !== 'string') {
    return '';
  }
  
  domain = domain.replace(REGEX_PROTOCOL, '');
  domain = domain.replace(REGEX_WWW, '');
  
  const parts = domain.split('.');
  if (parts.length < 2) {
    return domain;
  }
  
  // Check multi-part TLD (O(1) Set lookup instead of O(n) array scan)
  const lastTwoParts = parts[parts.length - 2] + '.' + parts[parts.length - 1];
  
  if (MULTI_PART_TLDS.has(lastTwoParts)) {
    return parts.length >= 3 ? parts[parts.length - 3] : parts[0];
  }
  
  // Handle rare 3-part TLDs
  if (parts.length >= 4) {
    const lastThreeParts = parts[parts.length - 3] + '.' + lastTwoParts;
    if (THREE_PART_TLDS.has(lastThreeParts)) {
      return parts[parts.length - 4];
    }
  }
  
  return parts[parts.length - 2];
}

/**
 * Calculates similarity between two domain base names using Levenshtein distance
 * @param {string} domain1 - First domain base name
 * @param {string} domain2 - Second domain base name
 * @returns {number} Similarity percentage (0-100)
 */
function calculateSimilarity(domain1, domain2) {
  if (domain1 === domain2) return 100;
  if (!domain1 || !domain2) return 0;
  
  const longer = domain1.length > domain2.length ? domain1 : domain2;
  const shorter = domain1.length > domain2.length ? domain2 : domain1;
  
  if (longer.length === 0) return 100;
  
  const distance = levenshteinDistance(longer, shorter);
  return Math.round(((longer.length - distance) / longer.length) * 100);
}

/**
 * Calculates Levenshtein distance using two-row approach
 * Same results as original, but O(min(m,n)) space instead of O(m*n)
 * @param {string} str1 - First string
 * @param {string} str2 - Second string  
 * @returns {number} Edit distance
 */
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  
  // Ensure we iterate over the shorter dimension for row arrays
  if (m < n) return levenshteinDistance(str2, str1);
  
  // Two rows instead of full matrix
  let prevRow = new Array(n + 1);
  let currRow = new Array(n + 1);
  
  for (let j = 0; j <= n; j++) {
    prevRow[j] = j;
  }
  
  for (let i = 1; i <= m; i++) {
    currRow[0] = i;
    const ch1 = str1[i - 1];
    
    for (let j = 1; j <= n; j++) {
      if (ch1 === str2[j - 1]) {
        currRow[j] = prevRow[j - 1];
      } else {
        const sub = prevRow[j - 1];
        const ins = currRow[j - 1];
        const del = prevRow[j];
        currRow[j] = (sub < ins ? (sub < del ? sub : del) : (ins < del ? ins : del)) + 1;
      }
    }
    
    // Swap rows
    const temp = prevRow;
    prevRow = currRow;
    currRow = temp;
  }
  
  return prevRow[n];
}

/**
 * Main function: Checks if a domain should be ignored based on similarity to existing domains
 * @param {string} newDomain - The domain to check for similarity
 * @param {Set|Array} existingDomains - Collection of already found domains
 * @param {object} options - Configuration options
 * @returns {object} Result object with shouldIgnore boolean and metadata
 */
function shouldIgnoreSimilarDomain(newDomain, existingDomains, options = {}) {
  const {
    enabled = true,
    threshold = 80,
    forceDebug = false
  } = options;
  
  if (!enabled) {
    return { shouldIgnore: false, reason: 'ignore_similar disabled' };
  }
  
  if (!newDomain) {
    return { shouldIgnore: false, reason: 'invalid domain' };
  }
  
  const newBaseDomain = getBaseDomainName(newDomain);
  if (!newBaseDomain) {
    return { shouldIgnore: false, reason: 'could not extract base domain' };
  }
  
  // KEEP original guard exactly as-is: Array.from handles undefined/null/objects safely
  const domainsArray = Array.isArray(existingDomains) ? existingDomains : Array.from(existingDomains);
  
  for (const existingDomain of domainsArray) {
    if (!existingDomain || existingDomain === newDomain) {
      continue;
    }
    
    const existingBaseDomain = getBaseDomainName(existingDomain);
    if (!existingBaseDomain || existingBaseDomain === newBaseDomain) {
      continue;
    }
    
    const similarity = calculateSimilarity(newBaseDomain, existingBaseDomain);
    
    if (similarity >= threshold) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', 
          `[ignore_similar] ${newDomain} (${newBaseDomain}) is ${similarity}% similar to ${existingDomain} (${existingBaseDomain}) - ignoring`
        ));
      }
      
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
  
  return { shouldIgnore: false, reason: 'no similar domains found' };
}

/**
 * Utility function: Filters out similar domains from a collection
 * @param {Array} domains - Array of domains to filter
 * @param {object} options - Filtering options
 * @returns {object} Result with filtered domains and removed domains
 */
function filterSimilarDomains(domains, options = {}) {
  const {
    enabled = true,
    threshold = 80,
    forceDebug = false
  } = options;
  
  if (!enabled || !Array.isArray(domains)) {
    return { filtered: domains, removed: [] };
  }
  
  const filtered = [];
  const removed = [];
  
  for (const domain of domains) {
    const result = shouldIgnoreSimilarDomain(domain, filtered, { enabled, threshold, forceDebug });
    
    if (result.shouldIgnore) {
      removed.push({
        domain,
        reason: result.reason,
        similarTo: result.similarDomain
      });
    } else {
      filtered.push(domain);
    }
  }
  
  if (forceDebug && removed.length > 0) {
    console.log(formatLogMessage('debug', 
      `[ignore_similar] Filtered out ${removed.length} similar domains`
    ));
  }
  
  return { filtered, removed };
}

module.exports = {
  getBaseDomainName,
  calculateSimilarity,
  shouldIgnoreSimilarDomain,
  filterSimilarDomains
};
