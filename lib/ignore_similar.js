const { formatLogMessage } = require('./colorize');

/**
 * Extracts the base domain name without TLD for similarity comparison
 * @param {string} domain - The domain to process
 * @returns {string} The base domain name
 */
function getBaseDomainName(domain) {
  if (!domain || typeof domain !== 'string') {
    return '';
  }
  
  // Remove protocol if present
  domain = domain.replace(/^https?:\/\//, '');
  
  // Remove www prefix
  domain = domain.replace(/^www\./, '');
  
  // Split by dots and get the part before the last dot (TLD)
  const parts = domain.split('.');
  if (parts.length < 2) {
    return domain; // Single part, return as-is
  }
  
 // Handle common multi-part TLDs (country code domains)
 const multiPartTLDs = [
  'co.uk', 'co.nz', 'com.au', 'co.za', 'co.in', 'co.jp', 'co.kr',
  'com.br', 'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve',
  'co.th', 'co.id', 'co.il', 'co.ke', 'co.tz', 'co.zw', 'co.bw',
  'com.sg', 'com.my', 'com.hk', 'com.tw', 'com.ph', 'com.vn',
  'co.cr', 'co.ug', 'co.zm', 'co.ao', 'co.mz', 'co.ls',
  
  // Europe extensions
  'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'gov.uk', 'ac.uk', 'sch.uk',
  'com.de', 'org.de', 'com.fr', 'org.fr', 'com.es', 'org.es',
  'com.it', 'org.it', 'com.pl', 'org.pl', 'com.nl', 'org.nl',
  'com.ru', 'org.ru', 'com.ua', 'org.ua', 'com.tr', 'org.tr',
  
  // Asia-Pacific extensions  
  'or.jp', 'ne.jp', 'ac.jp', 'ed.jp', 'go.jp',
  'or.kr', 'ne.kr', 'com.cn', 'org.cn', 'net.cn', 'edu.cn', 'gov.cn',
  'org.in', 'net.in', 'org.au', 'net.au', 'edu.au', 'gov.au',
  'org.nz', 'net.nz', 'org.il', 'net.il', 'org.za', 'net.za',
  
  // Americas extensions
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
 const lastTwoParts = parts.slice(-2).join('.');
 const lastThreeParts = parts.length >= 3 ? parts.slice(-3).join('.') : '';
 
 // Handle multi-part TLDs (e.g., google.co.nz ? "google")
 if (multiPartTLDs.includes(lastTwoParts)) {
   return parts.length >= 3 ? parts[parts.length - 3] : parts[0];
 }
 
 // Handle some 3-part TLDs (e.g., com.au.com if it existed)
 if (parts.length >= 4 && lastThreeParts && 
     ['com.au.com', 'co.uk.com'].includes(lastThreeParts)) {
   return parts[parts.length - 4];
 }
 
 // For standard TLDs, take the second-to-last part (e.g., google.com ? "google")
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
 * Calculates Levenshtein distance between two strings
 * @param {string} str1 - First string
 * @param {string} str2 - Second string
 * @returns {number} Edit distance
 */
function levenshteinDistance(str1, str2) {
  const matrix = [];
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  
  return matrix[str2.length][str1.length];
}

/**
 * Checks if a domain should be ignored based on similarity to existing domains
 * @param {string} newDomain - The domain to check
 * @param {Set|Array} existingDomains - Collection of existing domains
 * @param {object} options - Options for similarity checking
 * @returns {object} Result object with shouldIgnore boolean and details
 */
function shouldIgnoreSimilarDomain(newDomain, existingDomains, options = {}) {
  const {
    enabled = true,
    threshold = 80, // Similarity threshold percentage (80% by default)
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
  
  // Convert Set to Array if needed
  const domainsArray = Array.isArray(existingDomains) ? existingDomains : Array.from(existingDomains);
  
  for (const existingDomain of domainsArray) {
    if (!existingDomain || existingDomain === newDomain) {
      continue; // Skip empty or identical domains
    }
    
    const existingBaseDomain = getBaseDomainName(existingDomain);
    if (!existingBaseDomain || existingBaseDomain === newBaseDomain) {
      continue; // Skip if same base domain or invalid
    }
    
    const similarity = calculateSimilarity(newBaseDomain, existingBaseDomain);
    
    if (similarity >= threshold) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[ignore_similar] ${newDomain} (${newBaseDomain}) is ${similarity}% similar to ${existingDomain} (${existingBaseDomain}) - ignoring`));
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
 * Filters out similar domains from a collection
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
    console.log(formatLogMessage('debug', `[ignore_similar] Filtered out ${removed.length} similar domains`));
  }
  
  return { filtered, removed };
}

module.exports = {
  getBaseDomainName,
  calculateSimilarity,
  shouldIgnoreSimilarDomain,
  filterSimilarDomains
};