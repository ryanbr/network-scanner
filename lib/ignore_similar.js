const psl = require('psl');
const { formatLogMessage, messageColors } = require('./colorize');
const IGNORE_SIMILAR_TAG = messageColors.processing('[ignore_similar]');

// Strip protocol before handing to psl.parse, which expects a bare
// hostname per Public Suffix List semantics. psl handles 'www.' as a
// subdomain naturally (no need for a separate strip).
const REGEX_PROTOCOL = /^https?:\/\//;

/**
 * Extracts the base domain name (sld) without TLD for similarity comparison.
 *
 * Uses the project's `psl` dependency — the canonical Public Suffix List
 * parser, maintained against the live Mozilla list. Replaces a hand-curated
 * ~80-entry MULTI_PART_TLDS Set that went stale as PSL changed, plus a
 * THREE_PART_TLDS set that only listed two entries (both vanity domains
 * 'com.au.com'/'co.uk.com', not real public suffixes). The rest of the
 * codebase already uses psl (nwss.js, lib/post-processing.js, etc.) — this
 * brings ignore_similar in line.
 *
 * @param {string} domain - The domain to process
 * @returns {string} The base domain name (sld), e.g. 'example' for
 *   'www.example.co.uk'. Returns '' for invalid input; falls back to
 *   second-to-last token for hostnames psl can't parse (IPs, single-token
 *   hosts, unlisted TLDs).
 */
function getBaseDomainName(domain) {
  if (!domain || typeof domain !== 'string') {
    return '';
  }
  const hostname = domain.replace(REGEX_PROTOCOL, '');
  const parsed = psl.parse(hostname);
  if (parsed && parsed.sld) {
    return parsed.sld;
  }
  // Fallback for IPs / single-token / unparseable: best-effort
  // second-to-last token (the old behavior's default branch).
  const parts = hostname.split('.');
  return parts.length >= 2 ? parts[parts.length - 2] : hostname;
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
  // Ensure str1 is the longer one so the inner-loop dimension (n)
  // stays small. Inline swap instead of recursive re-entry — the old
  // `if (m < n) return levenshteinDistance(str2, str1)` paid a stack
  // frame + re-validation for what's really just a variable rename.
  let a = str1, b = str2;
  if (a.length < b.length) { const t = a; a = b; b = t; }
  const m = a.length;
  const n = b.length;

  // Two rows instead of full matrix — O(n) space instead of O(m*n).
  let prevRow = new Array(n + 1);
  let currRow = new Array(n + 1);

  for (let j = 0; j <= n; j++) {
    prevRow[j] = j;
  }

  for (let i = 1; i <= m; i++) {
    currRow[0] = i;
    const ch1 = a[i - 1];

    for (let j = 1; j <= n; j++) {
      if (ch1 === b[j - 1]) {
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
    if (!existingBaseDomain) {
      continue;
    }

    // BEHAVIOR NOTE: identical base names (e.g. google.com vs google.net)
    // now count as 100% similar — calculateSimilarity returns 100 for
    // matching strings, which is above any reasonable threshold. The old
    // `existingBaseDomain === newBaseDomain` skip silently exempted
    // same-base-different-TLD pairs, defeating the dedup purpose for the
    // most common variant case (brand registrations across multiple TLDs).
    // Both call sites in nwss.js (matched-dedup at ~2833, ignoreDomains
    // expansion at ~2849) want this stricter behavior. Set a lower
    // threshold or disable ignore_similar entirely if you actually want
    // to keep brand variants.
    const similarity = calculateSimilarity(newBaseDomain, existingBaseDomain);
    
    if (similarity >= threshold) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', 
          `${IGNORE_SIMILAR_TAG} ${newDomain} (${newBaseDomain}) is ${similarity}% similar to ${existingDomain} (${existingBaseDomain}) - ignoring`
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

// Public surface used by nwss.js. getBaseDomainName + (deleted)
// filterSimilarDomains had zero external callers — getBaseDomainName
// stays as an internal helper, filterSimilarDomains is gone entirely
// (no internal callers either).
module.exports = {
  calculateSimilarity,
  shouldIgnoreSimilarDomain
};
