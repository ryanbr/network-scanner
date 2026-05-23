// === Referrer Header Generation Module ===
// This module handles generation of referrer headers for different traffic simulation modes

const { formatLogMessage, messageColors } = require('./colorize');

// Precomputed colored '[referrer]' subsystem prefix — matches the project
// convention used by other modules (flowproxy/cloudflare/smart-cache/etc.).
const REFERRER_TAG = messageColors.processing('[referrer]');

/**
 * Performance utility: Get random element from array
 * Reduces code duplication and improves readability
 * @param {Array} array - Array to select from
 * @returns {*} Random element from array
 */
function getRandomElement(array) {
  return array[Math.floor(Math.random() * array.length)];
}

/**
 * Referrer URL collections for different modes
 */
const REFERRER_COLLECTIONS = Object.freeze({
  SEARCH_ENGINES: [
    'https://www.google.com/search?q=',
    'https://www.bing.com/search?q=',
    'https://duckduckgo.com/?q=',
    'https://search.yahoo.com/search?p=',
    'https://yandex.com/search/?text=',
    'https://www.baidu.com/s?wd=',
    'https://www.startpage.com/sp/search?query=',
    'https://search.brave.com/search?q='
  ],
  
  SOCIAL_MEDIA: [
    'https://www.facebook.com/',
    'https://twitter.com/',
    'https://www.linkedin.com/',
    'https://www.reddit.com/',
    'https://www.instagram.com/',
    'https://www.pinterest.com/',
    'https://www.tiktok.com/',
    'https://www.youtube.com/',
    'https://discord.com/channels/',
    'https://t.me/',
    'https://www.snapchat.com/',
    'https://www.tumblr.com/',
    'https://www.threads.net/',
    'https://mastodon.social/'
  ],
  
  NEWS_SITES: [
    'https://news.google.com/',
    'https://www.reddit.com/r/news/',
    'https://news.ycombinator.com/',
    'https://www.bbc.com/news',
    'https://www.cnn.com/',
    'https://techcrunch.com/',
    'https://www.theverge.com/'
  ],
  
  DEFAULT_SEARCH_TERMS: [
    'reviews', 'deals', 'discount', 'price', 'buy', 'shop', 'store',
    'compare', 'best', 'top', 'guide', 'how to', 'tutorial', 'tips',
    'news', 'update', 'latest', 'new', 'trending', 'popular', 'cheap',
    'free', 'download', 'online', 'service', 'product', 'website'
  ],
  
  ECOMMERCE_TERMS: [
    'buy online', 'shopping', 'store', 'sale', 'discount', 'coupon',
    'free shipping', 'best price', 'deals', 'outlet', 'marketplace'
  ],
  
  TECH_TERMS: [
    'software', 'app', 'download', 'tutorial', 'guide', 'review',
    'comparison', 'features', 'specs', 'performance', 'benchmark'
  ]
});

/**
 * Generates a random search term based on context or defaults
 * @param {Array} customTerms - Custom search terms provided by user
 * @param {string} context - Context hint for term selection (e.g., 'ecommerce', 'tech')
 * @returns {string} Selected search term
 */
function generateSearchTerm(customTerms, context = null) {
  // Array.isArray guard belt-and-braces: validateReferrerConfig now blocks
  // non-array search_terms at config load, but a direct internal caller
  // could still pass a non-array and trigger a TypeError on .length.
  if (Array.isArray(customTerms) && customTerms.length > 0) {
    return getRandomElement(customTerms);
  }
  
  // Use context-specific terms if available
  let termCollection = REFERRER_COLLECTIONS.DEFAULT_SEARCH_TERMS;
  if (context === 'ecommerce') {
    termCollection = REFERRER_COLLECTIONS.ECOMMERCE_TERMS;
  } else if (context === 'tech') {
    termCollection = REFERRER_COLLECTIONS.TECH_TERMS;
  }
  
  return getRandomElement(termCollection);
}

/**
 * Generates a search engine referrer URL
 * @param {Array} searchTerms - Custom search terms
 * @param {string} context - Context for term selection
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {string} Generated search engine referrer URL
 */
function generateSearchReferrer(searchTerms, context, forceDebug) {
  const randomEngine = getRandomElement(REFERRER_COLLECTIONS.SEARCH_ENGINES);
  
  const searchTerm = generateSearchTerm(searchTerms, context);
  const referrerUrl = randomEngine + encodeURIComponent(searchTerm);
  
  if (forceDebug) {
    console.log(formatLogMessage('debug', `${REFERRER_TAG} Generated search referrer: ${referrerUrl} (engine: ${randomEngine.split('//')[1].split('/')[0]}, term: "${searchTerm}")`));
  }
  
  return referrerUrl;
}

/**
 * Generates a social media referrer URL
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {string} Generated social media referrer URL
 */
function generateSocialMediaReferrer(forceDebug) {
  const randomSocial = getRandomElement(REFERRER_COLLECTIONS.SOCIAL_MEDIA);
  
  if (forceDebug) {
    console.log(formatLogMessage('debug', `${REFERRER_TAG} Generated social media referrer: ${randomSocial}`));
  }
  
  return randomSocial;
}

/**
 * Generates a news site referrer URL
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {string} Generated news site referrer URL
 */
function generateNewsReferrer(forceDebug) {
  const randomNews = getRandomElement(REFERRER_COLLECTIONS.NEWS_SITES);
  
  if (forceDebug) {
    console.log(formatLogMessage('debug', `${REFERRER_TAG} Generated news referrer: ${randomNews}`));
  }
  
  return randomNews;
}

/**
 * Validates a URL string
 * @param {string} url - URL to validate
 * @returns {boolean} True if valid HTTP/HTTPS URL
 */
function isValidUrl(url) {
  return typeof url === 'string' && (url.startsWith('http://') || url.startsWith('https://'));
}

/**
 * Checks if a URL should have its referrer disabled
 * @param {string} targetUrl - The URL being visited
 * @param {Array} disableList - Array of URLs/patterns that should have no referrer
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {boolean} True if referrer should be disabled for this URL
 */
function shouldDisableReferrer(targetUrl, disableList, forceDebug = false) {
  // Fast path: early return for empty/invalid inputs
  if (!disableList?.length || !targetUrl || typeof targetUrl !== 'string') {
    return false;
  }
  
  // Parse target URL once (performance optimization)
  let targetHostname = null;
  let targetUrlParsed = false;
  
  try {
    targetHostname = new URL(targetUrl).hostname;
    targetUrlParsed = true;
  } catch (e) {
    // Invalid URL - can only do string matching
    targetUrlParsed = false;
  }
  
  for (const disablePattern of disableList) {
    if (typeof disablePattern !== 'string') continue;

    // Fast check: Exact URL match (no parsing needed)
    if (targetUrl === disablePattern) {
      if (forceDebug) console.log(formatLogMessage('debug', `${REFERRER_TAG} Referrer disabled for exact match: ${targetUrl}`));
      return true;
    }

    // Resolve pattern to a hostname — full URL patterns ('https://example.com')
    // and bare-hostname patterns ('example.com') both end up running through
    // the same suffix-match logic so they behave identically. Previously
    // full-URL patterns only did exact hostname equality (no subdomain
    // match), while bare-hostname patterns did suffix match — same user
    // intent, different result depending on string form.
    let patternHostname = null;
    if (disablePattern.includes('/')) {
      try { patternHostname = new URL(disablePattern).hostname; } catch (_) { /* fall through */ }
    } else {
      patternHostname = disablePattern;
    }

    if (targetUrlParsed && patternHostname) {
      const p = patternHostname.toLowerCase();
      const h = targetHostname.toLowerCase();
      if (h === p || h.endsWith('.' + p)) {
        if (forceDebug) console.log(formatLogMessage('debug', `${REFERRER_TAG} Referrer disabled for hostname match: ${p} matches ${h}`));
        return true;
      }
    } else if (!targetUrlParsed) {
      // Pathological fallback: target URL didn't parse. Substring match
      // as last resort. Shouldn't fire in practice — we only call this
      // on URLs we're about to navigate to.
      if (targetUrl.includes(disablePattern)) {
        if (forceDebug) console.log(formatLogMessage('debug', `${REFERRER_TAG} Referrer disabled for pattern match (unparseable target): ${disablePattern}`));
        return true;
      }
    }
  }

  return false;
}

/**
 * Generates a referrer URL based on the specified mode and options
 * @param {Object|string|Array} referrerConfig - Referrer configuration
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {string} Generated referrer URL or empty string
 */
function generateReferrerUrl(referrerConfig, forceDebug = false) {
  // No top-level try/catch — nothing in here throws synchronously.
  // typeof / Array.isArray / object property access / string concat /
  // console.log / the helper functions are all non-throwing. The old
  // try/catch was unreachable defensive scaffolding.

  // Handle simple string URLs
  if (typeof referrerConfig === 'string') {
    const url = isValidUrl(referrerConfig) ? referrerConfig : '';
    if (forceDebug && url) {
      console.log(formatLogMessage('debug', `${REFERRER_TAG} Using direct referrer URL: ${url}`));
    } else if (forceDebug && !url) {
      console.log(formatLogMessage('debug', `${REFERRER_TAG} Invalid referrer URL provided: ${referrerConfig}`));
    }
    return url;
  }

  // Handle arrays - pick random URL
  if (Array.isArray(referrerConfig)) {
    if (referrerConfig.length === 0) {
      if (forceDebug) console.log(formatLogMessage('debug', `${REFERRER_TAG} Empty referrer array provided`));
      return '';
    }

    const randomUrl = getRandomElement(referrerConfig);
    const url = isValidUrl(randomUrl) ? randomUrl : '';

    if (forceDebug) {
      console.log(formatLogMessage('debug', `${REFERRER_TAG} Selected referrer from array (${referrerConfig.length} options): ${url || 'invalid URL'}`));
    }

    return url;
  }

  // Handle object modes
  if (typeof referrerConfig === 'object' && referrerConfig !== null && referrerConfig.mode) {
    switch (referrerConfig.mode) {
      case 'random_search': {
        const searchTerms = referrerConfig.search_terms;
        const context = referrerConfig.context; // Optional context hint
        return generateSearchReferrer(searchTerms, context, forceDebug);
      }

      case 'social_media': {
        return generateSocialMediaReferrer(forceDebug);
      }

      case 'news_sites': {
        return generateNewsReferrer(forceDebug);
      }

      case 'direct_navigation': {
        if (forceDebug) console.log(formatLogMessage('debug', `${REFERRER_TAG} Using direct navigation (no referrer)`));
        return '';
      }

      case 'custom': {
        const url = isValidUrl(referrerConfig.url) ? referrerConfig.url : '';
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${REFERRER_TAG} Using custom referrer URL: ${url || 'invalid URL provided'}`));
        }
        return url;
      }

      case 'mixed': {
        // Randomly choose between different referrer types
        const modes = ['random_search', 'social_media', 'news_sites'];
        const randomMode = getRandomElement(modes);

        if (forceDebug) console.log(formatLogMessage('debug', `${REFERRER_TAG} Mixed mode selected: ${randomMode}`));

        const mixedConfig = { mode: randomMode };
        if (randomMode === 'random_search' && referrerConfig.search_terms) {
          mixedConfig.search_terms = referrerConfig.search_terms;
          mixedConfig.context = referrerConfig.context;
        }

        return generateReferrerUrl(mixedConfig, forceDebug);
      }

      default: {
        if (forceDebug) console.log(formatLogMessage('debug', `${REFERRER_TAG} Unknown referrer mode: ${referrerConfig.mode}`));
        return '';
      }
    }
  }

  if (forceDebug) console.log(formatLogMessage('debug', `${REFERRER_TAG} Invalid referrer configuration type: ${typeof referrerConfig}`));
  return '';
}

/**
 * Main function to determine referrer for a specific URL
 * Handles both referrer generation and referrer_disable functionality
 * @param {string} targetUrl - The URL being visited
 * @param {Object|string|Array} referrerConfig - Referrer configuration
 * @param {Array} referrerDisable - Array of URLs that should have no referrer
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {string} Generated referrer URL or empty string if disabled/none
 */
function getReferrerForUrl(targetUrl, referrerConfig, referrerDisable, forceDebug = false) {
  // Check if referrer should be disabled for this specific URL
  if (shouldDisableReferrer(targetUrl, referrerDisable, forceDebug)) {
    return '';
  }
  
  // Generate referrer normally if not disabled
  return generateReferrerUrl(referrerConfig, forceDebug);
}

/**
 * Validates referrer configuration
 * @param {Object|string|Array} referrerConfig - Referrer configuration to validate
 * @returns {Object} Validation result with isValid flag and error messages
 */
function validateReferrerConfig(referrerConfig) {
  const result = { isValid: true, errors: [], warnings: [] };
  
  if (!referrerConfig) {
    result.isValid = false;
    result.errors.push('Referrer configuration is required');
    return result;
  }
  
  // Validate string URLs
  if (typeof referrerConfig === 'string') {
    if (!isValidUrl(referrerConfig)) {
      result.isValid = false;
      result.errors.push('String referrer must be a valid HTTP/HTTPS URL');
    }
    return result;
  }
  
  // Validate arrays — every item gets checked. The old code spot-checked
  // only first and last when length > 10 "for performance", but config
  // validation runs ONCE at startup and referrer arrays are tiny; the
  // perf savings were imaginary, the correctness gap (items 2..N-1 never
  // validated, typo'd URLs slipping through) was real.
  if (Array.isArray(referrerConfig)) {
    if (referrerConfig.length === 0) {
      result.warnings.push('Empty referrer array will result in no referrer');
      return result;
    }

    for (let i = 0; i < referrerConfig.length; i++) {
      if (!isValidUrl(referrerConfig[i])) {
        result.errors.push(`Array item ${i} is not a valid HTTP/HTTPS URL: ${referrerConfig[i]}`);
        result.isValid = false;
      }
    }

    return result;
  }
  
  // Validate object modes
  if (typeof referrerConfig === 'object') {
    const validModes = ['random_search', 'social_media', 'news_sites', 'direct_navigation', 'custom', 'mixed'];
    
    if (!referrerConfig.mode) {
      result.isValid = false;
      result.errors.push('Object referrer configuration must have a "mode" property');
      return result;
    }
    
    if (!validModes.includes(referrerConfig.mode)) {
      result.isValid = false;
      result.errors.push(`Invalid referrer mode: ${referrerConfig.mode}. Valid modes: ${validModes.join(', ')}`);
      return result;
    }
    
    // Mode-specific validation
    switch (referrerConfig.mode) {
      case 'custom':
        if (!referrerConfig.url) {
          result.isValid = false;
          result.errors.push('Custom mode requires a "url" property');
        } else if (!isValidUrl(referrerConfig.url)) {
          result.isValid = false;
          result.errors.push('Custom mode URL must be a valid HTTP/HTTPS URL');
        }
        break;
        
      case 'random_search':
        // Upgrade from warning to error: generateSearchTerm reads
        // customTerms.length, which throws TypeError on a non-array
        // (e.g. a single string the user expected to be auto-wrapped).
        // Letting this slip past validation produces a runtime crash
        // mid-scan instead of a clean config-load failure.
        if (referrerConfig.search_terms !== undefined && !Array.isArray(referrerConfig.search_terms)) {
          result.isValid = false;
          result.errors.push(`search_terms must be an array of strings (got ${typeof referrerConfig.search_terms})`);
        } else if (Array.isArray(referrerConfig.search_terms)) {
          if (referrerConfig.search_terms.length === 0) {
            result.warnings.push('Empty search_terms array will use default terms');
          } else {
            for (let i = 0; i < referrerConfig.search_terms.length; i++) {
              if (typeof referrerConfig.search_terms[i] !== 'string') {
                result.isValid = false;
                result.errors.push(`search_terms[${i}] must be a string (got ${typeof referrerConfig.search_terms[i]})`);
              }
            }
          }
        }
        break;
    }
    
    return result;
  }
  
  result.isValid = false;
  result.errors.push('Referrer configuration must be a string, array, or object');
  return result;
}

/**
 * Validates referrer_disable configuration
 * @param {Array} referrerDisable - Array of URLs/patterns to disable referrer for
 * @returns {Object} Validation result with isValid flag and error messages
 */
function validateReferrerDisable(referrerDisable) {
  const result = { isValid: true, errors: [], warnings: [] };
  
  if (!referrerDisable) {
    return result; // referrer_disable is optional
  }
  
  if (!Array.isArray(referrerDisable)) {
    result.isValid = false;
    result.errors.push('referrer_disable must be an array of URLs/patterns');
    return result;
  }
  
  if (referrerDisable.length === 0) {
    result.warnings.push('Empty referrer_disable array has no effect');
    return result;
  }
  
  referrerDisable.forEach((pattern, index) => {
    if (typeof pattern !== 'string') {
      result.errors.push(`referrer_disable item ${index} must be a string (got ${typeof pattern})`);
      result.isValid = false;
    } else if (pattern.trim() === '') {
      result.warnings.push(`referrer_disable item ${index} is empty string`);
    } else if (!pattern.includes('.') && !pattern.includes('/')) {
      result.warnings.push(`referrer_disable item ${index} "${pattern}" might be too broad - consider using full URLs or hostnames`);
    }
  });
  
  if (referrerDisable.length > 100) {
    result.warnings.push('Large referrer_disable list (>100 items) may impact performance');
  }
  
  return result;
}

// Public surface used by nwss.js. Internal helpers
// (generateReferrerUrl, shouldDisableReferrer, generateSearch/Social/News
// Referrer, isValidUrl, REFERRER_COLLECTIONS) stay module-private —
// the old export list included nine names no caller imported, plus two
// dead helper functions (getReferrerModes, getReferrerStats) that have
// been removed entirely.
module.exports = {
  getReferrerForUrl,
  validateReferrerConfig,
  validateReferrerDisable
};