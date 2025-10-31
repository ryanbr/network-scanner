// === Referrer Header Generation Module ===
// This module handles generation of referrer headers for different traffic simulation modes

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
  if (customTerms && customTerms.length > 0) {
    return customTerms[Math.floor(Math.random() * customTerms.length)];
  }
  
  // Use context-specific terms if available
  let termCollection = REFERRER_COLLECTIONS.DEFAULT_SEARCH_TERMS;
  if (context === 'ecommerce') {
    termCollection = REFERRER_COLLECTIONS.ECOMMERCE_TERMS;
  } else if (context === 'tech') {
    termCollection = REFERRER_COLLECTIONS.TECH_TERMS;
  }
  
  return termCollection[Math.floor(Math.random() * termCollection.length)];
}

/**
 * Generates a search engine referrer URL
 * @param {Array} searchTerms - Custom search terms
 * @param {string} context - Context for term selection
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {string} Generated search engine referrer URL
 */
function generateSearchReferrer(searchTerms, context, forceDebug) {
  const randomEngine = REFERRER_COLLECTIONS.SEARCH_ENGINES[
    Math.floor(Math.random() * REFERRER_COLLECTIONS.SEARCH_ENGINES.length)
  ];
  const searchTerm = generateSearchTerm(searchTerms, context);
  const referrerUrl = randomEngine + encodeURIComponent(searchTerm);
  
  if (forceDebug) {
    console.log(`[debug] Generated search referrer: ${referrerUrl} (engine: ${randomEngine.split('//')[1].split('/')[0]}, term: "${searchTerm}")`);
  }
  
  return referrerUrl;
}

/**
 * Generates a social media referrer URL
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {string} Generated social media referrer URL
 */
function generateSocialMediaReferrer(forceDebug) {
  const randomSocial = REFERRER_COLLECTIONS.SOCIAL_MEDIA[
    Math.floor(Math.random() * REFERRER_COLLECTIONS.SOCIAL_MEDIA.length)
  ];
  
  if (forceDebug) {
    console.log(`[debug] Generated social media referrer: ${randomSocial}`);
  }
  
  return randomSocial;
}

/**
 * Generates a news site referrer URL
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {string} Generated news site referrer URL
 */
function generateNewsReferrer(forceDebug) {
  const randomNews = REFERRER_COLLECTIONS.NEWS_SITES[
    Math.floor(Math.random() * REFERRER_COLLECTIONS.NEWS_SITES.length)
  ];
  
  if (forceDebug) {
    console.log(`[debug] Generated news referrer: ${randomNews}`);
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
  if (!disableList || !Array.isArray(disableList) || disableList.length === 0) {
    return false;
  }
  
  if (!targetUrl || typeof targetUrl !== 'string') {
    return false;
  }
  
  for (const disablePattern of disableList) {
    if (typeof disablePattern !== 'string') continue;
    
    // Exact URL match
    if (targetUrl === disablePattern) {
      if (forceDebug) console.log(`[debug] Referrer disabled for exact URL match: ${targetUrl}`);
      return true;
    }
    
    // Domain/hostname match
    try {
      const targetHostname = new URL(targetUrl).hostname;
      const disableHostname = new URL(disablePattern).hostname;
      if (targetHostname === disableHostname) {
        if (forceDebug) console.log(`[debug] Referrer disabled for domain match: ${targetHostname}`);
        return true;
      }
    } catch (e) {
      // If pattern is not a valid URL, try simple string matching
      if (targetUrl.includes(disablePattern)) {
        if (forceDebug) console.log(`[debug] Referrer disabled for pattern match: ${disablePattern} in ${targetUrl}`);
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
  try {
    // Handle simple string URLs
    if (typeof referrerConfig === 'string') {
      const url = isValidUrl(referrerConfig) ? referrerConfig : '';
      if (forceDebug && url) {
        console.log(`[debug] Using direct referrer URL: ${url}`);
      } else if (forceDebug && !url) {
        console.log(`[debug] Invalid referrer URL provided: ${referrerConfig}`);
      }
      return url;
    }
    
    // Handle arrays - pick random URL
    if (Array.isArray(referrerConfig)) {
      if (referrerConfig.length === 0) {
        if (forceDebug) console.log(`[debug] Empty referrer array provided`);
        return '';
      }
      
      const randomUrl = referrerConfig[Math.floor(Math.random() * referrerConfig.length)];
      const url = isValidUrl(randomUrl) ? randomUrl : '';
      
      if (forceDebug) {
        console.log(`[debug] Selected referrer from array (${referrerConfig.length} options): ${url || 'invalid URL'}`);
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
          if (forceDebug) console.log(`[debug] Using direct navigation (no referrer)`);
          return '';
        }
        
        case 'custom': {
          const url = isValidUrl(referrerConfig.url) ? referrerConfig.url : '';
          if (forceDebug) {
            console.log(`[debug] Using custom referrer URL: ${url || 'invalid URL provided'}`);
          }
          return url;
        }
        
        case 'mixed': {
          // Randomly choose between different referrer types
          const modes = ['random_search', 'social_media', 'news_sites'];
          const randomMode = modes[Math.floor(Math.random() * modes.length)];
          
          if (forceDebug) console.log(`[debug] Mixed mode selected: ${randomMode}`);
          
          const mixedConfig = { mode: randomMode };
          if (randomMode === 'random_search' && referrerConfig.search_terms) {
            mixedConfig.search_terms = referrerConfig.search_terms;
            mixedConfig.context = referrerConfig.context;
          }
          
          return generateReferrerUrl(mixedConfig, forceDebug);
        }
        
        default: {
          if (forceDebug) console.log(`[debug] Unknown referrer mode: ${referrerConfig.mode}`);
          return '';
        }
      }
    }
    
    if (forceDebug) console.log(`[debug] Invalid referrer configuration type: ${typeof referrerConfig}`);
    return '';
  } catch (err) {
    if (forceDebug) console.log(`[debug] Referrer generation failed: ${err.message}`);
    return '';
  }
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
  
  // Validate arrays
  if (Array.isArray(referrerConfig)) {
    if (referrerConfig.length === 0) {
      result.warnings.push('Empty referrer array will result in no referrer');
    } else {
      referrerConfig.forEach((url, index) => {
        if (!isValidUrl(url)) {
          result.errors.push(`Array item ${index} is not a valid HTTP/HTTPS URL: ${url}`);
          result.isValid = false;
        }
      });
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
        if (referrerConfig.search_terms && !Array.isArray(referrerConfig.search_terms)) {
          result.warnings.push('search_terms should be an array of strings');
        }
        if (referrerConfig.search_terms && referrerConfig.search_terms.length === 0) {
          result.warnings.push('Empty search_terms array will use default terms');
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

/**
 * Gets available referrer modes and their descriptions
 * @returns {Object} Object containing mode descriptions
 */
function getReferrerModes() {
  return {
    'random_search': 'Generate random search engine referrers with customizable search terms',
    'social_media': 'Use random social media platform referrers',
    'news_sites': 'Use random news website referrers',
    'direct_navigation': 'No referrer (simulates direct URL entry)',
    'custom': 'Use a specific custom referrer URL',
    'mixed': 'Randomly mix different referrer types for varied traffic simulation'
  };
}

/**
 * Gets statistics about available referrer collections
 * @returns {Object} Statistics about referrer collections
 */
function getReferrerStats() {
  return {
    searchEngines: REFERRER_COLLECTIONS.SEARCH_ENGINES.length,
    socialMedia: REFERRER_COLLECTIONS.SOCIAL_MEDIA.length,
    newsSites: REFERRER_COLLECTIONS.NEWS_SITES.length,
    defaultSearchTerms: REFERRER_COLLECTIONS.DEFAULT_SEARCH_TERMS.length,
    ecommerceTerms: REFERRER_COLLECTIONS.ECOMMERCE_TERMS.length,
    techTerms: REFERRER_COLLECTIONS.TECH_TERMS.length
  };
}

module.exports = {
  generateReferrerUrl,
  getReferrerForUrl,
  shouldDisableReferrer,
  validateReferrerConfig,
  validateReferrerDisable,
  getReferrerModes,
  getReferrerStats,
  generateSearchReferrer,
  generateSocialMediaReferrer,
  generateNewsReferrer,
  isValidUrl,
  REFERRER_COLLECTIONS
};