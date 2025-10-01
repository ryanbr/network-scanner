// === Dry Run Module (dry-run.js) ===
// Handles dry run mode functionality for network scanner

const fs = require('fs');
const { messageColors, formatLogMessage } = require('./colorize');

// Constants for dry run collection keys
const DRY_RUN_KEYS = {
  MATCHES: 'dryRunMatches',
  NET_TOOLS: 'dryRunNetTools',
  SEARCH_STRING: 'dryRunSearchString'
};

/**
 * Initialize dry run collections for a matched domains map
 * @param {Map} matchedDomains - The matched domains map to initialize
 * @throws {Error} If matchedDomains is not a Map instance
 */
function initializeDryRunCollections(matchedDomains) {
  if (!(matchedDomains instanceof Map)) {
    throw new Error('matchedDomains must be a Map instance for dry-run mode');
  }
  
  matchedDomains.set(DRY_RUN_KEYS.MATCHES, []);
  matchedDomains.set(DRY_RUN_KEYS.NET_TOOLS, []);
  matchedDomains.set(DRY_RUN_KEYS.SEARCH_STRING, new Map());
}

/**
 * Validates match data object structure
 * @param {Object} matchData - Match data to validate
 * @throws {Error} If matchData is invalid
 */
function validateMatchData(matchData) {
  if (!matchData || typeof matchData !== 'object') {
    throw new Error('Match data must be an object');
  }
  
  const requiredFields = ['regex', 'domain', 'resourceType', 'fullUrl'];
  for (const field of requiredFields) {
    if (!(field in matchData)) {
      throw new Error(`Match data missing required field: ${field}`);
    }
  }
}

/**
 * Validates nettools data object structure
 * @param {Object} netToolsData - NetTools data to validate
 * @throws {Error} If netToolsData is invalid
 */
function validateNetToolsData(netToolsData) {
  if (!netToolsData || typeof netToolsData !== 'object') {
    throw new Error('NetTools data must be an object');
  }
  
  const requiredFields = ['domain', 'tool', 'matchType', 'matchedTerm'];
  for (const field of requiredFields) {
    if (!(field in netToolsData)) {
      throw new Error(`NetTools data missing required field: ${field}`);
    }
  }
}

/**
 * Add a match to dry run collections
 * @param {Map} matchedDomains - The matched domains map
 * @param {Object} matchData - Match data object
 * @throws {Error} If parameters are invalid
 */
function addDryRunMatch(matchedDomains, matchData) {
  if (!(matchedDomains instanceof Map)) {
    throw new Error('matchedDomains must be a Map instance');
  }
  
  validateMatchData(matchData);
  
  if (!matchedDomains.has(DRY_RUN_KEYS.MATCHES)) {
    throw new Error('Dry run collections not initialized. Call initializeDryRunCollections first.');
  }
  
  matchedDomains.get(DRY_RUN_KEYS.MATCHES).push({
    ...matchData,
    timestamp: new Date().toISOString()
  });
}

/**
 * Add a nettools result to dry run collections
 * @param {Map} matchedDomains - The matched domains map
 * @param {Object} netToolsData - NetTools result data
 * @throws {Error} If parameters are invalid
 */
function addDryRunNetTools(matchedDomains, netToolsData) {
  if (!(matchedDomains instanceof Map)) {
    throw new Error('matchedDomains must be a Map instance');
  }
  
  validateNetToolsData(netToolsData);
  
  if (!matchedDomains.has(DRY_RUN_KEYS.NET_TOOLS)) {
    throw new Error('Dry run collections not initialized. Call initializeDryRunCollections first.');
  }
  
  matchedDomains.get(DRY_RUN_KEYS.NET_TOOLS).push({
    ...netToolsData,
    timestamp: new Date().toISOString()
  });
}

/**
 * Add a search string result to dry run collections
 * @param {Map} matchedDomains - The matched domains map
 * @param {string} url - The URL that was searched
 * @param {Object} searchResult - Search result data
 * @throws {Error} If parameters are invalid
 */
function addDryRunSearchString(matchedDomains, url, searchResult) {
  if (!(matchedDomains instanceof Map)) {
    throw new Error('matchedDomains must be a Map instance');
  }
  
  if (!url || typeof url !== 'string') {
    throw new Error('URL must be a non-empty string');
  }
  
  if (!searchResult || typeof searchResult !== 'object') {
    throw new Error('Search result must be an object');
  }
  
  if (!matchedDomains.has(DRY_RUN_KEYS.SEARCH_STRING)) {
    throw new Error('Dry run collections not initialized. Call initializeDryRunCollections first.');
  }
  
  matchedDomains.get(DRY_RUN_KEYS.SEARCH_STRING).set(url, {
    ...searchResult,
    timestamp: new Date().toISOString()
  });
}

/**
 * Safely truncate long URLs for display
 * @param {string} url - URL to truncate
 * @param {number} maxLength - Maximum length to display
 * @returns {string} Truncated URL with ellipsis if needed
 */
function truncateUrl(url, maxLength = 80) {
  if (!url || url.length <= maxLength) {
    return url;
  }
  return url.substring(0, maxLength - 3) + '...';
}

/**
 * Format search string match information
 * @param {Object} searchStringMatch - Search string match data
 * @returns {string} Formatted match description
 */
function formatSearchStringMatch(searchStringMatch) {
  if (!searchStringMatch) return null;
  
  const matchType = searchStringMatch.type || 'unknown';
  const term = searchStringMatch.term || 'unknown';
  return `${matchType} - "${term}"`;
}

/**
 * Generate adblock rule from domain and resource type
 * @param {string} domain - Domain name
 * @param {string} resourceType - Resource type (optional)
 * @returns {string} Formatted adblock rule
 */
function generateAdblockRule(domain, resourceType = null) {
  if (!domain) return '';
  
  if (resourceType && resourceType !== 'other') {
    return `||${domain}^${resourceType}`;
  }
  return `||${domain}^`;
}

/**
 * Outputs dry run results to console with formatted display
 * If outputFile is specified, also captures output for file writing
 * @param {string} url - The URL being processed  
 * @param {Array} matchedItems - Array of matched items with regex, domain, and resource type
 * @param {Array} netToolsResults - Array of whois/dig results
 * @param {string} pageTitle - Title of the page (if available)
 * @param {string} outputFile - Output file path (optional)
 * @param {Array} dryRunOutput - Array to collect output lines for file writing
 */
function outputDryRunResults(url, matchedItems = [], netToolsResults = [], pageTitle = '', outputFile = null, dryRunOutput = []) {
  try {
    const lines = [];
    const truncatedUrl = truncateUrl(url);
    
    lines.push(`\n=== DRY RUN RESULTS === ${truncatedUrl}`);
    console.log(`\n${messageColors.scanning('=== DRY RUN RESULTS ===')} ${truncatedUrl}`);
    
    if (pageTitle && pageTitle.trim()) {
      const cleanTitle = pageTitle.trim().substring(0, 200); // Limit title length
      lines.push(`Title: ${cleanTitle}`);
      console.log(`${messageColors.info('Title:')} ${cleanTitle}`);
    }
    
    const totalMatches = matchedItems.length + netToolsResults.length;
    
    if (totalMatches === 0) {
      const noMatchMsg = `No matching rules found on ${truncatedUrl}`;
      lines.push(noMatchMsg);
      
      if (outputFile) {
        dryRunOutput.push(...lines);
        dryRunOutput.push(''); // Add empty line
      }
      console.log(messageColors.warn(noMatchMsg));
      return;
    }
    
    lines.push(`Matches found: ${totalMatches}`);
    console.log(`${messageColors.success('Matches found:')} ${totalMatches}`);
    
    // Process regex matches
    matchedItems.forEach((item, index) => {
      try {
        lines.push('');
        lines.push(`[${index + 1}] Regex Match:`);
        lines.push(`  Pattern: ${item.regex || 'unknown'}`);
        lines.push(`  Domain: ${item.domain || 'unknown'}`);
        lines.push(`  Resource Type: ${item.resourceType || 'unknown'}`);
        lines.push(`  Full URL: ${truncateUrl(item.fullUrl || '')}`);

        console.log(`\n${messageColors.highlight(`[${index + 1}]`)} ${messageColors.match('Regex Match:')}`);
        console.log(`  Pattern: ${item.regex || 'unknown'}`);
        console.log(`  Domain: ${item.domain || 'unknown'}`);
        console.log(`  Resource Type: ${item.resourceType || 'unknown'}`);
        console.log(`  Full URL: ${truncateUrl(item.fullUrl || '')}`);
        
        // Show blocked status if applicable
        if (item.wasBlocked) {
          lines.push(`  Status: BLOCKED (even_blocked enabled)`);
          console.log(`  ${messageColors.warn('Status:')} BLOCKED (even_blocked enabled)`);
        }
        
        // Show searchstring results if available
        if (item.searchStringMatch) {
          const matchDesc = formatSearchStringMatch(item.searchStringMatch);
          lines.push(`  ? Searchstring Match: ${matchDesc}`);
          console.log(`  ${messageColors.success('? Searchstring Match:')} ${matchDesc}`);
        } else if (item.searchStringChecked) {
          lines.push(`  ? Searchstring: No matches found in content`);
          console.log(`  ${messageColors.warn('? Searchstring:')} No matches found in content`);
        }
        
        // Generate adblock rule
        const adblockRule = generateAdblockRule(item.domain, item.resourceType);
        lines.push(`  Adblock Rule: ${adblockRule}`);
        console.log(`  ${messageColors.info('Adblock Rule:')} ${adblockRule}`);
        
      } catch (itemErr) {
        const errorMsg = `Error processing match item ${index + 1}: ${itemErr.message}`;
        lines.push(`  Error: ${errorMsg}`);
        console.log(`  ${messageColors.warn('Error:')} ${errorMsg}`);
      }
    });
    
    // Process nettools results  
    netToolsResults.forEach((result, index) => {
      try {
        const resultIndex = matchedItems.length + index + 1;
        lines.push('');
        lines.push(`[${resultIndex}] NetTools Match:`);
        lines.push(`  Domain: ${result.domain || 'unknown'}`);
        lines.push(`  Tool: ${(result.tool || 'unknown').toUpperCase()}`);
        
        const matchDesc = `${result.matchType || 'unknown'} - "${result.matchedTerm || 'unknown'}"`;
        lines.push(`  ? Match: ${matchDesc}`);
        
        if (result.details) {
          lines.push(`  Details: ${result.details}`);
        }
        
        console.log(`\n${messageColors.highlight(`[${resultIndex}]`)} ${messageColors.match('NetTools Match:')}`);
        console.log(`  Domain: ${result.domain || 'unknown'}`);
        console.log(`  Tool: ${(result.tool || 'unknown').toUpperCase()}`);
        console.log(`  ${messageColors.success('? Match:')} ${matchDesc}`);
        
        if (result.details) {
          console.log(`  Details: ${result.details}`);
        }
        
        // Generate adblock rule for nettools matches
        const adblockRule = generateAdblockRule(result.domain);
        lines.push(`  Adblock Rule: ${adblockRule}`);
        console.log(`  ${messageColors.info('Adblock Rule:')} ${adblockRule}`);
        
      } catch (resultErr) {
        const errorMsg = `Error processing nettools result ${index + 1}: ${resultErr.message}`;
        lines.push(`  Error: ${errorMsg}`);
        console.log(`  ${messageColors.warn('Error:')} ${errorMsg}`);
      }
    });

    // Store output for file writing if outputFile is specified
    if (outputFile) {
      dryRunOutput.push(...lines);
      dryRunOutput.push(''); // Add empty line between sites
    }
    
  } catch (outputErr) {
    const errorMsg = `Error in outputDryRunResults: ${outputErr.message}`;
    console.error(messageColors.error(errorMsg));
    if (outputFile) {
      dryRunOutput.push(`Error: ${errorMsg}`);
    }
  }
}

/**
 * Process dry run results for a URL and output them
 * @param {string} currentUrl - The URL being processed
 * @param {Map} matchedDomains - The matched domains map with dry run collections
 * @param {Object} page - Puppeteer page object for getting title
 * @param {string} outputFile - Output file path (optional)
 * @param {Array} dryRunOutput - Array to collect output lines for file writing
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {Object} Dry run result summary
 */
async function processDryRunResults(currentUrl, matchedDomains, page, outputFile = null, dryRunOutput = [], forceDebug = false) {
  try {
    // Validate inputs
    if (!currentUrl || typeof currentUrl !== 'string') {
      throw new Error('currentUrl must be a non-empty string');
    }
    
    if (!(matchedDomains instanceof Map)) {
      throw new Error('matchedDomains must be a Map instance');
    }
    
    // Get page title for dry run output with error handling
    let pageTitle = '';
    try {
      if (page && typeof page.title === 'function') {
        pageTitle = await page.title();
      }
    } catch (titleErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Failed to get page title for ${currentUrl}: ${titleErr.message}`));
      }
      pageTitle = 'Title unavailable';
    }
    
    // Get collected matches with safe fallbacks
    const dryRunMatches = matchedDomains.get(DRY_RUN_KEYS.MATCHES) || [];
    const dryRunNetTools = matchedDomains.get(DRY_RUN_KEYS.NET_TOOLS) || [];
    const dryRunSearchString = matchedDomains.get(DRY_RUN_KEYS.SEARCH_STRING) || new Map();
    
    // Enhance matches with searchstring results
    const enhancedMatches = dryRunMatches.map((match, index) => {
      try {
        const searchResult = dryRunSearchString.get(match.fullUrl);
        return {
          ...match,
          searchStringMatch: searchResult && searchResult.matched ? searchResult : null,
          searchStringChecked: Boolean(match.needsSearchStringCheck)
        };
      } catch (enhanceErr) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Error enhancing match ${index}: ${enhanceErr.message}`));
        }
        return {
          ...match,
          searchStringMatch: null,
          searchStringChecked: false
        };
      }
    });
    
    outputDryRunResults(currentUrl, enhancedMatches, dryRunNetTools, pageTitle, outputFile, dryRunOutput);
    
    const totalMatches = enhancedMatches.length + dryRunNetTools.length;
    
    return {
      success: true,
      matchCount: totalMatches,
      enhancedMatches,
      netToolsResults: dryRunNetTools,
      pageTitle,
      regexMatches: enhancedMatches.length,
      netToolsMatches: dryRunNetTools.length
    };
    
  } catch (processErr) {
    const errorMsg = `Error processing dry run results for ${currentUrl}: ${processErr.message}`;
    console.error(messageColors.error(errorMsg));
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Stack trace: ${processErr.stack}`));
    }
    
    return {
      success: false,
      error: errorMsg,
      matchCount: 0,
      enhancedMatches: [],
      netToolsResults: [],
      pageTitle: '',
      regexMatches: 0,
      netToolsMatches: 0
    };
  }
}

/**
 * Write dry run output to file with enhanced error handling
 * @param {string} outputFile - Output file path
 * @param {Array} dryRunOutput - Array of output lines
 * @param {boolean} silentMode - Silent mode flag
 * @returns {Object} Operation result with details
 */
function writeDryRunOutput(outputFile, dryRunOutput, silentMode = false) {
  try {
    if (!outputFile || typeof outputFile !== 'string') {
      return { success: false, error: 'Invalid output file path' };
    }
    
    if (!Array.isArray(dryRunOutput) || dryRunOutput.length === 0) {
      if (!silentMode) {
        console.log(messageColors.info('No dry run output to write'));
      }
      return { success: true, written: false, reason: 'No output to write' };
    }
    
    const dryRunContent = dryRunOutput.join('\n');
    
    // Ensure output directory exists
    const path = require('path');
    const outputDir = path.dirname(outputFile);
    if (outputDir !== '.' && !fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    fs.writeFileSync(outputFile, dryRunContent);
    
    if (!silentMode) {
      console.log(`${messageColors.fileOp('?? Dry run results saved to:')} ${outputFile}`);
    }
    
    return { 
      success: true, 
      written: true, 
      file: outputFile, 
      lines: dryRunOutput.length,
      bytes: Buffer.byteLength(dryRunContent, 'utf8')
    };
    
  } catch (writeErr) {
    const errorMsg = `Failed to write dry run output to ${outputFile}: ${writeErr.message}`;
    console.error(`? ${errorMsg}`);
    
    return { 
      success: false, 
      error: errorMsg,
      written: false
    };
  }
}

/**
 * Get statistics from dry run collections
 * @param {Map} matchedDomains - The matched domains map
 * @returns {Object} Statistics object
 */
function getDryRunStats(matchedDomains) {
  if (!(matchedDomains instanceof Map)) {
    return { error: 'Invalid matchedDomains Map' };
  }
  
  const matches = matchedDomains.get(DRY_RUN_KEYS.MATCHES) || [];
  const netTools = matchedDomains.get(DRY_RUN_KEYS.NET_TOOLS) || [];
  const searchStrings = matchedDomains.get(DRY_RUN_KEYS.SEARCH_STRING) || new Map();
  
  return {
    totalMatches: matches.length + netTools.length,
    regexMatches: matches.length,
    netToolsMatches: netTools.length,
    searchStringResults: searchStrings.size,
    domains: new Set([
      ...matches.map(m => m.domain).filter(Boolean),
      ...netTools.map(n => n.domain).filter(Boolean)
    ]).size
  };
}

module.exports = {
  // Constants
  DRY_RUN_KEYS,
  
  // Core functions
  initializeDryRunCollections,
  addDryRunMatch,
  addDryRunNetTools,
  addDryRunSearchString,
  processDryRunResults,
  writeDryRunOutput,
  
  // Utility functions
  getDryRunStats,
  validateMatchData,
  validateNetToolsData,
  truncateUrl,
  formatSearchStringMatch,
  generateAdblockRule,
  outputDryRunResults
};