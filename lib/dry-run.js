// === Dry Run Module (dry-run.js) ===
// Handles dry run mode functionality for network scanner

const fs = require('fs');
const { messageColors, formatLogMessage } = require('./colorize');

// Constants for dry run collection keys. SEARCH_STRING was removed —
// addDryRunSearchString had zero callers, so the map was never populated
// and the downstream "Searchstring Match" enhancement always produced
// null. See the cleanup comment in processDryRunResults.
const DRY_RUN_KEYS = {
  MATCHES: 'dryRunMatches',
  NET_TOOLS: 'dryRunNetTools'
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
    // Check VALUE, not just key presence. The old `field in matchData`
    // accepted `{regex: undefined, ...}` because `in` only tests for
    // the property's existence on the object. The downstream output
    // then printed 'unknown' via `item.regex || 'unknown'` defensive
    // fallbacks — validation that doesn't catch this defeats its purpose.
    if (matchData[field] === undefined || matchData[field] === null) {
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
    // Value check (see validateMatchData for the rationale).
    if (netToolsData[field] === undefined || netToolsData[field] === null) {
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
 * Generate adblock rule from domain and resource type
 * @param {string} domain - Domain name
 * @param {string} resourceType - Resource type (optional)
 * @returns {string} Formatted adblock rule
 */
function generateAdblockRule(domain, resourceType = null) {
  if (!domain) return '';
  
  if (resourceType && resourceType !== 'other') {
    return `||${domain}^$${resourceType}`;
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

    // emit() — single source of truth for output. Writes the plain
    // version to the file-output array AND the (possibly colored)
    // version to the console. Previously every output line was a
    // paired lines.push(...) + console.log(...) statement, often in
    // separate blocks (file pushes first, then console logs), so
    // drift between file and terminal output was a real risk every
    // time someone edited only one half of a pair.
    const emit = (plain, colored = plain) => {
      lines.push(plain);
      console.log(colored);
    };

    const truncatedUrl = truncateUrl(url);

    emit(
      `\n=== DRY RUN RESULTS === ${truncatedUrl}`,
      `\n${messageColors.scanning('=== DRY RUN RESULTS ===')} ${truncatedUrl}`
    );

    if (pageTitle && pageTitle.trim()) {
      const cleanTitle = pageTitle.trim().substring(0, 200); // Limit title length
      emit(
        `Title: ${cleanTitle}`,
        `${messageColors.info('Title:')} ${cleanTitle}`
      );
    }

    const totalMatches = matchedItems.length + netToolsResults.length;

    if (totalMatches === 0) {
      const noMatchMsg = `No matching rules found on ${truncatedUrl}`;
      emit(noMatchMsg, messageColors.warn(noMatchMsg));

      if (outputFile) {
        dryRunOutput.push(...lines);
        dryRunOutput.push(''); // Add empty line
      }
      return;
    }

    emit(
      `Matches found: ${totalMatches}`,
      `${messageColors.success('Matches found:')} ${totalMatches}`
    );

    // Process regex matches
    matchedItems.forEach((item, index) => {
      try {
        emit(''); // blank separator before each match item
        emit(
          `[${index + 1}] Regex Match:`,
          `${messageColors.highlight(`[${index + 1}]`)} ${messageColors.match('Regex Match:')}`
        );
        emit(`  Pattern: ${item.regex || 'unknown'}`);
        emit(`  Domain: ${item.domain || 'unknown'}`);
        emit(`  Resource Type: ${item.resourceType || 'unknown'}`);
        emit(`  Full URL: ${truncateUrl(item.fullUrl || '')}`);

        if (item.wasBlocked) {
          emit(
            `  Status: BLOCKED (even_blocked enabled)`,
            `  ${messageColors.warn('Status:')} BLOCKED (even_blocked enabled)`
          );
        }

        // Searchstring "not found" — see processDryRunResults comment
        // for why the positive-match branch was removed.
        if (item.searchStringChecked) {
          emit(
            `  ✗ Searchstring: No matches found in content`,
            `  ${messageColors.warn('✗ Searchstring:')} No matches found in content`
          );
        }

        const adblockRule = generateAdblockRule(item.domain, item.resourceType);
        emit(
          `  Adblock Rule: ${adblockRule}`,
          `  ${messageColors.info('Adblock Rule:')} ${adblockRule}`
        );

      } catch (itemErr) {
        const errorMsg = `Error processing match item ${index + 1}: ${itemErr.message}`;
        emit(
          `  Error: ${errorMsg}`,
          `  ${messageColors.warn('Error:')} ${errorMsg}`
        );
      }
    });

    // Process nettools results
    netToolsResults.forEach((result, index) => {
      try {
        const resultIndex = matchedItems.length + index + 1;
        emit(''); // blank separator before each nettools item
        emit(
          `[${resultIndex}] NetTools Match:`,
          `${messageColors.highlight(`[${resultIndex}]`)} ${messageColors.match('NetTools Match:')}`
        );
        emit(`  Domain: ${result.domain || 'unknown'}`);
        emit(`  Tool: ${(result.tool || 'unknown').toUpperCase()}`);

        const matchDesc = `${result.matchType || 'unknown'} - "${result.matchedTerm || 'unknown'}"`;
        emit(
          `  ✓ Match: ${matchDesc}`,
          `  ${messageColors.success('✓ Match:')} ${matchDesc}`
        );

        if (result.details) {
          emit(`  Details: ${result.details}`);
        }

        const adblockRule = generateAdblockRule(result.domain);
        emit(
          `  Adblock Rule: ${adblockRule}`,
          `  ${messageColors.info('Adblock Rule:')} ${adblockRule}`
        );

      } catch (resultErr) {
        const errorMsg = `Error processing nettools result ${index + 1}: ${resultErr.message}`;
        emit(
          `  Error: ${errorMsg}`,
          `  ${messageColors.warn('Error:')} ${errorMsg}`
        );
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
      // Leave pageTitle as '' (its initial value) on failure — the
      // truthy check in outputDryRunResults then skips the Title line
      // entirely. Previously we set 'Title unavailable' here, which
      // was truthy and got printed as if it were the page's real
      // title: 'Title: Title unavailable'.
    }
    
    // Get collected matches with safe fallbacks
    const dryRunMatches = matchedDomains.get(DRY_RUN_KEYS.MATCHES) || [];
    const dryRunNetTools = matchedDomains.get(DRY_RUN_KEYS.NET_TOOLS) || [];

    // Enhance matches with the searchstring-checked flag from the
    // incoming match data. Previously this also looked up positive
    // searchstring results in a `dryRunSearchString` Map — but
    // `addDryRunSearchString` was never wired to any caller, so the
    // map was always empty and `searchStringMatch` was always null.
    // Removed that dead lookup and the per-item try/catch it required.
    const enhancedMatches = dryRunMatches.map((match) => ({
      ...match,
      searchStringChecked: Boolean(match.needsSearchStringCheck)
    }));
    
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
    if (outputDir !== '.') {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    fs.writeFileSync(outputFile, dryRunContent);
    
    if (!silentMode) {
      console.log(`${messageColors.fileOp('📄 Dry run results saved to:')} ${outputFile}`);
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
    // Matches outputDryRunResults / processDryRunResults error format —
    // was bare `console.error('✗ ${errorMsg}')` here, the odd one out
    // among the three error paths in this module.
    console.error(messageColors.error(errorMsg));

    return {
      success: false,
      error: errorMsg,
      written: false
    };
  }
}

// Public surface used by nwss.js. Internal helpers (truncateUrl,
// generateAdblockRule, validateMatchData, validateNetToolsData,
// outputDryRunResults) stay module-private. DRY_RUN_KEYS, getDryRunStats,
// addDryRunSearchString, and formatSearchStringMatch were removed —
// see comments at their original sites for details.
module.exports = {
  initializeDryRunCollections,
  addDryRunMatch,
  addDryRunNetTools,
  processDryRunResults,
  writeDryRunOutput
};