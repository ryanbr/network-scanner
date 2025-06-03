const fs = require('fs');
const path = require('path');
const { loadComparisonRules, filterUniqueRules } = require('./compare');

/**
 * Formats a domain according to the specified output mode
 * @param {string} domain - The domain to format
 * @param {object} options - Formatting options
 * @param {boolean} options.localhost - Use 127.0.0.1 format
 * @param {boolean} options.localhostAlt - Use 0.0.0.0 format  
 * @param {boolean} options.plain - Use plain domain format (no adblock syntax)
 * @param {boolean} options.adblockRules - Generate adblock filter rules with resource types
 * @param {string} options.resourceType - Resource type for adblock rules (script, xhr, iframe, css, image, etc.)
 * @returns {string} The formatted domain
 */
function formatDomain(domain, options = {}) {
  const { localhost = false, localhostAlt = false, plain = false, adblockRules = false, resourceType = null } = options;
  
  // Validate domain length and format
  if (!domain || domain.length <= 6 || !domain.includes('.')) {
    return null;
  }
  
  // If plain is true, always return just the domain regardless of other options
  if (plain) {
    return domain;
  }
  
  // Apply specific format based on localhost options
  if (localhost) {
    return `127.0.0.1 ${domain}`;
  } else if (localhostAlt) {
    return `0.0.0.0 ${domain}`;
  } else if (adblockRules && resourceType) {
    // Generate adblock filter rules with resource type modifiers
    return `||${domain}^${resourceType}`;
  } else {
    return `||${domain}^`;
  }
}

/**
 * Maps Puppeteer resource types to adblock filter modifiers
 * @param {string} resourceType - Puppeteer resource type
 * @returns {string|null} Adblock filter modifier, or null if should be ignored
 */
function mapResourceTypeToAdblockModifier(resourceType) {
  const typeMap = {
    'script': 'script',
    'xhr': 'xmlhttprequest', 
    'fetch': 'xmlhttprequest',
    'stylesheet': 'stylesheet',
    'image': 'image',
    'font': 'font',
    'document': 'document',
    'subdocument': 'subdocument',
    'iframe': 'subdocument',
    'websocket': 'websocket',
    'media': 'media',
    'ping': 'ping',
    'other': null  // Ignore 'other' type - return null
  };
  
  return typeMap[resourceType] || null; // Return null for unknown types too
}

/**
 * Formats an array of domains according to site and global settings
 * @param {Set<string>|Map<string, Set<string>>} matchedDomains - Set of matched domains or Map of domain -> resource types
 * @param {object} siteConfig - Site-specific configuration
 * @param {object} globalOptions - Global formatting options
 * @returns {string[]} Array of formatted rules
 */
function formatRules(matchedDomains, siteConfig = {}, globalOptions = {}) {
  const {
    localhostMode = false,
    localhostModeAlt = false,
    plainOutput = false,
    adblockRulesMode = false
  } = globalOptions;
  
  // Site-level overrides
  const siteLocalhost = siteConfig.localhost === true;
  const siteLocalhostAlt = siteConfig.localhost_0_0_0_0 === true;
  const sitePlainSetting = siteConfig.plain === true;
  const siteAdblockRules = siteConfig.adblock_rules === true;
  
  // Validate adblock rules compatibility - silently ignore if incompatible
  if ((adblockRulesMode || siteAdblockRules)) {
    if (localhostMode || siteLocalhost || localhostModeAlt || siteLocalhostAlt || plainOutput || sitePlainSetting) {
      // Silently fall back to standard format when incompatible options are used
      const formatOptions = {
        localhost: localhostMode || siteLocalhost,
        localhostAlt: localhostModeAlt || siteLocalhostAlt,
        plain: plainOutput || sitePlainSetting,
        adblockRules: false
      };
      
      const formattedRules = [];
      const domainsToProcess = matchedDomains instanceof Set ? matchedDomains : new Set(matchedDomains.keys());
      domainsToProcess.forEach(domain => {
        const formatted = formatDomain(domain, formatOptions);
        if (formatted) {
          formattedRules.push(formatted);
        }
      });
      return formattedRules;
    }
  }
  
  // Determine final formatting options
  const formatOptions = {
    localhost: localhostMode || siteLocalhost,
    localhostAlt: localhostModeAlt || siteLocalhostAlt,
    plain: plainOutput || sitePlainSetting,
    adblockRules: adblockRulesMode || siteAdblockRules
  };
  
  const formattedRules = [];
  
  if (matchedDomains instanceof Map && formatOptions.adblockRules) {
    // Handle Map format with resource types for --adblock-rules
    matchedDomains.forEach((resourceTypes, domain) => {
      if (resourceTypes.size > 0) {
        let hasValidResourceType = false;
        
        // Generate one rule per resource type found for this domain
        resourceTypes.forEach(resourceType => {
          const adblockModifier = mapResourceTypeToAdblockModifier(resourceType);
          // Skip if modifier is null (e.g., 'other' type)
          if (adblockModifier) {
            hasValidResourceType = true;
            const formatted = formatDomain(domain, {
              ...formatOptions,
              resourceType: adblockModifier
            });
            if (formatted) {
              formattedRules.push(formatted);
            }
          }
        });
        
        // If no valid resource types were found, add a generic rule
        if (!hasValidResourceType) {
          const formatted = formatDomain(domain, formatOptions);
          if (formatted) {
            formattedRules.push(formatted);
          }
        }
      } else {
        // Fallback to generic rule if no resource types
        const formatted = formatDomain(domain, formatOptions);
        if (formatted) {
          formattedRules.push(formatted);
        }
      }
    });
  } else {
    // Handle Set format (legacy behavior)
    const domainsToProcess = matchedDomains instanceof Set ? matchedDomains : new Set(matchedDomains);
    domainsToProcess.forEach(domain => {
      const formatted = formatDomain(domain, formatOptions);
      if (formatted) {
        formattedRules.push(formatted);
      }
    });
  }
  
  return formattedRules;
}

/**
 * Removes duplicate rules while preserving comments (lines starting with !)
 * @param {string[]} lines - Array of output lines
 * @returns {string[]} Array with duplicates removed
 */
function removeDuplicates(lines) {
  const uniqueLines = [];
  const seenRules = new Set();
  
  for (const line of lines) {
    if (line.startsWith('!') || !seenRules.has(line)) {
      uniqueLines.push(line);
      if (!line.startsWith('!')) {
        seenRules.add(line);
      }
    }
  }
  
  return uniqueLines;
}

/**
 * Builds the final output lines from processing results
 * @param {Array} results - Array of processing results from processUrl
 * @param {object} options - Output options
 * @param {boolean} options.showTitles - Include URL titles in output
 * @param {boolean} options.removeDupes - Remove duplicate rules
 * @param {boolean} options.forLogFile - Include titles regardless of showTitles (for log files)
 * @returns {object} Object containing outputLines and outputLinesWithTitles
 */
function buildOutputLines(results, options = {}) {
  const { showTitles = false, removeDupes = false, forLogFile = false } = options;
  
  // Filter and collect successful results with rules
  const finalSiteRules = [];
  let successfulPageLoads = 0;
  
  results.forEach(result => {
    if (result) {
      if (result.success) {
        successfulPageLoads++;
      }
      if (result.rules && result.rules.length > 0) {
        finalSiteRules.push({ url: result.url, rules: result.rules });
      }
    }
  });
  
  // Build output lines
  const outputLines = [];
  const outputLinesWithTitles = [];
  
  for (const { url, rules } of finalSiteRules) {
    if (rules.length > 0) {
      // Regular output (for -o files and console) - only add titles if --titles flag used
      if (showTitles) {
        outputLines.push(`! ${url}`);
      }
      outputLines.push(...rules);
      
      // Output with titles (for auto-saved log files) - always add titles
      outputLinesWithTitles.push(`! ${url}`);
      outputLinesWithTitles.push(...rules);
    }
  }
  
  // Remove duplicates if requested
  const finalOutputLines = removeDupes ? removeDuplicates(outputLines) : outputLines;
  
  return {
    outputLines: finalOutputLines,
    outputLinesWithTitles,
    successfulPageLoads,
    totalRules: finalOutputLines.filter(line => !line.startsWith('!')).length
  };
}

/**
 * Writes output to file or console
 * @param {string[]} lines - Lines to output
 * @param {string|null} outputFile - File path to write to, or null for console output
 * @param {boolean} silentMode - Suppress console messages
 * @returns {boolean} Success status
 */
function writeOutput(lines, outputFile = null, silentMode = false) {
  try {
    if (outputFile) {
      // Ensure output directory exists
      const outputDir = path.dirname(outputFile);
      if (outputDir !== '.' && !fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }
      
      fs.writeFileSync(outputFile, lines.join('\n') + '\n');
      if (!silentMode) {
        console.log(`\nAdblock rules saved to ${outputFile}`);
      }
    } else {
      // Console output
      if (lines.length > 0 && !silentMode) {
        console.log("\n--- Generated Rules ---");
      }
      console.log(lines.join('\n'));
    }
    return true;
  } catch (error) {
    console.error(`? Failed to write output: ${error.message}`);
    return false;
  }
}

/**
 * Main output handler that combines all output operations
 * @param {Array} results - Processing results from scanner
 * @param {object} config - Output configuration
 * @returns {object} Output statistics and file paths
 */
function handleOutput(results, config = {}) {
  const {
    outputFile = null,
    compareFile = null,
    showTitles = false,
    removeDupes = false,
    silentMode = false,
    dumpUrls = false,
    adblockRulesLogFile = null
  } = config;
  
  // Build output lines
  const { 
    outputLines, 
    outputLinesWithTitles, 
    successfulPageLoads, 
    totalRules 
  } = buildOutputLines(results, { showTitles, removeDupes });
  
  // Apply comparison filtering if compareFile is specified
  let filteredOutputLines = outputLines;
  if (compareFile && outputLines.length > 0) {
    try {
      const comparisonRules = loadComparisonRules(compareFile, config.forceDebug);
      const originalCount = outputLines.filter(line => !line.startsWith('!')).length;
      filteredOutputLines = filterUniqueRules(outputLines, comparisonRules, config.forceDebug);
      
      if (!silentMode) {
        console.log(`[compare] Filtered ${originalCount - filteredOutputLines.filter(line => !line.startsWith('!')).length} existing rules, ${filteredOutputLines.filter(line => !line.startsWith('!')).length} unique rules remaining`);
      }
    } catch (compareError) {
      console.error(`? Compare operation failed: ${compareError.message}`);
      return { success: false, totalRules: 0, successfulPageLoads: 0 };
    }
  }
  
  // Write main output
  const mainSuccess = writeOutput(filteredOutputLines, outputFile, silentMode);
  
  // Write log file output if --dumpurls is enabled
  let logSuccess = true;
  if (dumpUrls && adblockRulesLogFile) {
    logSuccess = writeOutput(outputLinesWithTitles, adblockRulesLogFile, silentMode);
  }
  
  return {
    success: mainSuccess && logSuccess,
    outputFile,
    adblockRulesLogFile,
    successfulPageLoads,
    totalRules: filteredOutputLines.filter(line => !line.startsWith('!')).length,
    totalLines: filteredOutputLines.length,
    outputLines: outputFile ? null : filteredOutputLines // Only return lines if not written to file
  };
}

/**
 * Get output format description for debugging/logging
 * @param {object} options - Format options
 * @returns {string} Human-readable format description
 */
function getFormatDescription(options = {}) {
  const { localhost = false, localhostAlt = false, plain = false, adblockRules = false } = options;
  
  // Plain always takes precedence
  if (plain) {
    return 'Plain domains only';
  }
  
  if (adblockRules) {
    return 'Adblock filter rules with resource type modifiers (||domain.com^$script)';
  } else if (localhost) {
    return 'Localhost format (127.0.0.1 domain.com)';
  } else if (localhostAlt) {
    return 'Localhost format (0.0.0.0 domain.com)';
  } else {
    return 'Adblock format (||domain.com^)';
  }
}

module.exports = {
  formatDomain,
  formatRules,
  removeDuplicates,
  buildOutputLines,
  writeOutput,
  handleOutput,
  getFormatDescription,
  mapResourceTypeToAdblockModifier
};