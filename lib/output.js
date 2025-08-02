const fs = require('fs');
const path = require('path');
// Import domain cache functions for statistics
const { getTotalDomainsSkipped } = require('./domain-cache');
const { loadComparisonRules, filterUniqueRules } = require('./compare');
const { colorize, colors, messageColors, tags, formatLogMessage } = require('./colorize');

/**
 * Check if domain matches any ignore patterns (supports wildcards)
 * @param {string} domain - Domain to check
 * @param {string[]} ignorePatterns - Array of ignore patterns
 * @returns {boolean} True if domain should be ignored
 */
function matchesIgnoreDomain(domain, ignorePatterns) {
  if (!ignorePatterns || !Array.isArray(ignorePatterns) || ignorePatterns.length === 0) {
    return false;
  }
  
  return ignorePatterns.some(pattern => {
    if (pattern.includes('*')) {
      // Convert wildcard pattern to regex
      const regexPattern = pattern
        .replace(/\./g, '\\.')  // Escape dots
        .replace(/\*/g, '.*');  // Convert * to .*
      return new RegExp(`^${regexPattern}$`).test(domain);
    }
    return domain.endsWith(pattern);
  });
}

/**
 * Extract domain from a formatted rule back to plain domain
 * @param {string} rule - Formatted rule (e.g., "||domain.com^", "127.0.0.1 domain.com", etc.)
 * @returns {string|null} Plain domain or null if cannot extract
 */
function extractDomainFromRule(rule) {
  if (!rule || rule.startsWith('!')) {
    return null; // Skip comments
  }
  
  // Handle different output formats
  if (rule.startsWith('||') && rule.includes('^')) {
    // Adblock format: ||domain.com^ or ||domain.com^$script
    return rule.substring(2).split('^')[0];
  } else if (rule.match(/^(127\.0\.0\.1|0\.0\.0\.0)\s+/)) {
    // Localhost format: 127.0.0.1 domain.com or 0.0.0.0 domain.com
    return rule.split(/\s+/)[1];
  } else if (rule.startsWith('local=/') && rule.endsWith('/')) {
    // DNSmasq format: local=/domain.com/
    return rule.substring(6, rule.length - 1);
  } else if (rule.startsWith('server=/') && rule.endsWith('/')) {
    // DNSmasq old format: server=/domain.com/
    return rule.substring(7, rule.length - 1);
  } else if (rule.startsWith('local-zone: "') && rule.includes('" always_null')) {
    // Unbound format: local-zone: "domain.com." always_null
    const domain = rule.substring(13).split('"')[0];
    return domain.endsWith('.') ? domain.slice(0, -1) : domain;
  } else if (rule.startsWith('{ +block } .')) {
    // Privoxy format: { +block } .domain.com
    return rule.substring(12);
  } else if (rule.match(/^\(\^\|\\?\.\)/)) {
    // Pi-hole regex format: (^|\.)domain\.com$
    return rule.replace(/^\(\^\|\\?\.\)/, '').replace(/\\\./g, '.').replace(/\$$/, '');
  }
  
  // If no format matches, assume it's already a plain domain
  return rule.includes('.') ? rule : null;
}

/**
 * Formats a domain according to the specified output mode
 * @param {string} domain - The domain to format
 * @param {object} options - Formatting options
 * @param {boolean} options.localhost - Use 127.0.0.1 format
 * @param {boolean} options.localhostAlt - Use 0.0.0.0 format  
 * @param {boolean} options.plain - Use plain domain format (no adblock syntax)
 * @param {boolean} options.adblockRules - Generate adblock filter rules with resource types
 * @param {boolean} options.dnsmasq - Use dnsmasq local format
 * @param {boolean} options.dnsmasqOld - Use dnsmasq old server format
 * @param {boolean} options.unbound - Use unbound local-zone format
 * @param {boolean} options.privoxy - Use Privoxy block format
 * @param {boolean} options.pihole - Use Pi-hole regex format
 * @param {string} options.resourceType - Resource type for adblock rules (script, xhr, iframe, css, image, etc.)
 * @returns {string} The formatted domain
 */
function formatDomain(domain, options = {}) {
  const { localhost = false, localhostAlt = false, plain = false, adblockRules = false, dnsmasq = false, dnsmasqOld = false, unbound = false, privoxy = false, pihole = false, resourceType = null } = options;

  
  // Validate domain length and format
  if (!domain || domain.length <= 6 || !domain.includes('.')) {
    return null;
  }
  
  // If plain is true, always return just the domain regardless of other options
  if (plain) {
    return domain;
  }
  
  // Apply specific format based on output mode
  if (pihole) {
    // Escape dots for regex and use Pi-hole format: (^|\.)domain\.com$
    const escapedDomain = domain.replace(/\./g, '\\.');
    return `(^|\\.)${escapedDomain}$`;
  } else if (privoxy) {
    return `{ +block } .${domain}`;
  } else if (dnsmasq) {
    return `local=/${domain}/`;
  } else if (dnsmasqOld) {
    return `server=/${domain}/`;
  } else if (unbound) {
    return `local-zone: "${domain}." always_null`;
  } else if (localhost) {
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
    adblockRulesMode = false,
    dnsmasqMode = false,
    dnsmasqOldMode = false,
    unboundMode = false,
    privoxyMode = false,
    piholeMode = false
  } = globalOptions;
  
  // Site-level overrides
  const siteLocalhost = siteConfig.localhost === true;
  const siteLocalhostAlt = siteConfig.localhost_0_0_0_0 === true;
  const sitePlainSetting = siteConfig.plain === true;
  const siteAdblockRules = siteConfig.adblock_rules === true;
  const siteDnsmasq = siteConfig.dnsmasq === true;
  const siteDnsmasqOld = siteConfig.dnsmasq_old === true;
  const siteUnbound = siteConfig.unbound === true;
  const sitePrivoxy = siteConfig.privoxy === true;
  const sitePihole = siteConfig.pihole === true;
  
  // Validate output format compatibility - silently ignore incompatible combinations
  const activeFormats = [
    dnsmasqMode || siteDnsmasq,
    dnsmasqOldMode || siteDnsmasqOld,
    unboundMode || siteUnbound,
    privoxyMode || sitePrivoxy,
    piholeMode || sitePihole,
    adblockRulesMode || siteAdblockRules,
    localhostMode || siteLocalhost,
    localhostModeAlt || siteLocalhostAlt,
    plainOutput || sitePlainSetting
  ].filter(Boolean).length;
  
  if (activeFormats > 1) {
    // Multiple formats specified - fall back to standard adblock format
    const formatOptions = {
      localhost: false,
      localhostAlt: false,
      plain: false,
      adblockRules: false,
      dnsmasq: false,
      dnsmasqOld: false,
      unbound: false,
      privoxy: false,
      pihole: false
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
  
  // Determine final formatting options
  const formatOptions = {
    localhost: localhostMode || siteLocalhost,
    localhostAlt: localhostModeAlt || siteLocalhostAlt,
    plain: plainOutput || sitePlainSetting,
    adblockRules: adblockRulesMode || siteAdblockRules,
    dnsmasq: dnsmasqMode || siteDnsmasq,
    dnsmasqOld: dnsmasqOldMode || siteDnsmasqOld,
    unbound: unboundMode || siteUnbound,
    privoxy: privoxyMode || sitePrivoxy,
    pihole: piholeMode || sitePihole
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
    // Handle Set format (legacy behavior) or other modes (including privoxy and pihole)
    const domainsToProcess = matchedDomains instanceof Set ? matchedDomains : new Set(matchedDomains.keys());
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
 * @param {string[]} options.ignoreDomains - Domains to filter out from final output
 * @param {boolean} options.forLogFile - Include titles regardless of showTitles (for log files)
 * @returns {object} Object containing outputLines and outputLinesWithTitles
 */
function buildOutputLines(results, options = {}) {
  const { showTitles = false, removeDupes = false, ignoreDomains = [], forLogFile = false } = options;
  
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
  let filteredOutCount = 0;
  
  for (const { url, rules } of finalSiteRules) {
    if (rules.length > 0) {
      // Regular output (for -o files and console) - only add titles if --titles flag used
      if (showTitles) {
        outputLines.push(`! ${url}`);
      }
      
      // Filter out ignored domains from rules
      const filteredRules = rules.filter(rule => {
        const domain = extractDomainFromRule(rule);
        if (domain && matchesIgnoreDomain(domain, ignoreDomains)) {
          filteredOutCount++;
    
          // Log each filtered domain
          if (options.forceDebug) {
            console.log(formatLogMessage('debug', `[output-filter] Removed rule matching ignoreDomains: ${rule} (domain: ${domain})`));
          } else if (!options.silentMode) {
            console.log(formatLogMessage('info', `Filtered out: ${domain}`));
         }

          return false;
        }
        return true;
      });
      
      outputLines.push(...filteredRules);
      
      // Output with titles (for auto-saved log files) - always add titles
      outputLinesWithTitles.push(`! ${url}`);
      outputLinesWithTitles.push(...filteredRules);
    }
  }
  
  // Log filtered domains if any were removed
  if (filteredOutCount > 0) {
    if (options.forceDebug) {
      console.log(formatLogMessage('debug', `[output-filter] Total: ${filteredOutCount} rules filtered out matching ignoreDomains patterns`));
    } else if (!options.silentMode) {
      console.log(formatLogMessage('info', `${filteredOutCount} domains filtered out by ignoreDomains`));
    }
  }
  
  // Remove duplicates if requested
  const finalOutputLines = removeDupes ? removeDuplicates(outputLines) : outputLines;
  
  return {
    outputLines: finalOutputLines,
    outputLinesWithTitles,
    successfulPageLoads,
    totalRules: finalOutputLines.filter(line => !line.startsWith('!')).length,
    filteredOutCount
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
        console.log(`\n${messageColors.success('Rules saved to')} ${outputFile}`);
      }
    } else {
      // Console output
      if (lines.length > 0 && !silentMode) {
        console.log(`\n${messageColors.highlight('--- Generated Rules ---')}`);
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
    appendMode = false,
    showTitles = false,
    removeDupes = false,
    silentMode = false,
    dumpUrls = false,
    adblockRulesLogFile = null,
    forceDebug = false,
    ignoreDomains = [],
    totalDomainsSkipped = null  // Allow override or get from cache
  } = config;
  
  // Handle append mode
  if (outputFile && appendMode) {
    try {
      // Build output lines first
      const { 
        outputLines, 
        outputLinesWithTitles, 
        successfulPageLoads,
        totalRules,
        filteredOutCount
      } = buildOutputLines(results, { showTitles, removeDupes, ignoreDomains: config.ignoreDomains, forceDebug: config.forceDebug });

      // Apply remove-dupes to new results if requested (before comparing to existing file)
      const deduplicatedOutputLines = removeDupes ? removeDuplicates(outputLines) : outputLines;
      if (removeDupes && forceDebug) console.log(formatLogMessage('debug', `Applied --remove-dupes to new scan results before append comparison`));
      
      // Read existing file content
      let existingContent = '';
      if (fs.existsSync(outputFile)) {
        existingContent = fs.readFileSync(outputFile, 'utf8');
      } else {
        // File doesn't exist - append mode should create it
        if (forceDebug) console.log(formatLogMessage('debug', `Append mode: Creating new file ${outputFile}`));
      }
      
      // Parse existing rules for comparison (exclude comments)
      const existingRules = new Set();
      if (existingContent.trim()) {
        const lines = existingContent.trim().split('\n');
        lines.forEach(line => {
          const cleanLine = line.trim();
          if (cleanLine && !cleanLine.startsWith('!') && !cleanLine.startsWith('#')) {
            existingRules.add(cleanLine);
          }
        });
      }
      
      // Filter out rules that already exist (exclude comments from filtering)
      const newRules = deduplicatedOutputLines.filter(rule => {
        return rule.startsWith('!') || !existingRules.has(rule);
      });
      
      if (newRules.length > 0) {
        // Prepare content to append
        let appendContent = '';
        
        // Ensure there's a newline before appending if file has content
        if (existingContent && !existingContent.endsWith('\n')) {
          appendContent = '\n';
        }
        
        // Add new rules
        appendContent += newRules.join('\n') + '\n';
        
        // Append to file
        fs.appendFileSync(outputFile, appendContent);
        
        const newRuleCount = newRules.filter(rule => !rule.startsWith('!')).length;
        if (!silentMode) {
          console.log(`${messageColors.success('? Appended')} ${newRuleCount} new rules to: ${outputFile} (${existingRules.size} rules already existed${removeDupes ? ', duplicates removed' : ''})`);
        }
      } else {
        if (!silentMode) {
          const ruleCount = deduplicatedOutputLines.filter(rule => !rule.startsWith('!')).length;
          console.log(`${messageColors.info('?')} No new rules to append - all ${ruleCount} rules already exist in: ${outputFile}`);
        }
      }
      
      // Write log file output if --dumpurls is enabled
      let logSuccess = true;
      if (dumpUrls && adblockRulesLogFile) {
        logSuccess = writeOutput(outputLinesWithTitles, adblockRulesLogFile, silentMode);
      }
      
      const newRuleCount = newRules.filter(rule => !rule.startsWith('!')).length;
      return {
        success: logSuccess,
        outputFile,
        adblockRulesLogFile,
        successfulPageLoads,
        totalRules: newRuleCount,
        filteredOutCount,
        totalLines: newRules.length,
        outputLines: null,
        appendedRules: newRuleCount,
        existingRules: existingRules.size
      };
      
    } catch (appendErr) {
      console.error(`? Failed to append to ${outputFile}: ${appendErr.message}`);
      return { success: false };
    }
  }

  // Build output lines
  const { 
    outputLines, 
    outputLinesWithTitles, 
    successfulPageLoads,
    totalRules,
    filteredOutCount
  } = buildOutputLines(results, { showTitles, removeDupes, ignoreDomains: config.ignoreDomains, forceDebug: config.forceDebug });
  
  // Apply comparison filtering if compareFile is specified
  let filteredOutputLines = outputLines;
  if (compareFile && outputLines.length > 0) {
    try {
      const comparisonRules = loadComparisonRules(compareFile, config.forceDebug);
      const originalCount = outputLines.filter(line => !line.startsWith('!')).length;
      filteredOutputLines = filterUniqueRules(outputLines, comparisonRules, config.forceDebug);
      
      if (!silentMode) {
        console.log(formatLogMessage('compare', `Filtered ${originalCount - filteredOutputLines.filter(line => !line.startsWith('!')).length} existing rules, ${filteredOutputLines.filter(line => !line.startsWith('!')).length} unique rules remaining`));

      }
    } catch (compareError) {
      console.error(messageColors.error('❌ Compare operation failed:') + ` ${compareError.message}`);
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

  // Get domain skip statistics from cache if not provided
  const finalTotalDomainsSkipped = totalDomainsSkipped !== null ? 
    totalDomainsSkipped : getTotalDomainsSkipped();

  return {
    success: mainSuccess && logSuccess,
    outputFile,
    adblockRulesLogFile,
    successfulPageLoads,
    totalRules: filteredOutputLines.filter(line => !line.startsWith('!')).length, 
    filteredOutCount,
    totalLines: filteredOutputLines.length,
    outputLines: outputFile ? null : filteredOutputLines // Only return lines if not written to file
    // Note: totalDomainsSkipped statistic is now available via getTotalDomainsSkipped() 
    // and doesn't need to be passed through the output handler
  };
}

/**
 * Get output format description for debugging/logging
 * @param {object} options - Format options
 * @returns {string} Human-readable format description
 */
function getFormatDescription(options = {}) {
  const { localhost = false, localhostAlt = false, plain = false, adblockRules = false, dnsmasq = false, dnsmasqOld = false, unbound = false, privoxy = false, pihole = false } = options;
  
  // Plain always takes precedence
  if (plain) {
    return 'Plain domains only';
  }
  
  if (pihole) {
    return 'Pi-hole regex format ((^|\\.)domain\\.com$)';
  } else if (privoxy) {
    return 'Privoxy format ({ +block } .domain.com)';
  } else if (dnsmasq) {
    return 'DNSmasq format (local=/domain.com/)';
  } else if (dnsmasqOld) {
    return 'DNSmasq old format (server=/domain.com/)';
  } else if (unbound) {
    return 'Unbound format (local-zone: "domain.com." always_null)';
  } else if (adblockRules) {
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
  mapResourceTypeToAdblockModifier,
  matchesIgnoreDomain,
  extractDomainFromRule
};