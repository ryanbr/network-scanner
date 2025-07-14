const { formatLogMessage } = require('./colorize');

/**
 * Enhanced domain validation function
 * @param {string} domain - The domain to validate
 * @returns {boolean} True if domain is valid, false otherwise
 */
function isValidDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    return false;
  }

  // Trim whitespace
  domain = domain.trim();
  
  // Check minimum length (shortest valid domain is something like "a.b" = 3 chars)
  if (domain.length < 3) {
    return false;
  }
  
  // Check maximum length (RFC 1035 - 253 characters max)
  if (domain.length > 253) {
    return false;
  }
  
  // Check for IP addresses (both IPv4 and IPv6)
  if (isIPAddress(domain)) {
    return true; // IP addresses are valid targets
  }
  
  // Must contain at least one dot
  if (!domain.includes('.')) {
    return false;
  }
  
  // Cannot start or end with dot
  if (domain.startsWith('.') || domain.endsWith('.')) {
    return false;
  }
  
  // Cannot contain consecutive dots
  if (domain.includes('..')) {
    return false;
  }
  
  // Split into labels and validate each
  const labels = domain.split('.');
  
  // Must have at least 2 labels (domain.tld)
  if (labels.length < 2) {
    return false;
  }
  
  // Validate each label
  for (const label of labels) {
    if (!isValidDomainLabel(label)) {
      return false;
    }
  }
  
  // TLD (last label) validation
  const tld = labels[labels.length - 1];
  if (!isValidTLD(tld)) {
    return false;
  }
  
  return true;
}

/**
 * Validates a single domain label
 * @param {string} label - The label to validate
 * @returns {boolean} True if label is valid
 */
function isValidDomainLabel(label) {
  if (!label || label.length === 0) {
    return false;
  }
  
  // Label cannot be longer than 63 characters (RFC 1035)
  if (label.length > 63) {
    return false;
  }
  
  // Label cannot start or end with hyphen
  if (label.startsWith('-') || label.endsWith('-')) {
    return false;
  }
  
  // Label can only contain alphanumeric characters and hyphens
  const labelRegex = /^[a-zA-Z0-9-]+$/;
  if (!labelRegex.test(label)) {
    return false;
  }
  
  return true;
}

/**
 * Validates TLD (Top Level Domain)
 * @param {string} tld - The TLD to validate
 * @returns {boolean} True if TLD is valid
 */
function isValidTLD(tld) {
  if (!tld || tld.length === 0) {
    return false;
  }
  
  // TLD must be at least 2 characters
  if (tld.length < 2) {
    return false;
  }
  
  // Allow numeric TLDs for modern domains like .1password
  // but still validate structure
  
  // TLD can contain letters and numbers, but must start with letter
  const tldRegex = /^[a-zA-Z][a-zA-Z0-9]*$/;
  if (!tldRegex.test(tld)) {
    return false;
  }
  
  return true;
}

/**
 * Checks if a string is an IP address (IPv4 or IPv6)
 * @param {string} str - String to check
 * @returns {boolean} True if it's an IP address
 */
function isIPAddress(str) {
  return isIPv4(str) || isIPv6(str);
}

/**
 * Checks if a string is a valid IPv4 address
 * @param {string} str - String to check
 * @returns {boolean} True if valid IPv4
 */
function isIPv4(str) {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(str);
}

/**
 * Checks if a string is a valid IPv6 address
 * @param {string} str - String to check
 * @returns {boolean} True if valid IPv6
 */
function isIPv6(str) {
  // Simplified IPv6 regex - covers most common cases
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(str);
}

/**
 * Validates a regex pattern string
 * @param {string} pattern - The regex pattern to validate
 * @returns {object} Validation result with isValid boolean and error message
 */
function validateRegexPattern(pattern) {
  if (!pattern || typeof pattern !== 'string') {
    return { isValid: false, error: 'Pattern must be a non-empty string' };
  }
  
  try {
    // Remove leading/trailing slashes if present
    const cleanPattern = pattern.replace(/^\/(.*)\/$/, '$1');
    new RegExp(cleanPattern);
    return { isValid: true };
  } catch (err) {
    return { isValid: false, error: `Invalid regex: ${err.message}` };
  }
}

/**
 * Validates adblock filter modifiers
 * @param {string} modifiers - The modifier string (e.g., "script,third-party")
 * @returns {object} Validation result
 */
function validateAdblockModifiers(modifiers) {
  if (!modifiers) {
    return { isValid: true, modifiers: [] };
  }
  
  // Valid adblock filter modifiers
  const validModifiers = new Set([
    // Resource type modifiers
    'script', 'stylesheet', 'image', 'object', 'xmlhttprequest', 'subdocument',
    'ping', 'websocket', 'webrtc', 'document', 'elemhide', 'generichide',
    'genericblock', 'popup', 'font', 'media', 'other',
    
    // Party modifiers
    'third-party', 'first-party', '~third-party', '~first-party',
    
    // Domain modifiers (domain= will be validated separately)
    'domain',
    
    // Method modifiers
    'match-case', '~match-case',
    
    // Action modifiers
    'important', 'badfilter',
    
    // CSP and redirect modifiers
    'csp', 'redirect', 'redirect-rule',
    
    // uBlock Origin specific
    'inline-script', 'inline-font', 'mp4', 'empty', 'xhr'
  ]);
  
  const modifierList = modifiers.split(',').map(m => m.trim());
  const invalidModifiers = [];
  const parsedModifiers = [];
  
  for (const modifier of modifierList) {
    if (!modifier) continue;
    
    // Handle domain= modifier specially
    if (modifier.startsWith('domain=')) {
      const domains = modifier.substring(7);
      if (domains) {
        // Validate domain list format (domains separated by |)
        const domainList = domains.split('|');
        for (const domain of domainList) {
          const cleanDomain = domain.startsWith('~') ? domain.substring(1) : domain;
          if (cleanDomain && !isValidDomain(cleanDomain)) {
            invalidModifiers.push(`Invalid domain in domain= modifier: ${cleanDomain}`);
          }
        }
        parsedModifiers.push({ type: 'domain', value: domains });
      } else {
        invalidModifiers.push('Empty domain= modifier');
      }
      continue;
    }
    
    // Handle csp= modifier
    if (modifier.startsWith('csp=')) {
      const cspValue = modifier.substring(4);
      if (!cspValue) {
        invalidModifiers.push('Empty csp= modifier');
      } else {
        parsedModifiers.push({ type: 'csp', value: cspValue });
      }
      continue;
    }
    
    // Handle redirect= modifier
    if (modifier.startsWith('redirect=')) {
      const redirectValue = modifier.substring(9);
      if (!redirectValue) {
        invalidModifiers.push('Empty redirect= modifier');
      } else {
        parsedModifiers.push({ type: 'redirect', value: redirectValue });
      }
      continue;
    }
    
    // Check for negated modifiers (starting with ~)
    const isNegated = modifier.startsWith('~');
    const baseModifier = isNegated ? modifier.substring(1) : modifier;
    
    if (validModifiers.has(modifier) || validModifiers.has(baseModifier)) {
      parsedModifiers.push({ 
        type: baseModifier, 
        negated: isNegated,
        raw: modifier
      });
    } else {
      invalidModifiers.push(modifier);
    }
  }
  
  if (invalidModifiers.length > 0) {
    return { 
      isValid: false, 
      error: `Invalid modifiers: ${invalidModifiers.join(', ')}`,
      validModifiers: parsedModifiers
    };
  }
  
  return { 
    isValid: true, 
    modifiers: parsedModifiers 
  };
}

/**
 * Validates adblock rule format with comprehensive modifier support
 * @param {string} rule - The rule to validate
 * @returns {object} Validation result with format type and validity
 */
function validateAdblockRule(rule) {
  if (!rule || typeof rule !== 'string') {
    return { isValid: false, format: 'unknown', error: 'Rule must be a non-empty string' };
  }
  
  const trimmedRule = rule.trim();
  
  // Skip comments
  if (trimmedRule.startsWith('!') || trimmedRule.startsWith('#')) {
    return { isValid: true, format: 'comment' };
  }
  
  // Adblock format: ||domain.com^ or ||domain.com^$script,third-party
  if (trimmedRule.startsWith('||') && trimmedRule.includes('^')) {
    const parts = trimmedRule.substring(2).split('^');
    const domain = parts[0];
    
    if (!isValidDomain(domain)) {
      return { isValid: false, format: 'adblock', error: `Invalid domain in adblock rule: ${domain}` };
    }
    
    // Check for modifiers after ^$
    let modifiers = '';
    let modifierValidation = { isValid: true, modifiers: [] };
    
    if (parts.length > 1 && parts[1].startsWith('$')) {
      modifiers = parts[1].substring(1);
      modifierValidation = validateAdblockModifiers(modifiers);
      
      if (!modifierValidation.isValid) {
        return { 
          isValid: false, 
          format: 'adblock', 
          error: `${modifierValidation.error} in rule: ${trimmedRule}`,
          domain,
          modifiers: modifierValidation.validModifiers || []
        };
      }
    }
    
    return { 
      isValid: true, 
      format: 'adblock', 
      domain,
      modifiers: modifierValidation.modifiers,
      hasModifiers: modifiers.length > 0
    };
  }
  
  // Basic adblock format without ||: domain.com^$modifier
  if (trimmedRule.includes('^') && trimmedRule.includes('$')) {
    const parts = trimmedRule.split('^$');
    if (parts.length === 2) {
      const domain = parts[0];
      const modifiers = parts[1];
      
      if (!isValidDomain(domain)) {
        return { isValid: false, format: 'adblock-basic', error: `Invalid domain in adblock rule: ${domain}` };
      }
      
      const modifierValidation = validateAdblockModifiers(modifiers);
      if (!modifierValidation.isValid) {
        return { 
          isValid: false, 
          format: 'adblock-basic', 
          error: modifierValidation.error,
          domain
        };
      }
      
      return { 
        isValid: true, 
        format: 'adblock-basic', 
        domain,
        modifiers: modifierValidation.modifiers
      };
    }
  }
  
  // Simple adblock format: ||domain.com^ (without modifiers)
  if (trimmedRule.startsWith('||') && trimmedRule.endsWith('^')) {
    const domain = trimmedRule.substring(2, trimmedRule.length - 1);
    if (isValidDomain(domain)) {
      return { isValid: true, format: 'adblock-simple', domain };
    } else {
      return { isValid: false, format: 'adblock-simple', error: `Invalid domain in adblock rule: ${domain}` };
    }
  }
  
  // Localhost format: 127.0.0.1 domain.com or 0.0.0.0 domain.com
  if (trimmedRule.match(/^(127\.0\.0\.1|0\.0\.0\.0)\s+/)) {
    const parts = trimmedRule.split(/\s+/);
    if (parts.length >= 2) {
      const domain = parts[1];
      if (isValidDomain(domain)) {
        return { isValid: true, format: 'localhost', domain };
      } else {
        return { isValid: false, format: 'localhost', error: `Invalid domain in localhost rule: ${domain}` };
      }
    }
    return { isValid: false, format: 'localhost', error: 'Malformed localhost rule' };
  }
  
  // DNSmasq format: local=/domain.com/
  if (trimmedRule.startsWith('local=/') && trimmedRule.endsWith('/')) {
    const domain = trimmedRule.substring(6, trimmedRule.length - 1);
    if (isValidDomain(domain)) {
      return { isValid: true, format: 'dnsmasq', domain };
    } else {
      return { isValid: false, format: 'dnsmasq', error: `Invalid domain in dnsmasq rule: ${domain}` };
    }
  }
  
  // DNSmasq old format: server=/domain.com/
  if (trimmedRule.startsWith('server=/') && trimmedRule.endsWith('/')) {
    const domain = trimmedRule.substring(7, trimmedRule.length - 1);
    if (isValidDomain(domain)) {
      return { isValid: true, format: 'dnsmasq-old', domain };
    } else {
      return { isValid: false, format: 'dnsmasq-old', error: `Invalid domain in dnsmasq-old rule: ${domain}` };
    }
  }
  
  // Unbound format: local-zone: "domain.com." always_null
  if (trimmedRule.startsWith('local-zone: "') && trimmedRule.includes('" always_null')) {
    const domain = trimmedRule.substring(13).split('"')[0];
    const cleanDomain = domain.endsWith('.') ? domain.slice(0, -1) : domain;
    if (isValidDomain(cleanDomain)) {
      return { isValid: true, format: 'unbound', domain: cleanDomain };
    } else {
      return { isValid: false, format: 'unbound', error: `Invalid domain in unbound rule: ${cleanDomain}` };
    }
  }
  
  // Privoxy format: { +block } .domain.com
  if (trimmedRule.startsWith('{ +block } .')) {
    const domain = trimmedRule.substring(12);
    if (isValidDomain(domain)) {
      return { isValid: true, format: 'privoxy', domain };
    } else {
      return { isValid: false, format: 'privoxy', error: `Invalid domain in privoxy rule: ${domain}` };
    }
  }
  
  // Pi-hole regex format: (^|\.)domain\.com$
  if (trimmedRule.match(/^\(\^\|\\?\.\).*\$$/)) {
    const domain = trimmedRule.replace(/^\(\^\|\\?\.\)/, '').replace(/\\\./g, '.').replace(/\$$/, '');
    if (isValidDomain(domain)) {
      return { isValid: true, format: 'pihole', domain };
    } else {
      return { isValid: false, format: 'pihole', error: `Invalid domain in pihole rule: ${domain}` };
    }
  }
  
  // Plain domain format
  if (isValidDomain(trimmedRule)) {
    return { isValid: true, format: 'plain', domain: trimmedRule };
  }
  
  return { isValid: false, format: 'unknown', error: 'Unrecognized rule format' };
}

/**
 * Validates an entire ruleset file
 * @param {string} filePath - Path to the file to validate
 * @param {object} options - Validation options
 * @returns {object} Validation results with statistics and errors
 */
function validateRulesetFile(filePath, options = {}) {
  const { 
    forceDebug = false, 
    silentMode = false,
    maxErrors = 10 
  } = options;
  
  const fs = require('fs');
  
  if (!fs.existsSync(filePath)) {
    return {
      isValid: false,
      error: `File not found: ${filePath}`,
      stats: { total: 0, valid: 0, invalid: 0, comments: 0 }
    };
  }
  
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    return {
      isValid: false,
      error: `Failed to read file: ${err.message}`,
      stats: { total: 0, valid: 0, invalid: 0, comments: 0 }
    };
  }
  
  const lines = content.split('\n');
  const stats = {
    total: 0,
    valid: 0,
    invalid: 0,
    comments: 0,
    formats: {}
  };
  
  const errors = [];
  const duplicates = new Set();
  const seenRules = new Set();
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Skip empty lines
    if (!line) continue;
    
    stats.total++;
    const lineNumber = i + 1;
    
    const validation = validateAdblockRule(line);
    
    if (validation.format === 'comment') {
      stats.comments++;
      continue;
    }
    
    if (validation.isValid) {
      stats.valid++;
      
      // Track format types
      if (!stats.formats[validation.format]) {
        stats.formats[validation.format] = 0;
      }
      stats.formats[validation.format]++;
      
      // Check for duplicates
      if (seenRules.has(line)) {
        duplicates.add(line);
        if (forceDebug) {
          errors.push(`Line ${lineNumber}: Duplicate rule - ${line}`);
        }
      } else {
        seenRules.add(line);
      }
    } else {
      stats.invalid++;
      errors.push(`Line ${lineNumber}: ${validation.error} - ${line}`);
      
      if (errors.length >= maxErrors) {
        errors.push(`... (stopping after ${maxErrors} errors, ${stats.total - i - 1} lines remaining)`);
        break;
      }
    }
  }
  
  // Log validation results
  if (!silentMode) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Validated ${filePath}:`));
      console.log(formatLogMessage('debug', `  Total lines: ${stats.total} (${stats.comments} comments)`));
      console.log(formatLogMessage('debug', `  Valid rules: ${stats.valid}`));
      console.log(formatLogMessage('debug', `  Invalid rules: ${stats.invalid}`));
      console.log(formatLogMessage('debug', `  Duplicates found: ${duplicates.size}`));
      
      if (Object.keys(stats.formats).length > 0) {
        console.log(formatLogMessage('debug', `  Format breakdown:`));
        Object.entries(stats.formats).forEach(([format, count]) => {
          console.log(formatLogMessage('debug', `    ${format}: ${count}`));
        });
      }
    }
    
    if (errors.length > 0) {
      console.log(formatLogMessage('warn', `Validation errors in ${filePath}:`));
      errors.slice(0, 5).forEach(error => {
        console.log(formatLogMessage('warn', `  ${error}`));
      });
      if (errors.length > 5) {
        console.log(formatLogMessage('warn', `  ... and ${errors.length - 5} more errors`));
      }
    }
  }
  
  return {
    isValid: stats.invalid === 0,
    stats,
    errors,
    duplicates: Array.from(duplicates),
    filePath
  };
}

/**
 * Validates configuration object for site settings
 * @param {object} siteConfig - Site configuration to validate
 * @param {number} siteIndex - Index of the site for error reporting
 * @returns {object} Validation result with warnings and errors
 */
function validateSiteConfig(siteConfig, siteIndex = 0) {
  const warnings = [];
  const errors = [];
  
  // Check required fields
  if (!siteConfig.url) {
    errors.push(`Site ${siteIndex}: Missing required 'url' field`);
  } else {
    // Validate URLs
    const urls = Array.isArray(siteConfig.url) ? siteConfig.url : [siteConfig.url];
    urls.forEach((url, urlIndex) => {
      try {
        new URL(url);
      } catch (urlErr) {
        errors.push(`Site ${siteIndex}, URL ${urlIndex}: Invalid URL format - ${url}`);
      }
    });
  }
  
  // Validate regex patterns
  if (siteConfig.filterRegex) {
    const regexes = Array.isArray(siteConfig.filterRegex) ? siteConfig.filterRegex : [siteConfig.filterRegex];
    regexes.forEach((pattern, patternIndex) => {
      const validation = validateRegexPattern(pattern);
      if (!validation.isValid) {
        errors.push(`Site ${siteIndex}, filterRegex ${patternIndex}: ${validation.error}`);
      }
    });
  }
  
  // Validate blocked patterns
  if (siteConfig.blocked) {
    if (!Array.isArray(siteConfig.blocked)) {
      errors.push(`Site ${siteIndex}: 'blocked' must be an array`);
    } else {
      siteConfig.blocked.forEach((pattern, patternIndex) => {
        const validation = validateRegexPattern(pattern);
        if (!validation.isValid) {
          errors.push(`Site ${siteIndex}, blocked ${patternIndex}: ${validation.error}`);
        }
      });
    }
  }
  
  // Validate resource types
  if (siteConfig.resourceTypes) {
    if (!Array.isArray(siteConfig.resourceTypes)) {
      errors.push(`Site ${siteIndex}: 'resourceTypes' must be an array`);
    } else {
      const validTypes = ['script', 'stylesheet', 'image', 'font', 'document', 'subdocument', 'xhr', 'fetch', 'websocket', 'media', 'ping', 'other'];
      siteConfig.resourceTypes.forEach(type => {
        if (!validTypes.includes(type)) {
          warnings.push(`Site ${siteIndex}: Unknown resourceType '${type}'. Valid types: ${validTypes.join(', ')}`);
        }
      });
    }
  }
  
  // Validate CSS selectors
  if (siteConfig.css_blocked) {
    if (!Array.isArray(siteConfig.css_blocked)) {
      errors.push(`Site ${siteIndex}: 'css_blocked' must be an array`);
    }
    // Note: CSS selector validation would be complex, skipping for now
  }
  
  // Validate numeric fields
  const numericFields = ['delay', 'reload', 'timeout'];
  numericFields.forEach(field => {
    if (siteConfig[field] !== undefined) {
      if (typeof siteConfig[field] !== 'number' || siteConfig[field] < 0) {
        errors.push(`Site ${siteIndex}: '${field}' must be a positive number`);
      }
    }
  });
  
  // Validate boolean fields
  const booleanFields = ['interact', 'clear_sitedata', 'firstParty', 'thirdParty', 'screenshot', 'headful', 'ignore_similar', 'ignore_similar_ignored_domains'];
  booleanFields.forEach(field => {
    if (siteConfig[field] !== undefined && typeof siteConfig[field] !== 'boolean') {
      warnings.push(`Site ${siteIndex}: '${field}' should be a boolean (true/false)`);
    }
  });

 // Validate ignore_similar_threshold
 if (siteConfig.ignore_similar_threshold !== undefined) {
   if (typeof siteConfig.ignore_similar_threshold !== 'number' || 
       siteConfig.ignore_similar_threshold < 0 || 
       siteConfig.ignore_similar_threshold > 100) {
     errors.push(`Site ${siteIndex}: 'ignore_similar_threshold' must be a number between 0 and 100`);
   }
 }

  // Validate user agent
  if (siteConfig.userAgent) {
    const validUserAgents = ['chrome', 'firefox', 'safari'];
    if (!validUserAgents.includes(siteConfig.userAgent.toLowerCase())) {
      warnings.push(`Site ${siteIndex}: Unknown userAgent '${siteConfig.userAgent}'. Valid options: ${validUserAgents.join(', ')}`);
    }
  }
  
  // Check for conflicting output format options
  const outputFormats = ['localhost', 'localhost_0_0_0_0', 'plain', 'dnsmasq', 'dnsmasq_old', 'unbound', 'privoxy', 'pihole', 'adblock_rules'];
  const enabledFormats = outputFormats.filter(format => siteConfig[format] === true);
  if (enabledFormats.length > 1) {
    warnings.push(`Site ${siteIndex}: Multiple output formats enabled (${enabledFormats.join(', ')}). Only one should be used.`);
  }
  
  return {
    isValid: errors.length === 0,
    warnings,
    errors
  };
}

/**
 * Cleans a ruleset file by removing invalid lines and optionally duplicates
 * @param {string} filePath - Path to the file to clean
 * @param {string} outputPath - Optional output path (defaults to overwriting input file)
 * @param {object} options - Cleaning options
 * @returns {object} Cleaning results with statistics
 */
function cleanRulesetFile(filePath, outputPath = null, options = {}) {
  const { 
    forceDebug = false, 
    silentMode = false,
    removeDuplicates = false,
    backupOriginal = true,
    dryRun = false
  } = options;
  
  const fs = require('fs');
  const path = require('path');
  
  if (!fs.existsSync(filePath)) {
    return {
      success: false,
      error: `File not found: ${filePath}`,
      stats: { total: 0, valid: 0, invalid: 0, removed: 0, duplicates: 0 }
    };
  }
  
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    return {
      success: false,
      error: `Failed to read file: ${err.message}`,
      stats: { total: 0, valid: 0, invalid: 0, removed: 0, duplicates: 0 }
    };
  }
  
  const lines = content.split('\n');
  const validLines = [];
  const invalidLines = [];
  const seenRules = new Set();
  const duplicateLines = [];
  
  const stats = {
    total: 0,
    valid: 0,
    invalid: 0,
    removed: 0,
    duplicates: 0,
    comments: 0,
    empty: 0
  };
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Keep empty lines for formatting
    if (!trimmed) {
      validLines.push(line);
      stats.empty++;
      continue;
    }
    
    stats.total++;
    const lineNumber = i + 1;
    
    const validation = validateAdblockRule(trimmed);
    
    // Comments are always valid
    if (validation.format === 'comment') {
      validLines.push(line);
      stats.valid++;
      stats.comments++;
      continue;
    }
    
    if (validation.isValid) {
      // Check for duplicates if requested
      if (removeDuplicates) {
        if (seenRules.has(trimmed)) {
          duplicateLines.push({ line: trimmed, lineNumber });
          stats.duplicates++;
          
          if (forceDebug) {
            console.log(formatLogMessage('debug', `[clean] Removing duplicate line ${lineNumber}: ${trimmed}`));
          }
          continue; // Skip duplicate
        } else {
          seenRules.add(trimmed);
        }
      }
      
      validLines.push(line);
      stats.valid++;
    } else {
      invalidLines.push({ line: trimmed, lineNumber, error: validation.error });
      stats.invalid++;
      
      if (forceDebug) {
        console.log(formatLogMessage('debug', `[clean] Removing invalid line ${lineNumber}: ${trimmed} (${validation.error})`));
      }
    }
  }
  
  stats.removed = stats.invalid + stats.duplicates;
  
  // Log cleaning results
  if (!silentMode) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Cleaning results for ${filePath}:`));
      console.log(formatLogMessage('debug', `  Total lines processed: ${stats.total}`));
      console.log(formatLogMessage('debug', `  Valid rules: ${stats.valid} (${stats.comments} comments)`));
      console.log(formatLogMessage('debug', `  Invalid rules: ${stats.invalid}`));
      console.log(formatLogMessage('debug', `  Duplicates: ${stats.duplicates}`));
      console.log(formatLogMessage('debug', `  Total removed: ${stats.removed}`));
    }
    
    if (invalidLines.length > 0 && forceDebug) {
      console.log(formatLogMessage('warn', `Invalid lines found:`));
      invalidLines.slice(0, 5).forEach(item => {
        console.log(formatLogMessage('warn', `  Line ${item.lineNumber}: ${item.error}`));
      });
      if (invalidLines.length > 5) {
        console.log(formatLogMessage('warn', `  ... and ${invalidLines.length - 5} more invalid lines`));
      }
    }
  }
  
  // Create cleaned content
  const cleanedContent = validLines.join('\n');
  
  // Determine output path
  const finalOutputPath = outputPath || filePath;
  
  // Create backup if requested and not in dry run mode
  if (backupOriginal && !dryRun && finalOutputPath === filePath) {
    try {
      const backupPath = `${filePath}.backup`;
      fs.copyFileSync(filePath, backupPath);
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Created backup: ${backupPath}`));
      }
    } catch (backupErr) {
      return {
        success: false,
        error: `Failed to create backup: ${backupErr.message}`,
        stats
      };
    }
  }
  
  // Write cleaned file (unless dry run)
  if (!dryRun) {
    try {
      fs.writeFileSync(finalOutputPath, cleanedContent);
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Wrote cleaned file: ${finalOutputPath}`));
      }
    } catch (writeErr) {
      return {
        success: false,
        error: `Failed to write cleaned file: ${writeErr.message}`,
        stats
      };
    }
  }
  
  return {
    success: true,
    stats,
    invalidLines,
    duplicateLines,
    modified: stats.removed > 0,
    wouldModify: dryRun && stats.removed > 0,
    backupCreated: backupOriginal && !dryRun && finalOutputPath === filePath
  };
}

/**
 * Validates full configuration object
 * @param {object} config - Complete configuration object
 * @param {object} options - Validation options
 * @returns {object} Comprehensive validation result
 */
function validateFullConfig(config, options = {}) {
  const { forceDebug = false, silentMode = false } = options;
  const globalErrors = [];
  const siteValidations = [];
  
  // Validate global configuration
  if (!config) {
    return {
      isValid: false,
      globalErrors: ['Configuration object is required'],
      siteValidations: [],
      summary: { totalSites: 0, validSites: 0, sitesWithErrors: 0, sitesWithWarnings: 0 }
    };
  }
  
  // Validate sites array
  if (!config.sites || !Array.isArray(config.sites)) {
    globalErrors.push('Configuration must contain a "sites" array');
  } else if (config.sites.length === 0) {
    globalErrors.push('Sites array cannot be empty');
  }
  
  // Validate global blocked patterns
  if (config.blocked && !Array.isArray(config.blocked)) {
    globalErrors.push('Global "blocked" must be an array');
  } else if (config.blocked) {
    config.blocked.forEach((pattern, index) => {
      const validation = validateRegexPattern(pattern);
      if (!validation.isValid) {
        globalErrors.push(`Global blocked pattern ${index}: ${validation.error}`);
      }
    });
  }

 // Validate global ignore_similar settings
 if (config.ignore_similar !== undefined && typeof config.ignore_similar !== 'boolean') {
   globalErrors.push('Global "ignore_similar" must be a boolean (true/false)');
 }
 
 if (config.ignore_similar_threshold !== undefined) {
   if (typeof config.ignore_similar_threshold !== 'number' || 
       config.ignore_similar_threshold < 0 || 
       config.ignore_similar_threshold > 100) {
     globalErrors.push('Global "ignore_similar_threshold" must be a number between 0 and 100');
   }
 }

 if (config.ignore_similar_ignored_domains !== undefined && typeof config.ignore_similar_ignored_domains !== 'boolean') {
   globalErrors.push('Global "ignore_similar_ignored_domains" must be a boolean (true/false)');
 }

  // Validate individual sites
  if (config.sites && Array.isArray(config.sites)) {
    config.sites.forEach((site, index) => {
      const siteValidation = validateSiteConfig(site, index);
      siteValidations.push(siteValidation);
    });
  }
  
  // Calculate summary
  const summary = {
    totalSites: siteValidations.length,
    validSites: siteValidations.filter(v => v.isValid).length,
    sitesWithErrors: siteValidations.filter(v => v.errors.length > 0).length,
    sitesWithWarnings: siteValidations.filter(v => v.warnings.length > 0).length
  };
  
  const isValid = globalErrors.length === 0 && summary.sitesWithErrors === 0;
  
  return {
    isValid,
    globalErrors,
    siteValidations,
    summary
  };
}

/**
 * Test domain validation with known test cases
 * @returns {boolean} True if all tests pass
 */
function testDomainValidation() {
  const testCases = [
    // Valid domains
    { domain: 'example.com', expected: true },
    { domain: 'sub.example.com', expected: true },
    { domain: 'test-site.co.uk', expected: true },
    { domain: '192.168.1.1', expected: true }, // IPv4
    { domain: '2001:db8::1', expected: true }, // IPv6
    
    // Invalid domains
    { domain: '', expected: false },
    { domain: 'example', expected: false },
    { domain: '.example.com', expected: false },
    { domain: 'example.com.', expected: false },
    { domain: 'ex..ample.com', expected: false },
    { domain: '-example.com', expected: false }
  ];
  
  let allPassed = true;
  
  testCases.forEach(({ domain, expected }) => {
    const result = isValidDomain(domain);
    if (result !== expected) {
      console.error(`Test failed for domain "${domain}": expected ${expected}, got ${result}`);
      allPassed = false;
    }
  });
  
  return allPassed;
}

/**
 * Test adblock rule validation with known test cases
 * @returns {boolean} True if all tests pass
 */
function testAdblockValidation() {
  const testCases = [
    // Valid rules
    { rule: '||example.com^', expected: true },
    { rule: '||example.com^$script', expected: true },
    { rule: '127.0.0.1 example.com', expected: true },
    { rule: 'local=/example.com/', expected: true },
    
    // Invalid rules
    { rule: '', expected: false },
    { rule: '||invalid..domain^', expected: false },
    { rule: '||.example.com^', expected: false }
  ];
  
  let allPassed = true;
  
  testCases.forEach(({ rule, expected }) => {
    const result = validateAdblockRule(rule);
    if (result.isValid !== expected) {
      console.error(`Test failed for rule "${rule}": expected ${expected}, got ${result.isValid}`);
      allPassed = false;
    }
  });
  
  return allPassed;
}

/**
 * Validates a domain and formats it according to specified output options
 * @param {string} domain - The domain to validate and format
 * @param {object} options - Formatting options
 * @returns {string|object} Formatted domain string or error object
 */
function formatDomainWithValidation(domain, options = {}) {
  const {
    localhost = false,
    localhostAlt = false,
    plain = false,
    dnsmasq = false,
    dnsmasqOld = false,
    unbound = false,
    privoxy = false,
    pihole = false,
    adblockRules = false,
    resourceType = ''
  } = options;

  // Validate domain first
  if (!isValidDomain(domain)) {
    return {
      isValid: false,
      error: `Invalid domain format: ${domain}`,
      formattedRule: null
    };
  }

  // Format according to specified options (priority order)
  if (pihole) {
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
    return `||${domain}^$${resourceType}`;
  } else if (plain) {
    return domain;
  } else {
    // Default adblock format
    return `||${domain}^`;
  }
}

module.exports = {
  isValidDomain,
  isValidDomainLabel,
  isValidTLD,
  isIPAddress,
  isIPv4,
  isIPv6,
  validateRegexPattern,
  validateAdblockModifiers,
  validateAdblockRule,
  validateRulesetFile,
  cleanRulesetFile,
  validateSiteConfig,
  validateFullConfig,
  testDomainValidation,
  testAdblockValidation,
  formatDomainWithValidation
};