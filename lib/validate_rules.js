const net = require('node:net');
const { formatLogMessage, messageColors } = require('./colorize');
// Cross-module validators wired into site-config validation — previously
// each had to be called separately (or wasn't called at all). Centralizing
// here means a single validateSiteConfig surfaces ALL misconfigurations
// at startup instead of mid-scan.
//   - validateSearchString: had ZERO callers anywhere before this hookup.
//   - validateVpnConfig / validateOvpnConfig: called inside connectForSite
//     per-site at scan time. Adding here catches errors at startup.
const { validateSearchString } = require('./searchstring');
const { validateVpnConfig: validateWgConfig, normalizeVpnConfig: normalizeWgConfig } = require('./wireguard_vpn');
const { validateOvpnConfig, normalizeOvpnConfig } = require('./openvpn_vpn');
const CLEAN_TAG = messageColors.processing('[clean]');

// Pre-compiled regex constants for validation. IPv4/IPv6 validation now
// uses Node's built-in net.isIP() — the old hand-rolled regexes were
// incomplete (missing IPv4-mapped IPv6, zone identifiers, etc.) and
// silently accepted some malformed inputs like '2001:db8:::1'.
const REGEX_LABEL = /^[a-zA-Z0-9-]+$/;
const REGEX_TLD = /^[a-zA-Z][a-zA-Z0-9]*$/;

// Module-level Set of valid adblock filter modifiers. Was previously
// re-allocated inside validateAdblockModifiers on every call — for a
// 100k-line filter list that's 100k identical Set allocations.
const VALID_MODIFIERS = new Set([
  // Resource type modifiers
  'script', 'stylesheet', 'image', 'object', 'xmlhttprequest', 'subdocument',
  'ping', 'websocket', 'webrtc', 'document', 'elemhide', 'generichide',
  'genericblock', 'popup', 'font', 'media', 'other',
  // Party modifiers
  'third-party', 'first-party', '~third-party', '~first-party',
  // Domain modifiers (domain= is validated separately below)
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
  if (!REGEX_LABEL.test(label)) {
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
  if (!REGEX_TLD.test(tld)) {
    return false;
  }
  
  return true;
}

/**
 * Checks if a string is an IP address (IPv4 or IPv6).
 * Delegates to Node's net.isIP() — standards-compliant, no regex to
 * maintain. Returns true for any valid IP form including IPv4-mapped
 * IPv6 (::ffff:192.0.2.1) which the old hand-rolled regex missed.
 * @param {string} str - String to check
 * @returns {boolean} True if it's an IP address
 */
function isIPAddress(str) {
  return net.isIP(str) !== 0;
}

/**
 * @param {string} str
 * @returns {boolean} True if valid IPv4
 */
function isIPv4(str) {
  return net.isIPv4(str);
}

/**
 * @param {string} str
 * @returns {boolean} True if valid IPv6
 */
function isIPv6(str) {
  return net.isIPv6(str);
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
    // Handle /pattern/flags literal syntax. The old `^\/(.*)\/$/` strip
    // didn't match patterns with flags ('/foo/i'), so they passed through
    // unchanged to `new RegExp('/foo/i')` — which compiled a regex that
    // matched the LITERAL string '/foo/i' instead of the intended `foo`
    // pattern with the `i` flag. Silent acceptance of malformed input.
    const literalMatch = pattern.match(/^\/(.*)\/([gimsuy]*)$/);
    if (literalMatch) {
      new RegExp(literalMatch[1], literalMatch[2]);
    } else {
      new RegExp(pattern);
    }
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
    
    if (VALID_MODIFIERS.has(modifier) || VALID_MODIFIERS.has(baseModifier)) {
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

  // Strip @@ exception (whitelist) prefix and run the rest of validation
  // on the remainder. Exception rules are standard adblock syntax
  // (e.g. '@@||example.com^', '@@||example.com^$image') and appear
  // throughout real-world filter lists like EasyList — without this,
  // `nwss --validate-rules easylist.txt` flagged every exception as
  // 'Unrecognized rule format'. We attach `isException: true` to the
  // result so downstream consumers can see the whitelist intent.
  let isException = false;
  let working = trimmedRule;
  if (working.startsWith('@@')) {
    isException = true;
    working = working.substring(2);
    if (!working) {
      return { isValid: false, format: 'unknown', error: '@@ exception prefix with no rule body' };
    }
  }

  // @@ only makes sense as a prefix for adblock-format rules. Bail
  // early if it's prefixing something else (e.g. '@@127.0.0.1 host'
  // is meaningless — localhost format has no exception concept).
  if (isException &&
      !(working.startsWith('||') && working.includes('^')) &&
      !(working.includes('^$'))) {
    return {
      isValid: false,
      format: 'unknown',
      isException: true,
      error: '@@ exception prefix only valid for adblock-format rules'
    };
  }

  // Adblock format: ||domain.com^ or ||domain.com^$script,third-party.
  // Uses `working` (post-@@-strip body) instead of `trimmedRule`.
  const ruleBody = working;
  if (ruleBody.startsWith('||') && ruleBody.includes('^')) {
    const parts = ruleBody.substring(2).split('^');
    const domain = parts[0];

    if (!isValidDomain(domain)) {
      return { isValid: false, format: 'adblock', isException, error: `Invalid domain in adblock rule: ${domain}` };
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
          isException,
          error: `${modifierValidation.error} in rule: ${trimmedRule}`,
          domain,
          modifiers: modifierValidation.validModifiers || []
        };
      }
    }

    return {
      isValid: true,
      format: 'adblock',
      isException,
      domain,
      modifiers: modifierValidation.modifiers,
      hasModifiers: modifiers.length > 0
    };
  }

  // Basic adblock format without ||: domain.com^$modifier
  if (ruleBody.includes('^') && ruleBody.includes('$')) {
    const parts = ruleBody.split('^$');
    if (parts.length === 2) {
      const domain = parts[0];
      const modifiers = parts[1];

      if (!isValidDomain(domain)) {
        return { isValid: false, format: 'adblock-basic', isException, error: `Invalid domain in adblock rule: ${domain}` };
      }

      const modifierValidation = validateAdblockModifiers(modifiers);
      if (!modifierValidation.isValid) {
        return {
          isValid: false,
          format: 'adblock-basic',
          isException,
          error: modifierValidation.error,
          domain
        };
      }

      return {
        isValid: true,
        format: 'adblock-basic',
        isException,
        domain,
        modifiers: modifierValidation.modifiers
      };
    }
  }
  
  // Removed: "Simple adblock format" branch for `||domain.com^` without
  // modifiers. The main `||...^` branch above already handles this case
  // (parts becomes ['domain.com', ''] on split, the empty modifier check
  // falls through to the success return as format='adblock'). This branch
  // was unreachable dead code.

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
        // Lines remaining in the file = total lines − current index − 1.
        // (Previously `stats.total - i - 1`, which mixed "non-empty lines
        // processed" with "file line index" and went negative when empties
        // were interleaved.)
        errors.push(`... (stopping after ${maxErrors} errors, ${lines.length - i - 1} lines remaining)`);
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

  // Cross-module validation: searchstring/searchstring_and. validateSearchString
  // catches things like both-defined-at-once (forbidden), empty arrays, length
  // caps, non-string elements. Before this call was added, misconfigured
  // searchstring values silently passed validation and only surfaced as
  // runtime TypeErrors mid-scan.
  if (siteConfig.searchstring !== undefined || siteConfig.searchstring_and !== undefined) {
    const ssValidation = validateSearchString(siteConfig.searchstring, siteConfig.searchstring_and);
    if (!ssValidation.isValid) {
      errors.push(`Site ${siteIndex}: ${ssValidation.error}`);
    }
  }

  // Cross-module validation: VPN configs. nwss.js dispatches on field
  // presence — `vpn` → WireGuard, `openvpn` → OpenVPN. Both validators
  // require a normalized config object, so normalize first. Previously
  // VPN errors only surfaced inside connectForSite at scan time; now
  // misconfigured configs fail loudly at startup.
  if (siteConfig.vpn !== undefined && siteConfig.openvpn !== undefined) {
    warnings.push(`Site ${siteIndex}: both 'vpn' (WireGuard) and 'openvpn' set — runtime dispatches to WireGuard, openvpn config will be ignored`);
  }
  if (siteConfig.vpn !== undefined) {
    const normalized = normalizeWgConfig(siteConfig.vpn);
    const vpnValidation = validateWgConfig(normalized);
    if (!vpnValidation.isValid) {
      vpnValidation.errors.forEach(e => errors.push(`Site ${siteIndex} (WireGuard): ${e}`));
    }
    // Validator warnings (e.g. "requires root") propagate too.
    (vpnValidation.warnings || []).forEach(w => warnings.push(`Site ${siteIndex} (WireGuard): ${w}`));
  }
  if (siteConfig.openvpn !== undefined && siteConfig.vpn === undefined) {
    const normalized = normalizeOvpnConfig(siteConfig.openvpn);
    const ovpnValidation = validateOvpnConfig(normalized);
    if (!ovpnValidation.isValid) {
      ovpnValidation.errors.forEach(e => errors.push(`Site ${siteIndex} (OpenVPN): ${e}`));
    }
    (ovpnValidation.warnings || []).forEach(w => warnings.push(`Site ${siteIndex} (OpenVPN): ${w}`));
  }

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
            console.log(formatLogMessage('debug', `${CLEAN_TAG} Removing duplicate line ${lineNumber}: ${trimmed}`));
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
        console.log(formatLogMessage('debug', `${CLEAN_TAG} Removing invalid line ${lineNumber}: ${trimmed} (${validation.error})`));
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

// ─── Per-site config normalization (runs on every scan, not just --validate-config) ───
//
// Catches the silent-failure class that bit a user across multiple scan iterations:
//   1. Typo'd siteConfig keys (whois_terms vs whois) silently ignored.
//   2. Boolean fields given truthy/falsy non-boolean values (interact: 1 vs interact: true)
//      silently disabled by strict `=== true` checks downstream.
//   3. Misleading downstream warnings that blame the wrong field.
//
// normalizeSiteConfig() mutates siteConfig in place (coercing 1→true, etc) and returns
// warnings the caller surfaces. Designed to run at scan startup, ALWAYS, not gated on
// --validate-config (which most users never run).

// Whitelist of every siteConfig.X key read across nwss.js + lib/*.js.
// Regenerate via BOTH:
//   grep -hoE "siteConfig\.[a-zA-Z_][a-zA-Z0-9_]*" nwss.js lib/*.js | sort -u
//   grep -hoE "siteConfig\[['\"][^'\"]+['\"]\]" nwss.js lib/*.js | sort -u
// The second pattern catches bracket-notation access required for keys with
// hyphens (e.g. 'dig-or', 'whois-or'). Dot-notation grep alone missed these
// and produced false 'unknown siteConfig key' warnings for valid config.
// Also grep for destructured siteConfig keys (master destructure block in
// processUrl) — those don't show up in either pattern.
const KNOWN_SITE_CONFIG_KEYS = new Set([
  'adblock_rules', 'blocked', 'bypass_cache', 'capture_popups',
  'capture_popups_max_depth', 'capture_popups_window_ms', 'cdp', 'cdp_specific',
  'clear_sitedata', 'clear_sitedata_full_on_reload',
  'cloudflare_bypass', 'cloudflare_max_retries', 'comments',
  'cloudflare_parallel_detection', 'cloudflare_phish', 'cloudflare_retry_on_error',
  'css_blocked', 'curl', 'cursor_mode', 'custom_headers', 'delay',
  'delay_uncapped', 'detect_js_patterns', 'dig', 'dig-or', 'digRecordType', 'dig_subdomain',
  'disable_adblock', 'dnsmasq', 'dnsmasq_old', 'evaluateOnNewDocument',
  'even_blocked',
  'filterRegex', 'fingerprint_protection', 'firstParty', 'flowproxy_additional_delay',
  'flowproxy_delay', 'flowproxy_detection', 'flowproxy_js_timeout', 'flowproxy_nav_timeout',
  'flowproxy_page_timeout', 'forcereload', 'ghost_cursor_duration',
  'ghost_cursor_hesitate', 'ghost_cursor_overshoot', 'ghost_cursor_speed',
  'goto_options', 'grep', 'headful', 'ignore_similar', 'ignore_similar_ignored_domains',
  'ignore_similar_threshold', 'interact', 'interact_click_count', 'interact_clicks',
  'interact_duration', 'interact_intensity', 'interact_scrolling', 'isBrave',
  'js_redirect_timeout', 'localhost', 'max_redirects', 'openvpn', 'pihole',
  'output_regex',
  'plain', 'privoxy', 'proxy', 'proxy_bypass', 'proxy_debug', 'proxy_remote_dns',
  'realistic_click', 'referrer_disable', 'referrer_headers', 'regex_and',
  'reload', 'resourceTypes', 'screenshot', 'searchstring', 'searchstring_and',
  'socks5_bypass', 'socks5_debug', 'socks5_proxy', 'socks5_remote_dns',
  'subDomains',
  'thirdParty', 'timeout', 'unbound', 'url', 'userAgent', 'verbose', 'vpn',
  'whois', 'whois-or', 'whois_delay', 'whois_max_retries', 'whois_retry_on_error',
  'whois_retry_on_timeout', 'whois_server', 'whois_server_mode',
  'whois_timeout_multiplier', 'whois_use_fallback', 'window_cleanup',
  'window_cleanup_threshold',
  // Internal sentinel added by nwss.js when fanning array URLs into tasks.
  '_originalUrl',
]);

// Boolean siteConfig fields where strict `=== true` is used downstream.
// Listed only for fields with UNAMBIGUOUS boolean semantics — fields with
// multi-type overloads stay out:
//   forcereload         : true | string[]
//   cloudflare_bypass   : true | 'debug'
//   cloudflare_phish    : true | 'debug'
//   window_cleanup      : true | 'all' | 'realtime'
//   cursor_mode         : string ('ghost')
// Update both this set AND the strict-equality call sites if a new boolean
// siteConfig field is added.
const BOOLEAN_SITE_CONFIG_FIELDS = new Set([
  'adblock_rules', 'bypass_cache', 'capture_popups', 'cdp', 'clear_sitedata',
  'clear_sitedata_full_on_reload', 'curl', 'delay_uncapped',
  'detect_js_patterns', 'dig_subdomain',
  'disable_adblock', 'dnsmasq', 'dnsmasq_old', 'evaluateOnNewDocument',
  'even_blocked', 'firstParty', 'flowproxy_detection',
  'grep', 'headful', 'ignore_similar', 'ignore_similar_ignored_domains',
  'interact', 'interact_clicks', 'interact_scrolling', 'isBrave', 'localhost',
  'pihole', 'plain', 'privoxy', 'proxy_debug', 'proxy_remote_dns',
  'realistic_click', 'referrer_disable', 'regex_and', 'screenshot',
  'searchstring_and', 'socks5_debug', 'socks5_remote_dns', 'thirdParty',
  'unbound', 'whois_retry_on_error', 'whois_retry_on_timeout', 'whois_use_fallback',
]);

// Fields that accept BOTH `"x"` (single term) and `["x", "y"]` (multi-term).
// Downstream consumers (nwss.js line ~2824, lib/nettools.js line ~1149-1152)
// do `Array.isArray(val) && val.length > 0` checks, so a string value
// previously caused silent feature-disable. normalizeSiteConfig() now wraps
// any string value in a single-element array so both forms are first-class.
// Non-string non-array values still warn (and stay as-is, since we don't
// know how to coerce them).
const STRING_TO_ARRAY_FIELDS = new Set([
  'dig', 'dig-or', 'whois', 'whois-or',
]);

// Truthy-but-not-true → true. Falsy-but-not-false → false. Otherwise leave alone.
// Strings are lower-cased before matching so "True"/"TRUE"/"Yes"/etc all match.
function _coerceBooleanLike(val) {
  if (val === true || val === false) return { coerced: false, value: val };
  const s = typeof val === 'string' ? val.toLowerCase() : val;
  if (s === 1 || s === '1' || s === 'true' || s === 'yes' || s === 'on') {
    return { coerced: true, value: true };
  }
  if (s === 0 || s === '0' || s === 'false' || s === 'no' || s === 'off') {
    return { coerced: true, value: false };
  }
  return { coerced: false, value: val };
}

// Tiny Levenshtein for "did you mean?" suggestions. Inlined rather than
// imported from lib/ignore_similar (which has its own dependency tree we
// don't want to drag into validation) -- 18 lines of well-known algorithm.
function _editDistance(a, b) {
  if (a === b) return 0;
  if (!a) return b.length;
  if (!b) return a.length;
  const m = a.length, n = b.length;
  let prev = new Array(n + 1);
  let curr = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]
        : 1 + Math.min(prev[j - 1], prev[j], curr[j - 1]);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

// Suggest a known key for an unknown one. Two parallel candidate searches,
// then pick the better signal:
//
//   1. EDIT-DISTANCE candidate — classic typo case ('intract' → 'interact').
//      Threshold scales with the unknown key's length (40%, min 2) so short
//      typos stay matchable.
//
//   2. PREFIX candidate — "user added a suffix to a known root" case.
//      'whois_terms' starts with 'whois' (known key) → suggest 'whois'.
//      Requires the prefix to be at least 3 chars to avoid spurious matches
//      on accidental 1-2 letter prefixes. Among multiple prefix candidates,
//      we take the LONGEST (most specific category boundary).
//
// Ranking: if there's a very close edit-distance match (≤2 edits), prefer
// it — almost certainly a misspelling of that specific key (e.g.
// 'whois_max_retri' → 'whois_max_retries' at distance 2 beats the prefix
// match 'whois'). Otherwise prefer the prefix match when present, since
// "extra suffix on a known root" is a stronger signal than a 4+-edit
// distance to an unrelated key.
function _suggestKey(unknownKey, knownKeys) {
  const threshold = Math.max(2, Math.floor(unknownKey.length * 0.4));
  let distBest = null, distBestVal = Infinity;
  let prefixBest = null, prefixBestLen = 0;

  for (const k of knownKeys) {
    const d = _editDistance(unknownKey, k);
    if (d < distBestVal && d <= threshold) {
      distBestVal = d;
      distBest = k;
    }
    if (k.length >= 3 && unknownKey !== k &&
        unknownKey.startsWith(k) && k.length > prefixBestLen) {
      prefixBest = k;
      prefixBestLen = k.length;
    }
  }

  if (distBest && distBestVal <= 2) return distBest;
  return prefixBest || distBest;
}

/**
 * Per-site validation + boolean coercion run at scan startup (always, not
 * gated on --validate-config).
 *
 * Mutates siteConfig in place to coerce boolean-like values (1, 0, "true",
 * "false", "yes", "no", "on", "off") to true/false for fields in
 * BOOLEAN_SITE_CONFIG_FIELDS. Returns warnings the caller surfaces via the
 * usual logging path.
 *
 * Catches the failure classes:
 *   1. Unknown siteConfig keys → typo warning + "did you mean?" suggestion.
 *      Example: 'whois_terms' → "did you mean 'whois'?"
 *   2. Boolean field with truthy non-boolean value → coerce + warn.
 *      Example: 'interact: 1' → coerced to 'interact: true', warning emitted.
 *   3. Boolean field with non-boolean non-truthy value → warn only, no coerce.
 *      Example: 'interact: "maybe"' → warned, left alone.
 *
 * @param {object} siteConfig - mutated in place
 * @param {number} siteIndex - for warning messages
 * @returns {{warnings: string[], errors: string[]}}
 */
function normalizeSiteConfig(siteConfig, siteIndex = 0) {
  const warnings = [];
  const errors = [];
  if (!siteConfig || typeof siteConfig !== 'object') {
    errors.push(`Site ${siteIndex}: not an object`);
    return { warnings, errors };
  }
  const tag = siteConfig.url ? `Site ${siteIndex} (${siteConfig.url})` : `Site ${siteIndex}`;

  // 1. Unknown-key detection. Scan every top-level key; report with
  // Levenshtein-based suggestion when close to a known key.
  for (const key of Object.keys(siteConfig)) {
    if (KNOWN_SITE_CONFIG_KEYS.has(key)) continue;
    const suggestion = _suggestKey(key, KNOWN_SITE_CONFIG_KEYS);
    warnings.push(
      `${tag}: unknown siteConfig key '${key}'` +
      (suggestion ? ` — did you mean '${suggestion}'?` : '') +
      ' — value will be ignored at runtime'
    );
  }

  // 2. Boolean coercion for known boolean fields. Mutates siteConfig.
  for (const field of BOOLEAN_SITE_CONFIG_FIELDS) {
    if (!(field in siteConfig)) continue;
    const original = siteConfig[field];
    if (original === undefined || original === null) continue;
    const { coerced, value } = _coerceBooleanLike(original);
    if (coerced) {
      siteConfig[field] = value;
      warnings.push(
        `${tag}: '${field}' value ${JSON.stringify(original)} should be ${value} ` +
        `(boolean) — coerced for compatibility; please update config to use ${value}`
      );
    } else if (typeof original !== 'boolean') {
      warnings.push(
        `${tag}: '${field}' should be boolean (true/false), got ${JSON.stringify(original)} ` +
        `— may not work as expected (downstream strict-equality check will treat as disabled)`
      );
    }
  }

  // 2b. output_regex must be a compilable regex. An invalid one is silently
  // disabled at runtime (the use-site try/catch falls back to ||host^), so
  // surface it here at load time where the user can fix it.
  if ('output_regex' in siteConfig && siteConfig.output_regex != null && siteConfig.output_regex !== '') {
    if (typeof siteConfig.output_regex !== 'string') {
      warnings.push(`${tag}: 'output_regex' should be a string regex, got ${JSON.stringify(siteConfig.output_regex)} — will be ignored`);
    } else {
      try {
        new RegExp(siteConfig.output_regex);
      } catch (e) {
        warnings.push(`${tag}: 'output_regex' is not a valid regex (${e.message}) — will be ignored, output falls back to ||host^`);
      }
    }
  }

  // 3. String → single-element array coercion for fields that accept both
  // forms (dig, dig-or, whois, whois-or). Downstream consumers all gate on
  // Array.isArray(), so a bare string value previously silently disabled
  // the feature. Wrapping in [val] is the canonical "user gave one term"
  // outcome and matches user intent. Both forms are first-class — no
  // warning is emitted on the string path, just the in-place mutation.
  //
  // Empty string is left alone: the downstream `siteConfig.dig && ...`
  // check sees the empty string as falsy and disables the feature. If we
  // coerced "" to [""], nettools' array.length>0 check would PASS and then
  // every dig/whois output would match (`"".includes(anything)` is true),
  // turning a clearly-empty config into a match-everything one.
  //
  // Non-string non-array values DO warn since we can't sensibly coerce.
  for (const field of STRING_TO_ARRAY_FIELDS) {
    if (!(field in siteConfig)) continue;
    const val = siteConfig[field];
    if (val === undefined || val === null) continue;
    if (typeof val === 'string') {
      if (val.length > 0) siteConfig[field] = [val];
      // empty string: leave as-is (preserves disable-on-falsy semantics)
    } else if (!Array.isArray(val)) {
      warnings.push(
        `${tag}: '${field}' should be a string or array of strings, got ${typeof val} ` +
        `(${JSON.stringify(val).slice(0, 60)}) — feature will be disabled at runtime`
      );
    }
  }

  // 4. Dependent-flag implication: clear_sitedata_full_on_reload only takes
  // effect inside the `if (clear_sitedata === true)` guard at nwss.js:4627
  // — setting it WITHOUT clear_sitedata: true silently does nothing. That's
  // the same silent-failure pattern this validator was created to prevent,
  // so auto-enable clear_sitedata and warn the user. They almost certainly
  // intended both to be true; opt-in to heavy-storage clearing without
  // opt-in to clearing-at-all doesn't make sense as a configuration.
  if (siteConfig.clear_sitedata_full_on_reload === true &&
      siteConfig.clear_sitedata !== true) {
    siteConfig.clear_sitedata = true;
    warnings.push(
      `${tag}: 'clear_sitedata_full_on_reload: true' requires 'clear_sitedata: true' ` +
      `— auto-enabled clear_sitedata for compatibility; please add 'clear_sitedata: true' ` +
      `to your config explicitly`
    );
  }

  return { warnings, errors };
}

// Public surface used by nwss.js (validateRulesetFile, validateFullConfig,
// testDomainValidation, cleanRulesetFile, normalizeSiteConfig). The rest
// (isValidDomain, isValidDomainLabel, isValidTLD, isIPAddress, isIPv4, isIPv6,
// validateRegexPattern, validateAdblockModifiers, validateAdblockRule,
// validateSiteConfig) stay internal-helper-but-exported for now since
// downstream callers MAY import them via the dotted path even if grep
// shows no current consumers — domain validators are the kind of thing
// that gets added to in future. testAdblockValidation and
// formatDomainWithValidation were removed entirely (zero callers
// anywhere; formatDomainWithValidation looked like an old implementation
// superseded by lib/output.js).
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
  normalizeSiteConfig,
  testDomainValidation
};