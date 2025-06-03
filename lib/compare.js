const fs = require('fs');
const path = require('path');

/**
 * Loads rules from a comparison file and returns them as a Set for fast lookup
 * @param {string} compareFilePath - Path to the file containing existing rules
 * @param {boolean} forceDebug - Whether to show debug output
 * @returns {Set<string>} Set of existing rules (normalized)
 */
function loadComparisonRules(compareFilePath, forceDebug = false) {
  try {
    if (!fs.existsSync(compareFilePath)) {
      throw new Error(`Comparison file not found: ${compareFilePath}`);
    }
    
    const content = fs.readFileSync(compareFilePath, 'utf8');
    const lines = content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('!') && !line.startsWith('#')); // Skip comments and empty lines
    
    const rules = new Set();
    
    for (const line of lines) {
      // Normalize the rule by removing different prefixes/formats
      let normalizedRule = line;
      
      // Remove adblock prefixes (||, |, etc.)
      normalizedRule = normalizedRule.replace(/^\|\|/, '');
      normalizedRule = normalizedRule.replace(/^\|/, '');
      
      // Remove localhost prefixes
      normalizedRule = normalizedRule.replace(/^127\.0\.0\.1\s+/, '');
      normalizedRule = normalizedRule.replace(/^0\.0\.0\.0\s+/, '');
      
      // Remove adblock suffixes and modifiers
      normalizedRule = normalizedRule.replace(/\^.*$/, ''); // Remove ^ and everything after
      normalizedRule = normalizedRule.replace(/\$.*$/, ''); // Remove $ and everything after
      
      // Clean up and add to set
      normalizedRule = normalizedRule.trim();
      if (normalizedRule) {
        rules.add(normalizedRule);
      }
    }
    
    if (forceDebug) {
      console.log(`[debug] Loaded ${rules.size} comparison rules from ${compareFilePath}`);
    }
    
    return rules;
  } catch (error) {
    throw new Error(`Failed to load comparison file: ${error.message}`);
  }
}

/**
 * Normalizes a rule to match the format used in comparison
 * @param {string} rule - The rule to normalize
 * @returns {string} Normalized rule
 */
function normalizeRule(rule) {
  let normalized = rule;
  
  // Remove adblock prefixes
  normalized = normalized.replace(/^\|\|/, '');
  normalized = normalized.replace(/^\|/, '');
  
  // Remove localhost prefixes
  normalized = normalized.replace(/^127\.0\.0\.1\s+/, '');
  normalized = normalized.replace(/^0\.0\.0\.0\s+/, '');
  
  // Remove adblock suffixes and modifiers
  normalized = normalized.replace(/\^.*$/, '');
  normalized = normalized.replace(/\$.*$/, '');
  
  return normalized.trim();
}

/**
 * Filters out rules that exist in the comparison set
 * @param {Array<string>} rules - Array of rules to filter
 * @param {Set<string>} comparisonRules - Set of existing rules
 * @param {boolean} forceDebug - Whether to show debug output
 * @returns {Array<string>} Filtered rules array
 */
function filterUniqueRules(rules, comparisonRules, forceDebug = false) {
  const uniqueRules = [];
  let duplicateCount = 0;
  
  for (const rule of rules) {
    // Always keep comment lines (starting with !)
    if (rule.startsWith('!')) {
      uniqueRules.push(rule);
      continue;
    }
    
    const normalized = normalizeRule(rule);
    
    if (!comparisonRules.has(normalized)) {
      uniqueRules.push(rule);
    } else {
      duplicateCount++;
      if (forceDebug) {
        console.log(`[debug] Filtered duplicate rule: ${rule} (normalized: ${normalized})`);
      }
    }
  }
  
  if (forceDebug) {
    console.log(`[debug] Filtered ${duplicateCount} duplicate rules, ${uniqueRules.filter(r => !r.startsWith('!')).length} unique rules remaining`);
  }
  
  return uniqueRules;
}

module.exports = {
  loadComparisonRules,
  normalizeRule,
  filterUniqueRules
};