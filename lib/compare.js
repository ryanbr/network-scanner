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
 * Filters out rules that exist in the comparison set, with smart title handling
 * @param {Array<string>} rules - Array of rules to filter
 * @param {Set<string>} comparisonRules - Set of existing rules
 * @param {boolean} forceDebug - Whether to show debug output
 * @returns {Array<string>} Filtered rules array
 */
function filterUniqueRules(rules, comparisonRules, forceDebug = false) {
  const result = [];
  let duplicateCount = 0;
  let orphanedTitles = 0;
  
  // Group rules by titles for smart filtering
  const groups = [];
  let currentGroup = { title: null, rules: [] };
  
  for (const rule of rules) {
    if (rule.startsWith('!')) {
      // Start a new group when we encounter a title
      if (currentGroup.title !== null || currentGroup.rules.length > 0) {
        groups.push(currentGroup);
      }
      currentGroup = { title: rule, rules: [] };
    } else {
      // Add rule to current group
      currentGroup.rules.push(rule);
    }
  }
  
  // Don't forget the last group
  if (currentGroup.title !== null || currentGroup.rules.length > 0) {
    groups.push(currentGroup);
  }
  
  // Process each group
  for (const group of groups) {
    const filteredRules = [];
    
    // Filter rules in this group
    for (const rule of group.rules) {
      const normalized = normalizeRule(rule);
      
      if (!comparisonRules.has(normalized)) {
        filteredRules.push(rule);
      } else {
        duplicateCount++;
        if (forceDebug) {
          console.log(`[debug] Filtered duplicate rule: ${rule} (normalized: ${normalized})`);
        }
      }
    }
    
    // Only include title if there are remaining rules, or if there's no title (rules without titles)
    if (group.title && filteredRules.length > 0) {
      result.push(group.title);
      result.push(...filteredRules);
    } else if (!group.title && filteredRules.length > 0) {
      // Rules without a title - just add them
      result.push(...filteredRules);
    } else if (group.title && filteredRules.length === 0) {
      // Title with no remaining rules - this is an orphaned title
      orphanedTitles++;
      if (forceDebug) {
        console.log(`[debug] Filtered orphaned title: ${group.title} (no unique rules remaining)`);
      }
    }
  }
  
  if (forceDebug) {
    console.log(`[debug] Filtered ${duplicateCount} duplicate rules and ${orphanedTitles} orphaned titles`);
    console.log(`[debug] ${result.filter(r => !r.startsWith('!')).length} unique rules remaining`);
  }
  
  return result;
}

module.exports = {
  loadComparisonRules,
  normalizeRule,
  filterUniqueRules
};
