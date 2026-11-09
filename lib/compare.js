const fs = require('fs');
const { formatLogMessage, messageColors } = require('./colorize');

// Subsystem tag matches the project convention used by other modules
// (lib/adblock.js, lib/adblock-rust.js, flowproxy, cloudflare, curl, grep, etc.).
const COMPARE_TAG = messageColors.processing('[compare]');

// Pre-compiled regexes for rule normalization (shared across functions)
const RE_ADBLOCK_PREFIX = /^\|\|?/;
const RE_LOCALHOST_127 = /^127\.0\.0\.1\s+/;
const RE_LOCALHOST_000 = /^0\.0\.0\.0\s+/;
const RE_CARET_SUFFIX = /\^.*$/;
const RE_DOLLAR_SUFFIX = /\$.*$/;
// Inline hosts-file comments: `0.0.0.0 ads.example.com  # tracker`. Must be
// stripped before the prefix/suffix passes so the host token isn't left with
// trailing annotation text that would never match an incoming rule.
const RE_INLINE_COMMENT = /\s+#.*$/;

// Output formats that are NOT adblock syntax. The strip chain below is written
// for `||host^` and hosts lines; applied to one of these it is destructive.
// Pi-hole is the measured case: formatDomain emits `(^|\.)host\.com$`, whose
// '^' sits at index 1, so RE_CARET_SUFFIX reduced EVERY pihole rule to '(' --
// the whole comparison set collapsed to that one key and every rule the scan
// produced was filtered out as a duplicate, reported as a clean dedupe. The
// other four prefixes only ever matched byte-identical lines, which is
// survivable, but they have no business in an adblock strip chain either.
const NON_ADBLOCK_PREFIXES = [
  '(^|\\.',       // pihole:      (^|\.)host\.com$
  'local-zone: "', // unbound:     local-zone: "host." always_null
  'local=/',       // dnsmasq:     local=/host/
  'server=/',      // dnsmasq old: server=/host/
  '{ +block } '    // privoxy:     { +block } .host
];

function normalizeRuleInline(rule) {
  const line = rule.replace(RE_INLINE_COMMENT, '').trim();

  // Non-adblock formats compare as whole lines (same format on both sides).
  for (let i = 0; i < NON_ADBLOCK_PREFIXES.length; i++) {
    if (line.startsWith(NON_ADBLOCK_PREFIXES[i])) return line;
  }

  // Adblock / hosts / plain, which stay mutually comparable by design.
  return line
    .replace(RE_ADBLOCK_PREFIX, '')
    .replace(RE_LOCALHOST_127, '')
    .replace(RE_LOCALHOST_000, '')
    .replace(RE_CARET_SUFFIX, '')
    .replace(RE_DOLLAR_SUFFIX, '')
    .trim();
}

/**
 * Loads rules from a comparison file and returns them as a Set for fast lookup
 * @param {string} compareFilePath - Path to the file containing existing rules
 * @param {boolean} forceDebug - Whether to show debug output
 * @returns {Set<string>} Set of existing rules (normalized)
 */
function loadComparisonRules(compareFilePath, forceDebug = false) {
  try {
    const content = fs.readFileSync(compareFilePath, 'utf8');
    const lines = content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('!') && !line.startsWith('#')); // Skip comments and empty lines
    
    const rules = new Set();
    
    for (const line of lines) {
      const normalizedRule = normalizeRuleInline(line);
      if (normalizedRule) {
        rules.add(normalizedRule);
      }
    }
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${COMPARE_TAG} Loaded ${rules.size} comparison rules from ${compareFilePath}`));
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
  return normalizeRuleInline(rule);
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
  
  // Group rules under their title BLOCK. buildOutputLines emits two or three
  // comment lines per site (`! <url>`, `! Redirected from:`, `! Regex:`), so a
  // title is a RUN of consecutive '!' lines, not a single one. Treating each
  // line as its own title closed a group with no rules for every line but the
  // last, and the orphan branch below then deleted them -- `! <url>`, the line
  // that says which page a rule came from, was dropped from every scan run
  // with --titles --compare, and counted as an orphaned title in the debug log.
  const groups = [];
  let currentGroup = { title: [], rules: [] };

  for (const rule of rules) {
    if (rule.startsWith('!')) {
      // A new group only once the current one has rules; consecutive comment
      // lines belong to the same header block.
      if (currentGroup.rules.length > 0) {
        groups.push(currentGroup);
        currentGroup = { title: [], rules: [] };
      }
      currentGroup.title.push(rule);
    } else {
      // Add rule to current group
      currentGroup.rules.push(rule);
    }
  }

  // Don't forget the last group
  if (currentGroup.title.length > 0 || currentGroup.rules.length > 0) {
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
          console.log(formatLogMessage('debug', `${COMPARE_TAG} Filtered duplicate rule: ${rule} (normalized: ${normalized})`));
        }
      }
    }
    
    // Keep or drop the header block as a unit: a title line is only orphaned
    // when its whole group lost every rule.
    if (filteredRules.length > 0) {
      if (group.title.length > 0) {
        result.push(...group.title);
      }
      result.push(...filteredRules);
    } else if (group.title.length > 0) {
      // Title block with no remaining rules - these are orphaned titles
      orphanedTitles += group.title.length;
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${COMPARE_TAG} Filtered orphaned title: ${group.title.join(' / ')} (no unique rules remaining)`));
      }
    }
  }

  if (forceDebug) {
    console.log(formatLogMessage('debug', `${COMPARE_TAG} Filtered ${duplicateCount} duplicate rules and ${orphanedTitles} orphaned titles`));
    console.log(formatLogMessage('debug', `${COMPARE_TAG} ${result.filter(r => !r.startsWith('!')).length} unique rules remaining`));
  }
  
  return result;
}

module.exports = {
  loadComparisonRules,
  filterUniqueRules
};
