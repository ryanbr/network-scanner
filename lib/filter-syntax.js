/**
 * filter-syntax.js — where a filter rule's options begin, and what they are.
 *
 * Shared because FOUR call sites need the same answer and had three copies of
 * the arithmetic between them: parseRule, the unsupported-option gate and
 * createPopupSignalMatcher in lib/adblock.js, plus the actionable-rule count in
 * lib/adblock-rust.js. The two engine modules are deliberately independent
 * drop-in replacements and do not require each other, so this follows the
 * lib/site-scope.js precedent of a third module rather than coupling them.
 *
 * It exists as a module at all because the copies DID disagree. `split('$')`
 * cuts a rule at the first `$`, which for a regex rule is usually its own end
 * anchor -- so `/^...\.js$/$script` parsed with the pattern truncated and the
 * options read as `/`. Fixing only parseRule made the gate at lib/adblock.js's
 * line ~183 disagree with the parser it documents itself as matching, and a
 * `/^...$/$popup` rule -- which neither engine can act on -- then reached the
 * blocking path as a live regex rule. That is the same over-blocking defect
 * scripts/test-adblock-parity.js was written for, re-opened from a second
 * direction. One copy, four callers.
 */

/**
 * Locate the `$` that separates a rule's pattern from its options.
 *
 * For an ordinary rule that is the first `$`. A REGEX rule (`/pattern/`) needs
 * more care, because `$` can appear in three places at once: the pattern's end
 * anchor, the options marker, and an option's own value
 * (`$removeparam=/^utm_$/`). The separator is the `$` that directly follows the
 * pattern's closing `/`, so it is searched for from the END -- a `$` inside the
 * options is not preceded by that `/`, so the scan walks past it.
 *
 * Each branch is load-bearing, and scripts/test-adblock-parity.js has a check
 * per branch:
 *  - the scan: `/^x\.js$/$script` must not split at the anchor;
 *  - the unescaped-slash test: `/^a\/$/` ends with an ESCAPED slash and so
 *    carries no options, where a bare `/$` test would split inside the pattern;
 *  - `endsWith('/')`: `/^x\.js$/` has no options at all, and must not fall
 *    through to the first-`$` rule, which would cut it at the anchor;
 *  - the first-`$` fall-through: a rule starting with `/` is not necessarily a
 *    regex (`/ads/banner.gif$image` is a path rule) and must keep its options.
 *
 * @param {string} rule - Raw rule text, options included, `@@` already stripped
 * @returns {number} Index of the separator, or -1 when the rule has no options
 */
function findOptionsSeparator(rule) {
  if (typeof rule !== 'string') return -1;
  if (rule.startsWith('/')) {
    for (let i = rule.length - 1; i >= 2; i--) {
      if (rule[i] !== '$') continue;
      if (rule[i - 1] !== '/') continue;
      if (rule[i - 2] === '\\') continue;
      return i;
    }
    // `/pattern/` with no `/$` boundary anywhere: a regex rule without options.
    if (rule.endsWith('/')) return -1;
    // Falls through: not a regex rule after all.
  }
  const first = rule.indexOf('$');
  return first === -1 ? -1 : first;
}

/**
 * The rule's options segment, or '' when it has none.
 *
 * @param {string} rule - Raw rule text, options included
 * @returns {string} Everything after the separator
 */
function ruleOptionsString(rule) {
  const i = findOptionsSeparator(rule);
  return i === -1 ? '' : rule.slice(i + 1);
}

/**
 * The option NAMES a rule carries, negation and value stripped, so a caller can
 * ask "does this rule use an option I cannot honour?".
 *
 * `~` is stripped because `$~script` is still the `script` option, and
 * everything after `=` because `$domain=a.com|b.com` is still `domain`.
 *
 * @param {string} rule - Raw rule text, options included
 * @returns {string[]} Option names, possibly empty
 */
function ruleOptionNames(rule) {
  const optionsStr = ruleOptionsString(rule);
  if (!optionsStr) return [];
  return optionsStr.split(',').map(o => o.replace(/^~/, '').split('=')[0].trim());
}

module.exports = { findOptionsSeparator, ruleOptionsString, ruleOptionNames };
