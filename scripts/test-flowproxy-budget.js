#!/usr/bin/env node
/**
 * test-flowproxy-budget.js
 *
 * flowproxy_detection makes a page load spend time on purpose: a rate-limit
 * pause, a JS-challenge wait and a settle delay. nwss.js's per-URL ceiling
 * (PER_URL_TIMEOUT_MS) feeds the hang check's emergency browser restart
 * (restartAfterMs), so any wait missing from the ceiling can be killed
 * mid-wait. This suite pins:
 *
 *   1. getFlowProxyOverheadMs' arithmetic and its fallbacks
 *   2. that nwss.js's SHIPPED formula actually adds the term (the formula is
 *      extracted from source and evaluated, so deleting the term here goes red)
 *   3. that the term is one-time, not multiplied by reloadCount
 *   4. that the resulting restart deadline clears the audited worst-case spend,
 *      including the flowproxy_delay: 120000 case that used to overrun
 *
 * Run: node scripts/test-flowproxy-budget.js
 */

const fs = require('fs');
const path = require('path');
const { getFlowProxyOverheadMs, getFlowProxyTimeouts } = require('../lib/flowproxy');

let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`); failed++; }
}
function eq(name, actual, expected) {
  check(name, actual === expected, `expected ${expected}, got ${actual}`);
}

// --- The audited wait sites. Kept as literals so that raising a default in
// --- lib/flowproxy.js (or nwss.js) fails a test instead of silently shrinking
// --- the safety margin.
const PAGE_LOAD_WAIT = 1500;      // flowproxy.js FAST_TIMEOUTS.PAGE_LOAD_WAIT
const RATE_LIMIT_DEFAULT = 30000; // flowproxy.js TIMEOUTS.RATE_LIMIT_DEFAULT
const JS_CHALLENGE_DEFAULT = 15000;
const ADDITIONAL_DELAY_DEFAULT = 3000;
const NWSS_ADDITIONAL_CAP = 3000; // nwss.js delayPromise: Math.min(cfg, 3000)

// Extract and evaluate nwss.js's own budget + restart formulas.
const src = fs.readFileSync(path.join(__dirname, '..', 'nwss.js'), 'utf8');

const budgetMatch = src.match(/const PER_URL_TIMEOUT_MS = Math\.max\(([\s\S]*?)\n\s*\);/);
if (!budgetMatch) { console.error('FATAL: could not locate PER_URL_TIMEOUT_MS in nwss.js'); process.exit(1); }
const shippedBudget = new Function(
  'task', 'reloadCount', 'INTERACTION_OVERHEAD_MS', 'CLICK_ELEMENTS_OVERHEAD_MS',
  'DIG_RETRY_OVERHEAD_MS', 'FLOWPROXY_OVERHEAD_MS',
  `return Math.max(${budgetMatch[1]}\n);`
);

const restartMatch = src.match(/const restartAfterMs = (Math\.max\([^)]*\));/);
if (!restartMatch) { console.error('FATAL: could not locate restartAfterMs in nwss.js'); process.exit(1); }
const shippedRestart = new Function('maxPerUrlTimeoutMs', `return ${restartMatch[1]};`);

// nwss.js's composition of the term, extracted the same way.
const termMatch = src.match(/const FLOWPROXY_OVERHEAD_MS = ([\s\S]*?);\n\s*const PER_URL_TIMEOUT_MS/);
if (!termMatch) { console.error('FATAL: could not locate FLOWPROXY_OVERHEAD_MS in nwss.js'); process.exit(1); }
const shippedTerm = new Function('task', 'getFlowProxyOverheadMs', `return ${termMatch[1]};`);

function budgetFor(config, reloadCount = 0, extra = {}) {
  const task = { config };
  const {
    interaction = 0, clicks = 0, dig = 0,
    flowproxy = shippedTerm(task, getFlowProxyOverheadMs)
  } = extra;
  return shippedBudget(task, reloadCount, interaction, clicks, dig, flowproxy);
}

console.log('\n=== getFlowProxyOverheadMs: gate ===');
eq('detection absent → 0', getFlowProxyOverheadMs({}), 0);
eq('detection false → 0', getFlowProxyOverheadMs({ flowproxy_detection: false }), 0);
eq('detection "true" (string) → 0, matches nwss\'s === true gate',
  getFlowProxyOverheadMs({ flowproxy_detection: 'true' }), 0);
eq('null siteConfig → 0', getFlowProxyOverheadMs(null), 0);

console.log('\n=== getFlowProxyOverheadMs: arithmetic ===');
const DEFAULT_OVERHEAD = PAGE_LOAD_WAIT + RATE_LIMIT_DEFAULT + JS_CHALLENGE_DEFAULT + ADDITIONAL_DELAY_DEFAULT;
eq('defaults → 49500ms', getFlowProxyOverheadMs({ flowproxy_detection: true }), DEFAULT_OVERHEAD);
eq('defaults match the audited wait sites', DEFAULT_OVERHEAD, 49500);
eq('flowproxy_delay honoured',
  getFlowProxyOverheadMs({ flowproxy_detection: true, flowproxy_delay: 120000 }),
  DEFAULT_OVERHEAD - RATE_LIMIT_DEFAULT + 120000);
eq('js + additional honoured',
  getFlowProxyOverheadMs({ flowproxy_detection: true, flowproxy_js_timeout: 40000, flowproxy_additional_delay: 9000 }),
  PAGE_LOAD_WAIT + RATE_LIMIT_DEFAULT + 40000 + 9000);
eq('zero falls back to the default the handler will use',
  getFlowProxyOverheadMs({ flowproxy_detection: true, flowproxy_delay: 0 }), DEFAULT_OVERHEAD);
eq('garbage falls back',
  getFlowProxyOverheadMs({ flowproxy_detection: true, flowproxy_delay: 'soon', flowproxy_js_timeout: -5 }),
  DEFAULT_OVERHEAD);

console.log('\n=== nwss.js wiring (shipped formula) ===');
const offCfg = { timeout: 35000, delay: 5000 };
const onCfg = { timeout: 35000, delay: 5000, flowproxy_detection: true };
const bigOff = { timeout: 120000, delay: 5000 };
const bigOn = { timeout: 120000, delay: 5000, flowproxy_detection: true };

eq('detection off adds nothing', budgetFor(bigOn) - budgetFor(bigOff),
  DEFAULT_OVERHEAD + NWSS_ADDITIONAL_CAP);
check('the term reaches PER_URL_TIMEOUT_MS (would be 0 if the + line were dropped)',
  budgetFor(bigOn) > budgetFor(bigOff),
  `on=${budgetFor(bigOn)} off=${budgetFor(bigOff)}`);
eq('nwss adds its own capped post-delay wait on top of the handler\'s',
  shippedTerm({ config: onCfg }, getFlowProxyOverheadMs),
  DEFAULT_OVERHEAD + NWSS_ADDITIONAL_CAP);
eq('nwss\'s own wait stays capped at 3000 even when configured higher',
  shippedTerm({ config: { flowproxy_detection: true, flowproxy_additional_delay: 60000 } }, getFlowProxyOverheadMs)
    - getFlowProxyOverheadMs({ flowproxy_detection: true, flowproxy_additional_delay: 60000 }),
  NWSS_ADDITIONAL_CAP);

console.log('\n=== one-time, not per-reload ===');
// flowproxy runs on the initial-load path only (handler at ~4953, nwss's wait
// at ~5179; the reload loop starts at ~5380 and touches neither).
const perReload = (bigOn.delay || 0) + 0;
eq('3 reloads add only delay+interaction, no extra flowproxy',
  budgetFor(bigOn, 3) - budgetFor(bigOn, 0), 3 * perReload);

console.log('\n=== restart deadline clears the worst-case spend ===');
function spendFor(config) {
  // Audited worst case for one URL: page timeout + the delay/interact phase +
  // every flowproxy wait taken.
  const fp = config.flowproxy_detection === true
    ? PAGE_LOAD_WAIT
      + (config.flowproxy_delay || RATE_LIMIT_DEFAULT)
      + (config.flowproxy_js_timeout || JS_CHALLENGE_DEFAULT)
      + (config.flowproxy_additional_delay || ADDITIONAL_DELAY_DEFAULT)
      + Math.min(config.flowproxy_additional_delay || NWSS_ADDITIONAL_CAP, NWSS_ADDITIONAL_CAP)
    : 0;
  return (config.timeout || 35000) + (config.delay || 0) + fp;
}
for (const [label, cfg] of [
  ['defaults + detection', onCfg],
  ['module doc example (45s/20s/8s)', { timeout: 35000, delay: 5000, flowproxy_detection: true, flowproxy_page_timeout: 45000, flowproxy_js_timeout: 20000, flowproxy_additional_delay: 8000 }],
  ['aggressive flowproxy_delay: 120000', { timeout: 35000, delay: 5000, flowproxy_detection: true, flowproxy_delay: 120000 }]
]) {
  const restart = shippedRestart(budgetFor(cfg));
  const spend = spendFor(cfg);
  check(`${label}: restart ${restart}ms > spend ${spend}ms`, restart > spend);
}

// The regression this fix closes: without the term, the aggressive config's
// restart deadline landed BELOW its own spend.
const aggressive = { timeout: 35000, delay: 5000, flowproxy_detection: true, flowproxy_delay: 120000 };
const restartWithout = shippedRestart(budgetFor(aggressive, 0, { flowproxy: 0 }));
check(`pre-fix behaviour reproduced: restart ${restartWithout}ms < spend ${spendFor(aggressive)}ms`,
  restartWithout < spendFor(aggressive));

console.log('\n=== getFlowProxyTimeouts: values reach puppeteer as configured ===');
const PAGE_TIMEOUT_DEFAULT = 45000, NAVIGATION_TIMEOUT_DEFAULT = 45000;
eq('page default', getFlowProxyTimeouts({}).pageTimeout, PAGE_TIMEOUT_DEFAULT);
eq('nav default', getFlowProxyTimeouts({}).navigationTimeout, NAVIGATION_TIMEOUT_DEFAULT);
eq('page honoured above the old 25000 cap',
  getFlowProxyTimeouts({ flowproxy_page_timeout: 60000 }).pageTimeout, 60000);
eq('nav honoured above the old 35000 cap',
  getFlowProxyTimeouts({ flowproxy_nav_timeout: 90000 }).navigationTimeout, 90000);
eq('zero falls back', getFlowProxyTimeouts({ flowproxy_page_timeout: 0 }).pageTimeout, PAGE_TIMEOUT_DEFAULT);
eq('negative falls back, never reaching setDefaultTimeout',
  getFlowProxyTimeouts({ flowproxy_page_timeout: -1000 }).pageTimeout, PAGE_TIMEOUT_DEFAULT);
eq('non-numeric falls back',
  getFlowProxyTimeouts({ flowproxy_nav_timeout: 'slow' }).navigationTimeout, NAVIGATION_TIMEOUT_DEFAULT);

// The clamp that used to sit here paired the page timeout with DEFAULT_NAVIGATION
// (25000) and the nav timeout with DEFAULT_PAGE (35000), so both 45000 defaults
// were capped and raising either option did nothing. Evaluate what nwss.js
// actually hands to puppeteer.
const fpBlock = src.slice(src.indexOf('const flowproxyTimeouts = getFlowProxyTimeouts(siteConfig);'));
const applied = {};
for (const [label, fn] of [['page', 'setDefaultTimeout'], ['nav', 'setDefaultNavigationTimeout']]) {
  const m = fpBlock.match(new RegExp(`page\\.${fn}\\(([^;]*)\\);`));
  if (!m) { console.error(`FATAL: could not locate page.${fn} in the flowproxy block`); process.exit(1); }
  applied[label] = new Function('flowproxyTimeouts', 'timeout', 'TIMEOUTS',
    `return ${m[1]};`);
}
const NWSS_TIMEOUTS = { DEFAULT_PAGE: 35000, DEFAULT_NAVIGATION: 25000, DEFAULT_PAGE_REDUCED: 15000 };
const want = getFlowProxyTimeouts({ flowproxy_page_timeout: 60000, flowproxy_nav_timeout: 90000 });
eq('nwss applies the configured page timeout unclamped',
  applied.page(want, 35000, NWSS_TIMEOUTS), 60000);
eq('nwss applies the configured nav timeout unclamped',
  applied.nav(want, 35000, NWSS_TIMEOUTS), 90000);
const wantDefaults = getFlowProxyTimeouts({});
eq('the documented 45000 page default now actually applies',
  applied.page(wantDefaults, 35000, NWSS_TIMEOUTS), 45000);
eq('the documented 45000 nav default now actually applies',
  applied.nav(wantDefaults, 35000, NWSS_TIMEOUTS), 45000);

console.log(`\n${failed === 0 ? '✅' : '❌'} ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
