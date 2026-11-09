#!/usr/bin/env node
/**
 * test-compare.js — pins lib/compare.js: --compare normalization across every
 * output format, and the title-block handling that --titles depends on.
 *
 * Both bugs pinned here are the same species: the filter reported a clean
 * dedupe while throwing results away.
 *
 *   1. Pi-hole rules are regexes that START with '^' — `(^|\.)host\.com$`. The
 *      strip chain's RE_CARET_SUFFIX (/\^.*$/) reduced every one of them to
 *      '(', so the comparison set held a single key that every rule matched:
 *      `--pihole --compare` wrote an EMPTY file and printed
 *      "Filtered 2 existing rules, 0 unique rules remaining" to say so.
 *   2. buildOutputLines emits a header BLOCK per site (`! <url>` plus
 *      `! Redirected from:` / `! Regex:`), and a live scan always populates
 *      matchedRegexes, so the block is ≥2 lines. Each line was treated as its
 *      own title, closing a group with no rules, which the orphan branch then
 *      deleted — `! <url>` was dropped from every --titles --compare run.
 *
 * Normalization is reached through loadComparisonRules rather than a widened
 * module.exports, which also exercises the path output.js really calls.
 *
 * ~0.1s, no browser, no network, no config.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadComparisonRules, filterUniqueRules } = require('../lib/compare');
const { formatDomain } = require('../lib/output');

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`); }
};

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-compare-'));
let seq = 0;
// Build a comparison file and return its rule Set.
const compareSet = (lines) => {
  const p = path.join(dir, `cmp-${seq++}.txt`);
  fs.writeFileSync(p, lines.join('\n') + '\n');
  return loadComparisonRules(p, false);
};
// The normalized key a line reduces to, as the comparison set stores it.
const key = (line) => [...compareSet([line])][0];
const filter = (rules, existing) => filterUniqueRules(rules, compareSet(existing), false);

// === 1. every output format keeps its own identity ========================
// formatDomain is the real producer, so the fixtures cannot drift from it.
const fmt = (domain, opts) => formatDomain(domain, opts);
const PIHOLE = fmt('ads.example.com', { pihole: true });
const PIHOLE2 = fmt('trk.example.net', { pihole: true });

check('pihole rule survives normalization intact', key(PIHOLE), PIHOLE);
check('two pihole rules do not collide',
  key(PIHOLE) === key(PIHOLE2), false);
check('unbound rule survives intact',
  key(fmt('ads.example.com', { unbound: true })), 'local-zone: "ads.example.com." always_null');
check('dnsmasq rule survives intact',
  key(fmt('ads.example.com', { dnsmasq: true })), 'local=/ads.example.com/');
check('dnsmasq-old rule survives intact',
  key(fmt('ads.example.com', { dnsmasqOld: true })), 'server=/ads.example.com/');
check('privoxy rule survives intact',
  key(fmt('ads.example.com', { privoxy: true })), '{ +block } .ads.example.com');

// === 2. the pihole wipeout ================================================
check('pihole: unrelated compare file filters nothing',
  filter([PIHOLE, PIHOLE2], [fmt('nothing-to-do-with-it.invalid', { pihole: true })]),
  [PIHOLE, PIHOLE2]);
check('pihole: compare still removes a genuine duplicate',
  filter([PIHOLE, PIHOLE2], [PIHOLE]), [PIHOLE2]);
check('unbound: unrelated compare file filters nothing',
  filter([fmt('ads.example.com', { unbound: true })],
         [fmt('other.invalid', { unbound: true })]),
  ['local-zone: "ads.example.com." always_null']);
check('privoxy: compare still removes a genuine duplicate',
  filter([fmt('ads.example.com', { privoxy: true })],
         [fmt('ads.example.com', { privoxy: true })]), []);

// === 3. adblock / hosts / plain stay mutually comparable ==================
// This equivalence is the point of the strip chain — the pihole fix must not
// cost it, so it is pinned from every direction.
check('adblock rule normalizes to its host', key('||ads.example.com^'), 'ads.example.com');
check('hosts 0.0.0.0 normalizes to its host', key('0.0.0.0 ads.example.com'), 'ads.example.com');
check('hosts 127.0.0.1 normalizes to its host', key('127.0.0.1 ads.example.com'), 'ads.example.com');
check('plain domain normalizes to itself', key('ads.example.com'), 'ads.example.com');
check('inline hosts comment is stripped', key('0.0.0.0 ads.example.com  # tracker'), 'ads.example.com');
check('hosts file filters an adblock rule',
  filter(['||ads.example.com^'], ['0.0.0.0 ads.example.com']), []);
check('plain list filters an adblock rule',
  filter(['||ads.example.com^'], ['ads.example.com']), []);
check('adblock list filters a hosts rule',
  filter(['0.0.0.0 ads.example.com'], ['||ads.example.com^']), []);
// Deliberate, not a side effect: an existing domain rule covers a typed one.
check('existing domain rule filters a resource-typed rule',
  filter(['||ads.example.com^$script'], ['||ads.example.com^']), []);
check('adblock path rule keeps its path',
  key('||ads.example.com/track/'), 'ads.example.com/track/');
check('a different host is not filtered',
  filter(['||ads.example.com^'], ['||other.example.net^']), ['||ads.example.com^']);

// === 4. title blocks =====================================================
// The shape buildOutputLines really emits: url + redirect + regex, per site.
const H1 = ['! https://site.example/page', '! Redirected from: https://old.site.example/p', '! Regex: ads\\.'];
const H2 = ['! https://two.example/page', '! Regex: trk\\.'];
const R1 = '||ads.example.com^';
const R2 = '||trk.example.net^';

check('multi-line header kept whole when its rules survive',
  filter([...H1, R1, R2], ['||unrelated.invalid^']), [...H1, R1, R2]);
check('multi-line header dropped whole when every rule is a duplicate',
  filter([...H1, R1, R2], [R1, R2]), []);
check('partial duplicate keeps the whole header',
  filter([...H1, R1, R2], [R1]), [...H1, R2]);
check('two sites: first orphaned, second kept whole',
  filter([...H1, R1, ...H2, R2], [R1]), [...H2, R2]);
check('two sites: second orphaned, first kept whole',
  filter([...H1, R1, ...H2, R2], [R2]), [...H1, R1]);
check('single-line header still works',
  filter(['! https://site.example/', R1], ['||unrelated.invalid^']), ['! https://site.example/', R1]);
check('single-line header still orphans',
  filter(['! https://site.example/', R1], [R1]), []);
check('rules before any header are kept',
  filter([R1, ...H2, R2], ['||unrelated.invalid^']), [R1, ...H2, R2]);
check('trailing header with no rules is dropped',
  filter([R1, ...H2], ['||unrelated.invalid^']), [R1]);
check('no headers at all behaves as before',
  filter([R1, R2], [R2]), [R1]);

// === 5. comparison-file parsing ==========================================
check('compare file comments and blanks are ignored',
  [...compareSet(['! a title', '', '# a hosts comment', '||ads.example.com^'])], ['ads.example.com']);
check('missing compare file throws', (() => {
  try { loadComparisonRules(path.join(dir, 'does-not-exist.txt'), false); return 'no throw'; }
  catch (e) { return e.message.startsWith('Failed to load comparison file:'); }
})(), true);

fs.rmSync(dir, { recursive: true, force: true });

if (fail > 0) {
  console.log(`\n${fail} check(s) failed, ${pass} passed`);
  process.exit(1);
}
console.log(`\nAll ${pass} check(s) passed`);
