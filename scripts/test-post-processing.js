#!/usr/bin/env node
/**
 * Two defects in lib/post-processing.js, and the surface around them.
 *
 * 1. reportFirstPartyViolations could not fail. It ran third in processResults,
 *    after cleanupFirstPartyDomains, and the two share an identical predicate
 *    -- same extractDomainFromRule, same shouldRemoveAsFirstParty, same
 *    scannedDomain, same `firstParty === false` gate -- while the only step
 *    between them removes rules and never adds any. So every violation it
 *    looked for had already been deleted before it looked. Measured: two
 *    first-party rules through processResults printed "Cleaned 2 first-party
 *    rule(s)" and then "No first-party violations found - filtering working
 *    correctly". It is now step 1, where it sees what the SCAN produced, and
 *    reports without removing -- removal stays with cleanupFirstPartyDomains.
 *
 * 2. Unbound was the one output format of seven that ignoreDomains cleanup
 *    silently skipped. REGEX_UNBOUND ended in `\.?`, which could never fire,
 *    because `[^"]+` is greedy and `.` is inside its class -- so the root dot
 *    unbound writes was captured and extraction returned 'example.com.'.
 *    shouldIgnoreAsIgnoreDomain compares raw strings, and neither
 *    'example.com.' === 'example.com' nor .endsWith('.example.com') holds.
 *    lib/output.js's own copy of extractDomainFromRule strips that dot
 *    explicitly; the two copies diverged on exactly this format, so the checks
 *    below pin them together rather than only pinning a value.
 *
 * The first-party path never failed on unbound, but not for a good reason:
 * psl.parse tolerates a trailing dot and that path compares registrable roots.
 * That is pinned too, so the save stays deliberate.
 *
 * No browser, no network, no config. Runs in well under a second.
 */

const pp = require('../lib/post-processing.js');
const output = require('../lib/output.js');

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

// Message assertions need the console text, and messageColors may wrap it.
const ANSI = /\u001b\[[0-9;]*m/g;
// Returns both the console text and fn's return value, so no check() runs
// INSIDE the interception -- a swallowed PASS line is invisible, and worse, it
// lands in the string the assertions then search.
function capture(fn) {
  const real = console.log;
  const lines = [];
  console.log = (...a) => lines.push(a.map(String).join(' ').replace(ANSI, ''));
  let value;
  try { value = fn(); } finally { console.log = real; }
  return { out: lines.join('\n'), value };
}

const SITE = 'https://www.recorder.ca/gananoque/';
const sites = [
  { url: SITE, firstParty: false },
  { url: 'https://keep.example/', firstParty: true },
];
const res = (url, rules) => [{ url, rules: rules.slice() }];

// =====================================================================
// 1. Fix 2 — the unbound root dot
// =====================================================================
console.log('\n--- 1. unbound root dot (fix 2)');

const UNBOUND_DOT = 'local-zone: "example.com." always_null';
const UNBOUND_BARE = 'local-zone: "example.com" always_null';

check('unbound rule with the root dot extracts the bare domain',
  pp.extractDomainFromRule(UNBOUND_DOT) === 'example.com',
  JSON.stringify(pp.extractDomainFromRule(UNBOUND_DOT)));

check('unbound rule without a root dot is unaffected',
  pp.extractDomainFromRule(UNBOUND_BARE) === 'example.com',
  JSON.stringify(pp.extractDomainFromRule(UNBOUND_BARE)));

// The divergence itself, not just its symptom: output.js writes these rules and
// has its own extractDomainFromRule. If either copy moves, this fails.
for (const rule of [UNBOUND_DOT, UNBOUND_BARE,
                    'local-zone: "a.b.example.co.uk." always_null',
                    'local-zone: "example.com.." always_null']) {
  const mine = pp.extractDomainFromRule(rule);
  const theirs = output.extractDomainFromRule(rule);
  check('post-processing agrees with output.js on ' + JSON.stringify(rule.slice(12, 40)),
    mine === theirs, 'post-processing=' + JSON.stringify(mine) + ' output=' + JSON.stringify(theirs));
}

// Every output format, through the cleanup that used to miss one of them.
const FORMATS = {
  adblock:    '||example.com^',
  hosts:      '0.0.0.0 example.com',
  hostsLocal: '127.0.0.1 example.com',
  dnsmasq:    'local=/example.com/',
  dnsmasqOld: 'server=/example.com/',
  unbound:    UNBOUND_DOT,
  privoxy:    '{ +block } .example.com',
  pihole:     '(^|\\.)example\\.com$',
};
const missedByIgnore = Object.entries(FORMATS).filter(([, rule]) => {
  const r = pp.cleanupIgnoreDomains(res(SITE, [rule]), ['example.com'], { silentMode: true });
  return r[0].rules.length !== 0;
}).map(([name]) => name);
check('ignoreDomains cleanup removes every output format', missedByIgnore.length === 0,
  missedByIgnore.length ? 'missed: ' + missedByIgnore.join(', ')
                        : Object.keys(FORMATS).length + ' formats checked');

const fpSites = [{ url: 'https://www.example.com/', firstParty: false }];
const missedByFirstParty = Object.entries(FORMATS).filter(([, rule]) => {
  const r = pp.cleanupFirstPartyDomains(res('https://www.example.com/', [rule]), fpSites, { silentMode: true });
  return r[0].rules.length !== 0;
}).map(([name]) => name);
check('first-party cleanup removes every output format', missedByFirstParty.length === 0,
  missedByFirstParty.length ? 'missed: ' + missedByFirstParty.join(', ')
                            : Object.keys(FORMATS).length + ' formats checked');

// Stripping the dot must not have widened anything: an unbound rule for a host
// that is NOT ignored still has to survive.
const keptUnbound = pp.cleanupIgnoreDomains(
  res(SITE, ['local-zone: "keepme.test." always_null', 'local-zone: "ignoreme.test." always_null']),
  ['ignoreme.test'], { silentMode: true });
check('an unbound rule for a non-ignored host is kept',
  keptUnbound[0].rules.length === 1 && keptUnbound[0].rules[0].includes('keepme.test'),
  JSON.stringify(keptUnbound[0].rules));

// A near-miss host must not be swept up by the now-bare domain.
const nearMiss = pp.cleanupIgnoreDomains(
  res(SITE, ['local-zone: "notexample.com." always_null']), ['example.com'], { silentMode: true });
check('unbound rule for notexample.com is NOT treated as example.com',
  nearMiss[0].rules.length === 1, JSON.stringify(nearMiss[0].rules));

// The first-party save was psl tolerating the dot; keep it deliberate.
check('a trailing root dot still resolves to the same registrable root',
  require('psl').parse('example.com.').domain === 'example.com',
  JSON.stringify(require('psl').parse('example.com.').domain));

// =====================================================================
// 2. Fix 1 — the validator can now fail, and no longer claims otherwise
// =====================================================================
console.log('\n--- 2. first-party violation reporting (fix 1)');

const DIRTY = ['||recorder.ca^', '||ads.recorder.ca^', '||third.example^'];

// Called alone it must REPORT and remove nothing -- removal is the cleanup
// step's job, and if this step removed, the cleanup step would be the dead one.
const alone = capture(() => pp.reportFirstPartyViolations(res(SITE, DIRTY), sites, { silentMode: false }));
const aloneOut = alone.out;
check('validation alone keeps every rule (report-only)', alone.value[0].rules.length === 3,
  JSON.stringify(alone.value[0].rules));
check('validation alone names the violating site', aloneOut.includes('CONFIG VIOLATION') && aloneOut.includes('recorder.ca'));
check('validation alone counts both violations', aloneOut.includes('Found 2 first-party rule(s)'));
check('validation alone does not claim it removed them',
  !/SCAN FILTERING FAILURE: Removed/.test(aloneOut), aloneOut.includes('reached post-processing') ? 'says "reached post-processing"' : 'wording: ' + aloneOut.slice(0, 80));

// The regression that mattered: through processResults the violation is now
// REPORTED, where before the all-clear was printed instead.
const pipe = capture(() => pp.processResults(res(SITE, DIRTY), sites, { silentMode: false, forceDebug: true, ignoreDomains: [] }));
const pipeOut = pipe.out;
check('processResults still removes the first-party rules',
  JSON.stringify(pipe.value[0].rules) === JSON.stringify(['||third.example^']),
  JSON.stringify(pipe.value[0].rules));
check('processResults REPORTS the violation', pipeOut.includes('CONFIG VIOLATION'),
  pipeOut.includes('CONFIG VIOLATION') ? '' : 'no CONFIG VIOLATION line');
check('processResults no longer prints a false all-clear',
  !pipeOut.includes('No first-party violations found'),
  pipeOut.includes('No first-party violations found') ? 'still claims filtering working correctly' : '');
// The claim, not the phrasing: on input that DID carry violations, no all-clear
// of any wording may appear. Reverting only the step order leaves the new
// sentence printing a falsehood, and this is the check that sees it.
check('no all-clear of any wording survives dirty input',
  !pipeOut.includes('the scan emitted no first-party rules'),
  pipeOut.includes('the scan emitted no first-party rules') ? 'all-clear printed for input with 2 violations' : '');
check('the report precedes the cleanup it describes',
  pipeOut.indexOf('CONFIG VIOLATION') < pipeOut.indexOf('Cleaned 2 first-party rule(s)') &&
  pipeOut.includes('Cleaned 2 first-party rule(s)'));

// Clean input: the all-clear is allowed, and now it means something.
const clean = capture(() => pp.processResults(res(SITE, ['||third.example^', '||other.example^']), sites,
  { silentMode: false, forceDebug: true, ignoreDomains: [] }));
const cleanOut = clean.out;
check('clean input passes through untouched', clean.value[0].rules.length === 2,
  JSON.stringify(clean.value[0].rules));
check('clean input reports no violation', !cleanOut.includes('CONFIG VIOLATION'));
check('the all-clear states what was actually checked',
  cleanOut.includes('the scan emitted no first-party rules'),
  cleanOut.includes('filtering working correctly') ? 'still the old unprovable wording' : '');

// silentMode must still suppress the visible report, and forceDebug must still
// carry the count -- the branch that used to say "Removed" on a report-only path.
const silentOut = capture(() => pp.processResults(res(SITE, DIRTY), sites,
  { silentMode: true, forceDebug: true, ignoreDomains: [] })).out;
check('silentMode hides the visible violation line', !silentOut.includes('CONFIG VIOLATION'));
check('silentMode + forceDebug still reports the count',
  /\(silentMode\) 2 first-party violation\(s\)/.test(silentOut),
  silentOut.includes('(silentMode)') ? '' : 'no silentMode debug line');

// A firstParty:true site is not this step's business.
const keep = capture(() => pp.processResults(res('https://keep.example/', ['||keep.example^', '||x.example^']), sites,
  { silentMode: false, forceDebug: true, ignoreDomains: [] }));
const keepOut = keep.out;
check('firstParty:true site keeps its own domain', keep.value[0].rules.length === 2,
  JSON.stringify(keep.value[0].rules));
check('firstParty:true site raises no violation', !keepOut.includes('CONFIG VIOLATION'));

// =====================================================================
// 3. Surface I did not change — pinned so the fixes cannot drift into it
// =====================================================================
console.log('\n--- 3. untouched behaviour');

const exact = pp.cleanupIgnoreDomains(
  res(SITE, ['||example.com^', '||sub.example.com^', '||notexample.com^']),
  ['example.com'], { silentMode: true });
check('exact ignore pattern takes the apex and subdomains, not a near-miss',
  JSON.stringify(exact[0].rules) === JSON.stringify(['||notexample.com^']),
  JSON.stringify(exact[0].rules));

const valid = pp.validateScanResults(
  [{ url: SITE, rules: ['', '   ', null, 42, '||keep.example^'] }], {});
check('validateScanResults prunes empty, blank and non-string rules',
  JSON.stringify(valid[0].rules) === JSON.stringify(['||keep.example^']),
  JSON.stringify(valid[0].rules));

const mixed = pp.cleanupIgnoreDomains(
  res(SITE, ['0.0.0.0 ignoreme.test', 'local=/ignoreme.test/', 'server=/ignoreme.test/',
             '{ +block } .ignoreme.test', '(^|\\.)ignoreme\\.test$', '||keepme.test^']),
  ['ignoreme.test'], { silentMode: true });
check('a mixed-format batch is reduced to the one non-ignored rule',
  JSON.stringify(mixed[0].rules) === JSON.stringify(['||keepme.test^']),
  JSON.stringify(mixed[0].rules));

const noPatterns = pp.cleanupIgnoreDomains(res(SITE, ['||a.test^']), [], { silentMode: true });
check('an empty ignore list is a no-op', noPatterns[0].rules.length === 1);

const unknownUrl = pp.processResults(res('https://not-in-config.test/', ['||not-in-config.test^']), sites,
  { silentMode: true, ignoreDomains: [] });
check('a result whose url is not in the config is left alone',
  unknownUrl[0].rules.length === 1, JSON.stringify(unknownUrl[0].rules));

console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
