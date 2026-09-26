#!/usr/bin/env node
/**
 * What formatDomain() will and will not emit.
 *
 * formatDomain is the last gate before a matched domain becomes a rule, and it
 * signals rejection by returning null -- which every caller drops with a bare
 * `if (formatted)`. A wrong rejection is therefore invisible: the domain is
 * matched, counted, marked processed and reported in the unique-domain stat,
 * and then simply never appears in the output file.
 *
 * That is exactly what happened. The guard was a flat `domain.length <= 6`,
 * so bit.ly, goo.gl, vk.com, qq.com, adf.ly, t.co, x.com, ok.ru and is.gd
 * produced no rule in ANY output format, with no warning -- found because a
 * fixture serving trackers from lvh.me and nip.io (both 6 characters) reported
 * 4 matched domains and wrote 2 rules, deterministically, with the same two
 * hosts lost when the DOM order was reversed. The number also measured the
 * whole key including any path, so `t.co/ads/` passed where the bare host did
 * not, which is proof it was not protecting anything structural.
 *
 * The checks below pin both directions: real short domains must be emitted in
 * every format, and genuinely malformed keys must still be refused. The
 * malformed half matters as much as the fix -- `output_regex` captures are the
 * reason the guard exists at all.
 */

const { formatDomain } = require('../lib/output.js');

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

// --- 1. Real domains a scanner must be able to block, all <= 6 characters.
const SHORT_REAL = ['bit.ly', 'goo.gl', 'vk.com', 'qq.com', 'adf.ly', 't.co', 'x.com', 'ok.ru', 'is.gd', 'a.io'];
const droppedShort = SHORT_REAL.filter(d => formatDomain(d, { plain: true }) === null);
check('short real domains are emitted', droppedShort.length === 0,
  droppedShort.length ? `dropped: ${droppedShort.join(', ')}` : `${SHORT_REAL.length} checked, none dropped`);

const wrongAdblock = SHORT_REAL.filter(d => formatDomain(d, {}) !== `||${d}^`);
check('short domains get correct adblock syntax', wrongAdblock.length === 0,
  wrongAdblock.length ? `wrong: ${wrongAdblock.join(', ')}` : 'all ||domain^');

// --- 2. Malformed keys are still refused (what the guard is actually for).
// 'abc.d' and 'foobar.x' are long enough to clear the 4-character floor, so
// they are what actually exercises the TLD check -- without them, deleting it
// leaves every check green (found by mutating it out).
const MALFORMED = ['', 'a.b', 'x.y', 'abc.d', 'foobar.x', 'localhost', '.com', 'foo.', 'a..b', 'ab', '.', 'a.b/very/long/path/'];
const leaked = MALFORMED.filter(d => formatDomain(d, { plain: true }) !== null);
check('malformed keys are refused', leaked.length === 0,
  leaked.length ? `leaked: ${leaked.map(d => JSON.stringify(d)).join(', ')}` : `${MALFORMED.length} checked, none leaked`);

// --- 3. Bare IP rules stay legitimate (a numeric last label is not a bad TLD).
const IPS = ['1.2.3.4', '93.184.216.34', '10.0.0.1'];
const droppedIps = IPS.filter(d => formatDomain(d, { plain: true }) === null);
check('IP-literal hosts are emitted', droppedIps.length === 0,
  droppedIps.length ? `dropped: ${droppedIps.join(', ')}` : `${IPS.length} checked`);

// --- 4. The host is validated, not the whole key: a path must not pad a bad
//        host past the check, and must not disqualify a good short one.
// A path already anchors, so adblock path rules carry no trailing '^' (by design
// in formatDomain) -- pinned here so the host validation can't change the shape.
check('path rule on a valid short host is emitted', formatDomain('t.co/ads/', {}) === '||t.co/ads/',
  JSON.stringify(formatDomain('t.co/ads/', {})));
check('path rule on a malformed host is refused', formatDomain('a.b/ads/', {}) === null,
  JSON.stringify(formatDomain('a.b/ads/', {})));

// --- 5. Every output format stays valid for a short domain.
const FORMATS = [
  ['plain', { plain: true }, 'bit.ly'],
  ['adblock', {}, '||bit.ly^'],
  ['hosts', { localhostIP: '0.0.0.0' }, '0.0.0.0 bit.ly'],
  ['dnsmasq', { dnsmasq: true }, 'local=/bit.ly/'],
  ['dnsmasqOld', { dnsmasqOld: true }, 'server=/bit.ly/'],
  ['unbound', { unbound: true }, 'local-zone: "bit.ly." always_null'],
  ['privoxy', { privoxy: true }, '{ +block } .bit.ly'],
  ['pihole', { pihole: true }, '(^|\\.)bit\\.ly$'],
  ['adblock+type', { adblockRules: true, resourceType: 'script' }, '||bit.ly^script']
];
const wrongFormat = FORMATS.filter(([, opts, want]) => formatDomain('bit.ly', opts) !== want);
check('all output formats emit a short domain correctly', wrongFormat.length === 0,
  wrongFormat.length ? wrongFormat.map(([n, o, w]) => `${n}: got ${JSON.stringify(formatDomain('bit.ly', o))} want ${JSON.stringify(w)}`).join('; ')
                     : `${FORMATS.length} formats`);

// --- 6. A rejection is no longer silent when --debug is on.
const logged = [];
const realLog = console.log;
console.log = (...a) => logged.push(a.join(' '));
formatDomain('a.b', { plain: true, forceDebug: true });
formatDomain('bit.ly', { plain: true, forceDebug: true });
console.log = realLog;
check('rejection is reported under forceDebug',
  logged.length === 1 && logged[0].includes('a.b') && !logged[0].includes('bit.ly'),
  `${logged.length} line(s): ${logged.join(' | ') || 'none'}`);

console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
