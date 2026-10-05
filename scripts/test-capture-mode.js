#!/usr/bin/env node
/**
 * test-capture-mode.js — pins `nwss.js --har` and lib/capture.js.
 *
 * Every check here is a bug that actually happened while building the flag:
 *  - a multi-URL site emitted its rules once PER URL, because a capture was
 *    matched per configured URL rather than once per site. A capture is a
 *    single page load.
 *  - the output-format flags were silently ignored, because formatRules() was
 *    handed {} instead of the globalOptions the live path builds. Every format
 *    emitted adblock syntax and looked plausible.
 *  - a positional config file was ignored unless an optional .nwssconfig
 *    existed, so the scan ran against config.json with no warning. That is a
 *    pre-existing nwss bug this flag kept tripping over.
 *
 *   node scripts/test-capture-mode.js        # ~5s, no browser, no network
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { sniffFormat, parseCapture, selectSitesForCapture } = require('../lib/capture');

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`); }
};

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-capture-'));
const F = n => path.join(dir, n);
const NWSS = path.join(__dirname, '..', 'nwss.js');

// ---- fixtures -------------------------------------------------------------
const harEntry = (url, dest, mime, status = 200) => ({
  request: { url, method: 'GET', headers: [{ name: 'Sec-Fetch-Dest', value: dest }] },
  response: { status, content: { mimeType: mime } }
});
const HAR = {
  log: {
    version: '1.2',
    creator: { name: 'test-fixture', version: '1' },
    pages: [{ title: 'https://example.test/' }],
    entries: [
      harEntry('https://example.test/', 'document', 'text/html'),
      harEntry('https://tracker.invalid/script/abcdefghij.js', 'script', 'application/javascript'),
      harEntry('https://other.invalid/script/klmnopqrst.js', 'script', 'application/javascript'),
      harEntry('https://cdn.example.test/app.js', 'script', 'application/javascript'),
      // status 0 == the USER'S content blocker cancelled it. Whether this
      // becomes a rule is what even_blocked decides.
      harEntry('https://blockedbyubo.invalid/script/uvwxyzabcd.js', 'script', '', 0)
    ]
  }
};
const harPath = F('capture.har');
fs.writeFileSync(harPath, JSON.stringify(HAR));

const CONFIG = {
  ignoreDomains: [],
  sites: [
    { url: 'https://unrelated.test/', filterRegex: '\\.js$' },
    {
      // TWO urls on purpose: the duplication bug only shows with more than one.
      url: ['https://example.test/deep/page', 'https://example.test/'],
      filterRegex: '\\/[a-z]{8,12}\\.js$',
      firstParty: false
    }
  ]
};
const cfgPath = F('config.json');
fs.writeFileSync(cfgPath, JSON.stringify(CONFIG, null, 2));

const run = (args) => {
  try {
    return execFileSync(process.execPath, [NWSS, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    return (e.stdout || '') + (e.stderr || '');
  }
};
const outLines = file => fs.existsSync(file)
  ? fs.readFileSync(file, 'utf8').split('\n').map(l => l.trim()).filter(Boolean) : [];

console.log('\ncapture mode (--har)\n');

// ---- format sniffing ------------------------------------------------------
check('sniffs a HAR', sniffFormat(harPath), 'har');
const netlogPath = F('n.json');
fs.writeFileSync(netlogPath, '{"constants":{"logEventTypes":{},"logSourceType":{},"netError":{}},\n"events": [\n]\n}\n');
check('sniffs a net-log', sniffFormat(netlogPath), 'netlog');
const mozPath = F('m.moz_log');
fs.writeFileSync(mozPath, '2026-01-01 00:00:00.000 UTC - [Parent 1: Main Thread]: E/nsHttp uri=https://a.test/\r\n');
check('sniffs a MOZ_LOG', sniffFormat(mozPath), 'mozlog');
check('rejects a non-capture', sniffFormat(cfgPath), null);

let threw = '';
try { parseCapture(F('nope.har')); } catch (e) { threw = e.message; }
check('missing file gives an actionable error', /not found/.test(threw), true);

// ---- site selection -------------------------------------------------------
const cap = parseCapture(harPath);
check('auto-selects the site matching the captured page',
  selectSitesForCapture(CONFIG.sites, cap, null).length, 1);
check('auto-selection picks the RIGHT site',
  selectSitesForCapture(CONFIG.sites, cap, null)[0].filterRegex, '\\/[a-z]{8,12}\\.js$');
check('selector by index', selectSitesForCapture(CONFIG.sites, cap, '0')[0].url, 'https://unrelated.test/');
check('selector by substring', selectSitesForCapture(CONFIG.sites, cap, 'example.test').length, 1);
check('no match returns nothing rather than every site',
  selectSitesForCapture([{ url: 'https://nowhere.test/' }], cap, null).length, 0);

// ---- end to end -----------------------------------------------------------
const out1 = F('rules1.txt');
run([cfgPath, '--har', harPath, '--output', out1, '--silent']);
const rules1 = outLines(out1);
check('rules are produced from the capture', rules1.length > 0, true);
check('third-party loader hosts matched', rules1.sort(), ['||other.invalid^', '||tracker.invalid^']);
// The duplication bug: two configured URLs must not double the rules.
check('a multi-URL site emits each rule ONCE', rules1.length, new Set(rules1).size);

// The format bug: --plain must actually change the output.
const out2 = F('rules2.txt');
run([cfgPath, '--har', harPath, '--output', out2, '--plain', '--silent']);
check('--plain is honoured (globalOptions threaded)', outLines(out2).sort(), ['other.invalid', 'tracker.invalid']);

const out3 = F('rules3.txt');
run([cfgPath, '--har', harPath, '--output', out3, '--dnsmasq', '--silent']);
check('--dnsmasq is honoured', outLines(out3).some(l => l.startsWith('local=/')), true);

// The positional-config bug: the file named on the command line must be used.
// If it were ignored, nwss would fall back to its own config.json, whose sites
// do not match this capture -- so it would exit with the no-match error.
const posOut = run([cfgPath, '--har', harPath, '--site', '1', '--output', F('r4.txt')]);
check('positional config file is honoured, not config.json',
  /No site in the config matches/.test(posOut), false);

// Refusing to guess is the designed behaviour, not an accident.
fs.writeFileSync(F('lonely.json'), JSON.stringify({ sites: [{ url: 'https://nowhere.test/' }] }));
check('a capture matching no site is refused, not guessed',
  /No site in the config matches/.test(run([F('lonely.json'), '--har', harPath])), true);

const badCap = run([cfgPath, '--har', cfgPath]);
check('a non-capture file is refused with a useful message',
  /not a recognised capture/.test(badCap), true);

// ---- naming a DIRECTORY uses the newest capture, not all of them --------
// Capture filenames are timestamped so runs never overwrite each other, which
// means a fixed command has to name the folder. Reading every capture in it is
// NOT the same thing: it merged separate page loads into one result (two real
// runs of 350 and 288 requests came back as 498).
const capDir = F('captures');
fs.mkdirSync(capDir);
const older = path.join(capDir, 'ff-000000-000000.log.moz_log');
const newer = path.join(capDir, 'ff-111111-111111.log.moz_log');
const mozLines = urls => urls.map(u =>
  `2026-01-01 00:00:00.000 UTC - [Parent 1: Main Thread]: E/nsHttp uri=${u}`).join('\r\n') + '\r\n';
fs.writeFileSync(older, mozLines(['https://example.test/', 'https://old-only.invalid/script/aaaaaaaaaa.js']));
fs.writeFileSync(newer, mozLines(['https://example.test/', 'https://new-only.invalid/script/bbbbbbbbbb.js']));
// A per-process sibling of the newer run must be included with it...
fs.writeFileSync(path.join(capDir, 'ff-111111-111111.log.child-3.moz_log'),
  mozLines(['https://sibling.invalid/script/cccccccccc.js']));
const old_t = new Date(Date.now() - 60000);
fs.utimesSync(older, old_t, old_t);

const dirCap = parseCapture(capDir);
const dirHosts = dirCap.entries.map(e => e.host);
check('a directory resolves to the NEWEST capture', dirHosts.includes('new-only.invalid'), true);
check('and does not merge the older one', dirHosts.includes('old-only.invalid'), false);
check("the newest run's own child logs are still included", dirHosts.includes('sibling.invalid'), true);
check('the resolved file is reported', path.basename(dirCap.filePath), 'ff-111111-111111.log.moz_log');

let dirThrew = '';
try { parseCapture(F('emptydir')); } catch (e) { dirThrew = e.message; }
fs.mkdirSync(F('emptydir'));
try { parseCapture(F('emptydir')); } catch (e) { dirThrew = e.message; }
check('an empty directory says so', /no capture found/.test(dirThrew), true);

// ---- even_blocked, and the two tools agreeing --------------------------
// har-rules.js and `nwss --har` read the same config and the same capture, so
// they must produce the same rules. They did not: har-rules excluded blocked
// requests while nwss honoured the site's even_blocked, so the same inputs gave
// different answers depending on which tool you reached for.
const HAR_RULES = path.join(__dirname, 'har-rules.js');
const runHarRules = (cfg, sel) => {
  let out;
  try {
    out = execFileSync(process.execPath, [HAR_RULES, harPath, '--config', cfg, '--site', String(sel)],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) { out = (e.stdout || '') + (e.stderr || ''); }
  const i = out.indexOf('rules:');
  return i === -1 ? [] : out.slice(i).split('\n').map(l => l.trim()).filter(l => l.startsWith('||')).sort();
};

for (const evenBlocked of [false, true]) {
  const cfg = JSON.parse(JSON.stringify(CONFIG));
  cfg.sites[1].even_blocked = evenBlocked;
  const cfgFile = F(`cfg-eb-${evenBlocked}.json`);
  fs.writeFileSync(cfgFile, JSON.stringify(cfg));

  const outFile = F(`eb-${evenBlocked}.txt`);
  run([cfgFile, '--har', harPath, '--site', '1', '--output', outFile, '--silent']);
  const viaNwss = outLines(outFile).sort();
  const viaHarRules = runHarRules(cfgFile, 1);

  check(`even_blocked:${evenBlocked} -- blocked host ${evenBlocked ? 'included' : 'excluded'}`,
    viaNwss.includes('||blockedbyubo.invalid^'), evenBlocked);
  check(`even_blocked:${evenBlocked} -- har-rules.js and nwss --har agree`,
    viaHarRules, viaNwss);
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
