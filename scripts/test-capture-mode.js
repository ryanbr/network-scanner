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
const { sniffFormat, parseCapture, selectSitesForCapture, pageUrlForSite } = require('../lib/capture');

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

// ---- filterRegex as an ARRAY, as the live scan accepts --------------------
// `new RegExp(array)` coerces the array to a comma-joined string, so
// ["a$","b$"] compiled to /a$,b$/ and matched NOTHING -- silently, with every
// url still counted as "considered". Found on a real site whose loader token
// (36 chars) needed a second pattern: 2071 considered, 0 matched.
const arrCfg = {
  ignoreDomains: [],
  sites: [{
    url: 'https://example.test/',
    filterRegex: ['\\/[a-z]{8,12}\\.js$', '\\/script\\/[A-Za-z0-9]{20,48}\\.js$'],
    firstParty: false
  }]
};
const arrHar = {
  log: {
    version: '1.2', creator: { name: 't', version: '1' },
    pages: [{ title: 'https://example.test/' }],
    entries: [
      harEntry('https://example.test/', 'document', 'text/html'),
      harEntry('https://first.invalid/abcdefghij.js', 'script', 'application/javascript'),
      harEntry('https://second.invalid/script/ABCDEFGHIJKLMNOPQRSTUV.js', 'script', 'application/javascript'),
      harEntry('https://neither.invalid/x.js', 'script', 'application/javascript')
    ]
  }
};
const arrHarPath = F('arr.har'); fs.writeFileSync(arrHarPath, JSON.stringify(arrHar));
const arrCfgPath = F('arr-cfg.json'); fs.writeFileSync(arrCfgPath, JSON.stringify(arrCfg));
const arrOut = F('arr-out.txt');
run([arrCfgPath, '--har', arrHarPath, '--site', '0', '--output', arrOut, '--silent']);
check('array filterRegex matches ANY pattern by default', outLines(arrOut).sort(),
  ['||first.invalid^', '||second.invalid^']);

// regex_and flips it to ALL, as it does for the live path.
const andCfg = JSON.parse(JSON.stringify(arrCfg));
andCfg.sites[0].regex_and = true;
const andCfgPath = F('and-cfg.json'); fs.writeFileSync(andCfgPath, JSON.stringify(andCfg));
const andOut = F('and-out.txt');
run([andCfgPath, '--har', arrHarPath, '--site', '0', '--output', andOut, '--silent']);
check('regex_and requires ALL patterns', outLines(andOut), []);

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
const runHarRules = (cfg, sel, har = harPath) => {
  let out;
  try {
    out = execFileSync(process.execPath, [HAR_RULES, har, '--config', cfg, '--site', String(sel)],
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

// ---- Chrome "Preserve log": one page per navigation -----------------------
// A HAR recorded with Preserve log carries several pages, and pageUrl is
// pages[0]. Using that for first/third-party made the SCANNED site read as
// third-party, so with firstParty:false it was published as a rule for itself.
// The page used for party must be the one belonging to THIS site.
{
  const pagesHar = F('preservelog.har');
  const mk = pages => ({
    log: {
      version: '1.2',
      creator: { name: 'WebInspector', version: '537.36' },
      pages,
      entries: [
        harEntry('https://target.invalid/article', 'document', 'text/html'),
        harEntry('https://third.invalid/a.js', 'script', 'application/javascript')
      ]
    }
  });
  // pages[0] is an EARLIER, unrelated navigation -- the trap.
  fs.writeFileSync(pagesHar, JSON.stringify(mk([
    { id: 'page_1', title: 'https://unrelated.invalid/', pageTimings: {} },
    { id: 'page_2', title: 'https://target.invalid/article', pageTimings: {} }
  ])));
  const singleHar = F('singlepage.har');
  fs.writeFileSync(singleHar, JSON.stringify(mk([
    { id: 'page_1', title: 'https://target.invalid/article', pageTimings: {} }
  ])));

  check('parseCapture exposes every page, not just the first',
    parseCapture(pagesHar).pageUrls,
    ['https://unrelated.invalid/', 'https://target.invalid/article']);
  check('pageUrlForSite picks the page belonging to the site',
    pageUrlForSite(parseCapture(pagesHar), ['https://target.invalid/article']),
    'https://target.invalid/article');
  check('pageUrlForSite reports nothing when no page matches',
    pageUrlForSite(parseCapture(pagesHar), ['https://elsewhere.invalid/']), '');

  const cfg3p = F('cfg3p.json');
  fs.writeFileSync(cfg3p, JSON.stringify({ sites: [{
    url: 'https://target.invalid/article', filterRegex: '.',
    firstParty: false, thirdParty: true
  }] }));
  const rulesOf = har => run(['--custom-json', cfg3p, '--har', har, '--site', 'target.invalid'])
    .split('\n').map(l => l.trim()).filter(l => l.startsWith('||')).sort();

  // The regression: the scanned site must never be emitted as its own rule.
  check('preserve-log HAR does not publish the scanned site as a rule',
    rulesOf(pagesHar).includes('||target.invalid^'), false);
  check('preserve-log HAR matches the single-page HAR exactly',
    rulesOf(pagesHar), rulesOf(singleHar));

  // har-rules.js must agree with nwss --har on a MULTI-PAGE har too. The
  // existing agreement check uses a single-page fixture, so it could not see
  // har-rules.js still deciding party from pages[0].
  check('har-rules.js and nwss --har agree on a preserve-log HAR',
    runHarRules(cfg3p, 'target.invalid', pagesHar), rulesOf(pagesHar));
}

// ---- output_regex in the capture path --------------------------------------
// The flag was honoured by the live scan and silently ignored from a capture:
// `output_regex` had zero references in lib/har.js, so the same config produced
// a narrowed ||host/path/ rule live and a whole-host ||host^ rule from a MOZ_LOG
// or HAR. Both now go through outputKeyFromUrl(), so these checks pin the shared
// contract from the capture side; the four unit checks below pin the helper
// itself, including the two mis-written patterns it must refuse.
{
  const orHar = F('or.har');
  fs.writeFileSync(orHar, JSON.stringify({ log: {
    version: '1.2',
    creator: { name: 'WebInspector', version: '537.36' },
    pages: [{ id: 'page_1', title: 'https://target.invalid/', pageTimings: {} }],
    entries: [
      harEntry('https://target.invalid/', 'document', 'text/html'),
      harEntry('https://a.invalid/script/abcdefgh1234.js', 'script', 'application/javascript'),
      harEntry('https://b.invalid/other/abcdefgh1234.js', 'script', 'application/javascript'),
      harEntry('https://deep.sub.c.invalid/other/abcdefgh1234.js', 'script', 'application/javascript')
    ]
  } }));

  const mkCfg = (name, outputRegex) => {
    const f = F(name);
    const site = {
      url: 'https://target.invalid/', filterRegex: '\\/[A-Za-z0-9]{8,12}\\.js$',
      firstParty: false, thirdParty: true
    };
    if (outputRegex !== undefined) site.output_regex = outputRegex;
    fs.writeFileSync(f, JSON.stringify({ sites: [site] }));
    return f;
  };
  const rulesOf = cfg => run(['--custom-json', cfg, '--har', orHar, '--site', 'target.invalid'])
    .split('\n').map(l => l.trim()).filter(l => l.startsWith('||')).sort();

  // Baseline: no output_regex, so both hosts emit as whole hosts.
  check('capture: no output_regex emits whole hosts',
    rulesOf(mkCfg('or-none.json', undefined)),
    ['||a.invalid^', '||b.invalid^', '||c.invalid^']);

  // The fix: a host+path capture narrows the matching URL's rule, and the URL
  // the pattern does NOT match still emits its whole host rather than vanishing.
  check('capture: output_regex narrows the matching url and falls back on the rest',
    rulesOf(mkCfg('or-path.json', '^https?:\\/\\/([^\\/]+\\/script\\/)')),
    ['||a.invalid/script/', '||b.invalid^', '||c.invalid^']);

  // A HOST-ONLY capture must NOT narrow the host -- it falls back. This is the
  // documented gate, and the reason output_regex cannot be used to collapse
  // 1.host.site.com and ab.n.host.site.com onto ||host.site.com^.
  //
  // deep.sub.c.invalid is in the fixture so this check DISCRIMINATES: the
  // capture is the full host, the fallback is the registrable domain, so they
  // are different strings. Written first with a capture equal to its own
  // fallback, it passed with the gate deleted -- a check that cannot fail.
  check('capture: a host-only output_regex capture falls back to the normal key',
    rulesOf(mkCfg('or-host.json', '^https?:\\/\\/([^\\/]+)')),
    ['||a.invalid^', '||b.invalid^', '||c.invalid^']);

  // A pattern that swallows the scheme makes the host part read "https:", which
  // has no dot, so it is refused rather than emitted as a garbage rule.
  check('capture: an output_regex capture including the scheme falls back',
    rulesOf(mkCfg('or-scheme.json', '^(https?:\\/\\/[^\\/]+\\/script\\/)')),
    ['||a.invalid^', '||b.invalid^', '||c.invalid^']);

  // An uncompilable pattern must disable the feature for the site, not throw and
  // lose every other rule in the run.
  check('capture: an invalid output_regex is ignored, other rules survive',
    rulesOf(mkCfg('or-bad.json', '([unclosed')),
    ['||a.invalid^', '||b.invalid^', '||c.invalid^']);

  // The parity this change exists for: har-rules.js and nwss --har must agree
  // under output_regex, as they already do without it.
  check('har-rules.js and nwss --har agree under output_regex',
    runHarRules(mkCfg('or-path2.json', '^https?:\\/\\/([^\\/]+\\/script\\/)'), 'target.invalid', orHar),
    rulesOf(mkCfg('or-path.json', '^https?:\\/\\/([^\\/]+\\/script\\/)')));

  // The shared helper itself, including the group-1-vs-whole-match rule.
  const { outputKeyFromUrl } = require('../lib/output');
  const U = 'https://a.invalid/script/x.js';
  check('helper: host+path capture is used',
    outputKeyFromUrl(U, /^https?:\/\/([^/]+\/script\/)/, 'a.invalid'), 'a.invalid/script/');
  check('helper: whole match is used when there is no capture group',
    outputKeyFromUrl(U, /a\.invalid\/script\//, 'a.invalid'), 'a.invalid/script/');
  // fallback deliberately UNLIKE the capture, for the same discrimination reason
  check('helper: host-only capture falls back',
    outputKeyFromUrl('https://x.a.invalid/script/x.js', /^https?:\/\/([^/]+)/, 'a.invalid'),
    'a.invalid');
  check('helper: no regex and no url both fall back',
    [outputKeyFromUrl(U, null, 'a.invalid'), outputKeyFromUrl('', /x/, 'a.invalid')],
    ['a.invalid', 'a.invalid']);
}

// ---- subDomains accepted as 1 AND true ------------------------------------
// nwss.js keyed this off `subDomains === 1` while matchEntries() accepted 1 or
// true, so "subDomains": true preserved subdomains in a rule built from a
// capture and was silently ignored in a live scan of the same config. The
// README documents the field as `0 or 1`, which is what makes `true` plausible
// to write. Both now call useSubDomainsFor().
{
  const { useSubDomainsFor } = require('../lib/har');
  check('useSubDomainsFor accepts 1', useSubDomainsFor({ subDomains: 1 }), true);
  check('useSubDomainsFor accepts true', useSubDomainsFor({ subDomains: true }), true);
  check('useSubDomainsFor rejects 0', useSubDomainsFor({ subDomains: 0 }), false);
  check('useSubDomainsFor rejects false', useSubDomainsFor({ subDomains: false }), false);
  check('useSubDomainsFor defaults to off', useSubDomainsFor({}), false);

  // End to end from a capture, so the two spellings must agree in the OUTPUT
  // and not merely in the predicate.
  const sdHar = F('sd.har');
  fs.writeFileSync(sdHar, JSON.stringify({ log: {
    version: '1.2',
    creator: { name: 'WebInspector', version: '537.36' },
    pages: [{ id: 'page_1', title: 'https://target.invalid/', pageTimings: {} }],
    entries: [
      harEntry('https://target.invalid/', 'document', 'text/html'),
      harEntry('https://deep.sub.ads.invalid/abcdefgh1234.js', 'script', 'application/javascript')
    ]
  } }));
  const sdRules = v => {
    const f = F(`sd-${String(v)}.json`);
    const site = {
      url: 'https://target.invalid/', filterRegex: '\\/[A-Za-z0-9]{8,12}\\.js$',
      firstParty: false, thirdParty: true
    };
    if (v !== undefined) site.subDomains = v;
    fs.writeFileSync(f, JSON.stringify({ sites: [site] }));
    return run(['--custom-json', f, '--har', sdHar, '--site', 'target.invalid'])
      .split('\n').map(l => l.trim()).filter(l => l.startsWith('||')).sort();
  };
  check('capture: subDomains omitted keys on the registrable domain',
    sdRules(undefined), ['||ads.invalid^']);
  check('capture: subDomains 1 preserves the full host',
    sdRules(1), ['||deep.sub.ads.invalid^']);
  check('capture: subDomains true preserves the full host too',
    sdRules(true), ['||deep.sub.ads.invalid^']);
  check('capture: both spellings agree', sdRules(1), sdRules(true));

  // The live-scan half cannot be exercised offline -- it needs a browser -- so
  // this pins the SOURCE instead: nwss.js must route through the shared
  // predicate and must not reintroduce a bare `subDomains === 1` comparison.
  // A drift canary, not a behaviour test, and the only offline check that can
  // see a re-divergence of the live path.
  const nwssSrc = fs.readFileSync(path.join(__dirname, '..', 'nwss.js'), 'utf8');
  check('nwss.js uses the shared subDomains predicate',
    nwssSrc.includes('useSubDomainsFor({ subDomains })'), true);
  check('nwss.js has no bare `subDomains === 1` comparison left',
    /subDomains\s*===\s*1/.test(nwssSrc), false);
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
