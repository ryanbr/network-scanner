#!/usr/bin/env node
/**
 * Pre-seeding regression suite — cookies, Web Storage and the $popup signal.
 *
 * Covers lib/cookies.js, lib/storage.js, lib/site-scope.js and the popunder
 * signal path (lib/adblock.js's createPopupSignalMatcher plus nwss.js's
 * capture_popups_signal), at three levels: pure-function checks, Puppeteer
 * harnesses that exercise the real browser behaviour, and end-to-end nwss runs
 * driven from generated configs.
 *
 * Purpose: every check here exists because a review pass found a real bug, and
 * most of them are things static reading got WRONG. A cookie without a leading
 * dot is host-only on the CDP path even though the same string in a Set-Cookie
 * header is not. One rejected cookie in a batch used to reject the whole batch.
 * DOMStorage removal resolves through the inspected target's frame tree, so the
 * seeding page being closed silently stranded the keys. A throwing signal matcher
 * discarded a capture the page had already matched. None of that is visible by
 * inspection, so it is pinned by execution instead.
 *
 * Self-contained: fixture servers bind ephemeral ports, configs and filter lists
 * are generated into a temp directory, and nothing depends on a scan config,
 * a downloaded filter list or a previous run.
 *
 * Mutation-verified 2026-09-26: each of the ten fixes these checks pin was
 * reverted in turn, and the suite went red every time. Worth repeating after
 * adding a check -- a check that cannot fail is decoration. The first attempt at
 * that exercise also produced a false clean bill of health, by injecting the
 * throw INSIDE the try/catch it meant to disable; make the mutation remove the
 * guard, not exercise it.
 *
 * Usage:
 *   node scripts/test-seeding.js                   # everything
 *   node scripts/test-seeding.js cookie            # only checks matching "cookie"
 *   node scripts/test-seeding.js --group=unit      # unit | browser | e2e
 *   node scripts/test-seeding.js --list            # list check names and exit
 *   node scripts/test-seeding.js --verbose         # show each check's own output
 *   node scripts/test-seeding.js --keep            # keep the temp fixture dir
 *   node scripts/test-seeding.js --help
 *
 * Environment:
 *   PUPPETEER_NO_SANDBOX=1   pass --no-sandbox --disable-setuid-sandbox to
 *                            Chromium. Required when running as root (CI
 *                            containers). Off by default so local dev does not
 *                            silently drop the sandbox.
 *
 * Exit code: 0 when every selected check passes, 1 when any fails, 2 on bad
 * usage — so it is usable as a gate.
 */

const fs = require('fs');
const os = require('os');
const http = require('http');
const path = require('path');
const puppeteer = require('puppeteer');

const { messageColors } = require('../lib/colorize');
const { runProcess } = require('../lib/spawn-async');
const { registrableDomain, siteScope } = require('../lib/site-scope');
const { normalizeCookies, applyCookies, applySiteCookies, retainSeeded, removeCookies } = require('../lib/cookies');
const { applySiteStorage, retainSeeded: retainSeededStorage, removeStorage } = require('../lib/storage');
const { createPopupSignalMatcher, parseAdblockRules } = require('../lib/adblock');
const { validateSiteConfig, normalizeSiteConfig } = require('../lib/validate_rules');

const REPO_ROOT = path.resolve(__dirname, '..');
const NWSS = path.join(REPO_ROOT, 'nwss.js');

// Resolver rules let the browser reach invented hostnames on the loopback
// fixture server, which is the only way to test a real apex -> www redirect:
// an IP literal has no subdomains, and the scope rules being tested are all
// about subdomains.
const SITE = 'seedtest.example';
const RESOLVER_HOSTS = [SITE, `www.${SITE}`, `other.${SITE}`];

// nwss runs are a whole scan each (browser launch, page load, delay, teardown),
// so they get their own generous budget rather than runProcess's 30s default.
const NWSS_TIMEOUT_MS = 180000;

const args = process.argv.slice(2);
const HELP = args.includes('--help') || args.includes('-h');
const LIST = args.includes('--list');
const VERBOSE = args.includes('--verbose');
const KEEP = args.includes('--keep');
const GROUP = (args.find(a => a.startsWith('--group=')) || '').split('=')[1] || null;
const NAME_FILTERS = args.filter(a => !a.startsWith('-'));
const KNOWN_FLAGS = new Set(['--help', '-h', '--list', '--verbose', '--keep']);
const GROUPS = ['unit', 'browser', 'e2e'];

function printHelp() {
  console.log(`
Pre-seeding regression suite (cookies / storage / $popup signal).

Usage:
  node scripts/test-seeding.js [name-filter ...] [flags]

Flags:
  --group=<unit|browser|e2e>  run only one layer
  --list                      print check names and exit
  --verbose                   print each check's detail lines
  --keep                      keep the temp fixture directory
  --help, -h                  show this message

Environment:
  PUPPETEER_NO_SANDBOX=1      pass --no-sandbox to Chromium (required in some CI)

Exit code 0 = all selected checks passed, 1 = a failure, 2 = bad usage.
`);
}

// ---------------------------------------------------------------------------
// tiny assertion helpers — each throws with a message that names the actual
// value, because "expected true" tells you nothing when a check fails in CI.
// ---------------------------------------------------------------------------

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

/** Thrown by a check that cannot run here -- reported as SKIP, not a failure. */
class SkipCheck extends Error {}

/**
 * The popup checks need a SECOND loopback address: a popup must be third-party to
 * its opener to survive first-party cleanup, and 127.0.0.1 vs 127.0.0.2 is the
 * only way to get two registrable domains without DNS. Linux answers on the whole
 * 127/8 range; macOS binds 127.0.0.1 only unless an alias was added, so check
 * rather than fail with something cryptic.
 */
async function requireSecondLoopback(port) {
  await new Promise((resolve, reject) => {
    const req = http.get(`http://127.0.0.2:${port}/`, (res) => {
      res.resume();
      resolve();
    });
    req.setTimeout(2000, () => req.destroy(new Error('timed out')));
    req.on('error', (err) => reject(new SkipCheck(
      `127.0.0.2 is not reachable (${err.message}). On macOS: sudo ifconfig lo0 alias 127.0.0.2 up`)));
  });
}

function assertEqual(actual, expected, what) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) throw new Error(`${what}: got ${a}, want ${e}`);
}

function assertIncludes(haystack, needle, what) {
  if (!String(haystack).includes(needle)) {
    throw new Error(`${what}: output does not contain ${JSON.stringify(needle)}`);
  }
}

function assertExcludes(haystack, needle, what) {
  if (String(haystack).includes(needle)) {
    throw new Error(`${what}: output unexpectedly contains ${JSON.stringify(needle)}`);
  }
}

/**
 * Run fn with console.log captured, so a check can assert on what the library
 * PRINTED. Several behaviours here are warnings -- "this failed and a later URL
 * may inherit state" -- and a warning nobody can see is the bug, not the
 * behaviour, so the text is worth pinning. Also keeps expected noise out of the
 * suite's own output.
 * @param {Function} fn - async function to run
 * @returns {Promise<{value: *, output: string}>}
 */
async function captureLogs(fn) {
  const lines = [];
  const original = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  try {
    const value = await fn();
    return { value, output: lines.join('\n') };
  } finally {
    console.log = original;
  }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/**
 * One fixture server serving every route the checks need. Binds an ephemeral
 * port (listen(0)) so parallel runs and a busy dev box cannot collide.
 *
 * Routes:
 *   /gate            page that reports cookies + both storage areas back
 *   /redirect        302 to http://www.<SITE>:<port>/landed  (apex -> www)
 *   /landed          plain page, records the Cookie header it received
 *   /opener          page that window.open()s the popup target
 *   /pop-target.html popup destination, matches the test list's $popup rule
 *   /report?d=...    readback sink; every hit is appended to the log
 */
async function startFixtureServer() {
  const hits = [];
  // Which e2e check's readback log to append to. Mutable so each run reads back
  // only its own page loads.
  let logPath = null;
  const server = http.createServer((req, res) => {
    const url = req.url || '/';
    hits.push({ host: req.headers.host || '', url, cookie: req.headers.cookie || null });

    if (url.startsWith('/report')) {
      let payload = '';
      try {
        payload = decodeURIComponent(new URL(url, 'http://x').searchParams.get('d') || '');
      } catch (_) { /* malformed report; record the raw hit only */ }
      if (logPath) {
        fs.appendFileSync(logPath, `COOKIE_HEADER=${JSON.stringify(req.headers.cookie || null)}\nPAGE_READBACK=${payload}\n`);
      }
      res.writeHead(204);
      res.end();
      return;
    }

    if (url.startsWith('/redirect')) {
      res.writeHead(302, { location: `http://www.${SITE}:${server.address().port}/landed` });
      res.end();
      return;
    }

    if (url.startsWith('/pop-target.html')) {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><html><body>popunder destination</body></html>');
      return;
    }

    if (url.startsWith('/opener')) {
      // The target arrives base64-encoded (?to64=) on purpose. Passing it in
      // clear put the literal "pop-target.html" in the OPENER's own URL, so a
      // filterRegex meant to match only the popup matched the main page too and
      // captured the opener's domain instead -- the fixture silently tested
      // something else. Cost a real debugging detour; keep it encoded.
      let target = '/pop-target.html';
      try {
        const raw = new URL(url, 'http://x').searchParams.get('to64');
        if (raw) target = Buffer.from(raw, 'base64').toString('utf8');
      } catch (_) { /* fall back to the relative default */ }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(`<!doctype html><html><body>opener<script>window.open(${JSON.stringify(target)},'_blank');</script></body></html>`);
      return;
    }

    if (url.startsWith('/gate')) {
      res.writeHead(200, { 'content-type': 'text/html' });
      // Reads everything in the FIRST inline script: anything visible here was
      // seeded before the page's own code ran, which is the entire contract.
      res.end(`<!doctype html><html><body><script>
        function dump(s){const o={};for(let i=0;i<s.length;i++){const k=s.key(i);o[k]=s.getItem(k);}return o;}
        var r={where:location.href,cookie:document.cookie,local:dump(localStorage),session:dump(sessionStorage)};
        window.__seedReport = r;
        new Image().src = '/report?d=' + encodeURIComponent(JSON.stringify(r));
      </script>gate</body></html>`);
      return;
    }

    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<!doctype html><html><body>ok</body></html>');
  });

  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  return {
    port,
    hits,
    setLog: (p) => { logPath = p; },
    ipBase: `http://127.0.0.1:${port}`,
    // A second loopback IP: a distinct root domain from 127.0.0.1, so a popup
    // there is third-party to the opener and survives first-party cleanup.
    popupBase: `http://127.0.0.2:${port}`,
    apexBase: `http://${SITE}:${port}`,
    wwwBase: `http://www.${SITE}:${port}`,
    // Build an opener URL whose own text cannot match a filterRegex aimed at the
    // popup (see the /opener route).
    openerFor: (popupUrl) => `http://127.0.0.1:${port}/opener?to64=${Buffer.from(popupUrl, 'utf8').toString('base64')}`,
    lastHit: () => hits[hits.length - 1] || null,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

function launchBrowser(extraArgs = []) {
  const browserArgs = [...extraArgs];
  if (process.env.PUPPETEER_NO_SANDBOX) browserArgs.push('--no-sandbox', '--disable-setuid-sandbox');
  return puppeteer.launch({ headless: true, args: browserArgs });
}

function resolverRuleArg() {
  // Host-only mapping: the fixture URL already carries the ephemeral port, and
  // the resolver preserves it.
  return `--host-resolver-rules=${RESOLVER_HOSTS.map(h => `MAP ${h} 127.0.0.1`).join(', ')}`;
}

/** localStorage keys currently visible to a page, as a sorted array. */
function storageKeys(page) {
  return page.evaluate(() => Object.keys(localStorage).sort());
}

/**
 * Run a real nwss scan against a generated config.
 * @returns {Promise<{stdout: string, code: number|null, readback: Array<object>}>}
 */
async function runNwss(ctx, config, extraArgs = [], { readbackLog = null } = {}) {
  const cfgPath = path.join(ctx.tmpDir, `cfg-${ctx.nextId()}.json`);
  fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2));
  // Point the fixture server at this run's log here rather than trusting each
  // check to do it: forgetting would silently read back the PREVIOUS run's loads
  // and assert against them.
  ctx.setReadbackLog(readbackLog);
  if (readbackLog) fs.writeFileSync(readbackLog, '');

  // runProcess resolves (never rejects) with Buffers, and inherits this
  // process's cwd -- main() chdir's to the repo root for that reason.
  const result = await runProcess('node', [NWSS, '--custom-json', cfgPath, ...extraArgs], {
    timeout: NWSS_TIMEOUT_MS
  });

  const readback = [];
  if (readbackLog && fs.existsSync(readbackLog)) {
    const blocks = fs.readFileSync(readbackLog, 'utf8').split('COOKIE_HEADER=').filter(b => b.trim());
    for (const block of blocks) {
      const [header, rest] = block.split('\nPAGE_READBACK=');
      try {
        readback.push({ cookieHeader: JSON.parse(header.trim()), page: JSON.parse((rest || '').trim()) });
      } catch (_) { /* truncated block mid-write; ignore */ }
    }
  }
  const stdout = `${(result.stdout || '').toString()}${(result.stderr || '').toString()}`;
  return { stdout, code: result.code, readback };
}

// A deliberately tiny filter list: deterministic, unlike easylist.txt, which is
// not tracked and whose rule counts move every update.
const TEST_LIST = [
  '[Adblock Plus 2.0]',
  '! test list for scripts/test-seeding.js',
  '/pop-target.html$popup',
  '@@/pop-target.html$popup,domain=never.example',
  '||some-unrelated-domain.test^$popup',
  '||ads.example.com^$popup,third-party',
  '##.cosmetic-popup-rule',
  '||blocked-normally.test^'
].join('\n');

// ---------------------------------------------------------------------------
// checks
// ---------------------------------------------------------------------------

const CHECKS = [];
const check = (group, name, run) => CHECKS.push({ group, name, run });

// ----- unit -----

check('unit', 'site-scope: registrable domain and its non-widenable cases', async () => {
  const expected = {
    'domain.com': 'domain.com',
    'www.domain.com': 'domain.com',
    'abc.xyz.domain.com': 'domain.com',
    'example.co.uk': 'example.co.uk',
    'www.example.co.uk': 'example.co.uk',
    // Nothing below has a wider scope than itself, and widening any of them
    // would be wrong: psl.get('127.0.0.1') is '0.1', which would make unrelated
    // IPs share a scope.
    'co.uk': null,
    localhost: null,
    '127.0.0.1': null,
    '::1': null,
    '': null
  };
  for (const [host, want] of Object.entries(expected)) {
    assertEqual(registrableDomain(host), want, `registrableDomain(${JSON.stringify(host)})`);
  }
  // siteScope is the MATCHING variant: it falls back to the host so an
  // unwidenable host still matches itself.
  assertEqual(siteScope('localhost'), 'localhost', 'siteScope(localhost)');
  assertEqual(siteScope('127.0.0.1'), '127.0.0.1', 'siteScope(127.0.0.1)');
  assertEqual(siteScope('www.domain.com'), 'domain.com', 'siteScope(www.domain.com)');
  return '10 host shapes + both fallbacks';
});

check('unit', 'cookies: short form defaults to the whole site', async () => {
  const cases = [
    ['https://www.domain.com/a/b', '.domain.com'],
    ['https://domain.com/', '.domain.com'],
    ['https://a.b.c.domain.co.uk/', '.domain.co.uk'],
    // No wider scope to take, so host-only: '.localhost' is not storable.
    ['http://localhost:8080/', 'localhost'],
    ['http://127.0.0.1:9/', '127.0.0.1']
  ];
  for (const [url, want] of cases) {
    const { cookies } = normalizeCookies({ consent: 'granted' }, url);
    assertEqual(cookies[0].domain, want, `default domain for ${url}`);
  }
  // Explicit values are honoured verbatim, including asking for host-only.
  assertEqual(normalizeCookies([{ name: 'x', value: '1', domain: '.www.domain.com' }], 'https://www.domain.com/').cookies[0].domain,
    '.www.domain.com', 'explicit .www domain');
  assertEqual(normalizeCookies([{ name: 'x', value: '1', domain: 'www.domain.com' }], 'https://www.domain.com/').cookies[0].domain,
    'www.domain.com', 'explicit host-only domain');
  return '5 default scopes + 2 explicit forms';
});

check('unit', 'cookies: the host-only warning only suggests storable scopes', async () => {
  // [domain, url, shouldWarn]. The false rows are the bug this pins: suggesting
  // '.com' or '.0.0.1' sends someone to a cookie that cannot carry anything.
  const rows = [
    ['domain.com', 'https://www.domain.com/', true],
    ['b.domain.com', 'https://a.b.domain.com/', true],
    ['com', 'https://www.domain.com/', false],
    ['co.uk', 'https://www.site.co.uk/', false],
    ['0.0.1', 'http://127.0.0.1:9/', false],
    ['www.domain.com', 'https://www.domain.com/', false],
    ['other.test', 'https://www.domain.com/', false],
    ['.domain.com', 'https://www.domain.com/', false]
  ];
  for (const [domain, url, shouldWarn] of rows) {
    const { errors } = normalizeCookies([{ name: 'x', value: '1', domain }], url);
    const warned = errors.some(e => e.includes('HOST-ONLY'));
    assertEqual(warned, shouldWarn, `warning for domain=${JSON.stringify(domain)} on ${url}`);
  }
  return '8 domain shapes';
});

check('unit', 'cookies: a relative path is corrected before the browser sees it', async () => {
  const bad = normalizeCookies([{ name: 'x', value: '1', path: 'relative' }], 'https://www.domain.com/');
  assertEqual(bad.cookies[0].path, '/', 'relative path falls back');
  assert(bad.errors.some(e => e.includes('not absolute')), 'relative path is reported');
  assertEqual(normalizeCookies([{ name: 'x', value: '1', path: '/keep' }], 'https://www.domain.com/').cookies[0].path,
    '/keep', 'absolute path is kept');
  return 'relative corrected, absolute preserved';
});

check('unit', 'cookies: a repeated identity is deduped and reported', async () => {
  // One cookie in the browser, so the later entry silently won and the earlier
  // vanished. lib/storage.js has always warned about this shape for storage keys;
  // the two modules disagreed until 2026-09-26.
  const dup = normalizeCookies([{ name: 'dup', value: 'first' }, { name: 'dup', value: 'second' }], 'https://www.domain.com/');
  assertEqual(dup.cookies.length, 1, 'duplicate identities collapse to one cookie');
  assertEqual(dup.cookies[0].value, 'second', 'the last declaration wins, as setCookie would');
  assert(dup.errors.some(e => e.includes('declared more than once')), 'the collision is reported');

  // Same NAME on different domains is two real cookies, not a collision.
  const distinct = normalizeCookies([
    { name: 'same', value: '1', domain: '.a.test' },
    { name: 'same', value: '2', domain: '.b.test' }
  ], 'https://www.domain.com/');
  assertEqual(distinct.cookies.length, 2, 'same name on different domains is kept');
  assertEqual(distinct.errors.length, 0, 'and is not reported');
  return 'deduped with a warning; distinct domains untouched';
});

check('unit', 'popup signal: parses $popup rules that blocking discards', async () => {
  const listPath = path.join(os.tmpdir(), `nwss-seed-list-${process.pid}.txt`);
  fs.writeFileSync(listPath, TEST_LIST);
  try {
    const sig = createPopupSignalMatcher(listPath);
    // 3 non-exception $popup rules: one path rule, two exact-domain.
    assertEqual(sig.size, 3, 'retained signal rules');
    assertEqual(sig.domainEntries, 2, 'exact-domain signal rules');
    assertEqual(sig.scanEntries, 1, 'path/regex signal rules');
    assertEqual(sig.unparseable, 0, 'unparseable signal rules');

    assertEqual(sig.match('http://x.test/pop-target.html?a=1', 'http://site.test/'), '/pop-target.html$popup', 'path rule match');
    assertEqual(sig.match('http://some-unrelated-domain.test/x', 'http://site.test/'), '||some-unrelated-domain.test^$popup', 'domain rule match');
    // Parent-suffix walk, same as the blocking path's.
    assertEqual(sig.match('http://sub.some-unrelated-domain.test/x', 'http://site.test/'), '||some-unrelated-domain.test^$popup', 'subdomain match');
    assertEqual(sig.match('http://unrelated.test/asset.png', 'http://site.test/'), null, 'non-matching URL');
    // Third-party status comes from BASE domains, exactly as shouldBlock derives
    // it -- so this rule must not report for a sibling of the opener.
    assertEqual(sig.match('http://ads.example.com/x', 'http://www.example.com/'), null, 'same-site opener is not third-party');
    assertEqual(sig.match('http://ads.example.com/x', 'http://other.test/'), '||ads.example.com^$popup,third-party', 'third-party opener matches');

    // The same list must not contribute popup rules to BLOCKING.
    const blocker = parseAdblockRules(listPath, {});
    assertEqual(blocker.shouldBlock('http://x.test/pop-target.html', 'http://site.test/', 'document').blocked, false, '$popup rule does not block');
    assertEqual(blocker.shouldBlock('http://blocked-normally.test/x', 'http://site.test/', 'script').blocked, true, 'ordinary rule still blocks');
    assert(blocker.matchPopupSignal === undefined, 'signal is not exposed on the blocking matcher');
    return 'composition, 6 match shapes, blocking unaffected';
  } finally {
    try { fs.unlinkSync(listPath); } catch (_) { /* best effort */ }
  }
});

check('unit', 'validator: cookie scope warning and boolean coercion', async () => {
  // The probe URL must be a REAL one from the config, or the host-derived
  // warning silently never fires for array-url sites.
  const arraySite = validateSiteConfig({
    url: ['https://www.domain.com/a', 'https://www.domain.com/b'],
    cookies: [{ name: 'x', value: '1', domain: 'domain.com' }]
  }, 0);
  assert(arraySite.warnings.some(w => w.includes('HOST-ONLY')), 'array-url site warns about a host-only parent domain');

  const cfg = { url: 'https://x.test', capture_popups: 1, capture_popups_signal: 1, interact_popups: 'yes' };
  normalizeSiteConfig(cfg, 0);
  assertEqual([cfg.capture_popups, cfg.capture_popups_signal, cfg.interact_popups], [true, true, true], 'boolean-like coercion');

  const typo = normalizeSiteConfig({ url: 'https://x.test', capture_popups_signl: true }, 1);
  assert(typo.warnings.some(w => w.includes('capture_popups_signal')), 'typo suggestion names the real key');
  return 'array-url probe, 3 coercions, typo suggestion';
});

// ----- browser harnesses -----

check('browser', 'seeds survive an apex -> www redirect', async (ctx) => {
  const browser = await launchBrowser([resolverRuleArg()]);
  try {
    const page = await browser.newPage();
    const siteConfig = {
      cookies: { c1: true, c2: 'granted', c3: 'b', c4: 3 },
      local_storage: { l1: true, l2: 'granted', l3: 7, l4: { ok: true } },
      session_storage: { s1: 1, s2: false, s3: 'x', s4: [1, 2] }
    };
    const seeded = await applySiteCookies(page, siteConfig, `${ctx.server.apexBase}/`, false);
    assertEqual(seeded.applied, 4, 'cookies applied');
    // Stored dotted = domain-scoped. A bare domain here would be host-only and
    // would not survive the hop, which is the bug this pins.
    const jar = await page.browserContext().cookies();
    for (const cookie of jar) {
      assertEqual(cookie.domain, `.${SITE}`, `stored scope of ${cookie.name}`);
    }
    await applySiteStorage(page, siteConfig, `${ctx.server.apexBase}/`, false);

    await page.goto(`${ctx.server.apexBase}/redirect`, { waitUntil: 'domcontentloaded' });
    const landed = await page.evaluate(() => location.hostname);
    assertEqual(landed, `www.${SITE}`, 'landed host');
    const sent = ctx.server.lastHit().cookie || '';
    for (const name of ['c1', 'c2', 'c3', 'c4']) {
      assertIncludes(sent, `${name}=`, `cookie ${name} reached the post-redirect host`);
    }
    // Storage matches on the registrable domain, so it re-seeds on the new
    // document; the cookie scope has to be just as wide or the two disagree.
    await page.goto(`${ctx.server.wwwBase}/gate`, { waitUntil: 'domcontentloaded' });
    const report = await page.evaluate(() => window.__seedReport);
    assertEqual(Object.keys(report.local).sort(), ['l1', 'l2', 'l3', 'l4'], 'localStorage on the www document');
    assertEqual(Object.keys(report.session).sort(), ['s1', 's2', 's3', 's4'], 'sessionStorage on the www document');
    return '4 cookies + 4 local + 4 session across the hop';
  } finally {
    await browser.close();
  }
});

check('browser', 'cookie teardown is reference-counted across concurrent URLs', async (ctx) => {
  const browser = await launchBrowser([resolverRuleArg()]);
  try {
    const cfg = { cookies: { a: '1', b: '2', c: '3', d: '4' } };
    const p1 = await browser.newPage();
    const p2 = await browser.newPage();
    const s1 = (await applySiteCookies(p1, cfg, `${ctx.server.apexBase}/`, false)).cookies;
    retainSeeded(s1);
    const s2 = (await applySiteCookies(p2, cfg, `${ctx.server.apexBase}/`, false)).cookies;
    retainSeeded(s2);

    const first = await removeCookies(p1, s1, false);
    assertEqual(first.removed, 0, 'first finisher must not remove a cookie the second still needs');
    assertEqual((await p1.browserContext().cookies()).length, 4, 'jar after the first teardown');

    const second = await removeCookies(p2, s2, false);
    assertEqual(second.removed, 4, 'last finisher removes all four');
    assertEqual((await p2.browserContext().cookies()).length, 0, 'jar after the last teardown');
    return 'dotted cookies: 0 then 4, empty jar';
  } finally {
    await browser.close();
  }
});

check('browser', 'one rejected cookie costs only itself', async (ctx) => {
  const browser = await launchBrowser([resolverRuleArg()]);
  try {
    const page = await browser.newPage();
    // '.0.0.1' is refused by CDP. It used to take every other cookie in the
    // same setCookie() call with it, leaving the jar empty.
    // applyCookies directly, because applySiteCookies does not forward its
    // per-cookie `error` string and that string is what names the offender.
    const { cookies } = normalizeCookies([
      { name: 'good1', value: '1' },
      { name: 'bad', value: '2', domain: '.0.0.1' },
      { name: 'good2', value: '3' }
    ], `${ctx.server.apexBase}/`);
    const { value: res, output } = await captureLogs(() => applyCookies(page, cookies, false));
    assertEqual(res.applied, 2, 'the two valid cookies still land');
    assertIncludes(output, 'Browser rejected cookie bad', 'the rejection is reported with the cookie name');
    const names = (await page.browserContext().cookies()).map(c => c.name).sort();
    assertEqual(names, ['good1', 'good2'], 'jar contents');
    assertIncludes(res.error || '', 'bad', 'the rejected cookie is named in the result');
    return '2 of 3 applied, offender named';
  } finally {
    await browser.close();
  }
});

check('browser', 'storage writes are per-key: one over-quota value does not stop the rest', async (ctx) => {
  const browser = await launchBrowser();
  try {
    const page = await browser.newPage();
    const big = 'x'.repeat(6 * 1024 * 1024);      // over the ~5MB per-origin quota
    const { output } = await captureLogs(() =>
      applySiteStorage(page, { local_storage: { a: '1', b: '2', big, d: '4' } }, `${ctx.server.ipBase}/`, false));
    assertIncludes(output, 'per-origin quota', 'the oversized value is flagged before the page loads');
    await page.goto(`${ctx.server.ipBase}/gate`, { waitUntil: 'domcontentloaded' });
    assertEqual(await storageKeys(page), ['a', 'b', 'd'], 'keys written alongside the failing one');
    return '3 of 4 keys written';
  } finally {
    await browser.close();
  }
});

check('browser', 'storage teardown survives the seeding page closing', async (ctx) => {
  const browser = await launchBrowser();
  try {
    // DOMStorage removal resolves through the inspected target's frame tree, so
    // a sibling page ON the origin can do it and a blank one cannot. Without the
    // sibling route, a closed seeding page stranded the keys forever -- the
    // refcount is dropped by then, so nothing retries.
    for (const [label, siblingUrl, wantRemoved] of [
      ['sibling on the origin', `${ctx.server.ipBase}/gate`, 2],
      ['sibling on about:blank', null, 0]
    ]) {
      const ctxt = await browser.createBrowserContext();
      const seeder = await ctxt.newPage();
      const seeded = await applySiteStorage(seeder, { local_storage: { k1: 'v', k2: 'v' } }, `${ctx.server.ipBase}/`, false);
      retainSeededStorage(seeded.scope.site, seeded.localItems, seeded.scope.origin);
      await seeder.goto(`${ctx.server.ipBase}/gate`, { waitUntil: 'domcontentloaded' });

      const sibling = await ctxt.newPage();
      if (siblingUrl) await sibling.goto(siblingUrl, { waitUntil: 'domcontentloaded' });
      await seeder.close();

      const { value: result, output } = await captureLogs(() =>
        removeStorage(seeder, seeded.localItems, seeded.scope, false));
      assertEqual(result.removed, wantRemoved, `keys removed with a ${label}`);
      if (wantRemoved === 0) {
        // The keys really are stranded here, so this must not be silent: the
        // refcount is already dropped, nothing will retry, and a later URL on
        // this host inherits them.
        assertIncludes(output, 'Could not clear 2 seeded localStorage key(s)', 'an unrecoverable leak is reported');
      } else {
        assertExcludes(output, 'Could not clear', 'a successful teardown reports no leak');
      }

      const verify = await ctxt.newPage();
      await verify.goto(`${ctx.server.ipBase}/gate`, { waitUntil: 'domcontentloaded' });
      const left = await storageKeys(verify);
      assertEqual(left, wantRemoved === 2 ? [] : ['k1', 'k2'], `keys left with a ${label}`);
      await ctxt.close();
    }
    return 'recovered via a same-origin sibling; blank sibling correctly cannot';
  } finally {
    await browser.close();
  }
});

check('browser', 'cookie teardown survives the page closing', async (ctx) => {
  const browser = await launchBrowser();
  try {
    // The browser context outlives the page, so cookies need no sibling route --
    // the asymmetry with storage is intrinsic, not an oversight.
    const ctxt = await browser.createBrowserContext();
    const page = await ctxt.newPage();
    const seeded = (await applySiteCookies(page, { cookies: { a: '1', b: '2' } }, `${ctx.server.ipBase}/`, false)).cookies;
    retainSeeded(seeded);
    await page.close();
    const result = await removeCookies(page, seeded, false);
    assertEqual(result.removed, 2, 'cookies removed after the page closed');
    assertEqual((await ctxt.cookies()).length, 0, 'jar is empty');
    await ctxt.close();
    return 'removed 2 on a closed page';
  } finally {
    await browser.close();
  }
});

check('browser', 'a cookie teardown failure is reported, not swallowed', async (ctx) => {
  const browser = await launchBrowser();
  try {
    const ctxt = await browser.createBrowserContext();
    const page = await ctxt.newPage();
    const seeded = (await applySiteCookies(page, { cookies: { a: '1', b: '2' } }, `${ctx.server.ipBase}/`, false)).cookies;
    retainSeeded(seeded);

    // Break only the READ, leaving the cookies in place: this used to return
    // {removed: 0} and print nothing at all on a normal run, so two cookies
    // silently outlived the entry and the next site on the host inherited them.
    const realContext = page.browserContext();
    page.browserContext = () => ({
      cookies: () => { throw new Error('simulated read failure'); },
      deleteCookie: realContext.deleteCookie.bind(realContext),
      setCookie: realContext.setCookie.bind(realContext)
    });

    const { value: result, output } = await captureLogs(() => removeCookies(page, seeded, false));
    assertEqual(result.removed, 0, 'nothing could be removed');
    assertIncludes(output, 'Could not remove 2 seeded cookie(s)', 'the failure is reported at warn level');
    assertIncludes(output, 'may inherit them', 'the consequence is spelled out');
    assertEqual((await realContext.cookies()).length, 2, 'the cookies are indeed still there');
    await ctxt.close();
    return 'warns and states the consequence';
  } finally {
    await browser.close();
  }
});

// ----- end-to-end nwss runs -----

check('e2e', 'a scan seeds 4 cookies + 4 local + 4 session on every load', async (ctx) => {
  const readback = path.join(ctx.tmpDir, 'readback-conc.log');
  const site = {
    url: [`${ctx.server.ipBase}/gate?a`, `${ctx.server.ipBase}/gate?b`],
    cookies: { k1: true, k2: 'granted', k3: 'b', k4: 3 },
    local_storage: { l1: true, l2: 'granted', l3: 7, l4: { cmp: { ok: true } } },
    session_storage: { s1: 1, s2: false, s3: 'x', s4: [1, 2] },
    reload: 2,
    clear_sitedata: true,
    filterRegex: ['/matches-nothing/']
  };
  const run = await runNwss(ctx, { max_concurrent_sites: 2, sites: [site] }, ['--debug'], { readbackLog: readback });
  assertEqual(run.readback.length, 4, 'page loads reported (2 URLs x initial + reload)');
  for (const entry of run.readback) {
    assertEqual(Object.keys(entry.page.local).length, 4, 'localStorage items on a load');
    assertEqual(Object.keys(entry.page.session).length, 4, 'sessionStorage items on a load');
    for (const name of ['k1', 'k2', 'k3', 'k4']) {
      assertIncludes(entry.cookieHeader || '', `${name}=`, `cookie ${name} on a load`);
    }
  }
  // clear_sitedata wipes cookies before each reload, so they are re-seeded;
  // storage rides the evaluateOnNewDocument hook and needs no re-seed.
  assertIncludes(run.stdout, 'Kept 4 seeded cookie(s)', 'refcount holds cookies for the concurrent URL');
  assertIncludes(run.stdout, 'Removed 4 seeded cookie(s)', 'last finisher removes the cookies');
  assertIncludes(run.stdout, 'Released 4 seeded localStorage key(s)', 'last finisher releases the storage keys');
  // Scoped to the two subsystems under test: asserting on ALL warnings would
  // make an unrelated nwss warning fail this check.
  assertExcludes(run.stdout, '[warn] [cookies]', 'a clean run emits no cookie warnings');
  assertExcludes(run.stdout, '[warn] [storage]', 'a clean run emits no storage warnings');
  return '4 loads x 12 items, teardown ordered, no warnings';
});

check('e2e', 'a later entry on the same host inherits nothing', async (ctx) => {
  const readback = path.join(ctx.tmpDir, 'readback-slate.log');
  const run = await runNwss(ctx, {
    max_concurrent_sites: 1,
    sites: [
      {
        url: `${ctx.server.ipBase}/gate?first`,
        cookies: { c: '1' },
        local_storage: { l: '1' },
        session_storage: { s: '1' },
        filterRegex: ['/matches-nothing/']
      },
      { url: `${ctx.server.ipBase}/gate?second`, filterRegex: ['/matches-nothing/'] }
    ]
  }, [], { readbackLog: readback });

  assertEqual(run.readback.length, 2, 'both entries loaded');
  const [first, second] = run.readback;
  assertEqual(Object.keys(first.page.local), ['l'], 'first entry is seeded');
  assertEqual(second.cookieHeader, null, 'second entry receives no cookie header');
  assertEqual(Object.keys(second.page.local), [], 'second entry sees no localStorage');
  assertEqual(Object.keys(second.page.session), [], 'second entry sees no sessionStorage');
  return 'clean slate for the second entry';
});

check('e2e', 'a URL that never loads does not claim a storage leak', async (ctx) => {
  // Nothing is written when no document on the origin exists, so warning about
  // inherited keys would be noise on every dead URL in a scan.
  const site = {
    url: 'http://127.0.0.1:1/never-listens',
    cookies: { c: '1' },
    local_storage: { l1: 'v', l2: 'v' },
    filterRegex: ['/matches-nothing/']
  };
  const quiet = await runNwss(ctx, { sites: [site] });
  assertExcludes(quiet.stdout, '[warn]', 'normal run stays quiet');
  const debug = await runNwss(ctx, { sites: [site] }, ['--debug']);
  assertIncludes(debug.stdout, 'Nothing to clear', '--debug explains why there was nothing to clear');
  return 'silent normally, explained under --debug';
});

check('e2e', '$popup signal reports and can promote a capture', async (ctx) => {
  await requireSecondLoopback(ctx.server.port);
  const listPath = path.join(ctx.tmpDir, 'popup-list.txt');
  fs.writeFileSync(listPath, TEST_LIST);
  // Loopback IPs rather than the resolver-mapped hostnames the browser harnesses
  // use: nwss has no flag for passing Chrome arguments, and 127.0.0.1 vs
  // 127.0.0.2 are already distinct root domains, so the popup is third-party.
  const base = {
    url: ctx.server.openerFor(`${ctx.server.popupBase}/pop-target.html?campaign=1`),
    capture_popups: true,
    capture_popups_window_ms: 3000,
    filterRegex: ['/matches-nothing/']
  };
  const listArgs = ['--block-ads=' + listPath, '--adblock-rules', '--debug'];

  // Promotion ON: the site's own filterRegex matches nothing, so a captured rule
  // can only have come from the signal.
  const on = await runNwss(ctx, { sites: [{ ...base, capture_popups_signal: true }] }, listArgs);
  assertIncludes(on.stdout, 'matches known popunder pattern', 'the signal fires for the popup URL');
  assertIncludes(on.stdout, 'known popunder pattern(s) reached', 'end-of-scan tally is printed');
  assertIncludes(on.stdout, '||127.0.0.2^', 'the promoted hit is captured');

  // Promotion OFF: same scan, reported but never captured.
  const off = await runNwss(ctx, { sites: [{ ...base, capture_popups_signal: false }] }, listArgs);
  assertIncludes(off.stdout, 'known popunder pattern(s) reached', 'signal is still tallied with promotion off');
  assertExcludes(off.stdout, '||127.0.0.2^', 'nothing is captured with promotion off');
  return 'reported either way, captured only when promoted';
});

check('e2e', 'a failing signal matcher cannot discard a capture', async (ctx) => {
  // The popup evaluation ends in a catch-all, so a throw from the signal used to
  // take the surrounding capture with it -- silently.
  await requireSecondLoopback(ctx.server.port);
  const listPath = path.join(ctx.tmpDir, 'popup-list-throw.txt');
  fs.writeFileSync(listPath, TEST_LIST);
  const patchPath = path.join(ctx.tmpDir, 'throwing-matcher.js');
  fs.writeFileSync(patchPath, `const adblock = require(${JSON.stringify(path.join(REPO_ROOT, 'lib', 'adblock.js'))});
const orig = adblock.createPopupSignalMatcher;
adblock.createPopupSignalMatcher = (...a) => Object.assign({}, orig(...a), {
  match() { throw new TypeError('injected matcher failure'); }
});
`);
  const cfgPath = path.join(ctx.tmpDir, `cfg-throw-${ctx.nextId()}.json`);
  fs.writeFileSync(cfgPath, JSON.stringify({
    sites: [{
      url: ctx.server.openerFor(`${ctx.server.popupBase}/pop-target.html`),
      capture_popups: true,
      capture_popups_signal: true,
      capture_popups_window_ms: 3000,
      // This DOES match the popup URL, so the capture must happen even though
      // the signal throws.
      filterRegex: ['pop-target\\.html']
    }]
  }, null, 2));

  const result = await runProcess('node', [
    '--require', patchPath, NWSS, '--custom-json', cfgPath,
    '--block-ads=' + listPath, '--adblock-rules', '--debug'
  ], { timeout: NWSS_TIMEOUT_MS });
  const out = `${(result.stdout || '').toString()}${(result.stderr || '').toString()}`;
  try {
    assertIncludes(out, 'signal evaluation failed', 'the matcher failure is reported once');
    assertIncludes(out, '||127.0.0.2^', 'the filterRegex capture survives the signal failure');
  } catch (err) {
    // A bare "output does not contain X" is useless for a whole scan's log, so
    // attach the lines that decide this check.
    const relevant = out.split('\n')
      .filter(l => /^\|\||popup|Matched|Generated|signal|error|Failed/i.test(l))
      .slice(-12).join('\n          ');
    throw new Error(`${err.message}\n          relevant output:\n          ${relevant}`);
  }
  return 'capture preserved, failure reported';
});

check('e2e', '--validate-config accepts a cookie + storage config', async (ctx) => {
  const run = await runNwss(ctx, {
    sites: [{
      url: `${ctx.server.ipBase}/gate`,
      cookies: { c: '1' },
      local_storage: { l: true },
      session_storage: { s: 1 },
      capture_popups: true,
      capture_popups_signal: true,
      filterRegex: ['/matches-nothing/']
    }]
  }, ['--validate-config']);
  assertIncludes(run.stdout, 'Configuration is valid', 'config validates');
  return 'valid';
});

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

async function main() {
  if (HELP) { printHelp(); process.exit(0); }

  const badFlags = args.filter(a => a.startsWith('-') && !KNOWN_FLAGS.has(a) && !a.startsWith('--group='));
  if (badFlags.length) {
    console.error(`Unrecognised flag(s): ${badFlags.join(', ')}. See --help.`);
    process.exit(2);
  }
  if (GROUP && !GROUPS.includes(GROUP)) {
    console.error(`--group must be one of ${GROUPS.join(', ')} (got: ${GROUP}).`);
    process.exit(2);
  }

  let selected = CHECKS;
  if (GROUP) selected = selected.filter(c => c.group === GROUP);
  if (NAME_FILTERS.length) {
    selected = selected.filter(c => NAME_FILTERS.some(f => c.name.toLowerCase().includes(f.toLowerCase())));
  }

  if (LIST) {
    for (const c of CHECKS) console.log(`  [${c.group}] ${c.name}`);
    process.exit(0);
  }
  if (!selected.length) {
    console.error('No checks matched the given filter. Try --list.');
    process.exit(2);
  }

  // nwss resolves its logs/ directory against the cwd, so run it from the repo
  // root however this script was invoked.
  process.chdir(REPO_ROOT);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-seed-test-'));
  let idCounter = 0;
  const server = await startFixtureServer();
  const ctx = {
    tmpDir,
    server,
    nextId: () => ++idCounter,
    setReadbackLog: (p) => server.setLog(p)
  };

  let failures = 0;
  let skipped = 0;
  let lastGroup = null;
  const started = Date.now();

  for (const c of selected) {
    if (c.group !== lastGroup) {
      console.log(`\n${messageColors.highlight(`== ${c.group} ==`)}`);
      lastGroup = c.group;
    }
    const t0 = Date.now();
    try {
      const detail = await c.run(ctx);
      const ms = Date.now() - t0;
      console.log(`  ${messageColors.success('PASS')}  ${c.name}${VERBOSE && detail ? `\n          ${detail} (${ms}ms)` : ''}`);
    } catch (err) {
      if (err instanceof SkipCheck) {
        skipped++;
        console.log(`  ${messageColors.warn('SKIP')}  ${c.name}`);
        console.log(`          ${err.message}`);
        continue;
      }
      failures++;
      console.log(`  ${messageColors.error('FAIL')}  ${c.name}`);
      console.log(`          ${err.message}`);
      if (VERBOSE && err.stack) console.log(err.stack.split('\n').slice(1, 4).join('\n'));
    }
  }

  await server.close();
  if (KEEP) {
    console.log(`\nFixtures kept in ${tmpDir}`);
  } else {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) { /* best effort */ }
  }

  const secs = ((Date.now() - started) / 1000).toFixed(1);
  console.log('');
  if (failures === 0) {
    const skipNote = skipped ? `, ${skipped} skipped` : '';
    console.log(messageColors.success(`All ${selected.length - skipped} check(s) passed in ${secs}s${skipNote}`));
    process.exit(0);
  }
  console.log(messageColors.error(`${failures} of ${selected.length} check(s) FAILED in ${secs}s`));
  process.exit(1);
}

main().catch((err) => {
  console.error(`test-seeding: unexpected failure: ${err && err.stack ? err.stack : err}`);
  process.exit(1);
});
