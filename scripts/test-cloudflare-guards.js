#!/usr/bin/env node
/**
 * test-cloudflare-guards.js
 *
 * Pins the correctness guards in lib/cloudflare.js, all of which shared one
 * failure mode: reporting success (or "clean") on evidence that could not
 * support it.
 *
 *   1. A failed quick detection is not cached, is not reported as
 *      "no indicators", and does not suppress handling on the whole domain
 *   2. checkChallengeCompletion never passes safePageEvaluate's truthy
 *      defaults object back as `isCompleted`
 *   3. cf_clearance is read over CDP (it is HttpOnly, so document.cookie
 *      cannot see it)
 *   4. The retry ladder stops when the caller's adaptive timeout gives up,
 *      before the page.reload() in betweenAttempts
 *   5. The JS-challenge wait requires positive evidence, and does not
 *      pre-empt the Turnstile solver on a page carrying both
 *
 * Run: node scripts/test-cloudflare-guards.js          (browser part needs puppeteer)
 */

const fs = require('fs');
const path = require('path');
const Module = require('module');
const http = require('http');

let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`); failed++; }
}
function eq(name, actual, expected) {
  check(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

const CF_PATH = path.join(__dirname, '..', 'lib', 'cloudflare.js');

// The module keeps its public surface deliberately narrow, so the internals
// these guards live in aren't exported. Compile the real file with one extra
// line appended to expose them, rather than widening module.exports for tests.
function loadInternals() {
  const code = fs.readFileSync(CF_PATH, 'utf8') +
    '\nmodule.exports._internals = { safePageEvaluate, checkChallengeCompletion, ' +
    'waitForJSChallengeCompletion, analyzeCloudflareChallenge, attemptChallengeSolve, ' +
    'runWithRetries, getRetryConfig, performCloudflareHandling, handlePhishingWarning, ' +
    'clickInShadowDOM, attemptChallengeSolveWithTimeout, FAST_TIMEOUTS, TIMEOUTS, ' +
    'buildOutcomeString, CHALLENGE_HTTP_STATUSES };\n';
  const m = new Module(CF_PATH, null);
  m.filename = CF_PATH;
  m.paths = Module._nodeModulePaths(path.dirname(CF_PATH));
  m._compile(code, CF_PATH);
  return m.exports;
}

const DETACHED = 'Attempted to use detached Frame';

(async () => {
  // =====================================================================
  console.log('\n=== quick detection: a failure is not an answer ===');
  {
    // Fresh module instance per case so the detection cache starts empty.
    const cf = loadInternals();
    let evaluateCalls = 0;
    const page = {
      isClosed: () => false,
      url: async () => 'https://flaky.test/page1',
      frames: () => [], cookies: async () => [],
      evaluate: async () => {
        evaluateCalls++;
        if (evaluateCalls === 1) throw new Error(DETACHED);
        return { hasIndicators: true, title: 'Just a moment', url: 'https://flaky.test/', bodySnippet: '' };
      }
    };
    // No explicit config: the early return stands, but must say WHY honestly.
    const r1 = await cf.handleCloudflareProtection(page, 'https://flaky.test/page1', {}, false);
    eq('no config: reported as detection_failed, not no_indicators', !!r1.quickDetectionFailed, true);
    eq('no config: skippedNoIndicators is not claimed', !!r1.skippedNoIndicators, false);
    eq('nothing was cached', cf.getCacheStats().size, 0);

    // Second URL on the same host must re-detect rather than read a cached
    // "clean" verdict. Before the fix this was 1 evaluate total, forever.
    const before = evaluateCalls;
    page.url = async () => 'https://flaky.test/page2';
    const r2 = await cf.handleCloudflareProtection(page, 'https://flaky.test/page2', {}, false);
    check('next URL on the domain re-detects', evaluateCalls > before,
      `evaluate calls stayed at ${evaluateCalls}`);
    eq('and now finds the indicators it missed', !!r2.skippedNoIndicators, false);
  }
  {
    const cf = loadInternals();
    const page = {
      isClosed: () => false, url: async () => 'https://flaky2.test/a',
      frames: () => [], cookies: async () => [],
      evaluate: async () => { throw new Error(DETACHED); }
    };
    // With explicit config the handler must attempt handling anyway: skipping
    // on a transient failure is how a challenge page gets scanned as the site.
    const r = await cf.handleCloudflareProtection(page, 'https://flaky2.test/a', { cloudflare_bypass: true }, false);
    eq('cloudflare_bypass set: handling is attempted despite the failure', !!r.skippedNoIndicators, false);
  }
  {
    // No regression: a SUCCESSFUL detection is still cached per hostname.
    const cf = loadInternals();
    let calls = 0;
    const page = {
      isClosed: () => false, url: async () => 'https://ok.test/a',
      frames: () => [], cookies: async () => [],
      evaluate: async () => { calls++; return { hasIndicators: false, title: 'Shop', url: 'https://ok.test/a', bodySnippet: '' }; }
    };
    await cf.handleCloudflareProtection(page, 'https://ok.test/a', {}, false);
    page.url = async () => 'https://ok.test/b';
    await cf.handleCloudflareProtection(page, 'https://ok.test/b', {}, false);
    eq('a clean result is still cached domain-wide (1 evaluate for 2 URLs)', calls, 1);
    eq('cache holds the one hostname', cf.getCacheStats().size, 1);
  }

  // =====================================================================
  console.log('\n=== checkChallengeCompletion: a failed evaluation is not a solve ===');
  {
    const { _internals: I } = loadInternals();
    const failing = {
      isClosed: () => false, url: async () => 'https://x.test/',
      cookies: async () => [],
      evaluate: async () => { throw new Error(DETACHED); }
    };
    const fallback = await I.safePageEvaluate(failing, () => true, 100, { maxRetries: 1 });
    check('safePageEvaluate still returns its truthy defaults object', !!fallback && typeof fallback === 'object');

    const r = await I.checkChallengeCompletion(failing);
    eq('isCompleted is strictly false, not a truthy object', r.isCompleted, false);
    check('and carries the reason', typeof r.error === 'string' && r.error.length > 0);
  }
  {
    const { _internals: I } = loadInternals();
    const mk = (payload, cookies = []) => ({
      isClosed: () => false, url: async () => 'https://x.test/',
      cookies: async () => cookies,
      evaluate: async () => payload
    });
    eq('DOM clear of challenge markers -> completed',
      (await I.checkChallengeCompletion(mk({ __cfCheck: true, domClear: true, hasToken: false }))).isCompleted, true);
    eq('Turnstile token present -> completed',
      (await I.checkChallengeCompletion(mk({ __cfCheck: true, domClear: false, hasToken: true }))).isCompleted, true);
    eq('neither, and no cookie -> not completed',
      (await I.checkChallengeCompletion(mk({ __cfCheck: true, domClear: false, hasToken: false }))).isCompleted, false);
    // document.cookie cannot see an HttpOnly cf_clearance; page.cookies() can.
    // This used to assert that the cookie ALONE completes the challenge. It
    // does not any more, and the reason is a measured race: cf_clearance is set
    // for the HOST and cookies are shared by every page in the browser context,
    // while a challenge is per document -- and nwss runs a site's URLs
    // concurrently in ONE browser. A page whose DOM was still "Just a moment"
    // with the container present and no token flipped to completed the moment a
    // SIBLING page acquired clearance. The cookie now buys a re-check, and this
    // page's own DOM decides.
    //
    // The wait between the two reads is shortened here: the control flow under
    // test is unaffected by its length, and the real 2s would be paid twice per
    // run of this suite.
    I.TIMEOUTS.POST_SOLVE_REDIRECT_MS = 10;
    // A stub whose DOM answers differently on the second read, so the re-check
    // is distinguishable from the first look.
    const mkSeq = (payloads, cookies = []) => {
      let i = 0;
      return {
        isClosed: () => false, url: async () => 'https://x.test/',
        cookies: async () => cookies,
        evaluate: async () => payloads[Math.min(i++, payloads.length - 1)]
      };
    };
    const CLEARANCE = [{ name: 'cf_clearance', value: 'abc' }];
    const STILL_CHALLENGED = { __cfCheck: true, domClear: false, hasToken: false };
    const CLEARED = { __cfCheck: true, domClear: true, hasToken: false };

    eq('cf_clearance alone does NOT complete while this page is still challenged',
      (await I.checkChallengeCompletion(
        mkSeq([STILL_CHALLENGED, STILL_CHALLENGED], CLEARANCE))).isCompleted, false);
    eq('cf_clearance + this page clearing on the re-check -> completed',
      (await I.checkChallengeCompletion(
        mkSeq([STILL_CHALLENGED, CLEARED], CLEARANCE))).isCompleted, true);
    // The re-check is subject to the same trap as the first read: a failed
    // evaluation is a truthy object, and must not read as a solve.
    eq('a re-check that could not run is not a solve',
      (await I.checkChallengeCompletion(
        mkSeq([STILL_CHALLENGED, { error: 'Attempted to use detached Frame' }], CLEARANCE))).isCompleted, false);
    // ...and the cookie is still read over CDP rather than from the document.
    {
      let cookieReads = 0;
      const counting = {
        isClosed: () => false, url: async () => 'https://x.test/',
        cookies: async () => { cookieReads++; return CLEARANCE; },
        evaluate: async () => STILL_CHALLENGED
      };
      await I.checkChallengeCompletion(counting);
      check('cf_clearance is still read over CDP (page.cookies called)', cookieReads === 1,
        `page.cookies() called ${cookieReads} time(s)`);
    }
    // A predicate carrying no docId at all -- a stub here, or a later refactor
    // -- must degrade to ONE wait per page, not one per call. Read straight off
    // the WeakMap, undefined means both "nothing spent yet" and "spent for an
    // undefined docId", and every call would wait again: the per-selector cost
    // the gate exists to stop.
    {
      I.TIMEOUTS.POST_SOLVE_REDIRECT_MS = 120;
      const noDocId = {
        isClosed: () => false, url: async () => 'https://x.test/',
        cookies: async () => CLEARANCE,
        evaluate: async () => STILL_CHALLENGED        // no docId field
      };
      const t = Date.now();
      for (let i = 0; i < 3; i++) await I.checkChallengeCompletion(noDocId);
      const spent = Date.now() - t;
      check('a predicate without a docId still waits once, not per call',
        spent < 300, `3 calls took ${spent}ms with a 120ms window`);
      I.TIMEOUTS.POST_SOLVE_REDIRECT_MS = 10;
    }

    // No cookie at all must stay on the fast path -- no re-check, no wait.
    {
      let evals = 0;
      const noCookie = {
        isClosed: () => false, url: async () => 'https://x.test/',
        cookies: async () => [],
        evaluate: async () => { evals++; return STILL_CHALLENGED; }
      };
      const r = await I.checkChallengeCompletion(noCookie);
      check('no clearance -> one DOM read, no re-check', r.isCompleted === false && evals === 1,
        `isCompleted=${r.isCompleted}, evaluate called ${evals} time(s)`);
    }
    // Comment lines stripped: the fix's own explanation names the dead call.
    const cfCode = fs.readFileSync(CF_PATH, 'utf8').split('\n')
      .filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
    check('no executable line tests document.cookie for cf_clearance',
      !/document\.cookie\.includes\('cf_clearance'\)/.test(cfCode),
      'an HttpOnly cookie is invisible to document.cookie, so that term was dead');
    // The completion check reads the page twice (arrival, then after clearance
    // shows up). Both reads must run the SAME predicate: two copies of the
    // selector list is how the pair drifts, and the second copy had already
    // lost the comment explaining why body.textContent is read once.
    // Scoped to the function's OWN body: that selector appears in three other
    // functions for their own reasons, so a file-wide count cannot tell a
    // duplicate inside this path from legitimate use elsewhere. (It said 4 and
    // failed on correct code -- a badly specified check invents a defect the
    // same way a bad mutation invents a coverage gap.)
    const bodyStart = cfCode.indexOf('async function checkChallengeCompletion(page) {');
    const after = cfCode.slice(bodyStart + 1);
    const nextDecl = after.search(/\n(?:async )?function /);
    const fnBody = nextDecl === -1 ? after : after.slice(0, nextDecl);
    const hoistedUses = (fnBody.match(/safePageEvaluate\(page, readChallengeMarkers/g) || []).length;
    check('both completion reads share one hoisted predicate',
      bodyStart !== -1 && hoistedUses === 2 && !/querySelector/.test(fnBody),
      `readChallengeMarkers used ${hoistedUses}x in the function body; inline querySelector present: ${/querySelector/.test(fnBody)}`);
  }

  // =====================================================================
  console.log('\n=== retry ladder stops when the caller gives up ===');
  {
    const { _internals: I } = loadInternals();
    const retryConfig = I.getRetryConfig({ cloudflare_max_retries: 5 });

    let attempts = 0, reloads = 0;
    const signal = { cancelled: true };
    const res = await I.runWithRetries({
      label: 'Challenge', retryConfig, forceDebug: false, signal,
      attemptFn: async () => { attempts++; return { success: false, error: 'nope' }; },
      betweenAttempts: async () => { reloads++; }
    });
    eq('pre-cancelled: no attempt is made', attempts, 0);
    eq('pre-cancelled: no reload is made', reloads, 0);
    eq('pre-cancelled: reports cancelled', !!res.cancelled, true);
    eq('pre-cancelled: does not claim success', res.success, false);
  }
  {
    const { _internals: I } = loadInternals();
    const retryConfig = I.getRetryConfig({ cloudflare_max_retries: 5 });
    let attempts = 0, reloads = 0;
    const signal = { cancelled: false };
    const res = await I.runWithRetries({
      label: 'Challenge', retryConfig, forceDebug: false, signal,
      // Cancel during the first attempt, the way the adaptive timeout does.
      attemptFn: async () => { attempts++; signal.cancelled = true; return { success: false, error: 'nope' }; },
      betweenAttempts: async () => { reloads++; }
    });
    eq('cancelled mid-flight: the first attempt still ran', attempts, 1);
    eq('cancelled mid-flight: page.reload() is skipped', reloads, 0);
    eq('cancelled mid-flight: no further attempts', attempts, 1);
    eq('cancelled mid-flight: reports cancelled', !!res.cancelled, true);
  }
  {
    // Not cancelled: the ladder must still retry and still reload.
    const { _internals: I } = loadInternals();
    const retryConfig = I.getRetryConfig({ cloudflare_max_retries: 3 });
    let attempts = 0, reloads = 0;
    await I.runWithRetries({
      label: 'Challenge', retryConfig, forceDebug: false, signal: null,
      attemptFn: async () => { attempts++; return { success: false, error: 'nope' }; },
      betweenAttempts: async () => { reloads++; }
    });
    eq('no signal: all attempts run', attempts, 3);
    eq('no signal: reload still happens between them', reloads, 2);
  }
  {
    // The wiring: the adaptive timeout must trip the signal it passes down.
    const src = fs.readFileSync(CF_PATH, 'utf8');
    const block = src.slice(src.indexOf('const cfSignal = { cancelled: false };'),
                            src.indexOf('// Cache timeout results at domain level'));
    check('the adaptive timeout sets cfSignal.cancelled', /cfSignal\.cancelled = true;/.test(block));
    check('and cfSignal reaches performCloudflareHandling',
      /performCloudflareHandling\([^)]*cfSignal\)/.test(block.replace(/\n/g, ' ')));
  }

  {
    // A cancelled stage must not be reported as one the user disabled: the
    // signal check shares its else-branch with the "disabled" log.
    const { _internals: I } = loadInternals();
    const page = { isClosed: () => false, url: async () => 'https://c.test/', frames: () => [], cookies: async () => [] };
    const lines = [];
    const realLog = console.log;
    console.log = (...a) => { lines.push(a.join(' ')); };
    let res;
    try {
      res = await I.performCloudflareHandling(page, 'https://c.test/', {}, true,
        { cfBypassEnabled: true, cfPhishEnabled: false }, {}, { cancelled: true });
    } finally { console.log = realLog; }
    check('a cancelled challenge stage is not reported as "disabled"',
      !lines.some(l => l.includes('Challenge bypass disabled')),
      lines.filter(l => l.includes('Challenge bypass')).join(' | '));
    check('it says the caller stopped waiting',
      lines.some(l => l.includes('caller stopped waiting')));
    eq('and the stage really was skipped', res.verificationChallenge.attempted, false);
  }

  {
    // byOutcome already names the solve method, so a parallel bySolveMethod
    // tally was a duplicate kept per URL that no caller read.
    const cf = loadInternals();
    const snap = cf.getAggregateStats();
    check('getAggregateStats no longer carries a bySolveMethod duplicate',
      !('bySolveMethod' in snap), Object.keys(snap).join(','));
    check('byOutcome is still there to carry the breakdown', 'byOutcome' in snap);
    const nwssSrc0 = fs.readFileSync(path.join(__dirname, '..', 'nwss.js'), 'utf8');
    check('and nwss does not reference the dropped field', !/bySolveMethod/.test(nwssSrc0));
  }

  // =====================================================================
  console.log('\n=== end-of-scan summary counts detection_failed honestly ===');
  {
    // Extract nwss.js's own arithmetic rather than re-typing it. A
    // detection that never completed is not evidence the URL met
    // Cloudflare: before lib/cloudflare.js started labelling it, that URL
    // counted as no_indicators and so was suppressed, and counting it as
    // notable would make a scan of Cloudflare-free pages announce
    // "1 of 1 URL(s) met Cloudflare" off one flaky evaluation.
    const nwssSrc = fs.readFileSync(path.join(__dirname, '..', 'nwss.js'), 'utf8');
    const m = nwssSrc.match(/const quiet = ([\s\S]*?)\n\s*const notable = ([^;]*);/);
    if (!m) { console.error('FATAL: could not locate the Cloudflare summary arithmetic in nwss.js'); process.exit(1); }
    const quietExpr = m[1].split('\n').filter(l => !/^\s*\/\//.test(l)).join('\n').trim().replace(/;$/, '');
    const detectionFailedExpr = (m[1].match(/const detectionFailed = ([^;]*);/) || [])[1];
    check('nwss computes a detectionFailed term', !!detectionFailedExpr);
    const notableFn = new Function('outcomes', 'cf',
      `const quiet = ${quietExpr.replace(/const detectionFailed[\s\S]*$/, '').trim().replace(/;$/, '')};
       const detectionFailed = ${detectionFailedExpr || '0'};
       const notable = ${m[2]};
       return { notable, detectionFailed };`);

    const flaky = notableFn({ no_indicators: 4, detection_failed: 1 }, { total: 5 });
    eq('a flaky Cloudflare-free scan reports 0 as having met Cloudflare', flaky.notable, 0);
    eq('and surfaces the failure count separately', flaky.detectionFailed, 1);

    const real = notableFn({ no_indicators: 8, 'solved(turnstile)': 2, detection_failed: 1 }, { total: 11 });
    eq('genuine Cloudflare URLs are still counted', real.notable, 2);

    const clean = notableFn({ no_indicators: 10 }, { total: 10 });
    eq('a clean scan stays quiet', clean.notable, 0);
  }

  // =====================================================================
  console.log('\n=== JS-challenge wait: positive evidence only (browser) ===');
  let puppeteer = null;
  try { puppeteer = require('puppeteer'); } catch { /* optional */ }
  if (!puppeteer) {
    console.log('  … skipped (puppeteer not resolvable)');
  } else {
    const PORT = 8299;
    const srv = http.createServer((req, res) => {
      if (req.url.startsWith('/cdn-cgi/challenge-platform/')) {
        res.writeHead(200, { 'Content-Type': 'application/javascript' }); return res.end('// cf');
      }
      if (req.url.startsWith('/js-clears')) {
        // A classic JS challenge that clears itself in place after N ms, which
        // is what a real one does before redirecting.
        const clearAt = parseInt((req.url.match(/(\d+)/) || [])[1] || '4000', 10);
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><head><title>Just a moment...</title></head><body>' +
          '<div class="cf-challenge-running">Checking your browser before accessing</div>' +
          '<script src="/cdn-cgi/challenge-platform/x"></script><script>setTimeout(() => {' +
          'document.title = "Real Site";' +
          'document.querySelector(".cf-challenge-running").remove();' +
          'document.querySelectorAll(\'script[src*="challenge-platform"]\').forEach(s => s.remove());' +
          `}, ${clearAt});</script></body></html>`);
      }
      if (req.url.startsWith('/clear-stuck')) {
        // Clearance is set for the host, but THIS page stays on the
        // interstitial -- the sibling race, in one page.
        res.writeHead(200, { 'Content-Type': 'text/html',
          'Set-Cookie': 'cf_clearance=tok; Path=/; HttpOnly' });
        return res.end('<html><head><title>Just a moment...</title></head><body>' +
          '<div class="cf-challenge-container"><p>Verify you are human</p></div></body></html>');
      }
      if (req.url.startsWith('/clear-nav')) {
        // Clearance set AND this page's own redirect lands shortly after: the
        // legitimate case the cookie fallback existed for. A real NAVIGATION,
        // not an in-place DOM edit, because that detaches the frame mid-check
        // and is what a post-solve redirect actually does.
        res.writeHead(200, { 'Content-Type': 'text/html',
          'Set-Cookie': 'cf_clearance=tok; Path=/; HttpOnly' });
        return res.end('<html><head><title>Just a moment...</title></head><body>' +
          '<div class="cf-challenge-container"><p>Verify you are human</p></div>' +
          '<script>setTimeout(() => { location.href = "/landed"; }, 200);</script>' +
          '</body></html>');
      }
      if (req.url.startsWith('/landed')) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><head><title>Real Site</title></head><body><p>content</p></body></html>');
      }
      if (req.url === '/phish-stuck') {
        // A phishing interstitial whose continue link is an in-page anchor: the
        // click lands, nothing navigates, the warning stays.
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><head><title>Attention Required!</title></head><body>' +
          '<p>This website has been reported for potential phishing.</p>' +
          '<a href="#continue-anyway">Continue to site</a></body></html>');
      }
      if (req.url === '/phish-ok') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><head><title>Attention Required!</title></head><body>' +
          '<p>This website has been reported for potential phishing.</p>' +
          '<a href="/clean?continue=1">Continue to site</a></body></html>');
      }
      if (req.url === '/shadow-late') {
        // Only a LATER candidate matches, and it renders after 800ms -- the
        // shape the shortened per-selector probe must still catch.
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><body><div id="host"></div><script>' +
          'setTimeout(() => { document.getElementById("host").innerHTML = ' +
          '\'<span class="ctp-checkbox" style="display:block;width:20px;height:20px"></span>\'; }, 800);' +
          '</script></body></html>');
      }
      if (req.url === '/shadow-now') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><body><span class="ctp-checkbox" ' +
          'style="display:block;width:20px;height:20px"></span></body></html>');
      }
      if (req.url === '/shadow-none') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><body><div class="cf-turnstile"><span>widget</span></div></body></html>');
      }
      if (req.url === '/title-only') {
        // The title is the only interstitial signal: no challenge-platform
        // script, no widget, no telltale body text. Cloudflare serves this
        // shape when the markers sit in a closed shadow root, and
        // analyzeCloudflareChallenge treats the title alone as a challenge.
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><head><title>Just a moment...</title></head><body><div>loading</div></body></html>');
      }
      if (req.url === '/widget-only') {
        // A Turnstile widget whose page gives away nothing else: neutral
        // title, no challenge-platform script, none of the telltale phrases.
        // The widget term in the predicate is the only thing that catches it.
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><head><title>Attention Required!</title></head><body>' +
          '<p>Please complete the security check to continue.</p><div class="cf-turnstile"></div></body></html>');
      }
      if (req.url === '/clean') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end('<html><head><title>Real Site</title></head><body><h1>content</h1></body></html>');
      }
      // A Turnstile interstitial: carries the challenge-platform script (so
      // the detector sets isJSChallenge) but none of the phrases the old
      // predicate tested for.
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><head><title>Just a moment...</title></head><body>
        <div class="cf-turnstile"></div>
        <p>Verify you are human by completing the action below.</p>
        <script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>
      </body></html>`);
    });
    await new Promise(r => srv.listen(PORT, '127.0.0.1', r));
    const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
    try {
      const { _internals: I } = loadInternals();
      const page = await browser.newPage();

      await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'domcontentloaded' });
      const info = await I.analyzeCloudflareChallenge(page);
      check('fixture is seen as both a JS and a Turnstile challenge',
        info.isJSChallenge === true && info.isTurnstile === true,
        `js=${info.isJSChallenge} turnstile=${info.isTurnstile}`);

      // --- the clearance re-check, in a real browser -------------------
      {
        // A real redirect must still read as completed. Window generous
        // relative to the page's 200ms navigation.
        I.TIMEOUTS.POST_SOLVE_REDIRECT_MS = 1000;
        const navPage = await browser.newPage();
        await navPage.goto(`http://127.0.0.1:${PORT}/clear-nav`, { waitUntil: 'domcontentloaded' });
        const navRes = await I.checkChallengeCompletion(navPage);
        const landedTitle = await navPage.evaluate(() => document.title);
        check('clearance + this page\'s own redirect landing -> completed',
          navRes.isCompleted === true && landedTitle === 'Real Site',
          `isCompleted=${navRes.isCompleted}, title=${JSON.stringify(landedTitle)}`);
        await navPage.close();

        // The same cookie must NOT complete a page that stays on the
        // interstitial, and the wait must be paid ONCE however many times the
        // selector loops ask. Three calls, one window.
        I.TIMEOUTS.POST_SOLVE_REDIRECT_MS = 200;
        const stuckPage = await browser.newPage();
        await stuckPage.goto(`http://127.0.0.1:${PORT}/clear-stuck`, { waitUntil: 'domcontentloaded' });
        const tStuck = Date.now();
        const verdicts = [];
        for (let i = 0; i < 3; i++) verdicts.push((await I.checkChallengeCompletion(stuckPage)).isCompleted);
        const elapsed = Date.now() - tStuck;
        check('a sibling\'s clearance does not complete a page still challenged',
          verdicts.every(v => v === false), `verdicts=${JSON.stringify(verdicts)}`);
        // One 200ms wait plus three DOM reads; three waits would be 600ms+.
        check('the clearance wait is paid once, not once per selector',
          elapsed < 500, `3 calls took ${elapsed}ms with a 200ms window`);

        // ...but a RELOAD is a new document and must earn a fresh wait. A
        // wall-clock window could not tell the two apart: RETRY_CONFIG.baseDelay
        // is 800ms and the ladder reloads between attempts, so attempt 2's first
        // check lands inside a 2s window and would skip its wait -- losing a
        // redirect that was about to land, on the last attempt maxAttempts
        // allows.
        await stuckPage.reload({ waitUntil: 'domcontentloaded' });
        const tReload = Date.now();
        await I.checkChallengeCompletion(stuckPage);
        const reloadElapsed = Date.now() - tReload;
        check('a reloaded page earns a fresh clearance wait',
          reloadElapsed >= 180, `the call after a reload took ${reloadElapsed}ms with a 200ms window`);
        await stuckPage.close();
      }

      const t0 = Date.now();
      const js = await I.waitForJSChallengeCompletion(page, false);
      const ms = Date.now() - t0;
      eq('interstitial is NOT reported as a completed JS challenge', js.success, false);
      check('it waited for its timeout instead of resolving instantly', ms > 1000, `returned in ${ms}ms`);

      const solve = await I.attemptChallengeSolve(page, `http://127.0.0.1:${PORT}/`, info, false);
      check('the JS wait no longer claims the solve on a Turnstile page',
        solve.method !== 'js_challenge_wait', `method=${solve.method}`);
      eq('an unsolved Turnstile page is reported unsolved', solve.success, false);

      // Ordering: on a page carrying a Turnstile widget the interactive
      // method must be tried BEFORE the passive wait. The predicate fix alone
      // stops the false claim, so only the order proves the deferral works --
      // capture the module's own debug lines and compare their positions.
      await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'domcontentloaded' });
      const lines = [];
      const realLog = console.log;
      console.log = (...a) => { lines.push(a.join(' ')); };
      try {
        await I.attemptChallengeSolve(page, `http://127.0.0.1:${PORT}/`, info, true);
      } finally {
        console.log = realLog;
      }
      const iTurnstile = lines.findIndex(l => l.includes('Attempting Turnstile method'));
      const iJsWait = lines.findIndex(l => l.includes('Attempting JS challenge wait'));
      check('Turnstile is attempted on a Turnstile page', iTurnstile !== -1);
      check('the passive JS wait runs AFTER it, not before',
        iTurnstile !== -1 && iJsWait !== -1 && iTurnstile < iJsWait,
        `turnstile@${iTurnstile} jsWait@${iJsWait}`);
      check('and the deferral is announced',
        lines.some(l => l.includes('Deferring JS challenge wait')));

      // A title-only interstitial must not read as a completed JS challenge:
      // the title test is the only guard that catches this shape.
      await page.goto(`http://127.0.0.1:${PORT}/title-only`, { waitUntil: 'domcontentloaded' });
      const jsTitleOnly = await I.waitForJSChallengeCompletion(page, false);
      eq('a page whose only signal is the "Just a moment" title is not completed',
        jsTitleOnly.success, false);

      // A live Turnstile widget means unsolved, whatever the title and body say.
      await page.goto(`http://127.0.0.1:${PORT}/widget-only`, { waitUntil: 'domcontentloaded' });
      const jsWidgetOnly = await I.waitForJSChallengeCompletion(page, false);
      eq('a page still showing a Turnstile widget is not completed', jsWidgetOnly.success, false);

      // --- a solved challenge must survive the solve cap -----------------
      // The post-solve redirect wait used to be 10000ms and timed out in full
      // on every solve (the completion predicate already proves the
      // interstitial is gone), pushing the total past CHALLENGE_SOLVING: a
      // challenge clearing in 4s came back success=false method=null.
      check(`the post-solve redirect wait is small (${I.TIMEOUTS.POST_SOLVE_REDIRECT_MS}ms)`,
        I.TIMEOUTS.POST_SOLVE_REDIRECT_MS <= 3000, `${I.TIMEOUTS.POST_SOLVE_REDIRECT_MS}ms`);
      for (const clearAt of [1000, 4000]) {
        await page.goto(`http://127.0.0.1:${PORT}/js-clears${clearAt}`, { waitUntil: 'domcontentloaded' });
        const ci = await I.analyzeCloudflareChallenge(page);
        const t = Date.now();
        const capped = await I.attemptChallengeSolveWithTimeout(page, 'x', ci, false);
        const ms = Date.now() - t;
        eq(`a challenge clearing in ${clearAt}ms is reported solved through the cap`, capped.success, true);
        eq(`  ...with the method named (clearAt=${clearAt})`, capped.method, 'js_challenge_wait');
        check(`  ...and returns inside the ${I.FAST_TIMEOUTS.CHALLENGE_SOLVING}ms cap (took ${ms}ms)`,
          ms < I.FAST_TIMEOUTS.CHALLENGE_SOLVING, `${ms}ms`);
      }

      // --- phishing bypass must confirm the warning is gone -------------
      await page.goto(`http://127.0.0.1:${PORT}/phish-stuck`, { waitUntil: 'domcontentloaded' });
      const stuck = await I.handlePhishingWarning(page, `http://127.0.0.1:${PORT}/phish-stuck`, false);
      eq('a continue click that changes nothing is not a bypass', stuck.success, false);
      check('and it says why', /still present/.test(stuck.error || ''), stuck.error);
      const stuckPage = await page.evaluate(() => document.body.textContent.includes('reported for potential phishing'));
      check('the warning really is still on screen', stuckPage === true);

      await page.goto(`http://127.0.0.1:${PORT}/phish-ok`, { waitUntil: 'domcontentloaded' });
      const okPhish = await I.handlePhishingWarning(page, `http://127.0.0.1:${PORT}/phish-ok`, false);
      eq('a continue click that clears the warning IS a bypass', okPhish.success, true);
      eq('and it is marked as attempted', okPhish.attempted, true);

      // --- the rendering wait is paid once, not per selector -------------
      const SELS = ['input[type="checkbox"]', '.ctp-checkbox', '.ctp-checkbox-label',
                    '[role="checkbox"]', 'label.cb-lb', 'label'];
      await page.goto(`http://127.0.0.1:${PORT}/shadow-none`, { waitUntil: 'domcontentloaded' });
      const tMiss = Date.now();
      const miss = await I.clickInShadowDOM(page, SELS, false);
      const missMs = Date.now() - tMiss;
      eq('all-miss finds nothing', miss.found, false);
      // Two of these run per solve attempt, inside one CHALLENGE_SOLVING cap.
      check(`all-miss cost (${missMs}ms) leaves room for two calls inside the ${I.FAST_TIMEOUTS.CHALLENGE_SOLVING}ms cap`,
        missMs * 2 < I.FAST_TIMEOUTS.CHALLENGE_SOLVING,
        `2 x ${missMs}ms vs ${I.FAST_TIMEOUTS.CHALLENGE_SOLVING}ms`);

      await page.goto(`http://127.0.0.1:${PORT}/shadow-now`, { waitUntil: 'domcontentloaded' });
      const nowHit = await I.clickInShadowDOM(page, SELS, false);
      check('a later candidate present from the start is still clicked',
        nowHit.found === true && nowHit.clicked === true, JSON.stringify(nowHit));

      await page.goto(`http://127.0.0.1:${PORT}/shadow-late`, { waitUntil: 'domcontentloaded' });
      const lateHit = await I.clickInShadowDOM(page, SELS, false);
      check('a later candidate that renders after 800ms is still clicked',
        lateHit.found === true && lateHit.clicked === true, JSON.stringify(lateHit));

      // Positive case: a page with no challenge markers must still pass, or
      // the fix would have broken real JS-challenge detection.
      await page.goto(`http://127.0.0.1:${PORT}/clean`, { waitUntil: 'domcontentloaded' });
      const jsOk = await I.waitForJSChallengeCompletion(page, false);
      eq('a cleared page IS reported as completed', jsOk.success, true);
    } finally {
      await browser.close();
      srv.close();
    }
  }

  // --- the outcome tag must not say 'ok' for a page that is still challenged ---
  // Measured 2026-11-09 on a real site: the per-URL line read
  //   Outcome: ok | clearance=no | cf_bm=no | http=403
  // with 20 cdn-cgi/challenge-platform requests in the same run, and that 'ok'
  // was read as "we got through". Both the status and the clearance state were
  // already printed on that line; neither reached the verdict. Same class as the
  // 11ms 'solved' this suite was built for, one tag over.
  {
    const { _internals: I } = loadInternals();
    const { buildOutcomeString, CHALLENGE_HTTP_STATUSES } = I;
    const base = {
      overallSuccess: true,
      phishingWarning: { attempted: false, success: true },
      verificationChallenge: { attempted: false, success: true }
    };

    eq('403 with nothing attempted is still_challenged, not ok',
      buildOutcomeString(base, null, { httpStatus: 403, bypassEnabled: true }),
      'still_challenged(403)');
    eq('503 interstitial is still_challenged too',
      buildOutcomeString(base, null, { httpStatus: 503, bypassEnabled: true }),
      'still_challenged(503)');

    // Narrow on purpose: an ORIGIN 404/500 is not a challenge. If this ever
    // starts tagging those, every ordinary error page becomes a false alarm.
    eq('an origin 404 stays ok',
      buildOutcomeString(base, null, { httpStatus: 404, bypassEnabled: true }), 'ok');
    eq('an origin 500 stays ok',
      buildOutcomeString(base, null, { httpStatus: 500, bypassEnabled: true }), 'ok');
    check('the challenge-status set is exactly 403 and 503',
      CHALLENGE_HTTP_STATUSES.size === 2 && CHALLENGE_HTTP_STATUSES.has(403) &&
      CHALLENGE_HTTP_STATUSES.has(503));

    // A solve must still win over the status: Cloudflare can answer 403 on the
    // challenge document and then clear, so a successful solve is the stronger
    // evidence and must not be downgraded.
    eq('a solved challenge outranks a challenge status',
      buildOutcomeString({ ...base, verificationChallenge: { attempted: true, success: true, method: 'turnstile' } },
        null, { httpStatus: 403, bypassEnabled: true }), 'solved(turnstile)');

    // --- disabled is not the same as "nothing there" -------------------------
    // `no_indicators` means detection ran and found nothing. There was no tag at
    // all for "found plenty, but cloudflare_bypass is false", so that reported
    // 'ok' and pointed the investigation at this module instead of at a config
    // flag that defaults to false.
    eq('bypass disabled reports skipped(bypass_disabled)',
      buildOutcomeString(base, null, { httpStatus: 200, bypassEnabled: false }),
      'skipped(bypass_disabled)');
    eq('disabled takes precedence over the status, since nothing was even tried',
      buildOutcomeString(base, null, { httpStatus: 403, bypassEnabled: false }),
      'skipped(bypass_disabled)');
    eq('no_indicators still wins -- detection ran and found nothing',
      buildOutcomeString({ ...base, skippedNoIndicators: true }, null,
        { httpStatus: 403, bypassEnabled: false }), 'no_indicators');
    eq('a timeout still wins over both new tags',
      buildOutcomeString({ ...base, timedOut: true }, null,
        { httpStatus: 403, bypassEnabled: false }), 'timeout');
    // No evidence passed at all (older callers): must behave exactly as before.
    eq('with no evidence argument the tag is unchanged',
      buildOutcomeString(base, null), 'ok');
  }

  console.log(`\n${failed === 0 ? '✅' : '❌'} ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})().catch(e => { console.error('FATAL', e); process.exit(1); });
