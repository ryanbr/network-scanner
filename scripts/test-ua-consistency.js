#!/usr/bin/env node
/**
 * test-ua-consistency.js
 *
 * The spoofed Chrome identity is spread across four places that must agree,
 * and a real scan is the only way to see all four at once:
 *
 *   lib/fingerprint.js  navigator.userAgentData.brands
 *   lib/fingerprint.js  getHighEntropyValues().fullVersionList
 *   nwss.js             Sec-CH-UA
 *   nwss.js             Sec-CH-UA-Full-Version-List
 *
 * A site that requests the hints via accept-ch can read the HTTP pair and the
 * JS pair and compare them, so any disagreement is a detection tell rather
 * than a cosmetic bug. The Chrome 151 bump updated three of the four and left
 * fullVersionList on 150's brand order, which is what prompted this suite.
 *
 * It also re-derives the GREASE brand/version/order from the pinned major
 * using Chromium's documented algorithm, so the constants cannot drift from
 * the major they are supposed to describe.
 *
 * Runs a real scan against a local server that records the request headers
 * while the page reports its own JS view. ~20s, needs a browser.
 *
 * Run: node scripts/test-ua-consistency.js
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { execFile } = require('child_process');

const REPO = path.join(__dirname, '..');
const {
  CHROME_BUILD, CHROME_GREASE_BRAND, CHROME_GREASE_VERSION, USER_AGENT_COLLECTIONS
} = require(path.join(REPO, 'lib', 'fingerprint.js'));

let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`); failed++; }
}
const eqJSON = (name, got, want) =>
  check(name, JSON.stringify(got) === JSON.stringify(want),
    `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);

// Chromium's deterministic GREASE derivation, documented in lib/fingerprint.js's
// module header and verified there against real Chrome 128/131/148.
function deriveGrease(major) {
  const chars = [' ', '(', ':', '-', '.', '/', ')', ';', '=', '?', '_'];
  const orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
  const version = ['8', '99', '24'][major % 3];
  const brand = 'Not' + chars[major % 11] + 'A' + chars[(major + 1) % 11] + 'Brand';
  const names = ['grease', 'Chromium', 'Google Chrome'];
  const seq = [];
  orders[major % 6].forEach((slot, elem) => { seq[slot] = names[elem]; });
  return { brand, version, order: seq };
}

const parseCH = (v) => [...v.matchAll(/"([^"]+)";v="([^"]+)"/g)].map(m => [m[1], m[2]]);

(async () => {
  const chromeUa = USER_AGENT_COLLECTIONS.get('chrome');
  const major = (chromeUa.match(/Chrome\/(\d+)/) || [])[1];
  const full = `${major}.0.${CHROME_BUILD}`;
  const derived = deriveGrease(Number(major));
  // The brand order with 'grease' resolved to the configured brand string.
  const expectedOrder = derived.order.map(n => (n === 'grease' ? CHROME_GREASE_BRAND : n));

  console.log(`\n=== pinned identity: Chrome ${major}, build ${CHROME_BUILD} ===`);
  console.log(`=== GREASE re-derived from major ${major} ===`);
  check(`brand matches the algorithm (${derived.brand})`,
    CHROME_GREASE_BRAND === derived.brand, `constant is ${CHROME_GREASE_BRAND}`);
  check(`version matches the algorithm (${derived.version})`,
    CHROME_GREASE_VERSION === derived.version, `constant is ${CHROME_GREASE_VERSION}`);
  console.log(`  … expected brand order: ${expectedOrder.join(', ')}`);

  // --- Is major.0.BUILD a version that actually EXISTS? ------------------
  // The checks below are all internal consistency, and every surface derives
  // from CHROME_BUILD, so a stale build agrees with itself perfectly: reverting
  // CHROME_BUILD to a 151 build while the UA says 154 passed every other check
  // in this file. That pair is impossible in the wild and is the exact tell
  // nwss.js's chromeMajor fallback comment warns about, so ask Google.
  // Network-optional: skipped, not failed, when offline.
  try {
    const res = await fetch('https://versionhistory.googleapis.com/v1/chrome/platforms/win/' +
      'channels/stable/versions/all/releases?filter=endtime=none',
      { signal: AbortSignal.timeout(15000) });
    const releases = (await res.json()).releases || [];
    const served = releases.map(r => r.version);
    const majors = [...new Set(served.map(v => v.split('.')[0]))];
    check(`Chrome ${major} is a currently-served Stable major (serving: ${majors.join(', ')})`,
      majors.includes(String(major)));
    check(`${full} is a real served build, not a stale one from another major`,
      served.includes(full),
      `served builds for this major: ${served.filter(v => v.startsWith(major + '.')).join(', ') || 'none'}`);
    // Share is informational: a served-but-rare build still blends worse.
    const tot = releases.reduce((a, r) => a + (r.fraction || 0), 0) || 1;
    const mine = releases.filter(r => r.version === full).reduce((a, r) => a + (r.fraction || 0), 0);
    console.log(`  … ${full} is ${(mine / tot * 100).toFixed(1)}% of served Stable` +
      `, major ${major} is ${(releases.filter(r => r.version.startsWith(major + '.'))
        .reduce((a, r) => a + (r.fraction || 0), 0) / tot * 100).toFixed(1)}%`);
  } catch (e) {
    console.log(`  … skipped the real-build check (no network: ${e.message})`);
  }

  // --- local server: records the document request's headers, and receives the
  // --- page's own view of navigator.userAgentData back as a query string.
  const captured = { headers: null, js: null };
  const PORT = 8353;
  const srv = http.createServer((req, res) => {
    if (req.url === '/') {
      captured.headers = req.headers;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(`<html><body><script>
        (async () => {
          const d = navigator.userAgentData;
          const hi = d ? await d.getHighEntropyValues(['architecture','bitness','model',
            'platformVersion','uaFullVersion','fullVersionList','wow64','formFactors']) : null;
          const img = new Image();
          // chrome.runtime.getManifest().version is derived from the UA, so a
          // tracker can cross-check it against navigator.userAgent's major.
          let manifestVersion = null;
          try {
            if (window.chrome && window.chrome.runtime && window.chrome.runtime.getManifest) {
              manifestVersion = window.chrome.runtime.getManifest().version;
            }
          } catch (e) { manifestVersion = 'threw: ' + e.message; }
          img.src = '/report?d=' + encodeURIComponent(JSON.stringify({
            userAgent: navigator.userAgent, brands: d ? d.brands : null,
            platform: d ? d.platform : null, mobile: d ? d.mobile : null, high: hi,
            manifestVersion }));
        })();
      </script></body></html>`);
    }
    if (req.url.startsWith('/report')) {
      try { captured.js = JSON.parse(decodeURIComponent(req.url.split('?d=')[1])); } catch { /* reported below */ }
      res.writeHead(200, { 'Content-Type': 'image/gif' });
      return res.end();
    }
    res.writeHead(404); res.end();
  });
  await new Promise(r => srv.listen(PORT, '127.0.0.1', r));

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-ua-'));
  const cfgPath = path.join(tmp, 'cfg.json');
  fs.writeFileSync(cfgPath, JSON.stringify({ sites: [{
    url: `http://127.0.0.1:${PORT}/`, filterRegex: 'never-matches-anything',
    userAgent: 'chrome', fingerprint_protection: true,
    resourceTypes: ['document', 'image'], timeout: 20000, delay: 2500
  }] }));

  // ASYNC on purpose: the recording server lives in this process, so a
  // synchronous spawn would block the event loop and the server would never
  // accept the requests it is here to capture (the first version of this
  // suite did exactly that and reported an empty capture).
  await new Promise((resolve) => {
    execFile(process.execPath, [path.join(REPO, 'nwss.js'),
      '--custom-json', cfgPath, '-o', path.join(tmp, 'out.txt')],
      { cwd: REPO, timeout: 180000 }, (err) => {
        if (err) { console.log(`  ✗ the scan did not complete: ${err.message}`); failed++; }
        resolve();
      });
  });
  srv.close();
  fs.rmSync(tmp, { recursive: true, force: true });

  if (!captured.headers || !captured.js) {
    console.log(`  ✗ capture incomplete (headers=${!!captured.headers} js=${!!captured.js}) — cannot compare`);
    failed++;
    console.log(`\n❌ ${passed} passed, ${failed} failed\n`);
    process.exit(1);
  }

  const h = Object.fromEntries(Object.entries(captured.headers).map(([k, v]) => [k.toLowerCase(), v]));
  const js = captured.js;
  const hi = js.high || {};
  const strip = (s) => String(s).replace(/^"|"$/g, '');

  console.log('\n=== user agent ===');
  eqJSON('navigator.userAgent is the pinned collection entry', js.userAgent, chromeUa);
  eqJSON('HTTP User-Agent equals the JS one', h['user-agent'], js.userAgent);

  console.log('\n=== chrome.runtime manifest agrees with the UA ===');
  check('chrome.runtime.getManifest().version is present',
    typeof js.manifestVersion === 'string' && /^\d/.test(js.manifestVersion), String(js.manifestVersion));
  eqJSON('manifest major equals the UA major', String(js.manifestVersion || '').split('.')[0], String(major));

  console.log('\n=== brand order: all four surfaces must be identical ===');
  eqJSON('Sec-CH-UA (HTTP)', parseCH(h['sec-ch-ua']).map(([b]) => b), expectedOrder);
  eqJSON('Sec-CH-UA-Full-Version-List (HTTP)', parseCH(h['sec-ch-ua-full-version-list']).map(([b]) => b), expectedOrder);
  eqJSON('userAgentData.brands (JS)', js.brands.map(b => b.brand), expectedOrder);
  eqJSON('fullVersionList (JS)', hi.fullVersionList.map(b => b.brand), expectedOrder);

  console.log('\n=== every full-version surface carries the same build ===');
  eqJSON('Sec-CH-UA-Full-Version (HTTP)', strip(h['sec-ch-ua-full-version']), full);
  eqJSON('Full-Version-List builds (HTTP)',
    parseCH(h['sec-ch-ua-full-version-list']).filter(([b]) => b !== CHROME_GREASE_BRAND).map(([, v]) => v), [full, full]);
  eqJSON('uaFullVersion (JS)', hi.uaFullVersion, full);
  eqJSON('fullVersionList builds (JS)',
    hi.fullVersionList.filter(b => b.brand !== CHROME_GREASE_BRAND).map(b => b.version), [full, full]);
  eqJSON('Sec-CH-UA majors (HTTP)',
    parseCH(h['sec-ch-ua']).filter(([b]) => b !== CHROME_GREASE_BRAND).map(([, v]) => v), [major, major]);
  eqJSON('brands majors (JS)',
    js.brands.filter(b => b.brand !== CHROME_GREASE_BRAND).map(b => b.version), [major, major]);
  check('the UA major and the claimed build agree (an impossible pair is a tell)',
    (js.userAgent.match(/Chrome\/(\d+)/) || [])[1] === hi.uaFullVersion.split('.')[0]);

  console.log('\n=== grease value on every surface ===');
  eqJSON('grease version, Sec-CH-UA (HTTP)',
    Object.fromEntries(parseCH(h['sec-ch-ua']))[CHROME_GREASE_BRAND], CHROME_GREASE_VERSION);
  eqJSON('grease version, Full-Version-List (HTTP)',
    Object.fromEntries(parseCH(h['sec-ch-ua-full-version-list']))[CHROME_GREASE_BRAND], `${CHROME_GREASE_VERSION}.0.0.0`);
  eqJSON('grease version, brands (JS)',
    Object.fromEntries(js.brands.map(b => [b.brand, b.version]))[CHROME_GREASE_BRAND], CHROME_GREASE_VERSION);
  eqJSON('grease version, fullVersionList (JS)',
    Object.fromEntries(hi.fullVersionList.map(b => [b.brand, b.version]))[CHROME_GREASE_BRAND], `${CHROME_GREASE_VERSION}.0.0.0`);

  console.log('\n=== platform hints: HTTP and JS must not disagree ===');
  eqJSON('platform', js.platform, strip(h['sec-ch-ua-platform']));
  eqJSON('platformVersion', hi.platformVersion, strip(h['sec-ch-ua-platform-version']));
  eqJSON('mobile', js.mobile ? '?1' : '?0', h['sec-ch-ua-mobile']);
  eqJSON('architecture', hi.architecture, strip(h['sec-ch-ua-arch']));
  eqJSON('bitness', hi.bitness, strip(h['sec-ch-ua-bitness']));
  eqJSON('wow64', hi.wow64 ? '?1' : '?0', h['sec-ch-ua-wow64']);
  eqJSON('model', hi.model, strip(h['sec-ch-ua-model']));
  eqJSON('formFactors', hi.formFactors, [strip(h['sec-ch-ua-form-factors'])]);

  // =====================================================================
  // Firefox has no UA-Client-Hints at all, so "coherent" means something
  // different: the Chromium-only surfaces must be ABSENT and the Gecko-only
  // ones present and correctly shaped. A Firefox UA that still answers
  // navigator.userAgentData, or reports Chrome's productSub, contradicts
  // itself in one line.
  console.log('\n=== Firefox family coherence ===');
  const ffUa = USER_AGENT_COLLECTIONS.get('firefox');
  const ffMajor = (ffUa.match(/Firefox\/(\d+)/) || [])[1];
  const ffRv = (ffUa.match(/rv:(\d+)/) || [])[1];
  eqJSON('rv: and Firefox/ carry the same major', ffRv, ffMajor);
  check('Gecko trail is the frozen 20100101, not a release date',
    /Gecko\/20100101/.test(ffUa), ffUa);

  const ffCaptured = { js: null };
  const FF_PORT = 8355;
  const ffSrv = http.createServer((req, res) => {
    if (req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(`<html><body><script>
        (async () => {
          const img = new Image();
          img.src = '/report?d=' + encodeURIComponent(JSON.stringify({
            userAgent: navigator.userAgent,
            hasUserAgentData: ('userAgentData' in navigator) || ('userAgentData' in Navigator.prototype),
            productSub: navigator.productSub,
            appVersion: navigator.appVersion,
            buildID: navigator.buildID,
            oscpu: navigator.oscpu,
            vendor: navigator.vendor,
            // Chromium-only globals that must not exist under a Gecko UA.
            hasChromeObj: 'chrome' in window,
            chromeType: typeof window.chrome,
            chromeKeys: window.chrome ? Object.keys(window.chrome).slice(0, 6) : null,
            chromeDescriptor: (d => d ? { configurable: d.configurable, writable: d.writable } : null)(
              Object.getOwnPropertyDescriptor(window, 'chrome')),
            plugins: navigator.plugins.length,
            mimeTypes: navigator.mimeTypes.length
          }));
        })();
      </script></body></html>`);
    }
    if (req.url.startsWith('/report')) {
      try { ffCaptured.js = JSON.parse(decodeURIComponent(req.url.split('?d=')[1])); } catch { /* reported below */ }
      res.writeHead(200, { 'Content-Type': 'image/gif' });
      return res.end();
    }
    res.writeHead(404); res.end();
  });
  await new Promise(r => ffSrv.listen(FF_PORT, '127.0.0.1', r));

  const ffTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-ff-'));
  const ffCfg = path.join(ffTmp, 'cfg.json');
  fs.writeFileSync(ffCfg, JSON.stringify({ sites: [{
    url: `http://127.0.0.1:${FF_PORT}/`, filterRegex: 'never-matches-anything',
    userAgent: 'firefox', fingerprint_protection: true,
    resourceTypes: ['document', 'image'], timeout: 20000, delay: 2500
  }] }));
  await new Promise((resolve) => {
    execFile(process.execPath, [path.join(REPO, 'nwss.js'),
      '--custom-json', ffCfg, '-o', path.join(ffTmp, 'out.txt')],
      { cwd: REPO, timeout: 180000 }, (err) => {
        if (err) { console.log(`  ✗ the Firefox scan did not complete: ${err.message}`); failed++; }
        resolve();
      });
  });
  ffSrv.close();
  fs.rmSync(ffTmp, { recursive: true, force: true });

  if (!ffCaptured.js) {
    console.log('  ✗ Firefox capture incomplete — cannot compare');
    failed++;
  } else {
    const f = ffCaptured.js;
    eqJSON('navigator.userAgent is the pinned Firefox entry', f.userAgent, ffUa);
    // Not "returns undefined" — ABSENT. The real browser under the spoof is
    // Chrome, so an un-overridden userAgentData is the genuine Chromium API
    // reporting the genuine Chrome.
    check('navigator.userAgentData is ABSENT (Gecko has no UA-CH)',
      f.hasUserAgentData === false, `hasUserAgentData=${f.hasUserAgentData}`);
    // window.chrome is non-configurable on some Chrome builds (measured:
    // system Chrome 145 yes, puppeteer's bundled 154 no), so `delete` cannot
    // always remove the property. What IS always achievable is blanking the
    // value, which is the part that carries the Chromium API surface. Assert
    // the achievable invariant; report the unreachable residue.
    check('window.chrome exposes no Chromium surface (typeof undefined, as in Gecko)',
      f.chromeType === 'undefined', `typeof window.chrome = ${f.chromeType}, keys=${JSON.stringify(f.chromeKeys)}`);
    if (f.hasChromeObj) {
      console.log(`  … note: 'chrome' in window is still true — this browser build has it` +
        ` non-configurable (${JSON.stringify(f.chromeDescriptor)}), so the property cannot be` +
        ` removed from JS; its value is blanked instead`);
    }
    eqJSON("productSub is Firefox's 20100101, not 20030107", f.productSub, '20100101');
    // Gecko builds appVersion as legacyAppVersion + " (" + platform + ")"
    // (dom/base/Navigator.cpp + netwerk/protocol/http/nsHttpHandler.cpp), NOT
    // Chromium's "UA minus Mozilla/". The collections' firefox entry is the
    // Windows one, so "Windows" is the expected platform literal.
    eqJSON('appVersion is Gecko\'s short form, not Chromium\'s derived UA',
      f.appVersion, '5.0 (Windows)');
    check('appVersion does not leak the whole UA',
      !(f.appVersion || '').includes('Gecko/'), String(f.appVersion));
    eqJSON('vendor is empty, as Gecko reports it', f.vendor, '');
    // Real Firefox freezes buildID at a 14-digit YYYYMMDDHHMMSS stamp. The
    // previous value was the 8-char Gecko trail, catchable on length alone.
    check('buildID is present', typeof f.buildID === 'string' && f.buildID.length > 0, String(f.buildID));
    check(`buildID is 14 digits (got ${f.buildID && f.buildID.length})`,
      /^\d{14}$/.test(f.buildID || ''), String(f.buildID));
    check('buildID is not the Gecko trail copied from the UA',
      f.buildID !== '20100101', String(f.buildID));
    check('oscpu is present (Gecko-only, absent in Chromium)',
      typeof f.oscpu === 'string' && f.oscpu.length > 0, String(f.oscpu));
    check('plugins and mimeTypes agree (0 plugins must mean 0 mimeTypes)',
      (f.plugins === 0) === (f.mimeTypes === 0),
      `plugins=${f.plugins} mimeTypes=${f.mimeTypes}`);
  }

  console.log(`\n${failed === 0 ? '✅' : '❌'} ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})().catch(e => { console.error('FATAL', e); process.exit(1); });
