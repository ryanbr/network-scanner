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
  CHROME_BUILD, CHROME_GREASE_BRAND, CHROME_GREASE_VERSION, USER_AGENT_COLLECTIONS,
  acceptLanguageFor
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

  // The UA strings are the whole point of the spoof, so check their SHAPE
  // strictly rather than comparing them to themselves: asserting
  // navigator.userAgent === USER_AGENT_COLLECTIONS.get('chrome') passes even
  // if someone edits that entry. These templates allow exactly the tokens a
  // real reduced Chrome / Gecko UA carries and nothing else, and the majors
  // are checked against the vendors' own release data further down.
  const UA_SHAPES = {
    chrome: /^Mozilla\/5\.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit\/537\.36 \(KHTML, like Gecko\) Chrome\/(\d+)\.0\.0\.0 Safari\/537\.36$/,
    firefox: /^Mozilla\/5\.0 \(Windows NT 10\.0; Win64; x64; rv:(\d+)\.0\) Gecko\/20100101 Firefox\/(\d+)\.0$/
  };
  console.log('\n=== UA strings have exactly the expected shape ===');
  const chromeShape = UA_SHAPES.chrome.exec(USER_AGENT_COLLECTIONS.get('chrome'));
  check('chrome UA matches the reduced-Chrome template exactly',
    !!chromeShape, USER_AGENT_COLLECTIONS.get('chrome'));
  const ffShape = UA_SHAPES.firefox.exec(USER_AGENT_COLLECTIONS.get('firefox'));
  check('firefox UA matches the Gecko template exactly',
    !!ffShape, USER_AGENT_COLLECTIONS.get('firefox'));
  if (ffShape) {
    eqJSON('firefox UA: rv: and Firefox/ are the same major', ffShape[1], ffShape[2]);
  }

  console.log('\n=== Accept-Language matches the UA family on every transport ===');
  // Firefox sends ";q=0.5", Chromium ";q=0.9". The rule has three consumers --
  // nwss.js at the HTTP layer, lib/curl.js and lib/grep.js on their curl
  // invocations -- and one definition, acceptLanguageFor. Pin the mapping for
  // every collection entry so a new UA family cannot quietly inherit the wrong
  // q-value.
  for (const [key, ua] of USER_AGENT_COLLECTIONS) {
    const want = key.startsWith('firefox') ? 'en-US,en;q=0.5' : 'en-US,en;q=0.9';
    eqJSON(`acceptLanguageFor(${key})`, acceptLanguageFor(ua), want);
  }
  // Wiring, not behaviour: the two curl transports must ASK for the value
  // rather than carry their own copy. Both held a hardcoded ";q=0.5" that went
  // out under Chrome UAs too, so this guards the specific regression.
  for (const f of ['lib/curl.js', 'lib/grep.js']) {
    const src = fs.readFileSync(path.join(REPO, f), 'utf8');
    check(`${f} derives Accept-Language from the UA`,
      src.includes('Accept-Language: ${acceptLanguageFor(userAgent)}'), f);
    check(`${f} carries no hardcoded Accept-Language`,
      !/'Accept-Language: en-US/.test(src), f);
  }

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

  // Firefox major against Mozilla's product-details API, mirroring the Chrome
  // check above: a UA claiming a major that is not current Stable stands out
  // regardless of how internally consistent the rest of the spoof is.
  // Network-optional.
  try {
    const res = await fetch('https://product-details.mozilla.org/1.0/firefox_versions.json',
      { signal: AbortSignal.timeout(15000) });
    const v = await res.json();
    const latest = String(v.LATEST_FIREFOX_VERSION || '');
    const ffUaMajor = (USER_AGENT_COLLECTIONS.get('firefox').match(/Firefox\/(\d+)/) || [])[1];
    eqJSON(`firefox UA major is Mozilla's current Stable (${latest})`,
      ffUaMajor, latest.split('.')[0]);
  } catch (e) {
    console.log(`  … skipped the Firefox Stable check (no network: ${e.message})`);
  }

  // --- local server: records the document request's headers, and receives the
  // --- page's own view of navigator.userAgentData back as a query string.
  const captured = { headers: null, js: null, fetchHeaders: null };
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
          // A page-initiated fetch() carrying NO explicit headers, so the
          // request shows whatever the engine -- or our spoof -- decided.
          try { await fetch('/fetchprobe'); } catch (e) { /* recorded as absent */ }
          img.src = '/report?d=' + encodeURIComponent(JSON.stringify({
            userAgent: navigator.userAgent, brands: d ? d.brands : null,
            platform: d ? d.platform : null, mobile: d ? d.mobile : null, high: hi,
            manifestVersion,
            // Locale/timezone view. Wrapped because a hostile or broken Intl
            // must not abort the whole report -- a null reads as a failure
            // below rather than as a silently missing check.
            tz: (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return null; } })(),
            icuLocale: (() => { try { return Intl.DateTimeFormat().resolvedOptions().locale; } catch (e) { return null; } })(),
            tzOffset: new Date().getTimezoneOffset(),
            navLanguage: navigator.language,
            navLanguages: (() => { try { return Array.from(navigator.languages); } catch (e) { return null; } })(),
            navPlatform: navigator.platform }));
        })();
      </script></body></html>`);
    }
    if (req.url.startsWith('/fetchprobe')) {
      captured.fetchHeaders = req.headers;
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('ok');
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
  console.log('\n=== page-initiated fetch() must not contradict the spoofed family ===');
  // The engine underneath is always Chromium, which sends "en-US,en;q=0.9";
  // Firefox sends ";q=0.5". So a chrome* spoof has to keep the engine's own
  // value, and a real fetch() with no Accept sends "*/*" -- not a navigation
  // Accept. lib/fingerprint.js used to set the Gecko q-value and a document
  // Accept unconditionally, which made every chrome-spoofed page fetch
  // contradict its own UA; these pin that it is Gecko-only now.
  if (!captured.fetchHeaders) {
    check('fetch() headers were captured', false, 'no /fetchprobe request arrived');
  } else {
    const fh = Object.fromEntries(
      Object.entries(captured.fetchHeaders).map(([k, v]) => [k.toLowerCase(), v]));
    check("chrome fetch(): Accept-Language is NOT Firefox's q=0.5",
      fh['accept-language'] !== 'en-US,en;q=0.5', String(fh['accept-language']));
    check("chrome document: Accept-Language is NOT Firefox's q=0.5",
      h['accept-language'] !== 'en-US,en;q=0.5', String(h['accept-language']));
    eqJSON('chrome: document and fetch() agree on Accept-Language',
      fh['accept-language'], h['accept-language']);
    eqJSON('chrome fetch(): Accept is the fetch default, not a navigation Accept',
      fh['accept'], '*/*');
    eqJSON('chrome fetch(): User-Agent still carries the spoof',
      fh['user-agent'], js.userAgent);
  }

  // ---- locale / timezone / platform coherence ----------------------------
  //
  // nwss already does the hard part the right way: the timezone is emulated at
  // the CDP level (Emulation.setTimezoneOverride), not by overriding Intl and
  // Date.getTimezoneOffset, which lib/fingerprint.js records as "actively
  // harmful" because the hardcoded offsets ignored DST. What nothing pinned is
  // that the surfaces AGREE. They agree today by convention -- every profile
  // timezone is America/* and acceptLanguageFor always returns en-US -- so a
  // Europe/Berlin profile, or a locale change, would ship an en-US page sitting
  // in a German timezone. That is a first-order contradiction, the same class
  // as a Chrome 145 engine advertising 157, and no UA surface would notice.
  //
  // These are discriminating on this host rather than passing by luck: the
  // machine's real zone is Pacific/Auckland, so an emulation failure reports
  // Auckland against an America/* profile and the check fails. navigator
  // .language is the exception -- it is spoofed to en-US and the host is also
  // en-US, so its check proves coherence with the header, not that spoofing ran.
  {
    const fpSrc = fs.readFileSync(path.join(REPO, 'lib', 'fingerprint.js'), 'utf8');
    const zones = [...new Set([...fpSrc.matchAll(/timezone:\s*'([^']+)'/g)].map(m => m[1]))];
    const langFamily = (acceptLanguageFor(chromeUa).split(',')[0] || '').trim();

    check('fingerprint.js declares at least one timezone', zones.length > 0, String(zones.length));
    // If a non-US locale or a non-American zone is introduced this SHOULD fail:
    // the pairing is the decision being pinned, not an implementation detail.
    check(`every declared timezone matches the ${langFamily} locale region`,
      langFamily === 'en-US' && zones.every(z => z.startsWith('America/')),
      `locale ${langFamily}, zones ${zones.join(', ')}`);

    check('the page reports a spoofed timezone from the declared set',
      zones.includes(js.tz), `page tz ${js.tz}, declared ${zones.join(', ')}`);

    // navigator.languages against the Accept-Language header THIS scan sent.
    // A clean browser puts the base language in the header and NOT in the
    // list: measured, `en-US,en;q=0.9` pairs with ["en-US"]. The spoof used to
    // report ['en-US', 'en'], which disagreed with our own header -- and with
    // what the same browser reports inside a worker, where the injection does
    // not reach. The list is the thing pinned here, since the header already
    // has its own checks above.
    const headerLangs = (h['accept-language'] || '').split(',').map(s => s.split(';')[0].trim()).filter(Boolean);
    check('navigator.languages is a list, not null',
      Array.isArray(js.navLanguages) && js.navLanguages.length > 0, JSON.stringify(js.navLanguages));
    check('navigator.languages holds only the full locale, not the base language',
      Array.isArray(js.navLanguages) && js.navLanguages.length === 1 && js.navLanguages[0] === headerLangs[0],
      `languages ${JSON.stringify(js.navLanguages)}, header ${JSON.stringify(headerLangs)}`);
    check('...and the header still carries the base language as its q-fallback',
      headerLangs.length === 2 && headerLangs[1] === headerLangs[0].split('-')[0],
      `header ${JSON.stringify(headerLangs)}`);
    check('navigator.language is the first entry of navigator.languages',
      Array.isArray(js.navLanguages) && js.navLanguage === js.navLanguages[0],
      `language ${js.navLanguage}, languages ${JSON.stringify(js.navLanguages)}`);

    // The UA injection's own languages literal is NOT observable above: both
    // scans here set fingerprint_protection, and applyFingerprintProtection
    // assigns languages SECOND, overwriting it. Mutation-tested -- appending
    // the base language in the UA injection alone passes every runtime check
    // in this file. It is observable for a site that sets userAgent WITHOUT
    // fingerprint_protection, so pin both assignments in the source rather
    // than paying for a third real scan to cover one property. This is a text
    // check and says nothing about behaviour; the runtime checks above cover
    // the path that these scans actually exercise.
    const langAssigns = [...fpSrc.matchAll(/const languages = ([^;]+);/g)].map(m => m[1].trim());
    check('fingerprint.js still has exactly two languages assignments',
      langAssigns.length === 2, `found ${langAssigns.length}: ${langAssigns.join(' | ')}`);
    check('neither languages assignment appends the base language',
      langAssigns.length === 2 && langAssigns.every(a => !/\.split\('-'\)\[0\]/.test(a) && !/\['en-US',\s*'en'\]/.test(a)),
      langAssigns.join(' | '));

    // getTimezoneOffset is derived by the engine from the emulated zone, so it
    // must match an independent computation for that zone -- the DST correctness
    // the JS-override approach kept getting wrong. Computed via formatToParts
    // rather than Date parsing, which is implementation-defined.
    //
    // A REGRESSION guard, labelled as one: while the zone comes from
    // emulateTimezone, Date and Intl agree by construction, so no mutation
    // reaches this -- disabling emulation leaves the page reporting its real
    // zone AND that zone's offset, which still agrees. It fails only if someone
    // reintroduces JS-level timezone patching, which is the decision it pins.
    const offsetFor = (zone, when = new Date()) => {
      const parts = new Intl.DateTimeFormat('en-US', {
        timeZone: zone, hour12: false, year: 'numeric', month: '2-digit',
        day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'
      }).formatToParts(when).filter(x => x.type !== 'literal');
      const f = Object.fromEntries(parts.map(x => [x.type, x.value]));
      const asUTC = Date.UTC(+f.year, +f.month - 1, +f.day,
        f.hour === '24' ? 0 : +f.hour, +f.minute, +f.second);
      return Math.round((when.getTime() - asUTC) / 60000);
    };
    if (js.tz) {
      const want = offsetFor(js.tz);
      check('Date.getTimezoneOffset agrees with the emulated zone (DST included)',
        Math.abs(js.tzOffset - want) <= 1, `page ${js.tzOffset}, computed ${want} for ${js.tz}`);
    } else {
      check('Date.getTimezoneOffset agrees with the emulated zone (DST included)',
        false, 'page reported no timezone');
    }

    eqJSON('navigator.language matches the Accept-Language family', js.navLanguage, langFamily);
    check('ICU locale agrees with navigator.language',
      String(js.icuLocale || '').startsWith(langFamily), `${js.icuLocale} vs ${langFamily}`);
  }

  console.log('\n=== Firefox family coherence ===');
  const ffUa = USER_AGENT_COLLECTIONS.get('firefox');
  const ffMajor = (ffUa.match(/Firefox\/(\d+)/) || [])[1];
  const ffRv = (ffUa.match(/rv:(\d+)/) || [])[1];
  eqJSON('rv: and Firefox/ carry the same major', ffRv, ffMajor);
  check('Gecko trail is the frozen 20100101, not a release date',
    /Gecko\/20100101/.test(ffUa), ffUa);

  const ffCaptured = { js: null, headers: null, fetchHeaders: null };
  const FF_PORT = 8355;
  const ffSrv = http.createServer((req, res) => {
    if (req.url === '/') {
      ffCaptured.headers = req.headers;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(`<html><body><script>
        (async () => {
          const img = new Image();
          // A page-initiated fetch() carrying NO explicit headers, so the
          // request shows whatever the engine -- or our spoof -- decided.
          try { await fetch('/fetchprobe'); } catch (e) { /* recorded as absent */ }
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
    if (req.url.startsWith('/fetchprobe')) {
      ffCaptured.fetchHeaders = req.headers;
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('ok');
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
    // The Gecko half of the same question: here the override IS required,
    // because the Chromium underneath would otherwise send q=0.9 against a
    // Firefox UA.
    if (!ffCaptured.fetchHeaders) {
      check('firefox fetch() headers were captured', false, 'no /fetchprobe request arrived');
    } else {
      const ffh = Object.fromEntries(
        Object.entries(ffCaptured.fetchHeaders).map(([k, v]) => [k.toLowerCase(), v]));
      eqJSON("firefox fetch(): Accept-Language is Gecko's q=0.5",
        ffh['accept-language'], 'en-US,en;q=0.5');
      // The point of setting it at the HTTP layer: the DOCUMENT request has to
      // carry it too. A fetch()-only override left this on Chromium's q=0.9,
      // so the one request matching the UA disagreed with its own page.
      eqJSON("firefox document: Accept-Language is Gecko's q=0.5",
        ffCaptured.headers && ffCaptured.headers['accept-language'], 'en-US,en;q=0.5');
      eqJSON('firefox: document and fetch() agree on Accept-Language',
        ffh['accept-language'], ffCaptured.headers && ffCaptured.headers['accept-language']);
      eqJSON('firefox fetch(): Accept is the fetch default',
        ffh['accept'], '*/*');
      eqJSON('firefox fetch(): User-Agent still carries the spoof',
        ffh['user-agent'], f.userAgent);
    }
  }

  // ---- Which ENGINE carries the spoofed identity -------------------------
  //
  // Every surface above derives from the pinned major, so they agree with each
  // other no matter what browser is underneath -- which is how a real 12-major
  // gap went unnoticed: nwss drives the first existing path from its standard
  // list, which on the machine this was found on is Chrome 145 while the pin
  // advertises 157. `typeof Iterator.concat === "function"` is false on 145 and
  // true from 157, so one line of feature detection reads through the disguise.
  //
  // The gap is REPORTED here, not closed. A variant that picked the newest
  // browser installed instead made scripts/test-seeding.js fail intermittently
  // on the sessionStorage seed -- 3 of 5 runs, against 4 of 4 clean on the
  // installed Chrome, measured serially on one machine -- and scans still
  // produced rules, so the damage would have been quiet. Closing the gap
  // belongs in the installed browser. These pin the reporting AND the revert.
  {
    const STANDARD_PATHS = [
      '/usr/bin/google-chrome-stable', '/usr/bin/google-chrome',
      '/usr/bin/chromium-browser', '/usr/bin/chromium', '/snap/bin/chromium',
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium'
    ];
    const run = (cmd, args) => new Promise((res) =>
      execFile(cmd, args, { timeout: 20000, maxBuffer: 8 << 20 },
        (err, stdout, stderr) => res({ err, stdout: String(stdout || ''), stderr: String(stderr || '') })));

    const firstExisting = STANDARD_PATHS.find(c => fs.existsSync(c)) || null;
    const pinnedMajor = parseInt((USER_AGENT_COLLECTIONS.get('chrome').match(/Chrome\/(\d+)/) || [])[1], 10);

    const cfg = path.join(os.tmpdir(), `nwss-engine-${process.pid}.json`);
    // Port 9 is on Chrome's blocked list, so navigation fails immediately --
    // the browser still launches, which is the only part under test.
    fs.writeFileSync(cfg, JSON.stringify({ sites: [{ url: 'http://127.0.0.1:9/', filterRegex: 'doubleclick' }] }));
    const out = path.join(os.tmpdir(), `nwss-engine-${process.pid}.txt`);
    const scan = await run(process.execPath, [path.join(REPO, 'nwss.js'), '--custom-json', cfg, '-o', out, '--debug']);
    for (const f of [cfg, out]) { try { fs.unlinkSync(f); } catch {} }
    const log = scan.stdout + scan.stderr;

    const engineLine = (log.match(/Browser engine: .*/) || [])[0] || '';
    const engineMajor = parseInt((engineLine.match(/\b(\d+)\.\d+\.\d+\.\d+\b/) || [])[1], 10);
    check('nwss reports which engine it is driving', engineLine !== '',
      'no "Browser engine:" line under --debug');

    // Pins the REVERT: a newest-wins chooser is what broke seeding, so
    // selection staying first-match is a decision rather than an accident.
    if (firstExisting) {
      check('the engine is the FIRST existing standard path, not the newest installed',
        engineLine.includes(firstExisting), `${engineLine} (first existing: ${firstExisting})`);
    }

    // Anchored to the line: `[^[]*` matched across newlines, so with the path
    // removed this ran on to the NEXT log line's `[debug]` prefix and captured
    // "debug" -- non-empty and not the shell, so both checks below passed on
    // garbage. Found by mutating the log line away and seeing nothing fail.
    const spawned = (log.match(/Browser launched successfully:[^[\n]*\[([^\]\n]+)\]/) || [])[1] || '';
    check('the launch log names the binary that actually spawned', spawned !== '',
      'no [path] on the "Browser launched successfully" line');

    // chrome-headless-shell is a different binary, reached by `headless:
    // 'shell'` only when puppeteer resolves the browser itself. Not merely a
    // fingerprinting tell: measured, it seeds 0 of 4 sessionStorage items, so
    // it breaks the seeding this scanner depends on.
    check('nwss does not drive chrome-headless-shell (it breaks storage seeding)',
      spawned !== '' && !/chrome-headless-shell/.test(spawned), `spawned ${spawned}`);

    // Reported when the gap exists, not invented when it does not -- an
    // unconditional notice trains the operator to ignore it. NOTE: the no-gap
    // branch is unreachable on a machine whose Chrome is behind the pin, so a
    // mutation making this unconditional cannot be caught there.
    const reported = /spoof advertises/.test(log);
    check(`engine/spoof gap is reported iff present (engine ${engineMajor}, pin ${pinnedMajor})`,
      reported === (Number.isFinite(engineMajor) && engineMajor < pinnedMajor),
      `reported=${reported}, engine=${engineMajor}, pinned=${pinnedMajor}`);
  }


  console.log(`\n${failed === 0 ? '✅' : '❌'} ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})().catch(e => { console.error('FATAL', e); process.exit(1); });
