#!/usr/bin/env node
/**
 * Stealth integration smoke test.
 *
 * Launches Puppeteer, applies the project's full fingerprint spoofing stack
 * (lib/fingerprint.js's applyAllFingerprintSpoofing), navigates to public
 * bot-detection test pages, and reports what the page concluded about us.
 *
 * Purpose: replace "I think the spoof works" theoretical reviews with real
 * signal -- which checks pass, which fail, which moved after a fingerprint
 * change. Run before and after a stealth-related commit to A/B the impact.
 *
 * Usage:
 *   node scripts/test-stealth.js                  # all targets, human-readable
 *   node scripts/test-stealth.js sannysoft        # one target
 *   node scripts/test-stealth.js --headful        # show browser GUI
 *   node scripts/test-stealth.js --no-spoof       # baseline (no fingerprint protection)
 *   node scripts/test-stealth.js --ua=firefox     # change UA family
 *   node scripts/test-stealth.js --format=json    # machine-readable output
 *   node scripts/test-stealth.js --help           # show usage
 *
 * Environment:
 *   PUPPETEER_NO_SANDBOX=1   pass --no-sandbox --disable-setuid-sandbox to
 *                            Chromium. Required when running as root (CI
 *                            containers, some Docker setups). Off by default
 *                            so local dev doesn't silently drop the sandbox.
 *
 * Targets (extend by adding to TARGETS below):
 *   sannysoft     https://bot.sannysoft.com/                  — classic fingerprint tests
 *   creepjs       https://abrahamjuliot.github.io/creepjs/    — modern fingerprint suite
 *   browserleaks  https://browserleaks.com/javascript         — JS env probe
 *
 * Output: one line per target with PASS / WARN / FAIL counts (where parseable),
 * plus a short summary of any explicit detection markers ("Bot detected",
 * "Headless", etc.) found in the page text. With --format=json, emits a single
 * JSON object suitable for piping to diff/jq for before/after comparison.
 *
 * This is a SMOKE test, not a unit test. It doesn't make assertions; it
 * reports what the page reports. Use the output to decide if a stealth
 * change moved the needle.
 */

'use strict';

const puppeteer = require('puppeteer');
const path = require('path');
const {
  applyAllFingerprintSpoofing,
  USER_AGENT_COLLECTIONS
} = require(path.resolve(__dirname, '..', 'lib', 'fingerprint'));

const args = process.argv.slice(2);
const HELP = args.includes('--help') || args.includes('-h');
const HEADFUL = args.includes('--headful');
const NO_SPOOF = args.includes('--no-spoof');
const UA_FLAG = (args.find(a => a.startsWith('--ua=')) || '').slice(5) || 'chrome';
const FORMAT = (args.find(a => a.startsWith('--format=')) || '').slice(9) || 'text';
const filterTargets = args.filter(a => !a.startsWith('-'));
// Anything starting with '-' is a flag claim; we validate the known set
// below so typos like "-headful" or "--no_spoof" don't silently no-op.
const flagArgs = args.filter(a => a.startsWith('-'));
const KNOWN_FLAGS = new Set(['--headful', '--no-spoof', '--help', '-h']);
const KNOWN_FLAG_PREFIXES = ['--ua=', '--format='];

const TARGETS = [
  {
    name: 'sannysoft',
    url: 'https://bot.sannysoft.com/',
    // Parse the result tables. Sannysoft uses td.passed / td.failed / td.warn.
    extract: async (page) => {
      return await page.evaluate(() => {
        const cells = Array.from(document.querySelectorAll('td'));
        const out = { passed: 0, failed: 0, warn: 0, total: 0, failures: [], warnings: [] };
        for (const c of cells) {
          const cls = c.className || '';
          if (cls.includes('passed')) { out.passed++; out.total++; }
          else if (cls.includes('failed')) {
            out.failed++; out.total++;
            // Try to capture the row label for context
            const row = c.closest('tr');
            const label = row?.querySelector('td')?.textContent?.trim() || '?';
            out.failures.push(label);
          }
          else if (cls.includes('warn')) {
            out.warn++; out.total++;
            // Capture warn-row labels too so a soft regression (cell moving
            // passed -> warn) is debuggable without --headful.
            const row = c.closest('tr');
            const label = row?.querySelector('td')?.textContent?.trim() || '?';
            out.warnings.push(label);
          }
        }
        return out;
      });
    }
  },
  {
    name: 'creepjs',
    url: 'https://abrahamjuliot.github.io/creepjs/',
    extract: async (page) => {
      // CreepJS surfaces a trust score in the page. Wait briefly for the
      // async fingerprinting tests to complete.
      await page.waitForSelector('#fingerprint-data', { timeout: 30000 }).catch(() => {});
      await new Promise(r => setTimeout(r, 8000)); // give async tests time
      return await page.evaluate(() => {
        const text = document.body.innerText || '';
        // CreepJS's actual stealth-relevant outputs are in a "Headless"
        // section as percentages (e.g. "67% headless", "40% stealth",
        // "44% like headless"), not the "Trust Score" label the old
        // regex expected. Engine identification comes from "chromium:
        // true/false" in the same block. Lower headless % and higher
        // stealth % are better for evasion.
        const headlessMatch = text.match(/(\d+(?:\.\d+)?)\s*%\s+headless\b/i);
        const likeHeadlessMatch = text.match(/(\d+(?:\.\d+)?)\s*%\s+like\s+headless/i);
        const stealthMatch = text.match(/(\d+(?:\.\d+)?)\s*%\s+stealth\b/i);
        const chromiumMatch = text.match(/chromium\s*:\s*(true|false)/i);
        // FP ID is CreepJS's stable fingerprint hash — same value across
        // reloads if the fingerprint is unchanged; lets you A/B before
        // and after a spoof change.
        const fpIdMatch = text.match(/FP\s*ID\s*:?\s*([0-9a-f]{16,})/i);
        return {
          headlessPct: headlessMatch ? parseFloat(headlessMatch[1]) : null,
          likeHeadlessPct: likeHeadlessMatch ? parseFloat(likeHeadlessMatch[1]) : null,
          stealthPct: stealthMatch ? parseFloat(stealthMatch[1]) : null,
          isChromium: chromiumMatch ? chromiumMatch[1] === 'true' : null,
          fpId: fpIdMatch ? fpIdMatch[1].slice(0, 16) : null,
          // Larger excerpt (40 lines, up to 2KB) so a future UI rotation
          // is debuggable from the output without --headful.
          excerpt: text.split('\n').slice(0, 40).join('\n').slice(0, 2000)
        };
      });
    }
  },
  {
    name: 'browserleaks',
    url: 'https://browserleaks.com/javascript',
    extract: async (page) => {
      return await page.evaluate(() => {
        // browserleaks shows the values; we just capture the navigator-related ones
        // and report which look anomalous.
        return {
          userAgent: navigator.userAgent,
          platform: navigator.platform,
          webdriver: navigator.webdriver,
          languages: JSON.stringify(navigator.languages),
          hardwareConcurrency: navigator.hardwareConcurrency,
          deviceMemory: navigator.deviceMemory,
          plugins: navigator.plugins?.length,
          chromeRuntime: typeof window.chrome?.runtime,
          chromeRuntimeVersion: (() => { try { return window.chrome?.runtime?.getManifest?.()?.version; } catch (e) { return 'error'; } })(),
          windowChromeDescriptor: (() => {
            const d = Object.getOwnPropertyDescriptor(window, 'chrome');
            return d ? `writable=${d.writable},enumerable=${d.enumerable},configurable=${d.configurable}` : 'no-descriptor';
          })(),
          errorName: Error.name,
          errorLength: Error.length,
          rtcName: window.RTCPeerConnection?.name,
          imageName: window.Image?.name
        };
      });
    }
  }
];

function printHelp() {
  console.log(`Usage: node scripts/test-stealth.js [options] [target...]

Options:
  --headful           launch with browser GUI visible
  --no-spoof          baseline run — skip applyAllFingerprintSpoofing
  --ua=<family>       UA family to spoof (default: chrome)
                      valid: ${Array.from(USER_AGENT_COLLECTIONS.keys()).join(', ')}
  --format=<fmt>      output format: text (default) | json
  --help, -h          show this message

Environment:
  PUPPETEER_NO_SANDBOX=1   pass --no-sandbox to Chromium (required in some CI)

Targets: ${TARGETS.map(t => t.name).join(', ')} (default: all)`);
}

function formatResult(target, result) {
  const lines = [`\n=== ${target.name} (${target.url}) ===`];
  if (target.name === 'sannysoft') {
    lines.push(`  passed: ${result.passed} | warn: ${result.warn} | failed: ${result.failed} | total: ${result.total}`);
    if (result.failures.length) {
      lines.push(`  failure rows: ${result.failures.slice(0, 10).join(', ')}${result.failures.length > 10 ? ` ... +${result.failures.length - 10} more` : ''}`);
    }
    if (result.warnings && result.warnings.length) {
      lines.push(`  warn rows: ${result.warnings.slice(0, 10).join(', ')}${result.warnings.length > 10 ? ` ... +${result.warnings.length - 10} more` : ''}`);
    }
  } else if (target.name === 'creepjs') {
    lines.push(`  FP ID: ${result.fpId ?? 'n/a'}  (stable across reloads if fingerprint unchanged)`);
    lines.push(`  engine chromium: ${result.isChromium ?? 'n/a'}`);
    lines.push(`  headless score: ${result.headlessPct ?? 'n/a'}%  (lower = better; 0% = real browser)`);
    lines.push(`  like-headless: ${result.likeHeadlessPct ?? 'n/a'}%  (lower = better; soft headless signals)`);
    lines.push(`  stealth score: ${result.stealthPct ?? 'n/a'}%  (lower = better; % likely to be using anti-detection tooling)`);
    if (result.excerpt) lines.push(`  excerpt:\n    ${result.excerpt.split('\n').join('\n    ')}`);
  } else if (target.name === 'browserleaks') {
    for (const [k, v] of Object.entries(result)) {
      lines.push(`  ${k.padEnd(24)} ${v}`);
    }
  }
  return lines.join('\n');
}

(async () => {
  if (HELP) { printHelp(); process.exit(0); }

  // Validate --ua= against the canonical UA list. Previously a typo like
  // --ua=opera silently fell through to applyUserAgentSpoofing's "unknown UA,
  // no-op" path, producing run results that looked spoofed but weren't.
  if (!USER_AGENT_COLLECTIONS.has(UA_FLAG)) {
    console.error(`Invalid --ua=${UA_FLAG}. Valid: ${Array.from(USER_AGENT_COLLECTIONS.keys()).join(', ')}`);
    process.exit(2);
  }

  if (!['text', 'json'].includes(FORMAT)) {
    console.error(`Invalid --format=${FORMAT}. Valid: text, json`);
    process.exit(2);
  }

  // Reject unrecognised flags before we launch a browser. Typos like
  // "-headful" or "--no_spoof" used to silently no-op and produce a
  // misleading "spoof on" run that wasn't actually spoofed.
  const badFlags = flagArgs.filter(f =>
    !KNOWN_FLAGS.has(f) && !KNOWN_FLAG_PREFIXES.some(p => f.startsWith(p))
  );
  if (badFlags.length) {
    console.error(`Unrecognised flag(s): ${badFlags.join(', ')}. See --help.`);
    process.exit(2);
  }

  const targetsToRun = filterTargets.length
    ? TARGETS.filter(t => filterTargets.includes(t.name))
    : TARGETS;

  if (targetsToRun.length === 0) {
    console.error(`No targets matched. Available: ${TARGETS.map(t => t.name).join(', ')}`);
    process.exit(2);
  }

  if (FORMAT === 'text') {
    console.log(`Stealth test config: spoof=${!NO_SPOOF}, ua=${UA_FLAG}, headful=${HEADFUL}`);
    console.log(`Targets: ${targetsToRun.map(t => t.name).join(', ')}`);
  }

  // Sandbox is on by default; opt out via env var rather than baking
  // --no-sandbox into the launch line. CI-as-root needs it; local dev should
  // not silently drop the sandbox just because the test happens to start it.
  const launchArgs = ['--disable-blink-features=AutomationControlled'];
  if (process.env.PUPPETEER_NO_SANDBOX === '1') {
    launchArgs.push('--no-sandbox', '--disable-setuid-sandbox');
  }

  const browser = await puppeteer.launch({
    headless: !HEADFUL,
    args: launchArgs
  });

  // Collected for JSON output (and to support a future --fail-on-detection
  // exit code without restructuring the loop).
  const collected = [];

  // --- Self-consistency check (runs for whatever --ua is selected) ---
  //
  // The bot-detection targets below are built to catch headless CHROME, so a
  // non-Chrome --ua scores their checks as "doesn't look like Chrome" and the
  // real contradictions hide in the noise. This check instead asks whether the
  // spoofed identity is coherent with ITSELF, which is what a detector actually
  // exploits: two bugs found this way were window.chrome being built under a
  // Firefox/Safari UA, and Firefox reporting 5 PDF plugins with 0 mimeTypes.
  // Cheap, offline (about:blank), and independent of any third-party page.
  // Run for BOTH fingerprint_protection profiles. The harness only ever
  // exercised 'random', which is why it never saw that the FIXED profile
  // reported navigator.platform Win32 under a Linux or Mac UA while the UA,
  // userAgentData and Sec-CH-UA-Platform all said otherwise.
  for (const fpProfile of (NO_SPOOF ? [] : ['random', true])) {
    const page = await browser.newPage();
    try {
      await applyAllFingerprintSpoofing(page,
        { userAgent: UA_FLAG, fingerprint_protection: fpProfile }, false, 'https://example.com');
      await page.goto('about:blank');
      const f = await page.evaluate(() => ({
        ua: navigator.userAgent,
        platform: navigator.platform,
        vendor: navigator.vendor,
        chromeObj: typeof window.chrome !== 'undefined',
        uaData: typeof navigator.userAgentData !== 'undefined',
        uaDataPlatform: navigator.userAgentData ? navigator.userAgentData.platform : null,
        perfMemory: typeof performance.memory !== 'undefined',
        deviceMemory: typeof navigator.deviceMemory !== 'undefined',
        connection: typeof navigator.connection !== 'undefined',
        scheduling: typeof navigator.scheduling !== 'undefined',
        oscpu: typeof navigator.oscpu !== 'undefined',
        buildID: typeof navigator.buildID !== 'undefined',
        plugins: navigator.plugins.length,
        mimeTypes: navigator.mimeTypes.length,
        // Collection TYPES, not just lengths: a plain array passes a length
        // check but fails `instanceof`, which is false on no real browser.
        pluginsIsPluginArray: (() => { try { return navigator.plugins instanceof PluginArray; } catch (e) { return false; } })(),
        mimeIsMimeTypeArray: (() => { try { return navigator.mimeTypes instanceof MimeTypeArray; } catch (e) { return false; } })(),
        // Every method this spoof replaces must still report its own name and
        // arity. Function.name and Function.length are OWN properties of a
        // function object, so an anonymous expression assigned to a prototype
        // slot reports name '' plus whatever arity it declared -- measured at
        // 18 of 26 probed methods before this was fixed, which makes
        // `WebGLRenderingContext.prototype.getParameter.name === 'getParameter'`
        // a one-expression detector. Lengths are the spec arities, taken from
        // a clean browser.
        wrapIdentity: (() => {
          const expect = [
            ['WebGLRenderingContext.prototype', 'getParameter', 1],
            ['WebGLRenderingContext.prototype', 'getExtension', 1],
            ['WebGLRenderingContext.prototype', 'getSupportedExtensions', 0],
            ['WebGL2RenderingContext.prototype', 'getParameter', 1],
            ['WebGL2RenderingContext.prototype', 'getExtension', 1],
            ['HTMLCanvasElement.prototype', 'getContext', 1],
            ['HTMLCanvasElement.prototype', 'toDataURL', 0],
            ['HTMLCanvasElement.prototype', 'toBlob', 1],
            ['CanvasRenderingContext2D.prototype', 'getImageData', 4],
            ['CanvasRenderingContext2D.prototype', 'fillText', 3],
            ['CanvasRenderingContext2D.prototype', 'strokeText', 3],
            ['CanvasRenderingContext2D.prototype', 'measureText', 1],
            ['OffscreenCanvasRenderingContext2D.prototype', 'getImageData', 4],
            ['OffscreenCanvasRenderingContext2D.prototype', 'fillText', 3],
            ['OffscreenCanvasRenderingContext2D.prototype', 'measureText', 1],
            ['OffscreenCanvas.prototype', 'convertToBlob', 0],
            ['EventTarget.prototype', 'addEventListener', 2],
            ['EventTarget.prototype', 'removeEventListener', 2],
            ['navigator.permissions', 'query', 1],
            ['navigator', 'getBattery', 0],
            ['performance', 'now', 0],
            ['Notification', 'requestPermission', 0],
            ['console', 'debug', 0]
          ];
          const bad = [];
          for (const [path, method, len] of expect) {
            let obj = null;
            try { obj = path.split('.').reduce((o, k) => o[k], window); } catch (e) { obj = null; }
            const fn = obj && obj[method];
            // Absent interface (an older Chrome without WebGL2, say) is not a
            // finding; a present one reporting the wrong identity is.
            if (typeof fn !== 'function') continue;
            if (fn.name !== method) bad.push(`${path}.${method} name=${JSON.stringify(fn.name)}`);
            else if (fn.length !== len) bad.push(`${path}.${method} length=${fn.length} want ${len}`);
          }
          // Accessors carry names too: a getter written as `{ get: () => ... }`
          // in an object literal takes its name from the KEY, so a spoofed
          // property reported "get" where real Chrome reports "get platform".
          // Measured at 13 of 22 probed accessors. Checked for properties
          // whether or not this config spoofs them -- a native getter already
          // has the right name, so the assertion holds either way.
          for (const [path, prop] of [
            ['navigator', 'platform'], ['navigator', 'hardwareConcurrency'], ['navigator', 'deviceMemory'],
            ['navigator', 'maxTouchPoints'], ['navigator', 'languages'], ['navigator', 'language'],
            ['navigator', 'vendor'], ['navigator', 'cookieEnabled'], ['navigator', 'doNotTrack'],
            ['screen', 'width'], ['screen', 'height'], ['screen', 'availWidth'], ['screen', 'colorDepth']
          ]) {
            let obj = null;
            try { obj = path === 'window' ? window : path.split('.').reduce((o, k) => o[k], window); } catch (e) { obj = null; }
            if (!obj) continue;
            let d = null, o = obj;
            while (o && !d) { d = Object.getOwnPropertyDescriptor(o, prop); if (!d) o = Object.getPrototypeOf(o); }
            if (!d || typeof d.get !== 'function') continue;
            if (d.get.name !== `get ${prop}`) bad.push(`${path}.${prop} getter name=${JSON.stringify(d.get.name)}`);
            // SOURCE. An arrow function prints ITSELF, so a spoofed getter
            // returned "() => spoof.platform" where Chrome returns
            // "function get platform() { [native code] }", and screen.width
            // returned "() => spoof.screen[prop]" -- it does not just reveal
            // the patch, it prints the spoof's internals. Measured at 13 of 22
            // probed accessors, every one installed by the injection that had
            // no toString masking of its own. A native getter satisfies this
            // already, so the assertion holds either way.
            let gsrc = '';
            try { gsrc = d.get.toString(); } catch (e) { gsrc = 'THREW ' + e.message; }
            if (!gsrc.includes('[native code]')) bad.push(`${path}.${prop} getter source=${JSON.stringify(gsrc.slice(0, 48))}`);
            // WHERE the accessor lives. Chrome keeps these on
            // Navigator.prototype / Screen.prototype, so a spoof that defines
            // them on the instance makes
            // Object.getOwnPropertyDescriptor(navigator, 'platform') return a
            // descriptor where a real browser returns undefined -- one
            // expression per property, needing no function metadata at all.
            // Specifically SHADOWING: an own property sitting in front of a
            // prototype slot that exists. A property the context does not
            // expose natively at all (navigator.deviceMemory on about:blank,
            // which Chrome gates) has no slot to mirror, so defining it on the
            // instance is the only option and is not this defect.
            const ownHere = Object.getOwnPropertyDescriptor(obj, prop);
            let protoHas = false;
            for (let o = Object.getPrototypeOf(obj); o; o = Object.getPrototypeOf(o)) {
              if (Object.getOwnPropertyDescriptor(o, prop)) { protoHas = true; break; }
            }
            if (ownHere && protoHas) {
              bad.push(`${path}.${prop} is an OWN property shadowing the prototype slot`);
            }
          }
          // Function.prototype.toString is itself replaced -- once per
          // injection, so twice -- and is the function a detector is likeliest
          // to inspect. Four things have to match a real one.
          (() => {
            const ts = Function.prototype.toString;
            let tsrc = '';
            try { tsrc = ts.toString(); } catch (e) { tsrc = 'THREW ' + e.message; }
            if (!tsrc.includes('[native code]')) bad.push(`Function.prototype.toString source=${JSON.stringify(tsrc.slice(0, 48))}`);
            if (ts.name !== 'toString') bad.push(`Function.prototype.toString name=${JSON.stringify(ts.name)}`);
            if (ts.length !== 0) bad.push(`Function.prototype.toString length=${ts.length}`);
            // A function EXPRESSION has an own `prototype`; a native function
            // and a method shorthand do not. One expression, and it cannot be
            // deleted after the fact.
            const own = Object.getOwnPropertyNames(ts).sort().join(',');
            if (own !== 'length,name') bad.push(`Function.prototype.toString ownProps=${own}`);
            // Calling it on a non-function throws, and the stack COUNTS THE
            // WRAPPERS: Chrome's builtin frame carries no source position,
            // every layer here does, which is what makes them countable.
            // Measured 3 frames against a clean browser's 1.
            try { ts.call({}); } catch (err) {
              const frames = String((err && err.stack) || '').split('\n')
                .filter(line => /^\s*at (?:[\w$]+\.)?toString \(<anonymous>:\d+:\d+\)$/.test(line));
              if (frames.length) bad.push(`Function.prototype.toString leaks ${frames.length} wrapper frame(s) in its error stack`);
            }
            // The chain must not swallow a page's OWN source: a wrapper that
            // answered "[native code]" for everything would break every
            // library that inspects a function, and be caught in one line.
            function harnessOwnFn(a, b) { return a + b; }
            if (!harnessOwnFn.toString().includes('return a + b')) bad.push('a page function no longer reports its own source');
          })();
          return bad;
        })(),
        // Canvas noise has to reach OffscreenCanvas, a SEPARATE interface from
        // HTMLCanvasElement whose 2d context has its own prototype. Measured
        // before it did: the same drawing came back noised through one and RAW
        // through the other, so a fingerprinter read the true canvas by using
        // OffscreenCanvas, and the disagreement was itself a one-line test that
        // a patch was present. '16px Arial' is deliberate -- a standard family
        // keeps fillText's font-normalisation branch out of the comparison.
        canvas: (() => {
          try {
            if (typeof OffscreenCanvas === 'undefined') return { available: false };
            const hash = (a) => { let h = 2166136261; for (let i = 0; i < a.length; i++) { h ^= a[i]; h = (h * 16777619) >>> 0; } return h.toString(16); };
            const ctxOf = (kind, w, h) => kind === 'html'
              ? (() => { const c = document.createElement('canvas'); c.width = w; c.height = h; return c.getContext('2d'); })()
              : new OffscreenCanvas(w, h).getContext('2d');
            // A solid mid-grey fill is uniform BEFORE noise, so every departure
            // from 0x80 is the noise and can be counted. 0x80 so a +/-1
            // perturbation cannot be lost to clamping at 0 or 255.
            //
            // Counting rather than just asking "did anything change" is the
            // point: the shipped noise was once a constant -1 on EVERY pixel
            // (a broken hash whose low bits were all rounded to zero), which
            // changes every pixel and so passes any did-anything-change test
            // while randomising nothing and being invertible by adding 1 back.
            // unchanged>0, both directions present, and nothing beyond +/-1 are
            // what separate real per-pixel noise from a blanket offset.
            const profile = (kind) => {
              const ctx = ctxOf(kind, 60, 20);
              ctx.fillStyle = '#808080'; ctx.fillRect(0, 0, 60, 20);
              const d = ctx.getImageData(0, 0, 60, 20).data;
              let unchanged = 0, up = 0, down = 0, other = 0;
              for (let i = 0; i < d.length; i += 4) {
                if (d[i] === 0x80) unchanged++;
                else if (d[i] === 0x81) up++;
                else if (d[i] === 0x7f) down++;
                else other++;
              }
              return { unchanged, up, down, other, total: d.length / 4 };
            };
            const draw = (ctx) => {
              ctx.fillStyle = '#808080'; ctx.fillRect(0, 0, 120, 40);
              ctx.fillStyle = '#069'; ctx.font = '16px Arial'; ctx.fillText('probe', 4, 30);
            };
            // A fresh canvas is fully transparent, and because a canvas stores
            // premultiplied alpha a real browser can only ever return 0,0,0,0
            // for such a pixel. Noise that touches R/G regardless of alpha
            // invents an impossible state -- measured at 17 of 400 pixels, and
            // bot.sannysoft.com's TRANSPARENT_PIXEL row caught it.
            let impossiblePixels = 0;
            {
              const t = document.createElement('canvas'); t.width = 40; t.height = 10;
              const td = t.getContext('2d').getImageData(0, 0, 40, 10).data;
              for (let i = 0; i < td.length; i += 4) {
                if (td[i + 3] === 0 && (td[i] || td[i + 1] || td[i + 2])) impossiblePixels++;
              }
            }

            // Two documents on the SAME host must get the same canvas. The
            // seed was once Math.random() per document, which only looked fine
            // while the noise hash was broken and the seed did nothing --
            // measured once it worked: a same-origin iframe and a reload each
            // produced a different fingerprint, which real Chrome never does.
            // The canvas is built inside the iframe's own document so it is the
            // IFRAME's patched prototype and its own seed being read, not this
            // document's.
            let crossDocument = 'n/a';
            try {
              const ifr = document.createElement('iframe');
              ifr.style.display = 'none';
              document.body.appendChild(ifr);
              const solidHash = (doc) => {
                const c = doc.createElement('canvas'); c.width = 60; c.height = 20;
                const cx = c.getContext('2d');
                cx.fillStyle = '#808080'; cx.fillRect(0, 0, 60, 20);
                return hash(cx.getImageData(0, 0, 60, 20).data);
              };
              const inFrame = solidHash(ifr.contentDocument);
              const inTop = solidHash(document);
              ifr.remove();
              crossDocument = inFrame === inTop ? 'agree' : 'differ';
            } catch (e) { crossDocument = 'error:' + e.name; }

            // Font normalisation: a non-standard family must be drawn AND
            // measured as if only the standard set were installed, generics must
            // be left alone, and ctx.font must still read back what the page set.
            const renderWith = (font) => {
              const ctx = ctxOf('html', 160, 30);
              ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, 160, 30);
              ctx.fillStyle = '#000000'; ctx.font = font; ctx.fillText('Handgloves 123', 2, 20);
              return hash(ctx.getImageData(0, 0, 160, 30).data);
            };
            const widthWith = (font) => {
              const ctx = ctxOf('html', 10, 10);
              ctx.font = font; return +ctx.measureText('Handgloves 123').width.toFixed(2);
            };
            const arialRender = renderWith('16px Arial');
            // Control: can this host tell two families apart at all? Measured
            // with TWO STANDARD families, which normalisation never rewrites --
            // so the control stays independent of everything it gates. Using
            // monospace here (the first attempt) made the control and the
            // generic-preservation assertion the same measurement, so breaking
            // generics turned the control false and gated its own check out:
            // the mutation passed clean.
            const fontsDiffer = renderWith('16px "Times New Roman"') !== arialRender;
            const font = {
              fontsDiffer,
              normalisedRender: renderWith('16px "DejaVu Sans Mono"') === arialRender,
              normalisedWidth: widthWith('16px "DejaVu Sans Mono"') === widthWith('16px Arial'),
              genericPreserved: renderWith('16px monospace') !== arialRender,
              leak: (() => {
                const ctx = ctxOf('html', 10, 10);
                const asked = '16px "DejaVu Sans Mono"';
                ctx.font = asked; ctx.fillText('x', 1, 1);
                return ctx.font !== asked;
              })(),
              // Function.name and Function.length are own properties, so a
              // wrapper assigned to a prototype slot reports name '' and its own
              // declared arity unless both are restored. Lengths are the spec
              // arities of these three methods.
              identity: [['fillText', 3], ['strokeText', 3], ['measureText', 1]]
                .filter(([n, len]) => {
                  const f = CanvasRenderingContext2D.prototype[n];
                  return !f || f.name !== n || f.length !== len;
                }).map(([n]) => n)
            };

            const hx = ctxOf('html', 120, 40); draw(hx);
            const ox = ctxOf('off', 120, 40); draw(ox);
            return {
              available: true,
              font,
              impossiblePixels,
              crossDocument,
              html: profile('html'),
              off: profile('off'),
              agree: hash(hx.getImageData(0, 0, 120, 40).data) === hash(ox.getImageData(0, 0, 120, 40).data),
              offWrapVisible: typeof OffscreenCanvasRenderingContext2D !== 'undefined'
                && !/\[native code\]/.test(String(OffscreenCanvasRenderingContext2D.prototype.getImageData))
            };
          } catch (e) { return { available: true, error: e.name }; }
        })()
      }));

      // The mousemove-timing wrapper's REGISTRATION bookkeeping, which no
      // amount of reading settles: that block replaces
      // EventTarget.prototype.addEventListener for every target in the
      // document, so a bug there leaks listeners for as long as the target
      // lives. One wrapper must serve each (target, listener, capture) triple,
      // because that is what lets the spec's own de-duplication and removal
      // keep working through it. Measured before the fix: 5 identical adds
      // produced 5 invocations, and 5000 adds of one handler to window plus
      // the matching remove left 4,999 live listeners, each firing (and
      // scheduling a setTimeout) on every mousemove.
      //
      // Every count is taken on an element this check OWNS, never document or
      // window: simulateHumanBehavior dispatches synthetic mousemove events at
      // those, which inflates any count taken there.
      const listenerIssues = await page.evaluate(async () => {
        const bad = [];
        // The wrapper defers by 0-2ms; 60 is clear of that without adding
        // seconds to the run across both fingerprint profiles.
        const settle = () => new Promise(r => setTimeout(r, 60));
        const el = document.createElement('div');
        document.body.appendChild(el);
        const fire = async (target) => {
          target.dispatchEvent(new MouseEvent('mousemove'));
          await settle();
        };

        // An identical (target, type, listener, capture) tuple added N times is
        // ONE listener, and one remove detaches it.
        let n = 0;
        const h = () => { n++; };
        for (let i = 0; i < 5; i++) el.addEventListener('mousemove', h);
        await fire(el);
        if (n !== 1) bad.push(`5 identical adds produced ${n} invocation(s), expected 1`);
        n = 0;
        el.removeEventListener('mousemove', h);
        await fire(el);
        if (n !== 0) bad.push(`${n} listener(s) still live after removeEventListener`);

        // ...and the wrapper still does its job: the call must be DEFERRED,
        // not synchronous, or the timing jitter the block exists for is gone.
        let ran = false;
        const h2 = () => { ran = true; };
        el.addEventListener('mousemove', h2);
        el.dispatchEvent(new MouseEvent('mousemove'));
        const immediate = ran;
        await settle();
        if (immediate) bad.push('mousemove listener ran synchronously — timing jitter not applied');
        if (!ran) bad.push('mousemove listener never ran');
        el.removeEventListener('mousemove', h2);

        // capture and bubble are SEPARATE registrations; removing one must not
        // take the other with it.
        let c = 0;
        const h3 = () => { c++; };
        el.addEventListener('mousemove', h3, true);
        el.addEventListener('mousemove', h3, false);
        c = 0; await fire(el);
        if (c !== 2) bad.push(`capture+bubble adds produced ${c} invocation(s), expected 2`);
        el.removeEventListener('mousemove', h3, false);
        c = 0; await fire(el);
        if (c !== 1) bad.push(`removing the bubble listener left ${c} invocation(s), expected 1`);
        el.removeEventListener('mousemove', h3, true);
        c = 0; await fire(el);
        if (c !== 0) bad.push(`${c} invocation(s) after both capture and bubble were removed`);

        // One handler on two targets — the ordinary drag pattern. Removing it
        // from each must detach both; a listener-keyed registry orphans the
        // first target's wrapper with nothing able to name it.
        let t = 0;
        const h4 = () => { t++; };
        const a = document.createElement('div');
        const b = document.createElement('div');
        document.body.appendChild(a);
        document.body.appendChild(b);
        a.addEventListener('mousemove', h4);
        b.addEventListener('mousemove', h4);
        b.removeEventListener('mousemove', h4);
        a.removeEventListener('mousemove', h4);
        t = 0;
        a.dispatchEvent(new MouseEvent('mousemove'));
        b.dispatchEvent(new MouseEvent('mousemove'));
        await settle();
        if (t !== 0) bad.push(`${t} invocation(s) after one handler on two targets was removed from both`);

        // An IMPLICIT removal is not observable from in here: `once` firing,
        // and an aborted `signal`, both detach the wrapper without telling the
        // registry, which is exactly why the browser has to be the thing that
        // de-duplicates. Re-adding the same handler must attach it again.
        let o = 0;
        const h5 = () => { o++; };
        el.addEventListener('mousemove', h5, { once: true });
        await fire(el);
        if (o !== 1) bad.push(`a {once:true} listener fired ${o} time(s), expected 1`);
        await fire(el);
        if (o !== 1) bad.push(`a {once:true} listener fired again after detaching (${o} total)`);
        el.addEventListener('mousemove', h5, { once: true });
        await fire(el);
        if (o !== 2) bad.push(`re-adding a fired {once:true} listener did not re-attach it (${o} total, expected 2)`);

        let s2 = 0;
        const h6 = () => { s2++; };
        const ac = new AbortController();
        el.addEventListener('mousemove', h6, { signal: ac.signal });
        ac.abort();
        await fire(el);
        if (s2 !== 0) bad.push(`an aborted signal left the listener attached (${s2} invocation(s))`);
        el.addEventListener('mousemove', h6);
        await fire(el);
        if (s2 !== 1) bad.push(`re-adding after an aborted signal did not attach (${s2} invocation(s), expected 1)`);
        el.removeEventListener('mousemove', h6);

        // The options dictionary must be read exactly ONCE per add. Reading
        // `capture` for the registry key and letting the native method read it
        // again ran a page's own getter twice, which is a one-expression probe
        // -- and a getter answering differently on the two reads would key the
        // registry on one value while registering the other. The ORDER is
        // pinned too, since a page's getter side effects are observable; it is
        // the dictionary's own (capture from EventListenerOptions, then
        // once/passive/signal), measured identical in a clean browser.
        const reads = { capture: 0, once: 0, passive: 0, signal: 0 };
        const order = [];
        el.addEventListener('mousemove', () => {}, {
          get capture() { reads.capture++; order.push('capture'); return false; },
          get once() { reads.once++; order.push('once'); return false; },
          get passive() { reads.passive++; order.push('passive'); return false; },
          get signal() { reads.signal++; order.push('signal'); return undefined; }
        });
        for (const k of Object.keys(reads)) {
          if (reads[k] !== 1) bad.push(`options.${k} was read ${reads[k]} time(s) on one add, expected 1`);
        }
        if (order.join(',') !== 'capture,once,passive,signal') {
          bad.push(`options members read in the order ${order.join(',') || '(none)'}, expected capture,once,passive,signal`);
        }

        el.remove(); a.remove(); b.remove();
        return bad;
      });

      // The WebGL context wrapper's IDENTITY and receiver handling. It
      // proxies every real context, so anything it gets wrong here is wrong
      // for every WebGL page: a fresh Proxy per getContext call and a fresh
      // bound function per property read made two strict-equality probes
      // false that are true in every browser, and reading through
      // Reflect.get with the proxy as receiver invoked native accessors with
      // the wrong `this`, so three ordinary property reads threw instead of
      // answering. Skipped when the browser has no WebGL at all, which is a
      // legitimate configuration rather than a failure.
      const glIssues = await page.evaluate(() => {
        const bad = [];
        const c = document.createElement('canvas');
        c.width = 300; c.height = 150;
        let g = null;
        try { g = c.getContext('webgl'); } catch (e) { bad.push(`getContext('webgl') threw ${e.name}`); return bad; }
        if (!g) return bad;

        // Identity: the same context object, and the same function object.
        if (c.getContext('webgl') !== c.getContext('webgl')) bad.push('getContext returns a different object each call');
        if (g.drawArrays !== g.drawArrays) bad.push('a context method returns a different function each read');
        if (g.getParameter !== g.getParameter) bad.push('getParameter returns a different function each read');

        // Reads that must answer rather than throw, with the real values.
        const read = (prop, expected) => {
          let v;
          try { v = g[prop]; } catch (e) { bad.push(`gl.${prop} threw ${e.name}: ${String(e.message).slice(0, 40)}`); return; }
          if (expected !== undefined && v !== expected) bad.push(`gl.${prop} = ${JSON.stringify(v)}, expected ${JSON.stringify(expected)}`);
        };
        read('drawingBufferWidth', 300);
        read('drawingBufferHeight', 150);
        let canvasProp;
        try { canvasProp = g.canvas; } catch (e) { bad.push(`gl.canvas threw ${e.name}`); }
        if (canvasProp !== undefined && canvasProp !== c) bad.push('gl.canvas is not the canvas it came from');

        // Names, which a bound function and an anonymous expression both get
        // wrong ('bound drawArrays' and '' respectively).
        if (g.drawArrays.name !== 'drawArrays') bad.push(`gl.drawArrays.name = ${JSON.stringify(g.drawArrays.name)}`);
        if (g.getParameter.name !== 'getParameter') bad.push(`gl.getParameter.name = ${JSON.stringify(g.getParameter.name)}`);
        if (!/\[native code\]/.test(String(g.drawArrays))) bad.push('gl.drawArrays does not report [native code]');

        // A canvas that already has a context answers null for an incompatible
        // type. Mocking that handed the page a truthy context whose methods
        // are all no-ops.
        const second = c.getContext('webgl2');
        if (second !== null) bad.push(`getContext('webgl2') after 'webgl' returned ${Object.prototype.toString.call(second)}, expected null`);

        // The context still has to work, and still has to carry the spoof.
        try {
          const buf = g.createBuffer();
          g.bindBuffer(g.ARRAY_BUFFER, buf);
        } catch (e) { bad.push(`an ordinary WebGL call threw ${e.name}`); }
        if (g.getParameter(37445) !== 'Google Inc. (ANGLE)' && g.getParameter(37445) !== null) {
          // only flag a value that is neither the spoof nor the clean answer
          bad.push(`UNMASKED_VENDOR_WEBGL = ${JSON.stringify(g.getParameter(37445))}`);
        }

        // The context must be the REAL one, not a wrapper. Three probes a
        // Proxy cannot pass, whatever its traps do: a native method called
        // through the prototype brand-checks its receiver, and the method a
        // context hands out IS the prototype's own function object.
        try {
          WebGLRenderingContext.prototype.isContextLost.call(g);
        } catch (e) {
          bad.push(`WebGLRenderingContext.prototype.isContextLost.call(gl) threw ${e.name} — the context is wrapped`);
        }
        if (g.drawArrays !== WebGLRenderingContext.prototype.drawArrays) {
          bad.push('gl.drawArrays is not the prototype\'s own function — the context is wrapped');
        }
        if (g.getParameter !== WebGLRenderingContext.prototype.getParameter) {
          bad.push('gl.getParameter is not the prototype\'s own function — the context is wrapped');
        }

        // The spoof's own methods must look native: a function EXPRESSION is a
        // constructor and carries an own `prototype`, so these read
        // length,name,prototype against a native method's length,name, and
        // `new gl.getParameter(1)` constructed where the native rejects it.
        for (const m of ['getParameter', 'getExtension', 'getSupportedExtensions']) {
          const fn = WebGLRenderingContext.prototype[m];
          const own = Object.getOwnPropertyNames(fn).sort().join(',');
          if (own !== 'length,name') bad.push(`${m} ownProps=${own}, expected length,name`);
          let constructed = false;
          try { new fn(); constructed = true; } catch (e) { /* native: not a constructor */ }
          if (constructed) bad.push(`new ${m}() constructed — a native method is not a constructor`);
        }

        // OffscreenCanvas contexts go through the same prototypes and must
        // answer these the SAME way. They used to differ, because only the
        // HTMLCanvasElement path was proxied, which let one page compare the
        // two and see the wrapper.
        if (typeof OffscreenCanvas === 'function') {
          let og = null;
          try { og = new OffscreenCanvas(300, 150).getContext('webgl'); } catch (e) { /* unsupported */ }
          if (og) {
            try {
              WebGLRenderingContext.prototype.isContextLost.call(og);
            } catch (e) {
              bad.push(`the same call on an OffscreenCanvas context threw ${e.name}`);
            }
            if (og.drawArrays !== WebGLRenderingContext.prototype.drawArrays) {
              bad.push('an OffscreenCanvas context does not hand out the prototype\'s own method');
            }
            // ...and the spoof has to reach it, including a parameter only the
            // prototype table carries (VERSION), which is what proved the old
            // per-context proxy was redundant.
            if (og.getParameter(37445) !== g.getParameter(37445)) {
              bad.push('OffscreenCanvas and HTMLCanvas disagree on UNMASKED_VENDOR_WEBGL');
            }
            if (og.getParameter(7936) !== g.getParameter(7936)) {
              bad.push('OffscreenCanvas and HTMLCanvas disagree on VERSION');
            }
            if (!/Chromium/.test(String(g.getParameter(7936)))) {
              bad.push(`VERSION = ${JSON.stringify(g.getParameter(7936))}, expected the spoofed Chromium string`);
            }
          }
        }
        return bad;
      });

      // ...and the registry must not RETAIN those handlers. An implicit removal
      // cannot be observed, so both levels of the registry are weak; a strong
      // map of listeners would hold every fired `once` handler for as long as
      // the target lives, which on window or document is the whole document.
      // Measured on a strong inner Map: 20,000 such handlers retained 3.81MB
      // after a forced GC against 0.01MB unspoofed, and 0 of 5000 were
      // collected. A FinalizationRegistry answers that directly, instead of
      // reading it off a heap delta that also carries the deferral's own
      // timers. The target is kept ALIVE on purpose -- the whole question is
      // whether a dead listener survives a live target. Threshold rather than
      // equality because GC progress is not contractual; the broken case
      // collects none at all, so there is no band to flake in.
      const gcIssues = await (async () => {
        const out = [];
        const N = 2000;
        await page.evaluate(async (n) => {
          window.__nwssGcTarget = document.createElement('div');
          document.body.appendChild(window.__nwssGcTarget);
          window.__nwssCollected = 0;
          window.__nwssFr = new FinalizationRegistry(() => { window.__nwssCollected++; });
          for (let i = 0; i < n; i++) {
            const h = () => {};
            window.__nwssFr.register(h);
            window.__nwssGcTarget.addEventListener('mousemove', h, { once: true });
          }
          window.__nwssGcTarget.dispatchEvent(new MouseEvent('mousemove'));
          await new Promise(r => setTimeout(r, 300));
        }, N);
        const cdp = await page.createCDPSession();
        try {
          for (let i = 0; i < 4; i++) await cdp.send('HeapProfiler.collectGarbage');
        } finally {
          await cdp.detach().catch(() => {});
        }
        const collected = await page.evaluate(async () => {
          await new Promise(r => setTimeout(r, 200));
          return window.__nwssCollected;
        });
        if (collected < N / 2) {
          out.push(`${N - collected} of ${N} detached mousemove listeners are still retained by the wrapper's registry`);
        }
        return out;
      })();

      const isFirefox = /Firefox\//.test(f.ua);
      const isSafari = /Version\/.*Safari/.test(f.ua) && !/Chrome\//.test(f.ua);
      const isChrome = /Chrome\//.test(f.ua);
      const uaOS = /Windows/.test(f.ua) ? 'Windows' : /Macintosh/.test(f.ua) ? 'Mac' : /Linux/.test(f.ua) ? 'Linux' : '?';
      const issues = [];

      // Chromium-only APIs must not survive a non-Chrome UA.
      if (!isChrome) {
        for (const [k, label] of [['chromeObj', 'window.chrome'], ['uaData', 'navigator.userAgentData'],
                                  ['perfMemory', 'performance.memory'], ['deviceMemory', 'navigator.deviceMemory'],
                                  ['connection', 'navigator.connection'], ['scheduling', 'navigator.scheduling']]) {
          if (f[k]) issues.push(`${label} present under a non-Chrome UA`);
        }
      }
      // Firefox-only props must be present for Firefox and absent elsewhere.
      if (isFirefox && !f.oscpu) issues.push('UA claims Firefox but navigator.oscpu is absent');
      if (isFirefox && !f.buildID) issues.push('UA claims Firefox but navigator.buildID is absent');
      if (!isFirefox && f.oscpu) issues.push('navigator.oscpu present but UA is not Firefox');
      // OS and vendor must track the UA.
      if (uaOS === 'Windows' && !/Win/.test(f.platform)) issues.push(`UA says Windows but platform=${f.platform}`);
      if (uaOS === 'Mac' && !/Mac/.test(f.platform)) issues.push(`UA says Mac but platform=${f.platform}`);
      // The Linux case was missing, and it is the one the fixed profile broke.
      if (uaOS === 'Linux' && !/Linux/.test(f.platform)) issues.push(`UA says Linux but platform=${f.platform}`);
      // navigator.platform against the UA-CH platform, which is now the
      // browser's own: these two disagreeing is a one-subtraction check.
      if (f.uaDataPlatform && uaOS === 'Linux' && f.uaDataPlatform !== 'Linux') issues.push(`UA says Linux but userAgentData.platform=${f.uaDataPlatform}`);
      if (f.uaDataPlatform && uaOS === 'Windows' && f.uaDataPlatform !== 'Windows') issues.push(`UA says Windows but userAgentData.platform=${f.uaDataPlatform}`);
      if (f.uaDataPlatform && uaOS === 'Mac' && f.uaDataPlatform !== 'macOS') issues.push(`UA says Mac but userAgentData.platform=${f.uaDataPlatform}`);
      if (isSafari && f.vendor !== 'Apple Computer, Inc.') issues.push(`UA claims Safari but vendor=${JSON.stringify(f.vendor)}`);
      // A PDF plugin with no PDF mime type (or the reverse) is incoherent.
      if (f.plugins > 0 && f.mimeTypes === 0) issues.push(`${f.plugins} plugins but 0 mimeTypes`);
      if (f.plugins === 0 && f.mimeTypes > 0) issues.push(`0 plugins but ${f.mimeTypes} mimeTypes`);
      // Type integrity of the collections, checked regardless of length.
      if (!f.pluginsIsPluginArray) issues.push('navigator.plugins is not a PluginArray');
      if (!f.mimeIsMimeTypeArray) issues.push('navigator.mimeTypes is not a MimeTypeArray');
      if (f.wrapIdentity && f.wrapIdentity.length) {
        issues.push(`wrapped method(s) report the wrong name/length: ${f.wrapIdentity.slice(0, 6).join('; ')}${f.wrapIdentity.length > 6 ? ` (+${f.wrapIdentity.length - 6} more)` : ''}`);
      }
      for (const li of listenerIssues) issues.push(`mousemove listener wrapper: ${li}`);
      for (const gi of gcIssues) issues.push(`mousemove listener wrapper: ${gi}`);
      for (const wi of glIssues) issues.push(`WebGL context wrapper: ${wi}`);
      // Canvas coherence. Three checks because none of them covers another,
      // both mutations verified: dropping the OffscreenCanvas wrap leaves that
      // path unnoised AND disagreeing, while giving it a SECOND, independent
      // noise implementation leaves it noised and still disagreeing -- which is
      // the drift the shared noiseImageData exists to prevent.
      if (f.canvas && f.canvas.available && !f.canvas.error) {
        for (const [kind, c] of [['HTMLCanvas', f.canvas.html], ['OffscreenCanvas', f.canvas.off]]) {
          if (c.up + c.down === 0) issues.push(`canvas noise is not reaching ${kind} getImageData`);
          else if (c.unchanged === 0) issues.push(`${kind} noise alters EVERY pixel — a blanket offset, not per-pixel noise`);
          else if (c.up === 0 || c.down === 0) issues.push(`${kind} noise moves pixels one way only (up=${c.up} down=${c.down})`);
          if (c.other > 0) issues.push(`${kind} noise moved ${c.other} pixel(s) by more than +/-1`);
          // The RATE, not just the shape. The gate selects 2 of 16 pixels and a
          // third of those draw a 0 shift, so ~8.3% of pixels move; at n=1200
          // this band sits about 7 sigma out, so it cannot flake. Added because
          // a mutation that broke only the GATE (every pixel selected, shifts
          // still distributed) passed every check above -- unchanged>0 was
          // satisfied by the zero-shift third rather than by the gate.
          const movedPct = (c.up + c.down) * 100 / c.total;
          if (c.up + c.down > 0 && (movedPct < 2 || movedPct > 20)) {
            issues.push(`${kind} noise moved ${movedPct.toFixed(1)}% of pixels, expected ~8% (12.5% selected, a third of them by 0)`);
          }
        }
        if (!f.canvas.agree) issues.push('HTMLCanvas and OffscreenCanvas return different pixels for the same drawing');
        if (f.canvas.font) {
          const fo = f.canvas.font;
          if (fo.fontsDiffer) {
            if (!fo.normalisedRender) issues.push('a non-standard font is drawn as itself — canvas font normalisation is not reaching fillText');
            if (!fo.normalisedWidth) issues.push('measureText reports a non-standard font\'s own metrics while fillText draws another font');
            if (!fo.genericPreserved) issues.push('a CSS generic family (monospace) is being rewritten to Arial');
          }
          if (fo.leak) issues.push('ctx.font does not read back what the page set — the font substitution is visible to the page');
          if (fo.identity.length) issues.push(`wrapped text method(s) report the wrong name/length: ${fo.identity.join(', ')}`);
        }
        if (f.canvas.impossiblePixels > 0) {
          issues.push(`${f.canvas.impossiblePixels} fully transparent pixel(s) returned non-zero RGB — premultiplied alpha makes that impossible in a real canvas`);
        }
        if (f.canvas.crossDocument === 'differ') {
          issues.push('canvas fingerprint differs between two documents on the same host — a per-document seed, so a reload or a same-origin iframe sees a different canvas');
        }
        if (f.canvas.offWrapVisible) issues.push('OffscreenCanvas getImageData wrapper is not masked as [native code]');
      } else if (f.canvas && f.canvas.error) {
        issues.push(`canvas coherence check could not run: ${f.canvas.error}`);
      }

      collected.push({ name: `self-consistency (fp=${fpProfile})`, url: 'about:blank', ok: true, durationMs: 0,
        result: { passed: issues.length === 0 ? 1 : 0, failed: issues.length, warn: 0,
                  total: 1, failures: issues, warnings: [] } });
      if (FORMAT !== 'json') {
        console.log(`\nself-consistency (--ua=${UA_FLAG}, fingerprint_protection=${fpProfile}): ${issues.length === 0 ? 'OK' : issues.length + ' issue(s)'}`);
        issues.forEach(i => console.log(`  - ${i}`));
      }
    } catch (err) {
      collected.push({ name: `self-consistency (fp=${fpProfile})`, url: 'about:blank', ok: false, durationMs: 0, error: err.message });
    } finally {
      try { await page.close(); } catch (_) {}
    }
  }

  try {
    for (const target of targetsToRun) {
      const page = await browser.newPage();
      const started = Date.now();
      try {
        if (!NO_SPOOF) {
          // Apply the same spoofing stack nwss.js uses for real scans.
          await applyAllFingerprintSpoofing(page,
            { userAgent: UA_FLAG, fingerprint_protection: 'random' },
            false,
            target.url
          );
        }
        await page.goto(target.url, { waitUntil: 'networkidle2', timeout: 60000 });
        const result = await target.extract(page);
        collected.push({ name: target.name, url: target.url, ok: true, durationMs: Date.now() - started, result });
        if (FORMAT === 'text') console.log(formatResult(target, result));
      } catch (err) {
        collected.push({ name: target.name, url: target.url, ok: false, durationMs: Date.now() - started, error: err.message });
        if (FORMAT === 'text') {
          console.error(`\n=== ${target.name} (${target.url}) ===`);
          console.error(`  ERROR: ${err.message}`);
        }
      } finally {
        await page.close().catch(() => {});
      }
    }
  } finally {
    await browser.close().catch(() => {});
  }

  if (FORMAT === 'json') {
    // Single object, not NDJSON — easier to diff with `jq` or `diff` between
    // before/after runs. Schema is stable: top-level config + targets[].
    process.stdout.write(JSON.stringify({
      config: { spoof: !NO_SPOOF, ua: UA_FLAG, headful: HEADFUL, noSandbox: process.env.PUPPETEER_NO_SANDBOX === '1' },
      targets: collected
    }, null, 2) + '\n');
  }
})().catch(err => {
  console.error('test-stealth fatal:', err);
  process.exit(1);
});
