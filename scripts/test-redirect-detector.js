#!/usr/bin/env node
/**
 * That the injected JS-redirect detector installs its watcher once per document.
 *
 * navigateWithRedirectHandling adds the detector with
 * page.evaluateOnNewDocument on every call, and nwss.js calls it up to three
 * times for one page: the initial navigation, an options fallback, and a
 * resolved-URL retry. evaluateOnNewDocument does not replace a previous script
 * — measured, three installs run three times per document — and this puppeteer
 * returns no handle to remove one, so the de-duplication has to happen inside
 * the injected script.
 *
 * Without that guard each document on a page that needed the fallback or retry
 * carried two or three MutationObservers on <head>, doing identical work:
 * measured 1 / 2 / 3 observers across three navigations, versus 1 / 1 / 1 with
 * the guard in place.
 *
 * The count is read by wrapping window.MutationObserver from a script installed
 * BEFORE the detector, so it counts real constructions rather than trusting the
 * guard's own sentinel.
 */

const http = require('http');
const puppeteer = require('puppeteer');
const { navigateWithRedirectHandling } = require('../lib/redirect');

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};
const fmt = (level, msg) => `[${level}] ${msg}`;

(async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    if (req.url.startsWith('/landed')) return res.end('<html><body>landed</body></html>');
    // /meta carries a refresh that fires inside the poll budget; /x does not
    if (req.url.startsWith('/meta')) {
      return res.end('<html><head><meta http-equiv="refresh" content="2;url=/landed"></head><body>go</body></html>');
    }
    res.end('<html><head><title>t</title></head><body>redirect detector fixture</body></html>');
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/x`;

  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.evaluateOnNewDocument(() => {
    const Real = window.MutationObserver;
    window.__moCount = 0;
    window.MutationObserver = class extends Real {
      constructor(cb) { super(cb); window.__moCount++; }
    };
  });

  const counts = [];
  try {
    for (let i = 0; i < 3; i++) {
      // 300ms deliberately, shorter than the 2s meta refresh used below: the
      // de-duplicated observer belongs to the FIRST script installed, and each
      // script closes over its own budget, so a stale 300 here would reject the
      // later 2000ms refresh as unable-to-fire. That is the bug this ordering
      // exists to catch.
      await navigateWithRedirectHandling(page, url, { js_redirect_timeout: 300 },
        { waitUntil: 'domcontentloaded', timeout: 8000 }, false, fmt);
      counts.push(await page.evaluate(() => window.__moCount));
    }
    check('the detector installs one observer per document however often it is added',
      counts.every(c => c === 1),
      `observers after each of 3 navigations: ${counts.join(', ')} (1, 2, 3 = the script accumulating)`);
    check('the guard sentinel is set in the page',
      (await page.evaluate(() => window.__nwssMetaRefreshWatch)) === true);

    // Behaviour, not counts. De-duplicating the observer means the copy that
    // installs it is the FIRST one, and each copy closes over the maxWaitMs of
    // the call that installed it -- so a naive guard freezes the first call's
    // budget for every later navigation on that page. Measured when this check
    // was first written: /x navigations at 300ms followed by a 2s meta refresh at
    // 3000ms produced detected=false on all three attempts, and the page never
    // followed the refresh. The budget therefore lives on window and every copy
    // updates it; this asserts that end to end.
    const metaCounts = [];
    for (let i = 0; i < 3; i++) {
      const logged = [];
      const collect = (level, msg) => { logged.push(`[${level}] ${msg}`); return ''; };
      const r = await navigateWithRedirectHandling(page, `${url.replace(/\/x$/, '')}/meta`,
        { js_redirect_timeout: 3000 }, { waitUntil: 'domcontentloaded', timeout: 9000 }, true, collect);
      metaCounts.push({
        landed: /\/landed/.test((r && r.finalUrl) || ''),
        fired: logged.some(l => /JS redirect detected|meta\.refresh/i.test(l))
      });
    }
    check('detection uses the CURRENT call budget, not the first script\'s',
      metaCounts.every(m => m.fired && m.landed),
      metaCounts.map((m, i) => `#${i + 1} fired=${m.fired} landed=${m.landed}`).join(', '));
  } finally {
    await browser.close();
    server.close();
  }

  console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error('harness error:', e); process.exit(2); });
