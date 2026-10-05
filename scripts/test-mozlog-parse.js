#!/usr/bin/env node
/**
 * test-mozlog-parse.js — pins how lib/mozlog.js reads a Firefox MOZ_LOG.
 *
 * The check that matters most is the CRLF one. Captures are produced by a
 * Windows browser and are CRLF, and in a JavaScript regex \r is a LINE
 * TERMINATOR, so "." does not match it: a pattern as ordinary as /foo (.*)$/
 * matches NOTHING on such a file. That is not a hypothetical -- the first
 * version of this parser returned 0 requests from a 424MB log that plainly
 * contained the text, and every regex tested fine against a hand-typed copy of
 * the same line without its \r.
 *
 *   node scripts/test-mozlog-parse.js         # <1s, no browser, no network
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseMozLog } = require('../lib/mozlog');

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`); }
};

const P = (level, text) => `2026-10-05 04:05:29.235000 UTC - [Parent 75652: Main Thread]: ${level}/nsHttp ${text}`;

/** The self-contained "http request [" block Firefox writes at nsHttp:5. */
function requestBlock(method, pathAndQuery, host, dest) {
  const lines = [P('E', 'http request ['), P('E', `  ${method} ${pathAndQuery} HTTP/1.1`), P('E', `  Host: ${host}`)];
  if (dest) lines.push(P('E', `  Sec-Fetch-Dest: ${dest}`));
  lines.push(P('E', '  Accept: */*'), P('E', '  '), P('E', ']'));
  return lines;
}

const LINES = [
  P('V', 'nsHttpAuthCache::nsHttpAuthCache 2693801f130'),
  P('E', 'uri=https://site.example/'),
  ...requestBlock('GET', '/', 'site.example', 'document'),
  P('E', 'uri=https://cdn.site.example/app.js'),
  ...requestBlock('GET', '/app.js', 'cdn.site.example', 'script'),
  P('E', 'uri=https://img.other.example/p.png'),
  ...requestBlock('GET', '/p.png', 'img.other.example', 'image'),
  // a request with no block (cancelled, or served from cache) -> type unknown
  P('E', 'uri=https://blocked.example/ads.js'),
  // the same URL again: must not be counted twice
  P('E', 'uri=https://cdn.site.example/app.js'),
  // trailing log punctuation is not part of the URL
  P('D', "redirect to uri=https://moved.example/x.js'"),
  // a non-http scheme must be ignored
  P('E', 'uri=about:blank'),
  P('V', 'nsHttpConnectionMgr::AddTransaction [trans=2693ef48b10 0]')
];

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-mozlog-'));
const F = n => path.join(dir, n);
const write = (file, lines, eol) => { fs.writeFileSync(file, lines.join(eol) + eol); return file; };

console.log('\nMOZ_LOG parsing\n');

// ---- CRLF, which is what a Windows Firefox actually writes ---------------
// Parsed inside a try so the headline regression reports itself by name: with
// the \r left on, no line matches, the parser concludes the file is not a
// MOZ_LOG at all and throws -- an opaque stack trace for the one failure this
// suite exists to catch.
let crlf = { entries: [], pageUrl: '' };
try {
  crlf = parseMozLog(write(F('crlf.log.moz_log'), LINES, '\r\n'));
} catch (e) {
  check(`CRLF capture parses (threw: ${e.message.slice(0, 60)})`, false, true);
}
check('CRLF capture yields requests at all', crlf.entries.length > 0, true);
check('CRLF request count', crlf.entries.length, 5);

// ---- LF, so the reader is not CRLF-only ----------------------------------
const lf = parseMozLog(write(F('lf.log.moz_log'), LINES, '\n'));
check('LF capture parses identically', lf.entries.map(e => e.url), crlf.entries.map(e => e.url));

const byHost = Object.fromEntries(crlf.entries.map(e => [e.host, e]));
// Every lookup below would otherwise read off undefined and crash rather than
// report, which is the same opacity problem one level down.
const at = h => byHost[h] || { resourceType: '(missing)', rootDomain: '(missing)', url: '(missing)', blocked: false };
check('duplicate URLs collapse', crlf.entries.filter(e => e.url === 'https://cdn.site.example/app.js').length, 1);
check('non-http schemes dropped', crlf.entries.some(e => /^about:/.test(e.url)), false);
check('trailing quote stripped from URL', at('moved.example').url, 'https://moved.example/x.js');

// ---- types come from the request block, joined on host+path ---------------
check('Sec-Fetch-Dest script -> script', at('cdn.site.example').resourceType, 'script');
check('Sec-Fetch-Dest image -> image', at('img.other.example').resourceType, 'image');
check('document type recognised', at('site.example').resourceType, 'document');
check('no request block -> other, not a wrong type', at('blocked.example').resourceType, 'other');
check('page is the document request', crlf.pageUrl, 'https://site.example/');
check('registrable domain, not host', at('img.other.example').rootDomain, 'other.example');

// Nothing is claimed blocked from this source -- the log cannot distinguish.
check('nothing is marked blocked', crlf.entries.some(e => e.blocked), false);

// ---- per-process sibling logs --------------------------------------------
const main = write(F('multi.log.moz_log'), LINES, '\r\n');
write(F('multi.log.child-3.moz_log'), [
  P('E', 'uri=https://child.example/from-content-process.js'),
  ...requestBlock('GET', '/from-content-process.js', 'child.example', 'script')
], '\r\n');
const multi = parseMozLog(main);
const child = multi.entries.find(e => e.host === 'child.example');
check('sibling child-N logs are read too', Boolean(child), true);
check('and typed from their own blocks', child ? child.resourceType : '(missing)', 'script');

// ---- a file that is not a MOZ_LOG ----------------------------------------
const notLog = F('nope.json');
fs.writeFileSync(notLog, JSON.stringify({ log: { entries: [] } }));
let threw = '';
try { parseMozLog(notLog); } catch (e) { threw = e.message; }
check('a HAR is rejected with a useful message', /nsHttp|MOZ_LOG/.test(threw), true);

fs.rmSync(dir, { recursive: true, force: true });

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
