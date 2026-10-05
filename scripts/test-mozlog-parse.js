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

const P = (level, text, origin = 'Parent 75652: Main Thread') =>
  `2026-10-05 04:05:29.235000 UTC - [${origin}]: ${level}/nsHttp ${text}`;

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

// Child mode for the retention check above: parse the given file, force a
// collection, and print the heap still held.
if (process.env.NWSS_MEMCHILD && process.argv[2] === '--memcheck') {
  const target = process.argv[3];
  if (global.gc) global.gc();
  const before = process.memoryUsage().heapUsed;
  const parsed = parseMozLog(target);
  if (global.gc) global.gc();
  const after = process.memoryUsage().heapUsed;
  if (!parsed.entries.length) { console.log('NaN'); process.exit(0); }
  console.log(((after - before) / 1048576).toFixed(2));
  process.exit(0);
}

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

// ---- interleaved threads must not truncate a request block ----------------
// The log is multi-threaded and interleaves LINE BY LINE: a socket thread's
// connection dump ("] idle conns [") lands inside the main thread's
// "http request [" block. Treating any "]" as the block's end truncated it
// before Sec-Fetch-Dest, so on a busy capture every request came back typed
// "other" -- including the top-level document, which made the page look like
// whatever Firefox happened to fetch first (a Mozilla cert-chain URL, in the
// real capture that exposed this). Quiet captures do not interleave and hid it.
const SOCK = 'Parent 75652: Socket Thread';
const interleaved = [
  P('E', 'uri=https://interleaved.test/'),
  P('E', 'http request ['),
  P('E', '  GET / HTTP/1.1'),
  P('V', 'active conns [', SOCK),             // other thread opens a bracket
  P('E', '  Host: interleaved.test'),
  P('V', '] idle conns [', SOCK),             // ...and closes one, mid-block
  P('V', ']', SOCK),                          // a BARE "]" -- exactly what the
                                              // real connection dump emits, and
                                              // what a thread-blind parser takes
                                              // as the end of the request block
  P('V', 'TlsHandshaker::SetupSSL 25a9 caps=0x1200911', SOCK),
  P('E', '  Sec-Fetch-Dest: document'),       // only reached if the block survived
  P('E', '  Accept: text/html'),
  P('E', ']')
];
const il = parseMozLog(write(F('interleaved.log.moz_log'), interleaved, '\r\n'));
const ilEntry = il.entries.find(e => e.host === 'interleaved.test');
check('a request block survives another thread interleaving a "]"',
  ilEntry ? ilEntry.resourceType : '(missing)', 'document');
check('and the page is identified from it', il.pageUrl, 'https://interleaved.test/');

// Two content processes fetch at the same time, so two request blocks are open
// at once and their lines alternate. Each must collect its OWN headers -- a
// parser that keeps "the" open block gives one of them the other's type.
const C1 = 'Child 101: Main Thread', C2 = 'Child 202: Main Thread';
const concurrent = [
  P('E', 'uri=https://one.test/a.css', C1),
  P('E', 'uri=https://two.test/b.png', C2),
  P('E', 'http request [', C1),
  P('E', 'http request [', C2),
  P('E', '  GET /a.css HTTP/1.1', C1),
  P('E', '  GET /b.png HTTP/1.1', C2),
  P('E', '  Host: two.test', C2),
  P('E', '  Host: one.test', C1),
  P('E', '  Sec-Fetch-Dest: image', C2),
  P('E', '  Sec-Fetch-Dest: style', C1),
  P('E', ']', C2),
  P('E', ']', C1)
];
const cc = parseMozLog(write(F('concurrent.log.moz_log'), concurrent, '\r\n'));
const byH = Object.fromEntries(cc.entries.map(e => [e.host, e.resourceType]));
check('concurrent blocks do not cross-contaminate (1)', byH['one.test'], 'stylesheet');
check('concurrent blocks do not cross-contaminate (2)', byH['two.test'], 'image');

// ---- a DIRECTORY is one run, not every run in it --------------------------
// Each capture is timestamped so runs never overwrite each other, so a
// directory holds several. Reading them all merged separate page loads into one
// result -- two real runs of 350 and 288 requests came back as 498.
const runDir = F('runs');
fs.mkdirSync(runDir);
const mk = (name, hosts) => {
  const file = path.join(runDir, name);
  write(file, hosts.flatMap(h => [
    P('E', `uri=https://${h}/x.js`),
    ...requestBlock('GET', '/x.js', h, 'script')
  ]), '\r\n');
  return file;
};
const oldRun = mk('ff-000000-000000.log.moz_log', ['old-run.invalid']);
mk('ff-111111-111111.log.moz_log', ['new-run.invalid']);
mk('ff-111111-111111.log.child-2.moz_log', ['new-run-child.invalid']);
const past = new Date(Date.now() - 60000);
fs.utimesSync(oldRun, past, past);

const dirHosts = parseMozLog(runDir).entries.map(e => e.host);
check('directory picks the newest run', dirHosts.includes('new-run.invalid'), true);
check('directory does NOT merge an older run', dirHosts.includes('old-run.invalid'), false);
check("that run's own child log is included", dirHosts.includes('new-run-child.invalid'), true);

// ---- retained strings must not pin the chunk they came from ---------------
// V8 keeps a substring as a SlicedString holding a reference to its parent, so
// retaining one 40-character url out of a 4MB read chunk pins the whole 4MB.
// Measured on a real 49MB capture before lib/mozlog.js flattened them: 43.8MB
// of heap retained for 350 entries, 187MB RSS. This runs in a child with
// --expose-gc, because retention is only observable after a forced collection.
if (!process.env.NWSS_MEMCHILD) {
  const padLine = P('V', 'nsHttpConnectionMgr ' + 'x'.repeat(2000));
  const lines = [];
  for (let i = 0; i < 6000; i++) lines.push(padLine);      // ~12MB of noise
  lines.push(P('E', 'uri=https://retained.test/a.js'));
  lines.push(...requestBlock('GET', '/a.js', 'retained.test', 'script'));
  const bigFile = write(F('big.log.moz_log'), lines, '\r\n');

  const res = require('child_process').spawnSync(
    process.execPath, ['--expose-gc', __filename, '--memcheck', bigFile],
    { encoding: 'utf8', env: { ...process.env, NWSS_MEMCHILD: '1' } });
  const retainedMb = parseFloat((res.stdout || '').trim());
  // The parsed data is a handful of short strings; anything near the file size
  // means a chunk is still pinned.
  check(`retained heap stays small (${isNaN(retainedMb) ? '?' : retainedMb.toFixed(1)}MB for a 12MB log)`,
    !isNaN(retainedMb) && retainedMb < 2, true);
}

// ---- a file that is not a MOZ_LOG ----------------------------------------
const notLog = F('nope.json');
fs.writeFileSync(notLog, JSON.stringify({ log: { entries: [] } }));
let threw = '';
try { parseMozLog(notLog); } catch (e) { threw = e.message; }
check('a HAR is rejected with a useful message', /nsHttp|MOZ_LOG/.test(threw), true);

fs.rmSync(dir, { recursive: true, force: true });

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
