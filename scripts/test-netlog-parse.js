#!/usr/bin/env node
/**
 * test-netlog-parse.js — pins how lib/netlog.js reads a Chrome net-log.
 *
 * Every check here is a shape that a real capture actually has and that a
 * reasonable-looking parser gets wrong. They were all found by parsing real
 * logs, not by reading the format docs:
 *  - the events array's "]" is APPENDED to the last event line (which can be
 *    110KB), not written on its own line, and a "polledData" section follows it
 *  - a killed browser leaves the array unterminated, so JSON.parse returns
 *    nothing for the whole file
 *  - request_type is too coarse to be a resourceType
 *
 * Fixtures are generated here rather than committed: a real net-log is 10-30MB,
 * and the parser's job is structural, so a small synthetic log with the same
 * structure exercises it exactly as well.
 *
 *   node scripts/test-netlog-parse.js          # <1s, no browser, no network
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseNetLog } = require('../lib/netlog');

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`); }
};

const EV = { REQUEST_ALIVE: 1, URL_REQUEST_START_JOB: 2, HTTP_TRANSACTION_READ_RESPONSE_HEADERS: 3, CORS_REQUEST: 4 };
const CONSTANTS = {
  logEventTypes: EV,
  logSourceType: { URL_REQUEST: 1, SOCKET: 2 },
  netError: { ERR_BLOCKED_BY_CLIENT: -20, ERR_FAILED: -2, ERR_CACHE_MISS: -400 },
  clientInfo: { name: 'TestChrome' }
};

const ev = (type, id, params, phase = 0, srcType = 1) =>
  JSON.stringify({ params, phase, source: { id, start_time: '1', type: srcType }, time: '1', type });

/** One request's worth of events. */
function request({ id, url, dest, mime, status, netError, initiator }) {
  const out = [];
  if (dest) out.push(ev(EV.CORS_REQUEST, id, { request_headers: { headers: [`Sec-Fetch-Dest: ${dest}`, 'Accept: */*'] } }, 1));
  out.push(ev(EV.REQUEST_ALIVE, id, { url, priority: 'LOW' }, 1));
  out.push(ev(EV.URL_REQUEST_START_JOB, id, { url, method: 'GET', request_type: 'other', initiator: initiator || '' }, 1));
  if (status !== undefined) {
    out.push(ev(EV.HTTP_TRANSACTION_READ_RESPONSE_HEADERS, id,
      { headers: [`HTTP/1.1 ${status}`, `content-type: ${mime || 'text/plain'}`] }, 0));
  }
  if (netError !== undefined) out.push(ev(EV.REQUEST_ALIVE, id, { net_error: netError }, 2));
  return out;
}

/**
 * Assemble a net-log with the real file's structure: constants on line 1,
 * "events": [ on line 2, one event per line, and the array's bracket appended
 * to the LAST event line followed by a polledData section.
 */
function writeLog(file, eventLines, { truncate = false } = {}) {
  const head = `{"constants":${JSON.stringify(CONSTANTS)},\n"events": [\n`;
  let body;
  if (truncate) {
    // A killed browser: last line cut mid-object, no bracket, no polledData.
    body = eventLines.join(',\n') + ',\n' + '{"params":{"url":"https://cut.exa';
  } else {
    body = eventLines.slice(0, -1).map(l => l + ',').join('\n') +
      (eventLines.length > 1 ? '\n' : '') +
      eventLines[eventLines.length - 1] + '],\n' +
      '"polledData": {"sockets":{"a":[1,2]},"note":"ends with a bracket too"}\n}\n';
  }
  fs.writeFileSync(file, head + body);
  return file;
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-netlog-'));
const F = n => path.join(dir, n);

console.log('\nnet-log parsing\n');

// ---- a complete log -------------------------------------------------------
const events = [
  ...request({ id: 1, url: 'https://site.example/', dest: 'document', mime: 'text/html', status: 200 }),
  ...request({ id: 2, url: 'https://cdn.site.example/app.js', dest: 'script', mime: 'application/javascript', status: 200, initiator: 'https://site.example' }),
  ...request({ id: 3, url: 'https://img.other.example/pixel.png', dest: 'image', mime: 'image/png', status: 200 }),
  // no Sec-Fetch-Dest: type must fall back to the response mime type
  ...request({ id: 4, url: 'https://x.other.example/a.css', mime: 'text/css', status: 200 }),
  // a network-level failure
  ...request({ id: 5, url: 'https://dead.example/x.js', dest: 'script', netError: -2 }),
  // non-http must be dropped entirely
  ...request({ id: 6, url: 'data:text/plain,hello', dest: 'other', status: 200 }),
  // an event on a non-URL_REQUEST source must be ignored
  ev(EV.REQUEST_ALIVE, 99, { url: 'https://socket.example/nope' }, 1, 2),
  // A server may send anything it likes as a RESPONSE header, including one
  // named like a request header. It must not be read as the request's own
  // Sec-Fetch-Dest: this request has no request-side dest, so the type has to
  // come from the mime type (script), never from the response's "image".
  ev(EV.REQUEST_ALIVE, 7, { url: 'https://liar.example/x.js' }, 1),
  ev(EV.URL_REQUEST_START_JOB, 7, { url: 'https://liar.example/x.js', method: 'GET' }, 1),
  ev(EV.HTTP_TRANSACTION_READ_RESPONSE_HEADERS, 7,
    { headers: ['HTTP/1.1 200', 'content-type: application/javascript', 'Sec-Fetch-Dest: image'] }, 0),
  // THE LAST LINE carries the events array's "]" -- so it must belong to a
  // request the checks below assert on, or the bracket-suffix handling is
  // never exercised. (It originally landed on the ignored socket event, and a
  // parser that only handles a trailing "," passed the whole suite.)
  ev(EV.REQUEST_ALIVE, 7, { net_error: -20 }, 2)
];
const clean = writeLog(F('clean.json'), events);
const r = parseNetLog(clean);

check('complete log is not reported truncated', r.truncated, false);
check('creator names the log source', /net-log/.test(r.creator), true);
check('non-http entries dropped (data: URL)', r.entries.some(e => /^data:/.test(e.url)), false);
check('events on other source types ignored', r.entries.some(e => e.host === 'socket.example'), false);
check('request count', r.entries.length, 6);
check('page is the document request', r.pageUrl, 'https://site.example/');

const byHost = Object.fromEntries(r.entries.map(e => [e.host, e]));
check('Sec-Fetch-Dest script -> script', byHost['cdn.site.example'].resourceType, 'script');
check('Sec-Fetch-Dest image -> image', byHost['img.other.example'].resourceType, 'image');
check('mime fallback when no Sec-Fetch-Dest', byHost['x.other.example'].resourceType, 'stylesheet');
check('response status parsed', byHost['cdn.site.example'].status, 200);
check('registrable domain, not host', byHost['img.other.example'].rootDomain, 'other.example');
check('initiator kept', byHost['cdn.site.example'].initiator, 'https://site.example');
check('net_error -> failed', byHost['dead.example'].failed, true);
check('net_error -> name, not number', byHost['dead.example'].netError, 'ERR_FAILED');
check('successful request is not failed', byHost['cdn.site.example'].failed, false);

// A response header must never be read as a request Sec-Fetch-Dest.
check('response headers do not supply the type', byHost['liar.example'].resourceType, 'script');

// ---- the last event, which carries the array bracket ----------------------
// The final line ends "}]," not "},", and it is this request's end phase, so a
// parser that only strips a trailing comma loses the net_error below.
check('last event line (carrying "],") is parsed', byHost['liar.example'].netError, 'ERR_BLOCKED_BY_CLIENT');
check('and a content blocker on it reads as blocked', byHost['liar.example'].blocked, true);

// ---- a truncated log ------------------------------------------------------
const cut = writeLog(F('cut.json'), events, { truncate: true });
let strictParseWorks = true;
try { JSON.parse(fs.readFileSync(cut, 'utf8')); } catch { strictParseWorks = false; }
check('truncated log defeats JSON.parse (the reason for streaming)', strictParseWorks, false);

const rc = parseNetLog(cut);
check('truncated log still parses', rc.entries.length > 0, true);
check('truncated log is reported truncated', rc.truncated, true);
check('truncated log recovers every complete request', rc.entries.length, 6);

// ---- a file that is not a net-log -----------------------------------------
const notLog = F('nope.json');
fs.writeFileSync(notLog, JSON.stringify({ log: { entries: [] } }));
let threw = '';
try { parseNetLog(notLog); } catch (e) { threw = e.message; }
check('a HAR is rejected with a useful message', /net-log|constants/.test(threw), true);

// ---- an empty / zero-length file ------------------------------------------
const empty = F('empty.json');
fs.writeFileSync(empty, '');
let threw2 = '';
try { parseNetLog(empty); } catch (e) { threw2 = e.message; }
check('empty file is rejected, not crashed on', /net-log|constants/.test(threw2), true);

fs.rmSync(dir, { recursive: true, force: true });

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
