#!/usr/bin/env node
/**
 * What `dig` is actually told to query, for a given --dns spec.
 *
 * `--dns` feeds three consumers: the DNS pre-check (lib/dns.js), nettools' dig,
 * and Chrome's DoH mapping. lib/dns.js deliberately accepts an address WITH a
 * port -- `8.8.8.8:5353`, `[2001:db8::1]:5353`, the form Resolver.setServers()
 * understands -- and the pre-check queries that port. nettools used to strip it
 * and invoke `dig @8.8.8.8`, so one flag pointed the two paths at DIFFERENT
 * servers. Measured before the fix with a UDP listener on 127.0.0.1:5353 and
 * `--dns 127.0.0.1:5353`: 7 pre-check queries arrived there, while dig ran as
 * `dig @127.0.0.1 +tcp +time=3 +tries=2 lvh.me A` -- port 53. Silent, and
 * exactly wrong for a split-DNS/dnsmasq-on-5353 setup.
 *
 * These checks read the real argv by putting a fake `dig` on PATH (execFile
 * resolves through PATH), so they assert what the subprocess is invoked with
 * rather than what the parser returns.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { createNetToolsHandler, setDigResolvers } = require('../lib/nettools');

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

// A fake dig: records its argv, then prints a minimal NOERROR answer so the
// lookup succeeds on the first attempt and the ladder stops there.
const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-digshim-'));
const argvLog = path.join(shimDir, 'argv.log');
fs.writeFileSync(path.join(shimDir, 'dig'), `#!/bin/sh
printf '%s\\n' "$*" >> ${argvLog}
cat <<'OUT'
; <<>> DiG fake <<>>
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; ANSWER SECTION:
example.test.\t300\tIN\tA\t127.0.0.1

OUT
`, { mode: 0o755 });
process.env.PATH = shimDir + path.delimiter + process.env.PATH;

let caseNo = 0;
async function digArgvFor(spec) {
  fs.writeFileSync(argvLog, '');
  setDigResolvers(spec === null ? [] : [spec]);
  const handler = createNetToolsHandler({
    digTerms: ['127.0.0.1'],
    processedDigDomains: new Set(),
    processedWhoisDomains: new Set()
  });
  // A fresh domain per case: the dig cache is global and keyed by domain+type.
  await handler(`case${++caseNo}.example.test`, `case${caseNo}.example.test`);
  return fs.readFileSync(argvLog, 'utf8').trim().split('\n').filter(Boolean);
}

(async () => {
  let argv = await digArgvFor('127.0.0.1:5353');
  check('an ip:port spec passes -p to dig',
    argv.length > 0 && argv[0].includes('@127.0.0.1') && / -p 5353( |$)/.test(argv[0]),
    JSON.stringify(argv[0] || '(no dig invocation)'));

  argv = await digArgvFor('8.8.8.8');
  check('a bare ip passes no -p', argv.length > 0 && argv[0].includes('@8.8.8.8') && !argv[0].includes('-p'),
    JSON.stringify(argv[0] || '(none)'));

  argv = await digArgvFor('[2001:db8::1]:5353');
  check('a bracketed IPv6 spec keeps address and port',
    argv.length > 0 && argv[0].includes('@2001:db8::1') && / -p 5353( |$)/.test(argv[0]),
    JSON.stringify(argv[0] || '(none)'));

  argv = await digArgvFor('[2001:db8::1]');
  check('a bracketed IPv6 spec without a port passes no -p',
    argv.length > 0 && argv[0].includes('@2001:db8::1') && !argv[0].includes('-p'),
    JSON.stringify(argv[0] || '(none)'));

  // lib/dns.js validates only \d{1,5}, so :0 and :99999 can reach nettools. A
  // bad -p makes dig fail outright, so they fall back to the default port.
  for (const bad of ['127.0.0.1:0', '127.0.0.1:99999']) {
    argv = await digArgvFor(bad);
    check(`an out-of-range port (${bad.split(':')[1]}) is ignored, not passed`,
      argv.length > 0 && argv[0].includes('@127.0.0.1') && !argv[0].includes('-p'),
      JSON.stringify(argv[0] || '(none)'));
  }

  argv = await digArgvFor(null);
  check('no --dns means no @server and no -p',
    argv.length > 0 && !argv[0].includes('@') && !argv[0].includes('-p'),
    JSON.stringify(argv[0] || '(none)'));

  fs.rmSync(shimDir, { recursive: true, force: true });
  console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error('harness error:', e); process.exit(2); });
