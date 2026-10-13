#!/usr/bin/env node
/**
 * --dns port validation in lib/dns.js (isResolverSpec / parseDnsServers).
 *
 * An out-of-range port is not merely useless -- it reaches c-ares through
 * Resolver.setServers(), which does not validate it:
 *
 *   `--dns 8.8.8.8:0`      ABORTED the process. c-ares_wrap.cc's SetServers
 *                          fails `Assertion failed: portValue->Int32Value(...)
 *                          .FromJust()` -- a native CHECK, so the try/catch
 *                          around setServers() in lib/dns.js never saw it.
 *                          Measured: `node nwss.js --dns 8.8.8.8:0 --help`
 *                          exited 134, "core dumped", at module load.
 *   `--dns 8.8.8.8:99999`  silently wrapped mod 65536 to 8.8.8.8:34463. No
 *                          throw, no warning; every pre-check then queried a
 *                          dead port, timed out, burned 2x the timeout on the
 *                          retry and tripped the circuit breaker.
 *
 * The validation admitted any `\d{1,5}`. lib/nettools.js's digSpecPort() had
 * already range-checked the port before handing it to dig's `-p` -- added for
 * this exact looseness, but it only protected the dig half of one --dns flag.
 *
 * The abort check runs in a CHILD PROCESS and asserts the exit code, because a
 * native abort cannot be caught in-process: a unit test of parseDnsServers
 * alone would still pass if someone re-loosened the regex while leaving the
 * spec check intact.
 */

const { execFileSync } = require('child_process');
const path = require('path');
const { parseDnsServers, createRotatingResolver } = require('../lib/dns');

let checks = 0;
let failures = 0;
let finished = false;
function check(name, cond, detail) {
  checks++;
  if (cond) { console.log(`  ok   ${name}`); return; }
  failures++;
  console.log(`  FAIL ${name}${detail ? ` -- ${detail}` : ''}`);
}

// A truncated run must not look like a passing one.
process.on('exit', (code) => {
  if (!finished && code === 0) {
    console.error('\nharness exited before finishing -- treating as failure');
    process.exitCode = 2;
  }
});

// Silence the expected "ignoring invalid server" warnings.
const realWarn = console.warn;
function quiet(fn) {
  console.warn = () => {};
  try { return fn(); } finally { console.warn = realWarn; }
}

console.log('--dns specs that must be DROPPED (out-of-range port)');
for (const spec of ['8.8.8.8:0', '8.8.8.8:65536', '8.8.8.8:99999', '8.8.8.8:123456',
                    '[2001:db8::1]:0', '[2001:db8::1]:99999']) {
  const out = quiet(() => parseDnsServers(spec));
  check(`drops ${spec}`, out.length === 0, `got ${JSON.stringify(out)}`);
}

console.log('\n--dns specs that must still be ACCEPTED (no regression)');
for (const spec of ['8.8.8.8', '9.9.9.9:53', '8.8.8.8:5353', '8.8.8.8:1', '8.8.8.8:65535',
                    '127.0.0.1:5353', '[2001:db8::1]', '[2001:db8::1]:5353',
                    '2001:4860:4860::8888']) {
  const out = quiet(() => parseDnsServers(spec));
  check(`keeps ${spec}`, out.length === 1 && out[0] === spec, `got ${JSON.stringify(out)}`);
}

console.log('\nmixed list keeps the good entries and drops only the bad one');
{
  const out = quiet(() => parseDnsServers('1.1.1.1,8.8.8.8:0,9.9.9.9:5353'));
  check('1.1.1.1,8.8.8.8:0,9.9.9.9:5353 -> 2 servers',
    out.length === 2 && out[0] === '1.1.1.1' && out[1] === '9.9.9.9:5353', `got ${JSON.stringify(out)}`);
}

console.log('\nan in-range port survives all the way into the resolver pool');
{
  // Guards the other direction: validation must not strip or rewrite the port
  // it accepts, or the pre-check would quietly query :53 instead.
  const servers = parseDnsServers('127.0.0.1:5353');
  const r = createRotatingResolver({ servers });
  check('pinned + rotating with the port intact',
    r.pinned === true && r.rotates === true && r.servers.join(',') === '127.0.0.1:5353',
    JSON.stringify({ pinned: r.pinned, rotates: r.rotates, servers: r.servers }));
}

console.log('\nthe parse -> createRotatingResolver path does not abort the process');
{
  // Exactly what nwss.js does: parseDnsServers(--dns value) straight into
  // createRotatingResolver, which calls setServers() on the pool.
  // The spec is INTERPOLATED into the child, not passed as an argv tail: with
  // `node -e <script> <arg>` the arg lands at process.argv[1], not [2]. Read
  // from [2] it was undefined, parseDnsServers(undefined) returned [], and both
  // checks passed against the pre-fix module -- a test that pinned nothing.
  // The child echoes the spec back so a future slip can't vacuum these again.
  const dnsPath = JSON.stringify(path.join(__dirname, '..', 'lib', 'dns.js'));
  for (const spec of ['8.8.8.8:0', '8.8.8.8:99999']) {
    const script = `
      const { parseDnsServers, createRotatingResolver } = require(${dnsPath});
      console.warn = () => {};
      const spec = ${JSON.stringify(spec)};
      const r = createRotatingResolver({ servers: parseDnsServers(spec) });
      process.stdout.write(JSON.stringify({ spec, pinned: r.pinned, servers: r.servers }));
    `;
    let status = 0;
    let stdout = '';
    try {
      stdout = execFileSync(process.execPath, ['-e', script], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      status = e.status == null ? 'signal ' + e.signal : e.status;
      stdout = (e.stdout || '') + (e.stderr || '');
    }
    const detail = `status=${status} out=${JSON.stringify(stdout.slice(0, 200))}`;
    check(`--dns ${spec} exits cleanly (was 134 / core dumped)`, status === 0, detail);
    let parsed = null;
    try { parsed = JSON.parse(stdout); } catch { /* aborted before writing */ }
    check(`--dns ${spec} actually reached the child`, parsed != null && parsed.spec === spec, detail);
    check(`--dns ${spec} falls back to system DNS, unpinned`,
      parsed != null && parsed.pinned === false && parsed.servers.every(srv => srv !== spec), detail);
  }
}

finished = true;
console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
