#!/usr/bin/env node
/**
 * The whois path in lib/nettools.js: that it runs at all, how many attempts it
 * makes, and that --dry-run reports the number the run will really use.
 *
 * Each check drives createNetToolsHandler with a fake `whois` on PATH (execFile
 * resolves through PATH), so the attempt count is read from what the subprocess
 * was actually invoked with rather than inferred.
 *
 * Why these exist:
 *
 *   - createNetToolsHandler destructured `siteConfig` with no default while the
 *     whois branch read siteConfig.whois_max_retries unconditionally, so a
 *     caller that omitted it got `Cannot read properties of undefined` -- and
 *     the handler's catch logged that at debug level only, so whois silently did
 *     nothing on a normal run. nwss always passes one, which is why it stayed
 *     hidden; the dig branch only touches siteConfig inside a forceDebug guard.
 *   - whois_max_retries defaulted to 3 in the live retryOptions while README,
 *     nwss.1, --help AND the --dry-run report all said 2. An unconfigured site
 *     made 50% more attempts than documented, and --dry-run reported a number
 *     the run would not use. Both readers now share one constant.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { createNetToolsHandler } = require('../lib/nettools');

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

// A whois that fails immediately. Paired with whois_retry_on_error, that makes
// the retry ladder observable without waiting out real timeouts (the timeout
// path is 8s/12s/18s by design and is measured separately, not here).
const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-whoisshim-'));
const callLog = path.join(shimDir, 'calls.log');
fs.writeFileSync(path.join(shimDir, 'whois'), `#!/bin/sh
printf '%s\\n' "$*" >> ${callLog}
exit 1
`, { mode: 0o755 });
// dig answers instantly so nothing here touches the network.
fs.writeFileSync(path.join(shimDir, 'dig'), `#!/bin/sh
printf ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\\n;; ANSWER SECTION:\\nx.\\t300\\tIN\\tA\\t127.0.0.1\\n'
`, { mode: 0o755 });
process.env.PATH = shimDir + path.delimiter + process.env.PATH;

let caseNo = 0;
async function whoisCalls(config = {}, { capture = false } = {}) {
  fs.writeFileSync(callLog, '');
  const lines = [];
  const realLog = console.log;
  const realWarn = console.warn;
  if (capture) {
    console.log = (...a) => lines.push(a.join(' '));
    console.warn = (...a) => lines.push('WARN ' + a.join(' '));
  }
  const handler = createNetToolsHandler(Object.assign({
    whoisTerms: ['no-such-term'],
    whoisDelay: 0,                       // no progressive delay: attempt count is the subject
    processedWhoisDomains: new Set(),
    processedDigDomains: new Set()
  }, config));
  const name = `w${++caseNo}.example.test`;
  try {
    await handler(name, name);
  } finally {
    if (capture) { console.log = realLog; console.warn = realWarn; }
  }
  const calls = fs.readFileSync(callLog, 'utf8').trim().split('\n').filter(Boolean);
  return { calls, logs: lines.map(l => l.replace(/\x1b\[[0-9;]*m/g, '')) };
}

(async () => {
  // 1. The regression that hid everything else: no siteConfig at all.
  let r = await whoisCalls({ siteConfig: undefined });
  check('whois runs when the caller passes no siteConfig', r.calls.length > 0,
    `${r.calls.length} invocation(s)`);

  // 2. Documented default: 2 attempts per server, not 3.
  r = await whoisCalls({ siteConfig: { whois_retry_on_error: true } });
  check('an unconfigured site retries to the documented 2 attempts', r.calls.length === 2,
    `${r.calls.length} invocation(s): ${JSON.stringify(r.calls)}`);

  // 3. An explicit setting still wins.
  r = await whoisCalls({ siteConfig: { whois_max_retries: 4, whois_retry_on_error: true } });
  check('whois_max_retries is honoured', r.calls.length === 4, `${r.calls.length} invocation(s)`);

  // 4. Default is one attempt when a non-timeout error shouldn't be retried
  //    (whois_retry_on_error defaults to false).
  r = await whoisCalls({ siteConfig: {} });
  check('a non-timeout failure does not retry by default', r.calls.length === 1,
    `${r.calls.length} invocation(s)`);

  // 5. --dry-run must report the count the run would really use.
  r = await whoisCalls({ siteConfig: { whois_retry_on_error: true }, forceDebug: true, dryRunCallback: () => {} }, { capture: true });
  const reported = (r.logs.find(l => l.includes('Max retries:')) || '').match(/Max retries: (\d+)/);
  check('the dry-run report matches the attempts actually made',
    !!reported && Number(reported[1]) === r.calls.length,
    `reported ${reported ? reported[1] : 'nothing'}, made ${r.calls.length}`);

  // 6. An unexpected throw is no longer debug-only.
  const exploding = new Proxy({}, { get(_, prop) { if (prop === 'whois_max_retries') throw new Error('boom'); return undefined; } });
  r = await whoisCalls({ siteConfig: exploding }, { capture: true });
  check('an unexpected error is reported without --debug',
    r.logs.some(l => l.startsWith('WARN') && l.includes('Unexpected error processing')),
    r.logs.filter(l => l.startsWith('WARN')).join(' | ') || 'nothing warned');

  fs.rmSync(shimDir, { recursive: true, force: true });
  console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error('harness error:', e); process.exit(2); });
