#!/usr/bin/env node
/**
 * lib/openvpn_vpn.js — config handling and teardown contract.
 *
 * The module had no test, and it runs `sudo openvpn` as a long-lived root
 * daemon that owns the host's default route. Its worst failure is silent:
 * a teardown that does not actually kill anything.
 *
 * Two defects, both found by review:
 *
 *   1. stopConnection reported success unconditionally. It ignored both pkill
 *      results, re-checked nothing after the `pkill -9` escalation, then
 *      deleted the activeConnections entry and returned { success: true }. A
 *      failed kill therefore left a root openvpn alive with the tunnel
 *      carrying all traffic, while nwss reported it torn down and discarded
 *      the only record — so disconnectAll could not retry, and its `errors`
 *      array could never fill because result.error was never set. The
 *      escalation is now verified, the entry is retained on failure, and the
 *      verdict is honest.
 *
 *   2. The three `sudo pkill` calls lacked -n. spawnSync wires stdin to a
 *      pipe, so a password prompt blocks until the 3 s timeout and then fails
 *      silently — feeding straight into defect 1. The realistic trigger is not
 *      a cold prompt but sudo's credential timestamp expiring between connect
 *      and teardown on a long scan. The long-running `spawn('sudo', openvpn)`
 *      is deliberately NOT changed: its stdio is ['ignore','ignore','ignore'],
 *      so sudo reads EOF and fails fast already.
 *
 * SCOPE, so the count is not mistaken for more than it is: the teardown
 * behaviour itself is NOT exercised here. Reaching it needs an entry in the
 * module-private activeConnections, which only a real `sudo openvpn` bringup
 * creates. What is pinned behaviourally is the exported config surface; the
 * teardown contract is pinned at the source level, which is what would have
 * caught both defects.
 *
 * No sudo, no openvpn, no network, no root.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const ovpn = require('../lib/openvpn_vpn.js');

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};
const eq = (name, got, want) =>
  check(name, JSON.stringify(got) === JSON.stringify(want),
    `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-ovpntest-'));
const conf = path.join(dir, 'us-east.ovpn');
fs.writeFileSync(conf, 'client\ndev tun\nremote 1.2.3.4 1194\n');
const v = c => ovpn.validateOvpnConfig(ovpn.normalizeOvpnConfig(c));

console.log('\n--- 1. connection naming');
eq('a .ovpn path yields its basename', ovpn.resolveConnectionName({ config: conf }), 'us-east');
eq('a path without .ovpn yields the same name',
  ovpn.resolveConnectionName({ config: path.join(dir, 'us-east') }), 'us-east');
eq('an explicit name wins for an inline config',
  ovpn.resolveConnectionName({ config_inline: 'client\n', name: 'custom' }), 'custom');
const inlineName = ovpn.resolveConnectionName({ config_inline: 'client\ndev tun\n' });
check('an unnamed inline config gets a stable derived name',
  inlineName === ovpn.resolveConnectionName({ config_inline: 'client\ndev tun\n' }), inlineName);
// pkillPattern interpolates the name, and stopConnection refuses to pkill a
// name outside this charset rather than risk matching unrelated processes.
check('a derived name stays inside the pkill-safe charset',
  /^[a-zA-Z0-9_.-]{1,64}$/.test(inlineName), inlineName);

console.log('\n--- 2. config validation');
check('an existing .ovpn validates', v({ config: conf }).isValid === true);
check('a path without the .ovpn extension validates (connect resolves it too)',
  v({ config: path.join(dir, 'us-east') }).isValid === true);
check('a missing config is rejected', v({ config: path.join(dir, 'nope') }).isValid === false);
check('neither config nor config_inline is rejected', v({}).isValid === false);

console.log('\n--- 3. extra_args denylist (root code-exec directives)');
for (const bad of [['--up', '/bin/sh'], ['--script-security=2'], ['--plugin', 'x.so'],
                   ['--config', '/other.ovpn'], ['--iproute', '/bin/sh'], ['--writepid', '/etc/x']]) {
  check(`extra_args ${JSON.stringify(bad[0])} is refused`,
    v({ config: conf, extra_args: bad }).isValid === false);
}
check('a benign extra_arg is allowed', v({ config: conf, extra_args: ['--mute', '20'] }).isValid === true);

console.log('\n--- 4. teardown of an unknown connection is a no-op, not a lie');
eq('stopConnection on a name never started',
  ovpn.stopConnection('never-started'), { success: true, alreadyDown: true });
eq('nothing is tracked in a fresh process', ovpn.getActiveConnections(), []);

console.log('\n--- 5. teardown contract (source-level: needs a real root daemon otherwise)');
const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'openvpn_vpn.js'), 'utf8');
const sudoSync = src.match(/spawnSync\('sudo',\s*\[[^\]]*\]/g) || [];
check('all three sudo pkill calls exist', sudoSync.length === 3, `found ${sudoSync.length}`);
for (const call of sudoSync) {
  check(`sudo pkill passes -n: ${call.slice(0, 44)}…`, /\[\s*'-n'/.test(call));
}
// The long-running bringup needs no -n: stdio 'ignore' makes sudo read EOF.
check("the openvpn spawn keeps stdio 'ignore' (why it needs no -n)",
  /spawn\('sudo',\s*\['openvpn'[\s\S]{0,120}stdio:\s*\['ignore',\s*'ignore',\s*'ignore'\]/.test(src));

const stop = src.slice(src.indexOf('function stopConnection'), src.indexOf('function waitForProcessExit'));
// The verdict must come from the kill PATTERN, not from info.pid: that is
// child.pid, i.e. the sudo process, and sudo's own cmdline matches the pattern
// too, so sudo exiting first while openvpn is slower to handle SIGTERM would
// read as a successful kill.
check('stopConnection judges by the process pattern, twice',
  (stop.match(/isConnectionProcessRunning\(/g) || []).length === 2,
  `${(stop.match(/isConnectionProcessRunning\(/g) || []).length} call(s)`);
check('waitForProcessExit is only a settle, never assigned to the verdict',
  !/killed\s*=\s*waitForProcessExit/.test(stop));
check('stopConnection can report failure', /success:\s*false/.test(stop));
check('the tracking entry is retained when the kill is unverified',
  stop.indexOf('return { success: false') < stop.indexOf('activeConnections.delete'),
  'the failure return must come before the delete');

console.log('\n--- 6. the detection the verdict rests on, for real');
// NOTE: run this file as `node scripts/test-openvpn-config.js`. The pattern is
// `openvpn.*<name>`, and pgrep matches ANY process whose argv contains both --
// including an ancestor of this one. Invoking via `node -e` or a heredoc puts
// the script text in a parent's cmdline and every probe below comes back true.
// That is not a flaw in the check; it is why the check drops our own pid, and
// it is worth knowing before debugging a surprising result here.
{
  const { spawn } = require('child_process');
  const NAME = 'nwss' + 'parityprobe';
  // bash's `exec -a` sets argv[0], so the child's cmdline looks like a real run.
  const child = spawn('bash', ['-c', `exec -a 'openvpn --config /tmp/${NAME}.ovpn' sleep 20`],
    { stdio: 'ignore' });
  const settle = ms => { const t = Date.now(); while (Date.now() - t < ms) { /* spin */ } };
  settle(400);
  check('a live matching process is seen', ovpn.isConnectionProcessRunning(NAME) === true);
  check('an unrelated connection name is not seen',
    ovpn.isConnectionProcessRunning('nwss' + 'nosuchconn') === false);
  try { process.kill(child.pid, 'SIGKILL'); } catch { /* already gone */ }
  settle(500);
  check('the process is not seen once it is killed',
    ovpn.isConnectionProcessRunning(NAME) === false);
  check('an unsafe name is refused rather than passed to pgrep',
    ovpn.isConnectionProcessRunning('bad name!') === false);

  // NOT tested: the self-pid exclusion inside isConnectionProcessRunning.
  // Exercising it needs an ancestor whose argv matches `openvpn.*<name>`, and
  // whether one does depends entirely on how this file was invoked — directly,
  // from the suite loop, or through a wrapper. A check written against it
  // passed under the loop and failed when run by hand, so it is left out
  // rather than shipped flaky. The exclusion errs safe in any case: without
  // it the probe over-reports, which makes stopConnection keep the entry and
  // say so, never the reverse.
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${failures === 0 ? '✅' : '❌'} ${checks - failures} passed, ${failures} failed\n`);
process.exit(failures === 0 ? 0 : 1);
