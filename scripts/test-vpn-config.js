#!/usr/bin/env node
/**
 * lib/wireguard_vpn.js config handling.
 *
 * The module had no test at all, which matters more here than elsewhere: it
 * runs `sudo wg-quick` against the host's routing table, needs root, and its
 * failure modes are slow and confusing rather than loud. Everything below is
 * pure config handling -- no sudo, no wg-quick, no network, no root.
 *
 * Two defects, both found by review:
 *
 *   1. sudo blocked instead of failing. spawnSync wires stdin to a pipe, so a
 *      password prompt had nothing to read and sat until the 15s timeout, then
 *      surfaced as ETIMEDOUT -- three times over with the default max_retries,
 *      roughly 49 seconds to report the wrong cause. `sudo -n` exits at once
 *      and stderr carries the real reason. Asserted at the source level, since
 *      reproducing it needs a host whose sudo actually prompts.
 *
 *   2. validateVpnConfig accepted a config spelling connectForSite could not
 *      resolve. Validation tried the path as given, path + '.conf', and
 *      /etc/wireguard/path.conf; the connector only expanded a bare name with
 *      no slash. So `config: "/home/me/wg0"` with the file at
 *      /home/me/wg0.conf validated clean and then ran `wg-quick up` against a
 *      path that does not exist. Both now call resolveConfigPath.
 *
 * The normalize and interface-name cases pin fixes the module's own comments
 * record, so a regression shows up here rather than in a tunnel that will not
 * come up.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const wg = require('../lib/wireguard_vpn.js');

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

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-wgtest-'));
const conf = path.join(dir, 'myvpn.conf');
fs.writeFileSync(conf, '[Interface]\nPrivateKey=deadbeef\n[Peer]\nEndpoint=1.2.3.4:51820\n');

console.log('\n--- 1. one resolver for validate and connect');
eq('an exact path resolves to itself', wg.resolveConfigPath(conf), conf);
// The divergence: this spelling validated clean and then failed at wg-quick.
eq('a path with no .conf resolves to the .conf', wg.resolveConfigPath(path.join(dir, 'myvpn')), conf);
eq('a missing absolute path resolves to null', wg.resolveConfigPath(path.join(dir, 'nope')), null);
eq('a missing bare name resolves to null', wg.resolveConfigPath('nwss-no-such-interface'), null);
eq('a non-string is rejected, not thrown on', wg.resolveConfigPath(null), null);
// An absolute path must not be probed under /etc/wireguard, where it could
// only ever form nonsense like /etc/wireguard//tmp/x.conf.
eq('an absolute path is not probed under /etc/wireguard',
  wg.resolveConfigPath('/definitely/not/here'), null);

// Precedence, not just existence: a bare name is wg-quick's spelling for
// /etc/wireguard/<name>.conf, and that must be probed BEFORE a same-named file
// in the working directory. Asserted by recording the probe order, since
// /etc/wireguard is not writable from a test.
{
  const realExists = fs.existsSync;
  const probed = [];
  fs.existsSync = (p) => { probed.push(String(p)); return false; };
  try { wg.resolveConfigPath('wg0'); } finally { fs.existsSync = realExists; }
  eq('a bare name probes /etc/wireguard first', probed[0], '/etc/wireguard/wg0.conf');
  check('a bare name still falls back to the raw value', probed.includes('wg0'),
    JSON.stringify(probed));

  const probed2 = [];
  fs.existsSync = (p) => { probed2.push(String(p)); return false; };
  try { wg.resolveConfigPath('/abs/wg0'); } finally { fs.existsSync = realExists; }
  eq('an absolute path probes itself first', probed2[0], '/abs/wg0');
  check('an absolute path never probes /etc/wireguard',
    !probed2.some(x => x.startsWith('/etc/wireguard')), JSON.stringify(probed2));

  const probed3 = [];
  fs.existsSync = (p) => { probed3.push(String(p)); return false; };
  try { wg.resolveConfigPath('clients/alice'); } finally { fs.existsSync = realExists; }
  check('a relative path WITH a slash still reaches /etc/wireguard last',
    probed3[probed3.length - 1] === '/etc/wireguard/clients/alice.conf', JSON.stringify(probed3));
}

console.log('\n--- 2. validation agrees with what the connector can resolve');
const v = n => wg.validateVpnConfig(wg.normalizeVpnConfig(n));
check('the .conf-less path now validates AND resolves',
  v({ config: path.join(dir, 'myvpn') }).isValid === true &&
  wg.resolveConfigPath(path.join(dir, 'myvpn')) !== null);
check('a missing config is rejected', v({ config: path.join(dir, 'nope') }).isValid === false);
check('neither config nor config_inline is rejected', v({}).isValid === false);
check('inline config missing [Peer] is rejected',
  v({ config_inline: '[Interface]\nPrivateKey=x\n' }).isValid === false);
check('a complete inline config is accepted',
  v({ config_inline: '[Interface]\nPrivateKey=x\n[Peer]\nEndpoint=1.2.3.4:1\n' }).isValid === true);

console.log('\n--- 3. interface names stay inside IFNAMSIZ and path-safe');
check('a 16-char interface name is rejected (IFNAMSIZ is 15)',
  v({ config: conf, interface: 'a'.repeat(16) }).isValid === false);
check('a 15-char interface name is accepted',
  v({ config: conf, interface: 'a'.repeat(15) }).isValid === true);
check('a traversal attempt in the interface name is rejected',
  v({ config: conf, interface: '../../etc/x' }).isValid === false);

// wg-quick names the interface after the CONFIG FILE, so an explicit
// `interface` alongside a file config cannot take effect -- tracking that name
// made ip link show / ping -I target a device that never existed and the
// health check fail on every attempt.
check('interface + file config warns that the file wins',
  v({ config: conf, interface: 'custom' }).warnings.some(w =>
    w.includes('"interface" is ignored') && w.includes('myvpn') && w.includes('custom')),
  JSON.stringify(v({ config: conf, interface: 'custom' }).warnings));
check('interface alone with an inline config does NOT warn',
  !v({ config_inline: '[Interface]\nPrivateKey=x\n[Peer]\nEndpoint=1.2.3.4:1\n', interface: 'custom' })
    .warnings.some(w => w.includes('"interface" is ignored')));

// The name that gets TRACKED, which must be the one wg-quick actually creates.
const INLINE = '[Interface]\nPrivateKey=x\n[Peer]\nEndpoint=1.2.3.4:1\n';
eq('a file config names the interface after the file, even with `interface` set',
  wg.resolveInterfaceName({ config: '/etc/wireguard/wg0.conf', interface: 'custom' }), 'wg0');
eq('a file config without .conf still yields the basename',
  wg.resolveInterfaceName({ config: '/home/me/wg0' }), 'wg0');
eq('an inline config DOES honour `interface` (it names the temp file)',
  wg.resolveInterfaceName({ config_inline: INLINE, interface: 'custom' }), 'custom');
check('an inline config with no name is stable across calls',
  wg.resolveInterfaceName({ config_inline: INLINE }) === wg.resolveInterfaceName({ config_inline: INLINE }),
  wg.resolveInterfaceName({ config_inline: INLINE }));
check('the derived inline name fits IFNAMSIZ',
  wg.resolveInterfaceName({ config_inline: INLINE }).length <= 15,
  String(wg.resolveInterfaceName({ config_inline: INLINE }).length));

console.log('\n--- 4. max_retries coercion (its own comment records the "31 attempts" bug)');
eq('an absent max_retries defaults to 2', wg.normalizeVpnConfig({ config: conf }).max_retries, 2);
eq('an explicit 0 is honoured, not treated as falsy',
  wg.normalizeVpnConfig({ config: conf, max_retries: 0 }).max_retries, 0);
eq('the string "3" is refused, not concatenated',
  wg.normalizeVpnConfig({ config: conf, max_retries: '3' }).max_retries, 2);
eq('a negative is refused', wg.normalizeVpnConfig({ config: conf, max_retries: -1 }).max_retries, 2);
eq('a string shorthand becomes a config path',
  wg.normalizeVpnConfig('/etc/wireguard/wg0.conf').config, '/etc/wireguard/wg0.conf');

console.log('\n--- 5. sudo is invoked non-interactively (source-level)');
// Not reproducible without a host whose sudo prompts, so this guards the flag
// itself: every sudo call must carry -n or the 15s-per-attempt hang returns.
const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'wireguard_vpn.js'), 'utf8');
const sudoCalls = src.match(/spawnSync\('sudo',\s*\[[^\]]*\]/g) || [];
check('both sudo call sites exist', sudoCalls.length === 2, `found ${sudoCalls.length}`);
for (const call of sudoCalls) {
  check(`sudo call passes -n: ${call.slice(0, 46)}…`, /\[\s*'-n'/.test(call));
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${failures === 0 ? '✅' : '❌'} ${checks - failures} passed, ${failures} failed\n`);
process.exit(failures === 0 ? 0 : 1);
