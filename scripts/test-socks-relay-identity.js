#!/usr/bin/env node
/**
 * What makes two SOCKS5 upstreams the same relay.
 *
 * Chromium cannot authenticate to a SOCKS proxy, so an authenticated socks5
 * upstream is served by a local no-auth relay that does the upstream auth. The
 * relay is reused per upstream identity — and that identity used to be
 * host:port:username, leaving the PASSWORD out. Measured before the fix: the
 * same user with passAAA and passBBB both got relay port 40789, so the second
 * site's traffic authenticated as the first's credentials, silently. Two ways
 * that bites in practice: credentials rotated for some sites but not others, and
 * providers that encode a session token in the password with a constant
 * username, where per-site rotation collapses onto the first session.
 *
 * The password is hashed into the key rather than stored, and stats report a
 * `display` field (host:port) instead of stripping the key's last segment —
 * otherwise adding the hash would have started leaking the username into stats
 * output that previously hid it.
 *
 * No network: ensureRelay binds a local listener; the upstream is never dialled.
 */

const { parseProxyUrl, prepareSocksRelays } = require('../lib/proxy');
const { ensureRelay, getRelayPort, getRelayStats, closeAllRelays, upstreamKey } = require('../lib/socks-relay');

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

(async () => {
  const same = parseProxyUrl('socks5://user1:passAAA@10.0.0.9:1080');
  const otherPass = parseProxyUrl('socks5://user1:passBBB@10.0.0.9:1080');
  const otherUser = parseProxyUrl('socks5://user2:passAAA@10.0.0.9:1080');
  const dupe = parseProxyUrl('socks5://user1:passAAA@10.0.0.9:1080');

  try {
    for (const u of [same, otherPass, otherUser, dupe]) await ensureRelay(u, false);

    const pSame = getRelayPort(same);
    const pOtherPass = getRelayPort(otherPass);
    const pOtherUser = getRelayPort(otherUser);
    const pDupe = getRelayPort(dupe);

    check('a different password gets its own relay',
      pSame && pOtherPass && pSame !== pOtherPass,
      `passAAA -> ${pSame}, passBBB -> ${pOtherPass}`);
    check('a different username still gets its own relay',
      pOtherUser && pOtherUser !== pSame && pOtherUser !== pOtherPass,
      `user2 -> ${pOtherUser}`);
    check('identical credentials still share one relay (dedup intact)',
      pDupe === pSame, `${pDupe} vs ${pSame}`);
    check('the identity function agrees with the reuse behaviour',
      upstreamKey(same) === upstreamKey(dupe) && upstreamKey(same) !== upstreamKey(otherPass));

    // Neither credential may appear in the key, nor in what stats report.
    const key = upstreamKey(same);
    check('the key holds no cleartext credential',
      !key.includes('passAAA'), JSON.stringify(key));
    const stats = getRelayStats();
    const leaky = stats.filter(s => /passAAA|passBBB|user1|user2/.test(JSON.stringify(s)));
    check('stats leak neither password nor username', leaky.length === 0,
      leaky.length ? JSON.stringify(leaky[0]) : `${stats.length} relay(s), e.g. ${JSON.stringify(stats[0] && stats[0].key)}`);
    // prepareSocksRelays is the production entry point and dedupes on the same
    // identity. Checked explicitly because it is the path that breaks when the
    // two disagree: while the relay key and proxy.js's copy were briefly out of
    // step during this fix, this threw `upstreamKey is not a function` at scan
    // startup, where the checks above still passed.
    await closeAllRelays(false);
    const prepared = await prepareSocksRelays([
      { proxy: 'socks5://u:p1@10.0.0.9:1080' },
      { proxy: 'socks5://u:p2@10.0.0.9:1080' },   // same user, different password
      { proxy: 'socks5://u:p1@10.0.0.9:1080' },   // exact duplicate
      { proxy: 'socks5://10.0.0.9:1080' },        // no auth: needs no relay
      { proxy: 'http://u:p@10.0.0.9:8080' }       // http auth is native, no relay
    ], false);
    check('prepareSocksRelays starts one relay per distinct credential set',
      prepared === 2, `${prepared} relay(s) started (2 = the two distinct passwords)`);
  } finally {
    await closeAllRelays(false);
  }

  console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error('harness error:', e); process.exit(2); });
