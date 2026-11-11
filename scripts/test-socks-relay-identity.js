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
 * The password is hashed into the key rather than stored, and both stats and
 * the teardown debug line report a `display` field (host:port) instead of
 * stripping the key's last segment — once the hash was appended, stripping the
 * last segment removed the HASH and left the username. getRelayStats was moved
 * onto `display` at the time; closeAllRelays was not, and printed
 * `closed relay for <host>:<port>:<username>` under --debug until it was.
 *
 * No network: ensureRelay binds a local listener; the upstream is never dialled.
 */

const fs = require('fs');
const net = require('net');
const path = require('path');
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

  // The teardown line is the only debug output that names a relay's identity,
  // and it was the one output path these checks never ran: every closeAllRelays
  // here passes forceDebug=false, so the leak sat behind a flag the suite did
  // not set while the checks above asserted the key and stats were clean.
  {
    await closeAllRelays(false);
    await ensureRelay(parseProxyUrl('socks5://user1:passAAA@10.0.0.9:1080'), false);
    const logged = [];
    const realLog = console.log;
    console.log = (...a) => logged.push(a.join(' ').replace(/\x1b\[[0-9;]*m/g, ''));
    try {
      await closeAllRelays(true);
    } finally {
      console.log = realLog;
    }
    const closeLines = logged.filter(l => /closed relay for/.test(l));
    check('teardown debug reports the relay it closed', closeLines.length === 1,
      `${closeLines.length} line(s)`);
    check('teardown debug leaks neither username nor password',
      !/user1|passAAA/.test(closeLines.join('\n')), JSON.stringify(closeLines[0]));
    check('teardown debug still identifies the upstream by host:port',
      /closed relay for 10\.0\.0\.9:1080(\s|$)/.test(closeLines[0] || ''),
      JSON.stringify(closeLines[0]));

    // Two relays the password-keying exists to separate: same host:port, so
    // `display` is identical for both. Moving teardown onto `display` to stop
    // the username leak removed the only thing that had varied between such
    // lines, so the local port now carries it -- unique per relay, nothing
    // sensitive, and the same value ensureRelay announced at startup.
    await closeAllRelays(false);
    const rotA = parseProxyUrl('socks5://acct:tokenA@10.0.0.9:1080');
    const rotB = parseProxyUrl('socks5://acct:tokenB@10.0.0.9:1080');  // same user, rotated token
    const rotPorts = [await ensureRelay(rotA, false), await ensureRelay(rotB, false)];
    const logged2 = [];
    console.log = (...a) => logged2.push(a.join(' ').replace(/\x1b\[[0-9;]*m/g, ''));
    try {
      await closeAllRelays(true);
    } finally {
      console.log = realLog;
    }
    const lines2 = logged2.filter(l => /closed relay for/.test(l));
    check('two relays on one upstream get distinguishable teardown lines',
      lines2.length === 2 && lines2[0] !== lines2[1], JSON.stringify(lines2));
    check('each teardown line carries the local port ensureRelay announced',
      rotPorts.length === 2 && rotPorts[0] !== rotPorts[1] &&
      rotPorts.every(p => lines2.some(l => l.includes(`127.0.0.1:${p}`))),
      `${JSON.stringify(rotPorts)} vs ${JSON.stringify(lines2)}`);
    check('the distinguishing field is still not a credential',
      !/acct|tokenA|tokenB/.test(lines2.join('\n')), JSON.stringify(lines2));
  }

  // Relays drain CONCURRENTLY, not one after another. Three relays each
  // holding a client that connects and never sends its SOCKS5 greeting force
  // the DRAIN_TIMEOUT_MS path on all three at once: concurrently that is ~1x
  // the budget, sequentially ~3x. Timed rather than asserted from the source
  // because the defect was wall-clock on a path that runs from nwss's SIGINT
  // handler, where the budget x N relays is the whole problem. The lower
  // bound is load-bearing: without it the check would pass vacuously if the
  // clients failed to stall and every server closed instantly.
  //
  // DRAIN_TIMEOUT_MS is module-private, so the budget is read from the
  // shipped source and the bounds expressed as multiples of it -- the same
  // approach test-flowproxy-budget.js takes to PER_URL_TIMEOUT_MS. Re-typed
  // millisecond bounds would misreport the moment the constant is tuned:
  // raise it past the hardcoded ceiling and a correctly concurrent teardown
  // goes red for a reason that has nothing to do with concurrency.
  {
    await closeAllRelays(false);
    const relaySrc = fs.readFileSync(path.join(__dirname, '..', 'lib', 'socks-relay.js'), 'utf8');
    const drainMatch = relaySrc.match(/const DRAIN_TIMEOUT_MS = (\d+);/);
    const budget = drainMatch ? parseInt(drainMatch[1], 10) : NaN;
    // Checked separately so a regex that stops matching reports itself,
    // rather than leaving the timing check to fail on NaN comparisons.
    check('the drain budget is readable from the shipped module source',
      Number.isInteger(budget) && budget > 0, `DRAIN_TIMEOUT_MS = ${budget}`);
    // The stalled clients are what hold a server open, and the handshake
    // watchdog destroys them at HANDSHAKE_TIMEOUT_MS -- which caps how slow a
    // SEQUENTIAL teardown can look, independently of the drain budget.
    // Measured while mutation-testing at a tuned budget of 5000: three relays
    // sequentially took 10003ms, not 15000, because the watchdog got there
    // first. Past roughly that point the cap falls below this check's own
    // ceiling and the check stops discriminating -- so assert the headroom
    // rather than let it quietly become decoration.
    const hsMatch = relaySrc.match(/const HANDSHAKE_TIMEOUT_MS = (\d+);/);
    const handshake = hsMatch ? parseInt(hsMatch[1], 10) : NaN;
    check('the drain check still discriminates at the shipped constants',
      Math.min(3 * budget, handshake) > 2 * budget,
      `sequential ${3 * budget}ms capped by watchdog ${handshake}ms, ceiling ${2 * budget}ms`);
    const drainPorts = [];
    for (let i = 0; i < 3; i++) {
      drainPorts.push(await ensureRelay(parseProxyUrl(`socks5://u:drain${i}@10.0.0.9:1080`), false));
    }
    const stalled = [];
    await Promise.all(drainPorts.map(port => new Promise((resolve) => {
      const c = net.connect(port, '127.0.0.1', () => resolve());   // connect, send nothing
      c.on('error', () => resolve());
      stalled.push(c);
    })));
    const t0 = Date.now();
    await closeAllRelays(false);
    const elapsed = Date.now() - t0;
    for (const c of stalled) { try { c.destroy(); } catch (_) {} }
    // Concurrent is ~1x the budget, sequential ~3x for three relays, so a
    // 2x ceiling discriminates at any value of the constant.
    check('three stalled relays drain concurrently, not one after another',
      elapsed >= budget * 0.75 && elapsed < budget * 2,
      `${elapsed}ms vs budget ${budget}ms (concurrent ~1x, sequential ~3x)`);
  }

  // A high relay count is a consequence of keying on credentials: a provider that
  // rotates a session token in the PASSWORD gets one loopback listener per site.
  // That is correct, but each costs an fd competing with Chrome's, so it warns
  // once past a threshold. Checked here because the warning is the only signal a
  // user gets before hitting an fd limit (tight on macOS: 256 by default).
  {
    await closeAllRelays(false);                       // resets the one-shot
    const warned = [];
    const realWarn = console.warn;
    console.warn = (...a) => warned.push(a.join(' ').replace(/\x1b\[[0-9;]*m/g, ''));
    try {
      for (let i = 0; i < 63; i++) await ensureRelay(parseProxyUrl(`socks5://u:p${i}@10.0.0.9:1080`), false);
      const quietAt63 = warned.filter(w => /relays are open/.test(w)).length;
      await ensureRelay(parseProxyUrl('socks5://u:p63@10.0.0.9:1080'), false);   // 64th
      const atThreshold = warned.filter(w => /relays are open/.test(w)).length;
      for (let i = 64; i < 70; i++) await ensureRelay(parseProxyUrl(`socks5://u:p${i}@10.0.0.9:1080`), false);
      const afterMore = warned.filter(w => /relays are open/.test(w)).length;
      check('no relay-count warning below the threshold', quietAt63 === 0, `${quietAt63} warning(s) at 63 relays`);
      check('one warning when the threshold is reached', atThreshold === 1, `${atThreshold} warning(s) at 64 relays`);
      check('the warning does not repeat per relay', afterMore === 1, `${afterMore} warning(s) at 70 relays`);

      // The one-shot resets with the relays it described, so a second phase is
      // judged on its own count. nwss only tears relays down at shutdown, so
      // this is for a library caller running several phases in one process --
      // covered rather than annotated, so the reset line is not decorative.
      await closeAllRelays(false);
      const beforeSecondPhase = warned.filter(w => /relays are open/.test(w)).length;
      for (let i = 0; i < 64; i++) await ensureRelay(parseProxyUrl(`socks5://v:q${i}@10.0.0.9:1080`), false);
      const secondPhase = warned.filter(w => /relays are open/.test(w)).length;
      check('a rebuilt set of relays warns again', secondPhase === beforeSecondPhase + 1,
        `${beforeSecondPhase} before, ${secondPhase} after a fresh 64`);
    } finally {
      console.warn = realWarn;
      await closeAllRelays(false);
    }
  }

  console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error('harness error:', e); process.exit(2); });
