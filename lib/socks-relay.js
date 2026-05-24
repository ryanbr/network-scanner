/**
 * Local no-auth SOCKS5 relay for authenticated SOCKS5 upstreams.
 *
 * Chromium cannot authenticate SOCKS5 proxies (crbug.com/256785 — it only
 * implements the no-auth method 0x00; credentials in --proxy-server are
 * discarded, and page.authenticate() is HTTP-407-only so it can't help —
 * SOCKS auth happens at the TCP handshake before any HTTP).
 *
 * Workaround: run an in-process no-auth SOCKS5 server bound to 127.0.0.1.
 * Chromium connects to it without auth (which it CAN do); for each
 * connection we open an authenticated tunnel to the real upstream via the
 * `socks` package (RFC 1929 user/pass) and pipe the two together. Domain
 * address types are forwarded as hostnames so remote DNS still works
 * end-to-end (no DNS leak).
 *
 * Relays are keyed by upstream identity and reused. closeAllRelays() must
 * be called on scan exit / signal so listening sockets don't leak.
 */

const net = require('net');
const { SocksClient } = require('socks');
const { formatLogMessage, messageColors } = require('./colorize');
const SOCKS_RELAY_TAG = messageColors.processing('[socks-relay]');

// upstreamKey -> {
//   server: net.Server,                  // listening on 127.0.0.1:port
//   port: number,                        // OS-assigned local port
//   activeSockets: Set<net.Socket>,      // live client sockets (Chromium side)
//   errors: number                       // cumulative upstream-connect failures
// }
const _relays = new Map();

// upstreamKey -> Promise<port> currently initialising. Singleflight guard for
// ensureRelay so two concurrent callers for the same upstream share one
// in-flight init instead of both creating servers and racing to _relays.set,
// where the loser's server would be orphaned (listening forever, never
// closed by closeAllRelays). Not triggered by current usage (proxy.js's
// prepareSocksRelays uses a sequential await loop) but cheap defence
// against future callers that don't know to serialise. Mirrors the
// pendingDigLookups / pendingWhoisLookups pattern in lib/nettools.js.
const _pendingRelays = new Map();

function upstreamKey(u) {
  return `${u.host}:${u.port}:${u.username || ''}`;
}

/**
 * Handle one Chromium->relay connection: minimal SOCKS5 server handshake,
 * then an authenticated upstream tunnel, then bidirectional pipe.
 */
// Bail on a client that connects and never completes SOCKS5 negotiation.
// Generous enough for a Chromium loopback handshake (microseconds), short
// enough to catch a stalled / half-open client before the OS TCP keepalive
// notices (default ~2 hours on Linux).
const HANDSHAKE_TIMEOUT_MS = 10000;

// Cap pre-piping buffer growth. A real SOCKS5 greeting+request is well
// under 300 bytes; absorbing more before the watchdog fires lets a hostile
// or buggy local process drip-feed garbage to pin memory for up to 10s.
// 4096 is the next clean ceiling above any realistic handshake and matches
// typical TCP receive-buffer batches.
const MAX_HANDSHAKE_BYTES = 4096;

// Cap simultaneous local connections per relay. If Chromium opens more than
// this (prefetch-heavy site, fetch-retry loop), excess gets refused at the
// TCP-accept layer, which Chromium's HTTP retry logic handles cleanly. The
// alternative (no cap) is excess tunnels opening to the upstream and the
// provider silently dropping them past its concurrent-tunnel quota — looks
// to the scan like random missed requests.
const MAX_LOCAL_CONNECTIONS = 256;

// On closeAllRelays, give in-flight tunnels this long to drain their
// response data into Chromium before force-destroying. Without it, SIGINT
// mid-scan loses any upstream bytes that hadn't yet hit Puppeteer's
// response listener, leaving incomplete entries in results.json.
const DRAIN_TIMEOUT_MS = 2000;

function handleClient(client, upstream, forceDebug, relay) {
  let phase = 'greeting';
  let buf = Buffer.alloc(0);
  let upstreamSock = null;
  let settled = false;
  // Handshake-phase watchdog handle. Assigned after cleanup is declared so
  // both references in this scope resolve unambiguously.
  let handshakeTimer = null;

  const cleanup = () => {
    if (settled) return;
    settled = true;
    if (handshakeTimer) { clearTimeout(handshakeTimer); handshakeTimer = null; }
    try { client.destroy(); } catch (_) {}
    if (upstreamSock) { try { upstreamSock.destroy(); } catch (_) {} }
  };

  // Bail on a client that connects and never completes SOCKS5 negotiation
  // (stalled / half-open / non-SOCKS protocol). Without this, such a socket
  // sits in activeSockets until the OS TCP keepalive notices — default
  // ~2 hours on Linux. unref'd so a pending watchdog never holds the
  // process alive after closeAllRelays().
  handshakeTimer = setTimeout(() => {
    if (phase !== 'piping') {
      if (forceDebug) {
        console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} handshake timeout (phase=${phase}) — closing`));
      }
      cleanup();
    }
  }, HANDSHAKE_TIMEOUT_MS);
  if (typeof handshakeTimer.unref === 'function') handshakeTimer.unref();

  const onData = async (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    // Reject oversize pre-piping buffers before the 10s watchdog. Sends
    // a protocol-appropriate failure reply per phase so a misbehaving but
    // RFC-aware client gets a clean signal rather than a raw connection
    // drop. Skipped once piping starts (buf is nulled then anyway).
    if (phase !== 'piping' && buf.length > MAX_HANDSHAKE_BYTES) {
      if (forceDebug) {
        console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} handshake oversize (${buf.length} bytes, phase=${phase}) — closing`));
      }
      if (phase === 'greeting') {
        try { client.write(Buffer.from([0x05, 0xFF])); } catch (_) {} // no acceptable methods
      } else if (phase === 'request') {
        failReply(client, 0x01); // general SOCKS server failure
      }
      return cleanup();
    }
    try {
      if (phase === 'greeting') {
        // [0x05, NMETHODS, METHODS...]
        if (buf.length < 2) return;
        const nMethods = buf[1];
        if (buf.length < 2 + nMethods) return;
        const offered = buf.subarray(2, 2 + nMethods);
        buf = buf.subarray(2 + nMethods);
        // We only speak no-auth (0x00) to the local client. Chromium always
        // offers it; if a client somehow didn't, reply "no acceptable
        // methods" rather than violate the protocol by selecting unoffered.
        if (!offered.includes(0x00)) {
          try { client.write(Buffer.from([0x05, 0xFF])); } catch (_) {}
          return cleanup();
        }
        client.write(Buffer.from([0x05, 0x00])); // select "no auth"
        phase = 'request';
      }

      if (phase === 'request') {
        // [0x05, CMD, 0x00, ATYP, ADDR..., PORT(2 BE)]
        if (buf.length < 4) return;
        if (buf[0] !== 0x05) { failReply(client, 0x01); return cleanup(); }
        const cmd = buf[1];
        const atyp = buf[3];
        let host, port, hdrLen;

        if (atyp === 0x01) {                 // IPv4
          if (buf.length < 10) return;
          host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
          port = buf.readUInt16BE(8);
          hdrLen = 10;
        } else if (atyp === 0x03) {          // domain
          if (buf.length < 5) return;
          const dLen = buf[4];
          if (buf.length < 7 + dLen) return;
          host = buf.subarray(5, 5 + dLen).toString('utf8');
          port = buf.readUInt16BE(5 + dLen);
          hdrLen = 7 + dLen;
        } else if (atyp === 0x04) {          // IPv6
          if (buf.length < 22) return;
          const seg = [];
          for (let i = 0; i < 16; i += 2) seg.push(buf.readUInt16BE(4 + i).toString(16));
          host = seg.join(':');
          port = buf.readUInt16BE(20);
          hdrLen = 22;
        } else {
          failReply(client, 0x08);            // address type not supported
          return cleanup();
        }

        if (cmd !== 0x01) {                    // only CONNECT
          failReply(client, 0x07);
          return cleanup();
        }

        // Hand the stream to .pipe() from here. Pause + detach this handler
        // so a data event during the upstream connect can't re-enter.
        phase = 'connecting';
        client.pause();
        client.off('data', onData);
        const early = buf.subarray(hdrLen);   // any bytes after the request header
        buf = null;

        let info;
        try {
          info = await SocksClient.createConnection({
            proxy: {
              host: upstream.host,
              port: upstream.port,
              type: 5,
              userId: upstream.username,
              password: upstream.password || '',
            },
            command: 'connect',
            destination: { host, port },
            timeout: 20000,
          });
        } catch (e) {
          // Bump the per-relay error counter (exposed via getRelayStats)
          // so post-scan diagnostics can see "X of N upstream connects
          // failed" without re-running with forceDebug.
          relay.errors++;
          if (forceDebug) {
            console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} upstream connect failed (${host}:${port}): ${e.message}`));
          }
          failReply(client, 0x05);             // connection refused
          return cleanup();
        }

        upstreamSock = info.socket;
        try { upstreamSock.setNoDelay(true); } catch (_) {}
        // Catch silently-dead upstreams (NAT timeout, mobile-tower drop,
        // proxy crash without FIN/RST) faster than the default ~2-hour
        // Linux idle. setKeepAlive(true, 60000) sets TCP_KEEPIDLE only —
        // the kernel still uses tcp_keepalive_intvl/tcp_keepalive_probes
        // for the probe phase, so total detection is ~60s idle + N probes
        // (default 9 × 75s on Linux) ≈ 12 minutes. Big improvement over
        // 2h, not the 60s the bare argument suggests. Client-side keep-
        // alive is omitted — same kernel, OS surfaces death immediately.
        try { upstreamSock.setKeepAlive(true, 60000); } catch (_) {}
        upstreamSock.on('error', cleanup);
        upstreamSock.on('close', cleanup);
        client.on('error', cleanup);
        client.on('close', cleanup);

        // SOCKS5 success (BND.ADDR 0.0.0.0:0 — Chromium ignores it for CONNECT)
        client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        if (early && early.length) upstreamSock.write(early);
        client.pipe(upstreamSock);
        upstreamSock.pipe(client);
        client.resume();
        phase = 'piping';
        // Negotiation complete — disarm the handshake watchdog so a
        // long-running download isn't killed mid-transfer.
        if (handshakeTimer) { clearTimeout(handshakeTimer); handshakeTimer = null; }
      }
    } catch (e) {
      if (forceDebug) {
        console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} handler error: ${e.message}`));
      }
      cleanup();
    }
  };

  client.on('data', onData);
  client.on('error', cleanup);
}

// SOCKS5 failure reply (valid only before piping starts).
function failReply(client, code) {
  try { client.write(Buffer.from([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); } catch (_) {}
}

/**
 * Ensure a relay exists for the given upstream; returns its local port.
 * Idempotent — repeated calls for the same upstream reuse one relay.
 *
 * @param {{host:string,port:number,username:string,password:string}} upstream
 * @param {boolean} forceDebug
 * @returns {Promise<number>} local 127.0.0.1 port the relay listens on
 */
async function ensureRelay(upstream, forceDebug = false) {
  const key = upstreamKey(upstream);
  const existing = _relays.get(key);
  if (existing) return existing.port;

  // Singleflight: if another caller is already initialising this upstream,
  // ride its promise instead of starting a parallel init. Prevents the
  // race where two concurrent callers both pass the _relays.get(key) check
  // above, both create servers, and the second _relays.set(key, ...) below
  // orphans the first server (listening forever, never closed).
  if (_pendingRelays.has(key)) return _pendingRelays.get(key);

  // Most authenticated SOCKS5 servers reject empty-password auth at the
  // RFC 1929 handshake; without this warn, the misconfig surfaces only
  // per-request inside forceDebug-gated logs (silent in production).
  // Fire once per unique upstream (after the existing-relay short-circuit
  // above) so repeated calls don't spam.
  if (upstream.username && !upstream.password) {
    console.warn(formatLogMessage('warn', `${SOCKS_RELAY_TAG} upstream ${upstream.host}:${upstream.port} has username but no password — RFC 1929 auth will likely fail`));
  }

  // .finally() (not try/finally inside the IIFE) so the cleanup is
  // scheduled in a microtask, guaranteed to run AFTER the _pendingRelays.set
  // below. If the cleanup were a try/finally inside an async IIFE and the
  // body threw SYNCHRONOUSLY (before its first await), the finally would
  // run SYNC before the implicit rejected promise was returned, _pendingRelays
  // wouldn't be set yet, the delete would no-op, and then the outer .set
  // would register a permanent rejected entry that future callers would
  // await forever. The current body has no realistic sync-throw paths
  // (net.createServer / Set / object literal don't throw), but defensive.
  const initPromise = (async () => {
    const activeSockets = new Set();
    // Single mutable state object referenced by both the connection handler
    // (writes .errors) and _relays / getRelayStats (read both). Server +
    // port assigned after listen() completes; declared up-front so the
    // closure below can close over `relayEntry` and pass it to handleClient.
    const relayEntry = { server: null, port: null, activeSockets, errors: 0 };

    const server = net.createServer((clientSock) => {
      // Disable Nagle: page scanning is full of small-packet phases (per-origin
      // TLS handshakes, small XHR/API calls, the SOCKS handshake itself).
      // Nagle + delayed-ACK adds ~40ms stalls on those; relays should not.
      try { clientSock.setNoDelay(true); } catch (_) {}
      activeSockets.add(clientSock);
      clientSock.on('close', () => activeSockets.delete(clientSock));
      handleClient(clientSock, upstream, forceDebug, relayEntry);
    });

    // Shed excess connections at the TCP-accept layer instead of letting them
    // all proceed to open authenticated tunnels (which the upstream provider
    // may silently drop past its quota).
    server.maxConnections = MAX_LOCAL_CONNECTIONS;

    await new Promise((resolve, reject) => {
      const onErr = (e) => reject(e);
      server.once('error', onErr);
      server.listen(0, '127.0.0.1', () => {
        server.removeListener('error', onErr);
        // Keep a listener so a late server error doesn't crash the process.
        server.on('error', (e) => {
          if (forceDebug) console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} server error: ${e.message}`));
        });
        resolve();
      });
    });

    relayEntry.server = server;
    relayEntry.port = server.address().port;
    _relays.set(key, relayEntry);
    const port = relayEntry.port;
    if (forceDebug) {
      // auth status is kept as a presence flag only -- previously printed
      // the raw username, which leaked into shared debug output (support
      // tickets, screenshots, gists). Same redaction policy as the
      // proxy.js getProxyInfo() change.
      const authTag = upstream.username ? ' (auth: [redacted])' : ' (no auth)';
      console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} 127.0.0.1:${port} -> ${upstream.host}:${upstream.port}${authTag}`));
    }
    return port;
  })().finally(() => {
    _pendingRelays.delete(key);
  });

  _pendingRelays.set(key, initPromise);
  return initPromise;
}

/**
 * Sync lookup of an already-started relay's port. Returns null if no relay
 * has been started for this upstream (caller should have called ensureRelay
 * upfront).
 */
function getRelayPort(upstream) {
  const r = _relays.get(upstreamKey(upstream));
  return r ? r.port : null;
}

/**
 * Snapshot of active relays for diagnostics. Returns an array of
 * { key, port, activeConnections, errors } — the upstream `key` has its
 * trailing `:username` segment stripped using the same regex as
 * closeAllRelays' display path (IPv6-safe). `errors` is the cumulative
 * count of failed upstream-tunnel opens for the relay's lifetime.
 * Useful for answering "is my proxy slow because the upstream is
 * saturated, or because the scan is opening too many parallel tunnels?"
 * without enabling forceDebug.
 */
function getRelayStats() {
  const stats = [];
  for (const [key, r] of _relays) {
    stats.push({
      key: key.replace(/:[^:]*$/, ''),
      port: r.port,
      activeConnections: r.activeSockets.size,
      errors: r.errors
    });
  }
  return stats;
}

/**
 * Tear down every relay. Stops accepting new connections, gives in-flight
 * tunnels up to DRAIN_TIMEOUT_MS (2s) to flush remaining response bytes
 * into Chromium / Puppeteer, then force-destroys any stragglers. Safe to
 * call multiple times (subsequent calls iterate an empty _relays Map).
 */
async function closeAllRelays(forceDebug = false) {
  for (const [key, r] of _relays) {
    // upstreamKey embeds the username (host:port:username), so the raw
    // key would leak it in debug output. Strip just the trailing
    // `:username` segment for display; using a regex (not split-on-':')
    // so IPv6 hosts with embedded colons (e.g. 2001:db8::1:1080:user)
    // aren't mangled. The relay identity stays unambiguous from host+port.
    const displayKey = key.replace(/:[^:]*$/, '');
    const startedWith = r.activeSockets.size;

    // server.close() stops accepting new connections and resolves only
    // when all existing sockets have closed naturally. Race that against
    // DRAIN_TIMEOUT_MS: if active tunnels finish flushing in time,
    // Chromium / Puppeteer gets the response bytes it was waiting for;
    // beyond that, force-destroy stragglers (the close callback then
    // fires immediately). Trade-off chosen so SIGINT mid-scan doesn't
    // amputate in-flight responses but a hung tunnel can't block exit.
    const closePromise = new Promise((res) => {
      try { r.server.close(() => res()); } catch (_) { res(); }
    });

    let timer;
    const drained = await Promise.race([
      closePromise.then(() => { if (timer) clearTimeout(timer); return true; }),
      new Promise((res) => {
        timer = setTimeout(() => res(false), DRAIN_TIMEOUT_MS);
        // Don't hold the event loop open on a still-pending drain timer
        // when the close-promise won the race.
        if (typeof timer.unref === 'function') timer.unref();
      })
    ]);

    let forcedCount = 0;
    if (!drained) {
      forcedCount = r.activeSockets.size;
      for (const s of r.activeSockets) { try { s.destroy(); } catch (_) {} }
      await closePromise; // resolves now that the last socket has closed
    }

    if (forceDebug) {
      const note = forcedCount > 0
        ? ` (drain timeout — force-closed ${forcedCount}/${startedWith} active socket(s))`
        : (startedWith > 0 ? ` (drained ${startedWith} active socket(s))` : '');
      console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} closed relay for ${displayKey}${note}`));
    }
  }
  _relays.clear();
}

module.exports = { ensureRelay, getRelayPort, getRelayStats, closeAllRelays };
