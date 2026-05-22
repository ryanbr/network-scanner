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

// upstreamKey -> { server, port, activeSockets:Set<net.Socket> }
const _relays = new Map();

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

function handleClient(client, upstream, forceDebug) {
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
          if (forceDebug) {
            console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} upstream connect failed (${host}:${port}): ${e.message}`));
          }
          failReply(client, 0x05);             // connection refused
          return cleanup();
        }

        upstreamSock = info.socket;
        try { upstreamSock.setNoDelay(true); } catch (_) {}
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

  const activeSockets = new Set();
  const server = net.createServer((clientSock) => {
    // Disable Nagle: page scanning is full of small-packet phases (per-origin
    // TLS handshakes, small XHR/API calls, the SOCKS handshake itself).
    // Nagle + delayed-ACK adds ~40ms stalls on those; relays should not.
    try { clientSock.setNoDelay(true); } catch (_) {}
    activeSockets.add(clientSock);
    clientSock.on('close', () => activeSockets.delete(clientSock));
    handleClient(clientSock, upstream, forceDebug);
  });

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

  const port = server.address().port;
  _relays.set(key, { server, port, activeSockets });
  if (forceDebug) {
    console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} 127.0.0.1:${port} -> ${upstream.host}:${upstream.port} (auth user "${upstream.username}")`));
  }
  return port;
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
 * Tear down every relay: destroy in-flight sockets, close listeners.
 * Safe to call multiple times.
 */
async function closeAllRelays(forceDebug = false) {
  for (const [key, r] of _relays) {
    for (const s of r.activeSockets) { try { s.destroy(); } catch (_) {} }
    await new Promise((res) => {
      try { r.server.close(() => res()); } catch (_) { res(); }
    });
    if (forceDebug) console.log(formatLogMessage('proxy', `${SOCKS_RELAY_TAG} closed relay for ${key}`));
  }
  _relays.clear();
}

module.exports = { ensureRelay, getRelayPort, closeAllRelays };
