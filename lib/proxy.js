/**
 * Proxy Module for NWSS Network Scanner
 * ======================================
 * Routes specific site URLs through SOCKS5, SOCKS4, HTTP, or HTTPS proxies.
 *
 * Chromium's --proxy-server flag is browser-wide, so sites requiring a proxy
 * need a separate browser instance. This module handles:
 *   - Parsing proxy URLs (all supported protocols)
 *   - Generating Chromium launch args
 *   - Per-page authentication via Puppeteer
 *   - Proxy bypass lists
 *   - Proxy health checks
 *
 * CONFIG EXAMPLES:
 *
 *   SOCKS5 (no auth):
 *     "proxy": "socks5://127.0.0.1:1080"
 *
 *   SOCKS5 with auth:
 *     "proxy": "socks5://user:pass@127.0.0.1:1080"
 *     Chromium itself cannot authenticate SOCKS5 (crbug.com/256785), so
 *     this module auto-starts an in-process no-auth SOCKS5 relay
 *     (lib/socks-relay.js) that does the upstream RFC 1929 auth. Chromium
 *     connects to the local relay (no auth — which it CAN do) and the
 *     relay tunnels to the authenticated upstream. Transparent: keep the
 *     socks5://user:pass@host form in config. Requires prepareSocksRelays()
 *     to be awaited once before the scan loop (nwss.js does this).
 *     NOTE: socks4 with auth is still unsupported (userId-only,
 *     near-extinct) — use socks5 or an authenticated HTTP proxy.
 *
 *   HTTP proxy (corporate):
 *     "proxy": "http://proxy.corp.com:3128"
 *
 *   HTTP proxy with auth:
 *     "proxy": "http://user:pass@proxy.corp.com:8080"
 *
 *   HTTPS proxy:
 *     "proxy": "https://secure-proxy.example.com:8443"
 *
 *   With bypass list and remote DNS:
 *     "proxy": "socks5://127.0.0.1:1080",
 *     "proxy_bypass": ["localhost", "127.0.0.1", "*.local"],
 *     "proxy_remote_dns": true
 *
 *   Debug mode:
 *     "proxy": "socks5://127.0.0.1:1080",
 *     "proxy_debug": true
 *
 *   Legacy key (backwards compatible):
 *     "socks5_proxy": "socks5://127.0.0.1:1080"
 *
 * INTEGRATION (in nwss.js):
 *   const { needsProxy, getProxyArgs, applyProxyAuth, getProxyInfo } = require('./lib/proxy');
 *
 *   // Before browser launch
 *   if (needsProxy(siteConfig)) {
 *     const proxyArgs = getProxyArgs(siteConfig, forceDebug);
 *     browserArgs.push(...proxyArgs);
 *   }
 *
 *   // After page creation, before page.goto()
 *   await applyProxyAuth(page, siteConfig, forceDebug);
 *
 * @version 1.2.0
 */

const net = require('net');
const { formatLogMessage } = require('./colorize');
const { ensureRelay, getRelayPort, closeAllRelays: closeAllSocksRelays } = require('./socks-relay');

// Note: no separate subsystem TAG here — formatLogMessage('proxy', ...)
// already emits the `[proxy]` prefix from the severity. socks-relay.js's
// pattern (`[proxy] [socks-relay] ...`) is correct THERE because its
// module name differs from the severity. For this file the module IS the
// severity, so a second '[proxy]' would be redundant double-prefix.

const SUPPORTED_PROTOCOLS = ['socks5', 'socks4', 'http', 'https'];

const DEFAULT_PORTS = {
  socks5: 1080,
  socks4: 1080,
  http: 8080,
  https: 8443
};

/**
 * Returns the configured proxy URL string from siteConfig.
 * Supports both "proxy" (preferred) and "socks5_proxy" (legacy) keys.
 *
 * @param {object} siteConfig
 * @returns {string|null}
 */
function getConfiguredProxy(siteConfig) {
  return siteConfig.proxy || siteConfig.socks5_proxy || null;
}

/**
 * Parses a proxy URL into components.
 * Accepts: protocol://host:port, protocol://user:pass@host:port, bare host:port
 *
 * @param {string} proxyUrl - Proxy URL string
 * @returns {object|null} Parsed proxy or null if invalid
 */
function parseProxyUrl(proxyUrl) {
  if (!proxyUrl || typeof proxyUrl !== 'string') return null;

  let cleaned = proxyUrl.trim();

  // Normalise bare host:port to socks5:// URL
  if (!cleaned.includes('://')) {
    cleaned = `socks5://${cleaned}`;
  }

  try {
    const url = new URL(cleaned);
    const protocol = url.protocol.replace(':', '');

    if (!SUPPORTED_PROTOCOLS.includes(protocol)) return null;

    const host = url.hostname;
    if (!host) return null;

    const port = parseInt(url.port, 10) || DEFAULT_PORTS[protocol] || 1080;
    // Reject obvious typos at parse time rather than passing a >65535 port
    // through to Chromium and getting an opaque downstream error. Port 0
    // is technically OS-assigned but never a valid proxy target.
    if (port < 1 || port > 65535) return null;
    // decodeURIComponent throws URIError on a literal '%' that isn't a valid
    // escape (e.g. a password containing '%'). Fall back to the raw value so
    // an otherwise-valid proxy isn't rejected as "Invalid proxy URL".
    const safeDecode = (v) => { try { return decodeURIComponent(v); } catch (_) { return v; } };
    const username = url.username ? safeDecode(url.username) : null;
    const password = url.password ? safeDecode(url.password) : null;

    return { protocol, host, port, username, password };
  } catch (_) {
    return null;
  }
}

/**
 * Checks if a site config requires a proxy
 *
 * @param {object} siteConfig
 * @returns {boolean}
 */
function needsProxy(siteConfig) {
  return !!getConfiguredProxy(siteConfig);
}

/**
 * Pre-start local no-auth SOCKS5 relays for every distinct authenticated
 * SOCKS5 upstream across the given site configs. Must be awaited ONCE
 * before the scan loop — getProxyArgs() then does a pure sync lookup of
 * the relay port, so the fragile per-batch browser-launch path stays
 * synchronous.
 *
 * @param {object[]} siteConfigs
 * @param {boolean} forceDebug
 * @returns {Promise<number>} count of relays started
 */
async function prepareSocksRelays(siteConfigs, forceDebug = false) {
  let started = 0;
  const seen = new Set();
  for (const cfg of (siteConfigs || [])) {
    const url = getConfiguredProxy(cfg);
    if (!url) continue;
    const parsed = parseProxyUrl(url);
    // Only socks5 with credentials needs a relay. socks4-auth stays
    // unsupported (near-extinct, userId-only); http/https auth works
    // natively via page.authenticate().
    if (!parsed || parsed.protocol !== 'socks5' || !parsed.username) continue;
    const key = `${parsed.host}:${parsed.port}:${parsed.username}`;
    if (seen.has(key)) continue;
    seen.add(key);
    try {
      await ensureRelay(parsed, forceDebug);
      started++;
    } catch (e) {
      console.warn(formatLogMessage('proxy', `Failed to start SOCKS5 auth relay for ${parsed.host}:${parsed.port}: ${e.message}`));
    }
  }
  return started;
}

/**
 * Returns Chromium launch arguments for the configured proxy.
 *
 * @param {object} siteConfig
 * @param {boolean} forceDebug
 * @returns {string[]} Array of Chromium args (empty if no proxy configured)
 */
function getProxyArgs(siteConfig, forceDebug = false) {
  const proxyUrl = getConfiguredProxy(siteConfig);
  if (!proxyUrl) return [];

  const parsed = parseProxyUrl(proxyUrl);
  if (!parsed) {
    // Strip user:pass before echoing the URL — same redaction policy as
    // getProxyInfo() / applyProxyAuth / socks-relay logs. Without this, a
    // proxy URL with embedded creds (`socks5://user:pass@host:port`) that
    // fails parse (typo in protocol, port out of range, etc.) leaks the
    // raw creds to stderr. Regex handles both scheme-prefixed
    // (`socks5://user:pass@`) and bare (`user:pass@`) forms — the latter
    // because parseProxyUrl normalises bare host:port internally so the
    // user-supplied string still reaches here unchanged.
    const safeUrl = String(proxyUrl).replace(
      /^([a-z0-9+]+:\/\/)?[^@\s]+@/i,
      (_m, scheme) => `${scheme || ''}[redacted]@`
    );
    console.warn(formatLogMessage('proxy', `Invalid proxy URL: ${safeUrl}`));
    return [];
  }

  // Authenticated SOCKS5: Chromium can't auth SOCKS, so point it at the
  // local no-auth relay (started upfront by prepareSocksRelays) which does
  // the upstream auth. Credentials never reach Chromium. The relay speaks
  // SOCKS5 and forwards domain addresses, so the remote-DNS rule below
  // still applies correctly to the localhost hop.
  let effectiveHost = parsed.host;
  let effectivePort = parsed.port;
  let effectiveProto = parsed.protocol;
  if (parsed.protocol === 'socks5' && parsed.username) {
    const relayPort = getRelayPort(parsed);
    if (relayPort) {
      effectiveHost = '127.0.0.1';
      effectivePort = relayPort;
      const debug = forceDebug || siteConfig.proxy_debug || siteConfig.socks5_debug;
      if (debug) {
        console.log(formatLogMessage('proxy', `SOCKS5 auth via local relay 127.0.0.1:${relayPort} -> ${parsed.host}:${parsed.port}`));
      }
    } else {
      // prepareSocksRelays should have started this; defensive only.
      console.warn(formatLogMessage('proxy', `No SOCKS5 auth relay for ${parsed.host}:${parsed.port} — call prepareSocksRelays() before the scan. Connection will fail (Chromium can't auth SOCKS).`));
    }
  }

  const args = [
    `--proxy-server=${effectiveProto}://${effectiveHost}:${effectivePort}`
  ];

  // Remote DNS: force proxy-side hostname resolution (prevents DNS leaks).
  // SOCKS5 only — it can carry a hostname to the proxy for remote
  // resolution. SOCKS4 cannot (the protocol only accepts an IPv4 address;
  // resolution must happen client-side), so applying MAP * ~NOTFOUND there
  // makes Chromium's local resolver fail with nothing able to resolve the
  // hostname — every request breaks. HTTP/HTTPS proxies resolve remotely
  // by default and need no rule.
  const remoteDns = siteConfig.proxy_remote_dns ?? siteConfig.socks5_remote_dns;
  if (parsed.protocol === 'socks5' && remoteDns !== false) {
    args.push('--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1');
  } else if (parsed.protocol === 'socks4' && remoteDns === true) {
    console.warn(formatLogMessage('proxy', `proxy_remote_dns ignored: SOCKS4 cannot do proxy-side DNS resolution (use SOCKS5)`));
  }

  // Bypass list: domains that skip the proxy. Accept either an array (the
  // documented form) or a single string — a bare "localhost" used to throw
  // `bypass.join is not a function` here, in the browser-launch path. Same
  // string-or-array tolerance as the dig/whois siteConfig fields.
  const rawBypass = siteConfig.proxy_bypass || siteConfig.socks5_bypass || [];
  const bypass = Array.isArray(rawBypass) ? rawBypass : [rawBypass];
  if (bypass.length > 0) {
    args.push(`--proxy-bypass-list=${bypass.join(';')}`);
  }

  const debug = forceDebug || siteConfig.proxy_debug || siteConfig.socks5_debug;
  if (debug) {
    console.log(formatLogMessage('proxy', `[${parsed.protocol}] Args: ${args.join(' ')}`));
  }

  return args;
}

/**
 * Applies proxy authentication to a page via Puppeteer's authenticate API.
 * Must be called BEFORE page.goto().
 *
 * Returns `true` only on a successful HTTP/HTTPS page.authenticate() call.
 * Returns `false` in five distinct scenarios — callers cannot use the
 * boolean to distinguish them; treat `false` as "no further action needed
 * from this module" rather than "auth failed":
 *   - no proxy configured
 *   - proxy has no username (anonymous)
 *   - SOCKS5 with creds  -> the local relay handles upstream auth out-of-band
 *   - SOCKS4 with creds  -> genuinely unsupported (warned)
 *   - page.authenticate() threw (warned)
 *
 * @param {object} page - Puppeteer page instance
 * @param {object} siteConfig
 * @param {boolean} forceDebug
 * @returns {Promise<boolean>}
 */
async function applyProxyAuth(page, siteConfig, forceDebug = false) {
  const proxyUrl = getConfiguredProxy(siteConfig);
  if (!proxyUrl) return false;

  const parsed = parseProxyUrl(proxyUrl);
  if (!parsed || !parsed.username) return false;

  // Chromium can't authenticate SOCKS proxies, and page.authenticate() is
  // HTTP-407-only. SOCKS5+creds is handled out-of-band by the local
  // no-auth relay (prepareSocksRelays + getProxyArgs rewrite) — Chromium
  // talks no-auth to 127.0.0.1, so there's nothing for page.authenticate
  // to do here; return quietly. SOCKS4 auth (userId-only, near-extinct)
  // stays genuinely unsupported.
  if (parsed.protocol === 'socks5') {
    return false; // relay handles upstream auth
  }
  if (parsed.protocol === 'socks4') {
    console.warn(formatLogMessage('proxy', `SOCKS4 proxy auth is unsupported (use SOCKS5, which is auto-relayed, or an authenticated HTTP proxy).`));
    return false;
  }

  try {
    await page.authenticate({
      username: parsed.username,
      password: parsed.password || ''
    });

    const debug = forceDebug || siteConfig.proxy_debug || siteConfig.socks5_debug;
    if (debug) {
      // Redact the username — same policy as getProxyInfo() and the
      // socks-relay logs. debug output gets pasted into support tickets /
      // screenshots / gists; '[redacted]' keeps the "yes, creds were
      // attached" signal without disclosing what they were.
      console.log(formatLogMessage('proxy', `Auth set for [redacted]@${parsed.host}:${parsed.port}`));
    }

    return true;
  } catch (err) {
    console.warn(formatLogMessage('proxy', `Failed to set proxy auth: ${err.message}`));
    return false;
  }
}

/**
 * Tests proxy connectivity by attempting a TCP connection.
 *
 * @param {object} siteConfig
 * @param {number} timeoutMs - Connection timeout (default 5000ms)
 * @returns {Promise<object>} { reachable, latencyMs, error }
 */
async function testProxy(siteConfig, timeoutMs = 5000) {
  const proxyUrl = getConfiguredProxy(siteConfig);
  if (!proxyUrl) {
    return { reachable: false, latencyMs: 0, error: 'No proxy configured' };
  }

  const parsed = parseProxyUrl(proxyUrl);
  if (!parsed) {
    return { reachable: false, latencyMs: 0, error: 'Invalid proxy URL' };
  }

  const start = Date.now();

  return new Promise((resolve) => {
    const socket = new net.Socket();

    const onError = (err) => {
      socket.destroy();
      resolve({ reachable: false, latencyMs: Date.now() - start, error: err.message });
    };

    socket.setTimeout(timeoutMs);
    socket.on('error', onError);
    socket.on('timeout', () => onError(new Error('Connection timeout')));

    socket.connect(parsed.port, parsed.host, () => {
      const latency = Date.now() - start;
      socket.destroy();
      resolve({ reachable: true, latencyMs: latency, error: null });
    });
  });
}

/**
 * Returns human-readable proxy info string for logging. The auth portion
 * is REDACTED -- previously the username was emitted verbatim, which
 * meant any error log line carrying this value (see nwss.js's
 * ERR_SOCKS_CONNECTION_FAILED handler) leaked the proxy username to
 * stderr / support tickets / screenshots. Password was already absent
 * here. We keep an explicit `[redacted]@` marker when auth was configured
 * so the reader still knows "yes, credentials were attached" without
 * disclosing what they were.
 *
 * @param {object} siteConfig
 * @returns {string}
 */
function getProxyInfo(siteConfig) {
  const proxyUrl = getConfiguredProxy(siteConfig);
  if (!proxyUrl) return 'none';

  const parsed = parseProxyUrl(proxyUrl);
  if (!parsed) return 'invalid';

  const auth = parsed.username ? '[redacted]@' : '';
  return `${parsed.protocol}://${auth}${parsed.host}:${parsed.port}`;
}

// getModuleInfo() / PROXY_MODULE_VERSION / SUPPORTED_PROTOCOLS / and now
// getConfiguredProxy removed from exports -- zero external callers (mirrors
// the same trim done in lib/cloudflare.js). SUPPORTED_PROTOCOLS and
// getConfiguredProxy stay as module-local since parseProxyUrl /
// needsProxy / prepareSocksRelays / getProxyArgs use them.

module.exports = {
  parseProxyUrl,
  needsProxy,
  prepareSocksRelays,
  closeAllSocksRelays,
  getProxyArgs,
  applyProxyAuth,
  testProxy,
  getProxyInfo
};