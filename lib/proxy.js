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
 *     ⚠ NOT SUPPORTED by Chromium. Chromium cannot authenticate SOCKS
 *       proxies via --proxy-server, and Puppeteer's page.authenticate()
 *       only answers HTTP 407 challenges, not SOCKS5 in-protocol auth.
 *       Credentials on a socks4/socks5 URL are parsed but cannot be
 *       applied — the connection is attempted unauthenticated and will
 *       usually fail. Use an authenticated HTTP proxy, or run a local
 *       no-auth SOCKS relay (microsocks/gost) that injects the upstream
 *       credentials, and point this at the local relay.
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
 * @version 1.1.0
 */

const { formatLogMessage } = require('./colorize');

const PROXY_MODULE_VERSION = '1.1.0';
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
    console.warn(formatLogMessage('proxy', `Invalid proxy URL: ${proxyUrl}`));
    return [];
  }

  const args = [
    `--proxy-server=${parsed.protocol}://${parsed.host}:${parsed.port}`
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

  // Bypass list: domains that skip the proxy
  const bypass = siteConfig.proxy_bypass || siteConfig.socks5_bypass || [];
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
 * @param {object} page - Puppeteer page instance
 * @param {object} siteConfig
 * @param {boolean} forceDebug
 * @returns {Promise<boolean>} True if auth was applied
 */
async function applyProxyAuth(page, siteConfig, forceDebug = false) {
  const proxyUrl = getConfiguredProxy(siteConfig);
  if (!proxyUrl) return false;

  const parsed = parseProxyUrl(proxyUrl);
  if (!parsed || !parsed.username) return false;

  // Chromium cannot authenticate SOCKS proxies via --proxy-server, and
  // page.authenticate() only answers HTTP 407 challenges — not SOCKS5's
  // in-protocol auth. Calling it for a socks URL would silently no-op and
  // (previously) falsely report success. Warn and bail honestly instead.
  if (parsed.protocol === 'socks4' || parsed.protocol === 'socks5') {
    console.warn(formatLogMessage('proxy', `SOCKS proxy auth is unsupported by Chromium — credentials for ${parsed.host}:${parsed.port} cannot be applied. Use an HTTP proxy with auth, or a local no-auth SOCKS relay (microsocks/gost) that injects the upstream credentials.`));
    return false;
  }

  try {
    await page.authenticate({
      username: parsed.username,
      password: parsed.password || ''
    });

    const debug = forceDebug || siteConfig.proxy_debug || siteConfig.socks5_debug;
    if (debug) {
      console.log(formatLogMessage('proxy', `Auth set for ${parsed.username}@${parsed.host}:${parsed.port}`));
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

  const net = require('net');
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
 * Returns human-readable proxy info string for logging.
 *
 * @param {object} siteConfig
 * @returns {string}
 */
function getProxyInfo(siteConfig) {
  const proxyUrl = getConfiguredProxy(siteConfig);
  if (!proxyUrl) return 'none';

  const parsed = parseProxyUrl(proxyUrl);
  if (!parsed) return 'invalid';

  const auth = parsed.username ? `${parsed.username}@` : '';
  return `${parsed.protocol}://${auth}${parsed.host}:${parsed.port}`;
}

/**
 * Returns module version information
 */
function getModuleInfo() {
  return { version: PROXY_MODULE_VERSION, name: 'Proxy Handler' };
}

module.exports = {
  parseProxyUrl,
  needsProxy,
  getProxyArgs,
  applyProxyAuth,
  testProxy,
  getProxyInfo,
  getModuleInfo,
  getConfiguredProxy,
  PROXY_MODULE_VERSION,
  SUPPORTED_PROTOCOLS
};