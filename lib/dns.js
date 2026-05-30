/**
 * DNS pre-check resolver with multi-nameserver rotation.
 *
 * Owns nameserver selection and robust resolution for the scan's DNS
 * pre-check. The default global resolver leads EVERY query with the FIRST
 * nameserver in /etc/resolv.conf, so under scan concurrency one server
 * (typically the ISP resolver) takes the whole c-ares burst and starts
 * answering REFUSED while the other configured servers (e.g. 8.8.8.8/8.8.4.4)
 * sit idle. This module builds one Resolver per nameserver — each leading with
 * a different server, the rest kept as failover order — and round-robins them
 * per resolve attempt so the lead spreads across all servers (and across the
 * retry). A `--dns` override pins/rotates an explicit list instead of
 * resolv.conf.
 *
 * Scope: this affects the pre-check resolver only. Chrome's navigation DNS
 * (OS resolver) and nettools' dig/whois are separate paths and unaffected.
 */
const net = require('node:net');
const dnsPromises = require('node:dns/promises');
const { getServers: getSystemDnsServers } = require('node:dns');
const { Resolver: DnsPromiseResolver } = require('node:dns/promises');
const { formatLogMessage } = require('./colorize');

// c-ares codes that mean "resolver problem" (retry-worthy / fail-open), not
// "the host does not exist".
const DNS_TRANSIENT_ERRORS = new Set(['ETIMEOUT', 'ESERVFAIL', 'EREFUSED', 'ECONNREFUSED']);

/**
 * True only for a definitive "host does not exist / has no address" answer —
 * the only case that justifies skipping a URL in the pre-check. Everything
 * else (EREFUSED, ESERVFAIL, ETIMEOUT, ECONNREFUSED, timeout) is a resolver
 * problem the caller should fail open on.
 * @param {string} code
 * @returns {boolean}
 */
function isNonExistenceError(code) {
  return code === 'ENOTFOUND' || code === 'ENODATA';
}

/**
 * Parse + validate a `--dns` / config value into a clean server list.
 * Accepts a comma-separated string or an array; drops invalid entries (warns).
 * @param {string|string[]|undefined} raw
 * @returns {string[]} validated IPv4/IPv6 addresses (possibly empty)
 */
function parseDnsServers(raw) {
  if (!raw) return [];
  const parts = (Array.isArray(raw) ? raw : String(raw).split(','))
    .map(s => String(s).trim())
    .filter(Boolean);
  const valid = [];
  for (const p of parts) {
    if (net.isIP(p)) valid.push(p);
    else console.warn(`⚠ --dns: ignoring invalid server "${p}" (not an IPv4/IPv6 address)`);
  }
  return valid;
}

/**
 * Build a rotating pre-check resolver.
 * @param {object} [opts]
 * @param {string[]} [opts.servers] - explicit servers (from --dns). When empty,
 *   the system resolv.conf servers are used.
 * @param {boolean} [opts.forceDebug] - emit a debug line on the retry path.
 * @returns {{ resolveHost: (hostname:string, timeoutMs:number)=>Promise<void>,
 *   servers: string[], rotates: boolean, pinned: boolean }}
 *   resolveHost resolves on success and rejects with the final error
 *   (err.code intact) on failure.
 */
function createRotatingResolver(opts = {}) {
  const forceDebug = !!opts.forceDebug;
  const override = Array.isArray(opts.servers) && opts.servers.length > 0 ? opts.servers : null;

  let systemServers = [];
  try { systemServers = getSystemDnsServers(); } catch { systemServers = []; }
  const servers = override || systemServers;

  // Pin/rotate an explicit --dns list (even a single server — never fall back
  // to the OS resolver in that case). For resolv.conf, only build a pool when
  // there is more than one server to rotate; otherwise use the global API
  // (which already reads resolv.conf).
  const shouldPool = override ? servers.length >= 1 : servers.length > 1;
  let pool = null;
  if (shouldPool) {
    pool = servers.map((_, i) => {
      const r = new DnsPromiseResolver();
      // setServers round-trips the exact format getServers returns (incl. ports
      // / bracketed IPv6), so this is safe. Keep default order if an entry is
      // somehow rejected.
      try { r.setServers([...servers.slice(i), ...servers.slice(0, i)]); } catch { /* keep default */ }
      return r;
    });
  }

  let cursor = 0;
  // Resolver for the next attempt: rotated when a pool exists, else the global
  // promises API. The cursor is shared across concurrent tasks; a benign race
  // there only perturbs the distribution, which is the goal anyway.
  const nextResolver = () => (pool ? pool[cursor++ % pool.length] : dnsPromises);

  // One resolution attempt: rotate the lead server, resolve4 first, and on
  // no-IPv4 (ENODATA/ENOTFOUND) fall back to resolve6 so IPv6-only hosts aren't
  // wrongly skipped. Any OTHER code propagates unchanged so the caller sees the
  // real resolver error. A timeout is kept as a safety net — with c-ares off
  // the libuv threadpool it should rarely fire.
  async function attempt(hostname, timeoutMs) {
    const resolver = nextResolver();
    let timer;
    try {
      const timeoutP = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('DNS timeout')), timeoutMs);
      });
      const chain = resolver.resolve4(hostname).catch(err => {
        if (err && (err.code === 'ENODATA' || err.code === 'ENOTFOUND')) {
          return resolver.resolve6(hostname);
        }
        throw err;
      });
      await Promise.race([chain, timeoutP]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * Resolve a hostname, rotating the lead server per attempt and retrying once
   * on a transient/resolver error (so the retry leads with the next server —
   * if one REFUSES, the retry hits another).
   */
  async function resolveHost(hostname, timeoutMs) {
    try {
      await attempt(hostname, timeoutMs);
    } catch (firstErr) {
      const code = firstErr && firstErr.code;
      if (DNS_TRANSIENT_ERRORS.has(code) || (firstErr && firstErr.message === 'DNS timeout')) {
        if (forceDebug) console.log(formatLogMessage('debug', `DNS pre-check transient (${code || 'timeout'}) for ${hostname}, retrying once`));
        await attempt(hostname, timeoutMs);
      } else {
        throw firstErr;
      }
    }
  }

  return { resolveHost, servers, rotates: !!pool, pinned: !!override };
}

module.exports = {
  createRotatingResolver,
  parseDnsServers,
  isNonExistenceError,
};
