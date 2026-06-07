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

// Accept a bare IPv4/IPv6 address, or an address with a port in the exact form
// Resolver.setServers() understands: `ipv4:port` or `[ipv6]:port`.
function isResolverSpec(s) {
  if (net.isIP(s)) return true;
  const bracketed = s.match(/^\[([0-9a-fA-F:]+)\](?::\d{1,5})?$/);
  if (bracketed) return net.isIP(bracketed[1]) === 6;
  const v4port = s.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/);
  if (v4port) return net.isIP(v4port[1]) === 4;
  return false;
}

/**
 * Parse + validate a `--dns` / config value into a clean, de-duplicated server
 * list. Accepts a comma-separated string or an array. Each entry may be a bare
 * IPv4/IPv6 address or an address with a port (`8.8.8.8:5353`,
 * `[2001:db8::1]:5353`) — the form setServers() accepts. Invalid entries are
 * warned and dropped; duplicates are collapsed so the rotation stays even.
 * @param {string|string[]|undefined} raw
 * @returns {string[]} validated server specs (possibly empty)
 */
function parseDnsServers(raw) {
  if (!raw) return [];
  const parts = (Array.isArray(raw) ? raw : String(raw).split(','))
    .map(s => String(s).trim())
    .filter(Boolean);
  const valid = [];
  const seen = new Set();
  for (const p of parts) {
    if (!isResolverSpec(p)) {
      console.warn(`⚠ --dns: ignoring invalid server "${p}" (expected IPv4/IPv6, optionally with :port)`);
      continue;
    }
    if (!seen.has(p)) { seen.add(p); valid.push(p); }
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
      // setServers accepts exactly what we hold here: getServers()'s own output
      // (system path) or net-validated specs incl. ip:port (override path).
      // Keep the resolver's default servers if an entry is somehow rejected.
      try { r.setServers([...servers.slice(i), ...servers.slice(0, i)]); } catch { /* keep default */ }
      return r;
    });
  }

  let cursor = 0;
  // Resolver for the next attempt: rotated when a pool exists, else the global
  // promises API. `cursor++` is a synchronous single-threaded increment, so even
  // under heavy concurrency every caller gets a distinct slot and the lead
  // distribution stays exactly even (no locking needed).
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

/**
 * Circuit breaker for the DNS pre-check. During a resolver-refusal storm the
 * pre-check is worthless (every host fails open and proceeds anyway) and
 * actively harmful (it piles ~2× the queries — with the retry — onto an
 * already-refusing resolver). This trips when resolver errors dominate a recent
 * window of attempts and suspends pre-checking for a cooldown so the resolver
 * gets breathing room; sites still load (a suspended pre-check just proceeds to
 * navigation, exactly like a single fail-open). NXDOMAIN and success count as
 * HEALTHY (the resolver answered) — only resolver errors (EREFUSED / ESERVFAIL
 * / ETIMEOUT / ECONNREFUSED / timeout) count against it.
 *
 * @param {object} [opts]
 * @param {number} [opts.window=20]        attempts kept in the rolling window
 * @param {number} [opts.threshold=10]     resolver-errors in the window to trip
 * @param {number} [opts.cooldownMs=30000] how long to stay suspended once tripped
 * @param {boolean} [opts.forceDebug]
 * @param {function} [opts.now]            clock injection (tests); defaults to Date.now
 * @returns {{ record:(isResolverError:boolean)=>void, isTripped:()=>boolean,
 *   stats:()=>{tripped:boolean,errorCount:number,windowFill:number,trips:number} }}
 */
function createDnsCircuitBreaker(opts = {}) {
  const windowSize = opts.window || 20;
  const threshold = opts.threshold || 10;
  const cooldownMs = opts.cooldownMs != null ? opts.cooldownMs : 30000;
  const forceDebug = !!opts.forceDebug;
  const now = opts.now || Date.now;

  const recent = [];   // booleans, true = resolver error
  let errorCount = 0;
  let openUntil = 0;   // suspended while now() < openUntil
  let trips = 0;

  // Feed one resolve outcome. Only ever called while closed (a suspended
  // pre-check skips the resolve, so no outcome is produced).
  function record(isResolverError) {
    recent.push(!!isResolverError);
    if (isResolverError) errorCount++;
    if (recent.length > windowSize && recent.shift()) errorCount--;

    if (now() >= openUntil && errorCount >= threshold) {
      openUntil = now() + cooldownMs;
      trips++;
      console.log(formatLogMessage('warn', `[dns-precheck] resolver errors ${errorCount}/${recent.length} — suspending DNS pre-check ${Math.round(cooldownMs / 1000)}s (sites still load; backing off the resolver)`));
    }
  }

  // True while suspended. On the first call after the cooldown elapses, resume
  // with a clean window so the storm is re-measured fresh rather than re-tripping
  // on stale errors.
  function isTripped() {
    if (now() < openUntil) return true;
    if (openUntil !== 0) {
      openUntil = 0;
      recent.length = 0;
      errorCount = 0;
      if (forceDebug) console.log(formatLogMessage('debug', '[dns-precheck] cooldown elapsed — resuming DNS pre-check'));
    }
    return false;
  }

  return {
    record,
    isTripped,
    stats: () => ({ tripped: now() < openUntil, errorCount, windowFill: recent.length, trips }),
  };
}

// Map well-known public resolver IPs to their DNS-over-HTTPS (DoH) endpoint
// templates. Chrome's page-navigation resolver ignores --dns and reads
// /etc/resolv.conf directly; pointing Chrome's *secure* DoH at the same
// provider the --dns pre-check uses closes that gap, so a broken or filtering
// system resolv.conf can't fail navigations the pre-check already passed.
// Only the unambiguous public providers are mapped — resolvers with
// per-account templates (NextDNS, AdGuard personal) can't be derived from an
// IP and fall through to `unmapped` (Chrome stays on system DNS for those).
const DOH_PROVIDER_TEMPLATES = {
  '8.8.8.8': 'https://dns.google/dns-query',
  '8.8.4.4': 'https://dns.google/dns-query',
  '1.1.1.1': 'https://cloudflare-dns.com/dns-query',
  '1.0.0.1': 'https://cloudflare-dns.com/dns-query',
  '9.9.9.9': 'https://dns.quad9.net/dns-query',
  '149.112.112.112': 'https://dns.quad9.net/dns-query',
  '208.67.222.222': 'https://doh.opendns.com/dns-query',
  '208.67.220.220': 'https://doh.opendns.com/dns-query',
};

/**
 * Resolve a list of --dns resolver specs to Chrome DoH templates.
 * Strips any :port (DoH is always 443) and dedupes. Returns the
 * space-joined template string Chrome's --dns-over-https-templates wants,
 * plus which inputs were mapped vs had no known DoH endpoint.
 * @param {string[]} servers - resolver IPs (optionally ip:port) from --dns
 * @returns {{ templates: string, mapped: string[], unmapped: string[] }}
 */
function dohTemplatesForResolvers(servers) {
  const templates = [];
  const mapped = [];
  const unmapped = [];
  for (const raw of (servers || [])) {
    const ip = String(raw).trim().replace(/:\d+$/, ''); // drop :port — DoH is 443
    if (!ip) continue;
    const tpl = DOH_PROVIDER_TEMPLATES[ip];
    if (tpl) {
      if (!templates.includes(tpl)) templates.push(tpl);
      mapped.push(ip);
    } else {
      unmapped.push(ip);
    }
  }
  return { templates: templates.join(' '), mapped, unmapped };
}

module.exports = {
  createRotatingResolver,
  createDnsCircuitBreaker,
  parseDnsServers,
  isNonExistenceError,
  dohTemplatesForResolvers,
};
