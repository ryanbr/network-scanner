/**
 * dig / whois confirmation for the capture (--har) path.
 *
 * The live scan withholds a domain until nettools confirms it -- nwss.js:
 * "if nettools validation is required ... NEVER add domains immediately".
 * Neither capture consumer did: createNetToolsHandler is only constructed
 * inside processUrl, which the `--har` branch returns thousands of lines
 * before, and scripts/har-rules.js never had a nettools path at all. One
 * config therefore produced different rules depending on which of the three
 * entry points read it, and the two capture ones produced the LARGER set --
 * which reads as success rather than as a bug.
 *
 * It lives in its own module rather than in either caller because this
 * codebase has already paid for duplicated logic twice: har-rules.js and
 * `nwss --har` disagreed over even_blocked (2 rules against 5 for the same
 * capture), and extractDomainFromRule exists in two files that broke once
 * each, in opposite directions, with nothing comparing them. One copy, two
 * callers, and scripts/test-capture-mode.js pins that they agree.
 *
 * nettools owns the handler, the .digcache/.whoiscache and the availability
 * checks; har owns root-domain derivation. Importing both here keeps
 * lib/nettools.js free of a dependency on the capture format modules.
 */

const fs = require('fs');
const { createNetToolsHandler, validateDigAvailability, validateWhoisAvailability,
        loadDnsIgnore, setDigResolvers } = require('./nettools');
const { rootDomainForHost } = require('./har');
const { formatLogMessage } = require('./colorize');

// .dnsignore holds the domains the operator has marked as not worth a dig
// confirmation. nwss loads it at startup for every run including --har;
// har-rules.js never did, so the same domain was EXEMPT from confirmation in
// one tool and dug -- and therefore dropped -- in the other. Sharing the
// confirmation logic did not fix that, because what differed was the global
// state the logic reads. Loaded here, once per process, so neither caller can
// forget. Idempotent in practice: the second read refills the same Set.
let dnsIgnoreLoaded = false;
function ensureDnsIgnoreLoaded() {
  if (dnsIgnoreLoaded) return;
  dnsIgnoreLoaded = true;
  try { loadDnsIgnore(); } catch { /* absent or unreadable: no exemptions */ }
}

/**
 * The live path's own derivation, which is literally this: nwss.js's
 * getRootDomain is `rootDomainForHost(new URL(url).hostname)`. Defaulted here
 * so a caller that has no copy of it cannot diverge by supplying a different
 * one -- the whois branch asks for the root of a domain and must get the same
 * answer in a scan, in `nwss --har` and in har-rules.js.
 */
function defaultGetRootDomain(url) {
  try { return rootDomainForHost(new URL(url).hostname); }
  catch { return ''; }
}

/**
 * Apply a site's dig/whois terms to the domains a capture matched, removing
 * those that do not confirm. Mutates `matchedDomains` in place and returns
 * what happened, so each caller can word its own summary line.
 *
 * @param {Set|Map} matchedDomains - matchEntries' output; a Map when
 *        adblock_rules is set, otherwise a Set. Both expose keys()/delete()/
 *        size, which is why one loop handles either.
 * @param {Map<string,Set<string>>} hostsByKey - the real hosts behind each
 *        output key, from matchEntries. The key is not always a resolvable
 *        name (output_regex rewrites it; rootDomain/subDomains collapse
 *        several hosts into one), and nettools' root-then-subdomain recovery
 *        needs the host it was handed.
 * @param {object} siteConfig - already through normalizeSiteConfig, so
 *        dig/whois are arrays rather than the string form configs use.
 * @param {object} options
 * @returns {Promise<{ran: boolean, before: number, after: number, tools: string}>}
 */
async function confirmCaptureDomains(matchedDomains, hostsByKey, siteConfig = {}, options = {}) {
  const {
    whoisDelay,
    whoisServerMode = 'random',
    processedWhoisDomains,
    processedDigDomains,
    getRootDomain = defaultGetRootDomain,
    dnsServers = null,
    debugLogFile = null,
    forceDebug = false,
    // The handler's late-ignore guard. It exists for the live path, where a
    // domain can become ignored during the async whois/dig window via
    // ignoreDomainsByUrl on a sibling request. A capture is a recording with
    // a static list that matchEntries has already applied, so a caller that
    // omits these loses nothing -- both default to a no-op in the handler.
    ignoreDomains = null,
    matchesIgnoreDomain = null,
    onWarn = (msg) => console.warn(formatLogMessage('warn', msg))
  } = options;

  const size = matchedDomains && typeof matchedDomains.size === 'number' ? matchedDomains.size : 0;
  const result = { ran: false, before: size, after: size, tools: '' };

  const digTerms = Array.isArray(siteConfig.dig) ? siteConfig.dig : null;
  const digOrTerms = Array.isArray(siteConfig['dig-or']) ? siteConfig['dig-or'] : null;
  const whoisTerms = Array.isArray(siteConfig.whois) ? siteConfig.whois : null;
  const whoisOrTerms = Array.isArray(siteConfig['whois-or']) ? siteConfig['whois-or'] : null;
  if (!(digTerms || digOrTerms || whoisTerms || whoisOrTerms) || size === 0) return result;

  ensureDnsIgnoreLoaded();
  // dig otherwise reads /etc/resolv.conf. nwss points it at the --dns servers
  // before the capture branch; har-rules.js had no equivalent, so the two
  // tools could resolve a geo-split host to different addresses and reach
  // different verdicts from the same config. Verdict-relevant, so it is
  // shared; dig_max_concurrent and the retry knobs stay CLI-only in nwss
  // because they change throughput, not the answer.
  if (Array.isArray(dnsServers) && dnsServers.length > 0) setDigResolvers(dnsServers);

  // Availability is checked the way the live path checks it, and a missing
  // tool degrades the same way: warn, skip that confirmation, keep the
  // domains. Dropping every rule because dig is not installed would be the
  // worse failure, and it is the same mistake in the other direction.
  let runDig = !!(digTerms || digOrTerms);
  let runWhois = !!(whoisTerms || whoisOrTerms);
  if (runDig) {
    const c = validateDigAvailability();
    if (!c.isAvailable) {
      runDig = false;
      onWarn(`Dig not available: ${c.error}. Skipping dig confirmation for this capture.`);
    }
  }
  if (runWhois) {
    const c = validateWhoisAvailability();
    if (!c.isAvailable) {
      runWhois = false;
      onWarn(`Whois not available: ${c.error}. Skipping whois confirmation for this capture.`);
    }
  }
  if (!runDig && !runWhois) return result;

  const confirmed = new Set();
  const netTools = createNetToolsHandler({
    whoisTerms: runWhois ? whoisTerms : null,
    whoisOrTerms: runWhois ? whoisOrTerms : null,
    digTerms: runDig ? digTerms : null,
    digOrTerms: runDig ? digOrTerms : null,
    digRecordType: siteConfig.digRecordType || 'A',
    digSubdomain: siteConfig.dig_subdomain === true,
    ...(whoisDelay !== undefined ? { whoisDelay } : {}),
    whoisServer: siteConfig.whois_server || null,
    whoisServerMode: siteConfig.whois_server_mode || whoisServerMode,
    ...(processedWhoisDomains ? { processedWhoisDomains } : {}),
    ...(processedDigDomains ? { processedDigDomains } : {}),
    matchedDomains: confirmed,
    addMatchedDomain: (d) => { confirmed.add(d); },
    // Every key here is a candidate awaiting judgement; the live path's
    // "already detected" short-circuit would skip the very check this
    // module exists to perform.
    isDomainAlreadyDetected: () => false,
    getRootDomain,
    siteConfig,
    debugLogFile,
    forceDebug,
    fs,
    ignoreDomains,
    matchesIgnoreDomain
  });

  // A key survives if ANY of its hosts confirms, which is what the live path
  // does: it adds the output domain on the first request that confirms.
  // .keys() is deliberate -- it is an alias of .values() on a Set, so one
  // loop handles both shapes matchEntries can return.
  await Promise.all([...matchedDomains.keys()].map(async (key) => {
    const hosts = hostsByKey && hostsByKey.get ? hostsByKey.get(key) : null;
    for (const host of (hosts && hosts.size ? [...hosts] : [key])) {
      await netTools(key, host);
      if (confirmed.has(key)) return;
    }
  }));
  for (const key of [...matchedDomains.keys()]) {
    if (!confirmed.has(key)) matchedDomains.delete(key);
  }

  result.ran = true;
  result.after = matchedDomains.size;
  result.tools = [runDig ? 'dig' : null, runWhois ? 'whois' : null].filter(Boolean).join('+');
  return result;
}

module.exports = { confirmCaptureDomains };
