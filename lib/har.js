/**
 * har.js — read a browser-exported HAR and match its requests the way a live
 * scan would.
 *
 * Why this exists: some request chains only appear in a REAL browser with a
 * real content blocker installed. Anti-adblock loaders of the AdShield family
 * walk a fallback list (html-load.cc -> exceptlone.com -> quitcertify.com) only
 * once an actual blocker cancels the earlier hosts; CDP request interception
 * does not trigger it (verified across twelve puppeteer configurations). A HAR
 * saved from that browser carries what the scanner cannot reach itself, and
 * this module feeds it through the same matching rules the live path uses so
 * the output is identical in shape.
 *
 * Firefox HARs carry no _resourceType (that is a Chrome extension to the
 * format), so the type is taken from the request's Sec-Fetch-Dest header,
 * which is present on most entries, and derived from the response mimeType
 * otherwise.
 */

const fs = require('fs');
const psl = require('psl');
const net = require('net');

// Sec-Fetch-Dest values -> the resourceTypes nwss configs use.
const DEST_TO_TYPE = {
  script: 'script', style: 'stylesheet', image: 'image', font: 'font',
  document: 'document', iframe: 'subdocument', frame: 'subdocument',
  empty: 'xhr', object: 'other', embed: 'other', video: 'media',
  audio: 'media', track: 'media', worker: 'script', sharedworker: 'script',
  serviceworker: 'script', manifest: 'other', report: 'ping'
};

const MIME_TO_TYPE = [
  [/^text\/css/, 'stylesheet'],
  [/javascript|ecmascript/, 'script'],
  [/^image\//, 'image'],
  [/^font\/|application\/(x-)?font|\.woff/, 'font'],
  [/^text\/html/, 'document'],
  [/^(audio|video)\//, 'media'],
  [/json|xml/, 'xhr']
];

function rootDomainForHost(hostname) {
  if (!hostname) return '';
  if (net.isIP(hostname)) return hostname;          // bare IPs are their own rule
  const parsed = psl.parse(hostname);
  return (parsed && parsed.domain) || hostname;
}

function typeOf(entry) {
  const headers = (entry.request && entry.request.headers) || [];
  const dest = headers.find(h => h.name && h.name.toLowerCase() === 'sec-fetch-dest');
  if (dest && DEST_TO_TYPE[String(dest.value).toLowerCase()]) {
    return DEST_TO_TYPE[String(dest.value).toLowerCase()];
  }
  const mime = ((entry.response || {}).content || {}).mimeType || '';
  for (const [re, t] of MIME_TO_TYPE) if (re.test(mime)) return t;
  return 'other';
}

/**
 * Parse a HAR into a flat request list.
 * `blocked` is inferred from status 0, which is what a browser-side content
 * blocker produces for a cancelled request -- verified against a Firefox HAR
 * where uBO-blocked hosts carried status 0 while allowed ones carried 200/302.
 */
function parseHar(filePath) {
  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const log = raw.log || {};
  const pages = log.pages || [];
  const entries = (log.entries || []).map(e => {
    const url = (e.request && e.request.url) || '';
    let host = '';
    try { host = new URL(url).hostname; } catch { /* malformed, left blank */ }
    const status = (e.response && e.response.status);
    return {
      url, host,
      rootDomain: rootDomainForHost(host),
      status,
      blocked: status === 0,
      resourceType: typeOf(e),
      mimeType: ((e.response || {}).content || {}).mimeType || ''
    };
  }).filter(e => e.url && /^https?:/i.test(e.url));

  return {
    pageUrl: (pages[0] && pages[0].title) || (entries[0] && entries[0].url) || '',
    creator: `${(log.creator || {}).name || '?'} ${(log.creator || {}).version || ''}`.trim(),
    entries
  };
}

/**
 * Apply a site config's matching rules to parsed HAR entries.
 * Mirrors the live path: filterRegex on the URL, resourceTypes, first/third
 * party relative to the page, and ignoreDomains. Returns the same
 * matchedDomains shape formatRules() expects -- a Map when resource types are
 * wanted (adblock_rules), otherwise a Set.
 */
function matchEntries(entries, siteConfig = {}, options = {}) {
  const { pageUrl = '', ignoreDomains = [], includeBlocked = false } = options;
  const filterRegex = siteConfig.filterRegex
    ? new RegExp(siteConfig.filterRegex)
    : null;
  const wantTypes = siteConfig.resourceTypes
    ? (Array.isArray(siteConfig.resourceTypes) ? siteConfig.resourceTypes : [siteConfig.resourceTypes])
    : null;
  const useSubDomains = siteConfig.subDomains === 1 || siteConfig.subDomains === true;
  const wantFirstParty = siteConfig.firstParty !== false;
  const wantThirdParty = siteConfig.thirdParty !== false;
  let pageRoot = '';
  try { pageRoot = rootDomainForHost(new URL(pageUrl).hostname); } catch { /* none */ }

  const asMap = siteConfig.adblock_rules === true;
  const matched = asMap ? new Map() : new Set();
  const stats = { total: entries.length, considered: 0, matched: 0, skippedBlocked: 0 };

  for (const e of entries) {
    // A blocked request never reached the network; by default it is evidence
    // about the blocker, not about the site, so it is not turned into a rule.
    if (e.blocked && !includeBlocked) { stats.skippedBlocked++; continue; }
    if (!e.host) continue;
    if (ignoreDomains.some(d => e.host === d || e.host.endsWith('.' + d))) continue;
    const isFirstParty = pageRoot && e.rootDomain === pageRoot;
    if (isFirstParty && !wantFirstParty) continue;
    if (!isFirstParty && !wantThirdParty) continue;
    if (wantTypes && !wantTypes.includes(e.resourceType)) continue;
    stats.considered++;
    if (filterRegex && !filterRegex.test(e.url)) continue;
    stats.matched++;
    const key = useSubDomains ? e.host : e.rootDomain;
    if (asMap) {
      if (!matched.has(key)) matched.set(key, new Set());
      matched.get(key).add(e.resourceType);
    } else {
      matched.add(key);
    }
  }
  return { matchedDomains: matched, stats };
}

module.exports = { parseHar, matchEntries, rootDomainForHost };
