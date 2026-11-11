#!/usr/bin/env node
/**
 * har-rules.js — turn a browser capture into rules, using a site config's own
 * matching settings.
 *
 *   node scripts/har-rules.js <capture> [--config <config.json>] [--site <n|url>]
 *                             [--include-blocked] [--show-skipped]
 *
 * Takes any of three capture formats, detected by content, not by extension:
 *   - a DevTools HAR            (F12 > Network > right-click > Save All As HAR)
 *   - a Chrome net-log          (chrome --log-net-log=out.json <url>)
 *   - a Firefox MOZ_LOG         (MOZ_LOG=timestamp,nsHttp:5 MOZ_LOG_FILE=... firefox <url>)
 *
 * The point: a real browser with a real content blocker sees request chains the
 * scanner cannot reproduce on its own. Apply the same filterRegex /
 * resourceTypes / party rules the live scan would, then emit through the same
 * formatRules() the scanner uses, so the output is identical in shape to a
 * normal run.
 *
 * Which format to reach for: the net-log and MOZ_LOG need no clicking, just a
 * flag or an environment variable, so they are the ones to automate. Prefer
 * MOZ_LOG when the blocker matters -- Chrome is MV3-only now, so uBO there is
 * uBO Lite on declarativeNetRequest, a weaker blocker, while Firefox still runs
 * full uBO with the user's own rules. Save a HAR when the question is
 * specifically "what did my blocker stop": only there is a blocked request
 * distinguishable, as status 0.
 */

const fs = require('fs');
const path = require('path');
const { matchEntries } = require('../lib/har');
const { pageUrlForSite, urlsOf } = require('../lib/capture');
const { parseCapture } = require('../lib/capture');
const { formatRules } = require('../lib/output');
// Shared with `nwss.js --har`: one copy of the dig/whois confirmation and one
// copy of the config normalization, because these two tools read the same
// config and the same capture and must not disagree. They already did once,
// over even_blocked -- 2 rules through one tool and 5 through the other.
const { confirmCaptureDomains } = require('../lib/capture-confirm');
const { normalizeSiteConfig } = require('../lib/validate_rules');
const { parseDnsServers } = require('../lib/dns');
const { enableDiskCache } = require('../lib/nettools');

const args = process.argv.slice(2);
const harPath = args.find(a => !a.startsWith('--'));
const argOf = (name, dflt = null) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : dflt;
};
if (!harPath) {
  console.error('usage: node scripts/har-rules.js <capture.har|netlog.json> [--config <config.json>] [--site <n|url>] [--include-blocked] [--show-skipped] [--dns <servers>] [--dns-cache]');
  process.exit(1);
}


const configPath = argOf('--config');
let siteConfig = {}, ignoreDomains = [], cfgBlockedList = [], blockByUrl = [], ignoreByUrl = [];
// Same spelling and same source as nwss: a CLI flag, not a config key. nwss
// reads `dns` only from .nwssconfig's per-config settings map, which it turns
// into this very flag, so taking the flag here is what keeps the two tools
// pointed at the same resolver. Without it dig reads /etc/resolv.conf while
// `nwss --har --dns ...` queries the configured servers, and a geo-split host
// can answer differently -- a verdict difference, not a cosmetic one.
const dnsServers = (() => {
  const spec = argOf('--dns');
  return spec ? parseDnsServers(spec) : [];
})();
// Same flag, same meaning, same files as a scan: without it dig/whois results
// live only for this process, so every run of this tool re-queried names the
// scan had already resolved into .digcache. Mirrors nwss.js's own
// `if (dnsCacheMode) enableDiskCache();`.
if (args.includes('--dns-cache')) enableDiskCache();
if (configPath) {
  const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  ignoreDomains = cfg.ignoreDomains || [];
  cfgBlockedList = cfg.blocked || [];
  blockByUrl    = cfg.blockDomainsByUrl || [];
  ignoreByUrl   = cfg.ignoreDomainsByUrl || [];
  const sites = cfg.sites || [];
  const sel = argOf('--site', '0');
  const byIndex = /^\d+$/.test(sel) ? sites[Number(sel)] : null;
  siteConfig = byIndex || sites.find(s =>
    (Array.isArray(s.url) ? s.url : [s.url]).some(u => String(u).includes(sel))) || sites[0] || {};
  // Same normalization a scan runs at startup. Without it `dig: "104.26."` --
  // the string form the live configs use -- stays a string, every downstream
  // Array.isArray() gate disables the feature, and this tool silently skips a
  // confirmation that `nwss --har` performs.
  // Index of the site actually selected, not 0: --site 4 reporting its
  // warnings as "Site 0" sends the reader to the wrong entry.
  const siteIdx = sites.indexOf(siteConfig);
  const { warnings: nWarnings, errors: nErrors } = normalizeSiteConfig(siteConfig, siteIdx >= 0 ? siteIdx : 0);
  for (const e of nErrors) console.warn('⚠ ' + e);
  for (const w of nWarnings) console.warn('⚠ [config] ' + w);
}

let har;
try {
  har = parseCapture(harPath);
} catch (err) {
  console.error(err.message);
  process.exit(1);
}
const format = har.format;
console.log(`\n${har.formatLabel}: ${path.basename(harPath)}`);
console.log(`  saved by      : ${har.creator}`);
console.log(`  page          : ${String(har.pageUrl).slice(0, 72)}`);
console.log(`  requests      : ${har.entries.length}`);
if (har.truncated) {
  console.log('  NOTE          : capture is truncated (browser was killed, not closed) -- ' +
    'everything up to the cut is used');
}
const blockedList = har.entries.filter(e => e.blocked);
if (format === 'mozlog') {
  console.log('  (a MOZ_LOG logs the channel before a blocker cancels it, so blocked');
  console.log('   requests generally DO appear -- it shows what the page TRIED to load.');
  console.log('   Nothing is marked blocked from this source; save a HAR for that.)');
} else if (format === 'netlog') {
  const failed = har.entries.filter(e => e.failed && !e.blocked);
  console.log(`  failed        : ${failed.length}` +
    (failed.length ? '  ' + [...new Set(failed.map(e => e.netError))].slice(0, 5).join(', ') : ''));
  console.log('  (a net-log does not record requests an extension blocked -- save a HAR for those)');
} else {
  console.log(`  blocked (status 0, i.e. your content blocker): ${blockedList.length}`);
  if (blockedList.length) {
    [...new Set(blockedList.map(e => e.host))].forEach(h => console.log(`     x ${h}`));
  }
}
if (configPath) {
  console.log(`  config        : ${path.basename(configPath)} site "${String(siteConfig.url).slice(0, 48)}"`);
  console.log(`  filterRegex   : ${siteConfig.filterRegex || '(none)'}`);
}

// Honour the site's own even_blocked, exactly as nwss.js --har does. Without
// this the two tools gave DIFFERENT rules for the same config and the same
// capture -- this script excluded blocked requests while nwss included them --
// which is the sort of disagreement that quietly discredits both.
const includeBlocked = args.includes('--include-blocked') || siteConfig.even_blocked === true;
// Party must be decided against the page belonging to THIS site, not pages[0]:
// a Chrome HAR saved with "Preserve log" holds one page per navigation. Same
// resolution nwss.js --har uses, so the two tools cannot disagree on it.
const siteUrlsForParty = siteConfig && siteConfig.url ? urlsOf(siteConfig) : [];
const partyPageUrl = pageUrlForSite(har, siteUrlsForParty) || siteUrlsForParty[0] || har.pageUrl;
const { matchedDomains, hostsByKey, stats } = matchEntries(har.entries, siteConfig, {
  pageUrl: partyPageUrl,
  ignoreDomains,
  includeBlocked,
  // Same three keys nwss.js --har now passes. These two tools read the same
  // config and the same capture and must not disagree -- they already did once
  // over even_blocked, which gave 2 rules through one and 5 through the other.
  blocked: cfgBlockedList,
  blockDomainsByUrl: blockByUrl,
  ignoreDomainsByUrl: ignoreByUrl
});

console.log(`\nmatching: ${stats.total} requests -> ${stats.considered} considered -> ${stats.matched} matched` +
  (includeBlocked
    ? ` (blocked requests INCLUDED${siteConfig.even_blocked === true ? ' -- even_blocked is set on this site' : ''})`
    : ` (${stats.skippedBlocked} skipped as blocked)`));

if (args.includes('--show-skipped') && siteConfig.filterRegex) {
  const re = new RegExp(siteConfig.filterRegex);
  const hit = har.entries.filter(e => !e.blocked && re.test(e.url));
  console.log('\nURLs matching the regex:');
  [...new Set(hit.map(e => e.url))].slice(0, 15).forEach(u => console.log(`  ${u.slice(0, 96)}`));
}

// Async only because the confirmation shells out to dig/whois. CommonJS has
// no top-level await, so the tail runs inside an IIFE rather than the script
// being converted to ESM for one call.
(async () => {
  const confirm = await confirmCaptureDomains(matchedDomains, hostsByKey, siteConfig, { dnsServers });
  if (confirm.ran) {
    console.log(`${confirm.tools}: ${confirm.before} candidate(s) -> ${confirm.after} confirmed ` +
      `(${confirm.before - confirm.after} dropped)`);
  }

  const rules = formatRules(matchedDomains, siteConfig, {});
  console.log('\nrules:');
  (Array.isArray(rules) ? rules : String(rules).split('\n')).filter(Boolean)
    .forEach(r => console.log(`  ${r}`));
  console.log('');
})();
