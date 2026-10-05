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
const { parseCapture } = require('../lib/capture');
const { formatRules } = require('../lib/output');

const args = process.argv.slice(2);
const harPath = args.find(a => !a.startsWith('--'));
const argOf = (name, dflt = null) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : dflt;
};
if (!harPath) {
  console.error('usage: node scripts/har-rules.js <capture.har|netlog.json> [--config <config.json>] [--site <n|url>] [--include-blocked] [--show-skipped]');
  process.exit(1);
}


const configPath = argOf('--config');
let siteConfig = {}, ignoreDomains = [];
if (configPath) {
  const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  ignoreDomains = cfg.ignoreDomains || [];
  const sites = cfg.sites || [];
  const sel = argOf('--site', '0');
  const byIndex = /^\d+$/.test(sel) ? sites[Number(sel)] : null;
  siteConfig = byIndex || sites.find(s =>
    (Array.isArray(s.url) ? s.url : [s.url]).some(u => String(u).includes(sel))) || sites[0] || {};
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

const { matchedDomains, stats } = matchEntries(har.entries, siteConfig, {
  pageUrl: har.pageUrl,
  ignoreDomains,
  includeBlocked: args.includes('--include-blocked')
});

console.log(`\nmatching: ${stats.total} requests -> ${stats.considered} considered -> ${stats.matched} matched` +
  ` (${stats.skippedBlocked} skipped as blocked)`);

if (args.includes('--show-skipped') && siteConfig.filterRegex) {
  const re = new RegExp(siteConfig.filterRegex);
  const hit = har.entries.filter(e => !e.blocked && re.test(e.url));
  console.log('\nURLs matching the regex:');
  [...new Set(hit.map(e => e.url))].slice(0, 15).forEach(u => console.log(`  ${u.slice(0, 96)}`));
}

const rules = formatRules(matchedDomains, siteConfig, {});
console.log('\nrules:');
(Array.isArray(rules) ? rules : String(rules).split('\n')).filter(Boolean)
  .forEach(r => console.log(`  ${r}`));
console.log('');
