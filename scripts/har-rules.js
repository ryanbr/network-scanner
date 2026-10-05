#!/usr/bin/env node
/**
 * har-rules.js — turn a browser capture into rules, using a site config's own
 * matching settings.
 *
 *   node scripts/har-rules.js <capture> [--config <config.json>] [--site <n|url>]
 *                             [--include-blocked] [--show-skipped]
 *
 * Takes either capture format, detected by content, not by extension:
 *   - a DevTools HAR            (F12 > Network > right-click > Save All As HAR)
 *   - a Chrome net-log          (chrome --log-net-log=out.json <url>)
 *
 * The point: a real browser with a real content blocker sees request chains the
 * scanner cannot reproduce on its own. Apply the same filterRegex /
 * resourceTypes / party rules the live scan would, then emit through the same
 * formatRules() the scanner uses, so the output is identical in shape to a
 * normal run.
 *
 * Which format to reach for: the net-log needs no clicking, just a flag, so it
 * is the one to automate. But it omits extension-blocked requests entirely
 * (measured -- see lib/netlog.js), so if the question is "what did my blocker
 * stop", save a HAR, where those arrive as status 0.
 */

const fs = require('fs');
const path = require('path');
const { parseHar, matchEntries } = require('../lib/har');
const { parseNetLog } = require('../lib/netlog');
const { formatRules } = require('../lib/output');

/**
 * Tell the two capture formats apart by looking at the head of the file: a
 * net-log opens {"constants":{, a HAR has a top-level "log". Extension is no
 * guide -- both are commonly .json, and Firefox names HARs .har.
 */
function sniffFormat(filePath) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.allocUnsafe(4096);
    const n = fs.readSync(fd, buf, 0, 4096, 0);
    const head = buf.toString('utf8', 0, n);
    if (/^\s*\{\s*"constants"\s*:/.test(head)) return 'netlog';
    if (/"log"\s*:/.test(head)) return 'har';
    return 'unknown';
  } finally { fs.closeSync(fd); }
}

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
if (!fs.existsSync(harPath)) {
  console.error(`not found: ${harPath}`);
  process.exit(1);
}
const format = sniffFormat(harPath);
if (format === 'unknown') {
  console.error(`${harPath}: not a DevTools HAR or a Chrome net-log (expected a top-level "log" or "constants")`);
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

const har = format === 'netlog' ? parseNetLog(harPath) : parseHar(harPath);
console.log(`\n${format === 'netlog' ? 'net-log' : 'HAR'}: ${path.basename(harPath)}`);
console.log(`  saved by      : ${har.creator}`);
console.log(`  page          : ${String(har.pageUrl).slice(0, 72)}`);
console.log(`  requests      : ${har.entries.length}`);
if (har.truncated) {
  console.log('  NOTE          : capture is truncated (browser was killed, not closed) -- ' +
    'everything up to the cut is used');
}
const blockedList = har.entries.filter(e => e.blocked);
if (format === 'netlog') {
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
