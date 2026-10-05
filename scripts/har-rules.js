#!/usr/bin/env node
/**
 * har-rules.js — turn a browser-saved HAR into rules, using a site config's
 * own matching settings.
 *
 *   node scripts/har-rules.js <file.har> [--config <config.json>] [--site <n|url>]
 *                             [--include-blocked] [--show-skipped]
 *
 * The point: a real browser with a real content blocker sees request chains the
 * scanner cannot reproduce on its own (anti-adblock fallback lists only walk
 * when an actual blocker cancels the earlier hosts). Save a HAR from that
 * browser, and this applies the same filterRegex / resourceTypes / party rules
 * the live scan would, then emits through the same formatRules() the scanner
 * uses, so the output is identical in shape to a normal run.
 */

const fs = require('fs');
const path = require('path');
const { parseHar, matchEntries } = require('../lib/har');
const { formatRules } = require('../lib/output');

const args = process.argv.slice(2);
const harPath = args.find(a => !a.startsWith('--'));
const argOf = (name, dflt = null) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : dflt;
};
if (!harPath) {
  console.error('usage: node scripts/har-rules.js <file.har> [--config <config.json>] [--site <n|url>] [--include-blocked] [--show-skipped]');
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

const har = parseHar(harPath);
console.log(`\nHAR: ${path.basename(harPath)}`);
console.log(`  saved by      : ${har.creator}`);
console.log(`  page          : ${String(har.pageUrl).slice(0, 72)}`);
console.log(`  requests      : ${har.entries.length}`);
const blockedList = har.entries.filter(e => e.blocked);
console.log(`  blocked (status 0, i.e. your content blocker): ${blockedList.length}`);
if (blockedList.length) {
  [...new Set(blockedList.map(e => e.host))].forEach(h => console.log(`     x ${h}`));
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
