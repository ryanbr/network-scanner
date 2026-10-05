#!/usr/bin/env node
/**
 * bait-confirm.js — confirm that domains found by the bait walk really belong
 * to the loader's operator, using dig and whois.
 *
 *   node scripts/bait-confirm.js --config <cfg> --site <sel> [--baits <file>]
 *                               [--strict] [--json]
 *
 * Why this is separate from the walk: discovery is regex-only, by design. The
 * walk finds hosts by the loader PATH and PAC-blocks them immediately, so a
 * loose pattern could in principle drag an unrelated domain into the block set
 * and quietly distort every later round. Confirmation is the second opinion,
 * and it is deliberately NOT a gate by default -- the operator controls their
 * own DNS, so a genuine bait moved to another account would fail a strict check
 * and be dropped. Report loudly, refuse only when asked (--strict).
 *
 * Config keys, matching the vocabulary nwss already uses for `dig`/`whois`:
 *
 *   bait_dig:        "term" | ["t1","t2"]   ALL terms must appear  (AND)
 *   bait_dig-or:     ["t1","t2"]            ANY term                (OR)
 *   bait_whois:      "term" | ["t1","t2"]   ALL terms               (AND)
 *   bait_whois-or:   ["t1","t2"]            ANY term                (OR)
 *
 * Terms are matched case-insensitively against the raw tool output, exactly as
 * the live-scan `dig`/`whois` options do, so an existing `dig: "104.26."` style
 * prefix works unchanged. Measured on the jmty chain: every bait domain carries
 * houston.ns.cloudflare.com + veda.ns.cloudflare.com, which none of the
 * unrelated ad domains on the same pages do.
 */

const fs = require('fs');
const path = require('path');
const { runProcess } = require('../lib/spawn-async');
const { messageColors, formatLogMessage } = require('../lib/colorize');

const TAG = messageColors.processing('[bait-confirm]');
const TOOL_TIMEOUT_MS = 15000;

const args = process.argv.slice(2);
const argOf = (name, dflt = null) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : dflt;
};
const asList = v => (v === undefined || v === null) ? [] : (Array.isArray(v) ? v : [v]).filter(Boolean).map(String);

const configPath = argOf('--config');
const baitsPath = argOf('--baits', '/mnt/c/nwss-har/capture-baits.txt');
const strict = args.includes('--strict');
const asJson = args.includes('--json');

if (!configPath) {
  console.error('usage: node scripts/bait-confirm.js --config <config.json> [--site <n|url>] [--baits <file>] [--strict] [--json]');
  process.exit(1);
}
if (!fs.existsSync(baitsPath)) {
  console.error(`bait list not found: ${baitsPath} (run win-bait-walk.ps1 first)`);
  process.exit(1);
}

const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const sites = cfg.sites || [];
const sel = argOf('--site', '0');
const site = (/^\d+$/.test(sel) ? sites[Number(sel)] : null) ||
  sites.find(s => (Array.isArray(s.url) ? s.url : [s.url]).some(u => String(u).includes(sel))) ||
  sites[0] || {};

// Site-level first, then global, so one chain's fingerprint can live beside a
// shared default without repeating it per site.
const pick = key => (site[key] !== undefined ? site[key] : cfg[key]);
const digAll = asList(pick('bait_dig'));
const digAny = asList(pick('bait_dig-or'));
const whoisAll = asList(pick('bait_whois'));
const whoisAny = asList(pick('bait_whois-or'));

if (!digAll.length && !digAny.length && !whoisAll.length && !whoisAny.length) {
  console.error(`${TAG} nothing to check: set bait_dig / bait_dig-or / bait_whois / bait_whois-or in the config`);
  process.exit(1);
}

const domains = fs.readFileSync(baitsPath, 'utf8')
  .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));

async function tool(cmd, cmdArgs) {
  const r = await runProcess(cmd, cmdArgs, { timeout: TOOL_TIMEOUT_MS, maxBuffer: 1 << 20 });
  // runProcess resolves rather than rejects; a missing tool shows as error.
  if (r.error) return { ok: false, out: '', why: r.error.message || String(r.error) };
  return { ok: r.code === 0, out: (r.stdout || '') + (r.stderr || ''), why: r.code === 0 ? '' : `exit ${r.code}` };
}

// ALL / ANY exactly as the live-scan dig/whois options define them.
const matchAll = (out, terms) => terms.every(t => out.toLowerCase().includes(t.toLowerCase()));
const matchAny = (out, terms) => terms.some(t => out.toLowerCase().includes(t.toLowerCase()));

(async () => {
  const results = [];
  for (const d of domains) {
    const row = { domain: d, dig: null, whois: null, confirmed: null, notes: [] };

    if (digAll.length || digAny.length) {
      // ANY record type the terms might name: A for ip prefixes, NS for the
      // nameserver fingerprint. One call each, concatenated.
      const [a, ns] = await Promise.all([tool('dig', ['+short', d, 'A']), tool('dig', ['+short', d, 'NS'])]);
      const out = `${a.out}\n${ns.out}`;
      // ERROR is not the same as NO MATCH. Conflating them meant a missing dig
      // binary or a dns blip reported every genuine bait as unconfirmed, and
      // --strict then rejected the lot -- measured with dig off PATH: 0/6.
      if (!a.ok && !ns.ok) { row.notes.push(`dig failed: ${a.why || ns.why}`); row.dig = 'error'; }
      else {
        row.dig = (digAll.length ? matchAll(out, digAll) : true) &&
                  (digAny.length ? matchAny(out, digAny) : true);
      }
    }

    if (whoisAll.length || whoisAny.length) {
      const w = await tool('whois', [d]);
      if (!w.ok && !w.out) { row.notes.push(`whois failed: ${w.why}`); row.whois = 'error'; }
      else {
        row.whois = (whoisAll.length ? matchAll(w.out, whoisAll) : true) &&
                    (whoisAny.length ? matchAny(w.out, whoisAny) : true);
      }
    }

    const checks = [row.dig, row.whois].filter(v => v !== null);
    const failed = checks.filter(v => v === false).length;
    const errored = checks.filter(v => v === 'error').length;
    row.verdict = failed > 0 ? 'mismatch' : (errored > 0 ? 'unknown' : (checks.length ? 'confirmed' : 'unknown'));
    row.confirmed = row.verdict === 'confirmed';
    results.push(row);
  }

  if (asJson) {
    console.log(JSON.stringify({ baits: baitsPath, site: site.url, results }, null, 2));
  } else {
    console.log(`\n${TAG} ${domains.length} bait domain(s) from ${path.basename(baitsPath)}`);
    if (digAll.length) console.log(`  bait_dig (ALL)      : ${digAll.join(', ')}`);
    if (digAny.length) console.log(`  bait_dig-or (ANY)   : ${digAny.join(', ')}`);
    if (whoisAll.length) console.log(`  bait_whois (ALL)    : ${whoisAll.join(', ')}`);
    if (whoisAny.length) console.log(`  bait_whois-or (ANY) : ${whoisAny.join(', ')}`);
    console.log('');
    for (const r of results) {
      const f = v => v === null ? '  -  ' : (v === 'error' ? ' err ' : (v ? ' yes ' : ' NO  '));
      const verdict = r.verdict === 'confirmed' ? messageColors.success('confirmed')
        : r.verdict === 'mismatch' ? messageColors.warn('MISMATCH')
          : messageColors.warn('UNKNOWN (lookup failed)');
      console.log(`  ${r.domain.padEnd(26)} dig:${f(r.dig)} whois:${f(r.whois)}  ${verdict}`);
      r.notes.forEach(n => console.log(formatLogMessage('debug', `${TAG}   ${n}`)));
    }
    const mismatched = results.filter(r => r.verdict === 'mismatch');
    const unknown = results.filter(r => r.verdict === 'unknown');
    console.log('');
    console.log(`  ${results.filter(r => r.confirmed).length}/${results.length} confirmed` +
      (mismatched.length ? ` — MISMATCH: ${mismatched.map(r => r.domain).join(', ')}` : '') +
      (unknown.length ? ` — could not check: ${unknown.map(r => r.domain).join(', ')}` : ''));
    if (unknown.length) {
      console.log(formatLogMessage('warn',
        `${TAG} ${unknown.length} domain(s) could not be checked (tool missing or lookup failed) — that is NOT a mismatch`));
    }
    if (mismatched.length && !strict) {
      console.log(formatLogMessage('warn',
        `${TAG} reported, not enforced. A genuine bait moved to other DNS would fail this; use --strict to exit non-zero.`));
    }
  }

  // Exit codes keep the two apart: 1 means a domain really did not match, 2
  // means it could not be checked. Treating a dns failure as a rejection is
  // how a transient blip would drop a real bait from the list.
  const mismatched = results.filter(r => r.verdict === 'mismatch').length;
  const unknown = results.filter(r => r.verdict === 'unknown').length;
  if (!strict) process.exit(0);
  process.exit(mismatched ? 1 : (unknown ? 2 : 0));
})().catch(err => {
  console.error(formatLogMessage('error', `${TAG} ${err.message}`));
  process.exit(1);
});
