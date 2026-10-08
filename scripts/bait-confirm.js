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
const { loadDiskCache, saveDiskCache } = require('../lib/nettools');
const { messageColors, formatLogMessage } = require('../lib/colorize');
const { guardBait } = require('../lib/baitguard');

const TAG = messageColors.processing('[bait-confirm]');
const TOOL_TIMEOUT_MS = 15000;

// Same mechanics and TTLs as the scan's dig/whois caches, but a SEPARATE file.
// Sharing .whoiscache would mean writing a different entry shape into it --
// nettools stores { result: <whoisResult>, timestamp, hostname } and reads
// cachedEntry.result expecting its own object -- so a shared file would corrupt
// the scan's whois path. Caching matters most for whois: registries rate-limit
// aggressively, and re-running the walk re-queries the same handful of domains.
const CACHE_FILE = path.join(__dirname, '..', '.baitcache');
const DIG_TTL_MS = 20 * 60 * 60 * 1000;        // 20h, as the scan uses for dig
const WHOIS_TTL_MS = 36 * 60 * 60 * 1000;      // 36h, as the scan uses for whois
const CACHE_MAX = 2000;
const cache = new Map();

const args = process.argv.slice(2);
const argOf = (name, dflt = null) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : dflt;
};
const asList = v => (v === undefined || v === null) ? [] : (Array.isArray(v) ? v : [v]).filter(Boolean).map(String);

const configPath = argOf('--config');
const baitsPath = argOf('--baits', '/mnt/c/nwss-har/capture-baits.txt');
// Optional sidecar written by win-bait-walk.ps1: "<root>\t<name that satisfied
// the gate>". It exists because a bait list holds ROOTS, and this operator runs a
// family whose apex is parked -- ickaside.com and goshupward.com both resolve to
// 3.33.251.168 (AWS Global Accelerator, shared by countless parked domains) while
// only the serving subdomain CNAMEs to sdi.html-load.com. Digging the root alone
// reported both MISMATCH and dropped them from the output, after the walk had
// already CONFIRMED them. Checking the root is still tried first; the sidecar name
// is a second chance, never a replacement.
const hostsPath = argOf('--hosts', null);
const confirmHost = new Map();
if (hostsPath && fs.existsSync(hostsPath)) {
  for (const line of fs.readFileSync(hostsPath, 'utf8').split('\n')) {
    const [root, host] = line.replace(/\r/g, '').split('\t');
    if (root && host && root.trim() && host.trim()) confirmHost.set(root.trim(), host.trim());
  }
}
const strict = args.includes('--strict');
const useCache = !args.includes('--no-cache');
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

let cacheHits = 0, cacheMisses = 0;

async function tool(cmd, cmdArgs, cacheKey, ttl) {
  if (useCache && cacheKey) {
    const hit = cache.get(cacheKey);
    if (hit && (Date.now() - hit.timestamp) < ttl) { cacheHits++; return hit.result; }
  }
  const r = await runProcess(cmd, cmdArgs, { timeout: TOOL_TIMEOUT_MS, maxBuffer: 1 << 20 });
  // runProcess resolves rather than rejects; a missing tool shows as error.
  const out = r.error
    ? { ok: false, out: '', why: r.error.message || String(r.error) }
    : { ok: r.code === 0, out: (r.stdout || '') + (r.stderr || ''), why: r.code === 0 ? '' : `exit ${r.code}` };
  // Never cache a FAILURE: a missing binary or a timeout would otherwise pin
  // "unknown" for the whole TTL and keep reporting it long after the cause is
  // gone. Only a real answer is worth remembering.
  if (useCache && cacheKey && out.ok) { cache.set(cacheKey, { result: out, timestamp: Date.now() }); cacheMisses++; }
  else if (cacheKey) cacheMisses++;
  return out;
}

// ALL / ANY exactly as the live-scan dig/whois options define them.
const matchAll = (out, terms) => terms.every(t => out.toLowerCase().includes(t.toLowerCase()));
const matchAny = (out, terms) => terms.some(t => out.toLowerCase().includes(t.toLowerCase()));

(async () => {
  if (useCache) { try { loadDiskCache(CACHE_FILE, cache, Math.max(DIG_TTL_MS, WHOIS_TTL_MS), CACHE_MAX); } catch { /* cold start */ } }
  const results = [];
  for (const d0 of domains) {
    // Guard the walk's root reduction BEFORE spending lookups on it. Get-Root
    // uses a 26-entry suffix list, not the public suffix list, so a bait under
    // an unlisted multi-part suffix arrives reduced one label too far --
    // "co.il" rather than bait.co.il. The dig gate is satisfied by the sidecar
    // alone, so such a root could reach "confirmed" and publish ||co.il^.
    // See lib/baitguard.js for the measurement.
    const g = guardBait(d0, confirmHost);
    if (g.reject) {
      results.push({ domain: d0, dig: null, whois: null, confirmed: false, verdict: 'rejected', notes: [g.reject] });
      continue;
    }
    // Re-key the sidecar whenever the name changed -- by repair OR by
    // normalisation -- so the dig below still finds the name the gate matched,
    // which is the only reason a repair is trustworthy at all.
    if (g.via) confirmHost.set(g.domain, g.via);
    const d = g.domain;
    const row = { domain: d, dig: null, whois: null, confirmed: null, notes: g.note ? [g.note] : [] };
    let hadAlt = false;

    if (digAll.length || digAny.length) {
      // ANY record type the terms might name: A for ip prefixes, NS for the
      // nameserver fingerprint. One call each, concatenated.
      const [a, ns] = await Promise.all([
        tool('dig', ['+short', d, 'A'], `dig:A:${d}`, DIG_TTL_MS),
        tool('dig', ['+short', d, 'NS'], `dig:NS:${d}`, DIG_TTL_MS)
      ]);
      let out = `${a.out}\n${ns.out}`;
      let digOk = a.ok || ns.ok;
      // Only reach for the sidecar when the root did not satisfy the terms --
      // two extra lookups per domain, and only for the hosts that need them.
      const alt = confirmHost.get(d);
      // Whether a sidecar name was available at all. This is the difference
      // between "we checked the right names and they do not match" and "we
      // never recorded how to check this one", and the two were reported
      // identically as MISMATCH. recorder.ca's goshupward.com sat like that:
      // live, hunt.goshupward.com still CNAMEd to sdi.html-load.com, but with
      // no sidecar row -- so it was dug root-only against a parked apex
      // (3.33.251.168, matching no bait_dig term) and called a mismatch for a
      // day. Adding the row alone made it confirm.
      hadAlt = !!(alt && alt !== d);
      const rootSatisfies = digOk &&
        (digAll.length ? matchAll(out, digAll) : true) && (digAny.length ? matchAny(out, digAny) : true);
      if (alt && alt !== d && !rootSatisfies) {
        const [a2, ns2] = await Promise.all([
          tool('dig', ['+short', alt, 'A'], `dig:A:${alt}`, DIG_TTL_MS),
          tool('dig', ['+short', alt, 'NS'], `dig:NS:${alt}`, DIG_TTL_MS)
        ]);
        out += `\n${a2.out}\n${ns2.out}`;
        digOk = digOk || a2.ok || ns2.ok;
        if (!rootSatisfies) row.notes.push(`checked via ${alt}`);
      }
      // ERROR is not the same as NO MATCH. Conflating them meant a missing dig
      // binary or a dns blip reported every genuine bait as unconfirmed, and
      // --strict then rejected the lot -- measured with dig off PATH: 0/6.
      if (!digOk) { row.notes.push(`dig failed: ${a.why || ns.why}`); row.dig = 'error'; }
      else {
        row.dig = (digAll.length ? matchAll(out, digAll) : true) &&
                  (digAny.length ? matchAny(out, digAny) : true);
      }
    }

    if (whoisAll.length || whoisAny.length) {
      const w = await tool('whois', [d], `whois:${d}`, WHOIS_TTL_MS);
      if (!w.ok && !w.out) { row.notes.push(`whois failed: ${w.why}`); row.whois = 'error'; }
      else {
        row.whois = (whoisAll.length ? matchAll(w.out, whoisAll) : true) &&
                    (whoisAny.length ? matchAny(w.out, whoisAny) : true);
      }
    }

    const checks = [row.dig, row.whois].filter(v => v !== null);
    const failed = checks.filter(v => v === false).length;
    const errored = checks.filter(v => v === 'error').length;
    // A dig that failed with NO sidecar name to fall back on is not evidence
    // that the bait moved -- it may simply be a parked apex whose serving name
    // was never recorded. Kept apart from 'mismatch' so a rotation is
    // actionable instead of indistinguishable from a data gap. Neither
    // publishes: only 'confirmed' does.
    const digFailedBlind = row.dig === false && !hadAlt;
    row.verdict = failed > 0
      ? (digFailedBlind ? 'unconfirmable' : 'mismatch')
      : (errored > 0 ? 'unknown' : (checks.length ? 'confirmed' : 'unknown'));
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
          : r.verdict === 'rejected' ? messageColors.warn('REFUSED (public suffix)')
            : r.verdict === 'unconfirmable' ? messageColors.warn('UNCONFIRMABLE (no sidecar name)')
              : messageColors.warn('UNKNOWN (lookup failed)');
      console.log(`  ${r.domain.padEnd(26)} dig:${f(r.dig)} whois:${f(r.whois)}  ${verdict}`);
      r.notes.forEach(n => console.log(formatLogMessage('debug', `${TAG}   ${n}`)));
    }
    const mismatched = results.filter(r => r.verdict === 'mismatch');
    const unknown = results.filter(r => r.verdict === 'unknown');
    const refused = results.filter(r => r.verdict === 'rejected');
    const blind = results.filter(r => r.verdict === 'unconfirmable');
    console.log('');
    console.log(`  ${results.filter(r => r.confirmed).length}/${results.length} confirmed` +
      (mismatched.length ? ` — MISMATCH: ${mismatched.map(r => r.domain).join(', ')}` : '') +
      (unknown.length ? ` — could not check: ${unknown.map(r => r.domain).join(', ')}` : '') +
      (refused.length ? ` — REFUSED as a public suffix: ${refused.map(r => r.domain).join(', ')}` : '') +
      (blind.length ? ` — NO SIDECAR, cannot be checked: ${blind.map(r => r.domain).join(', ')}` : ''));
    if (blind.length) {
      console.log(formatLogMessage('warn',
        `${TAG} ${blind.length} domain(s) have no recorded sidecar name and their apex does not match on its own — ` +
        `that is a missing sidecar row, not proof the bait moved. Re-run the walk while the host is serving, or add the row.`));
    }
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
  if (useCache) {
    try { saveDiskCache(CACHE_FILE, cache, Math.max(DIG_TTL_MS, WHOIS_TTL_MS), CACHE_MAX); } catch { /* best effort */ }
    if (!asJson) console.log(formatLogMessage('debug', `${TAG} cache ${cacheHits} hit(s), ${cacheMisses} miss(es) -> ${path.basename(CACHE_FILE)}`));
  }
  const mismatched = results.filter(r => r.verdict === 'mismatch').length;
  const unknown = results.filter(r => r.verdict === 'unknown').length;
  // A refusal is a definite "this must not be published", so it belongs with
  // mismatch rather than with "could not check". Left out of this sum at first,
  // which made --strict exit 0 on a run that had refused a bait outright.
  const refused = results.filter(r => r.verdict === 'rejected').length;
  // 'unconfirmable' sits with 'unknown', not with 'mismatch': both mean the
  // check could not be made, and exit 1 is reserved for a name that really did
  // not match what it was checked against.
  const unconfirmable = results.filter(r => r.verdict === 'unconfirmable').length;
  if (!strict) process.exit(0);
  process.exit((mismatched || refused) ? 1 : ((unknown || unconfirmable) ? 2 : 0));
})().catch(err => {
  console.error(formatLogMessage('error', `${TAG} ${err.message}`));
  process.exit(1);
});
