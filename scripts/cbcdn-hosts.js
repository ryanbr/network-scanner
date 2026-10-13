#!/usr/bin/env node
/**
 * cbcdn-hosts.js — harvest hosts a page was TOLD about from a capture, rather
 * than only the ones it actually fetched.
 *
 *   node scripts/cbcdn-hosts.js <capture-or-log> [...]        # ||host^ lines
 *   node scripts/cbcdn-hosts.js --plain <file>                # bare hostnames
 *   node scripts/cbcdn-hosts.js --param cdn <file>            # a different param
 *   node scripts/cbcdn-hosts.js --dig 104.21.,172.67. <file>  # keep only these
 *   node scripts/cbcdn-hosts.js --not-in list.txt <file>      # omit already-listed
 *
 * WHY THIS EXISTS. The matching in lib/har.js runs over REQUEST urls, so it can
 * only ever name a host the browser actually contacted. Some loaders announce
 * the next CDN host in a query parameter on an earlier beacon -- which means the
 * name is available one step BEFORE the request, and is still available when
 * that request never happens at all (the host is held in reserve, or whatever
 * would have triggered it was blocked). Measured on real captures: of four
 * rotating hosts seen across a set of captures and one live run, one appeared
 * only as a parameter value and was never requested, so no filterRegex over
 * request urls could have published it.
 *
 * It is deliberately NOT a config key. `output_regex` cannot do this job:
 * outputKeyFromUrl (lib/output.js) only accepts a capture shaped `host/path` and
 * falls back to the request's own domain for a bare hostname, so a parameter
 * holding just a host silently yields the WRONG key rather than nothing.
 *
 * WHAT IT DOES NOT DO. A parameter value is a claim by the page, not evidence
 * that anything was served from it. That is why --dig exists and why the output
 * is meant to be reviewed: this finds candidates a request-url scan cannot
 * reach, it does not confirm them.
 *
 * READING NOTES, each one a defect this would otherwise have:
 *
 *  - Captures are CRLF. A greedy value match swallows the trailing \r, and in a
 *    JS regex \r is a LINE TERMINATOR, so a later `$`-anchored check silently
 *    matches nothing. The value is cut on CR/LF explicitly.
 *  - The parameter name is anchored on `[?&]` -- unanchored, `cbcdn=` also
 *    matches a `xcbcdn=` or `mycbcdn=` belonging to something else.
 *  - Values arrive percent-encoded (a host inside an encoded query is encoded
 *    twice), so each is decoded until it stops changing, bounded.
 *  - Validity is hostRejectionReason(), the same guard the publish path uses --
 *    not a "looks printable" test. A parameter can hold filter SYNTAX.
 *  - A dns failure under --dig does NOT silently drop the host: it is kept and
 *    flagged, because losing a real host to a dns blip is the expensive
 *    direction (the same call scripts/win-bait-walk.ps1 makes).
 */

const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const { parseCapture } = require('../lib/capture');
const { hostRejectionReason } = require('../lib/output');

/** Decode a percent-encoded value repeatedly, until it settles. */
function fullyDecode(value) {
  let out = value;
  for (let i = 0; i < 4; i++) {
    let next;
    try { next = decodeURIComponent(out); } catch { return out; }
    if (next === out) return out;
    out = next;
  }
  return out;
}

/**
 * Every value of `param` in one url-ish string. Anchored on [?&] so a parameter
 * whose name merely ENDS with the wanted one is not harvested, and cut on the
 * delimiters a capture can introduce (& \r \n space ") as well as end of input.
 */
function valuesIn(text, param) {
  const re = new RegExp(`[?&]${param}=([^&\\r\\n\\s"']*)`, 'gi');
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) if (m[1]) out.push(m[1]);
  return out;
}

/**
 * Hosts named by `param` anywhere in a file. A capture is read through
 * parseCapture so all three formats work; anything else (a debug log, a saved
 * console dump) is scanned as plain text, because the live path's own --debug
 * output is not a capture and carries these parameters too.
 */
function hostsFrom(file, param) {
  let texts;
  let via;
  try {
    const cap = parseCapture(file);
    texts = (cap.entries || []).map(e => e.url || '');
    via = cap.formatLabel;
  } catch {
    texts = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    via = 'text';
  }
  const found = new Map(); // host -> times seen
  for (const t of texts) {
    for (const raw of valuesIn(t, param)) {
      const host = fullyDecode(raw).trim().toLowerCase();
      if (!host || hostRejectionReason(host)) continue;
      found.set(host, (found.get(host) || 0) + 1);
    }
  }
  return { via, found };
}

/**
 * Keep a host when any dig term prefixes any of its A records. A lookup that
 * FAILS keeps the host and says so -- see the header.
 */
async function digKeep(host, terms) {
  if (!terms.length) return { keep: true, note: '' };
  let addrs;
  try { addrs = await dns.resolve4(host); } catch (err) {
    return { keep: true, note: `dns failed (${err.code || err.message}) -- kept unconfirmed` };
  }
  const hit = addrs.find(a => terms.some(t => a.startsWith(t)));
  return hit
    ? { keep: true, note: hit }
    : { keep: false, note: `no term matched (${addrs.join(', ')})` };
}

/** Hosts already present in a list file, as `||host^` or one per line. */
function alreadyListed(file) {
  const set = new Set();
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.trim().match(/^\|\|([^/^|$]+)\^?/) || line.trim().match(/^([a-z0-9.-]+\.[a-z]{2,})$/i);
    if (m) set.add(m[1].toLowerCase());
  }
  return set;
}

module.exports = { fullyDecode, valuesIn, hostsFrom, digKeep, alreadyListed };

if (require.main === module) {
  (async () => {
    const args = process.argv.slice(2);
    const take = flag => {
      const i = args.indexOf(flag);
      if (i === -1) return null;
      const v = args[i + 1];
      args.splice(i, 2);
      return v;
    };
    const plain = (() => { const i = args.indexOf('--plain'); if (i !== -1) { args.splice(i, 1); return true; } return false; })();
    const quiet = (() => { const i = args.indexOf('--quiet'); if (i !== -1) { args.splice(i, 1); return true; } return false; })();
    const param = take('--param') || 'cbcdn';
    const digArg = take('--dig');
    const notIn = take('--not-in');
    const files = args.filter(a => !a.startsWith('-'));

    if (!files.length) {
      console.error('usage: cbcdn-hosts.js [--plain] [--quiet] [--param NAME] [--dig PFX,PFX] [--not-in FILE] <capture|log> [...]');
      process.exit(1);
    }
    const terms = digArg ? digArg.split(',').map(s => s.trim()).filter(Boolean) : [];
    const skip = notIn ? alreadyListed(notIn) : new Set();

    const all = new Map();
    for (const f of files) {
      let r;
      try { r = hostsFrom(f, param); } catch (err) {
        console.error(`  ! ${path.basename(f)}: ${err.message}`);
        continue;
      }
      if (!quiet) console.error(`  ${path.basename(f)} (${r.via}): ${r.found.size} host(s) named by ${param}=`);
      for (const [h, n] of r.found) all.set(h, (all.get(h) || 0) + n);
    }

    const rules = [];
    for (const host of [...all.keys()].sort()) {
      if (skip.has(host)) { if (!quiet) console.error(`  - ${host} (already listed)`); continue; }
      const { keep, note } = await digKeep(host, terms);
      if (!keep) { if (!quiet) console.error(`  - ${host} (${note})`); continue; }
      if (!quiet) console.error(`  + ${host}  seen ${all.get(host)}×${note ? '  ' + note : ''}`);
      rules.push(plain ? host : `||${host}^`);
    }
    for (const r of rules) console.log(r);
    process.exit(0);
  })();
}
