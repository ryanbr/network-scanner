#!/usr/bin/env node
/**
 * cbcdn-hosts.js — harvest hosts a page was TOLD about from a capture, rather
 * than only the ones it actually fetched.
 *
 *   node scripts/cbcdn-hosts.js <capture-or-log> [...]        # ||host^ lines
 *   node scripts/cbcdn-hosts.js --plain <file>                # bare hostnames
 *   node scripts/cbcdn-hosts.js --param cdn <file>            # a different param
 *   node scripts/cbcdn-hosts.js --dig 192.0.2.,198.51.100. <file>  # keep only these
 *   node scripts/cbcdn-hosts.js --dig-type NS --dig-all --dig ns1.x.example,ns2.x.example <file>
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
const { rootDomainForHost } = require('../lib/har');

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
 * The record types the gate can ask for. Only the two that are used, and an
 * unknown type is a NAMED ERROR rather than a silent fall back to A -- a gate
 * that quietly answers a different question than it was asked is the failure
 * this whole script is written to avoid.
 */
const RESOLVERS = Object.freeze({
  A: (host) => dns.resolve4(host),
  NS: (host) => dns.resolveNs(host)
});

/**
 * Record types that exist only at a zone APEX. A records answer at any label,
 * but NS records are the delegation itself, so a subdomain has none of its own
 * unless it is separately delegated -- `www.<site>` returns nothing while the
 * registrable root returns the pair. Asking such a type at a subdomain and
 * treating the empty answer as final left the gate with NO rejecting power for
 * every subdomain host: each one fell through the fail-open path and was
 * published unconfirmed. That is the same defect the record-type gate was
 * added to remove, one label down.
 */
const APEX_ONLY_TYPES = Object.freeze(new Set(['NS']));

/**
 * DNS outcomes that mean "authoritatively, there are no such records HERE",
 * and so are safe to re-ask at the root: NODATA (the name exists, this type
 * does not) and NXDOMAIN (the name does not exist).
 *
 * Deliberately NOT every failure. A SERVFAIL or a timeout leaves it UNKNOWN
 * whether the host carries its own delegation, and answering from the root in
 * that state would attribute the root operator's nameservers to a host that
 * may belong to someone else -- inventing a confirmation out of a blip. Those
 * keep the host unconfirmed exactly as before.
 */
const NO_RECORDS_HERE = Object.freeze(new Set(['ENODATA', 'ENOTFOUND', 'NOTFOUND']));

/**
 * Keep a host when its records satisfy the dig terms.
 *
 * `mode: 'any'` keeps on the first term that matches; `mode: 'all'` requires
 * every term to match some record. ALL exists for an operator fingerprint made
 * of several values at once -- a Cloudflare NAMESERVER PAIR, say, where a
 * single name is shared by many unrelated accounts and only the pair identifies
 * the account. With `recordType: 'A'` and ANY the gate is as it was.
 *
 * Why a record type at all: the A-record form can only ever express "which IP
 * range is this in", and for a host behind a shared CDN that is barely a
 * question. Measured on a real page, the two ranges the gate was being given
 * are a CDN's SHARED free-tier address pair, so it confirmed every third party
 * present INCLUDING the first-party site itself -- it had no rejecting power at
 * all. A nameserver pair does: across 24 hosts sampled from the published list,
 * all 21 that still resolve are on one pair, and neither the first party nor the
 * unrelated third parties share it. (The live values belong in the operator's
 * own gitignored config and the pipeline that calls this, not here.)
 *
 * A lookup that FAILS keeps the host and says so -- see the header; losing a
 * real host to a dns blip is the expensive direction. An EMPTY answer is
 * treated the same way, deliberately: no records is not evidence of a
 * mismatch, and the previous `.find()` would have returned undefined and
 * DROPPED the host, which contradicts that principle.
 *
 * For an apex-only type an empty answer is RE-ASKED at the registrable root
 * before that fail-open applies -- see APEX_ONLY_TYPES -- and any note that
 * came from the root says `(at root <name>)`, so a confirmation can never be
 * misread as being about the subdomain itself.
 *
 * Matching is `startsWith` on a lowercased pair, so an address prefix still works as a
 * prefix and a nameserver name survives a resolver that applies DNS 0x20
 * mixed-case randomisation to its answer.
 *
 * @param {string} host
 * @param {string[]} terms
 * @param {{recordType?: string, mode?: 'any'|'all', resolve?: Function}} options
 *        `resolve` overrides the lookup; it exists so the gate is testable
 *        without network, this script using node's dns rather than the dig
 *        binary a PATH fake could stand in for.
 * @returns {Promise<{keep: boolean, note: string}>}
 */
async function digKeep(host, terms, options = {}) {
  if (!terms.length) return { keep: true, note: '' };
  const { recordType = 'A', mode = 'any', resolve = null } = options;
  const type = String(recordType).toUpperCase();
  const lookup = resolve || RESOLVERS[type];
  if (!lookup) {
    return { keep: true, note: `unsupported dig type ${type} (want ${Object.keys(RESOLVERS).join('/')}) -- kept unconfirmed` };
  }
  // One query, two possible names. `scope` is carried into every note below:
  // an answer from the root must never read as an answer about the host, or
  // the operator sees a confirmation and believes the host itself is on the
  // fingerprint.
  const ask = async (name) => {
    try {
      const got = await lookup(name, type);
      return { records: (got || []).map(r => String(r).toLowerCase()), failure: null };
    } catch (err) {
      return { records: [], failure: err };
    }
  };

  let { records, failure } = await ask(host);
  let scope = '';
  if (!records.length && APEX_ONLY_TYPES.has(type) &&
      (!failure || NO_RECORDS_HERE.has(failure.code))) {
    const root = rootDomainForHost(host);
    // An apex host is already the root; re-asking would spend a second query
    // to get the same empty answer AND tag the note `(at root ...)` for a name
    // that IS the host, which is the misreading `scope` exists to prevent.
    // Compared lowercased because the root is: psl normalises its answer, so a
    // host spelled in mixed case would otherwise never equal its own root.
    if (root && root !== String(host).toLowerCase()) {
      scope = ` (at root ${root})`;
      ({ records, failure } = await ask(root));
    }
  }

  if (failure) {
    return { keep: true, note: `dns failed (${failure.code || failure.message})${scope} -- kept unconfirmed` };
  }
  if (!records.length) {
    return { keep: true, note: `no ${type} records${scope} -- kept unconfirmed` };
  }
  const lower = terms.map(t => t.toLowerCase());
  // Keep the RECORD that satisfied each term, not just the term. The note is
  // what the operator reads beside a host before it is published, and a term
  // is something they already know -- `192.0.2.` says far less than
  // `192.0.2. in 192.0.2.7`. A term that IS the whole record (a nameserver
  // name) is printed once rather than twice.
  const hits = lower
    .map(t => ({ term: t, record: records.find(r => r.startsWith(t)) }))
    .filter(x => x.record);
  const ok = mode === 'all' ? hits.length === lower.length : hits.length > 0;
  return ok
    ? { keep: true, note: hits.map(x => x.record === x.term ? x.record : `${x.term} in ${x.record}`).join('+') + scope }
    : { keep: false, note: `${mode === 'all' ? 'not all terms' : 'no term'} matched ${type}${scope} (${records.join(', ')})` };
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
    // A flag that is PRESENT must carry a real value. Without this check the
    // two ways of getting it wrong both passed silently, and both made the
    // gate answer a different question than the caller asked:
    //   --dig ""            -> no terms, so NO GATE, and every harvested host
    //                          was published unconfirmed (measured: including
    //                          the first-party site)
    //   ... --dig-type      -> value undefined, so it fell back to A while the
    //                          caller had asked for NS
    // A missing value also used to SWALLOW the next argument, so a capture
    // path could silently become a flag's value.
    const take = flag => {
      const i = args.indexOf(flag);
      if (i === -1) return null;
      const v = args[i + 1];
      if (v === undefined || v === '' || v.startsWith('-')) {
        console.error(`cbcdn-hosts.js: ${flag} needs a value`);
        process.exit(1);
      }
      args.splice(i, 2);
      return v;
    };
    const plain = (() => { const i = args.indexOf('--plain'); if (i !== -1) { args.splice(i, 1); return true; } return false; })();
    const quiet = (() => { const i = args.indexOf('--quiet'); if (i !== -1) { args.splice(i, 1); return true; } return false; })();
    // ALL rather than ANY. Needed for a fingerprint that is only identifying as
    // a SET -- a Cloudflare nameserver pair, where each name alone is shared
    // across unrelated accounts. --dig stays ANY so existing callers are
    // unaffected.
    const digAll = (() => { const i = args.indexOf('--dig-all'); if (i !== -1) { args.splice(i, 1); return true; } return false; })();
    const param = take('--param') || 'cbcdn';
    const digArg = take('--dig');
    // Taken AFTER --dig-all is spliced out but order does not matter for the
    // value flags: indexOf compares whole argv entries, so '--dig' cannot match
    // '--dig-type'.
    const digType = take('--dig-type') || 'A';
    const notIn = take('--not-in');
    const files = args.filter(a => !a.startsWith('-'));

    if (!files.length) {
      console.error('usage: cbcdn-hosts.js [--plain] [--quiet] [--param NAME] [--dig TERM,TERM]');
      console.error('                      [--dig-type A|NS] [--dig-all] [--not-in FILE] <capture|log> [...]');
      process.exit(1);
    }
    const terms = digArg ? digArg.split(',').map(s => s.trim()).filter(Boolean) : [];
    const digOpts = { recordType: digType, mode: digAll ? 'all' : 'any' };
    // Say what the gate is, because "kept unconfirmed" and "matched" read the
    // same whichever question was asked, and asking the wrong one is the defect
    // the --dig-type flag exists to let you avoid.
    if (!quiet && terms.length) {
      console.error(`  gate: ${digAll ? 'ALL' : 'ANY'} of ${terms.join(', ')} in ${digType.toUpperCase()} records`);
    }
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
      const { keep, note } = await digKeep(host, terms, digOpts);
      if (!keep) { if (!quiet) console.error(`  - ${host} (${note})`); continue; }
      if (!quiet) console.error(`  + ${host}  seen ${all.get(host)}×${note ? '  ' + note : ''}`);
      rules.push(plain ? host : `||${host}^`);
    }
    for (const r of rules) console.log(r);
    process.exit(0);
  })();
}
