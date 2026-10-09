#!/usr/bin/env node
/**
 * adshield-rule.js — derive a rotation-proof filter for ONE loader shape, and
 * report loader-shaped requests found in a capture.
 *
 *   node scripts/adshield-rule.js site.example [more.example ...]
 *   node scripts/adshield-rule.js --capture <file>   (HAR, net-log or MOZ_LOG)
 *
 * WHAT THE PREMISE IS, AND WHAT IT IS NOT.
 *
 * On one observed site the loader path is /script/<base64(site hostname), padding
 * stripped>.js and does NOT rotate, while the HOST does -- so a path-anchored
 * rule scoped with $domain= survives a rotation that a host-anchored rule does
 * not. That is worth having, and it is what this script derives.
 *
 * It is ONE shape out of several now measured, which the earlier version of this
 * header presented as universal on the strength of a single capture:
 *
 *   /script/<base64(site hostname)>.js     <- the shape this script derives
 *   /script/<fixed-length token>.js        token is NOT base64 of the hostname
 *   /script/<site hostname in clear>.js    plus a ?hash= query
 *   /session/.../<site hostname>/...       hostname as a path SEGMENT, no .js
 *   /preload/<hex>.js  /theme/<hex>.js  /vendor-libs/<token>.js  /build-output/...
 *
 * So treat a derived rule as a bonus on sites that use the first shape, not as a
 * substitute for enumerating the chain. Walking the fallback list is what finds
 * the hosts on every other shape, and it is what has actually been catching
 * rotations.
 *
 * VALIDATION. A rotating token decodes to printable ASCII roughly 1 time in 220
 * by chance, and because base64 is bijective such a token also "round-trips"
 * perfectly -- so round-tripping proves nothing. Two real checks are applied
 * before a rule is emitted: the decoded value must be a usable hostname
 * (lib/output.js hostRejectionReason, the same guard the publish path uses), and
 * in --capture mode it must match the page the capture is OF, because the premise
 * is that the token encodes that site's own hostname. Without those, a token like
 * "PCpPdmFX" decodes to "<*OvaW" and yielded the rule
 * /script/PCpPdmFX.js$script,domain=<*OvaW -- syntactically broken and scoped to
 * a domain that cannot exist.
 */

const path = require('path');
const { parseCapture } = require('../lib/capture');
const { hostRejectionReason } = require('../lib/output');

/** base64 of a hostname with padding stripped, as the loader path uses it. */
function token(hostname) {
  return Buffer.from(hostname, 'utf8').toString('base64').replace(/=+$/, '');
}

/** Decode a loader token back to a hostname, or null when it is not one. */
function hostFromToken(tok) {
  const pad = '==='.slice(0, (4 - tok.length % 4) % 4);
  let decoded;
  try { decoded = Buffer.from(tok + pad, 'base64').toString('utf8'); } catch { return null; }
  // A hostname, not merely printable. The printable test alone passes ~1 token
  // in 220 and produced rules with characters that are filter SYNTAX.
  if (!decoded || hostRejectionReason(decoded)) return null;
  return decoded;
}

function rulesFor(hostname) {
  const t = token(hostname);
  return {
    token: t,
    path: `/script/${t}.js`,
    // Path-anchored so it survives a host rotation; $domain= scopes it to the
    // site. In ABP/uBO syntax domain= already covers subdomains of the listed
    // domain, so there is no looser variant to offer -- an earlier
    // "ruleAnySubdomain" field appended |~nonexistent.invalid, which negated a
    // domain that never matches and changed nothing.
    rule: `/script/${t}.js$script,domain=${hostname}`
  };
}

// Path segments observed carrying a loader. Only the /script/ ones can hold a
// base64 hostname; the rest are reported so a capture shows the whole picture
// rather than silently matching nothing.
const LOADER_PATH = /^https?:\/\/([^/]+)(\/(?:script|preload|theme|vendor-libs|build-output)\/([A-Za-z0-9+/_=-]{4,64})\.js)/;

function reportCapture(file) {
  const cap = parseCapture(file);
  let pageHost = '';
  try { pageHost = new URL(cap.pageUrl || '').hostname; } catch { /* unknown */ }

  const found = new Map();
  for (const e of cap.entries || []) {
    const m = (e.url || '').match(LOADER_PATH);
    if (!m) continue;
    if (!found.has(m[2])) found.set(m[2], { hosts: new Set(), token: m[3] });
    found.get(m[2]).hosts.add(m[1]);
  }

  console.log(`\n  capture : ${path.basename(file)}  (${cap.formatLabel})`);
  console.log(`  page    : ${cap.pageUrl || '(unknown)'}`);
  if (!found.size) {
    console.log('  no loader-shaped request in this capture\n');
    return 0;
  }
  for (const [p, info] of found) {
    const decoded = hostFromToken(info.token);
    console.log(`\n  path    : ${p}`);
    console.log(`  token   : ${info.token}`);
    console.log(`  hosts   : ${[...info.hosts].sort().join(', ')}`);
    if (!decoded) {
      console.log('  decodes : not a hostname -- this is one of the non-base64 shapes,');
      console.log('            so no rule can be derived from the path alone. Enumerate');
      console.log('            the chain instead (scripts/win-bait-walk.ps1).');
      continue;
    }
    if (pageHost && decoded !== pageHost) {
      console.log(`  decodes : ${decoded} -- but this capture is of ${pageHost}, so the`);
      console.log('            token does not encode this page\'s hostname. Not emitting a');
      console.log('            rule: the premise does not hold here.');
      continue;
    }
    console.log(`  decodes : ${decoded}${pageHost ? ' (matches the captured page)' : ''}`);
    console.log(`  rule    : ${rulesFor(decoded).rule}`);
  }
  console.log('');
  return 0;
}

module.exports = { token, hostFromToken, rulesFor, LOADER_PATH };

if (require.main === module) {
  const args = process.argv.slice(2);
  // --har kept as an alias: the reader now sniffs HAR, Chrome net-log and
  // MOZ_LOG by content, and the pipeline only ever produces MOZ_LOG -- which
  // the HAR-only version could not read at all.
  const capIdx = args.findIndex(a => a === '--capture' || a === '--har');
  if (capIdx !== -1) {
    const file = args[capIdx + 1];
    if (!file) { console.error('usage: adshield-rule.js --capture <file>'); process.exit(1); }
    process.exit(reportCapture(file));
  } else if (!args.length) {
    console.error('usage: node scripts/adshield-rule.js <hostname> [...]   |   --capture <file>');
    process.exit(1);
  } else {
    for (const host of args) {
      const bad = hostRejectionReason(host);
      if (bad) { console.log(`\n  ${host}\n    refused: not a usable hostname (${bad})`); continue; }
      const r = rulesFor(host);
      console.log(`\n  ${host}`);
      console.log(`    token : ${r.token}`);
      console.log(`    path  : ${r.path}`);
      console.log(`    rule  : ${r.rule}`);
    }
    console.log('');
  }
}
