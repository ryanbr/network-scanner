#!/usr/bin/env node
/**
 * adshield-rule.js — derive the rotation-proof filter for an AdShield-style
 * loader, from the site's own hostname.
 *
 *   node scripts/adshield-rule.js example.com [more.example ...]
 *   node scripts/adshield-rule.js --har <file.har>     (confirm against a capture)
 *
 * Why this exists: the loader's HOST rotates through a fallback list
 * (html-load.cc -> exceptlone.com -> quitcertify.com -> ...), so a host-anchored
 * rule dies at the next rotation and has to be rediscovered. The PATH does not
 * rotate: it is /script/<base64(site hostname) without padding>.js, identical
 * on every host in the chain -- verified against a real capture in which four
 * different hosts all served the same /script/<token>.js, and base64 of that
 * site's own hostname reproduced the token exactly.
 *
 * So the filter can be written for a site before the next domain is even known,
 * and keeps working after it changes.
 */

const fs = require('fs');

function token(hostname) {
  return Buffer.from(hostname, 'utf8').toString('base64').replace(/=+$/, '');
}

function rulesFor(hostname) {
  const t = token(hostname);
  return {
    token: t,
    path: `/script/${t}.js`,
    // Path-anchored: matches whatever host the loader rotates to. Scoped to the
    // site with $domain= so it cannot affect anything else.
    rule: `/script/${t}.js$script,domain=${hostname}`,
    // Looser variant if the site also serves it from subdomains.
    ruleAnySubdomain: `/script/${t}.js$script,domain=${hostname}|~nonexistent.invalid`
  };
}

const args = process.argv.slice(2);
if (args[0] === '--har') {
  const har = JSON.parse(fs.readFileSync(args[1], 'utf8'));
  const found = new Map();
  for (const e of har.log.entries || []) {
    const u = e.request && e.request.url;
    const m = u && u.match(/^https?:\/\/([^/]+)(\/script\/([A-Za-z0-9+/_-]{4,32})\.js)/);
    if (m) {
      if (!found.has(m[2])) found.set(m[2], { hosts: new Set(), token: m[3] });
      found.get(m[2]).hosts.add(m[1]);
    }
  }
  if (!found.size) { console.log('  no AdShield-style loader URLs in this HAR'); process.exit(0); }
  for (const [path, info] of found) {
    let decoded = '';
    try { decoded = Buffer.from(info.token + '==='.slice(0, (4 - info.token.length % 4) % 4), 'base64').toString('utf8'); } catch { /* not base64 */ }
    const printable = /^[\x20-\x7e]+$/.test(decoded) ? decoded : '(not decodable)';
    console.log(`\n  path   : ${path}`);
    console.log(`  token  : ${info.token}  ->  ${printable}`);
    console.log(`  hosts  : ${[...info.hosts].join(', ')}`);
    if (printable !== '(not decodable)') {
      console.log(`  rule   : ${rulesFor(printable).rule}`);
      console.log(`           (host-anchored rules would need rewriting on each rotation; this one does not)`);
    }
  }
  console.log('');
} else if (!args.length) {
  console.error('usage: node scripts/adshield-rule.js <hostname> [...]   |   --har <file.har>');
  process.exit(1);
} else {
  for (const host of args) {
    const r = rulesFor(host);
    console.log(`\n  ${host}`);
    console.log(`    token : ${r.token}`);
    console.log(`    path  : ${r.path}`);
    console.log(`    rule  : ${r.rule}`);
  }
  console.log('');
}
