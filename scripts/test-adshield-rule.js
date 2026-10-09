#!/usr/bin/env node
/**
 * test-adshield-rule.js — pins scripts/adshield-rule.js.
 *
 * Every check here is a defect a review of that script found:
 *
 *  - a rotating token that happens to decode to printable ASCII produced a rule
 *    whose $domain= contained filter SYNTAX. Reachable ~1 in 220, and a
 *    round-trip check cannot catch it because base64 is bijective, so such a
 *    token round-trips perfectly. Only hostname VALIDITY rejects it.
 *  - a token that decodes to a valid hostname belonging to some OTHER site was
 *    emitted anyway, although the premise is that the token encodes the
 *    captured page's own hostname.
 *  - "ruleAnySubdomain" offered a looser variant by appending
 *    |~nonexistent.invalid to $domain=, which negates a domain that never
 *    matches and changes nothing — domain= already covers subdomains.
 *  - capture mode parsed har.log.entries directly, so it could not read the
 *    Chrome net-log or MOZ_LOG formats, and MOZ_LOG is the only one the
 *    pipeline produces.
 *
 *   node scripts/test-adshield-rule.js        # <1s, no browser, no network
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { token, hostFromToken, rulesFor, LOADER_PATH } = require('./adshield-rule');

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`); }
};

console.log('\nadshield rule derivation\n');

// ---- the encoding itself --------------------------------------------------
check('token is base64 of the hostname with padding stripped',
  token('site-one.example'), Buffer.from('site-one.example').toString('base64').replace(/=+$/, ''));
check('token carries no padding', /=/.test(token('a.example')), false);
check('a token round-trips back to its hostname',
  hostFromToken(token('site-one.example')), 'site-one.example');

// ---- the guard that matters ----------------------------------------------
// These three decode to printable ASCII and round-trip perfectly. The printable
// test alone passed them; only hostname validity refuses them.
for (const [tok, decoded] of [['PCpPdmFX', '<*OvaW'], ['I2w1bDhQ', '#l5l8P'], ['OVlhOTRd', '9Ya94]']]) {
  check(`"${tok}" decodes to printable junk and is refused`, hostFromToken(tok), null);
  // prove the mutation-proof part: it really does round-trip, so a round-trip
  // check would have accepted it
  check(`"${tok}" nonetheless round-trips (why round-tripping is no guard)`,
    Buffer.from(decoded, 'utf8').toString('base64').replace(/=+$/, ''), tok);
}
check('a token decoding to a dotless name is refused', hostFromToken(token('localhost')), null);
check('a token decoding to filter syntax is refused', hostFromToken(token('a$b.example')), null);
check('a token decoding to a wildcard host is refused', hostFromToken(token('*.example')), null);
check('a real hostname survives the guard', hostFromToken(token('sub.site.example')), 'sub.site.example');

// ---- the rule shape ------------------------------------------------------
const r = rulesFor('site-one.example');
check('rule is path-anchored, script-typed and domain-scoped',
  r.rule, `/script/${r.token}.js$script,domain=site-one.example`);
check('the no-op ruleAnySubdomain variant is gone', 'ruleAnySubdomain' in r, false);
check('rule exposes exactly token, path and rule', Object.keys(r).sort(), ['path', 'rule', 'token']);

// ---- which paths are recognised -----------------------------------------
for (const p of ['/script/abcdefgh.js', '/preload/0a1b2c3d.js', '/theme/0a1b2c3d.js',
  '/vendor-libs/Zm9vYmFy.js', '/build-output/abcdefgh.js']) {
  check(`recognises ${p}`, LOADER_PATH.test(`https://host.example${p}`), true);
}
check('does not treat an ordinary script path as a loader',
  LOADER_PATH.test('https://host.example/js/main.js'), false);

// ---- capture mode, across all three formats -----------------------------
// The old version read har.log.entries directly; MOZ_LOG is the only format the
// pipeline emits, so it could not read its own captures.
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-adshield-'));
  const SCRIPT = path.join(__dirname, 'adshield-rule.js');
  const run = f => execFileSync(process.execPath, [SCRIPT, '--capture', f], { encoding: 'utf8' });

  const tok = token('site-one.example');

  // a HAR whose token IS base64 of the captured page's hostname
  const har = path.join(dir, 'c.har');
  fs.writeFileSync(har, JSON.stringify({ log: {
    version: '1.2', creator: { name: 'x', version: '1' },
    pages: [{ id: 'p', title: 'https://site-one.example/', pageTimings: {} }],
    entries: [
      { request: { url: 'https://site-one.example/', method: 'GET', headers: [{ name: 'Sec-Fetch-Dest', value: 'document' }] },
        response: { status: 200, content: { mimeType: 'text/html' } } },
      { request: { url: `https://apex-one.example/script/${tok}.js`, method: 'GET', headers: [{ name: 'Sec-Fetch-Dest', value: 'script' }] },
        response: { status: 200, content: { mimeType: 'application/javascript' } } }
    ]
  } }));
  const harOut = run(har);
  check('HAR: emits the rule when the token encodes the captured page',
    harOut.includes(`/script/${tok}.js$script,domain=site-one.example`), true);
  check('HAR: reports the serving host', harOut.includes('apex-one.example'), true);

  // MOZ_LOG of the same shape — the format the pipeline actually produces
  const moz = path.join(dir, 'c.log.moz_log');
  fs.writeFileSync(moz,
    '2026-01-01 00:00:00.000000 UTC - [Parent 1: Main Thread]: E/nsHttp uri=https://site-one.example/\r\n' +
    '2026-01-01 00:00:00.000000 UTC - [Parent 1: Main Thread]: E/nsHttp http request [\r\n' +
    '2026-01-01 00:00:00.000000 UTC - [Parent 1: Main Thread]: E/nsHttp   Sec-Fetch-Dest: document\r\n' +
    '2026-01-01 00:00:00.000000 UTC - [Parent 1: Main Thread]: E/nsHttp ]\r\n' +
    `2026-01-01 00:00:01.000000 UTC - [Parent 1: Main Thread]: E/nsHttp uri=https://apex-one.example/script/${tok}.js\r\n` +
    '2026-01-01 00:00:01.000000 UTC - [Parent 1: Main Thread]: E/nsHttp http request [\r\n' +
    '2026-01-01 00:00:01.000000 UTC - [Parent 1: Main Thread]: E/nsHttp   Sec-Fetch-Dest: script\r\n' +
    '2026-01-01 00:00:01.000000 UTC - [Parent 1: Main Thread]: E/nsHttp ]\r\n');
  const mozOut = run(moz);
  check('MOZ_LOG: read at all (the old --har could not)', mozOut.includes('Firefox MOZ_LOG'), true);
  check('MOZ_LOG: emits the same rule as the HAR',
    mozOut.includes(`/script/${tok}.js$script,domain=site-one.example`), true);

  // a token encoding a DIFFERENT site must not produce a rule for this capture
  const other = path.join(dir, 'other.har');
  const otherTok = token('elsewhere.example');
  fs.writeFileSync(other, JSON.stringify({ log: {
    version: '1.2', creator: { name: 'x', version: '1' },
    pages: [{ id: 'p', title: 'https://site-one.example/', pageTimings: {} }],
    entries: [
      { request: { url: 'https://site-one.example/', method: 'GET', headers: [{ name: 'Sec-Fetch-Dest', value: 'document' }] },
        response: { status: 200, content: { mimeType: 'text/html' } } },
      { request: { url: `https://apex-one.example/script/${otherTok}.js`, method: 'GET', headers: [{ name: 'Sec-Fetch-Dest', value: 'script' }] },
        response: { status: 200, content: { mimeType: 'application/javascript' } } }
    ]
  } }));
  const otherOut = run(other);
  check('a token for another site emits NO rule', /rule\s+:/.test(otherOut), false);
  check('and says why', otherOut.includes('does not encode this page'), true);

  // a non-base64 token: report the shape, derive nothing
  const nb = path.join(dir, 'nb.har');
  fs.writeFileSync(nb, JSON.stringify({ log: {
    version: '1.2', creator: { name: 'x', version: '1' },
    pages: [{ id: 'p', title: 'https://site-one.example/', pageTimings: {} }],
    entries: [
      { request: { url: 'https://site-one.example/', method: 'GET', headers: [{ name: 'Sec-Fetch-Dest', value: 'document' }] },
        response: { status: 200, content: { mimeType: 'text/html' } } },
      { request: { url: 'https://apex-one.example/vendor-libs/Zm9vYmFy.js', method: 'GET', headers: [{ name: 'Sec-Fetch-Dest', value: 'script' }] },
        response: { status: 200, content: { mimeType: 'application/javascript' } } }
    ]
  } }));
  const nbOut = run(nb);
  check('a non-base64 shape is reported', nbOut.includes('/vendor-libs/Zm9vYmFy.js'), true);
  check('a non-base64 shape emits NO rule', /rule\s+:/.test(nbOut), false);
  check('and points at the walk instead', nbOut.includes('win-bait-walk.ps1'), true);

  fs.rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
