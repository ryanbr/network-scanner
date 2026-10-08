#!/usr/bin/env node
/**
 * test-bait-guard.js — pins lib/baitguard.js.
 *
 * The bug it guards against, measured: win-bait-walk.ps1's Get-Root reduces a
 * serving host with a hand-maintained 26-entry suffix list rather than the
 * public suffix list, so a bait under any unlisted multi-part suffix arrives
 * one label too short ("co.il", "com.pl", "github.io"). bait-confirm's dig gate
 * is satisfied by the sidecar name ALONE, so such a root reached verdict
 * "confirmed" -- and the publish step writes ||${domain}^ with no further
 * check, which would have published a rule blocking an entire ccTLD.
 *
 *   node scripts/test-bait-guard.js        # instant, no network
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { guardBait, isPublicSuffix, registrableOf, normaliseName } = require('../lib/baitguard');

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`); }
};

console.log('\nbait guard (public-suffix roots)\n');

// ---- the suffixes Get-Root gets wrong ------------------------------------
// Each of these is what Get-Root actually returns for a host under that
// suffix, verified against the PowerShell function.
for (const ps of ['co.il', 'com.pl', 'com.ua', 'github.io', 'co.uk', 'com.au']) {
  check(`"${ps}" is recognised as a public suffix`, isPublicSuffix(ps), true);
}

// ---- and the names that must NOT be treated as one -----------------------
// Unknown TLDs are the trap: psl gives no registrable domain for a bare public
// suffix AND for junk, so a naive "domain === null" test would refuse .invalid
// and .test, which every fixture in this repo uses.
for (const ok of ['bait.co.il', 'bait.com', 'sansyettusk.com', 'a.invalid', 'x.test', 'deep.sub.c.invalid']) {
  check(`"${ok}" is not a public suffix`, isPublicSuffix(ok), false);
}

// ---- passthrough ---------------------------------------------------------
check('a normal root passes through untouched',
  guardBait('sansyettusk.com', new Map()), { domain: 'sansyettusk.com' });
check('an unknown-TLD name passes through untouched',
  guardBait('a.invalid', new Map()), { domain: 'a.invalid' });

// ---- refusal -------------------------------------------------------------
// The measured case: a public-suffix root whose sidecar sits somewhere else
// entirely. Previously this returned "confirmed" on the sidecar's strength.
const r1 = guardBait('co.il', new Map([['co.il', '0.taro.sansyettusk.com']]));
check('public suffix + sidecar NOT under it is refused', !!r1.reject, true);
check('refusal keeps the original name for reporting', r1.domain, 'co.il');
check('refusal names the sidecar it would not trust',
  r1.reject.includes('0.taro.sansyettusk.com'), true);

const r2 = guardBait('github.io', new Map());
check('public suffix with no sidecar at all is refused', !!r2.reject, true);
check('that refusal says there was no sidecar', r2.reject.includes('no sidecar'), true);

// ---- repair --------------------------------------------------------------
// Refusal loses a real bait, so a sidecar UNDER the suffix repairs instead:
// psl names the registrable domain and the find survives.
const r3 = guardBait('com.pl', new Map([['com.pl', 'taro.bait.com.pl']]));
check('public suffix + sidecar under it is repaired, not refused', r3.reject, undefined);
check('repair uses psl\'s registrable domain', r3.domain, 'bait.com.pl');
check('repair records the name it came from', r3.via, 'taro.bait.com.pl');
check('repair explains itself in a note', r3.note.includes('public suffix'), true);

// A sidecar equal to the suffix cannot repair anything -- there is no extra
// label to take -- so it must still be refused rather than echoed back.
check('sidecar equal to the suffix is still refused',
  !!guardBait('co.uk', new Map([['co.uk', 'co.uk']])).reject, true);

// ---- the helper underneath ----------------------------------------------
check('registrableOf walks a deep host down to the registrable domain',
  registrableOf('0.taro.sansyettusk.com'), 'sansyettusk.com');
check('registrableOf returns null for a bare public suffix',
  registrableOf('co.il'), null);

// ---- a plain object works as well as a Map ------------------------------
check('sidecar may be a plain object',
  guardBait('com.pl', { 'com.pl': 'taro.bait.com.pl' }).domain, 'bait.com.pl');

// ---- the case / trailing-dot bypass -------------------------------------
// Found on re-review. psl normalises internally and reports tld "co.il" for
// "CO.IL" and "co.il.", so comparing psl's answer against the RAW name said
// "not a public suffix" and waved both straight through to ||CO.IL^. Reachable:
// Get-BaitHosts takes $_.Groups[1].Value out of the capture with no folding and
// Get-Root never lowercased, so an uppercase hostname in a log produced an
// uppercase root. A no-op on real data -- 0 lines across all six production
// bait lists need normalising -- which is exactly why it went unnoticed.
for (const n of ['CO.IL', 'Co.Il', 'co.il.', 'Co.Il.', 'CO.UK.', '  co.il  ']) {
  check(`"${n}" is still recognised as a public suffix`, isPublicSuffix(n), true);
}
check('an uppercase public suffix is refused, not published',
  !!guardBait('CO.IL', new Map()).reject, true);
check('a trailing-dot public suffix is refused, not published',
  !!guardBait('co.il.', new Map()).reject, true);

// Normalisation must reach the PUBLISHED name too, since the append writes
// ||${domain}^ verbatim with no formatDomain() on that path.
check('a mixed-case ordinary bait is published lowercased',
  guardBait('SansYettusk.COM', new Map()).domain, 'sansyettusk.com');
check('a root-anchored ordinary bait loses its trailing dot',
  guardBait('sansyettusk.com.', new Map()).domain, 'sansyettusk.com');
check('normaliseName folds case, trailing dots and whitespace',
  normaliseName('  Deer.ICKASIDE.CO.IL..  '), 'deer.ickaside.co.il');

// A sidecar keyed by the raw name must survive normalisation of the bait, or
// the confirmer digs the root alone -- the parked-apex failure, reintroduced.
const vp = guardBait('SansYettusk.COM', new Map([['SansYettusk.COM', '0.TARO.SansYettusk.com']]));
check('sidecar is carried through a normalising passthrough', vp.via, '0.taro.sansyettusk.com');
check('and the passthrough is not a refusal', vp.reject, undefined);

// Repair across case: the suffix, the sidecar and the result all normalise.
const rc = guardBait('CO.IL', new Map([['CO.IL', '0.TARO.Bait.co.il']]));
check('repair works on a mixed-case suffix', rc.domain, 'bait.co.il');
check('repair normalises the name it reports', rc.via, '0.taro.bait.co.il');

// ---- --strict must not report success after refusing a bait --------------
// A refusal is a definite "do not publish", so it belongs with mismatch, not
// with "could not check". It was left out of the exit sum at first, so --strict
// exited 0 on a run that had refused outright. No dig runs for a refused row,
// so this stays offline.
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-baitguard-'));
  const cfg = path.join(dir, 'cfg.json');
  fs.writeFileSync(cfg, JSON.stringify({ sites: [{ url: 'https://target.invalid/', 'bait_dig-or': ['never-matches'] }] }));
  const baits = path.join(dir, 'b.txt');
  fs.writeFileSync(baits, 'github.io\n');            // public suffix, no sidecar
  const codeOf = extra => {
    try {
      execFileSync(process.execPath,
        [path.join(__dirname, 'bait-confirm.js'), '--config', cfg, '--site', '0', '--baits', baits, '--no-cache', ...extra],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      return 0;
    } catch (e) { return e.status; }
  };
  check('bait-confirm exits 0 without --strict', codeOf(['--json']), 0);
  check('bait-confirm exits non-zero under --strict after a refusal', codeOf(['--strict']), 1);
  fs.rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
