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

const { guardBait, isPublicSuffix, registrableOf } = require('../lib/baitguard');

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

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
