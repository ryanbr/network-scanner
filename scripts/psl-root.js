#!/usr/bin/env node
/**
 * psl-root.js — reduce hostnames to their registrable domains, using the real
 * Public Suffix List.
 *
 * Reads one hostname per line on stdin (or takes them as arguments) and writes
 * "<normalised host>\t<registrable domain>" per line. A name with no
 * registrable domain -- a bare public suffix such as co.il, or junk -- is
 * written with an EMPTY root rather than dropped, so a caller can tell "I asked
 * and there is no answer" apart from "my question never arrived".
 *
 * WHY: win-bait-walk.ps1 has to reduce a serving host to the apex it blocks in
 * its PAC, and PowerShell has no public suffix list. It carried 26 multi-part
 * suffixes by hand against psl's 9,778 rules (8,330 multi-part), so anything
 * outside that list reduced one label too far -- "co.il" for deer.bait.co.il,
 * "github.io", "vercel.app", "com.pl", "co.th" -- which the walk then put in
 * its own PAC and wrote to the bait list. Of fifteen suffixes probed, thirteen
 * were missing from the hand list.
 *
 * Batched on purpose: node starts in ~100ms over the \\wsl.localhost path the
 * walk uses, so this is called once per round for every host in it rather than
 * once per host.
 *
 *   printf 'deer.bait.co.il\n0.taro.sansyettusk.com\n' | node scripts/psl-root.js
 *   deer.bait.co.il        bait.co.il
 *   0.taro.sansyettusk.com sansyettusk.com
 */

const { normaliseName, registrableOf } = require('../lib/baitguard');

function emit(names) {
  const seen = new Set();
  const out = [];
  for (const raw of names) {
    const h = normaliseName(raw);
    if (!h || h.startsWith('#') || seen.has(h)) continue;
    seen.add(h);
    out.push(`${h}\t${registrableOf(h) || ''}`);
  }
  if (out.length) process.stdout.write(out.join('\n') + '\n');
}

const argv = process.argv.slice(2).filter(a => a !== '-');
if (argv.length) {
  emit(argv);
} else {
  let buf = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', d => { buf += d; });
  process.stdin.on('end', () => emit(buf.split('\n')));
}
