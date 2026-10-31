#!/usr/bin/env node
/**
 * Disk-cache tmp-file handling in lib/nettools.js.
 *
 * Two scanners share one clone (a scheduled loop plus a second one), so two
 * processes can be inside saveDiskCache at the same moment. Both used a fixed
 * `<cache>.tmp`: they opened it with O_TRUNC together and the rename published
 * a mixture, which loadDiskCache's JSON.parse then threw into a silent catch,
 * dropping all 10,000 entries (it warns, but the run continues and re-digs
 * everything). And loadDiskCache unlinked that fixed tmp on
 * startup, so a starting run deleted the file a finishing run was writing.
 *
 * No timing-dependent interleave check here on purpose: a two-process race
 * passes most of the time even unfixed, and a check that can pass against the
 * bug is decoration. These pin the deterministic halves instead.
 *
 * ~1s, no network, no browser.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadDiskCache, saveDiskCache } = require('../lib/nettools');

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`); }
};

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-cachetmp-'));
const cacheFile = path.join(dir, '.digcache');
const TTL = 60000, MAX = 100;

// ---- a save leaves no unsuffixed tmp, and the file is valid JSON ----------
const m = new Map([['a.invalid-A', { result: { success: true }, timestamp: Date.now(), hostname: 'a.invalid' }]]);
saveDiskCache(cacheFile, m, TTL, MAX);
check('save produces a parseable cache file',
  Object.keys(JSON.parse(fs.readFileSync(cacheFile, 'utf8'))), ['a.invalid-A']);
check('save leaves no shared <cache>.tmp behind', fs.existsSync(cacheFile + '.tmp'), false);

// Source canary: the tmp name must carry the pid, or two processes collide
// again on one path and no behavioural check here would see it.
const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'nettools.js'), 'utf8');
// Assert the ABSENCE of the dangerous form, not just the presence of the safe
// one: the first version of this check matched `process.pid` anywhere in the
// file and so still passed with the assignment reverted, because the catch
// block's cleanup carries the same expression.
check('saveDiskCache assigns a per-pid tmp path',
  /const tmpPath = filePath \+ '\.' \+ process\.pid \+ '\.tmp';/.test(src), true);
check('no shared filePath + \'.tmp\' form remains in nettools',
  /filePath \+ '\.tmp'/.test(src), false);

// ---- the startup sweep is liveness-aware ---------------------------------
const liveTmp = `${cacheFile}.${process.pid}.tmp`;   // owned by a process that IS running
const deadTmp = `${cacheFile}.999999.tmp`;           // pid that cannot exist
fs.writeFileSync(liveTmp, 'partial');
fs.writeFileSync(deadTmp, 'partial');
loadDiskCache(cacheFile, new Map(), TTL, MAX);
check('sweep keeps a tmp whose owner is alive', fs.existsSync(liveTmp), true);
check('sweep removes a tmp whose owner is gone', fs.existsSync(deadTmp), false);

// ---- a corrupt cache loads empty rather than throwing --------------------
// Documents the blast radius the fix exists to prevent. It is not silent --
// loadDiskCache logs "<cache> was unreadable (...); starting fresh" -- but it
// does not throw and it does not stop the scan, so the run proceeds with an
// empty cache and re-digs all 10,000 entries.
fs.writeFileSync(cacheFile, '{"a.invalid-A":{"result"');
const loaded = new Map();
let threw = false;
try { loadDiskCache(cacheFile, loaded, TTL, MAX); } catch { threw = true; }
check('a truncated cache file does not throw', threw, false);
check('a truncated cache file loads zero entries', loaded.size, 0);

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
