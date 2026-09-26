#!/usr/bin/env node
/**
 * What --clear-cache is allowed to delete.
 *
 * This ran `fs.rmSync(cachePath, { recursive: true, force: true })` on a path
 * taken straight from the user's `cache_path`, which made --clear-cache a
 * recursive delete of whatever directory they named. Two things made that worse
 * than it sounds: persistence is off by default (and nwss hardcodes it off), so
 * the directory is usually not one nwss ever wrote; and nothing else stores
 * anything there either -- the adblock-rs disk cache lives under
 * os.tmpdir()/nwss-adblock-rs-cache. Demonstrated against a directory holding
 * only user files: 2 entries before, directory gone after.
 *
 * The rule now is that only this module's own files go, by name --
 * smart-cache.json and its pid-suffixed .tmp siblings -- and the directory
 * itself only when removing them leaves it empty. A cachePath that points at a
 * file is honoured only when that file IS smart-cache.json.
 *
 * Same shape as the guarded temp sweep in lib/browserexit.js: name what you
 * own, leave everything else, say so under --debug.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { clearPersistentCache } = require('../lib/smart-cache');

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};
const tmpDir = (label) => fs.mkdtempSync(path.join(os.tmpdir(), `nwss-clearcache-${label}-`));

// 1. a dedicated cache dir holding only our files: cleared, directory removed
let dir = tmpDir('own');
fs.writeFileSync(path.join(dir, 'smart-cache.json'), '{"timestamp":1}');
fs.writeFileSync(path.join(dir, 'smart-cache.json.4242.tmp'), 'partial');
let r = clearPersistentCache({ silent: true, cachePath: dir });
check('own cache file + stranded temp are removed', !fs.existsSync(dir),
  `dir gone=${!fs.existsSync(dir)} clearedItems=${r.clearedItems} errors=${r.errors.length}`);

// 2. a dir holding UNRELATED user data: our file goes, everything else survives
dir = tmpDir('mixed');
fs.writeFileSync(path.join(dir, 'smart-cache.json'), '{"timestamp":1}');
fs.writeFileSync(path.join(dir, 'important.txt'), 'do not delete');
fs.mkdirSync(path.join(dir, 'subdir'));
fs.writeFileSync(path.join(dir, 'subdir', 'deep.txt'), 'also do not delete');
r = clearPersistentCache({ silent: true, cachePath: dir });
check('unrelated files survive', fs.existsSync(path.join(dir, 'important.txt')) && fs.existsSync(path.join(dir, 'subdir', 'deep.txt')),
  `important.txt=${fs.existsSync(path.join(dir,'important.txt'))} subdir/deep.txt=${fs.existsSync(path.join(dir,'subdir','deep.txt'))}`);
check('our file still cleared from a shared dir', !fs.existsSync(path.join(dir, 'smart-cache.json')) && r.clearedItems === 1,
  `clearedItems=${r.clearedItems}`);
check('shared directory itself is kept', fs.existsSync(dir), `exists=${fs.existsSync(dir)}`);

// 3. THE DANGEROUS CASE: cache_path pointing at a directory of user data with
//    no cache in it at all. Nothing may be touched.
dir = tmpDir('nocache');
fs.writeFileSync(path.join(dir, 'source.js'), 'module.exports = 1;');
fs.mkdirSync(path.join(dir, 'nested')); fs.writeFileSync(path.join(dir, 'nested', 'a.txt'), 'x');
const before = fs.readdirSync(dir).sort().join(',');
r = clearPersistentCache({ silent: true, cachePath: dir });
check('a directory with no cache in it is untouched',
  fs.existsSync(dir) && fs.readdirSync(dir).sort().join(',') === before && r.clearedItems === 0,
  `contents unchanged=${fs.readdirSync(dir).sort().join(',') === before} clearedItems=${r.clearedItems}`);

// 3b. The user is told WHY a directory survived. This is also what makes the
//     emptiness check observable: fs.rmdirSync is non-recursive, so the OS
//     refuses a non-empty directory with ENOTEMPTY regardless -- the check
//     itself only earns its keep through this line (verified by mutating the
//     check out, which changes nothing else).
dir = tmpDir('kept-report');
fs.writeFileSync(path.join(dir, 'smart-cache.json'), '{"timestamp":1}');
fs.writeFileSync(path.join(dir, 'keep.txt'), 'x');
const logged = [];
const realLog = console.log;
console.log = (...a) => logged.push(a.join(' '));
clearPersistentCache({ silent: true, forceDebug: true, cachePath: dir });
console.log = realLog;
check('a kept directory is explained under forceDebug',
  logged.some(l => l.includes('Kept') && l.includes(dir) && l.includes('not ours')),
  logged.filter(l => l.includes('Kept')).join(' | ') || 'no "Kept" line');

// 4. cachePath pointing at an arbitrary FILE: refused, file survives
const f = path.join(tmpDir('file'), 'my-notes.txt');
fs.writeFileSync(f, 'keep me');
r = clearPersistentCache({ silent: true, cachePath: f });
check('an arbitrary file is refused, not unlinked', fs.existsSync(f) && r.success === false,
  `exists=${fs.existsSync(f)} success=${r.success} err=${r.errors[0] && r.errors[0].error}`);

// 5. cachePath pointing directly AT our cache file: honoured
const f2 = path.join(tmpDir('direct'), 'smart-cache.json');
fs.writeFileSync(f2, '{"timestamp":1}');
r = clearPersistentCache({ silent: true, cachePath: f2 });
check('cachePath pointing at smart-cache.json is honoured', !fs.existsSync(f2) && r.clearedItems === 1,
  `gone=${!fs.existsSync(f2)} clearedItems=${r.clearedItems}`);

// 6. missing path: no error, nothing cleared
r = clearPersistentCache({ silent: true, cachePath: path.join(os.tmpdir(), 'nwss-cc-does-not-exist-' + Date.now()) });
check('missing cache path is not an error', r.success === true && r.clearedItems === 0,
  `success=${r.success} clearedItems=${r.clearedItems}`);

console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
