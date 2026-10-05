#!/usr/bin/env node
/**
 * har-capture.js — drive a REAL Windows Firefox (with uBO) from WSL and collect
 * its HAR automatically, then hand it to the HAR matcher.
 *
 *   node scripts/har-capture.js <url> [--config <cfg.json>] [--site <sel>] [--wait 45]
 *
 * PARKED -- does not work. Read this before spending time on it.
 *
 * What was verified working:
 *   - launching Windows Firefox from WSL via interop, with cleanup that matches
 *     processes by COMMAND LINE (never a PID diff -- see the note below)
 *   - building a capture profile and installing the real uBO xpi into it
 *     (confirmed active, v1.75.0, from extensions.json after a run)
 *   - `--devtools` (two dashes) DOES open the toolbox: window title read back as
 *     "Developer Tools - ...", with devtools.toolbox.selectedTool=netmonitor and
 *     devtools.everOpened written back to prefs.js
 *   - HarAutomation is live code, not dead: toolbox.js:4685 constructs it from
 *     initHarAutomation(), called at toolbox open (toolbox.js:1153), gated only
 *     on devtools.netmonitor.har.enableAutoExportToFile
 *
 * What never happened: a HAR file. Tried defaultLogDir as an absolute path and
 * as "" (Firefox's documented <profile>/har/logs default), with
 * pageLoadedTimeout at 2500 and 12000. No file, and no <profile>/har/logs
 * directory was created at all -- so the export step is never reached, which
 * rules out path and permission problems.
 *
 * Best remaining theory: HarAutomation collects around a PAGE LOAD event, and
 * here the toolbox finishes opening after the URL (passed on the command line)
 * has already begun loading, so there is no load for it to bracket.
 * `forceExport` only governs whether an empty HAR is written for a load that
 * WAS seen. Testing that means opening devtools on a blank page, letting the
 * toolbox settle, and only then navigating -- which needs a way to drive an
 * already-open window, i.e. remote control, which is what this whole approach
 * existed to avoid.
 *
 * Use scripts/har-rules.js with a manually saved HAR instead (F12 > Network >
 * right-click > Save All As HAR). That path is proven end to end.
 *
 * Firefox can in principle export a HAR on every page load by itself, via:
 *   devtools.netmonitor.har.enableAutoExportToFile / defaultLogDir / forceExport
 * There is no CDP, no remote-debugging port and no interaction with whatever
 * browser the user already has open. HarAutomation attaches to the devtools
 * TOOLBOX, so devtools must be open -- hence --devtools and a visible window
 * (headless has no toolbox).
 *
 * Processes are matched by COMMAND LINE, never by diffing process lists: a live
 * browser spawns and retires content processes constantly, so a PID diff will
 * happily kill the user's own tabs.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile, execFileSync } = require('child_process');

const FF = '/mnt/c/Program Files/Mozilla Firefox/firefox.exe';
const PS = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe';
const WIN_ROOT = 'C:\\Temp\\nwss-har';
const WSL_ROOT = '/mnt/c/Temp/nwss-har';
const MARKER = 'nwss-har';                   // the profile path, which only our processes carry

const args = process.argv.slice(2);
const url = args.find(a => !a.startsWith('--'));
const argOf = (n, d) => { const i = args.indexOf(n); return i !== -1 && args[i + 1] ? args[i + 1] : d; };
if (!url) { console.error('usage: node scripts/har-capture.js <url> [--config cfg.json] [--site sel] [--wait 45]'); process.exit(1); }
const waitSec = parseInt(argOf('--wait', '45'), 10);

function sh(cmd) { try { return execFileSync(PS, ['-NoProfile', '-Command', cmd], { encoding: 'utf8' }); } catch { return ''; } }

// --- 1. capture profile: minimal, with uBO copied in -----------------------
const profile = path.join(WSL_ROOT, 'profile');
const harDir = path.join(WSL_ROOT, 'logs');
fs.rmSync(profile, { recursive: true, force: true });
fs.mkdirSync(path.join(profile, 'extensions'), { recursive: true });
fs.mkdirSync(harDir, { recursive: true });

const ffProfiles = '/mnt/c/Users/' + (process.env.WINUSER || 'mp3ge') + '/AppData/Roaming/Mozilla/Firefox/Profiles';
let xpi = null;
for (const d of fs.existsSync(ffProfiles) ? fs.readdirSync(ffProfiles) : []) {
  const p = path.join(ffProfiles, d, 'extensions', 'uBlock0@raymondhill.net.xpi');
  if (fs.existsSync(p)) { xpi = p; break; }
}
if (xpi) {
  fs.copyFileSync(xpi, path.join(profile, 'extensions', 'uBlock0@raymondhill.net.xpi'));
  console.log(`  uBO: copied from ${xpi.split('/Profiles/')[1].split('/')[0]}`);
} else {
  console.log('  uBO: NOT FOUND — capture will run without a content blocker');
}

fs.writeFileSync(path.join(profile, 'user.js'), [
  // Auto-export a HAR per page load -- the whole point.
  'user_pref("devtools.netmonitor.har.enableAutoExportToFile", true);',
  `user_pref("devtools.netmonitor.har.defaultLogDir", "${WIN_ROOT.replace(/\\/g, '\\\\')}\\\\logs");`,
  'user_pref("devtools.netmonitor.har.defaultFileName", "nwss-%y%m%d-%H%M%S");',
  'user_pref("devtools.netmonitor.har.forceExport", true);',
  'user_pref("devtools.netmonitor.har.pageLoadedTimeout", 2500);',
  'user_pref("devtools.netmonitor.har.includeResponseBodies", false);',
  // Devtools must be open for HarAutomation to attach to a toolbox.
  'user_pref("devtools.toolbox.selectedTool", "netmonitor");',
  'user_pref("devtools.toolbox.host", "window");',
  'user_pref("devtools.everOpened", true);',
  'user_pref("devtools.netmonitor.persistlog", true);',
  // Keep the run quiet and deterministic.
  'user_pref("browser.shell.checkDefaultBrowser", false);',
  'user_pref("browser.startup.homepage_override.mstone", "ignore");',
  'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
  'user_pref("browser.aboutwelcome.enabled", false);',
  'user_pref("extensions.autoDisableScopes", 0);',
  'user_pref("extensions.enabledScopes", 15);'
].join('\n') + '\n');

// --- 2. launch, wait for a HAR to appear -----------------------------------
const before = new Set(fs.readdirSync(harDir));
console.log(`  launching Firefox (devtools open, ${waitSec}s budget) …`);
// --devtools (two dashes, per firefox --help) opens DevTools on load, which is
// what HarAutomation needs to attach to. No synthetic marker flag: Firefox
// rejects unknown options, and the profile path already identifies our
// processes uniquely for cleanup.
const child = execFile(FF, [
  '-no-remote', '-profile', `${WIN_ROOT}\\profile`, '--devtools',
  '-new-instance', url
], () => {});
child.unref();

const deadline = Date.now() + waitSec * 1000;
let found = null;
(function poll() {
  const fresh = fs.readdirSync(harDir).filter(f => !before.has(f) && f.endsWith('.har'));
  if (fresh.length) { found = path.join(harDir, fresh[0]); return done(); }
  if (Date.now() > deadline) return done();
  setTimeout(poll, 2000);
})();

function done() {
  // Kill ONLY processes whose command line carries our marker/profile.
  sh(`Get-CimInstance Win32_Process -Filter "Name='firefox.exe'" | Where-Object { $_.CommandLine -like '*${MARKER}*' -or $_.CommandLine -like '*nwss-har*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`);
  if (!found) {
    console.log(`  no HAR produced within ${waitSec}s (looked in ${harDir})`);
    process.exit(2);
  }
  const size = fs.statSync(found).size;
  console.log(`  HAR written: ${path.basename(found)} (${size} bytes)`);
  const rest = ['--config', argOf('--config', ''), '--site', argOf('--site', '0')].filter(Boolean);
  execFile(process.execPath, [path.join(__dirname, 'har-rules.js'), found, ...rest],
    { encoding: 'utf8' }, (e, out) => { process.stdout.write(out || String(e)); });
}
