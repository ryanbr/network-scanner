#!/usr/bin/env node
/**
 * har-capture.js — drive a REAL Windows Firefox (with uBO) from WSL and collect
 * its HAR automatically, then hand it to the HAR matcher.
 *
 *   node scripts/har-capture.js <url> [--config <cfg.json>] [--site <sel>] [--wait 45]
 *
 * Firefox can export a HAR on every page load by itself, driven by prefs:
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
const MARKER = 'nwss-har-capture';           // appears in our command line only

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
const child = execFile(FF, [
  '-no-remote', '-profile', `${WIN_ROOT}\\profile`, '-devtools',
  '-new-instance', url, `-${MARKER}`
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
