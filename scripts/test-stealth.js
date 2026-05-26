#!/usr/bin/env node
/**
 * Stealth integration smoke test.
 *
 * Launches Puppeteer, applies the project's full fingerprint spoofing stack
 * (lib/fingerprint.js's applyAllFingerprintSpoofing), navigates to public
 * bot-detection test pages, and reports what the page concluded about us.
 *
 * Purpose: replace "I think the spoof works" theoretical reviews with real
 * signal -- which checks pass, which fail, which moved after a fingerprint
 * change. Run before and after a stealth-related commit to A/B the impact.
 *
 * Usage:
 *   node scripts/test-stealth.js                  # all targets, human-readable
 *   node scripts/test-stealth.js sannysoft        # one target
 *   node scripts/test-stealth.js --headful        # show browser GUI
 *   node scripts/test-stealth.js --no-spoof       # baseline (no fingerprint protection)
 *   node scripts/test-stealth.js --ua=firefox     # change UA family
 *   node scripts/test-stealth.js --format=json    # machine-readable output
 *   node scripts/test-stealth.js --help           # show usage
 *
 * Environment:
 *   PUPPETEER_NO_SANDBOX=1   pass --no-sandbox --disable-setuid-sandbox to
 *                            Chromium. Required when running as root (CI
 *                            containers, some Docker setups). Off by default
 *                            so local dev doesn't silently drop the sandbox.
 *
 * Targets (extend by adding to TARGETS below):
 *   sannysoft     https://bot.sannysoft.com/                  — classic fingerprint tests
 *   creepjs       https://abrahamjuliot.github.io/creepjs/    — modern fingerprint suite
 *   browserleaks  https://browserleaks.com/javascript         — JS env probe
 *
 * Output: one line per target with PASS / WARN / FAIL counts (where parseable),
 * plus a short summary of any explicit detection markers ("Bot detected",
 * "Headless", etc.) found in the page text. With --format=json, emits a single
 * JSON object suitable for piping to diff/jq for before/after comparison.
 *
 * This is a SMOKE test, not a unit test. It doesn't make assertions; it
 * reports what the page reports. Use the output to decide if a stealth
 * change moved the needle.
 */

'use strict';

const puppeteer = require('puppeteer');
const path = require('path');
const {
  applyAllFingerprintSpoofing,
  USER_AGENT_COLLECTIONS
} = require(path.resolve(__dirname, '..', 'lib', 'fingerprint'));

const args = process.argv.slice(2);
const HELP = args.includes('--help') || args.includes('-h');
const HEADFUL = args.includes('--headful');
const NO_SPOOF = args.includes('--no-spoof');
const UA_FLAG = (args.find(a => a.startsWith('--ua=')) || '').slice(5) || 'chrome';
const FORMAT = (args.find(a => a.startsWith('--format=')) || '').slice(9) || 'text';
const filterTargets = args.filter(a => !a.startsWith('-'));
// Anything starting with '-' is a flag claim; we validate the known set
// below so typos like "-headful" or "--no_spoof" don't silently no-op.
const flagArgs = args.filter(a => a.startsWith('-'));
const KNOWN_FLAGS = new Set(['--headful', '--no-spoof', '--help', '-h']);
const KNOWN_FLAG_PREFIXES = ['--ua=', '--format='];

const TARGETS = [
  {
    name: 'sannysoft',
    url: 'https://bot.sannysoft.com/',
    // Parse the result tables. Sannysoft uses td.passed / td.failed / td.warn.
    extract: async (page) => {
      return await page.evaluate(() => {
        const cells = Array.from(document.querySelectorAll('td'));
        const out = { passed: 0, failed: 0, warn: 0, total: 0, failures: [], warnings: [] };
        for (const c of cells) {
          const cls = c.className || '';
          if (cls.includes('passed')) { out.passed++; out.total++; }
          else if (cls.includes('failed')) {
            out.failed++; out.total++;
            // Try to capture the row label for context
            const row = c.closest('tr');
            const label = row?.querySelector('td')?.textContent?.trim() || '?';
            out.failures.push(label);
          }
          else if (cls.includes('warn')) {
            out.warn++; out.total++;
            // Capture warn-row labels too so a soft regression (cell moving
            // passed -> warn) is debuggable without --headful.
            const row = c.closest('tr');
            const label = row?.querySelector('td')?.textContent?.trim() || '?';
            out.warnings.push(label);
          }
        }
        return out;
      });
    }
  },
  {
    name: 'creepjs',
    url: 'https://abrahamjuliot.github.io/creepjs/',
    extract: async (page) => {
      // CreepJS surfaces a trust score in the page. Wait briefly for the
      // async fingerprinting tests to complete.
      await page.waitForSelector('#fingerprint-data', { timeout: 30000 }).catch(() => {});
      await new Promise(r => setTimeout(r, 8000)); // give async tests time
      return await page.evaluate(() => {
        const text = document.body.innerText || '';
        // CreepJS reports a "Trust Score" percentage and individual signal entries.
        const trustMatch = text.match(/Trust Score[:\s]+(\d+(?:\.\d+)?)\s*%/i);
        const lieMatch = text.match(/lies[:\s]+(\d+)/i);
        const botMatch = text.match(/bot[:\s]+(true|false)/i);
        return {
          trustScore: trustMatch ? parseFloat(trustMatch[1]) : null,
          lies: lieMatch ? parseInt(lieMatch[1], 10) : null,
          botDetected: botMatch ? botMatch[1] === 'true' : null,
          excerpt: text.split('\n').slice(0, 15).join('\n').slice(0, 400)
        };
      });
    }
  },
  {
    name: 'browserleaks',
    url: 'https://browserleaks.com/javascript',
    extract: async (page) => {
      return await page.evaluate(() => {
        // browserleaks shows the values; we just capture the navigator-related ones
        // and report which look anomalous.
        return {
          userAgent: navigator.userAgent,
          platform: navigator.platform,
          webdriver: navigator.webdriver,
          languages: JSON.stringify(navigator.languages),
          hardwareConcurrency: navigator.hardwareConcurrency,
          deviceMemory: navigator.deviceMemory,
          plugins: navigator.plugins?.length,
          chromeRuntime: typeof window.chrome?.runtime,
          chromeRuntimeVersion: (() => { try { return window.chrome?.runtime?.getManifest?.()?.version; } catch (e) { return 'error'; } })(),
          windowChromeDescriptor: (() => {
            const d = Object.getOwnPropertyDescriptor(window, 'chrome');
            return d ? `writable=${d.writable},enumerable=${d.enumerable},configurable=${d.configurable}` : 'no-descriptor';
          })(),
          errorName: Error.name,
          errorLength: Error.length,
          rtcName: window.RTCPeerConnection?.name,
          imageName: window.Image?.name
        };
      });
    }
  }
];

function printHelp() {
  console.log(`Usage: node scripts/test-stealth.js [options] [target...]

Options:
  --headful           launch with browser GUI visible
  --no-spoof          baseline run — skip applyAllFingerprintSpoofing
  --ua=<family>       UA family to spoof (default: chrome)
                      valid: ${Array.from(USER_AGENT_COLLECTIONS.keys()).join(', ')}
  --format=<fmt>      output format: text (default) | json
  --help, -h          show this message

Environment:
  PUPPETEER_NO_SANDBOX=1   pass --no-sandbox to Chromium (required in some CI)

Targets: ${TARGETS.map(t => t.name).join(', ')} (default: all)`);
}

function formatResult(target, result) {
  const lines = [`\n=== ${target.name} (${target.url}) ===`];
  if (target.name === 'sannysoft') {
    lines.push(`  passed: ${result.passed} | warn: ${result.warn} | failed: ${result.failed} | total: ${result.total}`);
    if (result.failures.length) {
      lines.push(`  failure rows: ${result.failures.slice(0, 10).join(', ')}${result.failures.length > 10 ? ` ... +${result.failures.length - 10} more` : ''}`);
    }
    if (result.warnings && result.warnings.length) {
      lines.push(`  warn rows: ${result.warnings.slice(0, 10).join(', ')}${result.warnings.length > 10 ? ` ... +${result.warnings.length - 10} more` : ''}`);
    }
  } else if (target.name === 'creepjs') {
    lines.push(`  trust score: ${result.trustScore ?? 'n/a'}%`);
    lines.push(`  lies detected: ${result.lies ?? 'n/a'}`);
    lines.push(`  bot flagged: ${result.botDetected ?? 'n/a'}`);
    if (result.excerpt) lines.push(`  excerpt:\n    ${result.excerpt.split('\n').join('\n    ')}`);
  } else if (target.name === 'browserleaks') {
    for (const [k, v] of Object.entries(result)) {
      lines.push(`  ${k.padEnd(24)} ${v}`);
    }
  }
  return lines.join('\n');
}

(async () => {
  if (HELP) { printHelp(); process.exit(0); }

  // Validate --ua= against the canonical UA list. Previously a typo like
  // --ua=opera silently fell through to applyUserAgentSpoofing's "unknown UA,
  // no-op" path, producing run results that looked spoofed but weren't.
  if (!USER_AGENT_COLLECTIONS.has(UA_FLAG)) {
    console.error(`Invalid --ua=${UA_FLAG}. Valid: ${Array.from(USER_AGENT_COLLECTIONS.keys()).join(', ')}`);
    process.exit(2);
  }

  if (!['text', 'json'].includes(FORMAT)) {
    console.error(`Invalid --format=${FORMAT}. Valid: text, json`);
    process.exit(2);
  }

  // Reject unrecognised flags before we launch a browser. Typos like
  // "-headful" or "--no_spoof" used to silently no-op and produce a
  // misleading "spoof on" run that wasn't actually spoofed.
  const badFlags = flagArgs.filter(f =>
    !KNOWN_FLAGS.has(f) && !KNOWN_FLAG_PREFIXES.some(p => f.startsWith(p))
  );
  if (badFlags.length) {
    console.error(`Unrecognised flag(s): ${badFlags.join(', ')}. See --help.`);
    process.exit(2);
  }

  const targetsToRun = filterTargets.length
    ? TARGETS.filter(t => filterTargets.includes(t.name))
    : TARGETS;

  if (targetsToRun.length === 0) {
    console.error(`No targets matched. Available: ${TARGETS.map(t => t.name).join(', ')}`);
    process.exit(2);
  }

  if (FORMAT === 'text') {
    console.log(`Stealth test config: spoof=${!NO_SPOOF}, ua=${UA_FLAG}, headful=${HEADFUL}`);
    console.log(`Targets: ${targetsToRun.map(t => t.name).join(', ')}`);
  }

  // Sandbox is on by default; opt out via env var rather than baking
  // --no-sandbox into the launch line. CI-as-root needs it; local dev should
  // not silently drop the sandbox just because the test happens to start it.
  const launchArgs = ['--disable-blink-features=AutomationControlled'];
  if (process.env.PUPPETEER_NO_SANDBOX === '1') {
    launchArgs.push('--no-sandbox', '--disable-setuid-sandbox');
  }

  const browser = await puppeteer.launch({
    headless: !HEADFUL,
    args: launchArgs
  });

  // Collected for JSON output (and to support a future --fail-on-detection
  // exit code without restructuring the loop).
  const collected = [];

  try {
    for (const target of targetsToRun) {
      const page = await browser.newPage();
      const started = Date.now();
      try {
        if (!NO_SPOOF) {
          // Apply the same spoofing stack nwss.js uses for real scans.
          await applyAllFingerprintSpoofing(page,
            { userAgent: UA_FLAG, fingerprint_protection: 'random' },
            false,
            target.url
          );
        }
        await page.goto(target.url, { waitUntil: 'networkidle2', timeout: 60000 });
        const result = await target.extract(page);
        collected.push({ name: target.name, url: target.url, ok: true, durationMs: Date.now() - started, result });
        if (FORMAT === 'text') console.log(formatResult(target, result));
      } catch (err) {
        collected.push({ name: target.name, url: target.url, ok: false, durationMs: Date.now() - started, error: err.message });
        if (FORMAT === 'text') {
          console.error(`\n=== ${target.name} (${target.url}) ===`);
          console.error(`  ERROR: ${err.message}`);
        }
      } finally {
        await page.close().catch(() => {});
      }
    }
  } finally {
    await browser.close().catch(() => {});
  }

  if (FORMAT === 'json') {
    // Single object, not NDJSON — easier to diff with `jq` or `diff` between
    // before/after runs. Schema is stable: top-level config + targets[].
    process.stdout.write(JSON.stringify({
      config: { spoof: !NO_SPOOF, ua: UA_FLAG, headful: HEADFUL, noSandbox: process.env.PUPPETEER_NO_SANDBOX === '1' },
      targets: collected
    }, null, 2) + '\n');
  }
})().catch(err => {
  console.error('test-stealth fatal:', err);
  process.exit(1);
});
