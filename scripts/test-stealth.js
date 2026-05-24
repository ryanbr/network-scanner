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
 *   node scripts/test-stealth.js                  # all targets
 *   node scripts/test-stealth.js sannysoft        # one target
 *   node scripts/test-stealth.js --headful        # show browser GUI
 *   node scripts/test-stealth.js --no-spoof       # baseline (no fingerprint protection)
 *   node scripts/test-stealth.js --ua=firefox     # change UA family
 *
 * Targets (extend by adding to TARGETS below):
 *   sannysoft     https://bot.sannysoft.com/         — classic fingerprint tests
 *   creepjs       https://abrahamjuliot.github.io/creepjs/  — modern fingerprint suite
 *   browserleaks  https://browserleaks.com/javascript        — JS env probe
 *
 * Output: one line per target with PASS / WARN / FAIL counts (where parseable),
 * plus a short summary of any explicit detection markers ("Bot detected",
 * "Headless", etc.) found in the page text.
 *
 * This is a SMOKE test, not a unit test. It doesn't make assertions; it
 * reports what the page reports. Use the output to decide if a stealth
 * change moved the needle.
 */

'use strict';

const puppeteer = require('puppeteer');
const path = require('path');
const { applyAllFingerprintSpoofing } = require(path.resolve(__dirname, '..', 'lib', 'fingerprint'));

const args = process.argv.slice(2);
const HEADFUL = args.includes('--headful');
const NO_SPOOF = args.includes('--no-spoof');
const UA_FLAG = (args.find(a => a.startsWith('--ua=')) || '').slice(5) || 'chrome';
const filterTargets = args.filter(a => !a.startsWith('--'));

const TARGETS = [
  {
    name: 'sannysoft',
    url: 'https://bot.sannysoft.com/',
    // Parse the result tables. Sannysoft uses td.passed / td.failed / td.warn.
    extract: async (page) => {
      return await page.evaluate(() => {
        const cells = Array.from(document.querySelectorAll('td'));
        const out = { passed: 0, failed: 0, warn: 0, total: 0, failures: [] };
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
          else if (cls.includes('warn')) { out.warn++; out.total++; }
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

function formatResult(target, result) {
  const lines = [`\n=== ${target.name} (${target.url}) ===`];
  if (target.name === 'sannysoft') {
    lines.push(`  passed: ${result.passed} | warn: ${result.warn} | failed: ${result.failed} | total: ${result.total}`);
    if (result.failures.length) {
      lines.push(`  failure rows: ${result.failures.slice(0, 10).join(', ')}${result.failures.length > 10 ? ` ... +${result.failures.length - 10} more` : ''}`);
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
  const targetsToRun = filterTargets.length
    ? TARGETS.filter(t => filterTargets.includes(t.name))
    : TARGETS;

  if (targetsToRun.length === 0) {
    console.error(`No targets matched. Available: ${TARGETS.map(t => t.name).join(', ')}`);
    process.exit(2);
  }

  console.log(`Stealth test config: spoof=${!NO_SPOOF}, ua=${UA_FLAG}, headful=${HEADFUL}`);
  console.log(`Targets: ${targetsToRun.map(t => t.name).join(', ')}`);

  const browser = await puppeteer.launch({
    headless: !HEADFUL,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-blink-features=AutomationControlled'
    ]
  });

  try {
    for (const target of targetsToRun) {
      const page = await browser.newPage();
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
        console.log(formatResult(target, result));
      } catch (err) {
        console.error(`\n=== ${target.name} (${target.url}) ===`);
        console.error(`  ERROR: ${err.message}`);
      } finally {
        await page.close().catch(() => {});
      }
    }
  } finally {
    await browser.close().catch(() => {});
  }
})().catch(err => {
  console.error('test-stealth fatal:', err);
  process.exit(1);
});
