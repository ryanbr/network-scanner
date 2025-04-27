// Network scanner script

const puppeteer = require('puppeteer');
const fs = require('fs');
const psl = require('psl');

const args = process.argv.slice(2);

let outputFile = 'adblock_rules.txt';
const outputIndex = args.findIndex(arg => arg === '--output' || arg === '-o');
if (outputIndex !== -1 && args[outputIndex + 1]) {
  outputFile = args[outputIndex + 1];
}

const forceVerbose = args.includes('--verbose');
const forceDebug = args.includes('--debug');
const silentMode = args.includes('--silent');
const showTitles = args.includes('--titles');
const dumpUrls = args.includes('--dumpurls');
const subDomainsMode = args.includes('--sub-domains');
const localhostMode = args.includes('--localhost');
const localhostModeAlt = args.includes('--localhost-0.0.0.0');

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
Usage: node scanner-script.js [options]

Options:
  -o, --output <file>         Output file (default: adblock_rules.txt)
  --verbose                   Force verbose mode globally
  --debug                     Force debug mode globally
  --silent                    Suppress normal console logs
  --titles                    Add ! <url> title before each site's group
  --dumpurls                  Dump full matched URLs into matched_urls.log
  --sub-domains               Output full subdomains instead of collapsing
  --localhost                 Output as 127.0.0.1 domain.com
  --localhost-0.0.0.0         Output as 0.0.0.0 domain.com
  --help, -h                  Show this help menu

Per-site options in config.json:
  interact: true/false            Fake mouse move, click, hover (default: false)
  isBrave: true/false              Fake Brave browser detection (default: false)
`);
  process.exit(0);
}

const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));
const { sites = [], ignoreDomains = [] } = config;

function getRootDomain(url) {
  try {
    const { hostname } = new URL(url);
    const parsed = psl.parse(hostname);
    return parsed.domain || hostname;
  } catch {
    return '';
  }
}

(async () => {
  const browser = await puppeteer.launch({ headless: true, protocolTimeout: 180000 });
  const siteRules = [];

  for (const site of sites) {
    const allowFirstParty = site.firstParty === 1;
    const allowThirdParty = site.thirdParty === undefined || site.thirdParty === 1;

    if (site.firstParty === 0 && site.thirdParty === 0) {
      console.warn(`⚠ Skipping ${site.url} because both firstParty and thirdParty are explicitly disabled.`);
      continue;
    }

    if (!silentMode) console.log(`\nScanning: ${site.url}`);

    let page;
    try {
      const isBraveEnabled = site.isBrave === true;
      page = await browser.newPage();
      await page.setRequestInterception(true);
      if (isBraveEnabled) {
        await page.evaluateOnNewDocument(() => {
          Object.defineProperty(navigator, 'brave', {
            get: () => ({ isBrave: () => Promise.resolve(true) })
          });
        });
        if (forceDebug) console.log(`    [debug] isBrave faked`);
      }
    } catch (err) {
      console.warn(`⚠ Failed to open page: ${err.message}`);
      continue;
    }

    const regexes = Array.isArray(site.filterRegex)
      ? site.filterRegex.map(r => new RegExp(r.replace(/^\/(.*)\/$/, '$1')))
      : [new RegExp(site.filterRegex.replace(/^\/(.*)\/$/, '$1'))];

    const matchedDomains = new Set();

    const blockedRegexes = Array.isArray(site.blocked) ? site.blocked.map(pattern => new RegExp(pattern)) : [];

    page.on('request', request => {
      const reqUrl = request.url();

      if (blockedRegexes.some(re => re.test(reqUrl))) {
        if (forceDebug) {
          console.log(`    [debug] Blocked: ${reqUrl}`);
        }
        request.abort();
        return;
      }
      const reqDomain = subDomainsMode ? (new URL(reqUrl)).hostname : getRootDomain(reqUrl);

      if (!reqDomain || ignoreDomains.some(domain => reqDomain.endsWith(domain))) {
        request.continue();
        return;
      }

      const isThirdPartyRequest = true;

      if (((allowFirstParty && !isThirdPartyRequest) || (allowThirdParty && isThirdPartyRequest)) && regexes.some(re => re.test(reqUrl))) {
        matchedDomains.add(reqDomain);
        if (forceDebug) {
          console.log(`    [debug] Request matched: ${reqUrl}`);
        }
        if (dumpUrls) {
          fs.appendFileSync('matched_urls.log', `${reqUrl}\n`);
        }
      }

      request.continue();
    });

    try {
const interactEnabled = site.interact === true;

await page.goto(site.url, { waitUntil: 'domcontentloaded', timeout: site.timeout || 30000 });

if (interactEnabled) {
  try {
    const randomX = Math.floor(Math.random() * 500) + 50;
    const randomY = Math.floor(Math.random() * 500) + 50;
    await page.mouse.move(randomX, randomY, { steps: 10 });
    await page.mouse.move(randomX + 50, randomY + 50, { steps: 15 });
    await page.mouse.click(randomX + 25, randomY + 25);
    await page.hover('body');
    if (forceDebug) console.log(`    [debug] Randomly interacted during loading at (${randomX}, ${randomY})`);
  } catch (e) {
    if (forceDebug) console.log(`    [debug] Interaction during load failed: ${e.message}`);
  }
}

    await page.waitForNetworkIdle({ idleTime: 2000, timeout: site.timeout || 30000 });
    await new Promise(resolve => setTimeout(resolve, site.delay || 2000));

      for (let i = 1; i < (site.reload || 1); i++) {
        if (!silentMode && site.reload > 1) console.log(`  → Reload ${i+1}/${site.reload}`);
        await page.reload({ waitUntil: 'networkidle2', timeout: site.timeout || 30000 });
        await new Promise(resolve => setTimeout(resolve, site.delay || 2000));
      }
    } catch (err) {
      console.warn(`⚠ Failed to load: ${site.url} (${err.message})`);
    }

    const siteMatchedDomains = [];

    matchedDomains.forEach(domain => {
      if (domain.length > 6 && domain.includes('.')) {
        if (localhostMode) {
          siteMatchedDomains.push(`127.0.0.1 ${domain}`);
        } else if (localhostModeAlt) {
          siteMatchedDomains.push(`0.0.0.0 ${domain}`);
        } else {
          siteMatchedDomains.push(`||${domain}^`);
        }
      }
    });

    siteRules.push({
      url: site.url,
      rules: siteMatchedDomains
    });

    if (page) await page.close();
  }

  const outputLines = [];

  for (const { url, rules } of siteRules) {
    if (rules.length > 0) {
      if (showTitles) outputLines.push(`! ${url}`);
      outputLines.push(...rules);
    }
  }

  fs.writeFileSync(outputFile, outputLines.join('\n'));

  if (!silentMode) console.log(`Adblock rules saved to ${outputFile}`);

  await browser.close();
  process.exit(0);
})();

