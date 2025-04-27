// thirdPartyScanner.js

const puppeteer = require('puppeteer');
const fs = require('fs');
const psl = require('psl');

const args = process.argv.slice(2);

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
  --localhost                 Output as 127.0.0.1 <domain>
  --localhost-0.0.0.0         Output as 0.0.0.0 <domain>
  --help, -h                  Show this help menu
`);
  process.exit(0);
}

const forceVerbose = args.includes('--verbose');
const subDomainsMode = args.includes('--sub-domains');
const localhostMode = args.includes('--localhost');
const localhostModeAlt = args.includes('--localhost-0.0.0.0');
const silentMode = args.includes('--silent');
const forceDebug = args.includes('--debug');
const dumpUrls = args.includes('--dumpurls');
const showTitles = args.includes('--titles');

let outputFile = 'adblock_rules.txt';
const outputIndex = args.findIndex(arg => arg === '--output' || arg === '-o');
if (outputIndex !== -1 && args[outputIndex + 1]) {
  outputFile = args[outputIndex + 1];
}

const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));
const { sites = [], ignoreDomains = [] } = config;

function isThirdParty(reqUrl, pageUrl) {
  try {
    const reqDomain = new URL(reqUrl).hostname;
    const pageDomain = new URL(pageUrl).hostname;
    return !reqDomain.endsWith(pageDomain);
  } catch {
    return true;
  }
}

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

    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), 120000);

    try {
      const {
        url,
        userAgent,
        filterRegex = '.*',
        resourceTypes = ['script', 'image', 'xhr', 'stylesheet'],
        reload = 1,
        delay = 2000,
        timeout = 30000,
        verbose = 0,
        debug = 0
      } = site;

      if (!silentMode) console.log(`\nScanning: ${url}`);

      let page;
      try {
        page = await browser.newPage();
        await page.setRequestInterception(true);
      } catch (err) {
        console.warn(`⚠ Failed to open page or enable interception: ${err.message}`);
        continue;
      }

      const regexes = Array.isArray(filterRegex)
        ? filterRegex.map(r => new RegExp(r.replace(/^\/(.*)\/$/, '$1')))
        : [new RegExp(filterRegex.replace(/^\/(.*)\/$/, '$1'))];

      const matchedDomains = new Set();

      page.on('request', request => {
        const reqUrl = request.url();
        const reqDomain = getRootDomain(reqUrl);

        if (!reqDomain || ignoreDomains.some(domain => reqDomain.endsWith(domain))) {
          request.continue();
          return;
        }

        const isThirdPartyRequest = isThirdParty(reqUrl, url);

        if (((allowFirstParty && !isThirdPartyRequest) || (allowThirdParty && isThirdPartyRequest)) && regexes.some(re => re.test(reqUrl))) {
          matchedDomains.add(reqDomain);
          if (debug || dumpUrls) {
            console.log(`    [debug] Request matched: ${reqUrl}`);
            fs.appendFileSync('matched_urls.log', `${reqUrl}\n`);
          }
        }

        request.continue();
      });

      await page.goto(url, { waitUntil: 'networkidle2', timeout }).catch(err => {
        console.warn(`⚠ Failed to load: ${url} (${err.message})`);
      });

      await new Promise(resolve => setTimeout(resolve, delay));

      for (let i = 1; i < reload; i++) {
        if (reload > 1 && !silentMode) console.log(`  → Reload ${i+1}/${reload}`);
        await page.reload({ waitUntil: 'networkidle2', timeout }).catch(err => {
          console.warn(`⚠ Failed to reload: ${url} (${err.message})`);
        });
        await new Promise(resolve => setTimeout(resolve, delay));
      }

      const siteMatchedDomains = [];

      matchedDomains.forEach(domain => {
        if (domain.length > 6 && domain.includes('.')) {
          siteMatchedDomains.push(`||${domain}^`);
        }
      });

      siteRules.push({
        url,
        rules: siteMatchedDomains
      });

      if (page) await page.close();
    } finally {
      clearTimeout(timeoutHandle);
    }
  }

  const totalRules = siteRules.reduce((sum, site) => sum + site.rules.length, 0);

  if (!silentMode) console.log(`Collected ${totalRules} rules.`);

  if (totalRules === 0 && !silentMode) {
    console.warn('⚠ No matches found for any site.');
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

