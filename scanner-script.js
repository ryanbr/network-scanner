// === Network scanner script v0.8.7 ===

const puppeteer = require('puppeteer');
const fs = require('fs');
const psl = require('psl');

const VERSION = '0.8.7';

const DEFAULT_PLATFORM = 'Win32';
const DEFAULT_TIMEZONE = 'America/New_York';

const args = process.argv.slice(2);

// 🆕 Default to --help if no arguments are provided
if (args.length === 0) {
  args.push('--help');
}

const headfulMode = args.includes('--headful');
const SOURCES_FOLDER = 'sources';

let outputFile = null;
const outputIndex = args.findIndex(arg => arg === '--output' || arg === '-o');
if (outputIndex !== -1 && args[outputIndex + 1]) outputFile = args[outputIndex + 1];

const forceVerbose = args.includes('--verbose');
const forceDebug = args.includes('--debug');
const silentMode = args.includes('--silent');
const showTitles = args.includes('--titles');
const dumpUrls = args.includes('--dumpurls');
const subDomainsMode = args.includes('--sub-domains');
const localhostMode = args.includes('--localhost');
const localhostModeAlt = args.includes('--localhost-0.0.0.0');
const disableInteract = args.includes('--no-interact');
const plainOutput = args.includes('--plain');
const enableCDP = args.includes('--cdp');
let globalCDP = enableCDP;
const globalEvalOnDoc = args.includes('--eval-on-doc');

if (args.includes('--version')) {
  console.log(`scanner-script.js version ${VERSION}`);
  process.exit(0);
}

if (args.includes('--help') || args.includes('-h')) {
  console.log(`Usage: node scanner-script.js [options]

Options:
  -o, --output <file>            Output file for rules. If omitted, prints to console
  --verbose                      Force verbose mode globally
  --debug                        Force debug mode globally
  --silent                       Suppress normal console logs
  --titles                       Add ! <url> title before each site's group
  --dumpurls                     Dump matched URLs into matched_urls.log
  --sub-domains                  Output full subdomains instead of collapsing to root
  --localhost                    Output as 127.0.0.1 domain.com
  --localhost-0.0.0.0            Output as 0.0.0.0 domain.com
  --no-interact                  Disable page interactions globally
  --custom-json <file>           Use a custom config JSON file instead of config.json
  --headful                      Launch browser with GUI (not headless)
  --plain                        Output just domains (no adblock formatting)
  --cdp                          Enable Chrome DevTools Protocol logging
  --eval-on-doc                 Globally enable evaluateOnNewDocument()
  --help, -h                     Show this help menu
  --version                      Show script version

Per-site config.json options:
  url: "site" or ["site1", "site2"]          Single URL or list of URLs
  filterRegex: "regex" or ["regex1", "regex2"]  Patterns to match requests
  blocked: ["regex"]                          Regex patterns to block requests
  interact: true/false                         Simulate mouse movements/clicks
  isBrave: true/false                          Spoof Brave browser detection
  userAgent: "chrome"|"firefox"|"safari"        Custom desktop User-Agent
  delay: <milliseconds>                        Delay after load (default: 2000)
  reload: <number>                             Reload page n times after load (default: 1)
  subDomains: 1/0                              Output full subdomains (default: 0)
  localhost: true/false                        Force localhost output (127.0.0.1)
  localhost_0_0_0_0: true/false                Force localhost output (0.0.0.0)
  source: true/false                           Save page source HTML after load
  firstParty: true/false                       Allow first-party matches (default: false)
  thirdParty: true/false                       Allow third-party matches (default: true)
  screenshot: true/false                       Capture screenshot on load failure
  headful: true/false                          Launch browser with GUI for this site
  fingerprint_protection: true/false/"random" Enable fingerprint spoofing: true/false/"random"
  evaluateOnNewDocument: true/false           Inject fetch/XHR interceptor in page
  cdp: true/false                            Enable CDP logging for this site Inject fetch/XHR interceptor in page
`);
  process.exit(0);
}

const configPathIndex = args.findIndex(arg => arg === '--custom-json');
const configPath = (configPathIndex !== -1 && args[configPathIndex + 1]) ? args[configPathIndex + 1] : 'config.json';
let config;
try {
  if (!fs.existsSync(configPath)) {
    console.error(`❌ Config file not found: ${configPath}`);
    process.exit(1);
  }
  if (forceDebug && configPath !== 'config.json') {
    console.log(`[debug] Using custom config file: ${configPath}`);
  }
  const raw = fs.readFileSync(configPath, 'utf8');
  config = JSON.parse(raw);
} catch (e) {
  console.error(`❌ Failed to load config file (${configPath}):`, e.message);
  process.exit(1);
}
const { sites = [], ignoreDomains = [], blocked: globalBlocked = [] } = config;

// Override CDP if enabled per site
if (!enableCDP) {
  globalCDP = sites.some(site => site.cdp === true);
  const cdpSites = sites.filter(site => site.cdp === true).map(site => site.url);
  if (forceDebug && globalCDP) console.log('[debug] CDP enabled via config.json for sites:', cdpSites);
  if (forceDebug && globalCDP) console.log('[debug] CDP enabled via config.json');
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

function getRandomFingerprint() {
  return {
    deviceMemory: Math.random() < 0.5 ? 4 : 8,
    hardwareConcurrency: [2, 4, 8][Math.floor(Math.random() * 3)],
    screen: {
      width: 360 + Math.floor(Math.random() * 400),
      height: 640 + Math.floor(Math.random() * 500),
      colorDepth: 24
    },
    platform: 'Linux x86_64',
    timezone: 'UTC'
  };
}

(async () => {
  const perSiteHeadful = sites.some(site => site.headful === true);
  const launchHeadless = !(headfulMode || perSiteHeadful);
  const browser = await puppeteer.launch({ headless: launchHeadless, protocolTimeout: 300000 });
  if (forceDebug) console.log(`[debug] Launching browser with headless: ${launchHeadless}`);
  if (forceDebug) console.log(`[debug] Launching browser with headless: ${!headfulMode}`);

  if (globalCDP && forceDebug) {
    const [page] = await browser.pages();
    const cdpSession = await page.target().createCDPSession();
    await cdpSession.send('Network.enable');
    cdpSession.on('Network.requestWillBeSent', (params) => {
      console.log(`[cdp] Request: ${params.request.url}`);
    });
  }

  for (const site of sites) {
    const shouldInjectEval = site.evaluateOnNewDocument === true || globalEvalOnDoc;
    if (forceDebug && shouldInjectEval) console.log('[debug] evaluateOnNewDocument enabled for', site.url);
        if (shouldInjectEval) {
      if (forceDebug) console.log(`[debug] evaluateOnNewDocument enabled for ${site.url}`);
      await browser.newPage().then(page => {
        page.evaluateOnNewDocument(() => {
          const originalFetch = window.fetch;
          window.fetch = (...args) => {
            console.log('[evalOnDoc][fetch]', args[0]);
            return originalFetch.apply(this, args);
          };

          const originalXHR = XMLHttpRequest.prototype.open;
          XMLHttpRequest.prototype.open = function (method, url) {
            console.log('[evalOnDoc][xhr]', url);
            return originalXHR.apply(this, arguments);
          };
        });
      });
    }
  }

  const siteRules = [];

  for (const site of sites) {
    const urls = Array.isArray(site.url) ? site.url : [site.url];

    for (const currentUrl of urls) {
      const allowFirstParty = site.firstParty === 1;
      const allowThirdParty = site.thirdParty === undefined || site.thirdParty === 1;
      const perSiteSubDomains = site.subDomains === 1 ? true : subDomainsMode;
      const siteLocalhost = site.localhost === true;
      const siteLocalhostAlt = site.localhost_0_0_0_0 === true;
      const fingerprintSetting = site.fingerprint_protection || false;

      if (site.firstParty === 0 && site.thirdParty === 0) {
        console.warn(`⚠ Skipping ${currentUrl} because both firstParty and thirdParty are disabled.`);
        continue;
      }

      let page;
      const matchedDomains = new Set();
      let pageLoadFailed = false;

      if (!silentMode) console.log(`
Scanning: ${currentUrl}`);

      try {
        page = await browser.newPage();
        await page.setRequestInterception(true);

        if (site.userAgent) {
          if (forceDebug) console.log(`[debug] userAgent spoofing enabled for ${currentUrl}: ${site.userAgent}`);
          const userAgents = {
            chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
            firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
            safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15"
          };
          const ua = userAgents[site.userAgent.toLowerCase()];
          if (ua) await page.setUserAgent(ua);
        }

        if (site.isBrave) {
          if (forceDebug) console.log(`[debug] Brave spoofing enabled for ${currentUrl}`);
          await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'brave', {
              get: () => ({ isBrave: () => Promise.resolve(true) })
            });
          });
        }

        if (fingerprintSetting) {
          if (forceDebug) console.log(`[debug] fingerprint_protection enabled for ${currentUrl}`);
          const spoof = fingerprintSetting === 'random' ? getRandomFingerprint() : {
            deviceMemory: 8,
            hardwareConcurrency: 4,
            screen: { width: 1920, height: 1080, colorDepth: 24 },
            platform: DEFAULT_PLATFORM,
            timezone: DEFAULT_TIMEZONE
          };

          try {
            await page.evaluateOnNewDocument(({ spoof }) => {
              Object.defineProperty(navigator, 'deviceMemory', { get: () => spoof.deviceMemory });
              Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => spoof.hardwareConcurrency });
              Object.defineProperty(window.screen, 'width', { get: () => spoof.screen.width });
              Object.defineProperty(window.screen, 'height', { get: () => spoof.screen.height });
              Object.defineProperty(window.screen, 'colorDepth', { get: () => spoof.screen.colorDepth });
              Object.defineProperty(navigator, 'platform', { get: () => spoof.platform });
              Intl.DateTimeFormat = class extends Intl.DateTimeFormat {
                resolvedOptions() {
                  return { timeZone: spoof.timezone };
                }
              };
            }, { spoof });
          } catch (err) {
            console.warn(`[fingerprint spoof failed] ${currentUrl}: ${err.message}`);
          }
        }
      
        const regexes = Array.isArray(site.filterRegex)
          ? site.filterRegex.map(r => new RegExp(r.replace(/^\/(.*)\/$/, '$1')))
          : site.filterRegex
            ? [new RegExp(site.filterRegex.replace(/^\/(.*)\/$/, '$1'))]
            : [];

        const blockedRegexes = Array.isArray(site.blocked)
          ? site.blocked.map(pattern => new RegExp(pattern))
          : [];

        page.on('request', request => {
          if (forceDebug) console.log('[debug request]', request.url());
          const reqUrl = request.url();

          if (blockedRegexes.some(re => re.test(reqUrl))) {
            request.abort();
            return;
          }

          const reqDomain = perSiteSubDomains ? (new URL(reqUrl)).hostname : getRootDomain(reqUrl);

          if (!reqDomain || ignoreDomains.some(domain => reqDomain.endsWith(domain))) {
            request.continue();
            return;
          }

          if (regexes.some(re => re.test(reqUrl))) {
            matchedDomains.add(reqDomain);
            if (dumpUrls) fs.appendFileSync('matched_urls.log', `${reqUrl}
`);
          }

          request.continue();
        });

        const interactEnabled = site.interact === true;
        await page.goto(currentUrl, { waitUntil: 'load', timeout: site.timeout || 40000 });

        if (interactEnabled && !disableInteract) {
          if (forceDebug) console.log(`[debug] interaction simulation enabled for ${currentUrl}`);
          const randomX = Math.floor(Math.random() * 500) + 50;
          const randomY = Math.floor(Math.random() * 500) + 50;
          await page.mouse.move(randomX, randomY, { steps: 10 });
          await page.mouse.move(randomX + 50, randomY + 50, { steps: 15 });
          await page.mouse.click(randomX + 25, randomY + 25);
          await page.hover('body');
        }

        const delayMs = site.delay || 2000;
        await page.waitForNetworkIdle({ idleTime: 2000, timeout: site.timeout || 30000 });
        await new Promise(resolve => setTimeout(resolve, delayMs));

        for (let i = 1; i < (site.reload || 1); i++) {
          await page.reload({ waitUntil: 'domcontentloaded', timeout: site.timeout || 30000 });
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }

        await page.close();
      } catch (err) {
        console.warn(`⚠ Failed to load: ${currentUrl} (${err.message})`);
        if (site.screenshot === true && page) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
          const safeUrl = currentUrl.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_');
          const filename = `${safeUrl}-${timestamp}.jpg`;
          try {
            await page.screenshot({ path: filename, type: 'jpeg', fullPage: true });
            if (forceDebug) console.log(`[debug] Screenshot saved: ${filename}`);
          } catch (err) {
            console.warn(`[screenshot failed] ${currentUrl}: ${err.message}`);
          }
        }
        pageLoadFailed = true;
      }

      const siteMatchedDomains = [];

      matchedDomains.forEach(domain => {
        if (domain.length > 6 && domain.includes('.')) {
          const sitePlain = site.plain === true || site.plain === undefined ? false : site.plain;
          const usePlain = plainOutput || sitePlain;

          if (localhostMode || siteLocalhost) {
            siteMatchedDomains.push(usePlain ? domain : `127.0.0.1 ${domain}`);
          } else if (localhostModeAlt || siteLocalhostAlt) {
            siteMatchedDomains.push(usePlain ? domain : `0.0.0.0 ${domain}`);
          } else {
            siteMatchedDomains.push(usePlain ? domain : `||${domain}^`);
          }
        }
      });

      siteRules.push({ url: currentUrl, rules: siteMatchedDomains });
    }
  }

  const outputLines = [];
  for (const { url, rules } of siteRules) {
    if (rules.length > 0) {
      if (showTitles) outputLines.push(`! ${url}`);
      outputLines.push(...rules);
    }
  }

if (outputFile) {
  fs.writeFileSync(outputFile, outputLines.join('\n') + '\n');
  if (!silentMode) console.log(`Adblock rules saved to ${outputFile}`);
} else {
  console.log(outputLines.join('\n'));
}


  await browser.close();
  process.exit(0);
})();

