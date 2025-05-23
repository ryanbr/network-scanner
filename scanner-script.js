// === Network scanner script v0.9.1 ===

// puppeteer for browser automation, fs for file system operations, psl for domain parsing.
const pLimit = require('p-limit'); // ADDED for concurrency control
const puppeteer = require('puppeteer');
const fs = require('fs');
const psl = require('psl');

// --- Script Configuration & Constants ---
const VERSION = '0.9.1'; // Script version
const MAX_CONCURRENT_SITES = 4; // ADDED: Concurrency limit for scanning

// get startTime
const startTime = Date.now();
// Default values for fingerprint spoofing if not set to 'random'
const DEFAULT_PLATFORM = 'Win32';
const DEFAULT_TIMEZONE = 'America/New_York';

// --- Command-Line Argument Parsing ---
// process.argv contains node path, script path, then arguments. slice(2) gets just the arguments.
const args = process.argv.slice(2);

// If no command-line arguments are given, default to showing the help menu.
if (args.length === 0) {
  args.push('--help');
}

// Check for --headful flag to run browser with GUI.
const headfulMode = args.includes('--headful');
const SOURCES_FOLDER = 'sources'; // Declared, but not actively used in the provided script.

// Parse --output or -o argument for specifying the output file.
let outputFile = null;
const outputIndex = args.findIndex(arg => arg === '--output' || arg === '-o');
if (outputIndex !== -1 && args[outputIndex + 1]) {
  outputFile = args[outputIndex + 1]; // Assign the filename provided after the flag.
}

// Boolean flags for various script behaviors.
const forceVerbose = args.includes('--verbose'); // Enables detailed logging.
const forceDebug = args.includes('--debug');     // Enables even more detailed debug logging.
const silentMode = args.includes('--silent');   // Suppresses most console output.
const showTitles = args.includes('--titles');   // Adds URL titles as comments in the output.
const dumpUrls = args.includes('--dumpurls');   // Logs all matched URLs to 'matched_urls.log'.
const subDomainsMode = args.includes('--sub-domains'); // Outputs full subdomains instead of root domains.
const localhostMode = args.includes('--localhost'); // Formats output for /etc/hosts (127.0.0.1).
const localhostModeAlt = args.includes('--localhost-0.0.0.0'); // Formats output for /etc/hosts (0.0.0.0).
const disableInteract = args.includes('--no-interact'); // Disables all simulated page interactions.
const plainOutput = args.includes('--plain');     // Outputs matched domains without adblock syntax.
const enableCDP = args.includes('--cdp');         // Enables Chrome DevTools Protocol logging globally.
let globalCDP = enableCDP; // Initialize globalCDP state; may be overridden by site config.
const globalEvalOnDoc = args.includes('--eval-on-doc'); // Enables evaluateOnNewDocument for all sites.

// Handle --version flag: print version and exit.
if (args.includes('--version')) {
  console.log(`scanner-script.js version ${VERSION}`);
  process.exit(0);
}

// Handle --help or -h flag: print usage instructions and exit.
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
  forcereload: true/false                      Force an additional reload after reloads
  clear_sitedata: true/false                   Clear all cookies, cache, storage before each load (default: false)
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

// --- Configuration File Loading ---
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

// --- Global CDP Override Logic ---
if (!enableCDP) {
  globalCDP = sites.some(site => site.cdp === true);
  if (forceDebug && globalCDP) {
    const cdpSites = sites.filter(site => site.cdp === true).map(site => site.url);
    console.log('[debug] CDP enabled via config.json for sites:', cdpSites.join(', '));
  }
}

/**
 * Extracts the root domain from a given URL string using the psl library.
 * For example, for 'http://sub.example.com/path', it returns 'example.com'.
 *
 * @param {string} url - The URL string to parse.
 * @returns {string} The root domain, or the original hostname if parsing fails (e.g., for IP addresses or invalid URLs), or an empty string on error.
 */
function getRootDomain(url) { // Utility function to get the main domain part of a URL.
  try {
    const { hostname } = new URL(url); // Extract hostname from URL.
    const parsed = psl.parse(hostname); // Use psl library to parse the hostname.
    return parsed.domain || hostname; // Return the parsed domain or the original hostname if psl fails.
  } catch {
    return ''; // Return empty string if URL parsing fails.
  }
}

/**
 * Generates an object with randomized browser fingerprint values.
 * This is used to spoof various navigator and screen properties to make
 * the headless browser instance appear more like a regular user's browser
 * and potentially bypass some fingerprint-based bot detection.
 *
 * @returns {object} An object containing the spoofed fingerprint properties:
 * @property {number} deviceMemory - Randomized device memory (4 or 8 GB).
 * @property {number} hardwareConcurrency - Randomized CPU cores (2, 4, or 8).
 * @property {object} screen - Randomized screen dimensions and color depth.
 * @property {number} screen.width - Randomized screen width.
 * @property {number} screen.height - Randomized screen height.
 * @property {number} screen.colorDepth - Fixed color depth (24).
 * @property {string} platform - Fixed platform string ('Linux x86_64').
 * @property {string} timezone - Fixed timezone ('UTC').
 */
function getRandomFingerprint() { // Utility function to generate randomized fingerprint data.
  return {
    deviceMemory: Math.random() < 0.5 ? 4 : 8, // Randomly pick 4 or 8 GB RAM.
    hardwareConcurrency: [2, 4, 8][Math.floor(Math.random() * 3)], // Randomly pick 2, 4, or 8 cores.
    screen: { // Randomize screen dimensions to mimic common mobile/desktop sizes.
      width: 360 + Math.floor(Math.random() * 400),  // Base width + random addition.
      height: 640 + Math.floor(Math.random() * 500), // Base height + random addition.
      colorDepth: 24 // Standard color depth.
    },
    platform: 'Linux x86_64', // Fixed platform.
    timezone: 'UTC' // Fixed timezone.
  };
}

// --- Main Asynchronous IIFE (Immediately Invoked Function Expression) ---
(async () => {
  const limit = pLimit(MAX_CONCURRENT_SITES); // ADDED: Initialize p-limit for concurrency control

  // --- Puppeteer Browser Launch Configuration ---
  const perSiteHeadful = sites.some(site => site.headful === true);
  const launchHeadless = !(headfulMode || perSiteHeadful);
  const browser = await puppeteer.launch({
    args: ['--no-sandbox', '--disable-setuid-sandbox'], // Common args for CI/Docker environments.
    headless: launchHeadless,
    protocolTimeout: 300000 // Set a higher protocol timeout (5 minutes).
  });
  if (forceDebug) console.log(`[debug] Launching browser with headless: ${launchHeadless}`);
 
  let siteCounter = 0; // This counter is for the [info] Loaded log line.
                       // It will be incremented non-atomically by concurrent tasks.
                       // The final accurate count of successful loads is `successfulPageLoads`.
  const totalUrls = sites.reduce((sum, site) => {
    const urls = Array.isArray(site.url) ? site.url.length : 1;
    return sum + urls;
  }, 0);

  // --- Global CDP (Chrome DevTools Protocol) Session ---
  // NOTE: This CDP session is attached to the initial browser page (e.g., about:blank).
  // This section remains as is, running before concurrent URL processing.
  if (globalCDP && forceDebug) {
    const [page] = await browser.pages(); // Get the initial page.
    const cdpSession = await page.target().createCDPSession();
    await cdpSession.send('Network.enable'); // Enable network request monitoring.
    cdpSession.on('Network.requestWillBeSent', (params) => { // Log requests.
      const { url, method } = params.request;
      const initiator = params.initiator ? params.initiator.type : 'unknown';
      console.log(`[cdp] ${method} ${url} (initiator: ${initiator})`);
    });
  }

  // --- Global evaluateOnNewDocument for Fetch/XHR Interception ---
  // NOTE: As per analysis, this `evaluateOnNewDocument` is applied to a temporary page...
  // This section remains as is, running before concurrent URL processing. Its original flaw persists.
  for (const site of sites) {
    const shouldInjectEval = site.evaluateOnNewDocument === true || globalEvalOnDoc;
    if (shouldInjectEval) {
      if (forceDebug) console.log(`[debug] evaluateOnNewDocument pre-injection attempt for ${site.url}`);
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

  // Function to process a single URL. Encapsulates the original per-URL logic.
  async function processUrl(currentUrl, siteConfig, browserInstance) {
    const allowFirstParty = siteConfig.firstParty === 1;
    const allowThirdParty = siteConfig.thirdParty === undefined || siteConfig.thirdParty === 1;
    const perSiteSubDomains = siteConfig.subDomains === 1 ? true : subDomainsMode;
    const siteLocalhost = siteConfig.localhost === true;
    const siteLocalhostAlt = siteConfig.localhost_0_0_0_0 === true;
    const fingerprintSetting = siteConfig.fingerprint_protection || false;

    if (siteConfig.firstParty === 0 && siteConfig.thirdParty === 0) {
      console.warn(`⚠ Skipping ${currentUrl} because both firstParty and thirdParty are disabled.`);
      return { url: currentUrl, rules: [], success: false, skipped: true };
    }

    let page;
    const matchedDomains = new Set();

    if (!silentMode) console.log(`\nScanning: ${currentUrl}`);

    try {
      page = await browserInstance.newPage();
      await page.setRequestInterception(true);

      if (siteConfig.clear_sitedata === true) {
        try {
          const client = await page.target().createCDPSession();
          await client.send('Network.clearBrowserCookies');
          await client.send('Network.clearBrowserCache');
          await page.evaluate(() => {
            localStorage.clear();
            sessionStorage.clear();
            indexedDB.databases().then(dbs => dbs.forEach(db => indexedDB.deleteDatabase(db.name)));
          });
          if (forceDebug) console.log(`[debug] Cleared site data for ${currentUrl}`);
        } catch (err) {
          console.warn(`[clear_sitedata failed] ${currentUrl}: ${err.message}`);
        }
      }

      if (siteConfig.userAgent) {
        if (forceDebug) console.log(`[debug] userAgent spoofing enabled for ${currentUrl}: ${siteConfig.userAgent}`);
        const userAgents = {
          chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
          firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
          safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15"
        };
        const ua = userAgents[siteConfig.userAgent.toLowerCase()];
        if (ua) await page.setUserAgent(ua);
      }

      if (siteConfig.isBrave) {
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
          deviceMemory: 8, hardwareConcurrency: 4,
          screen: { width: 1920, height: 1080, colorDepth: 24 },
          platform: DEFAULT_PLATFORM, timezone: DEFAULT_TIMEZONE
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
              resolvedOptions() { return { timeZone: spoof.timezone }; }
            };
          }, { spoof });
        } catch (err) {
          console.warn(`[fingerprint spoof failed] ${currentUrl}: ${err.message}`);
        }
      }
    
      const regexes = Array.isArray(siteConfig.filterRegex)
        ? siteConfig.filterRegex.map(r => new RegExp(r.replace(/^\/(.*)\/$/, '$1')))
        : siteConfig.filterRegex
          ? [new RegExp(siteConfig.filterRegex.replace(/^\/(.*)\/$/, '$1'))]
          : [];

      if (siteConfig.verbose === 1 && siteConfig.filterRegex) {
        const patterns = Array.isArray(siteConfig.filterRegex) ? siteConfig.filterRegex : [siteConfig.filterRegex];
        console.log(`[info] Regex patterns for ${currentUrl}:`);
        patterns.forEach((pattern, idx) => {
          console.log(`  [${idx + 1}] ${pattern}`);
        });
      }

      const blockedRegexes = Array.isArray(siteConfig.blocked)
        ? siteConfig.blocked.map(pattern => new RegExp(pattern))
        : [];

      page.on('request', request => {
        const checkedUrl = request.url();
        const isFirstParty = new URL(checkedUrl).hostname === new URL(currentUrl).hostname;

        if (isFirstParty && siteConfig.firstParty === false) {
          request.continue();
          return;
        }
        if (!isFirstParty && siteConfig.thirdParty === false) {
          request.continue();
          return;
        }

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

        for (const re of regexes) {
          if (re.test(reqUrl)) {
            matchedDomains.add(reqDomain);
            if (siteConfig.verbose === 1) {
              console.log(`[match] ${reqUrl} matched regex: ${re}`);
            }
            if (dumpUrls) fs.appendFileSync('matched_urls.log', `${reqUrl}\n`);
            break;
          }
        }
        request.continue();
      });

      const interactEnabled = siteConfig.interact === true;
      try {
        await page.goto(currentUrl, { waitUntil: 'load', timeout: siteConfig.timeout || 40000 });
        siteCounter++; // Non-atomic increment for the log line's progress indication.
        console.log(`[info] Loaded: (${siteCounter}/${totalUrls}) ${currentUrl}`);
        await page.evaluate(() => { console.log('Safe to evaluate on loaded page.'); });
      } catch (err) {
        console.error(`[error] Failed on ${currentUrl}: ${err.message}`);
        throw err; // Re-throw to be caught by processUrl's main try-catch
      }

      if (interactEnabled && !disableInteract) {
        if (forceDebug) console.log(`[debug] interaction simulation enabled for ${currentUrl}`);
        const randomX = Math.floor(Math.random() * 500) + 50;
        const randomY = Math.floor(Math.random() * 500) + 50;
        await page.mouse.move(randomX, randomY, { steps: 10 });
        await page.mouse.move(randomX + 50, randomY + 50, { steps: 15 });
        await page.mouse.click(randomX + 25, randomY + 25);
        await page.hover('body');
      }

      const delayMs = siteConfig.delay || 2000;
      await page.waitForNetworkIdle({ idleTime: 2000, timeout: siteConfig.timeout || 30000 });
      await new Promise(resolve => setTimeout(resolve, delayMs));

      for (let i = 1; i < (siteConfig.reload || 1); i++) {
       if (siteConfig.clear_sitedata === true) {
         try {
           const client = await page.target().createCDPSession();
           await client.send('Network.clearBrowserCookies');
           await client.send('Network.clearBrowserCache');
           await page.evaluate(() => {
             localStorage.clear();
             sessionStorage.clear();
             indexedDB.databases().then(dbs => dbs.forEach(db => indexedDB.deleteDatabase(db.name)));
           });
           if (forceDebug) console.log(`[debug] Cleared site data before reload #${i + 1} for ${currentUrl}`);
         } catch (err) {
           console.warn(`[clear_sitedata before reload failed] ${currentUrl}: ${err.message}`);
         }
       }
        await page.reload({ waitUntil: 'domcontentloaded', timeout: siteConfig.timeout || 30000 });
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }

      if (siteConfig.forcereload === true) {
        if (forceDebug) console.log(`[debug] Forcing extra reload (cache disabled) for ${currentUrl}`);
        try {
          await page.setCacheEnabled(false);
          await page.reload({ waitUntil: 'domcontentloaded', timeout: siteConfig.timeout || 30000 });
          await new Promise(resolve => setTimeout(resolve, delayMs));
          await page.setCacheEnabled(true);
        } catch (err) {
          console.warn(`[forcereload failed] ${currentUrl}: ${err.message}`);
        }
      }

      await page.close();

      const formattedRules = [];
      matchedDomains.forEach(domain => {
        if (domain.length > 6 && domain.includes('.')) {
          const sitePlainSetting = siteConfig.plain === true;
          const usePlain = plainOutput || sitePlainSetting;
          if (localhostMode || siteLocalhost) {
            formattedRules.push(usePlain ? domain : `127.0.0.1 ${domain}`);
          } else if (localhostModeAlt || siteLocalhostAlt) {
            formattedRules.push(usePlain ? domain : `0.0.0.0 ${domain}`);
          } else {
            formattedRules.push(usePlain ? domain : `||${domain}^`);
          }
        }
      });
      return { url: currentUrl, rules: formattedRules, success: true };

    } catch (err) {
      console.warn(`⚠ Failed to load or process: ${currentUrl} (${err.message})`);
      if (siteConfig.screenshot === true && page) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const safeUrl = currentUrl.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_');
        const filename = `${safeUrl}-${timestamp}.jpg`;
        try {
          await page.screenshot({ path: filename, type: 'jpeg', fullPage: true });
          if (forceDebug) console.lge.isClosed()) await page.close();
      return { url: currentUrl, rules: [], success: false };
    }
  } // --- End of processUrl function ---

  // --- Main Task Scheduling Loop ---
  const allProcessingTasks = [];
  for (const site of sites) {
    const urlsToProcess = Array.isArray(site.url) ? site.url : [site.url];
    for (const currentUrl of urlsToProcess) {
      allProcessingTasks.push(limit(() => processUrl(currentUrl, site, browser)));
    }
  }

  // --- Wait for all tasks to complete and gather results ---
  if (!silentMode && allProcessingTasks.length > 0) {
    console.log(`\nProcessing ${allProcessingTasks.length} URLs with concurrency ${MAX_CONCURRENT_SITES}...`);
  }
  const results = await Promise.all(allProcessingTasks);

  // --- Aggregate results ---
  const finalSiteRules = [];
  let successfulPageLoads = 0;

  results.forEach(result => {
    // Ensure result is valid before accessing its properties
    if (result) {
        if (result.success) {
            successfulPageLoads++;
        }
        if (result.rules && result.rules.length > 0) {
            finalSiteRules.push({ url: result.url, rules: result.rules });
        }
        // Skipped sites are already logged within processUrl, no further action here.
    }
  });
  
  // Update siteCounter to the accurate count for the final summary log.
  // The siteCounter used in processUrl's [info] Loaded log is for immediate, non-atomic feedback.
  siteCounter = successfulPageLoads;


  // --- Final Output Aggregation & Writing ---
  const outputLines = [];
  for (const { url, rules } of finalSiteRules) {
    if (rules.length > 0) {
      if (showTitles) outputLines.push(`! ${url}`);
      outputLines.push(...rules);
    }
  }

  if (outputFile) {
    fs.writeFileSync(outputFile, outputLines.join('\n') + '\n');
    if (!silentMode) console.log(`\nAdblock rules saved to ${outputFile}`);
  } else {
    if (outputLines.length > 0) console.log("\n--- Generated Rules ---");
    console.log(outputLines.join('\n'));
  }
  
  await browser.close();
  const endTime = Date.now();
  const durationMs = endTime - startTime;
  const totalSeconds = Math.floor(durationMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (!silentMode) {
    // Use the accurate siteCounter (successfulPageLoads) for the summary.
    console.log(`\nScan completed. ${siteCounter} of ${totalUrls} URLs processed successfully in ${hours}h ${minutes}m ${seconds}s`);
  }
  process.exit(0);
})();
