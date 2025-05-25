// === Network scanner script v0.9.0 ===

// puppeteer for browser automation, fs for file system operations, psl for domain parsing.
const puppeteer = require('puppeteer');
const fs = require('fs');
const psl = require('psl');

// --- Script Configuration & Constants ---
const VERSION = '0.9.0'; // Script version

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
  delay: <milliseconds>                        Delay after load (default: 4000)
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
// Determine path to config.json, allowing override with --custom-json flag.
const configPathIndex = args.findIndex(arg => arg === '--custom-json');
const configPath = (configPathIndex !== -1 && args[configPathIndex + 1]) ? args[configPathIndex + 1] : 'config.json';
let config;
try {
  // Check if the configuration file exists.
  if (!fs.existsSync(configPath)) {
    console.error(`❌ Config file not found: ${configPath}`);
    process.exit(1); // Exit if config file is missing.
  }
  // Log if a custom config file is being used (in debug mode).
  if (forceDebug && configPath !== 'config.json') {
    console.log(`[debug] Using custom config file: ${configPath}`);
  }
  // Read and parse the JSON configuration file.
  const raw = fs.readFileSync(configPath, 'utf8');
  config = JSON.parse(raw);
} catch (e) {
  // Handle errors during file loading or JSON parsing.
  console.error(`❌ Failed to load config file (${configPath}):`, e.message);
  process.exit(1);
}
// Destructure essential properties from config, providing defaults if they are missing.
// sites: array of site objects to scan.
// ignoreDomains: array of domain strings to ignore during scanning.
// globalBlocked: array of regex strings for requests to block globally (applied if site doesn't override).
const { sites = [], ignoreDomains = [], blocked: globalBlocked = [] } = config;

// --- Global CDP Override Logic ---
// If globalCDP is not already enabled by the --cdp flag,
// check if any site in config.json has `cdp: true`. If so, enable globalCDP.
// This allows site-specific config to trigger CDP logging for the entire session.
// Note: Analysis suggests CDP should ideally be managed per-page for comprehensive logging.
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
 *   @property {number} deviceMemory - Randomized device memory (4 or 8 GB).
 *   @property {number} hardwareConcurrency - Randomized CPU cores (2, 4, or 8).
 *   @property {object} screen - Randomized screen dimensions and color depth.
 *     @property {number} screen.width - Randomized screen width.
 *     @property {number} screen.height - Randomized screen height.
 *     @property {number} screen.colorDepth - Fixed color depth (24).
 *   @property {string} platform - Fixed platform string ('Linux x86_64').
 *   @property {string} timezone - Fixed timezone ('UTC').
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
// This is where the main script logic resides.
(async () => {
  // --- Puppeteer Browser Launch Configuration ---
  // Check if any site-specific config requests headful, otherwise use global headfulMode.
  const perSiteHeadful = sites.some(site => site.headful === true);
  // Launch headless unless global --headful or any site-specific headful is true.
  const launchHeadless = !(headfulMode || perSiteHeadful);
  const browser = await puppeteer.launch({
    args: ['--no-sandbox', '--disable-setuid-sandbox'], // Common args for CI/Docker environments.
    headless: launchHeadless,
    protocolTimeout: 300000 // Set a higher protocol timeout (5 minutes).
  });
  if (forceDebug) console.log(`[debug] Launching browser with headless: ${launchHeadless}`);
 
  // --- Site Processing Counter Setup ---
  let siteCounter = 0; // Counts successfully loaded sites.
  // Calculate total number of URLs to be processed for progress tracking.
  const totalUrls = sites.reduce((sum, site) => {
    const urls = Array.isArray(site.url) ? site.url.length : 1;
    return sum + urls;
  }, 0);

  // --- Global CDP (Chrome DevTools Protocol) Session ---
  // NOTE: This CDP session is attached to the initial browser page (e.g., about:blank).
  // For comprehensive network logging per scanned site, a CDP session should ideally be
  // created for each new page context. This current setup might miss some site-specific requests.
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
  // This loop attempts to set up fetch/XHR interception for sites that require it.
  // NOTE: As per analysis, this `evaluateOnNewDocument` is applied to a temporary page
  // created here (`browser.newPage().then(...)`) which is NOT the page used for actual site navigation later.
  // This means the interception defined here likely won't apply as intended to the target pages.
  // This should be refactored to apply to the correct page context during site processing.
  for (const site of sites) {
    const shouldInjectEval = site.evaluateOnNewDocument === true || globalEvalOnDoc;
    if (shouldInjectEval) { // Redundant debug log here was removed in previous analysis.
      if (forceDebug) console.log(`[debug] evaluateOnNewDocument pre-injection attempt for ${site.url}`);
      await browser.newPage().then(page => { // Creates a new, temporary page.
        page.evaluateOnNewDocument(() => { // Script to intercept fetch and XHR.
          const originalFetch = window.fetch;
          window.fetch = (...args) => {
            console.log('[evalOnDoc][fetch]', args[0]); // Log fetch requests.
            return originalFetch.apply(this, args);
          };

          const originalXHR = XMLHttpRequest.prototype.open;
          XMLHttpRequest.prototype.open = function (method, url) {
            console.log('[evalOnDoc][xhr]', url); // Log XHR requests.
            return originalXHR.apply(this, arguments);
          };
        });
        // This temporary page is not explicitly closed here or reused.
      });
    }
  }

  const siteRules = []; // Array to store generated rules for all sites.

  // --- Main Site Loop: Iterate through each site configuration from config.json ---
  for (const site of sites) {
    // A single site entry in config can have one or multiple URLs.
    const urls = Array.isArray(site.url) ? site.url : [site.url];
    
    // --- Inner URL Loop: Process each URL for the current site configuration ---
    for (const currentUrl of urls) {
      // --- Per-URL Variable Setup: Configure behavior for the current scan ---
      const allowFirstParty = site.firstParty === 1; // Match first-party requests if true.
      // Match third-party requests if true or undefined (default is true).
      const allowThirdParty = site.thirdParty === undefined || site.thirdParty === 1;
      // Use site-specific subdomain settings, else fallback to global subDomainsMode.
      const perSiteSubDomains = site.subDomains === 1 ? true : subDomainsMode;
      const siteLocalhost = site.localhost === true; // Format output as 127.0.0.1 for this site.
      const siteLocalhostAlt = site.localhost_0_0_0_0 === true; // Format as 0.0.0.0.
      const fingerprintSetting = site.fingerprint_protection || false; // Fingerprint spoofing setting.

      // Skip if both first-party and third-party are disabled for this site.
      if (site.firstParty === 0 && site.thirdParty === 0) {
        console.warn(`⚠ Skipping ${currentUrl} because both firstParty and thirdParty are disabled.`);
        continue;
      }

      let page; // Will hold the Puppeteer page object.
      const matchedDomains = new Set(); // Store unique matched domains for this URL.
      let pageLoadFailed = false; // Flag to track if page loading fails.

      if (!silentMode) console.log(`\nScanning: ${currentUrl}`);

      try {
        // --- Page Setup & Spoofing ---
        page = await browser.newPage(); // Create a new page for the current URL.
        await page.setRequestInterception(true); // Enable request interception.

        // Clear site data before navigating if enabled
        if (site.clear_sitedata === true) {
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

        // Apply User-Agent spoofing if specified in site config.
        if (site.userAgent) {
          if (forceDebug) console.log(`[debug] userAgent spoofing enabled for ${currentUrl}: ${site.userAgent}`);
          const userAgents = { // Predefined User-Agent strings.
            chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
            firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
            safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15"
          };
          const ua = userAgents[site.userAgent.toLowerCase()];
          if (ua) await page.setUserAgent(ua);
        }

        // Apply Brave browser detection spoofing if specified.
        if (site.isBrave) {
          if (forceDebug) console.log(`[debug] Brave spoofing enabled for ${currentUrl}`);
          // Inject script to make navigator.brave appear available.
          await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'brave', {
              get: () => ({ isBrave: () => Promise.resolve(true) })
            });
          });
        }

        // Apply Fingerprint Protection if specified.
        if (fingerprintSetting) {
          if (forceDebug) console.log(`[debug] fingerprint_protection enabled for ${currentUrl}`);
          // Use random fingerprint or predefined defaults.
          const spoof = fingerprintSetting === 'random' ? getRandomFingerprint() : {
            deviceMemory: 8, hardwareConcurrency: 4,
            screen: { width: 1920, height: 1080, colorDepth: 24 },
            platform: DEFAULT_PLATFORM, timezone: DEFAULT_TIMEZONE
          };

          try {
            // Inject script to override various navigator and screen properties.
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
      
        // --- Regex Compilation for Filtering and Blocking ---
        // Compile filterRegex strings from config into RegExp objects.
        // Handles single regex string or an array of regex strings.
        // Removes leading/trailing slashes if present (e.g. "/regex/").
        const regexes = Array.isArray(site.filterRegex)
          ? site.filterRegex.map(r => new RegExp(r.replace(/^\/(.*)\/$/, '$1')))
          : site.filterRegex
            ? [new RegExp(site.filterRegex.replace(/^\/(.*)\/$/, '$1'))]
            : [];

        // verbose logging, pattern matching
        if (site.verbose === 1 && site.filterRegex) {
          const patterns = Array.isArray(site.filterRegex) ? site.filterRegex : [site.filterRegex];
          console.log(`[info] Regex patterns for ${currentUrl}:`);
          patterns.forEach((pattern, idx) => {
            console.log(`  [${idx + 1}] ${pattern}`);
          });
        }

        // Compile blocked request patterns from config into RegExp objects.
        const blockedRegexes = Array.isArray(site.blocked)
          ? site.blocked.map(pattern => new RegExp(pattern))
          : [];

        // --- page.on('request', ...) Handler: Core Network Request Logic ---
        const pageUrl = currentUrl; // Reference to the current page's URL for first-party checks.
        page.on('request', request => {
          const checkedUrl = request.url();
          // Determine if the request is first-party relative to the page's main URL.
          const isFirstParty = new URL(checkedUrl).hostname === new URL(pageUrl).hostname;

          // Skip first-party requests if first-party matching is disabled for the site.
          if (isFirstParty && site.firstParty === false) {
            request.continue();
            return;
          }
          // Skip third-party requests if third-party matching is disabled for the site.
          if (!isFirstParty && site.thirdParty === false) {
            request.continue();
            return;
          }

          if (forceDebug) console.log('[debug request]', request.url());
          const reqUrl = request.url();

          // Abort requests that match any of the `blockedRegexes`.
          if (blockedRegexes.some(re => re.test(reqUrl))) {
            request.abort();
            return;
          }

          // Extract domain: full hostname or root domain based on `perSiteSubDomains`.
          const reqDomain = perSiteSubDomains ? (new URL(reqUrl)).hostname : getRootDomain(reqUrl);

          // Ignore if domain is empty or matches any entry in `ignoreDomains`.
          if (!reqDomain || ignoreDomains.some(domain => reqDomain.endsWith(domain))) {
            request.continue();
            return;
          }

          // show verbose logging if enabled
          for (const re of regexes) {
            if (re.test(reqUrl)) {
              matchedDomains.add(reqDomain);
              if (site.verbose === 1) {
                console.log(`[match] ${reqUrl} matched regex: ${re}`);
              }
              if (dumpUrls) fs.appendFileSync('matched_urls.log', `${reqUrl}\n`);
              break;
            }
          }

          request.continue(); // Allow all other requests to proceed.
        });

        // --- Page Navigation and Interaction ---
        const interactEnabled = site.interact === true;
        try {
          // Navigate to the current URL.
          await page.goto(currentUrl, { waitUntil: 'load', timeout: site.timeout || 40000 });
          siteCounter++; // Increment successful load counter.
          console.log(`[info] Loaded: (${siteCounter}/${totalUrls}) ${currentUrl}`);
          // Simple evaluation to confirm page context is accessible.
          await page.evaluate(() => { console.log('Safe to evaluate on loaded page.'); });
        } catch (err) {
          console.error(`[error] Failed on ${currentUrl}: ${err.message}`);
          // Note: pageLoadFailed will be set in the outer catch if this throws.
        }

        // Simulate user interaction if enabled for the site and not globally disabled.
        if (interactEnabled && !disableInteract) {
          if (forceDebug) console.log(`[debug] interaction simulation enabled for ${currentUrl}`);
          // Perform random mouse movements and a click.
          const randomX = Math.floor(Math.random() * 500) + 50;
          const randomY = Math.floor(Math.random() * 500) + 50;
          await page.mouse.move(randomX, randomY, { steps: 10 });
          await page.mouse.move(randomX + 50, randomY + 50, { steps: 15 });
          await page.mouse.click(randomX + 25, randomY + 25);
          await page.hover('body'); // Hover over body to potentially trigger events.
        }

        // Wait for network to be idle and then an additional fixed delay.
        const delayMs = site.delay || 4000; // Site-specific delay or default 2s.
        await page.waitForNetworkIdle({ idleTime: 4000, timeout: site.timeout || 30000 });
        await new Promise(resolve => setTimeout(resolve, delayMs));

        // Reload the page multiple times if specified in site config.
        for (let i = 1; i < (site.reload || 1); i++) { // Default is 1 (no extra reloads).
         if (site.clear_sitedata === true) { // If true, clear site data
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

          await page.reload({ waitUntil: 'domcontentloaded', timeout: site.timeout || 30000 });
          await new Promise(resolve => setTimeout(resolve, delayMs)); // Wait after each reload.
        }

        // Force an extra reload if specified "Shift reload website"
        if (site.forcereload === true) {
          if (forceDebug) console.log(`[debug] Forcing extra reload (cache disabled) for ${currentUrl}`);
        try {
          await page.setCacheEnabled(false);
          await page.reload({ waitUntil: 'domcontentloaded', timeout: site.timeout || 30000 });
          await new Promise(resolve => setTimeout(resolve, delayMs));
          await page.setCacheEnabled(true);
        } catch (err) {
          console.warn(`[forcereload failed] ${currentUrl}: ${err.message}`);
        }
       }

        await page.close(); // Close the page after processing.
      } catch (err) { // --- Error Handling for Page Load/Processing ---
        console.warn(`⚠ Failed to load or process: ${currentUrl} (${err.message})`);
        // If screenshot on failure is enabled and page object exists.
        if (site.screenshot === true && page) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
          const safeUrl = currentUrl.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_');
          const filename = `${safeUrl}-${timestamp}.jpg`;
          try {
            // Take a full-page screenshot.
            await page.screenshot({ path: filename, type: 'jpeg', fullPage: true });
            if (forceDebug) console.log(`[debug] Screenshot saved: ${filename}`);
          } catch (errSc) {
            console.warn(`[screenshot failed] ${currentUrl}: ${errSc.message}`);
          }
        }
        pageLoadFailed = true; // Mark that this page failed.
        if (page && !page.isClosed()) await page.close(); // Ensure page is closed on error.
      }

      // --- Output Formatting for Matched Domains ---
      const siteMatchedDomains = []; // Store formatted rules for this specific URL.
      matchedDomains.forEach(domain => {
        // Basic validation for domain string.
        if (domain.length > 6 && domain.includes('.')) {
          // Determine if plain output (just domain) or adblock rule format is needed.
          // site.plain defaults to false if undefined. True only if explicitly site.plain: true.
          const sitePlainSetting = site.plain === true;
          // Use plainOutput if global flag is set OR if site-specific plain is true.
          const usePlain = plainOutput || sitePlainSetting;

          // Format based on localhost flags or standard adblock syntax.
          if (localhostMode || siteLocalhost) { // 127.0.0.1 format
            siteMatchedDomains.push(usePlain ? domain : `127.0.0.1 ${domain}`);
          } else if (localhostModeAlt || siteLocalhostAlt) { // 0.0.0.0 format
            siteMatchedDomains.push(usePlain ? domain : `0.0.0.0 ${domain}`);
          } else { // Standard adblocker format (e.g., ||domain.com^)
            siteMatchedDomains.push(usePlain ? domain : `||${domain}^`);
          }
        }
      });

      // Store the rules collected for this URL along with the URL itself.
      siteRules.push({ url: currentUrl, rules: siteMatchedDomains });
    }
  }

  // --- Final Output Aggregation & Writing ---
  const outputLines = []; // Array to hold all lines for the final output.
  // Iterate through rules collected from all scanned URLs.
  for (const { url, rules } of siteRules) {
    if (rules.length > 0) { // Only process if there are rules for this URL.
      // Add a title comment (e.g., "! https://example.com") if showTitles is enabled.
      if (showTitles) outputLines.push(`! ${url}`);
      outputLines.push(...rules); // Add the actual rules.
    }
  }

  // Write the aggregated rules to the specified output file or to the console.
  if (outputFile) {
    fs.writeFileSync(outputFile, outputLines.join('\n') + '\n');
    if (!silentMode) console.log(`Adblock rules saved to ${outputFile}`);
  } else {
    console.log(outputLines.join('\n')); // Print to console if no output file.
  }
  
  await browser.close(); // Close the browser instance.
  // show time taken
  const endTime = Date.now();
  const durationMs = endTime - startTime;
  const totalSeconds = Math.floor(durationMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (!silentMode) {
    console.log(`Scan completed in ${hours}h ${minutes}m ${seconds}s`);
  }
  // Exit
  process.exit(0); // Exit script successfully.
})();
