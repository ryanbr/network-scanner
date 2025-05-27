// === Network scanner script v0.9.10 ===

// puppeteer for browser automation, fs for file system operations, psl for domain parsing.
// const pLimit = require('p-limit'); // Will be dynamically imported
const puppeteer = require('puppeteer');
const fs = require('fs');
const psl = require('psl');
// 
const { blockedManager } = require('./lib/blocked'); // Import the adblock module
const { fingerprintManager } = require('./lib/fingerprint'); // Import the fingerprint module
const { cssBlocker } = require('./lib/css-blocker'); // Import the CSS blocker module
const { cloudflareBypass } = require('./lib/cloudflare-bypass'); // Import the Cloudflare bypass module
const { pageInjector } = require('./lib/page-injector'); // Import the page injector module
const { interactionSimulator } = require('./lib/interaction-simulator'); // Import the interaction simulator module
const { cdpManager } = require('./lib/cdp-manager'); // Import the CDP manager module
const { processManager } = require('./lib/process-manager'); // Import the process manager module

// --- Script Configuration & Constants ---
const VERSION = '0.9.10'; // Script version
const MAX_CONCURRENT_SITES = 4;

// get startTime
const startTime = Date.now();

// --- Command-Line Argument Parsing ---
const args = process.argv.slice(2);

if (args.length === 0) {
  args.push('--help');
}

const headfulMode = args.includes('--headful');
const SOURCES_FOLDER = 'sources';

let outputFile = null;
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
const disableInteract = args.includes('--no-interact');
const plainOutput = args.includes('--plain');
const enableCDP = args.includes('--cdp');
const globalEvalOnDoc = args.includes('--eval-on-doc'); // For Fetch/XHR interception

// New argument for external blocked patterns file
let blockedPatternsFile = null;
const blockedFileIndex = args.findIndex(arg => arg === '--blocked-file');
if (blockedFileIndex !== -1 && args[blockedFileIndex + 1]) {
  blockedPatternsFile = args[blockedFileIndex + 1];
}

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
  --blocked-file <file>          Load additional blocked patterns from external file
  --headful                      Launch browser with GUI (not headless)
  --plain                        Output just domains (no adblock formatting)
  --cdp                          Enable Chrome DevTools Protocol logging (now per-page if enabled)
  --eval-on-doc                 Globally enable evaluateOnNewDocument() for Fetch/XHR interception
  --help, -h                     Show this help menu
  --version                      Show script version

Per-site config.json options:
  url: "site" or ["site1", "site2"]          Single URL or list of URLs
  filterRegex: "regex" or ["regex1", "regex2"]  Patterns to match requests
  blocked: ["regex"]                          Regex patterns to block requests
  css_blocked: ["#selector", ".class"]        CSS selectors to hide elements
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
  cloudflare_phish: true/false                 Auto-click through Cloudflare phishing warnings (default: false)
  cloudflare_bypass: true/false               Auto-solve Cloudflare "Verify you are human" challenges (default: false)
  evaluateOnNewDocument: true/false           Inject fetch/XHR interceptor in page (for this site)
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

// --- Initialize Blocked Manager ---
// Load additional blocked patterns from external file if specified
let externalBlockedPatterns = [];
if (blockedPatternsFile) {
  externalBlockedPatterns = blockedManager.constructor.loadFromFile(blockedPatternsFile);
}

// Combine global blocked patterns from config and external file
const allGlobalBlocked = [...globalBlocked, ...externalBlockedPatterns];
blockedManager.initialize(allGlobalBlocked, forceDebug);

// --- Initialize Fingerprint Manager ---
fingerprintManager.initialize(forceDebug);

// --- Initialize CSS Blocker ---
cssBlocker.initialize(forceDebug);

// --- Initialize Cloudflare Bypass ---
cloudflareBypass.initialize(forceDebug);

// --- Initialize Page Injector ---
pageInjector.initialize(forceDebug);

// --- Initialize Interaction Simulator ---
interactionSimulator.initialize(forceDebug);

// --- Initialize CDP Manager ---
cdpManager.initialize(forceDebug);

// --- Initialize Process Manager ---
processManager.initialize(forceDebug);

// If globalCDP is not already enabled by the --cdp flag,
// check if any site in config.json has `cdp: true`. If so, enable globalCDP.
// This allows site-specific config to trigger CDP logging for the entire session.
// Note: Analysis suggests CDP should ideally be managed per-page for comprehensive logging.
// (The code block that utilized this logic for a global CDP variable has been removed
// as CDP is now handled per-page based on 'enableCDP' and 'siteConfig.cdp')

/**
 * Extracts the root domain from a given URL string using the psl library.
 * For example, for 'http://sub.example.com/path', it returns 'example.com'.
 *
 * @param {string} url - The URL string to parse.
 * @returns {string} The root domain, or the original hostname if parsing fails (e.g., for IP addresses or invalid URLs), or an empty string on error.
 */
function getRootDomain(url) {
  try {
    const { hostname } = new URL(url);
    const parsed = psl.parse(hostname);
    return parsed.domain || hostname;
  } catch {
    return '';
  }
}

// --- Main Asynchronous IIFE (Immediately Invoked Function Expression) ---
// This is the main entry point and execution block for the network scanner script.
(async () => {
  // Register main browser cleanup handler
  let browser = null;
  processManager.registerCleanupHandler(async () => {
    if (browser) {
      if (forceDebug) console.log('[debug][process] Closing browser during cleanup');
      try {
        await browser.close();
      } catch (error) {
        console.error(`[error][process] Failed to close browser: ${error.message}`);
      }
    }
  }, 'browser-cleanup');

  try {
    
  const pLimit = (await import('p-limit')).default;
  const limit = pLimit(MAX_CONCURRENT_SITES);

  const perSiteHeadful = sites.some(site => site.headful === true);
  const launchHeadless = !(headfulMode || perSiteHeadful);
  // launch with no safe browsing
  browser = await puppeteer.launch({
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-features=SafeBrowsing',
      '--disable-dev-shm-usage',
      '--disable-sync',
      '--disable-gpu',
      '--mute-audio',
      '--disable-translate',
      '--window-size=1920,1080',
      '--disable-extensions',
      '--no-default-browser-check',
      '--safebrowsing-disable-auto-update'
    ],
    headless: launchHeadless,
    protocolTimeout: 300000
  });
  if (forceDebug) console.log(`[debug] Launching browser with headless: ${launchHeadless}`);

  // Register browser as a managed resource
  processManager.registerResource('main-browser', browser, async (browserInstance) => {
    if (forceDebug) console.log('[debug][process] Cleaning up main browser resource');
    await browserInstance.close();
  });

  let siteCounter = 0;
  const totalUrls = sites.reduce((sum, site) => {
    const urls = Array.isArray(site.url) ? site.url.length : 1;
    return sum + urls;
  }, 0);

  // --- Global CDP (Chrome DevTools Protocol) Session --- [COMMENT RE-ADDED PREVIOUSLY, relevant to old logic]
  // NOTE: This CDP session is attached to the initial browser page (e.g., about:blank).
  // For comprehensive network logging per scanned site, a CDP session should ideally be
  // created for each new page context. This current setup might miss some site-specific requests.
  // (The code block for this initial global CDP session has been removed.
  // CDP is now handled on a per-page basis within processUrl if enabled.)


  // --- Global evaluateOnNewDocument for Fetch/XHR Interception ---
  // REMOVED: The old flawed global loop for evaluateOnNewDocument (Fetch/XHR interception) is removed.
  // This functionality is now correctly implemented within the processUrl function on the actual target page.


  /**
   * Processes a single URL: navigates to it, applies configurations (spoofing, interception),
   * monitors network requests, and extracts domains based on matching filterRegex.
   *
   * @param {string} currentUrl - The URL to scan.
   * @param {object} siteConfig - The configuration object for this specific site/URL from config.json.
   * @param {import('puppeteer').Browser} browserInstance - The shared Puppeteer browser instance.
   * @returns {Promise<object>} A promise that resolves to an object containing scan results.
   */
  async function processUrl(currentUrl, siteConfig, browserInstance) {
    const allowFirstParty = siteConfig.firstParty === 1;
    const allowThirdParty = siteConfig.thirdParty === undefined || siteConfig.thirdParty === 1;
    const perSiteSubDomains = siteConfig.subDomains === 1 ? true : subDomainsMode;
    const siteLocalhost = siteConfig.localhost === true;
    const siteLocalhostAlt = siteConfig.localhost_0_0_0_0 === true;
    const fingerprintSetting = siteConfig.fingerprint_protection || false;
    const cloudflarePhishBypass = siteConfig.cloudflare_phish === true;
    const cloudflareBypass = siteConfig.cloudflare_bypass === true;

    if (siteConfig.firstParty === 0 && siteConfig.thirdParty === 0) {
      console.warn(`⚠ Skipping ${currentUrl} because both firstParty and thirdParty are disabled.`);
      return { url: currentUrl, rules: [], success: false, skipped: true };
    }

    let page = null;
    let cdpSession = null;
    const matchedDomains = new Set();
    const timeout = siteConfig.timeout || 30000;

    if (!silentMode) console.log(`\nScanning: ${currentUrl}`);

    try {
      page = await browserInstance.newPage();
      
      // Register page for cleanup if process is interrupted
      const pageId = `page-${Date.now()}-${Math.random()}`;
      processManager.registerResource(pageId, page, async (pageInstance) => {
        if (!pageInstance.isClosed()) await pageInstance.close();
      });

      // Set consistent timeouts for the page
      page.setDefaultTimeout(timeout);
      page.setDefaultNavigationTimeout(timeout);

      // Apply page script injections using page injector module
      await pageInjector.applyPageInjections(page, siteConfig, globalEvalOnDoc, currentUrl);

      // Apply CSS element blocking using CSS blocker module
      await cssBlocker.applyPreLoadBlocking(page, siteConfig.css_blocked, currentUrl);

      // Apply CDP monitoring using CDP manager module
      const cdpResult = await cdpManager.applyCDPMonitoring(page, enableCDP, siteConfig, currentUrl);
      cdpSession = cdpResult.session; // Keep reference for cleanup

      await page.setRequestInterception(true);

      if (siteConfig.clear_sitedata === true) {
        try {
          let clearDataSession = null;
          try {
            clearDataSession = await page.target().createCDPSession();
            await clearDataSession.send('Network.clearBrowserCookies');
            await clearDataSession.send('Network.clearBrowserCache');
          } finally {
            if (clearDataSession) {
              try { await clearDataSession.detach(); } catch (detachErr) { /* ignore */ }
            }
          }
          await page.evaluate(() => {
            localStorage.clear();
            sessionStorage.clear();
            indexedDB.databases().then(dbs => dbs.forEach(db => indexedDB.deleteDatabase(db.name)));
          });
          if (forceDebug) console.log(`[debug] Cleared site data for ${currentUrl}`);
        } catch (clearErr) {
          console.warn(`[clear_sitedata failed] ${currentUrl}: ${clearErr.message}`);
        }
      }

      // Apply user agent spoofing using fingerprint manager
      await fingerprintManager.applyUserAgent(page, siteConfig.userAgent, currentUrl);

      // Apply Brave spoofing using fingerprint manager
      if (siteConfig.isBrave) {
       await fingerprintManager.applyBraveSpoofing(page, currentUrl);
      }

      // Apply fingerprint protection using fingerprint manager
      if (fingerprintSetting) {
       await fingerprintManager.applyFingerprint(page, fingerprintSetting, currentUrl);
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

      // Compile site-specific blocked patterns using the blocked manager
      const siteBlockedRegexes = blockedManager.compileSitePatterns(siteConfig.blocked);

      // --- page.on('request', ...) Handler: Core Network Request Logic ---
      // This handler is triggered for every network request made by the page.
      // It decides whether to allow, block, or process the request based on:
      // - First-party/third-party status and site configuration.
      // - URL matching against blocklists (`blockedRegexes`).
      // - URL matching against filter patterns (`regexes`) for domain extraction.
      // - Global `ignoreDomains` list.
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

        // Use the blocked manager to check if URL should be blocked
        if (blockedManager.shouldBlock(reqUrl, siteBlockedRegexes)) {
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
      
      // Apply runtime CSS blocking as fallback using CSS blocker module
      await cssBlocker.applyRuntimeBlocking(page, siteConfig.css_blocked, currentUrl);

      try {
        await page.goto(currentUrl, { waitUntil: 'load', timeout: timeout });
        siteCounter++;

       // Handle Cloudflare protection using cloudflare bypass module
       await cloudflareBypass.handleCloudflareProtection(page, cloudflarePhishBypass, cloudflareBypass, currentUrl);
       
       console.log(`[info] Loaded: (${siteCounter}/${totalUrls}) ${currentUrl}`);
       await page.evaluate(() => { console.log('Safe to evaluate on loaded page.'); });
     } catch (err) {
       // Check if we're shutting down
       if (processManager.isShuttingDownNow()) {
         throw new Error('Operation cancelled due to shutdown');
       }
       console.error(`[error] Failed on ${currentUrl}: ${err.message}`);
       throw err;
     }     

      // Perform interaction simulation using interaction simulator module
      await interactionSimulator.performBasicInteraction(page, interactEnabled, disableInteract, currentUrl);

      // Use managed sleep instead of raw setTimeout
      const delayMs = siteConfig.delay || 4000;
      await page.waitForNetworkIdle({ idleTime: 4000, timeout: timeout });
      
      // Check for shutdown during delay
      const sleepCompleted = await processManager.sleep(delayMs);
      if (!sleepCompleted) {
        if (forceDebug) console.log(`[debug] Sleep interrupted by shutdown for ${currentUrl}`);
        // Don't throw error, just continue with cleanup
      }
      
      // Check if we're shutting down before proceeding with reloads
      if (processManager.isShuttingDownNow()) return { url: currentUrl, rules: [], success: false, interrupted: true };
 

      for (let i = 1; i < (siteConfig.reload || 1); i++) {
       if (siteConfig.clear_sitedata === true) {
         try {
           let reloadClearSession = null;
           try {
             reloadClearSession = await page.target().createCDPSession();
             await reloadClearSession.send('Network.clearBrowserCookies');
             await reloadClearSession.send('Network.clearBrowserCache');
           } finally {
             if (reloadClearSession) {
               try { await reloadClearSession.detach(); } catch (detachErr) { /* ignore */ }
             }
           }
           await page.evaluate(() => {
             localStorage.clear();
             sessionStorage.clear();
             indexedDB.databases().then(dbs => dbs.forEach(db => indexedDB.deleteDatabase(db.name)));
           });
           if (forceDebug) console.log(`[debug] Cleared site data before reload #${i + 1} for ${currentUrl}`);
         } catch (reloadClearErr) {
           console.warn(`[clear_sitedata before reload failed] ${currentUrl}: ${reloadClearErr.message}`);
         }
       }
        await page.reload({ waitUntil: 'domcontentloaded', timeout: timeout });
        
        const reloadSleepCompleted = await processManager.sleep(delayMs);
        if (!reloadSleepCompleted) {
          break; // Exit reload loop if shutdown requested
        }
      }

      if (siteConfig.forcereload === true) {
        if (forceDebug) console.log(`[debug] Forcing extra reload (cache disabled) for ${currentUrl}`);
        try {
          await page.setCacheEnabled(false);
          await page.reload({ waitUntil: 'domcontentloaded', timeout: timeout });
          const forceReloadSleepCompleted = await processManager.sleep(delayMs);
          if (!forceReloadSleepCompleted) {
            // Continue with processing even if sleep was interrupted
          }
          await page.setCacheEnabled(true);
        } catch (forceReloadErr) {
          console.warn(`[forcereload failed] ${currentUrl}: ${forceReloadErr.message}`);
        }
      }

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

          if (forceDebug) console.log(`[debug] Screenshot saved: ${filename}`);
        } catch (screenshotErr) {
          console.warn(`[screenshot failed] ${currentUrl}: ${screenshotErr.message}`);
        }
      }
      return { url: currentUrl, rules: [], success: false };
    } finally {
      // Guaranteed resource cleanup - this runs regardless of success or failure

      // Unregister page resource since we're cleaning it up manually
      processManager.unregisterResource(pageId);
      // Clean up CDP session using CDP manager
      await cdpManager.cleanupCDPSession(page, cdpSession);

      if (page && !page.isClosed()) {
        try {
          await page.close();

          // Clean up page injector tracking
          pageInjector.cleanupPage(page);

          if (forceDebug) console.log(`[debug] Page closed for ${currentUrl}`);
        } catch (pageCloseErr) {
          if (forceDebug) console.log(`[debug] Failed to close page for ${currentUrl}: ${pageCloseErr.message}`);
        }
      }
    }
  }

  const allProcessingTasks = [];
  for (const site of sites) {
    const urlsToProcess = Array.isArray(site.url) ? site.url : [site.url];
    for (const currentUrl of urlsToProcess) {
      allProcessingTasks.push(limit(() => processUrl(currentUrl, site, browser)));
    }
  }

  if (!silentMode && allProcessingTasks.length > 0) {
    console.log(`\nProcessing ${allProcessingTasks.length} URLs with concurrency ${MAX_CONCURRENT_SITES}...`);

    // Register a timeout to force shutdown if processing takes too long
    const maxProcessingTime = 300000; // 5 minutes
    processManager.createManagedTimeout(() => {
      console.warn(`[warn][process] Processing timeout exceeded (${maxProcessingTime}ms), initiating shutdown`);
      processManager.initiateShutdown('timeout', 1);
    }, maxProcessingTime, 'processing-timeout');
  }
  const results = await Promise.all(allProcessingTasks);

  const finalSiteRules = [];
  let successfulPageLoads = 0;

  results.forEach(result => {
    if (result) {
        if (result.success) {
            successfulPageLoads++;
        }
        if (result.rules && result.rules.length > 0) {
            finalSiteRules.push({ url: result.url, rules: result.rules });
        }
    }
  });
  
  siteCounter = successfulPageLoads;

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
  
  // Clean browser resource tracking before manual close
  processManager.unregisterResource('main-browser');
  
  if (browser && !browser.isConnected || !browser.isConnected()) {
    try {
      await browser.close();
    } catch (browserCloseError) {
      // Browser might already be closed
      if (forceDebug) console.log(`[debug] Browser close error (may be expected): ${browserCloseError.message}`);
    }
  }

  const endTime = Date.now();
  const durationMs = endTime - startTime;
  const totalSeconds = Math.floor(durationMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (!silentMode) {
    console.log(`\nScan completed. ${siteCounter} of ${totalUrls} URLs processed successfully in ${hours}h ${minutes}m ${seconds}s`);
  }

  // Use process manager for graceful exit
  await processManager.gracefulExit(0, 'Scanner completed successfully');
  
  } catch (mainError) {
    console.error(`[error] Fatal error in main execution: ${mainError.message}`);
    await processManager.gracefulExit(1, 'Scanner failed with error');
  }
})();
