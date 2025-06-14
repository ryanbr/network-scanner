// === Network scanner script (nwss.js) v1.0.17 ===

// puppeteer for browser automation, fs for file system operations, psl for domain parsing.
// const pLimit = require('p-limit'); // Will be dynamically imported
const puppeteer = require('puppeteer');
const fs = require('fs');
const psl = require('psl');
const path = require('path');
const { createGrepHandler, validateGrepAvailability } = require('./lib/grep');
const { compressMultipleFiles, formatFileSize } = require('./lib/compress');
const { parseSearchStrings, createResponseHandler, createCurlHandler } = require('./lib/searchstring');
const { applyAllFingerprintSpoofing } = require('./lib/fingerprint');
const { formatRules, handleOutput, getFormatDescription } = require('./lib/output');
const { handleCloudflareProtection } = require('./lib/cloudflare');
const { handleBrowserExit } = require('./lib/browserexit');
const { createNetToolsHandler, validateWhoisAvailability, validateDigAvailability } = require('./lib/nettools');
const { loadComparisonRules, filterUniqueRules } = require('./lib/compare');
const { colorize, colors, messageColors, tags, formatLogMessage } = require('./lib/colorize');

// --- Script Configuration & Constants ---
const VERSION = '1.0.17'; // Script version
const MAX_CONCURRENT_SITES = 3;
const RESOURCE_CLEANUP_INTERVAL = 40; // Close browser and restart every N sites to free resources

// Add retry configuration
const RETRY_CONFIG = {
  maxRetries: 3,
  retryDelay: 3000, // 3 seconds base delay
  backoffMultiplier: 1.5,
  retryableErrors: [
    'Protocol error: Connection closed',
    'net::ERR_CONNECTION_RESET',
    'net::ERR_CONNECTION_REFUSED',
    'net::ERR_TIMED_OUT',
    'Navigation timeout',
    'Target closed'
  ]
};

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

let compareFile = null;
const compareIndex = args.findIndex(arg => arg === '--compare');
if (compareIndex !== -1 && args[compareIndex + 1]) {
  compareFile = args[compareIndex + 1];
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
const dnsmasqMode = args.includes('--dnsmasq');
const dnsmasqOldMode = args.includes('--dnsmasq-old');
const unboundMode = args.includes('--unbound');
const removeDupes = args.includes('--remove-dupes') || args.includes('--remove-dubes');
const privoxyMode = args.includes('--privoxy');
const piholeMode = args.includes('--pihole');
const globalEvalOnDoc = args.includes('--eval-on-doc'); // For Fetch/XHR interception
const compressLogs = args.includes('--compress-logs');

const enableColors = args.includes('--color') || args.includes('--colour');
let adblockRulesMode = args.includes('--adblock-rules');

// Validate --adblock-rules usage - ignore if used incorrectly instead of erroring
if (adblockRulesMode) {
  if (!outputFile) {
    if (forceDebug) console.log(formatLogMessage('debug', `--adblock-rules ignored: requires --output (-o) to specify an output file`));
    adblockRulesMode = false;
  } else if (localhostMode || localhostModeAlt || plainOutput || dnsmasqMode || dnsmasqOldMode || unboundMode || privoxyMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--adblock-rules ignored: incompatible with localhost/plain output modes`));
    adblockRulesMode = false;
  }
}

// Validate --dnsmasq usage
if (dnsmasqMode) {
  if (localhostMode || localhostModeAlt || plainOutput || adblockRulesMode || dnsmasqOldMode || unboundMode || privoxyMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--dnsmasq-old ignored: incompatible with localhost/plain/adblock-rules/dnsmasq output modes`));
    dnsmasqMode = false;
  }
}

// Validate --dnsmasq-old usage
if (dnsmasqOldMode) {
  if (localhostMode || localhostModeAlt || plainOutput || adblockRulesMode || dnsmasqMode || unboundMode || privoxyMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--dnsmasq-old ignored: incompatible with localhost/plain/adblock-rules/dnsmasq output modes`));
    dnsmasqOldMode = false;
  }
}

// Validate --unbound usage
if (unboundMode) {
  if (localhostMode || localhostModeAlt || plainOutput || adblockRulesMode || dnsmasqMode || dnsmasqOldMode || privoxyMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--unbound ignored: incompatible with localhost/plain/adblock-rules/dnsmasq output modes`));
    unboundMode = false;
  }
}

// Validate --privoxy usage
if (privoxyMode) {
  if (localhostMode || localhostModeAlt || plainOutput || adblockRulesMode || dnsmasqMode || dnsmasqOldMode || unboundMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--privoxy ignored: incompatible with localhost/plain/adblock-rules/dnsmasq/unbound output modes`));
    privoxyMode = false;
  }
}

// Validate --pihole usage
if (piholeMode) {
  if (localhostMode || localhostModeAlt || plainOutput || adblockRulesMode || dnsmasqMode || dnsmasqOldMode || unboundMode || privoxyMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--pihole ignored: incompatible with localhost/plain/adblock-rules/dnsmasq/unbound/privoxy output modes`));
    piholeMode = false;
  }
}

// Validate --compress-logs usage
if (compressLogs && !dumpUrls) {
  console.error(`❌ --compress-logs can only be used with --dumpurls`);
  process.exit(1);
}

// Validate --compare usage
if (compareFile && !outputFile) {
  console.error(`❌ --compare requires --output (-o) to specify an output file`);
  process.exit(1);
}

if (compareFile && !fs.existsSync(compareFile)) {
  console.error(`❌ Compare file not found: ${compareFile}`);
  process.exit(1);
}

if (args.includes('--version')) {
  console.log(`nwss.js version ${VERSION}`);
  process.exit(0);
}

if (args.includes('--help') || args.includes('-h')) {
  console.log(`Usage: node nwss.js [options]

Options:
  --color, --colour              Enable colored console output for status messages
  -o, --output <file>            Output file for rules. If omitted, prints to console
  --compare <file>               Remove rules that already exist in this file before output
    
Output Format Options:
  --localhost                    Output as 127.0.0.1 domain.com
  --localhost-0.0.0.0            Output as 0.0.0.0 domain.com
  --plain                        Output just domains (no adblock formatting)
  --dnsmasq                      Output as local=/domain.com/ (dnsmasq format)
  --dnsmasq-old                  Output as server=/domain.com/ (dnsmasq old format)
  --unbound                      Output as local-zone: "domain.com." always_null (unbound format)
  --privoxy                      Output as { +block } .domain.com (Privoxy format)
  --pihole                       Output as (^|\\.)domain\\.com$ (Pi-hole regex format)
  --adblock-rules                Generate adblock filter rules with resource type modifiers (requires -o)

General Options:
  --verbose                      Force verbose mode globally
  --debug                        Force debug mode globally
  --silent                       Suppress normal console logs
  --titles                       Add ! <url> title before each site's group
  --dumpurls                     Dump matched URLs into matched_urls.log
  --compress-logs                Compress log files with gzip (requires --dumpurls)
  --sub-domains                  Output full subdomains instead of collapsing to root
  --no-interact                  Disable page interactions globally
  --custom-json <file>           Use a custom config JSON file instead of config.json
  --headful                      Launch browser with GUI (not headless)
  --cdp                          Enable Chrome DevTools Protocol logging (now per-page if enabled)
  --remove-dupes                 Remove duplicate domains from output (only with -o)
  --eval-on-doc                 Globally enable evaluateOnNewDocument() for Fetch/XHR interception
  --help, -h                     Show this help menu
  --version                      Show script version
  
Global config.json options:
  ignoreDomains: ["domain.com", "*.ads.com"]     Domains to completely ignore (supports wildcards)
  blocked: ["regex1", "regex2"]                   Global regex patterns to block requests (combined with per-site blocked)
  whois_server_mode: "random" or "cycle"      Default server selection mode for all sites (default: random)


Per-site config.json options:
  url: "site" or ["site1", "site2"]          Single URL or list of URLs
  filterRegex: "regex" or ["regex1", "regex2"]  Patterns to match requests
  comments: "text" or ["text1", "text2"]       Documentation/notes - ignored by script
  searchstring: "text" or ["text1", "text2"]   Text to search in response content (requires filterRegex match)
  searchstring_and: "text" or ["text1", "text2"] Text to search with AND logic - ALL terms must be present (requires filterRegex match)
  curl: true/false                             Use curl to download content for analysis (default: false)
                                               Note: curl respects filterRegex but ignores resourceTypes filtering
  grep: true/false                             Use grep instead of JavaScript for pattern matching (default: false)
                                               Note: requires curl=true, uses system grep command for faster searches
  blocked: ["regex"]                          Regex patterns to block requests
  css_blocked: ["#selector", ".class"]        CSS selectors to hide elements
  resourceTypes: ["script", "stylesheet"]     Only process requests of these resource types (default: all types)
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
  dnsmasq: true/false                          Force dnsmasq output (local=/domain.com/)
  dnsmasq_old: true/false                      Force dnsmasq old output (server=/domain.com/)
  unbound: true/false                          Force unbound output (local-zone: "domain.com." always_null)
  privoxy: true/false                          Force Privoxy output ({ +block } .domain.com)
  pihole: true/false                           Force Pi-hole regex output ((^|\\.)domain\\.com$)
  source: true/false                           Save page source HTML after load
  firstParty: true/false                       Allow first-party matches (default: false)
  thirdParty: true/false                       Allow third-party matches (default: true)
  screenshot: true/false                       Capture screenshot on load failure
  headful: true/false                          Launch browser with GUI for this site
  fingerprint_protection: true/false/"random" Enable fingerprint spoofing: true/false/"random"
  adblock_rules: true/false                    Generate adblock filter rules with resource types for this site
  cloudflare_phish: true/false                 Auto-click through Cloudflare phishing warnings (default: false)
  cloudflare_bypass: true/false               Auto-solve Cloudflare "Verify you are human" challenges (default: false)
  evaluateOnNewDocument: true/false           Inject fetch/XHR interceptor in page (for this site)
  cdp: true/false                            Enable CDP logging for this site Inject fetch/XHR interceptor in page
  whois: ["term1", "term2"]                   Check whois data for ALL specified terms (AND logic)
  whois-or: ["term1", "term2"]                Check whois data for ANY specified term (OR logic)
  whois_server_mode: "random" or "cycle"      Server selection mode: random (default) or cycle through list
  whois_server: "whois.domain.com" or ["server1", "server2"]  Custom whois server(s) - single server or randomized list (default: system default)
  whois_max_retries: 2                       Maximum retry attempts per domain (default: 2)
  whois_timeout_multiplier: 1.5              Timeout increase multiplier per retry (default: 1.5)
  whois_use_fallback: true                   Add TLD-specific fallback servers (default: true)
  whois_retry_on_timeout: true               Retry on timeout errors (default: true)
  whois_retry_on_error: false                Retry on connection/other errors (default: false)
  dig: ["term1", "term2"]                     Check dig output for ALL specified terms (AND logic)
  dig-or: ["term1", "term2"]                  Check dig output for ANY specified term (OR logic)
  goto_options: {"waitUntil": "domcontentloaded"} Custom page.goto() options (default: {"waitUntil": "load"})
  dig_subdomain: true/false                    Use subdomain for dig lookup instead of root domain (default: false)
  digRecordType: "A"                          DNS record type for dig (default: A)
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
    console.log(formatLogMessage('debug', `Using custom config file: ${configPath}`));
  }
  const raw = fs.readFileSync(configPath, 'utf8');
  config = JSON.parse(raw);
} catch (e) {
  console.error(`❌ Failed to load config file (${configPath}):`, e.message);
  process.exit(1);
}
// Extract config values while ignoring 'comments' field at global and site levels
const { sites = [], ignoreDomains = [], blocked: globalBlocked = [], whois_delay = 2000, whois_server_mode = 'random', comments: globalComments, ...otherGlobalConfig } = config;


// Add global cycling index tracker for whois server selection
let globalWhoisServerIndex = 0;

// --- Log File Setup ---
let debugLogFile = null;
let matchedUrlsLogFile = null;
let adblockRulesLogFile = null;
if (forceDebug || dumpUrls) {
  // Create logs folder if it doesn't exist
  const logsFolder = 'logs';
  if (!fs.existsSync(logsFolder)) {
    fs.mkdirSync(logsFolder, { recursive: true });
    console.log(formatLogMessage('debug', `Created logs folder: ${logsFolder}`));
  }

  // Generate timestamped log filenames
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, -5);
 
if (forceDebug) {
  debugLogFile = path.join(logsFolder, `debug_requests_${timestamp}.log`);
  console.log(formatLogMessage('debug', `Debug requests will be logged to: ${debugLogFile}`));
}

if (dumpUrls) {
    matchedUrlsLogFile = path.join(logsFolder, `matched_urls_${timestamp}.log`);
    console.log(messageColors.processing('Matched URLs will be logged to:') + ` ${matchedUrlsLogFile}`);

    // Also create adblock rules log file with same timestamp
    adblockRulesLogFile = path.join(logsFolder, `adblock_rules_${timestamp}.txt`);
    console.log(messageColors.processing('Adblock rules will be saved to:') + ` ${adblockRulesLogFile}`); 
  }
}

// Log comments if debug mode is enabled and comments exist
if (forceDebug && globalComments) {
  const commentList = Array.isArray(globalComments) ? globalComments : [globalComments];
  console.log(formatLogMessage('debug', `Global comments found: ${commentList.length} item(s)`));
  commentList.forEach((comment, idx) => console.log(formatLogMessage('debug', `  Comment ${idx + 1}: ${comment}`)));
}
// --- Global CDP Override Logic --- [COMMENT RE-ADDED PREVIOUSLY, relevant to old logic]
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

/**
 * Safely extracts hostname from a URL, handling malformed URLs gracefully
 * @param {string} url - The URL string to parse
 * @param {boolean} getFullHostname - If true, returns full hostname; if false, returns root domain
 * @returns {string} The hostname/domain, or empty string if URL is invalid
*/
function safeGetDomain(url, getFullHostname = false) {
  try {
    const parsedUrl = new URL(url);
    if (getFullHostname) {
      return parsedUrl.hostname;
    } else {
      return getRootDomain(url);
    }
  } catch (urlError) {
    // Log malformed URLs for debugging
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Malformed URL skipped: ${url} (${urlError.message})`));
    }
    return '';
  }
}

// ability to use widcards in ignoreDomains
function matchesIgnoreDomain(domain, ignorePatterns) {
  return ignorePatterns.some(pattern => {
    if (pattern.includes('*')) {
      // Convert wildcard pattern to regex
      const regexPattern = pattern
        .replace(/\./g, '\\.')  // Escape dots
        .replace(/\*/g, '.*');  // Convert * to .*
      return new RegExp(`^${regexPattern}$`).test(domain);
    }
    return domain.endsWith(pattern);
  });
}

function setupFrameHandling(page, forceDebug) {
  // Handle frame creation with error suppression
  page.on('frameattached', async (frame) => {
    if (frame.parentFrame()) { // Only handle child frames, not main frame
      try {
        const frameUrl = frame.url();
        
        if (forceDebug) {
          console.log(formatLogMessage('debug', `New frame attached: ${frameUrl || 'about:blank'}`));
        }
        
        // Don't try to navigate to frames with invalid/empty URLs
        if (!frameUrl ||
            frameUrl === 'about:blank' ||
            frameUrl === '' ||
            frameUrl === 'about:srcdoc' ||
            frameUrl.startsWith('about:') ||
            frameUrl.startsWith('data:') ||
            frameUrl.startsWith('blob:') ||
            frameUrl.startsWith('chrome-error://') ||
            frameUrl.startsWith('chrome-extension://')) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Skipping frame with invalid/special URL: ${frameUrl}`));
          }
          return;
        }
        
        // Validate URL format before attempting navigation
        try {
          const parsedUrl = new URL(frameUrl);
          // Only process http/https URLs
          if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Skipping frame with non-http protocol: ${frameUrl}`));
            }
            return;
          }
        } catch (urlErr) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Skipping frame with malformed URL: ${frameUrl}`));
          }
          return;
        }
        // REMOVED: Don't try to manually navigate frames
        // Let frames load naturally - manual navigation often causes Protocol errors
        // await frame.goto(frame.url(), { waitUntil: 'domcontentloaded', timeout: 5000 });
        
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Frame will load naturally: ${frameUrl}`));
        }
       
      } catch (err) {
        // Suppress "Cannot navigate to invalid URL" errors but log others
        if (!err.message.includes('Cannot navigate to invalid URL') && 
            !err.message.includes('Protocol error')) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Frame handling error: ${err.message}`));
          }
        }
      }
    }
  });
  // Handle frame navigations (keep this for monitoring)
  page.on('framenavigated', (frame) => {
    const frameUrl = frame.url();
    if (forceDebug &&
        frameUrl &&
        frameUrl !== 'about:blank' &&
        frameUrl !== 'about:srcdoc' &&
        !frameUrl.startsWith('about:') &&
        !frameUrl.startsWith('data:') &&
        !frameUrl.startsWith('chrome-error://') &&
        !frameUrl.startsWith('chrome-extension://')) {
      console.log(formatLogMessage('debug', `Frame navigated to: ${frameUrl}`));
    }
  });

  // Optional: Handle frame detachment for cleanup
  page.on('framedetached', (frame) => {
    if (forceDebug) {
      const frameUrl = frame.url();
      if (frameUrl &&
          frameUrl !== 'about:blank' &&
          frameUrl !== 'about:srcdoc' &&
          !frameUrl.startsWith('about:') &&
          !frameUrl.startsWith('chrome-error://') &&
          !frameUrl.startsWith('chrome-extension://')) {
        console.log(formatLogMessage('debug', `Frame detached: ${frameUrl}`));
      }
    }
  });
}

// Add utility functions for retry logic
function isRetryableError(error) {
  const errorMessage = error.message || error.toString();
  return RETRY_CONFIG.retryableErrors.some(retryableError => 
    errorMessage.includes(retryableError)
  );
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// --- Main Asynchronous IIFE (Immediately Invoked Function Expression) ---
// This is the main entry point and execution block for the network scanner script.
(async () => {
  /**
   * Creates a new browser instance with consistent configuration
   * Uses system Chrome and temporary directories to minimize disk usage
   * @returns {Promise<import('puppeteer').Browser>} Browser instance
   */
  async function createBrowser() {
    // Create temporary user data directory that we can fully control and clean up
    const tempUserDataDir = `/tmp/puppeteer-${Date.now()}-${Math.random().toString(36).substring(7)}`;

    // Try to find system Chrome installation to avoid Puppeteer downloads
    const systemChromePaths = [
      '/usr/bin/google-chrome-stable',
      '/usr/bin/google-chrome',
      '/usr/bin/chromium-browser',
      '/usr/bin/chromium',
      '/snap/bin/chromium'
    ];

    let executablePath = null;
    for (const chromePath of systemChromePaths) {
      if (fs.existsSync(chromePath)) {
        executablePath = chromePath;
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Using system Chrome: ${chromePath}`));
        }
        break;
      }
    }
    return await puppeteer.launch({
      // Use system Chrome if available to avoid downloads
      executablePath: executablePath,
      // Force temporary user data directory for complete cleanup control
      userDataDir: tempUserDataDir,
      args: [
        // Disk space controls - 50MB cache limits
        '--disk-cache-size=52428800', // 50MB disk cache (50 * 1024 * 1024)
        '--media-cache-size=52428800', // 50MB media cache  
        '--disable-application-cache',
        '--disable-offline-load-stale-cache',
        '--disable-background-downloads',
        '--no-first-run',
        '--disable-default-apps',
        '--disable-component-extensions-with-background-pages',
        '--disable-background-networking',
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
        '--safebrowsing-disable-auto-update',
        '--disable-web-security',
        '--disable-features=VizDisplayCompositor',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-ipc-flooding-protection',
        '--max_old_space_size=1024'
      ],
      headless: launchHeadless,
      protocolTimeout: 300000,
      handleSIGINT: false,
      handleSIGTERM: false,
      handleSIGHUP: false
    });
  }

  /**
   * Cleanup Chrome temporary files and directories
   */
  async function cleanupChromeFiles() {
    try {
      const { execSync } = require('child_process');

      // Clean Chrome cache directories with shell commands for wildcards
      const cleanupCommands = [
        'rm -rf /tmp/.org.chromium.Chromium.* 2>/dev/null || true',
        'rm -rf /tmp/puppeteer-* 2>/dev/null || true',
        'rm -rf /dev/shm/.org.chromium.Chromium.* 2>/dev/null || true'
      ];

      for (const command of cleanupCommands) {
        try {
          execSync(command, { stdio: 'ignore' });
        } catch (cmdErr) {
          // Ignore individual command errors
        }
      }

      if (forceDebug) {
        console.log(formatLogMessage('debug', 'Chrome temporary files cleaned'));
      }
    } catch (cleanupErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Chrome cleanup error: ${cleanupErr.message}`));
      }
    }
  }

  const pLimit = (await import('p-limit')).default;
  const limit = pLimit(MAX_CONCURRENT_SITES);

  const perSiteHeadful = sites.some(site => site.headful === true);
  const launchHeadless = !(headfulMode || perSiteHeadful);
  // launch with no safe browsing
  let browser = await createBrowser();
  if (forceDebug) console.log(formatLogMessage('debug', `Launching browser with headless: ${launchHeadless}`));

  // Initial cleanup of any existing Chrome temp files
  await cleanupChromeFiles();
 
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

  /**
   * Enhanced processUrl with retry logic for connection errors
   */
  async function processUrlWithRetry(currentUrl, siteConfig, browserInstance, attempt = 1) {
    try {
      return await processUrl(currentUrl, siteConfig, browserInstance);
    } catch (error) {
      const isLastAttempt = attempt >= RETRY_CONFIG.maxRetries;
      const shouldRetry = isRetryableError(error) && !isLastAttempt;
      
      if (shouldRetry) {
        const delay = Math.min(RETRY_CONFIG.retryDelay * Math.pow(RETRY_CONFIG.backoffMultiplier, attempt - 1), 10000); // Cap at 10 seconds
        console.warn(`⚠ Attempt ${attempt}/${RETRY_CONFIG.maxRetries} failed for ${currentUrl}: ${error.message}`);
        console.log(`🔄 Retrying in ${delay}ms...`);
        
        await sleep(delay);
        
        // Restart browser on connection errors
        if (error.message.includes('Protocol error: Connection closed')) {
          try {
            if (forceDebug) console.log(formatLogMessage('debug', `Restarting browser due to connection error...`));

            // Get user data dir before closing browser
            const userDataDir = browserInstance._userDataDir || browserInstance.process()?.spawnargs?.find(arg => arg.includes('--user-data-dir='))?.split('=')[1];
   
            // Force close with timeout
            await Promise.race([
              browserInstance.close(),
              new Promise((_, reject) => setTimeout(() => reject(new Error('Browser close timeout')), 5000))
            ]);

            // Clean up the specific user data directory
            if (userDataDir && fs.existsSync(userDataDir)) {
              fs.rmSync(userDataDir, { recursive: true, force: true });
            }

            browserInstance = await createBrowser();
          } catch (browserRestartErr) {
            if (forceDebug) console.log(formatLogMessage('debug', `Browser restart failed: ${browserRestartErr.message}`));
            // Continue with existing browser instance if restart fails
          }
        }
        
        return await processUrlWithRetry(currentUrl, siteConfig, browserInstance, attempt + 1);
      } else {
        // Final failure - return partial results if any matches were found
        console.warn(`❌ All ${RETRY_CONFIG.maxRetries} attempts failed for ${currentUrl}: ${error.message}`);
        return { url: currentUrl, rules: [], success: false, retryFailed: true };
      }
    }
  }

  /**
   * Enhanced navigation with better error handling
   */
  async function navigateWithRetry(page, url, options = {}, maxAttempts = 2, pageTimeout = 30000) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const defaultOptions = { 
          waitUntil: 'domcontentloaded', // More reliable than 'load' for flaky connections
          timeout: Math.min(45000, Math.max(pageTimeout, 30000)) // Between 30-45 seconds
        };
        const finalOptions = { ...defaultOptions, ...options };
        
        await page.goto(url, finalOptions);
        return true;
      } catch (navError) {
        if (attempt === maxAttempts) {
          throw navError;
        }
        
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Navigation attempt ${attempt} failed for ${url}: ${navError.message}`));
        }
        
        // Try to recover the page
        try {
          if (!page.isClosed()) {
            await page.evaluate(() => window.stop());
          }
        } catch (stopError) {
          // Ignore stop errors
        }
        
        await sleep(2000 * attempt);
      }
    }
    return false;
  }
  
  /**
   * Enhanced browser health check
   */
  async function isBrowserHealthy(browser) {
    try {
      const pages = await browser.pages();
      await browser.version();
      return true;
    } catch (healthError) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Browser health check failed: ${healthError.message}`));
      }
      return false;
    }
  }

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
    const cloudflarePhishBypass = siteConfig.cloudflare_phish === true;
    const cloudflareBypass = siteConfig.cloudflare_bypass === true;
    const sitePrivoxy = siteConfig.privoxy === true;
    const sitePihole = siteConfig.pihole === true;
    
    // Log site-level comments if debug mode is enabled
    if (forceDebug && siteConfig.comments) {
      const siteComments = Array.isArray(siteConfig.comments) ? siteConfig.comments : [siteConfig.comments];
      console.log(formatLogMessage('debug', `Site comments for ${currentUrl}: ${siteComments.length} item(s)`));
      siteComments.forEach((comment, idx) => 
        console.log(formatLogMessage('debug', `  Site comment ${idx + 1}: ${comment}`))
      );
    }

    if (siteConfig.firstParty === 0 && siteConfig.thirdParty === 0) {
      console.warn(`⚠ Skipping ${currentUrl} because both firstParty and thirdParty are disabled.`);
      return { url: currentUrl, rules: [], success: false, skipped: true };
    }

    let page = null;
    let cdpSession = null;
    // Use Map to track domains and their resource types for --adblock-rules
    const matchedDomains = adblockRulesMode || siteConfig.adblock_rules ? new Map() : new Set();
    const timeout = siteConfig.timeout || 30000;

    if (!silentMode) console.log(`\n${messageColors.scanning('Scanning:')} ${currentUrl}`);

    try {
      page = await browserInstance.newPage();
      
      // Set consistent timeouts for the page
      page.setDefaultTimeout(Math.max(timeout, 60000)); // At least 60 seconds
      page.setDefaultNavigationTimeout(Math.max(timeout, 60000));

      // Add page error handlers
      page.on('error', (err) => {
        if (forceDebug) console.log(`[debug] Page error: ${err.message}`);
      });
      
      page.on('pageerror', (err) => {
        if (forceDebug) {
          // Safely extract error message - err might not be an Error object
          const errorMessage = err?.message || err?.toString() || String(err) || 'Unknown error';
          console.log(`[debug] Page script error: ${errorMessage}`);
        }
      });
      
      page.on('console', (msg) => {
        if (forceDebug && msg.type() === 'error') console.log(`[debug] Console error: ${msg.text()}`);
      });

      // --- START: evaluateOnNewDocument for Fetch/XHR Interception (Moved and Fixed) ---
      // This script is injected if --eval-on-doc is used or siteConfig.evaluateOnNewDocument is true.
      const shouldInjectEvalForPage = siteConfig.evaluateOnNewDocument === true || globalEvalOnDoc;
      if (shouldInjectEvalForPage) {
          if (forceDebug) {
              if (globalEvalOnDoc) {
                  console.log(formatLogMessage('debug', `[evalOnDoc] Global Fetch/XHR interception enabled, applying to: ${currentUrl}`));
              } else { // siteConfig.evaluateOnNewDocument must be true
                  console.log(formatLogMessage('debug', `[evalOnDoc] Site-specific Fetch/XHR interception enabled for: ${currentUrl}`));
              }
          }
          try {
              await page.evaluateOnNewDocument(() => {
                  // This script intercepts and logs Fetch and XHR requests
                  // from within the page context at the earliest possible moment.
                  const originalFetch = window.fetch;
                  window.fetch = (...args) => {
                      console.log('[evalOnDoc][fetch]', args[0]); // Log fetch requests
                      return originalFetch.apply(this, args);
                  };

                  const originalXHROpen = XMLHttpRequest.prototype.open;
                  XMLHttpRequest.prototype.open = function (method, xhrUrl) { // Renamed 'url' to 'xhrUrl' to avoid conflict
                      console.log('[evalOnDoc][xhr]', xhrUrl); // Log XHR requests
                      return originalXHROpen.apply(this, arguments);
                  };
              });
          } catch (evalErr) {
              console.warn(formatLogMessage('warn', `[evalOnDoc] Failed to set up Fetch/XHR interception for ${currentUrl}: ${evalErr.message}`));
          }
      }
      // --- END: evaluateOnNewDocument for Fetch/XHR Interception ---

      // --- CSS Element Blocking Setup ---
      const cssBlockedSelectors = siteConfig.css_blocked;
      if (cssBlockedSelectors && Array.isArray(cssBlockedSelectors) && cssBlockedSelectors.length > 0) {
        if (forceDebug) console.log(formatLogMessage('debug', `CSS element blocking enabled for ${currentUrl}: ${cssBlockedSelectors.join(', ')}`));
        try {
          await page.evaluateOnNewDocument(({ selectors }) => {
            // Inject CSS to hide blocked elements
            const style = document.createElement('style');
            style.type = 'text/css';
            const cssRules = selectors.map(selector => `${selector} { display: none !important; visibility: hidden !important; }`).join('\n');
            style.innerHTML = cssRules;
            
            // Add the style as soon as DOM is available
            if (document.head) {
              document.head.appendChild(style);
            } else {
              document.addEventListener('DOMContentLoaded', () => document.head.appendChild(style));
            }
          }, { selectors: cssBlockedSelectors });
        } catch (cssErr) {
          console.warn(formatLogMessage('warn', `[css_blocked] Failed to set up CSS element blocking for ${currentUrl}: ${cssErr.message}`));
        }
      }
      // --- END: CSS Element Blocking Setup ---

      // --- Per-Page CDP Setup ---
      const cdpLoggingNeededForPage = enableCDP || siteConfig.cdp === true;
      if (cdpLoggingNeededForPage) {
        if (forceDebug) {
            if (enableCDP) {
                console.log(formatLogMessage('debug', `CDP logging globally enabled by --cdp, applying to page: ${currentUrl}`));
            } else if (siteConfig.cdp === true) {
                console.log(formatLogMessage('debug', `CDP logging enabled for page ${currentUrl} via site-specific 'cdp: true' config.`));
            }
        }
        try {
            cdpSession = await page.target().createCDPSession();
            await cdpSession.send('Network.enable');
            cdpSession.on('Network.requestWillBeSent', (params) => {
                const { url: requestUrl, method } = params.request;
                const initiator = params.initiator ? params.initiator.type : 'unknown';
                let hostnameForLog = 'unknown-host';
                try {
                    hostnameForLog = new URL(currentUrl).hostname;
                } catch (_) { /* ignore if currentUrl is invalid for URL parsing */ }
                console.log(formatLogMessage('debug', `[cdp][${hostnameForLog}] ${method} ${requestUrl} (initiator: ${initiator})`));
            });
        } catch (cdpErr) {
            cdpSession = null; // Reset on failure
            console.warn(formatLogMessage('warn', `[cdp] Failed to attach CDP session for ${currentUrl}: ${cdpErr.message}`));
        }
      }
      // --- End of Per-Page CDP Setup ---

      await page.setRequestInterception(true);
	  
	  // Set up frame handling to suppress invalid URL errors
      setupFrameHandling(page, forceDebug);
	  
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
          if (forceDebug) console.log(formatLogMessage('debug', `Cleared site data for ${currentUrl}`));
        } catch (clearErr) {
          console.warn(messageColors.warn(`[clear_sitedata failed] ${currentUrl}: ${clearErr.message}`));
        }
      }

      // --- Apply all fingerprint spoofing (user agent, Brave, fingerprint protection) ---
      await applyAllFingerprintSpoofing(page, siteConfig, forceDebug, currentUrl);

      const regexes = Array.isArray(siteConfig.filterRegex)
        ? siteConfig.filterRegex.map(r => new RegExp(r.replace(/^\/(.*)\/$/, '$1')))
        : siteConfig.filterRegex
          ? [new RegExp(siteConfig.filterRegex.replace(/^\/(.*)\/$/, '$1'))]
          : [];

   // Parse searchstring patterns using module
   const { searchStrings, searchStringsAnd, hasSearchString, hasSearchStringAnd } = parseSearchStrings(siteConfig.searchstring, siteConfig.searchstring_and);
   const useCurl = siteConfig.curl === true; // Use curl if enabled, regardless of searchstring
   let useGrep = siteConfig.grep === true && useCurl; // Grep requires curl to be enabled

   // Get user agent for curl if needed
   let curlUserAgent = '';
   if (useCurl && siteConfig.userAgent) {
     const userAgents = {
       chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
       firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
       safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15"
     };
     curlUserAgent = userAgents[siteConfig.userAgent.toLowerCase()] || '';
   }

   if (useCurl && forceDebug) {
     console.log(formatLogMessage('debug', `Curl-based content analysis enabled for ${currentUrl}`));
   }

   if (useGrep && forceDebug) {
     console.log(formatLogMessage('debug', `Grep-based pattern matching enabled for ${currentUrl}`));
   }
   
   // Validate grep availability if needed
   if (useGrep && (hasSearchString || hasSearchStringAnd)) {
     const grepCheck = validateGrepAvailability();
     if (!grepCheck.isAvailable) {
       console.warn(formatLogMessage('warn', `Grep not available for ${currentUrl}: ${grepCheck.error}. Falling back to JavaScript search.`));
       useGrep = false;
     } else if (forceDebug) {
       console.log(formatLogMessage('debug', `Using grep: ${grepCheck.version}`));
     }
   }

   // Parse whois and dig terms
   const whoisTerms = siteConfig.whois && Array.isArray(siteConfig.whois) ? siteConfig.whois : null;
   const whoisOrTerms = siteConfig['whois-or'] && Array.isArray(siteConfig['whois-or']) ? siteConfig['whois-or'] : null;
   const whoisServer = siteConfig.whois_server || null; // Parse whois_server configuration
   const digTerms = siteConfig.dig && Array.isArray(siteConfig.dig) ? siteConfig.dig : null;
   const digOrTerms = siteConfig['dig-or'] && Array.isArray(siteConfig['dig-or']) ? siteConfig['dig-or'] : null;
   const digRecordType = siteConfig.digRecordType || 'A';
   const hasNetTools = whoisTerms || whoisOrTerms || digTerms || digOrTerms;
   
   // Validate nettools availability if needed
   if (hasNetTools) {
     if (whoisTerms || whoisOrTerms) {
       const whoisCheck = validateWhoisAvailability();
       if (!whoisCheck.isAvailable) {
         console.warn(formatLogMessage('warn', `Whois not available for ${currentUrl}: ${whoisCheck.error}. Skipping whois checks.`));
         siteConfig.whois = null; // Disable whois for this site
	 siteConfig['whois-or'] = null; // Disable whois-or for this site
       } else if (forceDebug) {
         console.log(formatLogMessage('debug', `Using whois: ${whoisCheck.version}`));
       }
     }
     
     if (digTerms || digOrTerms) {
       const digCheck = validateDigAvailability();
       if (!digCheck.isAvailable) {
         console.warn(formatLogMessage('warn', `Dig not available for ${currentUrl}: ${digCheck.error}. Skipping dig checks.`));
         siteConfig.dig = null; // Disable dig for this site
         siteConfig['dig-or'] = null; // Disable dig-or for this site
       } else if (forceDebug) {
         console.log(formatLogMessage('debug', `Using dig: ${digCheck.version}`));
       }
     }
   }

      if (siteConfig.verbose === 1 && siteConfig.filterRegex) {
        const patterns = Array.isArray(siteConfig.filterRegex) ? siteConfig.filterRegex : [siteConfig.filterRegex];
        console.log(formatLogMessage('info', `Regex patterns for ${currentUrl}:`));
        patterns.forEach((pattern, idx) => {
          console.log(`  [${idx + 1}] ${pattern}`);
        });
      }

   if (siteConfig.verbose === 1 && (hasSearchString || hasSearchStringAnd)) {
     console.log(formatLogMessage('info', `Search strings for ${currentUrl}:`));
     if (hasSearchString) {
       console.log(`  OR logic (any must match):`);
       searchStrings.forEach((searchStr, idx) => {
         console.log(`    [${idx + 1}] "${searchStr}"`);
       });
     }
     if (hasSearchStringAnd) {
       console.log(`  AND logic (all must match):`);
       searchStringsAnd.forEach((searchStr, idx) => {
         console.log(`    [${idx + 1}] "${searchStr}"`);
       });
     }
   }

   if (siteConfig.verbose === 1 && whoisServer) {
     if (forceDebug) {
       if (Array.isArray(whoisServer)) {
         console.log(formatLogMessage('info', `Whois servers for ${currentUrl} (randomized): [${whoisServer.join(', ')}]`));
       } else {
         console.log(formatLogMessage('info', `Whois server for ${currentUrl}: ${whoisServer}`));
       }
     }
   }

   if (siteConfig.verbose === 1 && whoisTerms) {
     if (forceDebug) console.log(formatLogMessage('info', `Whois terms for ${currentUrl}:`));
     whoisTerms.forEach((term, idx) => {
       if (forceDebug) console.log(`  [${idx + 1}] "${term}"`);
     });
   }

   if (siteConfig.verbose === 1 && whoisOrTerms) {
     if (forceDebug) console.log(formatLogMessage('info', `Whois-or terms for ${currentUrl}:`));
     whoisOrTerms.forEach((term, idx) => {
       if (forceDebug) console.log(`  [${idx + 1}] "${term}" (OR logic)`);
     });
   }  
 
   if (siteConfig.verbose === 1 && digTerms) {
     if (forceDebug) console.log(formatLogMessage('info', `Dig terms for ${currentUrl} (${digRecordType} records):`));
     digTerms.forEach((term, idx) => {
       if (forceDebug) console.log(`  [${idx + 1}] "${term}"`);
     });
   }
   
  if (siteConfig.verbose === 1 && digOrTerms) {
    if (forceDebug) console.log(formatLogMessage('info', `Dig-or terms for ${currentUrl} (${digRecordType} records):`));
    digOrTerms.forEach((term, idx) => {
      if (forceDebug) console.log(`  [${idx + 1}] "${term}" (OR logic)`);
    });
  }

      const blockedRegexes = Array.isArray(siteConfig.blocked)
        ? siteConfig.blocked.map(pattern => new RegExp(pattern))
        : [];
		
      // Add global blocked patterns
      const globalBlockedRegexes = Array.isArray(globalBlocked)
        ? globalBlocked.map(pattern => new RegExp(pattern))
        : [];
      const allBlockedRegexes = [...blockedRegexes, ...globalBlockedRegexes];

      /**
       * Helper function to add domain to matched collection
       * @param {string} domain - Domain to add
       * @param {string} resourceType - Resource type (for --adblock-rules mode)
       */
      function addMatchedDomain(domain, resourceType = null) {
        if (matchedDomains instanceof Map) {
          if (!matchedDomains.has(domain)) {
            matchedDomains.set(domain, new Set());
          }
          // Only add the specific resourceType that was matched, not all types for this domain
          if (resourceType) {
            matchedDomains.get(domain).add(resourceType);
          }
        } else {
          matchedDomains.add(domain);
        }
      }

      // --- page.on('request', ...) Handler: Core Network Request Logic ---
      // This handler is triggered for every network request made by the page.
      // It decides whether to allow, block, or process the request based on:
      // - First-party/third-party status and site configuration.
      // - URL matching against blocklists (`blockedRegexes`).
      // - URL matching against filter patterns (`regexes`) for domain extraction.
      // - Global `ignoreDomains` list.
      page.on('request', request => {
        const checkedUrl = request.url();
        const checkedHostname = safeGetDomain(checkedUrl, true);
        const currentHostname = safeGetDomain(currentUrl, true);
        const isFirstParty = checkedHostname && currentHostname && checkedHostname === currentHostname;

        if (isFirstParty && siteConfig.firstParty === false) {
          request.continue();
          return;
        }
        if (!isFirstParty && siteConfig.thirdParty === false) {
          request.continue();
          return;
        }

        // Enhanced debug logging to show which frame the request came from
        if (forceDebug) {
          const frameUrl = request.frame() ? request.frame().url() : 'unknown-frame';
          const isMainFrame = request.frame() === page.mainFrame();
          console.log(formatLogMessage('debug', `${messageColors.highlight('[req]')}[frame: ${isMainFrame ? 'main' : 'iframe'}] ${frameUrl} → ${request.url()}`));
        }

        // Show --debug output and the url while its scanning
        if (forceDebug) {
          const simplifiedUrl = getRootDomain(currentUrl);
          const timestamp = new Date().toISOString();
          const logEntry = `${timestamp} [debug req][${simplifiedUrl}] ${request.url()}`;

          // Output to console
          console.log(formatLogMessage('debug', `${messageColors.highlight('[req]')}[${simplifiedUrl}] ${request.url()}`));

          // Output to file
          if (debugLogFile) {
            try {
              fs.appendFileSync(debugLogFile, logEntry + '\n');
            } catch (logErr) {
              console.warn(formatLogMessage('warn', `Failed to write to debug log file: ${logErr.message}`));
            }
          }
        }
        const reqUrl = request.url();

        if (allBlockedRegexes.some(re => re.test(reqUrl))) {
         if (forceDebug) {
           // Find which specific pattern matched for debug logging
            const allPatterns = [...(siteConfig.blocked || []), ...globalBlocked];
            const matchedPattern = allPatterns.find(pattern => new RegExp(pattern).test(reqUrl));
            const patternSource = siteConfig.blocked && siteConfig.blocked.includes(matchedPattern) ? 'site' : 'global';
           const simplifiedUrl = getRootDomain(currentUrl);
           console.log(formatLogMessage('debug', `${messageColors.blocked('[blocked]')}[${simplifiedUrl}] ${reqUrl} blocked by ${patternSource} pattern: ${matchedPattern}`));
           
           // Also log to file if debug logging is enabled
           if (debugLogFile) {
             try {
               const timestamp = new Date().toISOString();
               fs.appendFileSync(debugLogFile, `${timestamp} [blocked][${simplifiedUrl}] ${reqUrl} (${patternSource} pattern: ${matchedPattern})\n`);
             } catch (logErr) {
               console.warn(formatLogMessage('warn', `Failed to write blocked domain to debug log: ${logErr.message}`));
             }
           }
         }
          request.abort();
          return;
        }

        const reqDomain = safeGetDomain(reqUrl, perSiteSubDomains);

        if (!reqDomain) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Skipping request with unparseable URL: ${reqUrl}`));
          }
          request.continue();
          return;
        }

        if (matchesIgnoreDomain(reqDomain, ignoreDomains)) {
          request.continue();
          return;
        }

        for (const re of regexes) {
          if (re.test(reqUrl)) {
            const resourceType = request.resourceType();
            
           // *** UNIVERSAL RESOURCE TYPE FILTER ***
           // Check resourceTypes filter FIRST, before ANY processing (nettools, searchstring, immediate matching)
           const allowedResourceTypes = siteConfig.resourceTypes;
           if (allowedResourceTypes && Array.isArray(allowedResourceTypes) && allowedResourceTypes.length > 0) {
             if (!allowedResourceTypes.includes(resourceType)) {
               if (forceDebug) {
                 console.log(formatLogMessage('debug', `URL ${reqUrl} matches regex but resourceType '${resourceType}' not in allowed types [${allowedResourceTypes.join(', ')}]. Skipping ALL processing.`));

               }
               break; // Skip this URL entirely - doesn't match required resource types
             }
           }
            
            // Check if this URL matches any blocked patterns - if so, skip detection but still continue browser blocking
            if (allBlockedRegexes.some(re => re.test(reqUrl))) {
              if (forceDebug) {
                console.log(formatLogMessage('debug', `URL ${reqUrl} matches blocked pattern, skipping detection (but request already blocked)`));
              }
              break; // Skip detection but don't interfere with browser blocking
            }
            
            // Check ignoreDomains before any processing 
            if (!reqDomain || matchesIgnoreDomain(reqDomain, ignoreDomains)) {
              if (forceDebug) {
                console.log(formatLogMessage('debug', `Ignoring domain ${reqDomain} (matches ignoreDomains pattern)`));
              }
              break; // Skip this URL entirely
            }

           // If NO searchstring AND NO nettools are defined, match immediately (existing behavior)
           if (!hasSearchString && !hasSearchStringAnd && !hasNetTools) {
             addMatchedDomain(reqDomain, resourceType);
             const simplifiedUrl = getRootDomain(currentUrl);
             if (siteConfig.verbose === 1) {
               const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
              console.log(formatLogMessage('match', `[${simplifiedUrl}] ${reqUrl} matched regex: ${re} and resourceType: ${resourceType}${resourceInfo}`));

             }
             if (dumpUrls) {
               const timestamp = new Date().toISOString();
               const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
               fs.appendFileSync(matchedUrlsLogFile, `${timestamp} [match][${simplifiedUrl}] ${reqUrl} (resourceType: ${resourceType})${resourceInfo}\n`);

             }
            } else if (hasNetTools && !hasSearchString && !hasSearchStringAnd) {
             // If nettools are configured (whois/dig), perform checks on the domain
             if (forceDebug) {
               console.log(formatLogMessage('debug', `${reqUrl} matched regex ${re} and resourceType ${resourceType}, queued for nettools check`));
             }
             
             // Create and execute nettools handler
             const netToolsHandler = createNetToolsHandler({
               whoisTerms,
               whoisOrTerms,
               whoisDelay: whois_delay,
	       whoisServer, // Pass whois server configuration
               whoisServerMode: siteConfig.whois_server_mode || whois_server_mode,
               debugLogFile, // Pass debug log file for whois error logging
               fs, // Pass fs module for file operations
               digTerms,
               digOrTerms,
               digRecordType,
               digSubdomain: siteConfig.dig_subdomain === true,
               matchedDomains,
               addMatchedDomain,
               currentUrl,
               getRootDomain,
               siteConfig,
               dumpUrls,
               matchedUrlsLogFile,
               forceDebug,
               fs
             });
             
             // Execute nettools check asynchronously
            const originalDomain = (new URL(reqUrl)).hostname;
            setImmediate(() => netToolsHandler(reqDomain, originalDomain));
           } else {
             // If searchstring or searchstring_and IS defined (with or without nettools), queue for content checking
             if (forceDebug) {
               const searchType = hasSearchStringAnd ? 'searchstring_and' : 'searchstring';
               console.log(formatLogMessage('debug', `${reqUrl} matched regex ${re} and resourceType ${resourceType}, queued for ${searchType} content search`));
             }
           }
           
           // If curl is enabled, download and analyze content immediately
           if (useCurl) {
             try {
               // Use grep handler if both grep and searchstring/searchstring_and are enabled
               if (useGrep && (hasSearchString || hasSearchStringAnd)) {
                 const grepHandler = createGrepHandler({
                   searchStrings,
				   searchStringsAnd,
                   regexes,
                   matchedDomains,
                   addMatchedDomain, // Pass the helper function
                   currentUrl,
                   perSiteSubDomains,
                   ignoreDomains,
                   matchesIgnoreDomain,
                   getRootDomain,
                   siteConfig,
                   dumpUrls,
                   matchedUrlsLogFile,
                   forceDebug,
                   userAgent: curlUserAgent,
                   resourceType,
                   hasSearchString,
				   hasSearchStringAnd,
                   grepOptions: {
                     ignoreCase: true,
                     wholeWord: false,
                     regex: false
                   }
                 });
                 
                 setImmediate(() => grepHandler(reqUrl));
               } else {
                 // Use regular curl handler
                 const curlHandler = createCurlHandler({
                   searchStrings,
                   searchStringsAnd,
                   hasSearchStringAnd,
                   regexes,
                   matchedDomains,
                   addMatchedDomain, // Pass the helper function
                   currentUrl,
                   perSiteSubDomains,
                   ignoreDomains,
                   matchesIgnoreDomain,
                   getRootDomain,
                   siteConfig,
                   dumpUrls,
                   matchedUrlsLogFile,
                   forceDebug,
                   userAgent: curlUserAgent,
                   resourceType,
                   hasSearchString
                 });
                 
                 setImmediate(() => curlHandler(reqUrl));
               }
             } catch (curlErr) {
               if (forceDebug) {
                 console.log(formatLogMessage('debug', `Curl handler failed for ${reqUrl}: ${curlErr.message}`));
               }
             }
           }

          break;
          }
        }
        request.continue();
      });

     // Add response handler ONLY if searchstring/searchstring_and is defined AND neither curl nor grep is enabled
     if ((hasSearchString || hasSearchStringAnd) && !useCurl && !useGrep) {
       const responseHandler = createResponseHandler({
         searchStrings,
         searchStringsAnd,
         hasSearchStringAnd,
         regexes,
         matchedDomains,
         addMatchedDomain, // Pass the helper function
         currentUrl,
         perSiteSubDomains,
         ignoreDomains,
         matchesIgnoreDomain,
         getRootDomain,
         siteConfig,
         dumpUrls,
         matchedUrlsLogFile,
         forceDebug,
         resourceType: null // Response handler doesn't have direct access to resource type
       });

       page.on('response', responseHandler);
     }

      const interactEnabled = siteConfig.interact === true;
      
      // --- Runtime CSS Element Blocking (Fallback) ---
      // Apply CSS blocking after page load as a fallback in case evaluateOnNewDocument didn't work
      if (cssBlockedSelectors && Array.isArray(cssBlockedSelectors) && cssBlockedSelectors.length > 0) {
        try {
          await page.evaluate((selectors) => {
            const existingStyle = document.querySelector('#css-blocker-runtime');
            if (!existingStyle) {
              const style = document.createElement('style');
              style.id = 'css-blocker-runtime';
              style.type = 'text/css';
              const cssRules = selectors.map(selector => `${selector} { display: none !important; visibility: hidden !important; }`).join('\n');
              style.innerHTML = cssRules;
              document.head.appendChild(style);
            }
          }, cssBlockedSelectors);
        } catch (cssRuntimeErr) {
          console.warn(formatLogMessage('warn', `[css_blocked] Failed to apply runtime CSS blocking for ${currentUrl}: ${cssRuntimeErr.message}`));
        }
      }

      try {
        // Use custom goto options if provided, otherwise default to 'domcontentloaded'
        // load                  Wait for all resources (can timeout on broken sites)
        // domcontentloaded      Wait for DOM only (more reliable for flaky connections)
        // networkidle0          Wait until 0 network requests for 500ms
        // networkidle2          Wait until ≤2 network requests for 500ms
        const defaultGotoOptions = { waitUntil: 'domcontentloaded', timeout: Math.max(timeout, 45000) };
        const gotoOptions = siteConfig.goto_options ? { ...defaultGotoOptions, ...siteConfig.goto_options } : defaultGotoOptions;
        
        // Use enhanced navigation with retry
        await navigateWithRetry(page, currentUrl, gotoOptions, 2, timeout);
        siteCounter++;

        // Handle all Cloudflare protections using the dedicated module
        const cloudflareResult = await handleCloudflareProtection(page, currentUrl, siteConfig, forceDebug);
        
        if (!cloudflareResult.overallSuccess) {
          console.warn(`⚠ [cloudflare] Protection handling failed for ${currentUrl}:`);
          cloudflareResult.errors.forEach(error => {
            console.warn(`   - ${error}`);
          });
          // Continue with scan despite Cloudflare issues
        }

        console.log(formatLogMessage('info', `${messageColors.loaded('Loaded:')} (${siteCounter}/${totalUrls}) ${currentUrl}`));
        await page.evaluate(() => { console.log('Safe to evaluate on loaded page.'); });
        
        // Wait for iframes to load and log them
        if (forceDebug) {
          try {
            await new Promise(resolve => setTimeout(resolve, 2000)); // Give iframes time to load
            const frames = page.frames();
            console.log(formatLogMessage('debug', `Total frames found: ${frames.length}`));
            frames.forEach((frame, index) => {
          const frameUrl = frame.url();
          if (frameUrl &&
              frameUrl !== 'about:blank' &&
              frameUrl !== 'about:srcdoc' &&
              !frameUrl.startsWith('about:') &&
              !frameUrl.startsWith('data:') &&
              !frameUrl.startsWith('chrome-error://') &&
              !frameUrl.startsWith('chrome-extension://') &&
              frame !== page.mainFrame()) {
                console.log(formatLogMessage('debug', `Iframe ${index}: ${frameUrl}`));
              }
            });
          } catch (frameDebugErr) {
            console.log(formatLogMessage('debug', `Frame debugging failed: ${frameDebugErr.message}`));
          }
        }
      } catch (err) {
        console.error(formatLogMessage('error', `Failed on ${currentUrl}: ${err.message}`));
        throw err;
      }

      if (interactEnabled && !disableInteract) {
        if (forceDebug) console.log(formatLogMessage('debug', `interaction simulation enabled for ${currentUrl}`));
        const randomX = Math.floor(Math.random() * 500) + 50;
        const randomY = Math.floor(Math.random() * 500) + 50;
        await page.mouse.move(randomX, randomY, { steps: 10 });
        await page.mouse.move(randomX + 50, randomY + 50, { steps: 15 });
        await page.mouse.click(randomX + 25, randomY + 25);
        await page.hover('body');
      }

      const delayMs = siteConfig.delay || 4000;
      await page.waitForNetworkIdle({ idleTime: 4000, timeout: timeout });
      await new Promise(resolve => setTimeout(resolve, delayMs));

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
           if (forceDebug) console.log(formatLogMessage('debug', `Cleared site data before reload #${i + 1} for ${currentUrl}`));
         } catch (reloadClearErr) {
           console.warn(messageColors.warn(`[clear_sitedata before reload failed] ${currentUrl}: ${reloadClearErr.message}`));
         }
       }
        await page.reload({ waitUntil: 'domcontentloaded', timeout: timeout });
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }

      if (siteConfig.forcereload === true) {
        if (forceDebug) console.log(formatLogMessage('debug', `Forcing extra reload (cache disabled) for ${currentUrl}`));
        try {
          await page.setCacheEnabled(false);
          await page.reload({ waitUntil: 'domcontentloaded', timeout: timeout });
          await new Promise(resolve => setTimeout(resolve, delayMs));
          await page.setCacheEnabled(true);
        } catch (forceReloadErr) {
          console.warn(messageColors.warn(`[forcereload failed] ${currentUrl}: ${forceReloadErr.message}`));
        }
      }

      // Format rules using the output module
      const globalOptions = {
        localhostMode,
        localhostModeAlt,
        plainOutput,
        adblockRulesMode,
        dnsmasqMode,
        dnsmasqOldMode,
        unboundMode,
        privoxyMode,
        piholeMode
      };
      const formattedRules = formatRules(matchedDomains, siteConfig, globalOptions);
      
      return { url: currentUrl, rules: formattedRules, success: true };

    } catch (err) {
      console.warn(messageColors.warn(`⚠ Failed to load or process: ${currentUrl} (${err.message})`));
	  
      // Save any matches found even if page failed to load completely
      if (matchedDomains.size > 0 || (matchedDomains instanceof Map && matchedDomains.size > 0)) {
        const globalOptions = {
          localhostMode,
          localhostModeAlt,
          plainOutput,
          adblockRulesMode,
          dnsmasqMode,
          dnsmasqOldMode,
          unboundMode,
          piholeMode
        };
        const formattedRules = formatRules(matchedDomains, siteConfig, globalOptions);
        if (forceDebug) console.log(formatLogMessage('debug', `Saving ${formattedRules.length} rules despite page load failure`));
        return { url: currentUrl, rules: formattedRules, success: false, hasMatches: true };
      }
      
      
      if (siteConfig.screenshot === true && page) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const safeUrl = currentUrl.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_');
        const filename = `${safeUrl}-${timestamp}.jpg`;
        try {
          await page.screenshot({ path: filename, type: 'jpeg', fullPage: true });

          if (forceDebug) console.log(formatLogMessage('debug', `Screenshot saved: ${filename}`));
        } catch (screenshotErr) {
          console.warn(messageColors.warn(`[screenshot failed] ${currentUrl}: ${screenshotErr.message}`));
        }
      }
      return { url: currentUrl, rules: [], success: false };
    } finally {
      // Guaranteed resource cleanup - this runs regardless of success or failure
      
      if (cdpSession) {
        try {
          await cdpSession.detach();
          if (forceDebug) console.log(formatLogMessage('debug', `CDP session detached for ${currentUrl}`));
        } catch (cdpCleanupErr) {
          if (forceDebug) console.log(formatLogMessage('debug', `Failed to detach CDP session for ${currentUrl}: ${cdpCleanupErr.message}`));
        }
      }
      // Add small delay to allow cleanup to complete
      try {
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (delayErr) {
        // Ignore timeout errors
      }
      
      if (page && !page.isClosed()) {
        // Clear page resources before closing
        try {
          await page.evaluate(() => {
            if (window.gc) window.gc(); // Force garbage collection if available
          });
        } catch (gcErr) { /* ignore */ }

        try {
          await page.close();
          if (forceDebug) console.log(formatLogMessage('debug', `Page closed for ${currentUrl}`));
        } catch (pageCloseErr) {
          if (forceDebug) console.log(formatLogMessage('debug', `Failed to close page for ${currentUrl}: ${pageCloseErr.message}`));
        }
      }
    }
  }

// Temporarily store the pLimit function  
  const originalLimit = limit;

  // Group URLs by site to respect site boundaries during cleanup
  const siteGroups = [];
  let currentUrlCount = 0;

  for (const site of sites) {

    const urlsToProcess = Array.isArray(site.url) ? site.url : [site.url];
    siteGroups.push({
      config: site,
      urls: urlsToProcess
    });
    currentUrlCount += urlsToProcess.length;
  }
  if (!silentMode && currentUrlCount > 0) {
    console.log(`\n${messageColors.processing('Processing')} ${currentUrlCount} URLs across ${siteGroups.length} sites with concurrency ${MAX_CONCURRENT_SITES}...`);
    if (currentUrlCount > RESOURCE_CLEANUP_INTERVAL) {
      console.log(messageColors.processing('Browser will restart every') + ` ~${RESOURCE_CLEANUP_INTERVAL} URLs to free resources`);
    }
  }

  const results = [];
  let processedUrlCount = 0;
  let urlsSinceLastCleanup = 0;
  
  // Process sites one by one, but restart browser when hitting URL limits
  for (let siteIndex = 0; siteIndex < siteGroups.length; siteIndex++) {
    const siteGroup = siteGroups[siteIndex];
    const siteUrlCount = siteGroup.urls.length;
    
    // Check if processing this entire site would exceed cleanup interval
    const wouldExceedLimit = urlsSinceLastCleanup + siteUrlCount >= RESOURCE_CLEANUP_INTERVAL;
    const isNotLastSite = siteIndex < siteGroups.length - 1;
    
    // Restart browser if we've processed enough URLs and this isn't the last site
    if (wouldExceedLimit && urlsSinceLastCleanup > 0 && isNotLastSite) {

      // Get user data dir before closing browser for cleanup
      const userDataDir = browser._userDataDir || browser.process()?.spawnargs?.find(arg => arg.includes('--user-data-dir='))?.split('=')[1];

      // Check browser health before restart
      const isHealthy = await isBrowserHealthy(browser);
      if (!isHealthy) {
        if (!silentMode) {
          console.log(`\n${messageColors.fileOp('⚠ Browser unhealthy')}, forcing restart before site ${siteIndex + 1}/${siteGroups.length}...`);
        }
      } else {
      if (!silentMode) {
          console.log(`\n${messageColors.fileOp('🔄 Processed')} ${processedUrlCount} URLs. ${messageColors.fileOp('Restarting browser')} before processing site ${siteIndex + 1}/${siteGroups.length} to free resources...`);
        }
      }
      
      try {
        await handleBrowserExit(browser, {
          forceDebug,
          timeout: 10000,
          exitOnFailure: false
        });

        // Clean up the specific user data directory
        if (userDataDir && fs.existsSync(userDataDir)) {
          fs.rmSync(userDataDir, { recursive: true, force: true });
          if (forceDebug) console.log(formatLogMessage('debug', `Cleaned user data dir: ${userDataDir}`));
        }
        
        // Clean all Chrome temp files
        await cleanupChromeFiles();

      } catch (browserCloseErr) {
        if (forceDebug) console.log(formatLogMessage('debug', `Browser cleanup warning: ${browserCloseErr.message}`));
      }
      
      // Create new browser for next batch
      browser = await createBrowser();
      if (forceDebug) console.log(formatLogMessage('debug', `New browser instance created for site ${siteIndex + 1}`));
      
      // Reset cleanup counter and add delay
      urlsSinceLastCleanup = 0;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Processing site ${siteIndex + 1}/${siteGroups.length}: ${siteUrlCount} URL(s) (total processed: ${processedUrlCount})`));
    }
    
    // Create tasks with current browser instance and process them
    // Double-check browser health before processing this site group
    const isBrowserStillHealthy = await isBrowserHealthy(browser);
    if (!isBrowserStillHealthy) {
      console.warn(messageColors.warn(`⚠ Browser became unhealthy, attempting restart before site ${siteIndex + 1}...`));
      browser = await createBrowser();
    }

    const siteTasks = siteGroup.urls.map(url => originalLimit(() => processUrlWithRetry(url, siteGroup.config, browser)));
    const siteResults = await Promise.all(siteTasks);
    results.push(...siteResults);
    
    processedUrlCount += siteUrlCount;
    urlsSinceLastCleanup += siteUrlCount;
  }

  // Handle all output using the output module
  const outputConfig = {
    outputFile,
    compareFile,
    forceDebug,
    showTitles,
    removeDupes: removeDupes && outputFile,
    silentMode,
    dumpUrls,
    adblockRulesLogFile
  };
  
  const outputResult = handleOutput(results, outputConfig);
  
  if (!outputResult.success) {
    console.error(messageColors.error('❌ Failed to write output files'));
    process.exit(1);
  }

  // Use the success count from output handler
  siteCounter = outputResult.successfulPageLoads;
  
  // Count pages that had matches even if they failed to load completely
  const pagesWithMatches = results.filter(r => r.success || r.hasMatches).length;
  const totalMatches = results.reduce((sum, r) => sum + (r.rules ? r.rules.length : 0), 0);

  // Debug: Show output format being used
  if (forceDebug) {
    const globalOptions = {
      localhostMode,
      localhostModeAlt,
      plainOutput,
      adblockRules: adblockRulesMode,
      dnsmasq: dnsmasqMode,
      dnsmasqOld: dnsmasqOldMode,
      unbound: unboundMode,
      privoxy: privoxyMode,
      pihole: piholeMode
    };
     console.log(formatLogMessage('debug', `Output format: ${getFormatDescription(globalOptions)}`));
     console.log(formatLogMessage('debug', `Generated ${outputResult.totalRules} rules from ${outputResult.successfulPageLoads} successful page loads`));
  }
  
  // Compress log files if --compress-logs is enabled
  if (compressLogs && dumpUrls) {
    // Collect all existing log files for compression
    const filesToCompress = [];
    if (debugLogFile && fs.existsSync(debugLogFile)) filesToCompress.push(debugLogFile);
    if (matchedUrlsLogFile && fs.existsSync(matchedUrlsLogFile)) filesToCompress.push(matchedUrlsLogFile);
    if (adblockRulesLogFile && fs.existsSync(adblockRulesLogFile)) filesToCompress.push(adblockRulesLogFile);
    
    if (filesToCompress.length > 0) {
      if (!silentMode) console.log(`\n${messageColors.compression('Compressing')} ${filesToCompress.length} log file(s)...`);
      try {
        // Perform compression with original file deletion
        const results = await compressMultipleFiles(filesToCompress, true);
        
        if (!silentMode) {
          // Report compression results and file sizes
          results.successful.forEach(({ original, compressed }) => {
            const originalSize = fs.statSync(compressed).size; // compressed file size
            console.log(messageColors.success('✅ Compressed:') + ` ${path.basename(original)} → ${path.basename(compressed)}`);
          });
          // Report any compression failures
          if (results.failed.length > 0) {
            results.failed.forEach(({ path: filePath, error }) => {
              console.warn(messageColors.warn(`⚠ Failed to compress ${path.basename(filePath)}: ${error}`));
            });
          }
        }
      } catch (compressionErr) {
        console.warn(formatLogMessage('warn', `Log compression failed: ${compressionErr.message}`));
      }
    }
  }
 
  if (forceDebug) console.log(formatLogMessage('debug', `Starting browser cleanup...`));

  // Graceful browser shutdown with force closure fallback
  // Handle browser cleanup with force closure fallback (15 sec)
  // Get user data dir before final cleanup
  const finalUserDataDir = browser._userDataDir || browser.process()?.spawnargs?.find(arg => arg.includes('--user-data-dir='))?.split('=')[1];

  await handleBrowserExit(browser, {
    forceDebug,
    timeout: 15000,
    exitOnFailure: true
  });

  // Final cleanup of Chrome files
  if (finalUserDataDir && fs.existsSync(finalUserDataDir)) {
    fs.rmSync(finalUserDataDir, { recursive: true, force: true });
  }
  await cleanupChromeFiles();

  // Calculate timing, success rates, and provide summary information
  if (forceDebug) console.log(formatLogMessage('debug', `Calculating timing statistics...`));
  const endTime = Date.now();
  const durationMs = endTime - startTime;
  const totalSeconds = Math.floor(durationMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  // Final summary report with timing and success statistics
  if (!silentMode) {
    if (pagesWithMatches > outputResult.successfulPageLoads) {
      console.log(`\n${messageColors.success('Scan completed.')} ${outputResult.successfulPageLoads} of ${totalUrls} URLs loaded successfully, ${pagesWithMatches} had matches in ${messageColors.timing(`${hours}h ${minutes}m ${seconds}s`)}`);

    } else {
      console.log(`\n${messageColors.success('Scan completed.')} ${outputResult.successfulPageLoads} of ${totalUrls} URLs processed successfully in ${messageColors.timing(`${hours}h ${minutes}m ${seconds}s`)}`);

    }
    if (outputResult.totalRules > 0) {
      console.log(messageColors.success('Generated') + ` ${outputResult.totalRules} unique rules`);
    }
  }
  
  // Clean process termination
  if (forceDebug) console.log(formatLogMessage('debug', `About to exit process...`));
  process.exit(0);
  
  // Add graceful shutdown handling
  process.on('SIGINT', async () => {
    console.log('\n🛑 Received interrupt signal, shutting down gracefully...');
    if (browser) {
      try {
        await browser.close();
      } catch (err) {
        console.log('Browser cleanup error during shutdown:', err.message);
      }
    }
    process.exit(0);
  });
  process.on('SIGTERM', async () => {
    console.log('\n🛑 Received termination signal, shutting down gracefully...');
    if (browser) {
      try {
        await browser.close();
      } catch (err) {
        console.log('Browser cleanup error during shutdown:', err.message);
      }
    }
    process.exit(0);
  }); 
  
})();
