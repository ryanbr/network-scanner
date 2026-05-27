// === Network scanner script (nwss.js) v2.0.51 ===

// puppeteer for browser automation, fs for file system operations, psl for domain parsing.
// const pLimit = require('p-limit'); // Will be dynamically imported
const useObscura = process.argv.includes('--use-obscura');
const usePuppeteerCore = process.argv.includes('--use-puppeteer-core') || useObscura;
const puppeteer = usePuppeteerCore ? require('puppeteer-core') : require('puppeteer');
const fs = require('fs');
const os = require('os');
const psl = require('psl');
const path = require('path');
const dnsPromises = require('node:dns/promises');
const { createGrepHandler, validateGrepAvailability } = require('./lib/grep');
const { compressMultipleFiles, formatFileSize } = require('./lib/compress');
const { parseSearchStrings, createResponseHandler, createCurlHandler } = require('./lib/searchstring');
const { applyAllFingerprintSpoofing } = require('./lib/fingerprint');
const { formatRules, handleOutput, getFormatDescription } = require('./lib/output');
// Curl functionality (replace searchstring curl handler)
const { validateCurlAvailability, createCurlHandler: createCurlModuleHandler } = require('./lib/curl');
// Rule validation
const { validateRulesetFile, validateFullConfig, testDomainValidation, cleanRulesetFile, normalizeSiteConfig } = require('./lib/validate_rules');
// CF Bypass
const { 
  handleCloudflareProtection,
  getCacheStats,
  clearDetectionCache,
  parallelChallengeDetection,
  cleanup: cleanupCloudflareCache
} = require('./lib/cloudflare');
// FP Bypass
const { handleFlowProxyProtection, getFlowProxyTimeouts, attachFlowProxyHeaderListener } = require('./lib/flowproxy');
// ignore_similar rules
const { shouldIgnoreSimilarDomain, calculateSimilarity } = require('./lib/ignore_similar');
// Graceful exit
const { handleBrowserExit, cleanupChromeTempFiles, cleanupUserDataDir } = require('./lib/browserexit');
// Whois & Dig
const { createNetToolsHandler, createEnhancedDryRunCallback, validateWhoisAvailability, validateDigAvailability, enableDiskCache, getDnsCacheStats, domainKnownToResolve } = require('./lib/nettools');
// File compare
const { loadComparisonRules, filterUniqueRules } = require('./lib/compare');
// CDP functionality
const { createCDPSession, createPageWithTimeout, setRequestInterceptionWithTimeout } = require('./lib/cdp');
// Post-processing cleanup
const { processResults } = require('./lib/post-processing');
// Colorize various text when used
const { messageColors, formatLogMessage } = require('./lib/colorize');
const TIMEOUT_TAG = messageColors.processing('[TIMEOUT]');
const INTERACTION_TAG = messageColors.processing('[interaction]');
const GHOST_CURSOR_TAG = messageColors.processing('[ghost-cursor]');
const PROXY_TAG = messageColors.processing('[proxy]');
const GREP_RESPONSE_TAG = messageColors.processing('[grep-response]');
const IGNORE_DOMAINS_BY_URL_TAG = messageColors.processing('[ignoreDomainsByUrl]');
const BLOCK_DOMAINS_BY_URL_TAG = messageColors.processing('[blockDomainsByUrl]');
const IGNORE_SIMILAR_IGNORED_DOMAINS_TAG = messageColors.processing('[ignore_similar_ignored_domains]');
const IGNORE_SIMILAR_TAG = messageColors.processing('[ignore_similar]');
const CLEAR_SITEDATA_TAG = messageColors.processing('[clear_sitedata]');
const CSS_BLOCKED_TAG = messageColors.processing('[css_blocked]');
const EVAL_ON_DOC_TAG = messageColors.processing('[evalOnDoc]');
const REALTIME_CLEANUP_TAG = messageColors.processing('[realtime_cleanup]');
const VPN_TAG = messageColors.processing('[vpn]');
// Precomputed colored '[SmartCache]' subsystem prefix — paired with the
// same constant in lib/smart-cache.js so debug lines from both files
// produce consistently colored output. formatLogMessage only colors the
// [severity] tag; this constant colors the subsystem prefix.
const SMART_CACHE_TAG = messageColors.processing('[SmartCache]');
// Precomputed colored '[CONCURRENCY]' subsystem prefix for batch-throughput
// log lines (start/completed). Same cyan as the other monitoring tags.
const CONCURRENCY_TAG = messageColors.processing('[CONCURRENCY]');
// Enhanced mouse interaction and page simulation
const { performPageInteraction, createInteractionConfig, performContentClicks, humanLikeMouseMove } = require('./lib/interaction');
// Optional ghost-cursor support for advanced Bezier-based mouse movements
const { isGhostCursorAvailable, createGhostCursor, ghostMove, ghostClick, ghostRandomMove, resolveGhostCursorConfig } = require('./lib/ghost-cursor');
// Domain detection cache for performance optimization
const { createGlobalHelpers, getTotalDomainsSkipped, getDetectedDomainsCount } = require('./lib/domain-cache');
const { createSmartCache } = require('./lib/smart-cache'); // Smart cache system
const { clearPersistentCache } = require('./lib/smart-cache');
const { needsProxy, getProxyArgs, applyProxyAuth, getProxyInfo, testProxy, prepareSocksRelays, closeAllSocksRelays } = require('./lib/proxy');
// Dry run functionality
const { initializeDryRunCollections, addDryRunMatch, addDryRunNetTools, processDryRunResults, writeDryRunOutput } = require('./lib/dry-run');
// Enhanced site data clearing functionality
const { clearSiteData } = require('./lib/clear_sitedata');
// Referrer header generation
const { getReferrerForUrl, validateReferrerConfig, validateReferrerDisable } = require('./lib/referrer');
// Adblock rules parser
const adblockJs = require('./lib/adblock');
const adblockRust = require('./lib/adblock-rust');
// WireGuard VPN
const { connectForSite: wgConnect, disconnectForSite: wgDisconnect, disconnectAll: wgDisconnectAll, validateVpnConfig, normalizeVpnConfig } = require('./lib/wireguard_vpn');
// OpenVPN
const { connectForSite: ovpnConnect, disconnectForSite: ovpnDisconnect, disconnectAll: ovpnDisconnectAll, validateOvpnConfig, normalizeOvpnConfig } = require('./lib/openvpn_vpn');
 

// Fast setTimeout helper for Puppeteer 22.x compatibility
// Uses standard Promise constructor for better performance than node:timers/promises
function fastTimeout(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// --- Configuration Constants ---
const TIMEOUTS = Object.freeze({
  DEFAULT_PAGE: 35000,                // Standard page load timeout (35s)
  DEFAULT_NAVIGATION: 25000,          // Navigation operation timeout
  DEFAULT_NAVIGATION_REDUCED: 20000,  // Reduced timeout for faster failures
  DEFAULT_PAGE_REDUCED: 15000,        // Faster page timeout for quick failures
  FRAME_LOAD_WAIT: 2000,              // Wait time for iframes to load 
  DEFAULT_DELAY: 6000,                // Default delay: after page load
  NETWORK_IDLE: 2000,                 // Network idle detection time
  NETWORK_IDLE_MAX: 10000,            // Maximum network idle wait time
  FAST_SITE_THRESHOLD: 15000,         // Threshold for "fast site" optimizations
  EMERGENCY_RESTART_DELAY: 2000,      // Delay after emergency browser restart
  BROWSER_STABILIZE_DELAY: 1000,      // Browser stabilization after restart
  CURL_HANDLER_DELAY: 3000,           // Wait for async curl operations
  NETTOOLS_DRAIN_TIMEOUT: 3000,       // Hard cap for awaiting in-flight nettools (dig/whois) handlers before snapshot. Drains immediately if all complete; bounded so a hung dig can't block exit. Mirrors CURL_HANDLER_DELAY's role for curl/searchstring.
  PROTOCOL_TIMEOUT: 180000,           // Chrome DevTools Protocol timeout
  REDIRECT_JS_TIMEOUT: 5000           // JavaScript redirect detection timeout
});

const CACHE_LIMITS = Object.freeze({
  DISK_CACHE_SIZE: 1, // Effectively disabled — forcereload clears cache between loads
  MEDIA_CACHE_SIZE: 1, // Effectively disabled — no media caching needed for scanning
  DEFAULT_CACHE_PATH: '.cache',
  DEFAULT_MAX_SIZE: 5000
});

const CONCURRENCY_LIMITS = Object.freeze({
  MIN: 1,
  MAX: 50,
  DEFAULT: 6,
  HIGH_CONCURRENCY_THRESHOLD: 12  // Auto-enable aggressive caching above this
});

// V8 Optimization: Use Map for user agent lookups instead of object
const USER_AGENTS = Object.freeze(new Map([
  ['chrome', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"],
  ['chrome_mac', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"],
  ['chrome_linux', "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"],
  ['firefox', "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"],
  ['firefox_mac', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0"],
  ['firefox_linux', "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"],
  ['safari', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15"]
]));

const REALTIME_CLEANUP_THRESHOLD = 8; // Default pages to keep for realtime cleanup

/**
 * Detects the installed Puppeteer version dynamically
 * @returns {Object} Version info and compatibility settings
 */
function detectPuppeteerVersion() {
  try {
    const puppeteer = usePuppeteerCore ? require('puppeteer-core') : require('puppeteer');
    let versionString = null;
 
    // Try multiple methods to get version
    if (puppeteer.version) {
      versionString = puppeteer.version;
    } else if (puppeteer._version) {
      versionString = puppeteer._version;
    } else {
      // Fallback: try to get from Browser.version() after launch
      return { majorVersion: 22, useShellMode: true, detected: false };
    }
    
    const majorVersion = parseInt(versionString.split('.')[0]);
    const useShellMode = majorVersion >= 22;
    
    return {
      version: versionString,
      majorVersion,
      useShellMode,
      detected: true
    };
  } catch (err) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Could not detect Puppeteer version: ${err.message}`));
    }
    // Safe fallback - assume newer version
    return { majorVersion: 22, useShellMode: true, detected: false };
  }
}

// Enhanced redirect handling
const { navigateWithRedirectHandling, handleRedirectTimeout } = require('./lib/redirect');
// Ensure web browser is working correctly
// purgeStaleTrackers removed from import: browserhealth's pageCreationTracker
// and pageUsageTracker are now WeakMaps, so GC reclaims dead-page entries
// automatically — manual purging is no longer needed.
const { monitorBrowserHealth, isBrowserHealthy, isQuicklyResponsive, performGroupWindowCleanup, performRealtimeWindowCleanup, trackPageForRealtime, updatePageUsage, untrackPage, cleanupPageBeforeReload } = require('./lib/browserhealth');

// --- Script Configuration & Constants --- 
const VERSION = '2.0.33'; // Script version

// get startTime
const startTime = Date.now();

// Initialize domain cache helpers with debug logging if enabled
const domainCacheOptions = { enableLogging: false }; // Set to true for cache debug logs
const { isDomainAlreadyDetected, markDomainAsDetected } = createGlobalHelpers(domainCacheOptions);

// Smart cache will be initialized after config is loaded
let smartCache = null;

// --- Command-Line Argument Parsing ---
const args = process.argv.slice(2);

if (args.length === 0) {
  args.push('--help');
}

// --- .nwssconfig support: inject per-config settings into args ---
const NWSSCONFIG_PATH = path.join(__dirname, '.nwssconfig');
if (fs.existsSync(NWSSCONFIG_PATH)) {
  try {
    const nwssConfig = JSON.parse(fs.readFileSync(NWSSCONFIG_PATH, 'utf-8'));
    // Find which config file is being used (--custom-json <file> or positional .json arg)
    const customJsonIdx = args.findIndex(arg => arg === '--custom-json');
    const positionalJson = (customJsonIdx === -1)
      ? args.find(a => a.endsWith('.json') && !a.startsWith('--'))
      : null;
    const configFilename = (customJsonIdx !== -1 && args[customJsonIdx + 1])
      ? args[customJsonIdx + 1]
      : positionalJson;

    // If a positional .json was used (not --custom-json), wire it to --custom-json
    // so the real config loader picks it up instead of defaulting to config.json
    if (positionalJson && customJsonIdx === -1) {
      args.push('--custom-json', positionalJson);
      process.argv.push('--custom-json', positionalJson);
    }

    if (configFilename && nwssConfig.configs && nwssConfig.configs[configFilename]) {
      const settings = nwssConfig.configs[configFilename];
      const originalArgs = args.join(' ');

      // Map settings keys to CLI flags — only inject if not already in args
      const settingsMap = {
        output: ['-o', '--output'],
        max_concurrent: ['--max-concurrent'],
        dns_cache: ['--dns-cache'],
        cache_requests: ['--cache-requests'],
        dumpurls: ['--dumpurls'],
        remove_tempfiles: ['--remove-tempfiles'],
        color: ['--color'],
        remove_dupes: ['--remove-dupes', '--remove-dubes'],
        'remove-dupes': ['--remove-dupes', '--remove-dubes'],
        'remove-dubes': ['--remove-dupes', '--remove-dubes'],
        compress_logs: ['--compress-logs'],
        debug: ['--debug'],
        silent: ['--silent'],
        verbose: ['--verbose'],
        headful: ['--headful'],
        keep_open: ['--keep-open'],
        dry_run: ['--dry-run'],
        titles: ['--titles'],
        sub_domains: ['--sub-domains'],
        no_interact: ['--no-interact'],
        ghost_cursor: ['--ghost-cursor'],
        plain: ['--plain'],
        cdp: ['--cdp'],
        dnsmasq: ['--dnsmasq'],
        unbound: ['--unbound'],
        privoxy: ['--privoxy'],
        pihole: ['--pihole'],
        eval_on_doc: ['--eval-on-doc'],
        use_puppeteer_core: ['--use-puppeteer-core'],
        ignore_cache: ['--ignore-cache'],
        clear_cache: ['--clear-cache'],
        block_ads: ['--block-ads'],
        compare: ['--compare'],
        localhost: ['--localhost'],
        append: ['--append']
      };

      for (const [key, flags] of Object.entries(settingsMap)) {
        // Support both underscore and hyphen variants (e.g. dns_cache or dns-cache)
        const value = settings[key] !== undefined ? settings[key]
          : settings[key.replace(/_/g, '-')] !== undefined ? settings[key.replace(/_/g, '-')]
          : settings[key.replace(/-/g, '_')] !== undefined ? settings[key.replace(/-/g, '_')]
          : undefined;
        if (value === undefined) continue;
        // Skip if any variant of the flag is already in CLI args
        if (flags.some(f => originalArgs.includes(f))) continue;

        if (typeof value === 'boolean') {
          if (value) args.push(flags[flags.length - 1]);
        } else if (typeof value === 'string' || typeof value === 'number') {
          args.push(flags[flags.length - 1], String(value));
        }
      }
    }
  } catch (e) {
    console.error(`Warning: Failed to parse .nwssconfig: ${e.message}`);
  }
}

const headfulMode = args.includes('--headful');
// Sites (esp. video/streaming) call element.requestFullscreen() on load or
// click. In --headful that hijacks the real Chrome window into true
// fullscreen, forcing a manual ESC. Neutralize the Fullscreen API by
// default so it can't. Harmless in headless (no screen — the API is
// already inert there), so default-on keeps headful consistent with the
// primary headless path. --allow-fullscreen restores native behavior.
const allowFullscreen = args.includes('--allow-fullscreen');
const SOURCES_FOLDER = 'sources';

let outputFile = null;
const outputIndex = args.findIndex(arg => arg === '--output' || arg === '-o');
if (outputIndex !== -1 && args[outputIndex + 1]) {
  outputFile = args[outputIndex + 1];
}

const appendMode = args.includes('--append');

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
// Parse --localhost with optional IP address
let localhostIP = null;
const localhostIndex = args.findIndex(arg => arg.startsWith('--localhost'));
if (localhostIndex !== -1) {
  localhostIP = args[localhostIndex].includes('=') ? args[localhostIndex].split('=')[1] : '127.0.0.1';
}
const keepBrowserOpen = args.includes('--keep-open');
const loadExtensionPaths = [];
args.forEach((arg, idx) => {
  if (arg === '--load-extension' && args[idx + 1] && !args[idx + 1].startsWith('--')) {
    loadExtensionPaths.push(path.resolve(args[idx + 1]));
  }
});
const disableInteract = args.includes('--no-interact');
const globalGhostCursor = args.includes('--ghost-cursor');
const plainOutput = args.includes('--plain');
const enableCDP = args.includes('--cdp');
const dnsmasqMode = args.includes('--dnsmasq');
const dnsmasqOldMode = args.includes('--dnsmasq-old');
const unboundMode = args.includes('--unbound');
const removeDupes = args.includes('--remove-dupes') || args.includes('--remove-dubes');
const privoxyMode = args.includes('--privoxy');
const piholeMode = args.includes('--pihole');
const globalEvalOnDoc = args.includes('--eval-on-doc'); // For Fetch/XHR interception
const dryRunMode = args.includes('--dry-run');
const compressLogs = args.includes('--compress-logs');
const removeTempFiles = args.includes('--remove-tempfiles');
const validateConfig = args.includes('--validate-config');
let validateRules = args.includes('--validate-rules');
const testValidation = args.includes('--test-validation');
let cleanRules = args.includes('--clean-rules');
const clearCache = args.includes('--clear-cache');
const ignoreCache = args.includes('--ignore-cache');
const cacheRequests = args.includes('--cache-requests');
const dnsCacheMode = args.includes('--dns-cache');
if (dnsCacheMode) enableDiskCache();

// DNS pre-check before page.goto() — default-on, --no-dns-precheck disables.
// Filters NXDOMAIN / unresolvable hostnames in <100ms before paying the
// ~5-15s Puppeteer + Cloudflare detection round-trip on each.
const dnsPrecheckEnabled = !args.includes('--no-dns-precheck');
const dnsPrecheckTimeoutMs = 2000;

// Per-scan cache of negative DNS lookups. OS resolvers don't always cache
// NXDOMAIN responses, and a scan can hit the same dead hostname many times
// (different URL paths on the same site). Positive results are left to the
// OS cache; failure-cache avoids repeated lookup latency for known-dead hosts.
// FIFO eviction at DNS_NEGATIVE_CACHE_MAX so pathological scans (thousands
// of unique dead hosts) can't grow the cache unboundedly. Same pattern as
// the rest of the codebase's in-memory caches.
const dnsNegativeCache = new Map(); // hostname -> { error, timestamp }
const DNS_NEGATIVE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DNS_NEGATIVE_CACHE_MAX = 1000;
let dnsPrecheckSkips = 0;          // URLs skipped because hostname is NXDOMAIN-cached
let dnsPositiveSkips = 0;          // URLs skipped because dig/whois cache proves resolution
const dnsPositiveSkippedHosts = new Set(); // unique hostnames that triggered the positive skip path
// c-ares transient codes — read-only, hoisted out of the per-task DNS
// pre-check so we don't allocate a fresh Set per URL.
const DNS_TRANSIENT_ERRORS = new Set(['ETIMEOUT', 'ESERVFAIL', 'EREFUSED', 'ECONNREFUSED']);

function dnsNegativeCacheSet(hostname, error) {
  if (dnsNegativeCache.size >= DNS_NEGATIVE_CACHE_MAX) {
    dnsNegativeCache.delete(dnsNegativeCache.keys().next().value);
  }
  dnsNegativeCache.set(hostname, { error, timestamp: Date.now() });
}

let validateRulesFile = null;
const validateRulesIndex = args.findIndex(arg => arg === '--validate-rules');
if (validateRulesIndex !== -1 && args[validateRulesIndex + 1] && !args[validateRulesIndex + 1].startsWith('--')) {
  validateRulesFile = args[validateRulesIndex + 1];
  validateRules = true; // Override the boolean if file specified
}

let cleanRulesFile = null;
const cleanRulesIndex = args.findIndex(arg => arg === '--clean-rules');
if (cleanRulesIndex !== -1 && args[cleanRulesIndex + 1] && !args[cleanRulesIndex + 1].startsWith('--')) {
  cleanRulesFile = args[cleanRulesIndex + 1];
  cleanRules = true; // Override the boolean if file specified
}

let maxConcurrentSites = null;
const maxConcurrentIndex = args.findIndex(arg => arg === '--max-concurrent');
if (maxConcurrentIndex !== -1 && args[maxConcurrentIndex + 1]) {
  maxConcurrentSites = parseInt(args[maxConcurrentIndex + 1]);
}

let cleanupInterval = null;
const cleanupIntervalIndex = args.findIndex(arg => arg === '--cleanup-interval');
if (cleanupIntervalIndex !== -1 && args[cleanupIntervalIndex + 1]) {
  cleanupInterval = parseInt(args[cleanupIntervalIndex + 1]);
}

const enableColors = args.includes('--color') || args.includes('--colour');
let adblockRulesMode = args.includes('--adblock-rules');

// Adblock variables (request blocking)
let adblockEnabled = false;
let adblockMatcher = null;
let adblockStats = { blocked: 0, allowed: 0 };

// Cloudflare scan-wide stats. errorPages counts URLs where the returned page
// was a Cloudflare-served 5xx origin error (522/523/etc.) — no bypass
// possible, useful signal for diagnosing dead-origin scans. Named distinct
// from the local cloudflareStats = getCacheStats() in the debug stats block.
let cloudflareScanStats = { errorPages: 0 };

// Validate --adblock-rules usage - ignore if used incorrectly instead of erroring
if (adblockRulesMode) {
  if (!outputFile) {
    if (forceDebug) console.log(formatLogMessage('debug', `--adblock-rules ignored: requires --output (-o) to specify an output file`));
    adblockRulesMode = false;
  } else if (localhostIP || plainOutput || dnsmasqMode || dnsmasqOldMode || unboundMode || privoxyMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--adblock-rules ignored: incompatible with localhost/plain output modes`));
    adblockRulesMode = false;
  }
}

// Validate --dnsmasq usage
if (dnsmasqMode) {
  if (localhostIP || plainOutput || adblockRulesMode || dnsmasqOldMode || unboundMode || privoxyMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--dnsmasq-old ignored: incompatible with localhost/plain/adblock-rules/dnsmasq output modes`));
    dnsmasqMode = false;
  }
}

// Validate --dnsmasq-old usage
if (dnsmasqOldMode) {
  if (localhostIP || plainOutput || adblockRulesMode || dnsmasqMode || unboundMode || privoxyMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--dnsmasq-old ignored: incompatible with localhost/plain/adblock-rules/dnsmasq output modes`));
    dnsmasqOldMode = false;
  }
}

// Validate --unbound usage
if (unboundMode) {
  if (localhostIP || plainOutput || adblockRulesMode || dnsmasqMode || dnsmasqOldMode || privoxyMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--unbound ignored: incompatible with localhost/plain/adblock-rules/dnsmasq output modes`));
    unboundMode = false;
  }
}

// Validate --privoxy usage
if (privoxyMode) {
  if (localhostIP || plainOutput || adblockRulesMode || dnsmasqMode || dnsmasqOldMode || unboundMode || piholeMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--privoxy ignored: incompatible with localhost/plain/adblock-rules/dnsmasq/unbound output modes`));
    privoxyMode = false;
  }
}

// Validate --pihole usage
if (piholeMode) {
  if (localhostIP || plainOutput || adblockRulesMode || dnsmasqMode || dnsmasqOldMode || unboundMode || privoxyMode) {
    if (forceDebug) console.log(formatLogMessage('debug', `--pihole ignored: incompatible with localhost/plain/adblock-rules/dnsmasq/unbound/privoxy output modes`));
    piholeMode = false;
  }
}

// Validate --compress-logs usage
if (compressLogs && !dumpUrls) {
  console.error(`❌ --compress-logs can only be used with --dumpurls`);
  process.exit(1);
}

// Validate --append usage  
if (appendMode && !outputFile) {
  console.error(`❌ --append requires --output (-o) to specify an output file`);
  process.exit(1);
}

if (appendMode && (compareFile || dryRunMode)) {
  console.error(`❌ --append cannot be used with --compare or --dry-run`);
  process.exit(1);
}

// Validate --dry-run usage
if (dryRunMode) {
  if (compressLogs || compareFile) {
    console.error(`❌ --dry-run cannot be used with --compress-logs or --compare`);
    process.exit(1);
  }
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

// Handle --clear-cache before config loading (uses default cache path)
if (clearCache && !dryRunMode) {
  clearPersistentCache({
    silent: silentMode,
    forceDebug,
    cachePath: CACHE_LIMITS.DEFAULT_CACHE_PATH // Default path, will be updated after config loads if needed
  });
  
  // Also clear Cloudflare detection cache
  clearDetectionCache();
  if (forceDebug) console.log(formatLogMessage('debug', 'Cleared Cloudflare detection cache'));
}

// Handle validation-only operations before main help
if (testValidation) {
  console.log(`\n${messageColors.processing('Running domain validation tests...')}`);
  const testResult = testDomainValidation();
  if (testResult) {
    console.log(`${messageColors.success('✅ All validation tests passed!')}`);
    process.exit(0);
  } else {
    console.log(`${messageColors.error('❌ Some validation tests failed!')}`);
    process.exit(1);
  }
}

// Note: --validate-config is handled further down, AFTER the config file is
// loaded and `config`/`sites` are populated. Running it here would fail with
// "Cannot access 'config' before initialization" since those are declared
// later in the module.

if (validateRules || validateRulesFile) {
  const filesToValidate = validateRulesFile ? [validateRulesFile] : [outputFile, compareFile].filter(Boolean);
  
  if (filesToValidate.length === 0) {
    console.error('❌ --validate-rules requires either a file argument or --output/--compare files to be specified');
    process.exit(1);
  }
  
  console.log(`\n${messageColors.processing('Validating rule files...')}`);
  let overallValid = true;
  
  for (const file of filesToValidate) {
    console.log(`\n${messageColors.info('Validating:')} ${file}`);
    try {
      const validation = validateRulesetFile(file, { forceDebug, silentMode, maxErrors: 20 });
      
      if (validation.isValid) {
        console.log(`${messageColors.success('✅ Valid:')} ${validation.stats.valid} rules, ${validation.stats.comments} comments`);
        if (validation.duplicates.length > 0) {
          console.log(`${messageColors.warn('⚠ Duplicates:')} ${validation.duplicates.length} duplicate rules found`);
        }
        
        if (Object.keys(validation.stats.formats).length > 0) {
          console.log(`${messageColors.info('Formats:')} ${Object.entries(validation.stats.formats).map(([f, c]) => `${f}(${c})`).join(', ')}`);
        }
      } else {
        console.log(`${messageColors.error('❌ Invalid:')} ${validation.stats.invalid} invalid rules out of ${validation.stats.total} total`);
        overallValid = false;
      }
    } catch (validationErr) {
      console.error(`❌ Failed to validate ${file}: ${validationErr.message}`);
      overallValid = false;
    }
  }
  
  if (overallValid) {
    console.log(`\n${messageColors.success('✅ All rule files are valid!')}`);
    process.exit(0);
  } else {
    console.log(`\n${messageColors.error('❌ Some rule files have validation errors!')}`);
    process.exit(1);
  }
}

// Parse --adblock-engine=<js|rust> (default: js). Selects the matcher backend
// used by --block-ads. The rust engine requires the optional adblock-rs package.
const adblockEngineIndex = args.findIndex(arg => arg.startsWith('--adblock-engine'));
let adblockEngineName = 'js';
if (adblockEngineIndex !== -1) {
  const engineArg = args[adblockEngineIndex].includes('=')
    ? args[adblockEngineIndex].split('=')[1]
    : args[adblockEngineIndex + 1];
  if (engineArg === 'rust' || engineArg === 'js') {
    adblockEngineName = engineArg;
  } else {
    console.log(`Error: --adblock-engine must be 'js' or 'rust' (got: ${engineArg})`);
    process.exit(1);
  }
}

// Parse --block-ads argument for request-level ad blocking (supports comma-separated lists)
const blockAdsIndex = args.findIndex(arg => arg.startsWith('--block-ads'));
if (blockAdsIndex !== -1) {
  const rulesArg = args[blockAdsIndex].includes('=')
    ? args[blockAdsIndex].split('=')[1]
    : args[blockAdsIndex + 1];

  if (!rulesArg) {
    console.log('Error: No adblock rules file specified');
    process.exit(1);
  }

  const rulesFiles = rulesArg.split(',').map(f => f.trim()).filter(f => f);
  for (const file of rulesFiles) {
    if (!fs.existsSync(file)) {
      console.log(`Error: Adblock rules file not found: ${file}`);
      process.exit(1);
    }
  }

  adblockEnabled = true;
  const engine = adblockEngineName === 'rust' ? adblockRust : adblockJs;
  try {
    if (engine === adblockRust) {
      // Rust wrapper accepts an array directly — no temp file needed.
      adblockMatcher = engine.parseAdblockRules(rulesFiles, { enableLogging: forceDebug });
    } else {
      // JS engine takes a single path; concat to a temp file when multiple lists.
      let rulesFile = rulesFiles[0];
      if (rulesFiles.length > 1) {
        rulesFile = path.join(os.tmpdir(), `nwss-adblock-combined-${Date.now()}.txt`);
        const combined = rulesFiles.map(f => fs.readFileSync(f, 'utf-8')).join('\n');
        fs.writeFileSync(rulesFile, combined);
      }
      adblockMatcher = engine.parseAdblockRules(rulesFile, { enableLogging: forceDebug });
    }
  } catch (err) {
    console.log(`Error: Failed to load adblock engine '${adblockEngineName}': ${err.message}`);
    process.exit(1);
  }
  const stats = adblockMatcher.getStats();
  const ruleDesc = stats.total != null
    ? `${stats.total} blocking rules`
    : `compiled engine (cached)`;
  if (!silentMode) console.log(messageColors.success(`Adblock enabled (${adblockEngineName}): Loaded ${ruleDesc} from ${rulesFiles.length} list${rulesFiles.length > 1 ? 's' : ''}`));
}

if (args.includes('--help') || args.includes('-h')) {
  console.log(`Usage: node nwss.js [options]

Options:
  --color, --colour              Enable colored console output for status messages
  -o, --output <file>            Output file for rules. If omitted, prints to console
  --compare <file>               Remove rules that already exist in this file before output
  --append                       Append new rules to output file instead of overwriting (requires -o)
    
Output Format Options:
  --localhost[=IP]               Output as IP domain.com (default: 127.0.0.1)
                                 Examples: --localhost, --localhost=0.0.0.0, --localhost=192.168.1.1
  --plain                        Output just domains (no adblock formatting)
  --dnsmasq                      Output as local=/domain.com/ (dnsmasq format)
  --dnsmasq-old                  Output as server=/domain.com/ (dnsmasq old format)
  --unbound                      Output as local-zone: "domain.com." always_null (unbound format)
  --privoxy                      Output as { +block } .domain.com (Privoxy format)
  --pihole                       Output as (^|\\.)domain\\.com$ (Pi-hole regex format)
  --adblock-rules                Generate adblock filter rules with resource type modifiers (requires -o)
  
Request Blocking:
  --block-ads=<file>             Block ads/trackers using EasyList format rules (||domain.com^, /ads/*, etc)
                                 Works at request-level for maximum performance
                                 Supports comma-separated lists: --block-ads=easylist.txt,easyprivacy.txt
  --adblock-engine=<js|rust>     Matcher backend for --block-ads (default: js)
                                 'rust' uses Brave's adblock-rs (faster on large lists; needs: npm i adblock-rs)

Per-config settings file (.nwssconfig):
  Place a .nwssconfig file in the project root to define per-config settings.
  When a config filename matches a key in .nwssconfig, those settings are used.
  CLI flags merge with and override .nwssconfig settings.
  See README.md for format details.

General Options:
  --verbose                      Force verbose mode globally
  --debug                        Force debug mode globally
  --silent                       Suppress normal console logs
  --titles                       Add ! <url> title before each site's group
  --dumpurls                     Dump matched URLs into matched_urls.log
  --dry-run                      Console output only: show matching regex, titles, whois/dig/searchstring results, and adblock rules
  --compress-logs                Compress log files with gzip (requires --dumpurls)
  --sub-domains                  Output full subdomains instead of collapsing to root
  --no-interact                  Disable page interactions globally
  --ghost-cursor                 Use ghost-cursor Bezier mouse movements (requires: npm i ghost-cursor)
  --custom-json <file>           Use a custom config JSON file instead of config.json
  --headful                      Launch browser with GUI (not headless)
  --keep-open                    Keep browser open after scan completes (use with --headful)
  --allow-fullscreen             Allow sites to use the Fullscreen API. By default it is
                                 neutralized so sites can't hijack the window in --headful
  --use-puppeteer-core           Use puppeteer-core with system Chrome instead of bundled Chromium
  --use-obscura                  Connect to running Obscura CDP server (ws://127.0.0.1:9222 or OBSCURA_WS env)
                                 Skips fingerprint injection — Obscura provides built-in stealth
  --load-extension <path>        Load unpacked Chrome extension from directory
  --cdp                          Enable Chrome DevTools Protocol logging (now per-page if enabled)
  --remove-dupes                 Remove duplicate domains from output (only with -o)
  --eval-on-doc                 Globally enable evaluateOnNewDocument() for Fetch/XHR interception
  --help, -h                     Show this help menu
  --version                      Show script version
  --max-concurrent <number>      Maximum concurrent site processing (1-50, overrides config/default)
  --cleanup-interval <number>    Browser restart interval in URLs processed (1-1000, overrides config/default)
  --remove-tempfiles             Remove Chrome/Puppeteer temporary files before exit

Validation Options:
  --cache-requests               Cache HTTP requests to avoid re-requesting same URLs within scan
  --dns-cache                    Persist dig/whois results to disk between runs (20h TTL, 2000-entry cap each)
  --no-dns-precheck              Disable per-URL DNS resolution check before page navigation.
                                 By default, URLs whose hostname doesn't resolve are skipped
                                 immediately (saves ~5-15s of Puppeteer time per dead host).
  --validate-config              Validate config.json file and exit
  --validate-rules [file]        Validate rule file format (uses --output/--compare files if no file specified)
  --clean-rules [file]           Clean rule files by removing invalid lines and optionally duplicates (uses --output/--compare files if no file specified)
  --test-validation              Run domain validation tests and exit
  --clear-cache                  Clear persistent cache before scanning (improves fresh start performance)
  --ignore-cache                 Bypass all smart caching functionality during scanning
  
Global config.json options:
  ignoreDomains: ["domain.com", "*.ads.com"]     Domains to completely ignore (supports wildcards)
  ignoreDomainsByUrl: ["regex1", "regex2"]       Regex patterns; if any request URL matches, the request's root domain is ignored for the rest of the scan
  blockDomainsByUrl: ["regex1", "regex2"]        Regex patterns; if any request URL matches, ALL subsequent requests on that root domain (and subdomains) are aborted via Puppeteer for the rest of the scan
  blocked: ["regex1", "regex2"]                   Global regex patterns to block requests (combined with per-site blocked)
  whois_server_mode: "random" or "cycle"      Default server selection mode for all sites (default: random)
  ignore_similar: true/false                      Ignore domains similar to already found domains (default: true)
  ignore_similar_threshold: 80                    Similarity threshold percentage for ignore_similar (default: 80)
  ignore_similar_ignored_domains: true/false      Ignore domains similar to ignoreDomains list (default: true)
  max_concurrent_sites: 8                        Maximum concurrent site processing (1-50, default: 8)
  resource_cleanup_interval: 80                  Browser restart interval in URLs processed (1-1000, default: 80)
  disable_ad_tagging: true/false                 Disable Chrome AdTagging to prevent ad frame throttling (default: true)

Per-site config.json options:
  url: "site" or ["site1", "site2"]          Single URL or list of URLs
  filterRegex: "regex" or ["regex1", "regex2"]  Patterns to match requests
  regex_and: true/false                       Use AND logic for multiple filterRegex patterns (default: false)
                                              When true, ALL regex patterns must match the same URL
  
Redirect Handling Options:
  follow_redirects: true/false               Follow redirects to new domains (default: true)
  max_redirects: 10                          Maximum number of redirects to follow (default: 10)
  js_redirect_timeout: 5000                  Milliseconds to wait for JavaScript redirects (default: 5000)
  detect_js_patterns: true/false             Analyze page source for redirect patterns (default: true)
  redirect_timeout_multiplier: 1.5          Increase timeout for redirected URLs (default: 1.5)

  comments: "text" or ["text1", "text2"]       Documentation/notes - ignored by script
  searchstring: "text" or ["text1", "text2"]   Text to search in response content (requires filterRegex match)
  ignore_similar: true/false                   Override global ignore_similar setting for this site
  ignore_similar_threshold: 80                 Override global similarity threshold for this site
  ignore_similar_ignored_domains: true/false   Override global ignore_similar_ignored_domains for this site
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
  userAgent: "chrome"|"chrome_mac"|"chrome_linux"|"firefox"|"firefox_mac"|"firefox_linux"|"safari"  Custom desktop User-Agent
  interact_intensity: "low"|"medium"|"high"     Interaction simulation intensity (default: medium)
  delay: <milliseconds>                        Delay after load (default: 6000, capped at 2000ms unless delay_uncapped: true)
  delay_uncapped: true/false                   Honor 'delay' up to half the per-URL timeout instead of the 2s default cap. Use for sites with setTimeout-deferred lazy ad/tracker loaders that fire well past the standard post-networkidle window
  reload: <number>                             Reload page n times after load (default: 1)
  forcereload: true/false or ["domain1.com", "domain2.com"]  Force cache-clearing reload for all URLs or specific domains
  clear_sitedata: true/false                   Clear all cookies, cache, storage before each load (default: false)
  clear_sitedata_full_on_reload: true/false    With clear_sitedata: true, also clear heavy storage (IndexedDB, WebSQL, service workers) between reloads — quick mode (cookies+cache+local/session storage) is the default for reloads; this flag promotes them to full clears at ~100-500ms latency cost per reload. Use for sites with IndexedDB/service-worker-backed session caps. Off by default.
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
  screenshot: true/false/\"force\"                Capture screenshot (true=on failure, \"force\"=always)
  headful: true/false                          Launch browser with GUI for this site
  fingerprint_protection: true/false/"random" Enable fingerprint spoofing: true/false/"random"
  adblock_rules: true/false                    Generate adblock filter rules with resource types for this site
  even_blocked: true/false                     Add matching rules even if requests are blocked (default: false)
  
  bypass_cache: true/false                     Skip all caching for this site's URLs (default: false)
  referrer_headers: "url" or ["url1", "url2"] Set referrer header for realistic traffic sources
  custom_headers: {"Header": "value"}         Add custom HTTP headers to requests
  referrer_disable: ["url1", "url2"]         Disable referrer headers for specific URLs

Cloudflare Protection Options:
  cloudflare_phish: true/false                 Auto-click through Cloudflare phishing warnings (default: false)
  cloudflare_bypass: true/false               Auto-solve Cloudflare "Verify you are human" challenges (default: false)
  cloudflare_parallel_detection: true/false    Use parallel detection for faster Cloudflare checks (default: true)
  cloudflare_max_retries: <number>            Maximum retry attempts for Cloudflare operations (default: 3)
  cloudflare_cache_ttl: <milliseconds>        TTL for Cloudflare detection cache (default: 300000 - 5 minutes)
  cloudflare_retry_on_error: true/false       Enable retry logic for Cloudflare operations (default: true)
                                               Note: Automatically detects and exits on redirect loops to prevent endless loading
  cloudflare_retry_on_error: true/false       Enable retry logic for Cloudflare operations (default: true)

FlowProxy Protection Options:
  flowproxy_detection: true/false              Enable flowProxy protection detection and handling (default: false)
  flowproxy_page_timeout: <milliseconds>       Page timeout for flowProxy sites (default: 45000)
  flowproxy_nav_timeout: <milliseconds>        Navigation timeout for flowProxy sites (default: 45000)
  flowproxy_js_timeout: <milliseconds>         JavaScript challenge timeout (default: 15000)
  flowproxy_delay: <milliseconds>              Delay for rate limiting (default: 30000)
  flowproxy_additional_delay: <milliseconds>   Additional processing delay (default: 5000)

Advanced Options:
  evaluateOnNewDocument: true/false           Inject fetch/XHR interceptor in page (for this site)
  cdp: true/false                            Enable CDP logging for this site Inject fetch/XHR interceptor in page
  cdp_specific: ["domain1.com", "domain2.com"] Enable CDP logging only for specific domains in the URL list
  interact_duration: <milliseconds>           Duration of interaction simulation (default: 2000)
  interact_scrolling: true/false              Enable scrolling simulation (default: true)
  interact_clicks: true/false                 Enable element clicking simulation (default: false)
  interact_typing: true/false                 Enable typing simulation (default: false)
  cursor_mode: "ghost"                        Use ghost-cursor Bezier mouse (requires: npm i ghost-cursor)
  ghost_cursor_speed: <number>                Ghost-cursor speed multiplier (default: auto)
  ghost_cursor_hesitate: <milliseconds>       Delay before ghost-cursor clicks (default: 50)
  ghost_cursor_overshoot: <pixels>            Max ghost-cursor overshoot distance (default: auto)
  ghost_cursor_duration: <milliseconds>       Ghost-cursor interaction duration (default: interact_duration or 2000)
  whois: ["term1", "term2"]                   Check whois data for ALL specified terms (AND logic)
  whois-or: ["term1", "term2"]                Check whois data for ANY specified term (OR logic)
  whois_server_mode: "random" or "cycle"      Server selection mode: random (default) or cycle through list
  whois_server: "whois.domain.com" or ["server1", "server2"]  Custom whois server(s) - single server or randomized list (default: system default)
  whois_max_retries: 2                       Maximum retry attempts per domain (default: 2)
  whois_timeout_multiplier: 1.5              Timeout increase multiplier per retry (default: 1.5)
  whois_use_fallback: true                   Add TLD-specific fallback servers (default: true)
  whois_retry_on_timeout: true               Retry on timeout errors (default: true)
  whois_retry_on_error: true                 Retry on connection/other errors (default: true)
  whois_delay: <milliseconds>                Delay between whois requests for this site (default: global whois_delay)
  dig: ["term1", "term2"]                     Check dig output for ALL specified terms (AND logic)
  dig-or: ["term1", "term2"]                  Check dig output for ANY specified term (OR logic)
  goto_options: {"waitUntil": "domcontentloaded"} Custom page.goto() options (default: {"waitUntil": "load"})
  dig_subdomain: true/false                    Use subdomain for dig lookup instead of root domain (default: false)
  digRecordType: "A"                          DNS record type for dig (default: A)

VPN Options (requires sudo, affects system routing — not isolated per-site during concurrent scans):
  vpn: "/etc/wireguard/wg0.conf"              WireGuard config file path
  vpn: { config: "wg-us", interface: "wg0",   WireGuard with options: health_check, test_host,
         health_check: true, retry: true }      retry, max_retries
  openvpn: "/path/to/server.ovpn"             OpenVPN config file path (uses embedded credentials)
  openvpn: { config: "server.ovpn",           OpenVPN with options: username, password,
             username: "user",                  auth_file, health_check, test_host, retry,
             password: "pass",                  max_retries, connect_timeout, extra_args
             health_check: true,
             retry: true,
             max_retries: 2,
             connect_timeout: 30000 }

  window_cleanup: true/false/"realtime"/"all"  Window cleanup mode:
                                               true/false - Close extra windows after URL group completes (default: false)
                                               "realtime" - Continuously cleanup oldest pages when threshold exceeded
                                               "all" - Aggressive cleanup of all content pages after group
  window_cleanup_threshold: <number>           For realtime mode: max pages to keep open (default: 8)

Referrer Header Options:
  referrer_headers: "https://google.com"       Single referrer URL
  referrer_headers: ["url1", "url2"]           Random selection from array  
  referrer_headers: {"mode": "random_search", "search_terms": ["term1"]} Smart search engine traffic
  referrer_headers: {"mode": "social_media"}   Random social media referrers
  referrer_headers: {"mode": "direct_navigation"} No referrer (direct access)
  referrer_headers: {"mode": "news_sites"}     Random news website referrers
  referrer_headers: {"mode": "custom", "url": "https://example.com"} Custom referrer URL
  referrer_headers: {"mode": "mixed"}          Mixed referrer types for varied traffic
  referrer_disable: ["https://example.com/no-ref", "sensitive-site.com"] Disable referrer for specific URLs
  custom_headers: {"Header": "Value"}          Additional HTTP headers
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
const { 
  sites = [], 
  ignoreDomains = [],
  ignoreDomainsByUrl = [],
  blockDomainsByUrl = [],
  blocked: globalBlocked = [],
  whois_delay = 3000, 
  whois_server_mode = 'random', 
  ignore_similar = true, 
  ignore_similar_threshold = 80, 
  ignore_similar_ignored_domains = true,
  disable_ad_tagging = true,
  max_concurrent_sites = 6,
  resource_cleanup_interval = 80,
  comments: globalComments,
  ...otherGlobalConfig
} = config;

// --validate-config runs here, after `config` and `sites` are populated.
// Previously this block lived above the config load and triggered a TDZ
// "Cannot access 'config' before initialization" error.
if (validateConfig) {
  console.log(`\n${messageColors.processing('Validating configuration file...')}`);
  try {
    const validation = validateFullConfig(config, { forceDebug, silentMode });

    // Validate referrer_headers format
    for (const site of sites) {
       if (site.referrer_headers && typeof site.referrer_headers === 'object' && !Array.isArray(site.referrer_headers)) {
         const refValidation = validateReferrerConfig(site.referrer_headers);
         if (!refValidation.isValid) {
           console.warn(`⚠ Invalid referrer_headers configuration: ${refValidation.errors.join(', ')}`);
         }
         if (refValidation.warnings.length > 0) {
           console.warn(`⚠ Referrer warnings: ${refValidation.warnings.join(', ')}`);
         }
       }
       // Validate referrer_disable format
       if (site.referrer_disable) {
         const disableValidation = validateReferrerDisable(site.referrer_disable);
         if (!disableValidation.isValid) {
           console.warn(`⚠ Invalid referrer_disable configuration: ${disableValidation.errors.join(', ')}`);
         }
         if (disableValidation.warnings.length > 0) {
           console.warn(`⚠ Referrer disable warnings: ${disableValidation.warnings.join(', ')}`);
         }
       }
    }

    // Validate VPN configurations
    for (const site of sites) {
      if (site.vpn) {
        const vpnNorm = normalizeVpnConfig(site.vpn);
        const vpnValidation = validateVpnConfig(vpnNorm);
        if (!vpnValidation.isValid) {
          console.warn(`⚠ Invalid vpn configuration for ${site.url}: ${vpnValidation.errors.join(', ')}`);
        }
        if (vpnValidation.warnings.length > 0) {
          vpnValidation.warnings.forEach(w => console.warn(`⚠ VPN warning for ${site.url}: ${w}`));
        }
      }
      if (site.openvpn) {
        const ovpnNorm = normalizeOvpnConfig(site.openvpn);
        const ovpnValidation = validateOvpnConfig(ovpnNorm);
        if (!ovpnValidation.isValid) {
          console.warn(`⚠ Invalid openvpn configuration for ${site.url}: ${ovpnValidation.errors.join(', ')}`);
        }
        if (ovpnValidation.warnings.length > 0) {
          ovpnValidation.warnings.forEach(w => console.warn(`⚠ OpenVPN warning for ${site.url}: ${w}`));
        }
      }
      if (site.vpn && site.openvpn) {
        console.warn(`⚠ ${site.url} has both vpn and openvpn configured — only one will be used (vpn takes precedence)`);
      }
    }

    if (validation.isValid) {
      console.log(`${messageColors.success('✅ Configuration is valid!')}`);
      console.log(`${messageColors.info('Summary:')} ${validation.summary.validSites}/${validation.summary.totalSites} sites valid`);
      if (validation.summary.sitesWithWarnings > 0) {
        console.log(`${messageColors.warn('⚠ Warnings:')} ${validation.summary.sitesWithWarnings} sites have warnings`);
      }
      process.exit(0);
    } else {
      console.log(`${messageColors.error('❌ Configuration validation failed!')}`);
      console.log(`${messageColors.error('Errors:')} ${validation.globalErrors.length} global, ${validation.summary.sitesWithErrors} site-specific`);
      process.exit(1);
    }
  } catch (validationErr) {
    console.error(`❌ Validation failed: ${validationErr.message}`);
    process.exit(1);
  }
}

// Pre-compile global blocked regexes ONCE (used in every processUrl call).
// Was: bare `.map(pattern => new RegExp(pattern))` which hard-threw at
// module load on a single bad pattern, killing scan startup. Helper now
// warns + skips so the rest of the config can still run.
const globalBlockedRegexes = compilePatternList('blocked (global)', globalBlocked);

// Cache compiled regexes by pattern string — avoids recompiling same patterns across URLs
const _compiledRegexCache = new Map();
function getCompiledRegex(pattern) {
  let compiled = _compiledRegexCache.get(pattern);
  if (!compiled) {
    compiled = new RegExp(pattern.replace(/^\/(.*)\/$/, '$1'));
    if (_compiledRegexCache.size > 2000) _compiledRegexCache.clear();
    _compiledRegexCache.set(pattern, compiled);
  }
  return compiled;
}
function getCompiledRegexes(patterns) {
  if (!patterns) return [];
  const arr = Array.isArray(patterns) ? patterns : [patterns];
  return arr.map(p => getCompiledRegex(p));
}

/**
 * Compile a list of regex pattern strings, WARNING loudly on any that fail
 * compilation instead of:
 *   (a) silently dropping them (old ignoreDomainsByUrl/blockDomainsByUrl
 *       behavior) -- made debugging "why isn't my pattern matching?"
 *       miserable, and
 *   (b) hard-throwing at module load (old `blocked` behavior) -- one bad
 *       pattern would kill the whole scan startup.
 *
 * Returns the array of successfully compiled regexes. Failed patterns are
 * skipped with a single warn line per failure naming the config key + the
 * source string + the regex error -- enough to find and fix without
 * grepping through diff history.
 *
 * @param {string} configKey - name of the config key, for warn context
 * @param {string[]} patterns - raw regex source strings
 * @param {(p:string)=>RegExp} [compile] - compile fn (defaults to new RegExp)
 * @returns {RegExp[]}
 */
function compilePatternList(configKey, patterns, compile = (p) => new RegExp(p)) {
  if (!Array.isArray(patterns)) return [];
  const out = [];
  for (const p of patterns) {
    try {
      out.push(compile(p));
    } catch (err) {
      console.warn(formatLogMessage('warn', `[config] ${configKey} pattern dropped (compile error): ${JSON.stringify(p)} -- ${err.message}`));
    }
  }
  return out;
}

// Per-pattern match counters for the `blocked` regex (site + global,
// combined). Keyed by RegExp.source so the same pattern appearing in both
// site and global lists rolls up into one row. Reported at scan end so
// stale patterns that match zero requests are easy to spot and prune.
const _blockedPatternHits = new Map();

// Pre-split ignoreDomains into exact Set (O(1) lookup) and wildcard array
const _ignoreDomainsExact = new Set();
const _ignoreDomainsWildcard = [];
for (const pattern of ignoreDomains) {
  if (pattern.includes('*')) {
    _ignoreDomainsWildcard.push(pattern);
  } else {
    _ignoreDomainsExact.add(pattern);
  }
}

// Compile ignoreDomainsByUrl patterns once — match request URLs to dynamically ignore domains.
// Bad patterns warn (via compilePatternList) instead of silently dropping.
const _ignoreDomainsByUrlRegexes = compilePatternList('ignoreDomainsByUrl', ignoreDomainsByUrl, getCompiledRegex);
// Runtime Set of domains marked ignored by URL pattern matches — shared across all sites in this scan
const _dynamicallyIgnoredDomains = new Set();

// blockDomainsByUrl: symmetric to ignoreDomainsByUrl but for active
// blocking via Puppeteer's request.abort(). When a request URL matches
// one of these regex patterns, the request's root domain is added to
// _dynamicallyBlockedDomains; subsequent requests on that domain (and
// its subdomains, via parent-walk in matchesDynamicBlock) get aborted
// before reaching the network. The triggering request itself is also
// aborted -- same "gate fires immediately after trigger" semantic the
// ignoreDomainsByUrl path uses for the dynamic Set short-circuit.
const _blockDomainsByUrlRegexes = compilePatternList('blockDomainsByUrl', blockDomainsByUrl, getCompiledRegex);
const _dynamicallyBlockedDomains = new Set();

// Apply global configuration overrides with validation
// Priority: Command line args > config.json > defaults
const MAX_CONCURRENT_SITES = (() => {
  // Check command line argument first
  if (maxConcurrentSites !== null) {
    if (maxConcurrentSites >= CONCURRENCY_LIMITS.MIN && maxConcurrentSites <= CONCURRENCY_LIMITS.MAX) {
      if (forceDebug) console.log(formatLogMessage('debug', `Using command line max_concurrent_sites: ${maxConcurrentSites}`));
      return maxConcurrentSites;
    } else {
      console.warn(`⚠ Invalid --max-concurrent value: ${maxConcurrentSites}. Must be ${CONCURRENCY_LIMITS.MIN}-${CONCURRENCY_LIMITS.MAX}. Using config/default value.`);
    }
  }
  
  // Check config.json value
  if (typeof max_concurrent_sites === 'number' && max_concurrent_sites >= CONCURRENCY_LIMITS.MIN && max_concurrent_sites <= CONCURRENCY_LIMITS.MAX) {
    if (forceDebug) console.log(formatLogMessage('debug', `Using config max_concurrent_sites: ${max_concurrent_sites}`));
    return max_concurrent_sites;
  } else if (max_concurrent_sites !== CONCURRENCY_LIMITS.DEFAULT) {
    console.warn(`⚠ Invalid config max_concurrent_sites value: ${max_concurrent_sites}. Using default: ${CONCURRENCY_LIMITS.DEFAULT}`);
  }
  
  // Use default
  return CONCURRENCY_LIMITS.DEFAULT;
})();

const RESOURCE_CLEANUP_INTERVAL = (() => {
  // Check command line argument first
  if (cleanupInterval !== null) {
    if (cleanupInterval > 0 && cleanupInterval <= 1000) {
      if (forceDebug) console.log(formatLogMessage('debug', `Using command line resource_cleanup_interval: ${cleanupInterval}`));
      return cleanupInterval;
    } else {
      console.warn(`⚠ Invalid --cleanup-interval value: ${cleanupInterval}. Must be 1-1000. Using config/default value.`);
    }
  }
  
  // Check config.json value
  if (typeof resource_cleanup_interval === 'number' && resource_cleanup_interval > 0 && resource_cleanup_interval <= 1000) {
    if (forceDebug) console.log(formatLogMessage('debug', `Using config resource_cleanup_interval: ${resource_cleanup_interval}`));
    return resource_cleanup_interval;
  } else if (resource_cleanup_interval !== 80) {
    console.warn(`⚠ Invalid config resource_cleanup_interval value: ${resource_cleanup_interval}. Using default: 80`);
  }
  
  // Use default
  return 80;
})();

// Perform cache clear after config is loaded for custom cache paths
if (clearCache && dryRunMode) {
  clearPersistentCache({
    silent: silentMode,
    forceDebug,
    cachePath: config.cache_path || '.cache'
  });
}

// Also clear for custom cache paths in normal mode if not already cleared
if (clearCache && !dryRunMode && config.cache_path && config.cache_path !== CACHE_LIMITS.DEFAULT_CACHE_PATH) {
  clearPersistentCache({
    silent: silentMode,
    forceDebug,
    cachePath: config.cache_path
  });
}

// Initialize smart cache system AFTER config is loaded (unless --ignore-cache is used)
if (ignoreCache) {
  smartCache = null;
  if (forceDebug) console.log(formatLogMessage('debug', 'Smart cache disabled by --ignore-cache flag'));
} else {
smartCache = createSmartCache({
  ...config,
  cache_requests: cacheRequests, // NEW: Pass request caching flag
  forceDebug,
  max_concurrent_sites: MAX_CONCURRENT_SITES,  // Pass concurrency info
  cache_aggressive_mode: MAX_CONCURRENT_SITES > CONCURRENCY_LIMITS.HIGH_CONCURRENCY_THRESHOLD,  // Auto-enable for high concurrency
  cache_persistence: false, // Disable persistence completely
  cache_autosave: false, // Disable auto-save completely
  cache_autosave_minutes: config.cache_autosave_minutes || 1,
  cache_max_size: config.cache_max_size || CACHE_LIMITS.DEFAULT_MAX_SIZE
});
}

// Add safe domain processing helper after smartCache initialization
function safeMarkDomainProcessed(domain, context, metadata) {
  if (smartCache) {
    try {
      if (typeof smartCache.markDomainProcessed === 'function') {
        smartCache.markDomainProcessed(domain, context, metadata);
      } else {
        // Fallback: trigger cache via shouldSkipDomain
        smartCache.shouldSkipDomain(domain, context);
      }
    } catch (cacheErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${SMART_CACHE_TAG} Error marking domain: ${cacheErr.message}`));
      }
    }
  }
}

// Global deduplication for nettools to avoid redundant lookups across all URLs
// Whois: keyed by root domain only (whois data is consistent for entire domain)
// Dig: keyed by specific subdomain+config (DNS records can vary by subdomain)
const globalProcessedWhoisDomains = new Set();
const globalProcessedDigDomains = new Set();

// Handle --clean-rules after config is loaded (so we have access to sites)
if (cleanRules || cleanRulesFile) {
  const filesToClean = cleanRulesFile ? [cleanRulesFile] : [outputFile, compareFile].filter(Boolean);
  
  if (filesToClean.length === 0) {
    console.error('❌ --clean-rules requires either a file argument or --output/--compare files to be specified');
    process.exit(1);
  }
  
  console.log(`\n${messageColors.processing('Cleaning rule files...')}`);
  let overallSuccess = true;
  let totalCleaned = 0;
  
  // Check if we're cleaning the same file we want to use for output
  const cleaningOutputFile = outputFile && filesToClean.includes(outputFile);
  
  if (cleaningOutputFile && forceDebug) {
    console.log(formatLogMessage('debug', `Output file detected: will clean ${outputFile} first, then continue with scan`));
  }
  
  for (const file of filesToClean) {
    console.log(`\n${messageColors.info('Cleaning:')} ${file}`);

    // Check if file exists before trying to clean it
    if (!fs.existsSync(file)) {
      if (file === outputFile) {
        // If it's the output file that doesn't exist, that's OK - we'll create it during scan
        const modeText = appendMode ? 'created (append mode)' : 'created';
        console.log(`${messageColors.info('📄 Note:')} Output file ${file} doesn't exist yet - will be ${modeText} during scan`);
        continue;
      } else {
        // For other files (like compare files), this is an error
        console.log(`${messageColors.error('❌ Failed:')} File not found: ${file}`);
        overallSuccess = false;
        continue;
      }
    }

    try {
      const cleanResult = cleanRulesetFile(file, null, { 
        forceDebug, 
        silentMode, 
        removeDuplicates: removeDupes,
        backupOriginal: true,
        dryRun: dryRunMode
      });
      
      if (cleanResult.success) {
        if (dryRunMode) {
          if (cleanResult.wouldModify) {
            console.log(`${messageColors.info('🔍 Dry run:')} Would remove ${cleanResult.stats.removed} lines (${cleanResult.stats.invalid} invalid, ${cleanResult.stats.duplicates} duplicates)`);
          } else {
            console.log(`${messageColors.success('✅ Dry run:')} File is already clean - no changes needed`);
          }
        } else {
          if (cleanResult.modified) {
            console.log(`${messageColors.success('✅ Cleaned:')} Removed ${cleanResult.stats.removed} lines, preserved ${cleanResult.stats.valid} valid rules`);
            if (cleanResult.backupCreated) {
              console.log(`${messageColors.info('💾 Backup:')} Original file backed up`);
            }
            totalCleaned += cleanResult.stats.removed;

            if (cleaningOutputFile && file === outputFile) {
              console.log(`${messageColors.info('📄 Note:')} File cleaned - new rules will be ${appendMode ? 'appended' : 'written'} during scan`);
            }
          } else {
            console.log(`${messageColors.success('✅ Clean:')} File was already valid - no changes needed`);
          }
        }
      } else {
        console.log(`${messageColors.error('❌ Failed:')} ${cleanResult.error}`);
        overallSuccess = false;
      }
    } catch (cleanErr) {
      console.error(`❌ Failed to clean ${file}: ${cleanErr.message}`);
      overallSuccess = false;
    }
  }
  
  // Determine if we should continue with scanning
  const shouldContinueScanning = sites && sites.length > 0 && outputFile;
  const cleanedOutputFileForScanning = outputFile && filesToClean.includes(outputFile);
  
  if (overallSuccess) {
    if (dryRunMode) {
      console.log(`\n${messageColors.info('🔍 Dry run completed successfully!')}`);
      process.exit(0);
    } else {
      console.log(`\n${messageColors.success('✅ All rule files cleaned successfully!')} Total lines removed: ${totalCleaned}`);
      
      // Continue with scan if we have sites to process and we cleaned the output file
      if (shouldContinueScanning && cleanedOutputFileForScanning) {
        const actionText = appendMode ? 'append new rules to' : 'write rules to';
        console.log(`${messageColors.info('📄 Continuing:')} Proceeding with scan to ${actionText} ${outputFile}`);
        // Don't exit - continue with scanning
      } else {
        process.exit(0);
      }
    }
  } else {
    console.log(`\n${messageColors.error('❌ Some rule files failed to clean!')}`);
    process.exit(1);
  }
}

// Track dry run output for file writing
let dryRunOutput = [];

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

// --- Buffered Log Writer ---
// Avoids blocking I/O on every intercepted request in debug/dumpurls mode
const _logBuffers = new Map();  // filePath -> string[]
const LOG_FLUSH_INTERVAL = 2000; // Flush every 2 seconds
let _logFlushTimer = null;

function bufferedLogWrite(filePath, entry) {
  if (!filePath) return;
  if (!_logBuffers.has(filePath)) {
    _logBuffers.set(filePath, []);
  }
  _logBuffers.get(filePath).push(entry);
}

function flushLogBuffers() {
  for (const [filePath, entries] of _logBuffers) {
    if (entries.length > 0) {
      try {
        const data = entries.join('');
        entries.length = 0; // Clear buffer immediately
        fs.writeFile(filePath, data, { flag: 'a' }, (err) => {
          if (err) {
            console.warn(formatLogMessage('warn', `Failed to flush log buffer to ${filePath}: ${err.message}`));
          }
        });
      } catch (err) {
        console.warn(formatLogMessage('warn', `Failed to flush log buffer to ${filePath}: ${err.message}`));
      }
    }
  }
}

// Synchronous flush for exit handlers — guarantees data is written before process exits
function flushLogBuffersSync() {
  for (const [filePath, entries] of _logBuffers) {
    if (entries.length > 0) {
      try {
        fs.appendFileSync(filePath, entries.join(''));
      } catch (err) { /* best effort on exit */ }
      entries.length = 0;
    }
  }
}

// Start periodic flush if any logging is enabled
if (forceDebug || dumpUrls) {
  _logFlushTimer = setInterval(flushLogBuffers, LOG_FLUSH_INTERVAL);
  _logFlushTimer.unref(); // Don't keep process alive just for flushing
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
const _rootDomainCache = new Map();
function getRootDomain(url) {
  const cached = _rootDomainCache.get(url);
  if (cached !== undefined) return cached;
  try {
    const { hostname } = new URL(url);
    const parsed = psl.parse(hostname);
    const result = parsed.domain || hostname;
    if (_rootDomainCache.size > 5000) _rootDomainCache.clear();
    _rootDomainCache.set(url, result);
    return result;
  } catch {
    _rootDomainCache.set(url, '');
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

/**
 * Checks if a URL matches any domain in the cdp_specific list
 * @param {string} url - The URL to check
 * @param {Array} cdpSpecificList - Array of domains that should have CDP enabled
 * @returns {boolean} True if URL matches a domain in the list
 */
function shouldEnableCDPForUrl(url, cdpSpecificList) {
  if (!cdpSpecificList || !Array.isArray(cdpSpecificList) || cdpSpecificList.length === 0) {
    return false;
  }
  
  try {
    const urlHostname = new URL(url).hostname;
    return cdpSpecificList.some(domain => {
      // Remove protocol if present and clean domain
      const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      // Match exact hostname or subdomain
      return urlHostname === cleanDomain || urlHostname.endsWith('.' + cleanDomain);
    });
  } catch (urlErr) {
    return false;
  }
}

/**
 * Helper function to check if a URL should be processed (valid HTTP/HTTPS)
 * @param {string} url - URL to validate
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {boolean} True if URL is valid for processing
 */
function shouldProcessUrl(url, forceDebug) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (err) {
    if (forceDebug) console.log(formatLogMessage('debug', `Invalid URL for processing: ${url}`));
    return false;
  }
}

/**
 * Check if URL should bypass all caching for this site
 * @param {string} url - URL to check
 * @param {Object} siteConfig - Site configuration
 * @returns {boolean} True if should bypass cache
 */
function shouldBypassCacheForUrl(url, siteConfig) {
  return siteConfig.bypass_cache === true;
}

// ability to use wildcards in ignoreDomains
// Cache compiled wildcard regexes to avoid recompilation on every request
const _wildcardRegexCache = new Map();

// Generic parent-walk helper: returns true if `domain` or any of its
// parents (one label at a time, up to the TLD) is present in `set`.
// Mirrors the static/dynamic parent-walk inside matchesIgnoreDomain but
// usable against an arbitrary single Set -- consumed by
// matchesDynamicBlock below. matchesIgnoreDomain keeps its inline
// dual-Set probe so the hot path stays single-split, but new single-Set
// consumers (block, future similar features) share this helper.
function _domainOrParentInSet(set, domain) {
  if (set.size === 0) return false;
  if (set.has(domain)) return true;
  const parts = domain.split('.');
  for (let i = 1; i < parts.length; i++) {
    if (set.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

/**
 * Block-side counterpart to the ignore gate. Returns true if `domain`
 * (or any of its parents) has been added to _dynamicallyBlockedDomains
 * by an earlier blockDomainsByUrl pattern match. Called per-request to
 * decide whether to request.abort() before the static blocked-regex
 * check fires.
 */
function matchesDynamicBlock(domain) {
  return _domainOrParentInSet(_dynamicallyBlockedDomains, domain);
}

function matchesIgnoreDomain(domain, ignorePatterns) {
  // Both dynamic and static ignore lists are walked parent-by-parent so a
  // subdomain of an ignored root inherits the ignore. Previously the
  // dynamic check was exact-only, creating an asymmetry: a static-config
  // `example.com` ignored cdn.example.com transitively, but a runtime
  // ignoreDomainsByUrl match for the same root (stored as root via
  // checkedRootDomain at line ~2993) did NOT cascade -- subdomains slipped
  // through to dig/whois/regex despite the root being ignored. Now
  // unified: parts split once, shared between both Set probes.
  const hasDynamic = _dynamicallyIgnoredDomains.size > 0;
  const hasExact   = _ignoreDomainsExact.size > 0;

  if (hasDynamic || hasExact) {
    // Exact-domain hit on either set wins early.
    if (hasDynamic && _dynamicallyIgnoredDomains.has(domain)) return true;
    if (hasExact   && _ignoreDomainsExact.has(domain))         return true;

    // Parent-walk: sub.ads.example.com → ads.example.com → example.com
    const parts = domain.split('.');
    for (let i = 1; i < parts.length; i++) {
      const parent = parts.slice(i).join('.');
      if (hasDynamic && _dynamicallyIgnoredDomains.has(parent)) return true;
      if (hasExact   && _ignoreDomainsExact.has(parent))         return true;
    }
  }

  // Slow path: wildcard patterns only
  const wildcards = _ignoreDomainsWildcard;
  const len = wildcards.length;
  for (let i = 0; i < len; i++) {
    const pattern = wildcards[i];
    let compiled = _wildcardRegexCache.get(pattern);
    if (!compiled) {
      const regexPattern = pattern
        .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        .replace(/\\\*/g, '.*');
      compiled = new RegExp(`^${regexPattern}$`);
      _wildcardRegexCache.set(pattern, compiled);
    }
    if (compiled.test(domain)) return true;
  }
  return false;
}

function setupFrameHandling(page, forceDebug) {
  // Track active frames and clear on navigation to prevent detached frame access
  let activeFrames = new Set(); // Use Set to track frame references
  
  // Handle frame creation with error suppression
  page.on('frameattached', async (frame) => {
    // Enhanced frame handling with detached frame protection
    try {
      // Test frame accessibility first with safe method
      let isFrameValid = false;
      try {
        frame.url(); // This will throw if frame is detached
        isFrameValid = true;
      } catch (e) {
        return; // Frame is already detached, skip
      }

      // Multiple checks for frame validity to prevent detached frame errors
      if (!frame) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Skipping null frame`));
        }
        return;
      }
      
      // Enhanced frame validation with multiple safety checks
      let frameUrl;
      try {
        frameUrl = frame.url();
        
        // Check if frame is detached (if method exists)
        if (frame.isDetached && frame.isDetached()) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Skipping detached frame`));
          }
          return;
        }
        
        activeFrames.add(frame);
        
        if (forceDebug) {
          console.log(formatLogMessage('debug', `New frame attached: ${frameUrl || 'about:blank'}`));
        }
      } catch (frameAccessError) {
        // Frame is not accessible (likely detached)
        return;
      }

    } catch (detachError) {
      // Frame state checking can throw in 23.x, handle gracefully
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Frame state check failed: ${detachError.message}`));
      }
      return;
    }

    
    if (frame !== page.mainFrame() && frame.parentFrame()) { // Only handle child frames
      let frameUrl;
        frameUrl = frame.url();
        
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
        
        try {        
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
  // Handle frame navigations - clear stale tracking and monitor activity
  page.on('framenavigated', (frame) => {

    // Main frame navigated - clear all tracked frames to prevent stale references
    if (frame === page.mainFrame()) {
      activeFrames.clear();
      return;
    }

    // Skip child frames not in our active set
    if (!activeFrames.has(frame)) return;

    let frameUrl;
    try {
      frameUrl = frame.url();
    } catch (urlErr) {
      // Frame likely detached during navigation
      return;
    }
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
    // Remove from active tracking
    activeFrames.delete(frame); // This works for both Map and Set
    

    if (forceDebug) {
      let frameUrl;
      try {
        frameUrl = frame.url();

      if (frameUrl &&
          frameUrl !== 'about:blank' &&
          frameUrl !== 'about:srcdoc' &&
          !frameUrl.startsWith('about:') &&
          !frameUrl.startsWith('chrome-error://') &&
          !frameUrl.startsWith('chrome-extension://')) {
        console.log(formatLogMessage('debug', `Frame detached: ${frameUrl}`));
      }
      } catch (urlErr) {
        // Frame already detached, can't get URL - this is expected
        return;
      }

    }
  });
}

// --- Main Asynchronous IIFE (Immediately Invoked Function Expression) ---
// This is the main entry point and execution block for the network scanner script.
(async () => {

  // Declare userDataDir in outer scope for cleanup access
  let userDataDir = null;
  
  /**
   * Creates a new browser instance with consistent configuration
   * Uses system Chrome and temporary directories to minimize disk usage
   * @returns {Promise<import('puppeteer').Browser>} Browser instance
   */
  async function createBrowser(extraArgs = []) {
    // Obscura mode: connect to a running Obscura CDP server instead of launching Chrome
    if (useObscura) {
      const obscuraEndpoint = process.env.OBSCURA_WS || 'ws://127.0.0.1:9222/devtools/browser';
      if (forceDebug) console.log(formatLogMessage('debug', `Connecting to Obscura at ${obscuraEndpoint}`));
      try {
        const browser = await puppeteer.connect({ browserWSEndpoint: obscuraEndpoint });
        if (!silentMode) console.log(messageColors.success(`Connected to Obscura CDP at ${obscuraEndpoint}`));
        browser._nwssUserDataDir = null; // No temp dir to clean
        browser._nwssIsObscura = true;
        return browser;
      } catch (err) {
        console.error(formatLogMessage('error', `Failed to connect to Obscura: ${err.message}`));
        console.error(formatLogMessage('error', `Start Obscura first: obscura serve --port 9222 --stealth`));
        process.exit(1);
      }
    }

    // Create temporary user data directory that we can fully control and clean up
    const tempUserDataDir = path.join(os.tmpdir(), `puppeteer-${Date.now()}-${Math.random().toString(36).substring(7)}`);
    userDataDir = tempUserDataDir; // Store for cleanup tracking (use outer scope variable)

    // Try to find system Chrome installation to avoid Puppeteer downloads

    // Detect Puppeteer version for headless mode compatibility
    let headlessMode = launchHeadless;
    if (launchHeadless) {
      const puppeteerInfo = detectPuppeteerVersion();
      
      // Check if any site needs fingerprint protection — use stealth-friendly headless mode
      const needsStealth = sites.some(site => site.fingerprint_protection);
      
      if (puppeteerInfo.useShellMode) {
        if (needsStealth) {
          headlessMode = 'new'; // Full Chrome in headless — harder to detect than chrome-headless-shell
          if (forceDebug) console.log(formatLogMessage('debug', `Using headless=new for stealth (fingerprint_protection detected)`));
        } else {
          headlessMode = 'shell'; // Use fast chrome-headless-shell for 22.x+
          if (forceDebug) console.log(formatLogMessage('debug', `Using chrome-headless-shell (Puppeteer ${puppeteerInfo.version || 'v' + puppeteerInfo.majorVersion + '.x'})`));
        }
      } else {
        headlessMode = true; // Use regular headless for older versions
        if (forceDebug) console.log(formatLogMessage('debug', 'Could not detect Puppeteer version, using regular headless mode'));
      }
    } else {
      headlessMode = false; // Headful mode
    }

    const systemChromePaths = [
      // Linux / WSL
      '/usr/bin/google-chrome-stable',
      '/usr/bin/google-chrome',
      '/usr/bin/chromium-browser',
      '/usr/bin/chromium',
      '/snap/bin/chromium',
      // macOS
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium'
    ];
    // V8 Optimization: Freeze the Chrome paths array since it's constant
    Object.freeze(systemChromePaths);


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
    if (usePuppeteerCore && !executablePath) {
      console.error(formatLogMessage('error', '--use-puppeteer-core requires a system Chrome installation. No Chrome found in standard paths.'));
      process.exit(1);
    }
    const browser = await puppeteer.launch({
      // Use system Chrome if available to avoid downloads
      executablePath: executablePath,
      // Force temporary user data directory for complete cleanup control
      userDataDir: tempUserDataDir,
      // Puppeteer 22.x headless mode optimization
      // Auto-detect best headless mode based on Puppeteer version
      headless: headlessMode,
      args: [
        // CRITICAL: Remove automation detection markers
        '--disable-blink-features=AutomationControlled',
        '--no-first-run',
        '--disable-default-apps',
        ...(keepBrowserOpen ? [] : ['--disable-component-extensions-with-background-pages']),
        // HIGH IMPACT: Normal Chrome behavior simulation
        '--password-store=basic',
        '--use-mock-keychain',
        '--disable-client-side-phishing-detection',
        '--enable-features=NetworkService',
        // Disk space controls - minimal cache for scanning workloads
        `--disk-cache-size=${CACHE_LIMITS.DISK_CACHE_SIZE}`,
        `--media-cache-size=${CACHE_LIMITS.MEDIA_CACHE_SIZE}`,
        '--disable-application-cache',
        '--disable-offline-load-stale-cache',
        '--disable-background-downloads',
        // DISK I/O REDUCTION: Eliminate unnecessary Chrome disk writes
        '--disable-breakpad',          // No crash dump files
        ...(keepBrowserOpen ? [] : ['--disable-component-update']),  // No component update downloads
        '--disable-logging',           // No Chrome internal log files
        '--log-level=3',               // Fatal errors only (suppresses verbose disk logging)
        '--no-service-autorun',        // No background service disk activity
        '--disable-domain-reliability', // No reliability monitor disk writes
        // PERFORMANCE: Disable non-essential Chrome features in a single flag
        // IMPORTANT: Chrome only reads the LAST --disable-features flag, so combine all into one
        // AccountConsistencyMirror + AccountConsistencyDice prevent the
        // Chrome sign-in subsystem from initialising at startup. Combined
        // with --disable-sync + --allow-browser-signin=false below, this
        // suppresses the "Something went wrong when opening your profile"
        // popup that fires in headful + --keep-open mode (temp userDataDir
        // has no real profile, so the sync init errors out and pops up).
        `--disable-features=AudioServiceOutOfProcess,VizDisplayCompositor,TranslateUI,BlinkGenPropertyTrees,Translate,BackForwardCache,AcceptCHFrame,SafeBrowsing,HttpsFirstBalancedModeAutoEnable,site-per-process,PaintHolding,AccountConsistencyMirror,AccountConsistencyDice${disable_ad_tagging ? ',AdTagging' : ''}`,
        '--disable-ipc-flooding-protection',
        '--aggressive-cache-discard',
        '--memory-pressure-off',
        '--max_old_space_size=2048',   // V8 heap limit
        '--disable-prompt-on-repost',  // Fixes form popup on page reload
        ...(keepBrowserOpen ? [] : ['--disable-background-networking']),
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        // --disable-sync is always-on (was previously dropped in --keep-open
        // mode, which let the sync subsystem init against our temp
        // userDataDir and pop the "Something went wrong when opening your
        // profile" dialog). Inspection during --keep-open doesn't need
        // sync; nothing in the scanner flow does.
        '--disable-sync',
        // Prevent the sign-in promo / account banner from appearing in
        // headful sessions. Same family of fixes as --disable-sync and the
        // AccountConsistency* features disabled above.
        '--allow-browser-signin=false',
        '--mute-audio',
        '--disable-translate',
        '--window-size=1920,1080',
        ...(keepBrowserOpen ? [] : ['--disable-extensions', '--disable-component-update']),
        ...(loadExtensionPaths.length ? [`--load-extension=${loadExtensionPaths.join(',')}`, '--enable-extensions'] : []),
        '--no-default-browser-check',
        '--safebrowsing-disable-auto-update',
        '--ignore-ssl-errors',
        '--ignore-certificate-errors',
        '--ignore-certificate-errors-spki-list',
        '--ignore-certificate-errors-ca-list',
        '--disable-web-security',
        '--allow-running-insecure-content',
        // Puppeteer 23.x: Enhanced performance and stability args
        '--disable-renderer-backgrounding',
        '--disable-backgrounding-occluded-windows',
        '--disable-background-timer-throttling',
        '--no-zygote', // Better process isolation
        // PERFORMANCE: Process and memory reduction for high concurrency
        '--renderer-process-limit=10',  // Cap renderer processes (default: unlimited)
        '--disable-accelerated-2d-canvas', // Software canvas only (we spoof it anyway)
        '--disable-hang-monitor',      // Remove per-renderer hang check overhead
        '--js-flags=--max-old-space-size=512', // Cap V8 heap per renderer to 512MB
        ...extraArgs,
        ],
        // Optimized timeouts for Puppeteer 23.x performance
        protocolTimeout: TIMEOUTS.PROTOCOL_TIMEOUT,
        slowMo: 0, // No artificial delays
        defaultViewport: null, // Use system default viewport
        ignoreDefaultArgs: ['--enable-automation', '--enable-blink-features=AutomationControlled'] // Avoid automation detection
    });
    
    // Store the user data directory on the browser object for cleanup
    browser._nwssUserDataDir = tempUserDataDir;
    return browser;
   }


  const pLimit = (await import('p-limit')).default;
  const limit = pLimit(MAX_CONCURRENT_SITES);

  const perSiteHeadful = sites.some(site => site.headful === true);
  const launchHeadless = !(headfulMode || perSiteHeadful);
  // launch with no safe browsing
  let browser = await createBrowser();
  if (forceDebug) console.log(formatLogMessage('debug', `Launching browser with headless: ${launchHeadless}`));
  
  // Enhanced browser validation for Puppeteer 23.x
  try {
    const browserVersion = await browser.version();
    if (forceDebug) console.log(formatLogMessage('debug', `Browser launched successfully: ${browserVersion}`));
  } catch (versionError) {
    console.error(formatLogMessage('error', `Browser version check failed: ${versionError.message}`));
    throw new Error(`Browser startup validation failed: ${versionError.message}`);
  }

  // Log which headless mode is being used
  if (forceDebug && launchHeadless) {
    const needsStealth = sites.some(site => site.fingerprint_protection);
    const modeLabel = needsStealth ? 'headless=new (stealth mode)' : 'chrome-headless-shell (performance mode)';
    console.log(formatLogMessage('debug', `Using ${modeLabel}`));
  }

  // Initial cleanup of any existing Chrome temp files - always comprehensive on startup
  if (forceDebug) console.log(formatLogMessage('debug', 'Cleaning up any leftover temp files from previous runs...'));
  await cleanupChromeTempFiles({ 
    includeSnapTemp: true,  // Always clean snap dirs on startup
    forceDebug,
    comprehensive: true     // Always comprehensive on startup to clean leftovers
  });

  // Set up cleanup on process termination
  process.on('SIGINT', async () => {
    if (forceDebug) console.log(formatLogMessage('debug', 'SIGINT received, performing cleanup...'));
    flushLogBuffersSync();
    if (_logFlushTimer) clearInterval(_logFlushTimer);
    await performEmergencyCleanup();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    if (forceDebug) console.log(formatLogMessage('debug', 'SIGTERM received, performing cleanup...'));
    flushLogBuffersSync();
    if (_logFlushTimer) clearInterval(_logFlushTimer);
    await performEmergencyCleanup();
    process.exit(0);
  });

  // Emergency cleanup function
  async function performEmergencyCleanup() {
    try {
      if (browser && !browser.process()?.killed) {
        await handleBrowserExit(browser, {
          forceDebug,
          timeout: 5000,
          exitOnFailure: false,
          cleanTempFiles: true,
          comprehensiveCleanup: true,  // Always comprehensive on emergency
          userDataDir: browser._nwssUserDataDir
        });
      } else {
        // Browser already dead, just clean temp files
        await cleanupChromeTempFiles({ 
          includeSnapTemp: true, 
          forceDebug,
          comprehensive: true 
        });
      }
    } catch (emergencyErr) {
      if (forceDebug) console.log(formatLogMessage('debug', `Emergency cleanup failed: ${emergencyErr.message}`));
    }
    wgDisconnectAll(forceDebug);
    ovpnDisconnectAll(forceDebug);
    cleanupCloudflareCache();
    try { await closeAllSocksRelays(forceDebug); } catch (_) {}
  }
 
  let siteCounter = 0;
  // totalUrls now calculated from allTasks.length after URL flattening

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
    // Preserve the original URL (before any redirect) for output display
    const originalRequestedUrl = currentUrl;
    // Track regex patterns that produced matches (for title comments in output)
    const matchedRegexPatterns = new Set();
    // V8 Optimization: Single destructuring to avoid multiple property lookups
    const {
      firstParty,
      thirdParty,
      subDomains,
      localhost,
      cloudflare_phish,
      cloudflare_bypass,
      flowproxy_detection,
      privoxy,
      pihole,
      even_blocked,
      comments,
      bypass_cache
    } = siteConfig;
    
    const allowFirstParty = firstParty === true || firstParty === 1;
    const allowThirdParty = thirdParty === undefined || thirdParty === true || thirdParty === 1;
    const perSiteSubDomains = subDomains === 1 ? true : subDomainsMode;
    const siteLocalhostIP = localhost || null;
    const cloudflarePhishBypass = cloudflare_phish === true;
    const cloudflareBypass = cloudflare_bypass === true;
    // Add redirect and same-page loop protection
    const MAX_REDIRECT_DEPTH = siteConfig.max_redirects || 10;
    const redirectHistory = new Set();
    let redirectCount = 0;
    const pageLoadHistory = new Map(); // Track same-page reloads
    const MAX_SAME_PAGE_LOADS = 3;
    let currentPageUrl = currentUrl;

    const sitePrivoxy = privoxy === true;
    const sitePihole = pihole === true;
    const flowproxyDetection = flowproxy_detection === true;
    
    const evenBlocked = even_blocked === true;
    // Log site-level comments if debug mode is enabled
    if (forceDebug && comments) {
      const siteComments = Array.isArray(comments) ? comments : [comments];
      console.log(formatLogMessage('debug', `Site comments for ${currentUrl}: ${siteComments.length} item(s)`));
      siteComments.forEach((comment, idx) => 
        console.log(formatLogMessage('debug', `  Site comment ${idx + 1}: ${comment}`))
      );
    }

   // Log bypass_cache setting if enabled
   if (forceDebug && bypass_cache === true) {
     console.log(formatLogMessage('debug', `Cache bypass enabled for all URLs in site: ${currentUrl}`));
   }

    if (firstParty === 0 && thirdParty === 0) {
      console.warn(`⚠ Skipping ${currentUrl} because both firstParty and thirdParty are disabled.`);
      return { url: currentUrl, rules: [], success: false, skipped: true };
    }

    // Determine CDP enablement based on cdp_specific or traditional cdp setting
    let shouldEnableCDPForThisUrl = false;
    if (siteConfig.cdp === true) {
      // If cdp: true is set, enable CDP for all URLs and ignore cdp_specific
      shouldEnableCDPForThisUrl = true;
      if (forceDebug && siteConfig.cdp_specific) {
        console.log(formatLogMessage('debug', `CDP enabled for all URLs via cdp: true - ignoring cdp_specific for ${currentUrl}`));
      }
    } else if (siteConfig.cdp_specific && Array.isArray(siteConfig.cdp_specific)) {
      // Only use cdp_specific if cdp is not explicitly set to true
      shouldEnableCDPForThisUrl = shouldEnableCDPForUrl(currentUrl, siteConfig.cdp_specific);
      if (forceDebug && shouldEnableCDPForThisUrl) {
        console.log(formatLogMessage('debug', `CDP enabled for ${currentUrl} via cdp_specific domain match`));
      }
    } else {
      shouldEnableCDPForThisUrl = false;
    }

    let page = null;
    let cdpSession = null;
    let cdpSessionManager = null;
    // Use Map to track domains and their resource types for --adblock-rules or --dry-run
    const matchedDomains = (adblockRulesMode || siteConfig.adblock_rules || dryRunMode) ? new Map() : new Set();

    // Per-URL tracking of in-flight async nettools (dig/whois) handlers so we
    // can drain them BEFORE snapshotting matchedDomains into the result. The
    // previous fire-and-forget setImmediate pattern dropped late-completing
    // matches (handler resolved after formatRules had already run). Each
    // setImmediate-scheduled handler now registers a promise via
    // trackNetToolsHandler; drainPendingNetTools() awaits all of them with a
    // hard cap (TIMEOUTS.NETTOOLS_DRAIN_TIMEOUT) so a hung dig can't block.
    const pendingNetTools = [];
    const trackNetToolsHandler = (handlerFn) => {
      pendingNetTools.push(new Promise((resolve) => {
        setImmediate(async () => {
          try { await handlerFn(); } catch (_) { /* handler logs its own errors */ }
          finally { resolve(); }
        });
      }));
    };
    const drainPendingNetTools = async () => {
      if (pendingNetTools.length === 0) return;
      await Promise.race([
        Promise.all(pendingNetTools),
        fastTimeout(TIMEOUTS.NETTOOLS_DRAIN_TIMEOUT)
      ]);
    };

    // Local domain dedup scoped to THIS processUrl call only
    // Prevents cross-config contamination from the global domain cache
    const localDetectedDomains = new Set();
    const isLocallyDetected = (domain) => localDetectedDomains.has(domain);
    
    // Initialize dry run matches collection
    if (dryRunMode) {
      initializeDryRunCollections(matchedDomains);
    }
    const timeout = siteConfig.timeout || TIMEOUTS.DEFAULT_PAGE;

    if (!silentMode) console.log(`\n${messageColors.scanning('Scanning:')} ${currentUrl}`);

    // Track ALL domains that should be considered first-party (original + redirects)
    const firstPartyDomains = new Set();
    const originalRootDomain = safeGetDomain(currentUrl, false);
    if (originalRootDomain) {
      firstPartyDomains.add(originalRootDomain);
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Initial first-party domain: ${originalRootDomain} for ${currentUrl}`));
      }
    } 

    // Track redirect domains to exclude from matching
    let redirectDomainsToExclude = [];
    
    // Track the effective current URL and final URL for first-party detection (updates after redirects)
    let effectiveCurrentUrl = currentUrl;
    let finalUrlAfterRedirect = null;

    // Enhanced error types for Puppeteer 23.x compatibility
    const CRITICAL_BROWSER_ERRORS = Object.freeze([
      'Protocol error',
      'Target closed',
      'Browser has been closed',
      'Browser protocol broken',
      'Browser process exited',
      'Browser disconnected'
    ]);

    // Popup-capture cleanup registry — declared outside the try so the
    // finally block (which is a separate lexical scope from try) can see
    // it. Populated by the capture_popups setup block if siteConfig
    // .capture_popups is true; iterated in finally to deregister the
    // browser 'targetcreated' listener and close any tracked popup pages.
    const popupCleanups = [];
    // Race-window guard: 'targetcreated' fires synchronously, but
    // onTargetCreated does an `await target.page()`. If a popup target
    // is created right as the per-URL try block winds down, the await
    // can resolve AFTER finally has already iterated popupCleanups —
    // leaving the popup unregistered for manual cleanup (it still gets
    // closed by its own 3s auto-close timer, but in the meantime its
    // request listener could capture matches into matchedDomains for a
    // URL that already "finished"). The flag is set in finally and
    // checked at the start of onTargetCreated to short-circuit late
    // events cleanly.
    let urlFinished = false;

    try {

      // --- Connect VPN if configured for this site ---
      if (siteConfig.vpn) {
        const vpnResult = await wgConnect(siteConfig, forceDebug);
        if (!vpnResult.success) {
          console.warn(formatLogMessage('warn', `${VPN_TAG} WireGuard failed for ${currentUrl}: ${vpnResult.error}`));
          return { url: currentUrl, rules: [], success: false, vpnFailed: true };
        }
        if (!silentMode) {
          const ipInfo = vpnResult.externalIP ? ` (${vpnResult.externalIP})` : '';
          console.log(formatLogMessage('info', `${VPN_TAG} WireGuard connected via ${vpnResult.interface}${ipInfo} for ${currentUrl}`));
        }
      } else if (siteConfig.openvpn) {
        const ovpnResult = await ovpnConnect(siteConfig, forceDebug);
        if (!ovpnResult.success) {
          console.warn(formatLogMessage('warn', `${VPN_TAG} OpenVPN failed for ${currentUrl}: ${ovpnResult.error}`));
          return { url: currentUrl, rules: [], success: false, vpnFailed: true };
        }
        if (!silentMode) {
          const ipInfo = ovpnResult.externalIP ? ` (${ovpnResult.externalIP})` : '';
          console.log(formatLogMessage('info', `${VPN_TAG} OpenVPN connected via ${ovpnResult.connection}${ipInfo} for ${currentUrl}`));
        }
      }

      // Check for Protocol timeout errors that indicate browser is broken
      if (browserInstance.process() && browserInstance.process().killed) {
        throw new Error('Browser process was killed - restart required');
      }
      page = await createPageWithTimeout(browserInstance, 30000);

      // Enhanced page validation for Puppeteer 23.x
      if (!page || page.isClosed()) {
        throw new Error('Failed to create valid page instance');
      }

      // Track page for realtime cleanup
      trackPageForRealtime(page);

      // Mark page as actively processing
      updatePageUsage(page, true);

      // Perform realtime cleanup if enabled
      if (siteConfig.window_cleanup === "realtime") {
        const threshold = typeof siteConfig.window_cleanup_threshold === 'number' 
          ? siteConfig.window_cleanup_threshold 
          : REALTIME_CLEANUP_THRESHOLD;
        
        // Calculate appropriate delay based on site configuration
        const siteDelay = siteConfig.delay || 4000;
        const hasCloudflareConfig = siteConfig.cloudflare_bypass || siteConfig.cloudflare_phish;
        const bufferTime = hasCloudflareConfig ? 23000 : REALTIME_CLEANUP_BUFFER_MS; // 23s for Cloudflare, 15s for normal
        const totalDelay = siteDelay + bufferTime;
        
        if (forceDebug && hasCloudflareConfig) {
          console.log(formatLogMessage('debug', `${REALTIME_CLEANUP_TAG} Using extended delay for Cloudflare site: ${totalDelay}ms (${siteDelay}ms + ${bufferTime}ms CF buffer)`));
        }
        
        const realtimeResult = await performRealtimeWindowCleanup(browserInstance, threshold, forceDebug, totalDelay);
        if (realtimeResult.success && realtimeResult.closedCount > 0 && forceDebug) {
          console.log(formatLogMessage('debug', `${REALTIME_CLEANUP_TAG} Cleaned ${realtimeResult.closedCount} old pages, ${realtimeResult.remainingPages} remaining`));
        }
      } 
    
      // Set aggressive timeouts for problematic operations
      // Optimized timeouts for Puppeteer 23.x responsiveness
      page.setDefaultTimeout(Math.min(timeout, TIMEOUTS.DEFAULT_PAGE_REDUCED));
      page.setDefaultNavigationTimeout(Math.min(timeout, TIMEOUTS.DEFAULT_NAVIGATION));
      // Aggressive timeouts prevent hanging in Puppeteer 23.x while maintaining speed
      
      page.on('console', (msg) => {
        if (forceDebug && msg.type() === 'error') console.log(formatLogMessage('debug', `Console error: ${msg.text()}`));
      });
      
      // Add page crash handler
      page.on('error', (err) => {
        if (forceDebug) console.log(formatLogMessage('debug', `Page crashed: ${err.message}`));
        // Don't throw here as it might cause hanging - let the timeout handle it
      });
      
      // Enhanced error handling for Puppeteer 23.x
      page.on('pageerror', (err) => {
        // Safe error message extraction for Puppeteer 23.x compatibility
        const getErrorMessage = (error) => {
          if (!error) return 'Unknown error';
          if (typeof error === 'string') return error;
          if (error.message) return error.message;
          if (error.toString && typeof error.toString === 'function') {
            try {
              return error.toString();
            } catch (toStringErr) {
              return 'Error object toString failed';
            }
          }
          return JSON.stringify(error) || 'Unparseable error object';
        };
        
        const errorMessage = getErrorMessage(err);
        
        // Handle specific service worker errors
        if (errorMessage.includes('ServiceWorker') || 
            errorMessage.includes('service worker') ||
            errorMessage.includes('TCPusher service worker') ||
            errorMessage.includes('failed to register')) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Service worker error suppressed: ${errorMessage}`));
          }
          // Don't propagate service worker errors
          return;
        }
        
        // Handle network-related service worker errors
        if (errorMessage.includes('TypeError: failed to register') ||
            errorMessage.includes('SecurityError') ||
            errorMessage.includes('The operation is insecure')) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Registration security error suppressed: ${errorMessage}`));
          }
          return;
        }
        
        // Log other page errors normally
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Page JavaScript error: ${errorMessage}`));
        }
      });
      
      // Apply flowProxy timeouts if detection is enabled
      if (flowproxyDetection) {
        const flowproxyTimeouts = getFlowProxyTimeouts(siteConfig);
        page.setDefaultTimeout(Math.min(flowproxyTimeouts.pageTimeout, TIMEOUTS.DEFAULT_NAVIGATION));
        page.setDefaultNavigationTimeout(Math.min(flowproxyTimeouts.navigationTimeout, TIMEOUTS.DEFAULT_PAGE));
        // Attach the response/header listener BEFORE navigation so the
        // document response's own headers (Server, Set-Cookie, X-FlowProxy-*,
        // etc.) are observed. The listener accumulates state in a WeakMap
        // keyed by page; analyzeFlowProxyProtection reads from it later.
        attachFlowProxyHeaderListener(page);
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Applied flowProxy timeouts - page: ${flowproxyTimeouts.pageTimeout}ms, nav: ${flowproxyTimeouts.navigationTimeout}ms`));
        }
      }

      // --- START: evaluateOnNewDocument for Fetch/XHR Interception (Moved and Fixed) ---
      // This script is injected if --eval-on-doc is used or siteConfig.evaluateOnNewDocument is true.
      const shouldInjectEvalForPage = siteConfig.evaluateOnNewDocument === true || globalEvalOnDoc;
      let evalOnDocSuccess = false; // Track injection success for fallback logic
      
      // PREVENT realtime cleanup during injection to avoid "Session closed" errors
      if (shouldInjectEvalForPage && siteConfig.window_cleanup === "realtime") {
          updatePageUsage(page, true); // Mark page as actively processing BEFORE injection
      }

      if (shouldInjectEvalForPage) {
          if (forceDebug) {
              if (globalEvalOnDoc) {
                  console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Global Fetch/XHR interception enabled, applying to: ${currentUrl}`));
              } else { // siteConfig.evaluateOnNewDocument must be true
                  console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Site-specific Fetch/XHR interception enabled for: ${currentUrl}`));
              }
          }
          
          // Strategy 1: Try full injection with health check
          let browserResponsive = false;
          try {
              // Check if browser is still connected before attempting health check
              if (!browserInstance.connected) {
                  throw new Error('Browser not connected');
              }

              await Promise.race([
                  browserInstance.pages(), // Simple existence check that doesn't require active session
                  new Promise((_, reject) => 
                      setTimeout(() => reject(new Error('Browser health check timeout')), 3000)
                  )
              ]);
              browserResponsive = true;
          } catch (healthErr) {
              if (forceDebug) {
                  console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Browser health check failed: ${healthErr.message}`));
              }
              browserResponsive = false;
          }
          
          // Strategy 2: Try injection with reduced complexity if browser is responsive
          if (browserResponsive) {
              try {
                  // Add comprehensive timeout protection for evaluateOnNewDocument
                  await Promise.race([
                      // Main injection with all safety checks
                      page.evaluateOnNewDocument(() => {
                          // Prevent duplicate injections
                          if (window.__nwss_injection_applied) {
                              console.log('[evalOnDoc] Already injected, skipping');
                              return;
                          }
                          window.__nwss_injection_applied = true;

                          // Wrap everything in try-catch to prevent page crashes
                          try {
                              // Add timeout check within the injection
                              const injectionTimeout = setTimeout(() => {
                                  console.log('[evalOnDoc] Injection taking too long, aborting');
                              }, 3000);
                  // Prevent infinite reload loops
                  let reloadCount = 0;
                  const MAX_RELOADS = 2;
                  const originalReload = window.location.reload;
                  const originalReplace = window.location.replace;
                  const originalAssign = window.location.assign;
                  
                  window.location.reload = function() {
                      if (++reloadCount > MAX_RELOADS) {
                          console.log('[loop-protection] Blocked excessive reload attempt');
                          return;
                      }
                      return originalReload.apply(this, arguments);
                  };
                  
                  // Also protect against location.replace/assign to same URL
                  const currentHref = window.location.href;
                  window.location.replace = function(url) {
                      if (url === currentHref && ++reloadCount > MAX_RELOADS) {
                          console.log('[loop-protection] Blocked same-page replace attempt');
                          return;
                      }
                      return originalReplace.apply(this, arguments);
                  };

                  // This script intercepts and logs Fetch and XHR requests
                  // from within the page context at the earliest possible moment.
                  const originalFetch = window.fetch;
                  window.fetch = (...args) => {
                      try {
                          console.log('[evalOnDoc][fetch]', args[0]); // Log fetch requests
                          const fetchPromise = originalFetch.apply(this, args);
                          
                          // Add network error handling to prevent page errors
                          return fetchPromise.catch(fetchErr => {
                              console.log('[evalOnDoc][fetch-error]', args[0], fetchErr.message);
                              throw fetchErr; // Re-throw to maintain normal error flow
                          });
                      } catch (fetchWrapperErr) {
                          console.log('[evalOnDoc][fetch-wrapper-error]', fetchWrapperErr.message);
                          return originalFetch.apply(this, args);
                      }
                  };

                  const originalXHROpen = XMLHttpRequest.prototype.open;
                  XMLHttpRequest.prototype.open = function (method, xhrUrl) {
                      try {
                          console.log('[evalOnDoc][xhr]', xhrUrl); // Log XHR requests
                          
                          // Add error handling for XHR
                          this.addEventListener('error', function(event) {
                              console.log('[evalOnDoc][xhr-error]', xhrUrl, 'Network error occurred');
                          });
                          
                          return originalXHROpen.apply(this, arguments);
                      } catch (xhrOpenErr) {
                          console.log('[evalOnDoc][xhr-open-error]', xhrOpenErr.message);
                          return originalXHROpen.apply(this, arguments);
                      }
                  };
                              clearTimeout(injectionTimeout);
                          } catch (injectionError) {
                              console.log('[evalOnDoc][error]', 'Injection failed:', injectionError.message);
                          }
              }),
                      // Reduced timeout for faster failure
                      new Promise((_, reject) => {
                          setTimeout(() => {
                              reject(new Error('evaluateOnNewDocument timeout - browser may be unresponsive'));
                          }, 5000); // Reduced from 8000ms
                      })
                  ]);
                  evalOnDocSuccess = true;
                  if (forceDebug) {
                      console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Full injection successful for ${currentUrl}`));
                  }
              } catch (fullInjectionErr) {
                  // Enhanced error detection for CDP issues
                  const isCDPError = fullInjectionErr.constructor.name === 'ProtocolError' ||
                                    fullInjectionErr.name === 'ProtocolError' ||
                                    fullInjectionErr.message.includes('addScriptToEvaluateOnNewDocument timed out') ||
                                    fullInjectionErr.message.includes('Protocol error');
                  
                  if (forceDebug) {
                      const errorType = isCDPError ? 'CDP/Protocol error' : 'timeout/other';
                      console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Full injection failed (${errorType}): ${fullInjectionErr.message}`));
                  }

                  // Skip fallback for CDP errors - they indicate browser communication issues
                  if (isCDPError) {
                      console.warn(formatLogMessage('warn', `${EVAL_ON_DOC_TAG} CDP communication failure - skipping injection for ${currentUrl}`));
                      evalOnDocSuccess = false;
                  } else {
                  
                  // Strategy 3: Fallback - Try minimal injection (just fetch monitoring)
                  try {
                      await Promise.race([
                          (async () => {
                              // Validate page state before minimal injection
                              if (!page || page.isClosed()) {
                                  throw new Error('Page is closed');
                              }
                              
                              // FIX: Properly wrap page.url() in try-catch to handle race condition
                              let pageUrl;
                              try {
                                  pageUrl = await page.url();
                              } catch (urlErr) {
                                  // Page closed between isClosed check and url call
                                  throw new Error('Page closed while getting URL');
                              }

                              if (pageUrl === 'about:blank') {
                                  throw new Error('Cannot inject on about:blank');
                              }
                              
                              return page.evaluateOnNewDocument(() => {
                              // Minimal injection - just fetch monitoring
                              if (window.fetch) {
                                  const originalFetch = window.fetch;
                                  window.fetch = (...args) => {
                                      try {
                                          console.log('[evalOnDoc][fetch-minimal]', args[0]);
                                          return originalFetch.apply(this, args);
                                      } catch (err) {
                                          return originalFetch.apply(this, args);
                                      }
                                  };
                              }
                              });
                          })(),
                          new Promise((_, reject) => 
                              setTimeout(() => reject(new Error('Minimal injection timeout')), 3000)
                          )
                      ]);
                      evalOnDocSuccess = true;
                      if (forceDebug) {
                          console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Minimal injection successful for ${currentUrl}`));
                      }
                  } catch (minimalInjectionErr) {
                      if (forceDebug) {
                          console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Minimal injection also failed: ${minimalInjectionErr.message}`));
                      }
                      evalOnDocSuccess = false;
                  }
              }
           } 
          } else {
              if (forceDebug) {
                  console.log(formatLogMessage('debug', `${EVAL_ON_DOC_TAG} Browser unresponsive, skipping injection for ${currentUrl}`));
              }
              evalOnDocSuccess = false;
          }
          
          // Final status logging
          if (!evalOnDocSuccess) {
              console.warn(formatLogMessage('warn', `${EVAL_ON_DOC_TAG} All injection strategies failed for ${currentUrl} - continuing with standard request monitoring only`));
          }
      // Allow realtime cleanup to proceed after injection completes
      if (shouldInjectEvalForPage && siteConfig.window_cleanup === "realtime") {
          updatePageUsage(page, false); // Mark page as idle after injection
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
          console.warn(formatLogMessage('warn', `${CSS_BLOCKED_TAG} Failed to set up CSS element blocking for ${currentUrl}: ${cssErr.message}`));
        }
      }
      // --- END: CSS Element Blocking Setup ---

      // --- Per-Page CDP Setup ---
      
      try {
        cdpSessionManager = await createCDPSession(page, currentUrl, {
          enableCDP,
          siteSpecificCDP: shouldEnableCDPForThisUrl,
          forceDebug
        });
      } catch (cdpErr) {
        if (cdpErr.message.includes('Browser protocol broken')) {
          throw cdpErr; // Re-throw critical browser errors
        }
        // Non-critical CDP errors are already handled in the module
        cdpSessionManager = { session: null, cleanup: async () => {} };
      }
      // --- End of Per-Page CDP Setup ---

      // Protected request interception setup with timeout
      try {
        // Use timeout-protected request interception setup
        await setRequestInterceptionWithTimeout(page, 15000);
        
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Request interception enabled successfully for ${currentUrl}`));
        }
      } catch (networkErr) {
        if (networkErr.message.includes('CRITICAL_NETWORK_ERROR') || 
            networkErr.message.includes('CRITICAL_BROWSER_ERROR') ||
            networkErr.message.includes('ProtocolError') ||
            networkErr.message.includes('timed out') || 
            networkErr.message.includes('Network.enable') || 
            networkErr.message.includes('timeout')) {
          console.warn(formatLogMessage('warn', `Request interception setup failed for ${currentUrl}: ${networkErr.message} - triggering browser restart`));
          return { 
            url: currentUrl, 
            rules: [], 
            success: false, 
            needsImmediateRestart: true,
            error: 'Request interception timeout - browser restart required'
          };
        }
        throw networkErr; // Re-throw other errors
      }
	  
	  // Set up frame handling to suppress invalid URL errors
      setupFrameHandling(page, forceDebug);
	  
      if (siteConfig.clear_sitedata === true) {
        try {
          const clearResult = await clearSiteData(page, currentUrl, forceDebug);
          if (forceDebug) console.log(formatLogMessage('debug', `Cleared site data for ${currentUrl}`));
        } catch (clearErr) {
          if (forceDebug) console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} Failed for ${currentUrl}: ${clearErr.message}`));
        }
      }

      // --- Apply proxy authentication if configured ---
      if (needsProxy(siteConfig)) {
        await applyProxyAuth(page, siteConfig, forceDebug);
      }

      // --- Apply all fingerprint spoofing (user agent, Brave, fingerprint protection) ---
      // Skip when using Obscura — it has built-in stealth that conflicts with our injection
      try {
        if (!useObscura) {
          await applyAllFingerprintSpoofing(page, siteConfig, forceDebug, currentUrl);
        } else if (forceDebug) {
          console.log(formatLogMessage('debug', `Skipping fingerprint injection — Obscura provides built-in stealth`));
        }

        // Neutralize the Fullscreen API before any page script runs so a
        // site can't force the real browser window fullscreen in --headful
        // (or trip an anti-bot check that reads document.fullscreenElement).
        // requestFullscreen is stubbed to a resolved no-op — which is also
        // how browsers already behave when it's called without a user
        // gesture, so this looks normal, not automated. fullscreenElement
        // stays null naturally since we never enter fullscreen.
        if (!allowFullscreen) {
          try {
            await page.evaluateOnNewDocument(() => {
              const noop = function () { return Promise.resolve(); };
              const legacyNoop = function () {};
              try { Element.prototype.requestFullscreen = noop; } catch (_) {}
              try { Element.prototype.webkitRequestFullscreen = legacyNoop; } catch (_) {}
              try { Element.prototype.webkitRequestFullScreen = legacyNoop; } catch (_) {}
              try { Element.prototype.mozRequestFullScreen = legacyNoop; } catch (_) {}
              try { Element.prototype.msRequestFullscreen = legacyNoop; } catch (_) {}
            });
          } catch (fsErr) {
            if (forceDebug) console.log(formatLogMessage('debug', `Fullscreen neutralization injection failed: ${fsErr.message}`));
          }
        }
        
        // Client Hints protection for Chrome user agents (skipped under Obscura — it sets its own)
        if (!useObscura && siteConfig.userAgent && siteConfig.userAgent.toLowerCase().includes('chrome')) {
          const userAgentKey = siteConfig.userAgent.toLowerCase();
          let platform = 'Windows';
          let platformVersion = '15.0.0';
          let arch = 'x86';
          
          if (userAgentKey === 'chrome_mac') {
            platform = 'macOS';
            platformVersion = '13.5.0'; 
            arch = 'arm';
          } else if (userAgentKey === 'chrome_linux') {
            platform = 'Linux';
            platformVersion = '6.5.0';
            arch = 'x86';
          }
                    
          await page.setExtraHTTPHeaders({
            'Sec-CH-UA': '"Not:A-Brand";v="99", "Google Chrome";v="146", "Chromium";v="146"',
            'Sec-CH-UA-Platform': `"${platform}"`,
            'Sec-CH-UA-Platform-Version': `"${platformVersion}"`,
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Arch': `"${arch}"`,
            'Sec-CH-UA-Bitness': '"64"',
            'Sec-CH-UA-Full-Version': '"146.0.0.0"',
            'Sec-CH-UA-Full-Version-List': '"Not:A-Brand";v="99.0.0.0", "Google Chrome";v="146.0.0.0", "Chromium";v="146.0.0.0"'
          });
        }
      } catch (fingerprintErr) {
        if (fingerprintErr.message.includes('Session closed') || 
            fingerprintErr.message.includes('Protocol error') ||
            fingerprintErr.message.includes('addScriptToEvaluateOnNewDocument')) {
          console.warn(`[fingerprint protection failed] ${currentUrl}: ${fingerprintErr.message}`);
        } else {
          throw fingerprintErr;
        }
      }

      const regexes = getCompiledRegexes(siteConfig.filterRegex);

      // NEW: Get regex_and setting (defaults to false for backward compatibility)
      const useRegexAnd = siteConfig.regex_and === true;

   // Parse searchstring patterns using module
   const { searchStrings, searchStringsAnd, hasSearchString, hasSearchStringAnd } = parseSearchStrings(siteConfig.searchstring, siteConfig.searchstring_and);
   const useCurl = siteConfig.curl === true; // Use curl if enabled, regardless of searchstring
   let useGrep = siteConfig.grep === true; // Grep can work independently

   // Get user agent for curl if needed
   let curlUserAgent = '';
   if (useCurl && siteConfig.userAgent) {
     curlUserAgent = USER_AGENTS.get(siteConfig.userAgent.toLowerCase()) || '';
   }

   if (useCurl && forceDebug) {
     console.log(formatLogMessage('debug', `Curl-based content analysis enabled for ${currentUrl}`));
   }

   if (useGrep && forceDebug) {
     console.log(formatLogMessage('debug', `Grep-based pattern matching enabled for ${currentUrl}${useCurl ? ' (with curl)' : ' (with response handler)'}`));
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
   
   // Validate curl availability if needed
   if (useCurl) {
     const curlCheck = validateCurlAvailability();
     if (!curlCheck.isAvailable) {
       console.warn(formatLogMessage('warn', `Curl not available for ${currentUrl}: ${curlCheck.error}. Skipping curl-based analysis.`));
       useCurl = false;
     } else if (forceDebug) {
       console.log(formatLogMessage('debug', `Using curl: ${curlCheck.version}`));
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
        if (useRegexAnd && patterns.length > 1) {
          console.log(formatLogMessage('info', `  Logic: AND (all patterns must match same URL)`));
        } else if (patterns.length > 1) {
          console.log(formatLogMessage('info', `  Logic: OR (any pattern can match)`));
        }
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

      // Per-site blocked compile -- helper warns on bad patterns instead of
      // throwing out of processUrl and breaking that site's scan.
      const blockedRegexes = compilePatternList(`blocked (site: ${siteConfig.url || 'unknown'})`, siteConfig.blocked, getCompiledRegex);

      // Per-site escape hatch: disable_adblock turns off the two layers of
      // "global" ad-blocking for this URL — the adblock-rs filter-list engine
      // and the globalBlockedRegexes pattern list. Per-site siteConfig.blocked
      // is preserved (it's an explicit per-site choice, not "global" blocking).
      //
      // The use case: capture_popups + popunder/redirect chains. The global
      // adblock often aborts the exact requests that fire the popup or chain
      // to the tracker, defeating capture. Setting disable_adblock: true for
      // those specific URLs lets the chain play out naturally so the popup
      // request listener can observe the full hop sequence.
      const disableAdblock = siteConfig.disable_adblock === true;

      // Pre-build Set for O(1) resourceType lookups (fired per request)
      const allowedResourceTypesSet = Array.isArray(siteConfig.resourceTypes)
        ? new Set(siteConfig.resourceTypes)
        : null;

      // Combine site-specific with pre-compiled global blocked patterns.
      // When disable_adblock is true, globalBlockedRegexes is omitted so
      // only the per-site list applies.
      const allBlockedRegexes = disableAdblock
        ? blockedRegexes
        : (blockedRegexes.length > 0
            ? [...blockedRegexes, ...globalBlockedRegexes]
            : globalBlockedRegexes); // Avoid spread when no site-specific patterns

      if (disableAdblock && forceDebug) {
        const dropped = globalBlockedRegexes.length;
        const adblockNote = adblockEnabled && adblockMatcher ? ' + adblock-rs engine' : '';
        console.log(formatLogMessage('debug', `[adblock] disable_adblock=true for ${currentUrl} — skipping ${dropped} global blocked patterns${adblockNote} (site-level ${blockedRegexes.length} pattern(s) still apply)`));
      }

      /**
       * Helper function to add domain to matched collection
       * @param {string} domain - Domain to add
       * @param {string} fullSubdomain - Full subdomain for cache tracking
       * @param {string} resourceType - Resource type (for --adblock-rules mode)
       */
      function addMatchedDomain(domain, resourceType = null, fullSubdomain = null) {
       // Use fullSubdomain for cache tracking if provided, otherwise fall back to domain
       const cacheKey = fullSubdomain || domain;
       // Check if we should ignore similar domains
       const ignoreSimilarEnabled = siteConfig.ignore_similar !== undefined ? siteConfig.ignore_similar : ignore_similar;
       const similarityThreshold = siteConfig.ignore_similar_threshold || ignore_similar_threshold;
       const ignoreSimilarIgnoredDomains = siteConfig.ignore_similar_ignored_domains !== undefined ? siteConfig.ignore_similar_ignored_domains : ignore_similar_ignored_domains;
       
       // Use smart cache's similarity cache for performance (if cache is enabled)
       if (ignoreSimilarEnabled && smartCache) {
         const existingDomains = matchedDomains instanceof Map 
           ? Array.from(matchedDomains.keys()).filter(key => !['dryRunMatches', 'dryRunNetTools', 'dryRunSearchString'].includes(key))
           : Array.from(matchedDomains);
           
         // Check cached similarity scores first
         for (const existingDomain of existingDomains) {
           const cachedSimilarity = smartCache.getCachedSimilarity(domain, existingDomain);
           if (cachedSimilarity !== null && cachedSimilarity >= similarityThreshold) {
             if (forceDebug) {
               console.log(formatLogMessage('debug', `${SMART_CACHE_TAG} Used cached similarity: ${domain} ~= ${existingDomain} (${cachedSimilarity}%)`));
             }
             return; // Skip adding this domain
           }
           
           // If no cached similarity exists, calculate and cache it
           if (cachedSimilarity === null) {
             const similarity = calculateSimilarity(domain, existingDomain);
             if (smartCache && !ignoreCache) {
               smartCache.cacheSimilarity(domain, existingDomain, similarity);
             }
           }
         }
       }

       // Check smart cache first (if cache is enabled)
       const context = {
         filterRegex: siteConfig.filterRegex,
         searchString: siteConfig.searchstring,
         resourceType: resourceType
       };
       
       if (smartCache && smartCache.shouldSkipDomain(domain, context)) {
         if (forceDebug) {
           console.log(formatLogMessage('debug', `${SMART_CACHE_TAG} Skipping cached domain: ${domain}`));
         }
         return; // Skip adding this domain
       }

       if (ignoreSimilarEnabled) {
         const existingDomains = matchedDomains instanceof Map 
           ? Array.from(matchedDomains.keys()).filter(key => !['dryRunMatches', 'dryRunNetTools', 'dryRunSearchString'].includes(key))
           : Array.from(matchedDomains);
           
         const similarCheck = shouldIgnoreSimilarDomain(domain, existingDomains, {
           enabled: true,
           threshold: similarityThreshold,
           forceDebug
         });
         
         if (similarCheck.shouldIgnore) {
           if (forceDebug) {
             console.log(formatLogMessage('debug', `${IGNORE_SIMILAR_TAG} Skipping ${domain}: ${similarCheck.reason}`));
           }
           return; // Skip adding this domain
         }
       }

      // Check if domain is similar to any in ignoreDomains list
      if (ignoreSimilarIgnoredDomains && ignoreDomains && ignoreDomains.length > 0) {
        const ignoredSimilarCheck = shouldIgnoreSimilarDomain(domain, ignoreDomains, {
          enabled: true,
          threshold: similarityThreshold,
          forceDebug
        });
        
        if (ignoredSimilarCheck.shouldIgnore) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${IGNORE_SIMILAR_IGNORED_DOMAINS_TAG} Skipping ${domain}: ${ignoredSimilarCheck.reason} (similar to ignoreDomains)`));
          }
          return; // Skip adding this domain
        }
      }

      // Mark full subdomain as detected for future reference
      markDomainAsDetected(cacheKey);
      localDetectedDomains.add(cacheKey);
      
      // Also mark in smart cache with context (if cache is enabled)
      if (smartCache) {
  try {
    if (smartCache.markDomainProcessed) {
      safeMarkDomainProcessed(domain, context, { resourceType, fullSubdomain });
    } else {
      // Fallback: use shouldSkipDomain to indirectly cache
      smartCache.shouldSkipDomain(domain, context);
    }
  } catch (cacheErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${SMART_CACHE_TAG} Error marking domain: ${cacheErr.message}`));
    }
  }
      }

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

      // === POPUP CAPTURE (opt-in via siteConfig.capture_popups: true) ===
      // Many ad networks fire popunders / new-tab opens (window.open, target=
      // "_blank") that navigate to trackers and disappear from view. Those
      // pages are SEPARATE Puppeteer targets — page.on('request', ...) on the
      // main page never sees their network traffic.
      //
      // IMPORTANT: modern Chromium blocks programmatic window.open() unless
      // it's triggered by a real user gesture. In practice that means
      // capture_popups only catches anything when the scanner is actually
      // clicking on the page — i.e., the site config also has
      // `interact: true` AND `interact_clicks: true`. Setting capture_popups
      // alone will register the listener but no popups will fire.
      //
      // When capture_popups is true, we attach a browser-level 'targetcreated'
      // listener for THIS URL only. New page targets whose opener-chain leads
      // back to our main page (within maxDepth levels) get a stripped-down
      // request listener — same regex/first-party/ignoreDomains filter as
      // the main handler, same addMatchedDomain() sink, same domain
      // detection cache, same nettools/similarity logic (all inherited via
      // addMatchedDomain). Cloudflare bypass, adblock-rs matching, curl/grep
      // content download, and request.abort() are intentionally skipped on
      // popups — they're observation-only.
      //
      // Each popup's request listener stays attached across in-window
      // navigations, so a single popup that redirects A -> B -> C captures
      // every hop. The capture window (default 5s, configurable per-site
      // via capture_popups_window_ms) is the wall-clock budget for that
      // chain — bump it for long redirect chains, lower it for high-popup-
      // rate sites where memory pressure matters more than chain coverage.
      const capturePopups = siteConfig.capture_popups === true;
      // Per-site overrides (with sane defaults). Parsed as numbers so config
      // values from JSON come through correctly; falsy / non-positive values
      // fall back to the default rather than silently disabling capture.
      const POPUP_MAX_DEPTH = (() => {
        const v = parseInt(siteConfig.capture_popups_max_depth, 10);
        return Number.isFinite(v) && v > 0 ? v : 2;
      })();
      const POPUP_CAPTURE_WINDOW_MS = (() => {
        const v = parseInt(siteConfig.capture_popups_window_ms, 10);
        return Number.isFinite(v) && v > 0 ? v : 5000;
      })();

      if (capturePopups && forceDebug) {
        // One-time setup-time warning if the click prerequisite isn't met.
        // Without clicks, capture_popups is a no-op in practice. Previous
        // version blamed `interact_clicks` for both missing-piece cases — but
        // when the actual culprit is `interact: 1` (number, silently disabled
        // by strict `=== true`), the message misled users into debugging
        // interact_clicks while the real problem was interact itself.
        // (normalizeSiteConfig now coerces interact: 1 → true with a warning,
        // so by the time we get here both should be booleans — but keep the
        // diagnostic accurate for the truly-missing case.)
        const interactOn = siteConfig.interact === true;
        const clicksOn = siteConfig.interact_clicks === true;
        if (!interactOn && !clicksOn) {
          console.log(formatLogMessage('debug', `[popup] capture_popups is enabled but neither 'interact' nor 'interact_clicks' is — set BOTH to true to fire user-gesture clicks; without them, only popups opened via in-page redirects will capture`));
        } else if (!interactOn) {
          console.log(formatLogMessage('debug', `[popup] capture_popups is enabled but 'interact' is not — set interact: true to enable the interaction loop (interact_clicks is already set); without it, no fake clicks fire`));
        } else if (!clicksOn) {
          console.log(formatLogMessage('debug', `[popup] capture_popups is enabled but 'interact_clicks' is not — set interact_clicks: true to enable element-targeted clicks; without it, only random content-zone clicks fire and may miss overlay-based popunders`));
        }
        console.log(formatLogMessage('debug', `[popup] capture_popups settings: maxDepth=${POPUP_MAX_DEPTH}, windowMs=${POPUP_CAPTURE_WINDOW_MS}`));
      }

      if (capturePopups) {
        const mainTarget = page.target();

        // Walk target.opener() chain to find depth relative to mainTarget.
        // Returns 0 if the target isn't a descendant of mainTarget at all,
        // 1 for a direct popup of the main page, 2 for popup-of-popup, etc.
        const getPopupDepth = (target) => {
          let depth = 0;
          let cur = target.opener();
          while (cur && depth <= POPUP_MAX_DEPTH + 1) {
            depth++;
            if (cur === mainTarget) return depth;
            cur = cur.opener();
          }
          return 0;
        };

        // Attach observation-only request listener to a popup page. No
        // setRequestInterception(true) — page.on('request') fires for every
        // request regardless of interception state, and we don't need to
        // block anything on popups.
        // Evaluate ANY URL surfaced from a popup (the popup's own navigation URL
        // OR an in-popup request) against the same filter pipeline the main-page
        // request handler uses. Factored out so:
        //   1. attachPopupRequestCapture's `popupPage.on('request', ...)` calls
        //      this once per in-popup request (with the request's resourceType).
        //   2. onTargetCreated calls this once with `target.url()` and resourceType
        //      'document' BEFORE attaching the request listener — catches the
        //      popup's navigation URL itself, which fires before our listener can
        //      attach (targetcreated → page resolve → attach is async, and the
        //      browser dispatches the navigation immediately on window.open).
        //      Without #2, popunder destinations whose own URL contains the
        //      filterRegex pattern (e.g. AdsCore campaign URLs with &campaign=)
        //      were seen-but-not-evaluated.
        const evaluatePopupUrl = (checkedUrl, depth, resourceType) => {
          try {
            if (!checkedUrl || checkedUrl === 'about:blank') return;
            let fullSubdomain = '';
            let checkedRootDomain = '';
            try {
              const parsedUrl = new URL(checkedUrl);
              fullSubdomain = parsedUrl.hostname;
              const pslResult = psl.parse(fullSubdomain);
              checkedRootDomain = pslResult.domain || fullSubdomain;
            } catch (_) { return; }
            if (!checkedRootDomain) return;

            // ignoreDomainsByUrl — if any pattern matches this popup URL,
            // mark the root domain as ignored for the rest of the scan
            // (main page + all popups). Mirrors the main handler so a
            // tracker URL surfaced via popup chain has the same dampening
            // effect as one surfaced on the main page.
            if (_ignoreDomainsByUrlRegexes.length > 0 && !_dynamicallyIgnoredDomains.has(checkedRootDomain)) {
              for (let i = 0; i < _ignoreDomainsByUrlRegexes.length; i++) {
                if (_ignoreDomainsByUrlRegexes[i].test(checkedUrl)) {
                  _dynamicallyIgnoredDomains.add(checkedRootDomain);
                  if (forceDebug) {
                    console.log(formatLogMessage('debug', `${IGNORE_DOMAINS_BY_URL_TAG} ${checkedRootDomain} ignored — matched pattern: ${_ignoreDomainsByUrlRegexes[i].source} (from popup depth=${depth})`));
                  }
                  break;
                }
              }
            }

            // blockDomainsByUrl trigger — symmetric to ignoreDomainsByUrl
            // above; populating the dynamic block Set from popup URLs lets
            // tracker URLs surfaced via popup chains poison their root
            // domain for the rest of the scan just like main-page hits do.
            if (_blockDomainsByUrlRegexes.length > 0 && !_dynamicallyBlockedDomains.has(checkedRootDomain)) {
              for (let i = 0; i < _blockDomainsByUrlRegexes.length; i++) {
                if (_blockDomainsByUrlRegexes[i].test(checkedUrl)) {
                  _dynamicallyBlockedDomains.add(checkedRootDomain);
                  if (forceDebug) {
                    console.log(formatLogMessage('debug', `${BLOCK_DOMAINS_BY_URL_TAG} ${checkedRootDomain} blocked — matched pattern: ${_blockDomainsByUrlRegexes[i].source} (from popup depth=${depth})`));
                  }
                  break;
                }
              }
            }

            // ignoreDomains gate (global; matchesIgnoreDomain also short-
            // circuits on _dynamicallyIgnoredDomains, so a domain we just
            // added above will be caught here on the same request).
            if (matchesIgnoreDomain(checkedRootDomain, ignoreDomains)) return;

            // Dynamic-block gate for popup requests — early return on
            // matched root or any parent (parent-walk in
            // matchesDynamicBlock). Popups don't have a request object
            // available here, so we just return rather than abort; the
            // popup-request observer treats this as "don't process".
            if (matchesDynamicBlock(checkedRootDomain)) return;

            // First-party / third-party gate (popup belongs to the main URL's
            // domain group — its OWN URL doesn't redefine first-party).
            const isFirstParty = firstPartyDomains.has(checkedRootDomain);
            if (siteConfig.firstParty === false && isFirstParty) return;
            if (siteConfig.thirdParty === false && !isFirstParty) return;

            // Regex match against the site's filterRegex list
            let regexMatched = false;
            for (const re of regexes) {
              if (re.test(checkedUrl)) {
                regexMatched = true;
                if (forceDebug) {
                  console.log(formatLogMessage('debug', `[popup depth=${depth}] Matched ${checkedRootDomain} via ${re} (${resourceType})`));
                }
                break;
              }
            }

            if (!regexMatched) return;

            // hasNetTools is the same flag the main handler uses (line ~2639).
            // When the site config carries whois/dig terms, regex match is
            // not sufficient by itself — the URL must ALSO pass the whois/
            // dig validation before it counts. Mirrors the main handler's
            // behavior so 'capture popup domains that match regex/dig/whois'
            // means the same thing for popups as for the main page.
            if (hasNetTools) {
              const popupNetToolsHandler = createNetToolsHandler({
                whoisTerms, whoisOrTerms,
                processedWhoisDomains: globalProcessedWhoisDomains,
                processedDigDomains: globalProcessedDigDomains,
                whoisDelay: siteConfig.whois_delay !== undefined ? siteConfig.whois_delay : whois_delay,
                whoisServer,
                whoisServerMode: siteConfig.whois_server_mode || whois_server_mode,
                debugLogFile,
                digTerms, digOrTerms, digRecordType,
                digSubdomain: siteConfig.dig_subdomain === true,
                dryRunCallback: dryRunMode ? createEnhancedDryRunCallback(matchedDomains, forceDebug) : null,
                matchedDomains, addMatchedDomain,
                isDomainAlreadyDetected: isLocallyDetected,
                onWhoisResult: smartCache ? (domain, result) => smartCache.cacheNetTools(domain, 'whois', result) : undefined,
                onDigResult: smartCache ? (domain, result, recordType) => smartCache.cacheNetTools(domain, 'dig', result, recordType) : undefined,
                cachedWhois: smartCache ? smartCache.getCachedNetTools(checkedRootDomain, 'whois') : null,
                cachedDig: smartCache ? smartCache.getCachedNetTools(checkedRootDomain, 'dig', digRecordType) : null,
                currentUrl, getRootDomain, siteConfig, dumpUrls, matchedUrlsLogFile, forceDebug, fs,
                ignoreDomains, matchesIgnoreDomain
              });
              trackNetToolsHandler(() => popupNetToolsHandler(checkedRootDomain, fullSubdomain));
            } else {
              // No nettools required — regex match alone counts.
              addMatchedDomain(checkedRootDomain, resourceType, fullSubdomain);
            }
          } catch (_) { /* observation-only — never let a popup error escape */ }
        };

        // Thin wrapper around evaluatePopupUrl for the per-request listener.
        // Under forceDebug also attach framenavigated + close listeners so
        // the popup's full lifecycle (initial nav URL, mid-popup navigations,
        // close) is visible in logs. Useful when investigating "I saw a
        // Chrome window flash on screen" — the framenavigated transitions
        // tell you what URL the window was showing and for how long.
        const attachPopupRequestCapture = (popupPage, depth) => {
          popupPage.on('request', (request) => {
            evaluatePopupUrl(request.url(), depth, request.resourceType());
          });
          if (forceDebug) {
            try {
              popupPage.on('framenavigated', (frame) => {
                try {
                  if (frame !== popupPage.mainFrame()) return; // main frame only
                  console.log(formatLogMessage('debug', `[popup depth=${depth}] framenavigated → ${frame.url() || 'about:blank'}`));
                } catch (_) {}
              });
              popupPage.on('close', () => {
                try {
                  const lastUrl = popupPage.url ? popupPage.url() : '(unknown)';
                  console.log(formatLogMessage('debug', `[popup depth=${depth}] close (last URL: ${lastUrl})`));
                } catch (_) {}
              });
              popupPage.on('pageerror', (err) => {
                try { console.log(formatLogMessage('debug', `[popup depth=${depth}] pageerror: ${err.message}`)); } catch (_) {}
              });
            } catch (_) { /* listener attach errors aren't fatal */ }
          }
        };

        const onTargetCreated = async (target) => {
          // Log EVERY targetcreated event under forceDebug so callers can see
          // the full set of targets Chromium creates during the scan — not
          // just the ones we capture. Useful when investigating "is that
          // Chrome window I saw from a popup or from somewhere else?" — if
          // a window opens but no targetcreated fires, it's not ours. If a
          // targetcreated fires for type=page but we skip-and-explain below,
          // the user knows why we ignored it. Captures the FULL diagnostic
          // surface, no behavior change.
          let _tType, _tUrl;
          if (forceDebug) {
            try {
              _tType = target.type();
              _tUrl = target.url() || 'about:blank';
              console.log(formatLogMessage('debug', `[popup] targetcreated: type=${_tType} url=${_tUrl}`));
            } catch (_) {}
          }

          // Short-circuit guard: if finally has already started, don't attach
          // a request listener whose closure would outlive its meaningful
          // scope. The race is narrow (a targetcreated firing while we're
          // mid-await on target.page() across the finally boundary), but
          // without this guard a late popup could push matches into
          // matchedDomains for a URL whose processing has already returned.
          if (urlFinished) {
            if (forceDebug) console.log(formatLogMessage('debug', `[popup] skipping: urlFinished=true (scan teardown in progress)`));
            return;
          }
          if (target.type() !== 'page') {
            if (forceDebug) console.log(formatLogMessage('debug', `[popup] skipping: non-page target type=${target.type()} (workers/service-workers/etc are not popunder candidates)`));
            return;
          }
          const depth = getPopupDepth(target);
          if (depth < 1) {
            if (forceDebug) console.log(formatLogMessage('debug', `[popup] skipping: depth=0 — target not in opener chain of main page (likely a new browser tab opened independently, not a popunder from our scan)`));
            return; // Not one of ours
          }
          if (depth > POPUP_MAX_DEPTH) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `[popup] Skipping depth-${depth} popup (max=${POPUP_MAX_DEPTH}): ${target.url() || 'about:blank'}`));
            }
            return;
          }

          let popupPage;
          try { popupPage = await target.page(); } catch (_) { return; }
          if (!popupPage) {
            if (forceDebug) console.log(formatLogMessage('debug', `[popup depth=${depth}] target.page() returned null — popup not accessible as a Page object`));
            return;
          }
          // Re-check after the await — the per-URL finally may have flipped
          // the flag while target.page() was resolving.
          if (urlFinished) {
            try { if (!popupPage.isClosed()) popupPage.close().catch(() => {}); } catch (_) {}
            return;
          }

          if (forceDebug) {
            console.log(formatLogMessage('debug', `[popup depth=${depth}] Capturing popup: ${target.url() || 'about:blank'}`));
            // Window dimensions are useful for the "is the popup visible on
            // my screen?" question — a popup with non-zero viewport in a
            // headless=new launch shouldn't be visible but on some display
            // servers (WSLg, X11) it can briefly flash on screen. Log the
            // viewport so callers can correlate with what they saw.
            try {
              const vp = popupPage.viewport();
              if (vp) console.log(formatLogMessage('debug', `[popup depth=${depth}] viewport: ${vp.width}x${vp.height}`));
            } catch (_) {}
          }

          // Evaluate the popup's own navigation URL against the same filter
          // pipeline used for in-popup requests. Required because targetcreated
          // → target.page() → on('request', ...) is async, and the browser
          // dispatches the popup's navigation request immediately on window.open
          // — by the time the listener attaches below, the navigation request
          // has already fired and won't be re-emitted. resourceType 'document'
          // mirrors what Chrome would emit for a top-level navigation request.
          // Without this call, AdsCore-style popunder destinations (URL contains
          // &campaign=, &v=, etc) were seen-but-not-evaluated: the popup was
          // logged but its domain never matched the filter regex, so it never
          // became a rule. Only secondary in-popup requests (tracking pixels,
          // sub-resources) ever got tested against the regex.
          evaluatePopupUrl(target.url(), depth, 'document');

          attachPopupRequestCapture(popupPage, depth);

          // Auto-close after the capture window so popups don't pile up.
          const closeTimer = setTimeout(() => {
            try { if (!popupPage.isClosed()) popupPage.close().catch(() => {}); } catch (_) {}
          }, POPUP_CAPTURE_WINDOW_MS);
          if (typeof closeTimer.unref === 'function') closeTimer.unref();

          popupCleanups.push(() => {
            clearTimeout(closeTimer);
            try { if (!popupPage.isClosed()) popupPage.close().catch(() => {}); } catch (_) {}
          });
        };

        browser.on('targetcreated', onTargetCreated);
        popupCleanups.push(() => {
          try { browser.off('targetcreated', onTargetCreated); } catch (_) {}
        });
      }

      // --- page.on('request', ...) Handler: Core Network Request Logic ---
      // This handler is triggered for every network request made by the page.
      // It decides whether to allow, block, or process the request based on:
      // - First-party/third-party status and site configuration.
      // - URL matching against blocklists (`blockedRegexes`).
      // - URL matching against filter patterns (`regexes`) for domain extraction.
      // - Global `ignoreDomains` list.
      // Pre-compute values that are constant for this URL
      const simplifiedCurrentUrl = getRootDomain(currentUrl);

      page.on('request', request => {
        const checkedUrl = request.url();
        // Parse URL once, derive all domain variants from single parse
        let fullSubdomain = '';
        let checkedRootDomain = '';
        try {
          const parsedUrl = new URL(checkedUrl);
          fullSubdomain = parsedUrl.hostname;
          const pslResult = psl.parse(fullSubdomain);
          checkedRootDomain = pslResult.domain || fullSubdomain;
        } catch (e) {}

        // Check against ALL first-party domains (original + all redirects)
        const isFirstParty = checkedRootDomain && firstPartyDomains.has(checkedRootDomain);
        
        // Block infinite iframe loops - safely access frame URL
        const frameUrl = (() => {
          try {
            const frame = request.frame();
            return frame ? frame.url() : '';
          } catch (err) {
            return '';
          }
        })();
        if (frameUrl && frameUrl.includes('creative.dmzjmp.com') && 
            checkedUrl.includes('go.dmzjmp.com/api/models')) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Blocking potential infinite iframe loop: ${checkedUrl}`));
          }
          request.abort();
          return;
        }

        // Enhanced debug logging to show which frame the request came from
        if (forceDebug) {
          let debugFrameUrl = 'unknown-frame';
          let isMainFrame = false;
          
          try {
            const frame = request.frame();
            if (frame) {
              debugFrameUrl = frame.url();
              isMainFrame = frame === page.mainFrame();
            }
          } catch (frameErr) {
            debugFrameUrl = 'detached-frame';
          }
          console.log(formatLogMessage('debug', `${messageColors.highlight('[req]')}[frame: ${isMainFrame ? 'main' : 'iframe'}] ${debugFrameUrl} → ${checkedUrl}`));
        }

        // Apply adblock-rs filter-list rules BEFORE expensive regex checks
        // for better performance. Gated on !disableAdblock so per-URL configs
        // (e.g. for popup/redirect chain capture) can bypass it.
        if (!disableAdblock && adblockEnabled && adblockMatcher) {
          try {
            const result = adblockMatcher.shouldBlock(
              checkedUrl,
              currentUrl,
              request.resourceType()
            );

            if (result.blocked) {
              adblockStats.blocked++;
              if (forceDebug) {
                console.log(formatLogMessage('debug', `${messageColors.blocked('[adblock]')} ${checkedUrl} (${result.reason})`));
              }
              request.abort('blockedbyclient');
              return;
            }
            adblockStats.allowed++;
          } catch (err) { /* Silently continue on adblock errors */ }
        }

        // Show --debug output and the url while its scanning
        if (forceDebug) {
          const timestamp = new Date().toISOString();
          const logEntry = `${timestamp} [debug req][${simplifiedCurrentUrl}] ${checkedUrl}\n`;

          // Output to console
          console.log(formatLogMessage('debug', `${messageColors.highlight('[req]')}[${simplifiedCurrentUrl}] ${checkedUrl}`));

          // Output to file (buffered)
          bufferedLogWrite(debugLogFile, logEntry);
        }
        const reqUrl = checkedUrl;

        const reqDomain = perSiteSubDomains ? fullSubdomain : checkedRootDomain;

        // ignoreDomainsByUrl — if any pattern matches this URL, mark the root domain as ignored for the rest of the scan
        if (_ignoreDomainsByUrlRegexes.length > 0 && checkedRootDomain && !_dynamicallyIgnoredDomains.has(checkedRootDomain)) {
          for (let i = 0; i < _ignoreDomainsByUrlRegexes.length; i++) {
            if (_ignoreDomainsByUrlRegexes[i].test(reqUrl)) {
              _dynamicallyIgnoredDomains.add(checkedRootDomain);
              if (forceDebug) {
                console.log(formatLogMessage('debug', `${IGNORE_DOMAINS_BY_URL_TAG} ${checkedRootDomain} ignored — matched pattern: ${_ignoreDomainsByUrlRegexes[i].source}`));
              }
              break;
            }
          }
        }

        // blockDomainsByUrl trigger — symmetric to ignoreDomainsByUrl above.
        // If any pattern matches this URL, mark the root domain as blocked
        // for the rest of the scan. The gate immediately below catches the
        // triggering request itself + any future request on this domain or
        // its subdomains (parent-walk via matchesDynamicBlock).
        if (_blockDomainsByUrlRegexes.length > 0 && checkedRootDomain && !_dynamicallyBlockedDomains.has(checkedRootDomain)) {
          for (let i = 0; i < _blockDomainsByUrlRegexes.length; i++) {
            if (_blockDomainsByUrlRegexes[i].test(reqUrl)) {
              _dynamicallyBlockedDomains.add(checkedRootDomain);
              if (forceDebug) {
                console.log(formatLogMessage('debug', `${BLOCK_DOMAINS_BY_URL_TAG} ${checkedRootDomain} blocked — matched pattern: ${_blockDomainsByUrlRegexes[i].source}`));
              }
              break;
            }
          }
        }
        // blockDomainsByUrl gate — abort if reqDomain (or a parent) is in
        // the dynamic block Set. Fires BEFORE the static blocked-regex
        // check so domain-based blocks short-circuit without paying the
        // per-URL regex scan. Same abort reason as the static path so
        // request.failure() observers see consistent metadata.
        if (reqDomain && _dynamicallyBlockedDomains.size > 0 && matchesDynamicBlock(reqDomain)) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${BLOCK_DOMAINS_BY_URL_TAG} aborting ${reqUrl} (domain ${reqDomain} dynamically blocked)`));
          }
          request.abort('blockedbyclient');
          return;
        }

        let blockedMatchIndex = -1;
        for (let i = 0; i < allBlockedRegexes.length; i++) {
          if (allBlockedRegexes[i].test(reqUrl)) {
            blockedMatchIndex = i;
            break;
          }
        }
        if (blockedMatchIndex !== -1) {
          // Always track the hit (zero-cost on the un-debug path) so the
          // scan-end summary can show which patterns are doing work vs.
          // which are stale and ready to prune. Keyed by pattern.source --
          // identical patterns from site + global lists roll up together,
          // which matches how users think about them.
          const matchedPatternSrc = allBlockedRegexes[blockedMatchIndex].source;
          _blockedPatternHits.set(matchedPatternSrc, (_blockedPatternHits.get(matchedPatternSrc) || 0) + 1);

          if (forceDebug) {
            const matchedPattern = matchedPatternSrc;
            const patternSource = blockedMatchIndex < blockedRegexes.length ? 'site' : 'global';
            console.log(formatLogMessage('debug', `${messageColors.blocked('[blocked]')}[${simplifiedCurrentUrl}] ${reqUrl} blocked by ${patternSource} pattern: ${matchedPattern}`));
            
            // Also log to file (buffered)
            const timestamp = new Date().toISOString();
            bufferedLogWrite(debugLogFile, `${timestamp} [blocked][${simplifiedCurrentUrl}] ${reqUrl} (${patternSource} pattern: ${matchedPattern})\n`);
          }
          
          // NEW: Check if even_blocked is enabled and this URL matches filter regex
          if (evenBlocked) {
            // reqDomain already defined above
            if (reqDomain && !matchesIgnoreDomain(reqDomain, ignoreDomains)) {
              for (const re of regexes) {
                if (re.test(reqUrl)) {
                  const evenBlockedRegexPattern = re.source;
                  const resourceType = request.resourceType();

                  // Apply same filtering logic as unblocked requests
                  if (!allowedResourceTypesSet || allowedResourceTypesSet.has(resourceType)) {
                    if (dryRunMode) {
                      addDryRunMatch(matchedDomains, {
                        regex: evenBlockedRegexPattern,
                        domain: reqDomain,
                        resourceType: resourceType,
                        fullUrl: reqUrl,
                        isFirstParty: isFirstParty,
                        wasBlocked: true
                      });
                    } else {
                      addMatchedDomain(reqDomain, resourceType, fullSubdomain);
                    }
                    matchedRegexPatterns.add(evenBlockedRegexPattern);

                    if (siteConfig.verbose === 1) {
                      const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
                      console.log(formatLogMessage('match', `[${simplifiedCurrentUrl}] ${reqUrl} matched regex: ${evenBlockedRegexPattern} and resourceType: ${resourceType}${resourceInfo}`));
                    }
                    if (dumpUrls) {
                      const timestamp = new Date().toISOString();
                      const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
                      bufferedLogWrite(matchedUrlsLogFile, `${timestamp} [match][${simplifiedCurrentUrl}] ${reqUrl} (resourceType: ${resourceType})${resourceInfo} [BLOCKED BUT ADDED]\n`);
                    }
                    break; // Only match once per URL
                  }
                }
              }
            }
          }
          
          request.abort('blockedbyclient');
          return;
        }

      
        if (!reqDomain) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Skipping request with unparseable URL: ${reqUrl}`));
          }
          request.continue();
          return;
        }

      // Skip matching if this full subdomain is one of the redirect intermediaries
      if (redirectDomainsToExclude && redirectDomainsToExclude.includes(fullSubdomain)) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Skipping redirect intermediary domain: ${reqDomain}`));
          }
          request.continue();
          return;
        }

        // Early ignoreDomains gate — skip regex + dig/whois entirely for domains
        // in the ignoreDomains list (or dynamically-ignored ones populated by
        // ignoreDomainsByUrl above). Mirrors the popup handler's early gate so
        // the main path doesn't waste a dig/whois lookup on domains that
        // post-processing/output filters will strip anyway.
        if (matchesIgnoreDomain(reqDomain, ignoreDomains)) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Skipping ignoreDomains match: ${reqDomain}`));
          }
          request.continue();
          return;
        }

        // === ENHANCED REGEX MATCHING WITH AND/OR LOGIC ===
        let regexMatched = false;
        let matchedRegexPattern = null;

        if (regexes.length > 0) {
          if (useRegexAnd) {
            // AND logic: ALL regex patterns must match the same URL
            const allMatch = regexes.every(re => re.test(reqUrl));
            if (allMatch) {
              regexMatched = true;
              matchedRegexPattern = regexes.map(re => re.source).join(' AND ');
              if (forceDebug) {
                console.log(formatLogMessage('debug', `URL ${reqUrl} matched ALL regex patterns (AND logic)`));
              }
            }
          } else {
            // OR logic: ANY regex pattern can match (original behavior)
            for (const re of regexes) {
              if (re.test(reqUrl)) {
                regexMatched = true;
                matchedRegexPattern = re.source;
                break;
              }
            }
          }
        }

        if (regexMatched) {
            const resourceType = request.resourceType();
            
           // *** UNIVERSAL RESOURCE TYPE FILTER ***
           // Check resourceTypes filter FIRST, before ANY processing (nettools, searchstring, immediate matching)
           if (allowedResourceTypesSet && allowedResourceTypesSet.size > 0) {
             if (!allowedResourceTypesSet.has(resourceType)) {
               if (forceDebug) {
                 console.log(formatLogMessage('debug', `URL ${reqUrl} matches regex but resourceType '${resourceType}' not in allowed types [${Array.from(allowedResourceTypesSet).join(', ')}]. Skipping ALL processing.`));
               }
               // Skip this URL entirely - doesn't match required resource types
               request.continue();
               return;
             }
           }
           
           // Check party filtering AFTER regex match but BEFORE domain processing
           if (isFirstParty && (siteConfig.firstParty === false || siteConfig.firstParty === 0)) {
             if (forceDebug) {
               console.log(formatLogMessage('debug', `Skipping first-party match: ${reqUrl} (firstParty disabled)`));
             }
             // Skip this URL - it's first-party but firstParty is disabled
             request.continue();
             return;
           }
           if (!isFirstParty && (siteConfig.thirdParty === false || siteConfig.thirdParty === 0)) {
             if (forceDebug) {
               console.log(formatLogMessage('debug', `Skipping third-party match: ${reqUrl} (thirdParty disabled)`));
             }
             // Skip this URL - it's third-party but thirdParty is disabled
             request.continue();
             return;
           }
 
            // REMOVED: Check if this URL matches any blocked patterns - if so, skip detection but still continue browser blocking
            // This check is no longer needed here since even_blocked handles it above
            
          // Check if nettools validation is required - if so, NEVER add domains immediately
          if (hasNetTools) {
            // Call nettools handler BEFORE exiting
            if (hasNetTools && !hasSearchString && !hasSearchStringAnd) {
              // Create and execute nettools handler
              const netToolsHandler = createNetToolsHandler({
                whoisTerms,
                whoisOrTerms,
               processedWhoisDomains: globalProcessedWhoisDomains,
               processedDigDomains: globalProcessedDigDomains,
                whoisDelay: siteConfig.whois_delay !== undefined ? siteConfig.whois_delay : whois_delay,
                whoisServer,
                whoisServerMode: siteConfig.whois_server_mode || whois_server_mode,
                debugLogFile,
                digTerms,
                digOrTerms,
                digRecordType,
                digSubdomain: siteConfig.dig_subdomain === true,
                dryRunCallback: dryRunMode ? createEnhancedDryRunCallback(matchedDomains, forceDebug) : null,
                matchedDomains,
                addMatchedDomain,
                isDomainAlreadyDetected: isLocallyDetected,
                onWhoisResult: smartCache ? (domain, result) => smartCache.cacheNetTools(domain, 'whois', result) : undefined,
                onDigResult: smartCache ? (domain, result, recordType) => smartCache.cacheNetTools(domain, 'dig', result, recordType) : undefined,
                cachedWhois: smartCache ? smartCache.getCachedNetTools(reqDomain, 'whois') : null,
                cachedDig: smartCache ? smartCache.getCachedNetTools(reqDomain, 'dig', digRecordType) : null,
                currentUrl,
                getRootDomain,
                siteConfig,
                dumpUrls,
                matchedUrlsLogFile,
                forceDebug,
                fs,
                ignoreDomains,
                matchesIgnoreDomain
              });

              // Execute nettools check asynchronously
              const originalDomain = fullSubdomain;
              trackNetToolsHandler(() => netToolsHandler(reqDomain, originalDomain));
            }
            if (forceDebug) {
              console.log(formatLogMessage('debug', `${reqUrl} has nettools validation required - skipping immediate add`));
            }
            request.continue();
            return;
          }
           
           // If NO searchstring AND NO nettools are defined, match immediately (existing behavior)
           if (!hasSearchString && !hasSearchStringAnd && !hasNetTools) {
             if (dryRunMode) {
               addDryRunMatch(matchedDomains, {
                 regex: matchedRegexPattern,
                 domain: reqDomain,
                 resourceType: resourceType,
                 fullUrl: reqUrl,
                 isFirstParty: isFirstParty
               });
             } else {
               addMatchedDomain(reqDomain, resourceType);
             }
             if (matchedRegexPattern) matchedRegexPatterns.add(matchedRegexPattern);
             if (siteConfig.verbose === 1) {
               const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
              console.log(formatLogMessage('match', `[${simplifiedCurrentUrl}] ${reqUrl} matched regex: ${matchedRegexPattern} and resourceType: ${resourceType}${resourceInfo}`));
             }
             if (dumpUrls) {
               const timestamp = new Date().toISOString();
               const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
               bufferedLogWrite(matchedUrlsLogFile, `${timestamp} [match][${simplifiedCurrentUrl}] ${reqUrl} (resourceType: ${resourceType})${resourceInfo}\n`);
             }
            } else if (hasNetTools && !hasSearchString && !hasSearchStringAnd) {
             // If nettools are configured (whois/dig), perform checks on the domain
             // Skip nettools check if full subdomain was already detected in THIS scan
             if (localDetectedDomains.has(fullSubdomain)) {
               if (forceDebug) {
                 console.log(formatLogMessage('debug', `Skipping nettools check for already detected subdomain: ${fullSubdomain}`));
               }
               // Skip to next URL
               request.continue();
               return;
             }
             
             if (forceDebug) {
               console.log(formatLogMessage('debug', `${reqUrl} matched regex ${matchedRegexPattern} and resourceType ${resourceType}, queued for nettools check`));
             }

             // IMPORTANT: Do NOT add domain immediately when nettools validation is required
             // The nettools handler will add the domain only if validation passes
             if (forceDebug) {
               console.log(formatLogMessage('debug', `Domain ${reqDomain} queued for mandatory nettools validation (dig: ${JSON.stringify(siteConfig.dig)})`));
             }

             if (dryRunMode) {
               addDryRunMatch(matchedDomains, {
                 regex: matchedRegexPattern,
                 domain: reqDomain,
                 resourceType: resourceType,
                 fullUrl: reqUrl,
                 isFirstParty: isFirstParty,
                 needsNetToolsCheck: true
               });
             }
             
             // Create and execute nettools handler
             // Check smart cache for nettools results (if cache is enabled)
             const cachedWhois = smartCache ? smartCache.getCachedNetTools(reqDomain, 'whois') : null;
             const cachedDig = smartCache ? smartCache.getCachedNetTools(reqDomain, 'dig', digRecordType) : null;
             
             if ((cachedWhois || cachedDig) && forceDebug) {
               console.log(formatLogMessage('debug', `${SMART_CACHE_TAG} Using cached nettools results for ${reqDomain}`));
             }
             
             // Create nettools handler with cache callbacks (if cache is enabled)
             const netToolsHandler = createNetToolsHandler({
               whoisTerms,
               whoisOrTerms,
               processedWhoisDomains: globalProcessedWhoisDomains,
               processedDigDomains: globalProcessedDigDomains,
               whoisDelay: siteConfig.whois_delay !== undefined ? siteConfig.whois_delay : whois_delay, // Site-specific or global fallback
	       whoisServer, // Pass whois server configuration
               whoisServerMode: siteConfig.whois_server_mode || whois_server_mode,
               debugLogFile,
               digTerms,
               digOrTerms,
               digRecordType,
               digSubdomain: siteConfig.dig_subdomain === true,
               // Add dry run callback for nettools results
               dryRunCallback: dryRunMode ? createEnhancedDryRunCallback(matchedDomains, forceDebug) : null,
               matchedDomains,
               addMatchedDomain,
               isDomainAlreadyDetected: isLocallyDetected,
               // Add cache callbacks if smart cache is available and caching is enabled
               onWhoisResult: smartCache ? (domain, result) => {
                 smartCache.cacheNetTools(domain, 'whois', result);
               } : undefined,
               onDigResult: smartCache ? (domain, result, recordType) => {
                 smartCache.cacheNetTools(domain, 'dig', result, recordType);
               } : undefined,
               cachedWhois,
               cachedDig,
               currentUrl,
               getRootDomain,
               siteConfig,
               dumpUrls,
               matchedUrlsLogFile,
               forceDebug,
               fs,
               ignoreDomains,
               matchesIgnoreDomain
             });

             // Execute nettools check asynchronously
            const originalDomain = fullSubdomain; // Use full subdomain for nettools
            trackNetToolsHandler(() => netToolsHandler(reqDomain, originalDomain));

             // Do NOT continue processing this request for immediate domain addition
             // The nettools handler is responsible for adding the domain if validation passes
             if (forceDebug) {
               console.log(formatLogMessage('debug', `Request processing halted for ${reqUrl} - awaiting nettools validation`));
             }
           } else {
             // If searchstring or searchstring_and IS defined (with or without nettools), queue for content checking
             // Skip searchstring check if full subdomain was already detected in THIS scan
             if (localDetectedDomains.has(fullSubdomain)) {
               if (forceDebug) {
                 console.log(formatLogMessage('debug', `Skipping searchstring check for already detected subdomain: ${fullSubdomain}`));
               }
               // Skip to next URL
               request.continue();
               return;
             }
             if (forceDebug) {
               const searchType = hasSearchStringAnd ? 'searchstring_and' : 'searchstring';
               console.log(formatLogMessage('debug', `${reqUrl} matched regex ${matchedRegexPattern} and resourceType ${resourceType}, queued for ${searchType} content search`));
             }
             if (dryRunMode) {
               addDryRunMatch(matchedDomains, {
                 regex: matchedRegexPattern,
                 domain: reqDomain,
                 resourceType: resourceType,
                 fullUrl: reqUrl,
                 isFirstParty: isFirstParty,
                 needsSearchStringCheck: true
               });
             }
             // If we have BOTH searchstring AND nettools, ensure nettools validation still happens
             if (hasNetTools) {
               if (forceDebug) {
                 console.log(formatLogMessage('debug', `${reqUrl} requires both content and nettools validation`));
               }
             }
           }
           
           // If curl is enabled, download and analyze content immediately
           if (useCurl) {
             // Check bypass_cache before attempting cache lookup (curl mode)
             let cachedContent = null;
             if (!shouldBypassCacheForUrl(reqUrl, siteConfig)) {
               // Check request cache first if smart cache is available and caching is enabled
               cachedContent = smartCache ? smartCache.getCachedRequest(reqUrl, {
                 method: 'GET',
                 headers: { 'user-agent': curlUserAgent },
                 siteConfig: siteConfig
               }) : null;
             }
             
             if (cachedContent && forceDebug) {
               console.log(formatLogMessage('debug', `${SMART_CACHE_TAG} Using cached response content for ${reqUrl.substring(0, 50)}...`));
               // Process cached content instead of fetching
             } else {
             try {
               // Use grep handler if both grep and searchstring/searchstring_and are enabled
               if (useGrep && (hasSearchString || hasSearchStringAnd)) {
                 const grepHandler = createGrepHandler({
                   regexes,
                   searchStrings,
                   searchStringsAnd,
                   matchedDomains,
                   addMatchedDomain, // Pass the helper function
                   isDomainAlreadyDetected: isLocallyDetected,
                   onContentFetched: smartCache && !ignoreCache ? (url, content) => {
                     // Only cache if not bypassing cache
                     if (!shouldBypassCacheForUrl(url, siteConfig)) {
                       smartCache.cacheRequest(url, { method: 'GET', siteConfig }, { body: content, status: 200 });
                     }
                   } : undefined,
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
                   // Pass both flags separately — createGrepHandler now
                   // applies AND logic when hasSearchStringAnd is set.
                   // Previously OR'd into hasSearchString and the AND
                   // patterns were silently dropped.
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
                 const curlHandlerFromCurlModule = createCurlModuleHandler({
                   searchStrings,
                   searchStringsAnd,
                   hasSearchStringAnd,
                   regexes,
                   matchedDomains,
                   addMatchedDomain,
                   isDomainAlreadyDetected: isLocallyDetected,
                   onContentFetched: smartCache && !ignoreCache ? (url, content) => {
                     // Only cache if not bypassing cache
                     if (!shouldBypassCacheForUrl(url, siteConfig)) {
                       smartCache.cacheRequest(url, { method: 'GET', siteConfig }, { body: content, status: 200 });
                     }
                   } : undefined,
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
                   hasSearchString: hasSearchString || hasSearchStringAnd
                 });
                 
                 setImmediate(() => curlHandlerFromCurlModule(reqUrl));
               }
             } catch (curlErr) {
               if (forceDebug) {
                 console.log(formatLogMessage('debug', `Curl handler failed for ${reqUrl}: ${curlErr.message}`));
               }
             }
             }
            } else if (useGrep && (hasSearchString || hasSearchStringAnd)) {
             // Use grep with response handler (no curl)
             if (forceDebug) {
               console.log(formatLogMessage('debug', `${GREP_RESPONSE_TAG} Queuing ${reqUrl} for grep analysis via response handler`));
             }
             
             // Queue for grep processing via response handler
             // The response handler will download content and call grep
             if (dryRunMode) {
               matchedDomains.get('dryRunMatches').push({
                 regex: matchedRegexPattern,
                 domain: reqDomain,
                 resourceType: resourceType,
                 fullUrl: reqUrl,
                 isFirstParty: isFirstParty,
                 needsGrepCheck: true
               });
             }
             
             // Don't process immediately - let response handler do the work
             if (forceDebug) {
               console.log(formatLogMessage('debug', `URL ${reqUrl} queued for grep analysis via response handler`));
             }
           }
          // No break needed since we've already determined if regex matched
        }
        request.continue();
      });

      // Mark page as actively processing network requests
      updatePageUsage(page, true);

     // Add response handler if searchstring is defined and either no curl, or grep without curl
     if ((hasSearchString || hasSearchStringAnd) && (!useCurl || (useGrep && !useCurl))) {
       const responseHandler = createResponseHandler({
         searchStrings,
         searchStringsAnd,
         hasSearchStringAnd,
         regexes,
         matchedDomains,
         addMatchedDomain, // Pass the helper function
         bypassCache: (url) => shouldBypassCacheForUrl(url, siteConfig),
         isDomainAlreadyDetected: isLocallyDetected,
         onContentFetched: smartCache && !ignoreCache ? (url, content) => {
           // Only cache if not bypassing cache
           if (!shouldBypassCacheForUrl(url, siteConfig)) {
             smartCache.cacheRequest(url, { method: 'GET', siteConfig }, { body: content, status: 200 });
           }
         } : undefined,
         currentUrl,
         perSiteSubDomains,
         useGrep, // Pass grep flag to response handler
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
      
      // Create optimized interaction configuration for this site
      const interactionConfig = createInteractionConfig(currentUrl, siteConfig);
      
      // Mark page as actively processing interactions
      updatePageUsage(page, true);
      
      // --- Runtime CSS Element Blocking (Fallback) ---
      // Apply CSS blocking after page load as a fallback in case evaluateOnNewDocument didn't work
      if (cssBlockedSelectors && Array.isArray(cssBlockedSelectors) && cssBlockedSelectors.length > 0) {
        // FIX: Check page state before evaluation
        if (page && !page.isClosed()) {
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
            console.warn(formatLogMessage('warn', `${CSS_BLOCKED_TAG} Failed to apply runtime CSS blocking for ${currentUrl}: ${cssRuntimeErr.message}`));
          }
        }
      }

      try {
        // Use custom goto options if provided, otherwise default to 'load'
        // load                  Wait for all resources (default)
        // domcontentloaded      Wait for DOM only
        // networkidle0          Wait until 0 network requests for 500ms
        // networkidle2          Wait until ≤2 network requests for 500ms
        
        // Note: For Puppeteer 22.x compatibility, avoid deprecated timeout patterns
        // Use explicit Promise-based timeouts instead of page.waitForTimeout()

        // Use faster defaults for sites with long timeouts to improve responsiveness
        const isFastSite = timeout <= TIMEOUTS.FAST_SITE_THRESHOLD;
        const defaultWaitUntil = 'domcontentloaded'; // Always use faster option in Puppeteer 23.x
 
        // Enhanced navigation options for Puppeteer 23.x
        const defaultGotoOptions = {
          waitUntil: defaultWaitUntil,
          timeout: Math.min(timeout, TIMEOUTS.DEFAULT_PAGE), // Cap at default page timeout
          // Puppeteer 23.x: Fixed referrer header handling
          ...(siteConfig.referrer_headers && (() => {
            const referrerUrl = getReferrerForUrl(currentUrl, siteConfig.referrer_headers, siteConfig.referrer_disable, forceDebug);
            return referrerUrl 
              ? { referer: referrerUrl } 
              : {};
          })())
        };
        const gotoOptions = siteConfig.goto_options 
          ? { ...defaultGotoOptions, ...siteConfig.goto_options } : defaultGotoOptions;

        // Enhanced navigation with redirect handling - passes existing gotoOptions
        let navigationResult;
        try {
          navigationResult = await navigateWithRedirectHandling(page, currentUrl, siteConfig, gotoOptions, forceDebug, formatLogMessage);
        } catch (navErr) {
          // Only retry on genuine timeouts, not chrome-error:// redirects
          let pageUrl = '';
          try { if (!page.isClosed()) pageUrl = page.url(); } catch {}
          const isPopupFailure = navErr.message.includes('chrome-error://') || navErr.message.includes('invalid URL') ||
            pageUrl.startsWith('chrome-error://') || pageUrl === 'about:blank';
          if ((navErr.message.includes('timeout') || navErr.message.includes('Timeout')) && !isPopupFailure) {
            if (forceDebug) console.log(formatLogMessage('debug', `Navigation timeout, retrying with waitUntil:networkidle2 for ${currentUrl}`));
            const fallbackOptions = { ...gotoOptions, waitUntil: 'networkidle2', timeout: Math.min(timeout, 10000) };
            navigationResult = await navigateWithRedirectHandling(page, currentUrl, siteConfig, fallbackOptions, forceDebug, formatLogMessage);
          } else {
            throw navErr;
          }
        }
        
        const { finalUrl, redirected, redirectChain, originalUrl, redirectDomains, httpStatus, cfRay } = navigationResult;
        
        // Check for same-page reload loops BEFORE redirect processing
        const loadCount = pageLoadHistory.get(currentUrl) || 0;
        pageLoadHistory.set(currentUrl, loadCount + 1);
        
        if (loadCount >= MAX_SAME_PAGE_LOADS) {
          const samePageError = `Same page loaded ${loadCount + 1} times: ${currentUrl}`;
          console.warn(`⚠ ${samePageError} - possible infinite reload loop`);
          throw new Error(`Same-page loop detected: ${samePageError}`);
        }
        
        currentPageUrl = finalUrl || currentUrl;
        
        // Handle redirect to new domain
        if (redirected) {
          const originalDomain = safeGetDomain(originalUrl);
          const finalDomain = safeGetDomain(finalUrl);

          // Increment redirect counter
          redirectCount++;
          
          // Check for redirect loops
          if (redirectHistory.has(finalUrl)) {
            const loopError = `Redirect loop detected: ${finalUrl} already visited in chain`;
            console.warn(`⚠ ${loopError} for ${currentUrl}`);
            throw new Error(loopError);
          }
          
          // Check redirect depth
          if (redirectCount > MAX_REDIRECT_DEPTH) {
            const depthError = `Maximum redirect depth (${MAX_REDIRECT_DEPTH}) exceeded`;
            console.warn(`⚠ ${depthError} for ${currentUrl}`);
            throw new Error(`${depthError}: ${redirectCount} redirects`);
          }
          
          // Add URLs to history
          redirectHistory.add(currentUrl);
          redirectHistory.add(finalUrl);

          // Add redirect destination to first-party domains immediately
          if (finalDomain) {
            firstPartyDomains.add(finalDomain);
          }
          
          // Also add any intermediate redirect domains as first-party
          if (redirectDomains && redirectDomains.length > 0) {
            redirectDomains.forEach(domain => {
              const rootDomain = safeGetDomain(`http://${domain}`, false);
              if (rootDomain) firstPartyDomains.add(rootDomain);
            });
          }
          
          if (originalDomain !== finalDomain) {
            const isPopupRedirect = !finalUrl || finalUrl === 'about:blank' || finalUrl.startsWith('chrome-error://');
            if (!silentMode && !isPopupRedirect) {
              console.log(`🔄 Redirect detected: ${originalDomain} → ${finalDomain}`);
            }
            
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Full redirect chain: ${redirectChain.join(' → ')}`));
              console.log(formatLogMessage('debug', `All first-party domains: ${Array.from(firstPartyDomains).join(', ')}`));
            }
            
            // VALIDATION: Only update currentUrl if finalUrl is a valid HTTP/HTTPS URL
            if (shouldProcessUrl(finalUrl, forceDebug)) {
              // Update currentUrl for all subsequent processing to use the final redirected URL
              currentUrl = finalUrl;

              // IMPORTANT: Also update effectiveCurrentUrl for first-party detection
              effectiveCurrentUrl = finalUrl;
              finalUrlAfterRedirect = finalUrl;
              
              // Update the redirect domains to exclude from matching
              if (redirectDomains && redirectDomains.length > 0) {
                redirectDomainsToExclude = redirectDomains;
                
                if (forceDebug) {
                  console.log(formatLogMessage('debug', `Excluding redirect domains from matching: ${redirectDomains.join(', ')}`));
                }
              }
            } else {
              // Invalid final URL (ad popup redirect) - continue with original URL
              if (forceDebug) {
                console.log(formatLogMessage('debug', `Popup redirect ignored: ${originalDomain} → ${finalUrl}, keeping original: ${originalUrl}`));
              }
              // Continue with original URL — requests captured before the redirect are still valid
            }
          }
        }
        
        siteCounter++;

        // Enhanced Cloudflare handling with parallel detection
        // Only run parallel detection if cloudflare handling is explicitly configured
        const hasCloudflareConfig = siteConfig.cloudflare_bypass || siteConfig.cloudflare_phish;
        if (hasCloudflareConfig && siteConfig.cloudflare_parallel_detection !== false) {
          try {
            const parallelResult = await parallelChallengeDetection(page, forceDebug);
            if (parallelResult.hasAnyChallenge && forceDebug) {
              console.log(formatLogMessage('debug', `[cloudflare] Parallel detection found: ${parallelResult.challenges.join(', ')}`));
            }
          } catch (parallelErr) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `[cloudflare] Parallel detection failed: ${parallelErr.message}`));
            }
          }
        }

        // Handle all Cloudflare protections using the enhanced module. Pass
        // httpStatus and cfRay captured at goto time so the outcome log can
        // surface them — Puppeteer's response object is only available
        // immediately after page.goto, so handleCloudflareProtection can't
        // recover them from `page` alone.
        const cloudflareResult = await handleCloudflareProtection(page, currentUrl, siteConfig, forceDebug, { httpStatus, cfRay });

        if (cloudflareResult.cloudflareErrorPage) cloudflareScanStats.errorPages++;

        // Check if Cloudflare handling exceeded max retries and should terminate processing
        if (!cloudflareResult.overallSuccess && 
            (cloudflareResult.phishingWarning?.maxRetriesExceeded || 
             cloudflareResult.verificationChallenge?.maxRetriesExceeded ||
             cloudflareResult.phishingWarning?.loopDetected ||
             cloudflareResult.verificationChallenge?.loopDetected)) {
          throw new Error(`Cloudflare protection handling failed: ${cloudflareResult.errors.join('; ')}`);
        }

        // Check for retry recommendations
        if (cloudflareResult.errors && cloudflareResult.errors.length > 0) {
          const hasRetryableErrors = cloudflareResult.errors.some(err => 
            err.includes('timeout') || err.includes('network')
          );
          
          if (hasRetryableErrors && forceDebug) {
            console.log(formatLogMessage('debug', '[cloudflare] Errors may be retryable - consider enabling retry logic'));
          }
        }        

        // Log retry information if debug mode is enabled
        if (forceDebug && (cloudflareResult.phishingWarning?.attempts > 1 || cloudflareResult.verificationChallenge?.attempts > 1)) {
          console.log(formatLogMessage('debug', `[cloudflare] Total attempts - Phishing: ${cloudflareResult.phishingWarning?.attempts || 0}, Challenge: ${cloudflareResult.verificationChallenge?.attempts || 0}`));
        }

        if (!cloudflareResult.overallSuccess) {
          console.warn(`⚠ [cloudflare] Protection handling failed for ${currentUrl}:`);
          cloudflareResult.errors.forEach(error => {
            console.warn(`   - ${error}`);
          });
          // Continue with scan despite Cloudflare issues
        } else if (cloudflareResult.verificationChallenge?.attempted && cloudflareResult.verificationChallenge?.success && forceDebug) {
          // Require attempted === true so we don't log "Challenge solved using:
          // undefined" for pages that had no challenge to solve (success: true
          // is the natural state for that case).
          console.log(formatLogMessage('debug', `[cloudflare] Challenge solved using: ${cloudflareResult.verificationChallenge.method}`));
        }

        // Handle flowProxy protection if enabled
        if (flowproxyDetection) {
          const flowproxyResult = await handleFlowProxyProtection(page, currentUrl, siteConfig, forceDebug);

          if (flowproxyResult.flowProxyDetection.detected) {
            console.log(`🛡️  [flowproxy] FlowProxy protection detected on ${currentUrl}`);

            if (!flowproxyResult.overallSuccess) {
              console.warn(`⚠ [flowproxy] Protection handling failed for ${currentUrl}:`);
              flowproxyResult.errors.forEach(error => {
                console.warn(`   - ${error}`);
              });
            }

            if (flowproxyResult.warnings.length > 0) {
              flowproxyResult.warnings.forEach(warning => {
                console.warn(`⚠ [flowproxy] ${warning}`);
              });
            }
          }
        }

        console.log(formatLogMessage('info', `${messageColors.loaded('Loaded:')} (${siteCounter}/${totalUrls}) ${currentUrl}`));

        // FIX: Check page state before evaluation
        if (page && !page.isClosed()) {
          try {
            await page.evaluate(() => { console.log('Safe to evaluate on loaded page.'); });
          } catch (evalErr) {
            // Page closed during evaluation - safe to ignore
          }
        }
        
        // Mark page as processing frames
        updatePageUsage(page, true);
        
        // Wait for iframes to load and log them
        if (forceDebug) {
          try {
            // Use fast timeout helper for compatibility  
            await fastTimeout(TIMEOUTS.FRAME_LOAD_WAIT); // Give iframes time to load
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

      // Page finished initial loading - mark as idle
      updatePageUsage(page, false);
      } catch (err) {
        // Handle detached frame errors during navigation
        if (err.message.includes('Navigating frame was detached') || 
            err.message.includes('Attempted to use detached')) {
          // Silent handling - this is expected for iframe-heavy sites
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Frame detachment during navigation (expected): ${currentUrl}`));
          }
          // Continue with partial success - don't fail completely
          currentPageUrl = currentUrl;
          siteCounter++;
          // Skip to post-navigation processing
        } else {
        // Enhanced error handling for redirect timeouts using redirect module
        const timeoutResult = await handleRedirectTimeout(page, currentUrl, err, safeGetDomain, forceDebug, formatLogMessage);
        
        if (timeoutResult.success) {
          const isPopupRedirect = timeoutResult.finalUrl && (timeoutResult.finalUrl === 'about:blank' || timeoutResult.finalUrl.startsWith('chrome-error://'));
          if (!isPopupRedirect) {
            console.log(`⚠ Partial redirect timeout recovered: ${safeGetDomain(currentUrl)} → ${safeGetDomain(timeoutResult.finalUrl)}`);
          }
          currentUrl = timeoutResult.finalUrl; // Use the partial redirect URL
          siteCounter++;
          // Continue processing with the redirected URL instead of throwing error
        } else {
          // Detect proxy-specific failures and provide clear diagnostics
          if (needsProxy(siteConfig) && err.message) {
            const proxyErrors = [
              'ERR_PROXY_CONNECTION_FAILED',
              'ERR_SOCKS_CONNECTION_FAILED',
              'ERR_TUNNEL_CONNECTION_FAILED',
              'ERR_PROXY_AUTH_UNSUPPORTED',
              'ERR_PROXY_AUTH_REQUESTED',
              'ERR_SOCKS_CONNECTION_HOST_UNREACHABLE',
              'ERR_PROXY_CERTIFICATE_INVALID',
              'ERR_NO_SUPPORTED_PROXIES'
            ];
            const proxyErr = proxyErrors.find(e => err.message.includes(e));
            if (proxyErr) {
              const info = getProxyInfo(siteConfig);
              console.error(formatLogMessage('error', `${PROXY_TAG} ${proxyErr} — proxy: ${info} — URL: ${currentUrl}`));
              console.error(formatLogMessage('error', `${PROXY_TAG} Check: is the proxy running? Are credentials correct? Is the target reachable from the proxy?`));
            }
          }
          console.error(formatLogMessage('error', `Failed on ${currentUrl}: ${err.message}`));
          throw err;
        }
      }
      }

      const delayMs = siteConfig.delay || DEFAULT_DELAY;

      // Optimized delays for Puppeteer 23.x performance
      const isFastSite = timeout <= TIMEOUTS.FAST_SITE_THRESHOLD;
      const networkIdleTime = TIMEOUTS.NETWORK_IDLE;  // Balanced: 2s for reliable network detection
      const networkIdleTimeout = Math.min(timeout / 2, TIMEOUTS.NETWORK_IDLE_MAX);  // Balanced: 10s timeout
      // Post-networkidle delay cap. Default (2s) keeps fast sites fast. Opt
      // in with `delay_uncapped: true` to honor the configured `delay` up to
      // half the per-URL timeout — useful for sites with setTimeout-deferred
      // lazy ad/tracker loaders (weather.com, cbssports.com class) where
      // late requests fire well past the 2s window. See also the per-URL
      // drainPendingNetTools() which awaits in-flight dig/whois handlers
      // before the matchedDomains snapshot regardless of this flag.
      const actualDelay = siteConfig.delay_uncapped === true
        ? Math.min(delayMs, Math.floor(timeout / 2))
        : Math.min(delayMs, TIMEOUTS.NETWORK_IDLE);

      // Build delay promise (networkIdle + delay + optional flowProxy delay)
      const delayPromise = (async () => {
        if (page && !page.isClosed()) {
          try {
            await page.waitForNetworkIdle({
              idleTime: networkIdleTime,
              timeout: networkIdleTimeout
            });
          } catch (networkIdleErr) {
            if (forceDebug) console.log(formatLogMessage('debug', `Network idle wait failed: ${networkIdleErr.message}`));
          }
        }
        await fastTimeout(actualDelay);
        if (flowproxyDetection) {
          const additionalDelay = Math.min(siteConfig.flowproxy_additional_delay || 3000, 3000);
          if (forceDebug) console.log(formatLogMessage('debug', `Applying flowProxy additional delay: ${additionalDelay}ms`));
          await fastTimeout(additionalDelay);
        }
      })();

      // Build interaction promise — runs concurrently with delay
      const interactPromise = (async () => {
        if (!(interactEnabled && !disableInteract)) return;
        if (forceDebug) console.log(formatLogMessage('debug', `interaction simulation enabled for ${currentUrl}`));

        // Mark page as processing during interactions
        updatePageUsage(page, true);
        const INTERACTION_HARD_TIMEOUT = 15000;

        // Check if ghost-cursor mode is enabled for this site
        const ghostConfig = resolveGhostCursorConfig(siteConfig, globalGhostCursor, forceDebug);

        try {
          if (ghostConfig) {
            // Ghost-cursor mode: Bezier-based mouse movements
            if (forceDebug) console.log(formatLogMessage('debug', `${GHOST_CURSOR_TAG} Using ghost-cursor for ${currentUrl}`));
            const cursor = createGhostCursor(page, { forceDebug });
            if (cursor) {
              await Promise.race([
                (async () => {
                  const viewport = page.viewport() || { width: 1200, height: 800 };
                  const ghostDuration = ghostConfig.duration || 2000;
                  const ghostStart = Date.now();
                  const ghostTimeLeft = () => ghostDuration - (Date.now() - ghostStart);

                  // Time-based Bezier mouse movements — runs for ghostDuration ms
                  while (ghostTimeLeft() > 200) {
                    const toX = Math.floor(Math.random() * (viewport.width - 100)) + 50;
                    const toY = Math.floor(Math.random() * (viewport.height - 100)) + 50;
                    await ghostMove(cursor, toX, toY, {
                      moveSpeed: ghostConfig.moveSpeed,
                      overshootThreshold: ghostConfig.overshootThreshold,
                      forceDebug
                    });
                    if (ghostTimeLeft() > 100) {
                      await new Promise(r => setTimeout(r, 25 + Math.random() * 75));
                    }
                  }
                  if (ghostTimeLeft() > 100 && Math.random() < 0.3) {
                    await ghostRandomMove(cursor, { forceDebug });
                  }
                  if (interactionConfig.includeElementClicks && ghostTimeLeft() > 100) {
                    const clickX = Math.floor(viewport.width * 0.2 + Math.random() * viewport.width * 0.6);
                    const clickY = Math.floor(viewport.height * 0.2 + Math.random() * viewport.height * 0.6);
                    await ghostClick(cursor, { x: clickX, y: clickY }, {
                      hesitate: ghostConfig.hesitate,
                      forceDebug
                    });
                  }
                  if (interactionConfig.includeScrolling) {
                    await performPageInteraction(page, currentUrl, {
                      ...interactionConfig,
                      mouseMovements: 0,
                      includeElementClicks: false
                    }, forceDebug);
                  }
                })(),
                new Promise((_, reject) => setTimeout(() => reject(new Error('ghost-cursor interaction hard timeout')), INTERACTION_HARD_TIMEOUT))
              ]);
            } else {
              if (forceDebug) console.log(formatLogMessage('debug', '[ghost-cursor] Falling back to built-in mouse'));
              await Promise.race([
                performPageInteraction(page, currentUrl, interactionConfig, forceDebug),
                new Promise((_, reject) => setTimeout(() => reject(new Error('interaction hard timeout')), INTERACTION_HARD_TIMEOUT))
              ]);
            }
          } else {
            // Standard built-in mouse interaction
            await Promise.race([
              performPageInteraction(page, currentUrl, interactionConfig, forceDebug),
              new Promise((_, reject) => setTimeout(() => reject(new Error('interaction hard timeout')), INTERACTION_HARD_TIMEOUT))
            ]);
          }
        } catch (interactTimeoutErr) {
          if (forceDebug) console.log(formatLogMessage('debug', `${INTERACTION_TAG} Aborted after ${INTERACTION_HARD_TIMEOUT}ms: ${interactTimeoutErr.message}`));
        }
      })();

      // Run delay and mouse interaction concurrently — mouse moves while page settles
      await Promise.all([delayPromise, interactPromise]);

      // Use fast timeout helper for consistent Puppeteer 23.x compatibility

      // Handle reloads - use force reload mechanism if forcereload is enabled
      // Mark page as processing during reloads
      updatePageUsage(page, true);

      const totalReloads = (siteConfig.reload || 1) - 1; // Subtract 1 because initial load counts as first
      
      // Enhanced forcereload logic: support boolean or domain array
      let useForceReload = false;
      if (siteConfig.forcereload === true) {
        // Original behavior: force reload for all URLs
        useForceReload = true;
      } else if (Array.isArray(siteConfig.forcereload)) {
        // Input validation: filter out invalid entries
        const validDomains = siteConfig.forcereload.filter(domain => {
          if (typeof domain !== 'string') {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Invalid forcereload entry (not string): ${typeof domain} - ${JSON.stringify(domain)}`));
            }
            return false;
          }
          
          if (domain.trim() === '') {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Invalid forcereload entry (empty string)`));
            }
            return false;
          }
          
          return true;
        });
        
        if (validDomains.length === 0) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `No valid domains in forcereload array for ${currentUrl}`));
          }
          useForceReload = false;
        } else {
        // New behavior: force reload only for matching domains
        const currentDomain = safeGetDomain(currentUrl, true); // Get full hostname
        const currentRootDomain = safeGetDomain(currentUrl, false); // Get root domain
        
        useForceReload = validDomains.some(domain => {
          // Enhanced domain cleaning: handle protocols, ports, paths, and normalize case
          let cleanDomain = domain.trim();
          cleanDomain = cleanDomain.replace(/^https?:\/\//, '');  // Remove protocol
          cleanDomain = cleanDomain.replace(/:\d+$/, '');         // Remove port (e.g., :8080)
          cleanDomain = cleanDomain.replace(/\/.*$/, '');         // Remove path
          cleanDomain = cleanDomain.toLowerCase();               // Normalize case
          
          // Additional validation: basic domain format check
          if (!/^[a-z0-9.-]+$/.test(cleanDomain)) {
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Skipping invalid domain format in forcereload: ${domain} -> ${cleanDomain}`));
            }
            return false;
          }
          
          // Check if current URL matches this domain
          // Support both exact hostname match and subdomain match
          if (currentDomain.toLowerCase() === cleanDomain || currentRootDomain.toLowerCase() === cleanDomain) {
            return true;
          }
          
          // Check if current hostname ends with the domain (subdomain match)
          if (currentDomain.toLowerCase().endsWith('.' + cleanDomain)) {
            return true;
          }
          
          return false;
        });
        }
        
        if (forceDebug && useForceReload) {
          console.log(formatLogMessage('debug', `Force reload enabled for ${currentUrl} - matches domain in forcereload list`));
        } else if (forceDebug && validDomains.length > 0) {
          console.log(formatLogMessage('debug', `Force reload not applied for ${currentUrl} - no domain match in [${validDomains.join(', ')}]`));
        }
      }
      // If forcereload is not specified, false, or any other value, useForceReload remains false
      
      if (useForceReload && forceDebug) {
        console.log(formatLogMessage('debug', `Using force reload mechanism for all ${totalReloads + 1} reload(s) on ${currentUrl}`));
      }
      
      for (let i = 1; i <= totalReloads; i++) {
  // Check browser health before attempting reload
  try {
    const browserHealthy = await isQuicklyResponsive(browser, 2000);
    if (!browserHealthy) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Browser unresponsive before reload #${i}, skipping remaining reloads`));
      }
      console.warn(`Browser unresponsive before reload #${i}, skipping remaining reloads`);
      break;
    }
  } catch (healthErr) {
    console.warn(`Browser health check failed before reload #${i}: ${healthErr.message}`);
    break;
  }
        // Check if page is still valid before attempting reload
        let pageStillValid = false;
        try {
    // Add timeout to page validity check
    await Promise.race([
      page.evaluate(() => true),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Page validity check timeout')), 3000)
      )
    ]);
          pageStillValid = true;
        } catch (validityCheck) {
          console.warn(`Page invalid before reload #${i}, skipping remaining reloads`);
          break;
        }
        
        // Use comprehensive cleanup from browserhealth module
        await cleanupPageBeforeReload(page, forceDebug);
        
        // Add stabilization delay after cleanup
        await fastTimeout(1000);

        if (siteConfig.clear_sitedata === true) {
          try {
            // Default reload clear is quick mode (cookies + cache +
            // localStorage + sessionStorage — the storage layers where
            // session-cap tracking typically lives). Sites that put their
            // session cap in IndexedDB / WebSQL / service workers can opt
            // into a full clear-per-reload via clear_sitedata_full_on_reload.
            // Costs ~100-500ms extra per reload and may unregister a
            // service worker the page depends on; off by default.
            const fullOnReload = siteConfig.clear_sitedata_full_on_reload === true;
            const clearResult = await clearSiteData(page, currentUrl, forceDebug, !fullOnReload);
            if (forceDebug) console.log(formatLogMessage('debug', `Cleared site data (${fullOnReload ? 'full' : 'quick'}) before reload #${i} for ${currentUrl}`));
          } catch (reloadClearErr) {
            if (forceDebug) console.log(formatLogMessage('debug', `${CLEAR_SITEDATA_TAG} Before reload failed for ${currentUrl}`));
          }
        }
        
      let reloadSuccess = false;

  // Skip force reload if browser seems unhealthy
  const skipForceReload = i > 2; // After 2 attempts, skip force reload
      
      if (useForceReload && !reloadSuccess && !skipForceReload) {
        // Attempt force reload: disable cache, reload, re-enable cache
          try {
          // Timeout-protected cache disable
          await Promise.race([
            page.setCacheEnabled(false),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Cache disable timeout')), 8000))
          ]);
          
            // Use networkidle2 for force reload to better detect when page is actually loaded
            await page.reload({ waitUntil: 'networkidle2', timeout: Math.min(timeout, 15000) });
          
          // Timeout-protected cache enable
          await Promise.race([
            page.setCacheEnabled(true),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Cache enable timeout')), 8000))
          ]);
         
          reloadSuccess = true;
            if (forceDebug) console.log(formatLogMessage('debug', `Force reload #${i} completed for ${currentUrl}`));

          } catch (forceReloadErr) {
            // Don't warn for timeouts on problematic sites, just fall back silently
            if (forceDebug || !forceReloadErr.message.includes('timeout')) {
              console.warn(messageColors.warn(`[force reload #${i} failed] ${currentUrl}: ${forceReloadErr.message} - falling back to standard reload`));
            }
          reloadSuccess = false; // Ensure we try standard reload
        }
      }
      
      // Fallback to standard reload if force reload failed or wasn't attempted
      if (!reloadSuccess) {
        try {
            // FIX: Check page state before reload validation
            if (page.isClosed()) {
              throw new Error('Page closed before reload check');
            }

            const canReload = await page.evaluate(() => {
              return !!(document && document.body);
            }).catch(() => false);
            
            if (!canReload) {
              throw new Error('Page document invalid for reload');
            }

            // Use networkidle2 with reasonable timeout
      // Use simpler reload for problematic pages
      const reloadOptions = i > 1 
        ? { waitUntil: 'domcontentloaded', timeout: 10000 }  // Simpler after failures
        : { waitUntil: 'networkidle2', timeout: 15000 };     // Full wait first time
      
      await page.reload(reloadOptions);
            
          if (forceDebug) console.log(formatLogMessage('debug', `Standard reload #${i} completed for ${currentUrl}`));
        } catch (standardReloadErr) {
            // Categorize errors into expected vs unexpected
            const isExpectedError = standardReloadErr.message.includes('timeout') ||
                                   standardReloadErr.message.includes('detached Frame') ||
                                   standardReloadErr.message.includes('Attempted to use detached') ||
                                   standardReloadErr.message.includes('Navigating frame was detached') ||
                                   standardReloadErr.message.includes('document invalid') ||
                                   standardReloadErr.message.includes('Page document invalid');
            
            if (!isExpectedError) {
              // Only warn for truly unexpected errors
              console.warn(messageColors.warn(`[standard reload #${i} failed] ${currentUrl}: ${standardReloadErr.message}`));
            } else if (forceDebug) {
              // Expected errors only shown in debug mode
              console.log(formatLogMessage('debug', `[reload #${i}] Expected error for ${currentUrl}: ${standardReloadErr.message}`));
            }
          
          // Check if this is a persistent failure that should skip remaining reloads
            const isPersistentFailure = standardReloadErr.message.includes('detached Frame') ||
                                     standardReloadErr.message.includes('Attempted to use detached') ||
                                     standardReloadErr.message.includes('Navigating frame was detached') ||
                                     standardReloadErr.message.includes('document invalid') ||
                                     standardReloadErr.message.includes('net::ERR_') ||
                                     standardReloadErr.message.includes('Protocol error') ||
                                       standardReloadErr.message.includes('Page crashed');
          
          if (isPersistentFailure) {
            const remainingReloads = totalReloads - i;
            if (remainingReloads > 0 && forceDebug) {
              console.log(formatLogMessage('debug', `Persistent failure detected - skipping ${remainingReloads} remaining reload(s) for ${currentUrl}`));
            }
            // Break out of reload loop to move to next URL faster
            break;
          }
            // For navigation timeouts, we can continue - the page might still be partially loaded
            // Don't break the loop for simple timeouts
          }
        }

      // Post-reload interaction: trigger onclick ad scripts (Monetag etc.)
      // Each reload gives a fresh session with a new random ad domain —
      // without clicks the SDK never fires and we miss those domains.
      if (interactEnabled && !page.isClosed()) {
        try {
          // Brief wait for ad scripts to re-register after reload
          await fastTimeout(800);
          // Quick mouse moves to build movement score (Monetag tracks this)
          const vp = page.viewport() || { width: 1920, height: 1080 };
          const startX = 200 + Math.floor(Math.random() * (vp.width - 400));
          const startY = 200 + Math.floor(Math.random() * (vp.height - 400));
          await page.mouse.move(startX, startY);
          for (let m = 0; m < 2; m++) {
            const endX = 200 + Math.floor(Math.random() * (vp.width - 400));
            const endY = 200 + Math.floor(Math.random() * (vp.height - 400));
            await humanLikeMouseMove(page, startX, startY, endX, endY, { steps: 3, curve: 0.04, jitter: 1 });
          }
          // Content clicks to trigger document-level onclick handlers.
          // Honor siteConfig.interact_click_count so popunder-discovery configs
          // get the same click volume on every reload, not just the initial load.
          // Omit `clicks` when no override is set so performContentClicks uses
          // its CONTENT_CLICK.CLICK_COUNT default (single source of truth).
          // realistic forwards siteConfig.realistic_click; always passed
          // (defaults to false) so realistic mode applies to every reload's
          // clicks, not just the initial pass.
          const postReloadClickOpts = {
            preDelay: 200,
            forceDebug,
            realistic: !!interactionConfig.realistic
          };
          if (interactionConfig.clickCount) postReloadClickOpts.clicks = interactionConfig.clickCount;
          await performContentClicks(page, postReloadClickOpts);
          if (forceDebug) console.log(formatLogMessage('debug', `Post-reload interaction completed for reload #${i}`));
        } catch (postReloadInteractErr) {
          // Non-critical — continue with remaining reloads
          if (forceDebug) console.log(formatLogMessage('debug', `Post-reload interaction failed: ${postReloadInteractErr.message}`));
        }
      }

      // Only add delay if we're continuing with more reloads
      if (i < totalReloads) {
    // Reduce delay for problematic sites
    const adjustedDelay = i > 1 ? Math.min(DEFAULT_DELAY, 2000) : DEFAULT_DELAY;
    await fastTimeout(adjustedDelay);
      }
    }
    
    // Mark page as idle after all processing complete
    updatePageUsage(page, false);

      if (dryRunMode) {
        // Process dry run results using the module
        const dryRunResult = await processDryRunResults(currentUrl, matchedDomains, page, outputFile, dryRunOutput, forceDebug);

        if (!dryRunResult.success) {
          console.warn(messageColors.warn(`Dry run processing failed for ${currentUrl}: ${dryRunResult.error}`));
        }
        
        // Wait a moment for async nettools/searchstring operations to complete
        // Use fast timeout helper for Puppeteer 22.x compatibility
        await fastTimeout(TIMEOUTS.CURL_HANDLER_DELAY); // Wait for async operations
        await drainPendingNetTools(); // Bounded wait for in-flight dig/whois (race fix)

        return { url: currentUrl, rules: [], success: true, dryRun: true, matchCount: dryRunResult.matchCount };
      } else {
        // Format rules using the output module
        const globalOptions = {
        localhostIP,
        plainOutput,
        adblockRulesMode,
        dnsmasqMode,
        dnsmasqOldMode,
        unboundMode,
        privoxyMode,
        piholeMode
      };
        // Drain pending dig/whois handlers BEFORE snapshotting matchedDomains.
        // Without this, late-completing async validations (request fired near
        // end of the delay window, dig still in flight) get orphaned — their
        // addMatchedDomain calls happen but the result has already been
        // returned. Bounded by TIMEOUTS.NETTOOLS_DRAIN_TIMEOUT.
        await drainPendingNetTools();
        const formattedRules = formatRules(matchedDomains, siteConfig, globalOptions);
        
        return {
          url: currentUrl,
          originalUrl: originalRequestedUrl,
          rules: formattedRules,
          success: true,
          finalUrl: finalUrlAfterRedirect || currentUrl,
          redirectDomains: redirectDomainsToExclude,
          matchedRegexes: Array.from(matchedRegexPatterns)
        };
      }
      
    } catch (err) {
      // Detect proxy-specific failures at top level
      if (needsProxy(siteConfig) && err.message) {
        const proxyErrors = [
          'ERR_PROXY_CONNECTION_FAILED',
          'ERR_SOCKS_CONNECTION_FAILED',
          'ERR_TUNNEL_CONNECTION_FAILED',
          'ERR_PROXY_AUTH_UNSUPPORTED',
          'ERR_PROXY_AUTH_REQUESTED',
          'ERR_SOCKS_CONNECTION_HOST_UNREACHABLE',
          'ERR_PROXY_CERTIFICATE_INVALID',
          'ERR_NO_SUPPORTED_PROXIES'
        ];
        const proxyErr = proxyErrors.find(e => err.message.includes(e));
        if (proxyErr) {
          const info = getProxyInfo(siteConfig);
          console.error(formatLogMessage('error', `${PROXY_TAG} ${proxyErr} — proxy: ${info} — URL: ${currentUrl}`));
          console.error(formatLogMessage('error', `${PROXY_TAG} Check: is the proxy running? Are credentials correct? Is the target reachable from the proxy?`));
        }
      }

      // Only restart for truly fatal browser errors
      const isFatalError = CRITICAL_BROWSER_ERRORS.some(errorType => 
        err.message.includes(errorType)
      ) && !err.message.includes('timeout') && !err.message.includes('Navigation');
      
      if (isFatalError) {
        console.error(formatLogMessage('error', `Fatal browser error on ${currentUrl}: ${err.message}`));
      return { 
        url: currentUrl, 
        rules: [], 
        success: false, 
        needsImmediateRestart: true,
        error: `Fatal error: ${err.message}`,
        errorType: 'fatal'
      };
    }
         
      // For other errors, preserve any matches we found before the error.
      // Drain pending nettools first so dig/whois handlers scheduled DURING
      // the failed navigation get a chance to add to matchedDomains before
      // the partial-success snapshot — same race as the success path.
      await drainPendingNetTools();
      if (matchedDomains && (matchedDomains.size > 0 || (matchedDomains instanceof Map && matchedDomains.size > 0))) {
        const globalOptions = {
          localhostIP,
          plainOutput,
          adblockRulesMode,
          dnsmasqMode,
          dnsmasqOldMode,
          unboundMode,
          privoxyMode,
          piholeMode
        };
        const formattedRules = formatRules(matchedDomains, siteConfig, globalOptions);
        if (forceDebug) console.log(formatLogMessage('debug', `Saving ${formattedRules.length} rules despite page load failure`));
        return {
          url: currentUrl,
          originalUrl: originalRequestedUrl,
          rules: formattedRules,
          success: false,
          hasMatches: true,
          finalUrl: finalUrlAfterRedirect || currentUrl,
          redirectDomains: redirectDomainsToExclude,
          matchedRegexes: Array.from(matchedRegexPatterns)
        };
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
      return { 
        url: currentUrl, 
        rules: [], 
        success: false,
        finalUrl: finalUrlAfterRedirect || currentUrl,
        redirectDomains: redirectDomainsToExclude
      };
    } finally {
      // Guaranteed resource cleanup - this runs regardless of success or failure

      // Flip the popup-capture race-window guard first so any in-flight
      // 'targetcreated' handler that resolves after this point sees the
      // flag and bails (closing its own popup if it managed to fetch one).
      urlFinished = true;

      // Popup capture teardown (opt-in via siteConfig.capture_popups). Each
      // entry is either the browser.off('targetcreated', ...) deregistration
      // or a per-popup (clearTimeout + popupPage.close) cleanup. Iterate even
      // if one fails so the rest still run.
      if (popupCleanups.length) {
        for (const cleanup of popupCleanups) {
          try { cleanup(); } catch (_) {}
        }
        popupCleanups.length = 0;
      }

      // Disconnect VPN for this site
      if (siteConfig.vpn) {
        const vpnDown = wgDisconnect(siteConfig, forceDebug);
        if (vpnDown.tornDown && forceDebug) {
          console.log(formatLogMessage('debug', `${VPN_TAG} WireGuard interface torn down for ${currentUrl}`));
        }
      } else if (siteConfig.openvpn) {
        const ovpnDown = ovpnDisconnect(siteConfig, forceDebug);
        if (ovpnDown.tornDown && forceDebug) {
          console.log(formatLogMessage('debug', `${VPN_TAG} OpenVPN connection torn down for ${currentUrl}`));
        }
      }

      if (cdpSessionManager) {
        // Mark page as idle when cleanup starts
        if (page && !page.isClosed()) {
          updatePageUsage(page, false);
        }
        await cdpSessionManager.cleanup();
      }
      
      if (page && !page.isClosed()) {
        // Clear page resources before closing
        try {
          await page.evaluate(() => {
            if (window.gc) window.gc(); // Force garbage collection if available
          });
        } catch (gcErr) { /* ignore */ }

        // Force screenshot — always capture regardless of success/failure
        if (siteConfig.screenshot === 'force' && page && !page.isClosed()) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
          const safeUrl = currentUrl.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 80);
          const filename = `screenshots/${safeUrl}-${timestamp}.png`;
          try {
            if (!fs.existsSync('screenshots')) fs.mkdirSync('screenshots', { recursive: true });
            await page.screenshot({ path: filename, type: 'png', fullPage: true });
            console.log(formatLogMessage('info', `Screenshot saved: ${filename}`));
          } catch (screenshotErr) {
            console.warn(messageColors.warn(`[screenshot failed] ${currentUrl}: ${screenshotErr.message}`));
          }
        }

        if (!keepBrowserOpen) {
          try {
            untrackPage(page);
            await page.close();
            if (forceDebug) console.log(formatLogMessage('debug', `Page closed for ${currentUrl}`));
          } catch (pageCloseErr) {
            if (forceDebug) console.log(formatLogMessage('debug', `Failed to close page for ${currentUrl}: ${pageCloseErr.message}`));
          }
        }
      }
    }
  }

// Temporarily store the pLimit function
  const originalLimit = limit;

  // Per-site config normalization (always runs, not gated on --validate-config).
  // Catches typo'd keys (whois_terms vs whois) with "did you mean" suggestions
  // and coerces boolean-like values (interact: 1 → interact: true) before any
  // downstream strict-equality check silently treats them as disabled. Mutates
  // each site in place so the rest of the scan sees normalized values.
  // Reports via console.warn so messages surface even when --silent is set.
  for (let i = 0; i < sites.length; i++) {
    const { warnings, errors } = normalizeSiteConfig(sites[i], i);
    for (const e of errors) console.warn(messageColors.error('⚠ ' + e));
    for (const w of warnings) console.warn(messageColors.warn('⚠ [config] ' + w));
  }

  // V8 Optimization: Calculate total URLs first to pre-allocate array
  let totalUrls = 0;
  for (const site of sites) {
    const urlsToProcess = Array.isArray(site.url) ? site.url : [site.url];
    totalUrls += urlsToProcess.length;
  }
  
  // Pre-allocate array with exact size to prevent multiple reallocations
  const allTasks = new Array(totalUrls);
  let taskIndex = 0;
  
  // Populate the pre-allocated array
  for (const site of sites) {
    const urlsToProcess = Array.isArray(site.url) ? site.url : [site.url];
    for (const url of urlsToProcess) {
      allTasks[taskIndex++] = {
        url,
        config: { ...site, _originalUrl: url }, // Preserve original URL for CDP domain checking
        taskId: taskIndex - 1 // For tracking
      };
    }
  }

  // Helper to get a stable proxy key for grouping browser instances
  const proxyKeyFor = (siteConfig) => {
    if (!needsProxy(siteConfig)) return '';
    return getProxyInfo(siteConfig);
  };

  // Sort tasks so proxy groups are contiguous — direct connections first, then each proxy
  allTasks.sort((a, b) => proxyKeyFor(a.config).localeCompare(proxyKeyFor(b.config)));

  // Pre-start local no-auth SOCKS5 relays for any authenticated socks5://
  // upstreams. Done once here (the only async step) so getProxyArgs stays a
  // sync lookup in the per-batch browser-launch path. Chromium can't auth
  // SOCKS5; the relay does the upstream auth transparently.
  try {
    const relayCount = await prepareSocksRelays(sites, forceDebug);
    if (relayCount > 0 && !silentMode) {
      console.log(messageColors.processing(`Started ${relayCount} SOCKS5 auth relay(s)`));
    }
  } catch (relayErr) {
    console.warn(formatLogMessage('proxy', `SOCKS5 relay setup failed: ${relayErr.message}`));
  }

  let results = [];
  let processedUrlCount = 0;
  let urlsSinceLastCleanup = 0;
  
  if (!silentMode && totalUrls > 0) {
    console.log(`\n${messageColors.processing('Processing')} ${totalUrls} URLs with TRUE concurrency ${MAX_CONCURRENT_SITES}...`);
    if (totalUrls > RESOURCE_CLEANUP_INTERVAL) {
      console.log(messageColors.processing('Browser will restart every') + ` ~${RESOURCE_CLEANUP_INTERVAL} URLs to free resources`);
    }
  }

 // Track domain timeout counts — skip domain after 3 failures
 const domainTimeoutCounts = new Map();
 const DOMAIN_TIMEOUT_THRESHOLD = 3;

 // Enhanced hang detection with browser restart recovery
 let currentBatchInfo = { batchStart: 0, batchSize: 0 };
 let lastProcessedCount = 0;
 let hangCheckCount = 0;
 let forceRestartFlag = false; // Flag to trigger restart on next iteration

 // Precomputed colored '[HANG CHECK]' subsystem prefix. formatLogMessage
 // only colors the [severity] tag; the '[HANG CHECK]' substring was
 // sitting plain inside the message string. Colored once at function
 // entry so the interval callback doesn't re-colorize per tick.
 const HANG_CHECK_TAG = messageColors.processing('[HANG CHECK]');

 const hangDetectionInterval = setInterval(() => {
   // Progress check, counter, and forceRestartFlag MUST run regardless of
   // debug mode — previously the entire body was gated on forceDebug, which
   // made hang recovery a debug-only feature even though the restart
   // machinery exists for production scans. Only the verbose diagnostic
   // logs stay debug-gated; the "no progress" warning and the
   // "triggering restart" error are user-visible recovery events.
   if (processedUrlCount === lastProcessedCount) {
     hangCheckCount++;
     if (forceDebug) {
       console.log(formatLogMessage('warn', `${HANG_CHECK_TAG} No progress for ${hangCheckCount * 30}s`));
     }
     if (hangCheckCount >= 5) {
       console.log(formatLogMessage('error', `${HANG_CHECK_TAG} Hung for 2.5 minutes. Triggering emergency browser restart.`));
       forceRestartFlag = true; // Set flag instead of exiting
       hangCheckCount = 0; // Reset counter for next cycle
     }
   } else {
     hangCheckCount = 0;
   }
   lastProcessedCount = processedUrlCount;

   // Debug-only diagnostic snapshot
   if (forceDebug) {
     const currentBatch = Math.floor(currentBatchInfo.batchStart / RESOURCE_CLEANUP_INTERVAL) + 1;
     const totalBatches = Math.ceil(totalUrls / RESOURCE_CLEANUP_INTERVAL);
     console.log(formatLogMessage('debug', `${HANG_CHECK_TAG} Processed: ${processedUrlCount}/${totalUrls} URLs, Batch: ${currentBatch}/${totalBatches}, Current batch size: ${currentBatchInfo.batchSize}`));
     console.log(formatLogMessage('debug', `${HANG_CHECK_TAG} URLs since cleanup: ${urlsSinceLastCleanup}, Recent failures: ${results.slice(-3).filter(r => !r.success).length}/3`));
   }
 }, 30000);
 // Don't keep the event loop alive solely for the hang-check interval — the
 // clearInterval calls at the normal-exit and error paths already cover the
 // cleanup, this is belt-and-suspenders in case a future refactor moves them.
 hangDetectionInterval.unref();

 // Process URLs in batches with exception handling
 let siteGroupIndex = 0;
 let currentProxyKey = '';  // Track active proxy config — '' means direct connection
 // Map of site-config object -> index in sites[], built once. Per-batch
 // grouping below uses this for O(1) lookup instead of sites.indexOf which
 // walked the array per task (batch=80 * sites=20 was ~1600 cmps per batch).
 const configToIndex = new Map();
 for (let i = 0; i < sites.length; i++) configToIndex.set(sites[i], i);
 try {
   for (let batchStart = 0; batchStart < totalUrls; batchStart += RESOURCE_CLEANUP_INTERVAL) {
    const batchEnd = Math.min(batchStart + RESOURCE_CLEANUP_INTERVAL, totalUrls);
    const currentBatch = allTasks.slice(batchStart, batchEnd);


    // Group tasks by their source site configuration for window cleanup.
    // Single get-or-set replaces has + get + set (one Map lookup not two).
    // The `?? -1` preserves the old `sites.indexOf` semantics for a task
    // whose config isn't in sites[] — that case shouldn't happen, but if
    // it ever does the routing stays identical to the prior code's
    // 'site_-1' bucket rather than silently shifting to 'site_undefined'.
    const tasksBySite = new Map();
    for (let i = 0; i < currentBatch.length; i++) {
      const task = currentBatch[i];
      const siteKey = `site_${configToIndex.get(task.config) ?? -1}`;
      let arr = tasksBySite.get(siteKey);
      if (!arr) tasksBySite.set(siteKey, arr = []);
      arr.push(task);
    }
    
    // IMPROVED: Only check health if we have indicators of problems
    let healthCheck = { shouldRestart: false, reason: null };
    const recentResults = results.slice(-8); // Check more results for better pattern detection
    // Single-pass count for both failure rate and critical-error tally —
    // was two .filter(...).length calls allocating two intermediate arrays.
    let recentFailures = 0, recentCritical = 0;
    for (let i = 0; i < recentResults.length; i++) {
      const r = recentResults[i];
      if (!r.success) recentFailures++;
      if (r.needsImmediateRestart) recentCritical++;
    }
    const recentFailureRate = recentResults.length > 0 ? recentFailures / recentResults.length : 0;
    const hasHighFailureRate = recentFailureRate > 0.75; // 75% failure threshold (more conservative)
    const hasCriticalErrors = recentCritical > 2;
    
    // Only run health checks when we have STRONG indicators of problems
    if (urlsSinceLastCleanup > 15 && (
        (hasHighFailureRate && recentResults.length >= 5) ||  // Need sufficient sample size
        hasCriticalErrors ||
        urlsSinceLastCleanup > RESOURCE_CLEANUP_INTERVAL * 0.9  // Very close to cleanup limit
    )) {
     try {
       // Race the health check against a 30s timeout. Attach .catch on the
       // health promise itself so that if the timeout wins, the still-running
       // monitorBrowserHealth's eventual rejection doesn't surface as an
       // unhandledRejection warning.
       const healthPromise = monitorBrowserHealth(browser, {}, {
         siteIndex: Math.floor(batchStart / RESOURCE_CLEANUP_INTERVAL),
         totalSites: Math.ceil(totalUrls / RESOURCE_CLEANUP_INTERVAL),
         urlsSinceCleanup: urlsSinceLastCleanup,
         cleanupInterval: RESOURCE_CLEANUP_INTERVAL,
         forceDebug,
         silentMode
       });
       healthPromise.catch(() => {});
       healthCheck = await Promise.race([
         healthPromise,
         new Promise((_, reject) => setTimeout(() => reject(new Error('Health check timeout')), 30000))
       ]);
     } catch (healthError) {
       console.log(formatLogMessage('warn', `[HEALTH CHECK] Timeout, assuming restart needed`));
       healthCheck = { shouldRestart: true, reason: 'Health check timeout' };
     }
    } else if (forceDebug && urlsSinceLastCleanup > 10) {
      console.log(formatLogMessage('debug', `Skipping health check: failure rate ${Math.round(recentFailureRate * 100)}%, critical errors: ${hasCriticalErrors ? 'yes' : 'no'}`));
    }

    const batchSize = currentBatch.length;
    
    // Update hang detection info
    currentBatchInfo = { batchStart, batchSize };

    // Check if processing this entire site would exceed cleanup interval OR health check suggests restart
    const wouldExceedLimit = urlsSinceLastCleanup + batchSize >= Math.min(RESOURCE_CLEANUP_INTERVAL, 100);
    const isNotLastBatch = batchEnd < totalUrls;
    // IMPROVED: More restrictive health-based restart conditions
    const shouldRestartFromHealth = healthCheck.shouldRestart && 
      !healthCheck.reason?.includes('Scheduled cleanup') && 
      (healthCheck.reason?.includes('Critical') || healthCheck.reason?.includes('disconnected'));
    
    // Restart conditions split into hang recovery vs proactive triggers.
    // Hang recovery (forceRestartFlag set by 2.5-min HANG CHECK or a per-URL
    // timeout) bypasses the urlsSinceLastCleanup > 8 gate — a confirmed hang
    // needs immediate restart even if we just cleaned up. Proactive triggers
    // keep the gate to prevent thrashing.
    //
    // hasHighFailureRate is computed (and still used for the health-check
    // gate above) but intentionally NOT folded into proactiveRestart:
    // wouldExceedLimit is always true at every batch boundary with the
    // default RESOURCE_CLEANUP_INTERVAL == batch size, so the high-failure-
    // rate branch was dead code reached only at the same boundary that
    // wouldExceedLimit already triggers. If failure-rate ever needs to
    // interrupt mid-cleanup-interval, that requires interrupting the
    // running Promise.all — a real behavior change, not an OR addition.
    const hangRecoveryRestart = forceRestartFlag;
    const proactiveRestart = (wouldExceedLimit || shouldRestartFromHealth) && urlsSinceLastCleanup > 8;
    if ((hangRecoveryRestart || proactiveRestart) && isNotLastBatch) {
      let restartReason = 'Unknown';
      if (forceRestartFlag) {
        restartReason = 'Emergency restart due to 2.5-minute hang detection';
        forceRestartFlag = false; // Reset the flag
      } else if (shouldRestartFromHealth) {
        restartReason = healthCheck.reason;
      } else if (wouldExceedLimit) {
        restartReason = `Processed ${urlsSinceLastCleanup} URLs (scheduled maintenance)`;
      }

      if (!silentMode) {
        console.log(`\n${messageColors.fileOp('🔄 Browser restart triggered:')} ${restartReason}`);
      }
      
      // NEW: Clear request cache during browser restart to ensure fresh session
      if (smartCache && cacheRequests) {
        const requestCacheStats = smartCache.getRequestCacheStats();
        if (requestCacheStats.enabled && requestCacheStats.size > 0) {
          const clearedCount = smartCache.clearRequestCache();
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${SMART_CACHE_TAG} Cleared ${clearedCount} request cache entries during browser restart`));
          }
        }
      }

      try {
        await handleBrowserExit(browser, {
          forceDebug,
          timeout: 10000,
          exitOnFailure: false,
          cleanTempFiles: true,
          comprehensiveCleanup: removeTempFiles  // Respect --remove-tempfiles during restarts
        });

        // Clean up the specific user data directory
        if (userDataDir) await cleanupUserDataDir(userDataDir, forceDebug);

        // Additional cleanup for any remaining Chrome processes
        if (removeTempFiles) {
          await cleanupChromeTempFiles({
            includeSnapTemp: true,
            forceDebug,
            comprehensive: true
          });
        }

      } catch (browserCloseErr) {
        if (forceDebug) console.log(formatLogMessage('debug', `Browser cleanup warning: ${browserCloseErr.message}`));
      }

      // Create new browser for next batch (preserve current proxy config)
      const restartProxyArgs = currentProxyKey ? getProxyArgs(currentBatch[0].config, forceDebug) : [];
      browser = await createBrowser(restartProxyArgs);
      if (forceDebug) console.log(formatLogMessage('debug', `New browser instance created for batch ${Math.floor(batchStart / RESOURCE_CLEANUP_INTERVAL) + 1}`));
      
      // Reset cleanup counter and add delay
      urlsSinceLastCleanup = 0;
      await fastTimeout(TIMEOUTS.BROWSER_STABILIZE_DELAY);
    }

    // --- Proxy-aware browser restart ---
    // --proxy-server is browser-wide, so if the batch needs a different proxy we must restart
    const batchProxyKey = proxyKeyFor(currentBatch[0].config);
    if (batchProxyKey !== currentProxyKey) {
      const debug = forceDebug || currentBatch[0].config.proxy_debug || currentBatch[0].config.socks5_debug;
      if (debug) {
        const from = currentProxyKey || 'direct';
        const to = batchProxyKey || 'direct';
        console.log(formatLogMessage('proxy', `Switching proxy: ${from} → ${to}`));
      }

      try {
        await handleBrowserExit(browser, {
          forceDebug, timeout: 10000, exitOnFailure: false,
          cleanTempFiles: true, comprehensiveCleanup: removeTempFiles
        });
        if (userDataDir) await cleanupUserDataDir(userDataDir, forceDebug);
      } catch (proxyRestartErr) {
        if (forceDebug) console.log(formatLogMessage('debug', `Proxy switch browser cleanup: ${proxyRestartErr.message}`));
      }

      const proxyArgs = batchProxyKey ? getProxyArgs(currentBatch[0].config, forceDebug) : [];

      // Pre-flight: verify proxy is reachable before launching browser
      if (proxyArgs.length > 0) {
        const health = await testProxy(currentBatch[0].config, 5000);
        if (!health.reachable) {
          const info = getProxyInfo(currentBatch[0].config);
          console.error(formatLogMessage('error', `${PROXY_TAG} Unreachable: ${info} — ${health.error}`));
          console.error(formatLogMessage('error', `${PROXY_TAG} Skipping ${currentBatch.length} URL(s) in this batch`));
          const skipResults = currentBatch.map(task => ({
            success: false, url: task.url, rules: [],
            error: `Proxy unreachable: ${health.error}`
          }));
          results.push(...skipResults);
          processedUrlCount += currentBatch.length;
          urlsSinceLastCleanup += currentBatch.length;
          continue;
        }
        if (forceDebug) {
          console.log(formatLogMessage('proxy', `Proxy reachable (${health.latencyMs}ms)`));
        }
      }

      browser = await createBrowser(proxyArgs);
      currentProxyKey = batchProxyKey;
      urlsSinceLastCleanup = 0;
      await fastTimeout(TIMEOUTS.BROWSER_STABILIZE_DELAY);
    }
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Processing batch ${Math.floor(batchStart / RESOURCE_CLEANUP_INTERVAL) + 1}: ${batchSize} URL(s) (total processed: ${processedUrlCount})`));
    }
    
    // Log start of concurrent processing for hang detection
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${CONCURRENCY_TAG} Starting ${batchSize} concurrent tasks with limit ${MAX_CONCURRENT_SITES}`));
    }
    
 // Create tasks with timeout protection — skip domains that repeatedly timed out.
 // Wrapped in an outer try/finally so processedUrlCount is incremented exactly
 // once per URL no matter which return/throw path is taken — that turns HANG
 // CHECK's signal from "did the batch finish?" into "did any URL finish?",
 // which is what 30-second tick granularity actually needs.
 const batchTasks = currentBatch.map(task => originalLimit(async () => {
   try {
     // Short-circuit queued URLs once any URL in this batch has triggered a
     // restart. Without this, the 80-URL batch in the user's hang trace
     // would have to fail one-by-one at 75s each (~25 min total) before
     // the boundary restart could fire. Now: first hang fires the flag,
     // remaining queued URLs return immediately, batch completes, restart.
     if (forceRestartFlag) {
       return { url: task.url, rules: [], success: false, error: 'Browser restart pending', skipped: true };
     }

     try {
       const taskDomain = new URL(task.url).hostname;
       if ((domainTimeoutCounts.get(taskDomain) || 0) >= DOMAIN_TIMEOUT_THRESHOLD) {
         if (!silentMode) console.log(formatLogMessage('info', `Skipping ${task.url} — ${taskDomain} timed out ${DOMAIN_TIMEOUT_THRESHOLD} times`));
         return { url: task.url, rules: [], success: false, error: 'Domain repeatedly timed out', skipped: true };
       }

       // DNS pre-check — fails fast on NXDOMAIN/unresolvable hosts before
       // we pay ~5-15s for Puppeteer navigation + Cloudflare detection.
       // Skips IP literals. Respects an in-memory negative cache so a dead
       // host hit by many URL paths only costs one DNS round-trip per TTL.
       //
       // Uses dns.resolve* (c-ares, async network I/O) NOT dns.lookup
       // (getaddrinfo, libuv threadpool). Under scan concurrency Puppeteer
       // saturates the default 4-slot threadpool with filesystem I/O, so
       // dns.lookup calls sit queued and blow the timeout while never
       // actually starting — wrongly skipping live domains. c-ares isn't
       // threadpool-bound so it's immune to that contention.
       if (dnsPrecheckEnabled && taskDomain && !/^[\d.:]+$|^\[/.test(taskDomain)) {
         const cached = dnsNegativeCache.get(taskDomain);
         if (cached && Date.now() - cached.timestamp < DNS_NEGATIVE_CACHE_TTL_MS) {
           dnsPrecheckSkips++;
           if (forceDebug) console.log(formatLogMessage('debug', `DNS pre-check (cached): ${taskDomain} — ${cached.error}`));
           return { url: task.url, rules: [], success: false, error: `DNS: ${cached.error}`, skipped: true };
         }
         // Positive-resolution shortcut: dig or whois has already proven this
         // hostname live within their 20h cache TTL (populated either by an
         // earlier URL this run or by --dns-cache disk-load from a prior run).
         // Order matters -- negative cache (5min TTL, fresher data) wins
         // first, then this 20h-TTL positive index, then the actual resolve.
         if (domainKnownToResolve(taskDomain)) {
           dnsPositiveSkips++;
           dnsPositiveSkippedHosts.add(taskDomain);
           if (forceDebug) console.log(formatLogMessage('debug', `DNS pre-check skipped (dig/whois cache confirms resolution): ${taskDomain}`));
           // Fall through to navigation -- pre-check "passed" by proxy.
         } else {
         const dnsResolve = async () => {
           // resolve4 first; on no-IPv4 (ENODATA / ENOTFOUND) fall back to
           // resolve6 so IPv6-only hosts aren't wrongly skipped. ANY OTHER
           // error code (ESERVFAIL, ETIMEOUT, EREFUSED, etc.) propagates
           // unchanged so the outer transient-retry path sees the real
           // resolver code and the negative cache records the right reason.
           // Previously a bare .catch swallowed everything and tried
           // resolve6, which masked transient v4-side errors behind
           // whatever resolve6 ended up reporting.
           // 2s timeout kept as a real safety net — with c-ares off the
           // threadpool it should now rarely fire.
           let timer;
           try {
             const timeoutP = new Promise((_, reject) => {
               timer = setTimeout(() => reject(new Error('DNS timeout')), dnsPrecheckTimeoutMs);
             });
             const resolveChain = dnsPromises.resolve4(taskDomain)
               .catch(err => {
                 if (err && (err.code === 'ENODATA' || err.code === 'ENOTFOUND')) {
                   return dnsPromises.resolve6(taskDomain);
                 }
                 throw err;
               });
             await Promise.race([resolveChain, timeoutP]);
           } finally {
             if (timer) clearTimeout(timer);
           }
         };
         // c-ares transient codes — retry once so a momentary resolver
         // hiccup doesn't poison the negative cache for 5 minutes.
         // DNS_TRANSIENT_ERRORS is module-level so we don't allocate per task.
         try {
           try {
             await dnsResolve();
           } catch (firstErr) {
             const code = firstErr && firstErr.code;
             if (DNS_TRANSIENT_ERRORS.has(code) || (firstErr && firstErr.message === 'DNS timeout')) {
               if (forceDebug) console.log(formatLogMessage('debug', `DNS pre-check transient (${code || 'timeout'}) for ${taskDomain}, retrying once`));
               await dnsResolve();
             } else {
               throw firstErr;
             }
           }
         } catch (dnsErr) {
           const errCode = dnsErr.code || dnsErr.message || 'DNS resolve failed';
           dnsNegativeCacheSet(taskDomain, errCode);
           dnsPrecheckSkips++;
           if (forceDebug) console.log(formatLogMessage('debug', `DNS pre-check failed: ${taskDomain} — ${errCode}`));
           return { url: task.url, rules: [], success: false, error: `DNS: ${errCode}`, skipped: true };
         }
         } // close `else` from domainKnownToResolve shortcut above
       }
     } catch {}

     // Per-URL timeout so a single hung processUrl can't block the batch
     // forever. 75s sits comfortably above the realistic legit-page ceiling
     // (nav 35s + Cloudflare adaptive ~25s + interaction ~10s + network-idle
     // wait ~10s ≈ ~70s), well short of the old 120s safety net. Cuts
     // hang-recovery time roughly in half when an entire batch's URLs all
     // hang and we're waiting on this timeout to advance processedUrlCount.
     const PER_URL_TIMEOUT_MS = 75000;
     const processUrlPromise = processUrl(task.url, task.config, browser);
     let perUrlTimer;
     try {
       return await Promise.race([
         processUrlPromise,
         new Promise((_, reject) => {
           perUrlTimer = setTimeout(() => reject(new Error('Per-URL timeout (75s)')), PER_URL_TIMEOUT_MS);
         })
       ]);
     } catch (err) {
       if (err && err.message === 'Per-URL timeout (75s)') {
         processUrlPromise.catch(() => {});
         forceRestartFlag = true;
         return { url: task.url, rules: [], success: false, error: 'Per-URL timeout (75s)', needsImmediateRestart: true };
       }
       throw err;
     } finally {
       if (perUrlTimer) clearTimeout(perUrlTimer);
     }
   } finally {
     // Always count completion — even on unexpected throw — so HANG CHECK's
     // per-tick progress signal stays accurate. Replaces the old
     // `processedUrlCount += batchSize` that ran after the whole batch.
     processedUrlCount++;
   }
 }));
 
 let batchResults;
 try {
   // Same orphan-promise pattern as the health-check race above: if the
   // 10-min batch timeout wins, the still-running Promise.all keeps going
   // until every batchTask settles. Each individual task is already wrapped
   // in p-limit's error handling so unhandled rejections should not surface,
   // but the .catch is free belt-and-braces against future refactors that
   // change task internals.
   const batchPromise = Promise.all(batchTasks);
   batchPromise.catch(() => {});
   batchResults = await Promise.race([
     batchPromise,
     new Promise((_, reject) =>
       setTimeout(() => reject(new Error('Batch timeout')), 600000) // 10 min timeout
     )
   ]);
 } catch (timeoutError) {
   if (timeoutError.message.includes('timeout')) {
     console.log(formatLogMessage('error', `${TIMEOUT_TAG} Batch hung. Restarting browser.`));
     try {
       await handleBrowserExit(browser, { forceDebug, timeout: 5000, exitOnFailure: false });
       if (userDataDir) await cleanupUserDataDir(userDataDir, forceDebug);
       const timeoutProxyArgs = currentProxyKey ? getProxyArgs(currentBatch[0].config, forceDebug) : [];
       browser = await createBrowser(timeoutProxyArgs);
       urlsSinceLastCleanup = 0;
     } catch (restartErr) {
       throw restartErr;
     }
     batchResults = currentBatch.map(task => ({
       success: false, error: 'Batch timeout', needsImmediateRestart: true, url: task.url
     }));
   } else {
     throw timeoutError;
   }
 }

    // Track domain timeout counts — skip after threshold
    for (const result of batchResults) {
      if (!result.success && !result.skipped && result.error && result.error.includes('timeout')) {
        try {
          const domain = new URL(result.url).hostname;
          domainTimeoutCounts.set(domain, (domainTimeoutCounts.get(domain) || 0) + 1);
        } catch {}
      }
    }

    // IMPROVED: Much more conservative emergency restart logic
    const criticalRestartCount = batchResults.filter(r => r.needsImmediateRestart).length;
    // Require either:
    // - More than 50% of batch has critical errors, OR
    // - At least 3 critical errors in any size batch
    const restartThreshold = Math.max(3, Math.floor(batchSize * 0.5)); // 50% of batch or min 3
    const needsImmediateRestart = criticalRestartCount >= restartThreshold && criticalRestartCount >= 2;
    
    // Log restart decision for debugging
    if (forceDebug && criticalRestartCount > 0) {
      console.log(formatLogMessage('debug', `Emergency restart decision: ${criticalRestartCount}/${batchSize} critical errors (threshold: ${restartThreshold}, restart: ${needsImmediateRestart ? 'YES' : 'NO'})`));
    }
    
    // Log completion of concurrent processing
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${CONCURRENCY_TAG} Completed ${batchSize} concurrent tasks, ${batchResults.filter(r => r.success).length} successful`));
    }

    // Enhanced error reporting for Puppeteer 23.x
    if (forceDebug) {
      const errorSummary = batchResults.reduce((acc, result) => {
        if (!result.success && result.errorType) {
          acc[result.errorType] = (acc[result.errorType] || 0) + 1;
        }
        return acc;
      }, {});
      
      if (Object.keys(errorSummary).length > 0) {
        console.log(formatLogMessage('debug', `Batch ${Math.floor(batchStart / RESOURCE_CLEANUP_INTERVAL) + 1} error summary:`));
        Object.entries(errorSummary).forEach(([errorType, count]) => {
          console.log(formatLogMessage('debug', `  ${errorType}: ${count} error(s)`));
        });
      }
    }

    results.push(...batchResults);

    // Perform group window cleanup for completed sites
    for (const [siteKey, siteTasks] of tasksBySite) {
      const siteConfig = siteTasks[0].config; // All tasks in group have same config
      
      if (siteConfig.window_cleanup === true || siteConfig.window_cleanup === "all" || siteConfig.window_cleanup === "realtime") {
        const urlCount = siteTasks.length;
        const groupDescription = `${urlCount} URLs from site group ${++siteGroupIndex}`;
        const cleanupMode = siteConfig.window_cleanup === "realtime" ? true : siteConfig.window_cleanup; // Pass through the exact value, but don't pass "realtime" to group cleanup
        
        try {
          const groupCleanupResult = await performGroupWindowCleanup(browser, groupDescription, forceDebug, cleanupMode);
          if (!silentMode && groupCleanupResult.success && groupCleanupResult.closedCount > 0) {
            const modeText = cleanupMode === "all" ? "(aggressive)" : "(conservative)";
            console.log(`🗑️ Group cleanup: ${groupCleanupResult.closedCount} old windows closed ${modeText} after completing ${groupDescription}`);
            if (groupCleanupResult.mainPagePreserved) {
              console.log(`✅ Main Puppeteer window preserved during cleanup`);
            }
          }
        } catch (groupCleanupErr) {
          if (forceDebug) console.log(formatLogMessage('debug', `Group window cleanup failed: ${groupCleanupErr.message}`));
        }
      }
    }
    
    // processedUrlCount is now incremented per-URL inside the batchTasks
    // wrapper above; no batch-level += batchSize here.
    urlsSinceLastCleanup += batchSize;

    // Force browser restart if any URL had critical errors
    if (needsImmediateRestart && isNotLastBatch) {
      if (!silentMode) {
        console.log(`\n${messageColors.fileOp('🔄 Emergency browser restart:')} Critical browser errors detected`);
      }
      
      // NEW: Clear request cache during emergency restart
      if (smartCache && cacheRequests) {
        const requestCacheStats = smartCache.getRequestCacheStats();
        if (requestCacheStats.enabled && requestCacheStats.size > 0) {
          const clearedCount = smartCache.clearRequestCache();
          if (forceDebug) {
            console.log(formatLogMessage('debug', `${SMART_CACHE_TAG} Cleared ${clearedCount} request cache entries during emergency restart`));
          }
        }
      }

      // Force browser restart immediately
      try {
        // Enhanced emergency restart for Puppeteer 23.x
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Emergency restart triggered by errors: ${batchResults.filter(r => r.needsImmediateRestart).map(r => r.error).join(', ')}`));
        }
        
        // Try to gracefully close all pages first
        try {
          const pages = await browser.pages();
          await Promise.all(pages.map(page => page.close().catch(() => {})));
        } catch (pageCloseErr) {
          if (forceDebug) console.log(formatLogMessage('debug', `Page cleanup during emergency restart failed: ${pageCloseErr.message}`));
        }

        await handleBrowserExit(browser, { forceDebug, timeout: 5000, exitOnFailure: false, cleanTempFiles: true, comprehensiveCleanup: removeTempFiles });
        if (userDataDir) await cleanupUserDataDir(userDataDir, forceDebug);
        // Additional cleanup after emergency restart
        if (removeTempFiles) {
          await cleanupChromeTempFiles({
            includeSnapTemp: true,
            forceDebug,
            comprehensive: true
          });
        }
        browser = await createBrowser(currentProxyKey ? getProxyArgs(currentBatch[0].config, forceDebug) : []);
        urlsSinceLastCleanup = 0; // Reset counter
        // Reset the hang-detection flag too: this restart path is triggered
        // by needsImmediateRestart errors, which the per-URL 75s timeout
        // sets in lockstep with forceRestartFlag. Without this reset, the
        // hang-fallback restart below would fire a SECOND back-to-back
        // browser restart on the same batch boundary.
        forceRestartFlag = false;
        await fastTimeout(TIMEOUTS.EMERGENCY_RESTART_DELAY); // Give browser time to stabilize
      } catch (emergencyRestartErr) {
        if (forceDebug) console.log(formatLogMessage('debug', `Emergency restart failed: ${emergencyRestartErr.message}`));
      }
    }
    // Handle hang detection flag if it's still set (e.g., on last batch where normal restart wouldn't trigger)
    if (forceRestartFlag && batchEnd < totalUrls) {
      console.log(`\n${messageColors.fileOp('🔄 Emergency hang detection restart:')} Browser appears hung, forcing restart`);
      try {
        await handleBrowserExit(browser, { forceDebug, timeout: 5000, exitOnFailure: false, cleanTempFiles: true });
        if (userDataDir) await cleanupUserDataDir(userDataDir, forceDebug);
        browser = await createBrowser(currentProxyKey ? getProxyArgs(currentBatch[0].config, forceDebug) : []);
        urlsSinceLastCleanup = 0;
        forceRestartFlag = false; // Reset flag
        await fastTimeout(TIMEOUTS.EMERGENCY_RESTART_DELAY);
        if (forceDebug) console.log(formatLogMessage('debug', `Emergency hang detection restart completed`));
      } catch (hangRestartErr) {
        if (forceDebug) console.log(formatLogMessage('debug', `Hang detection restart failed: ${hangRestartErr.message}`));
        // Continue anyway - better to try processing remaining URLs than exit
      }
    }
  }
 } catch (processingError) {
   console.log(formatLogMessage('error', `Critical error: ${processingError.message}`));
   clearInterval(hangDetectionInterval);
   throw processingError;
  }

  // Clear hang detection interval
  clearInterval(hangDetectionInterval);

  // === POST-SCAN PROCESSING ===
  // Clean up first-party domains and validate results
  if (!dryRunMode) {
    // Always run post-processing for both firstParty cleanup and ignoreDomains safety net
    const sitesWithFirstPartyDisabled = sites.filter(site => site.firstParty === false);
    if (sitesWithFirstPartyDisabled.length > 0) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Running post-scan processing for ${sitesWithFirstPartyDisabled.length} sites with firstParty: false`));
      }
    // Always run post-processing for ignoreDomains safety net
    results = processResults(results, sites, { forceDebug, silentMode, ignoreDomains });
    }
  }

  // Handle dry run output file writing
  if (dryRunMode && outputFile && dryRunOutput.length > 0) {
    const writeResult = writeDryRunOutput(outputFile, dryRunOutput, silentMode);
    if (!writeResult.success && forceDebug) {
      console.log(formatLogMessage('debug', `Dry run file write failed: ${writeResult.error}`));
    }
  }

  let outputResult;
  
  // NEW: Clear request cache after processing all sites in the JSON config
  if (smartCache && cacheRequests) {
    const requestCacheStats = smartCache.getRequestCacheStats();
    if (requestCacheStats.enabled && requestCacheStats.size > 0) {
      const clearedCount = smartCache.clearRequestCache();
      if (!silentMode && clearedCount > 0) {
        console.log(`\n${messageColors.cleanup(`🗑️  Cleared request cache: ${clearedCount} entries after JSON processing`)}`);
      }
      if (forceDebug) {
        console.log(formatLogMessage('debug', 
          `${SMART_CACHE_TAG} Request cache cleared after JSON scan completion (hit rate: ${requestCacheStats.hitRate})`
        ));
      }
    }
  }
  
  if (!dryRunMode) {
    // Handle all output using the output module
    const outputConfig = {
      outputFile,
      appendMode,
      compareFile,
      forceDebug,
      showTitles,
      removeDupes: removeDupes && outputFile,
      silentMode,
      dumpUrls,
     adblockRulesLogFile,
     ignoreDomains
  };
  
  outputResult = handleOutput(results, outputConfig);
  
  if (!outputResult.success) {
    console.error(messageColors.error('❌ Failed to write output files'));
    process.exit(1);
  }

  } else {
    // For dry run mode, create a mock output result
    const totalMatches = results.reduce((sum, r) => sum + (r.matchCount || 0), 0);
    outputResult = {
      success: true,
      successfulPageLoads: results.filter(r => r.success).length,
      totalRules: totalMatches
    };
  }

  // Use the success count from output handler
  siteCounter = outputResult.successfulPageLoads;
  
  // Count pages that had matches even if they failed to load completely
  const pagesWithMatches = results.filter(r => r.success || r.hasMatches).length;
  const totalMatches = results.reduce((sum, r) => sum + (r.rules ? r.rules.length : 0), 0);

  // Debug: Show output format being used
  const totalDomainsSkipped = getTotalDomainsSkipped();
  const detectedDomainsCount = getDetectedDomainsCount();
  if (forceDebug) {
    const globalOptions = {
      localhostIP,
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
     console.log(formatLogMessage('debug', `Performance: ${totalDomainsSkipped} domains skipped (already detected), ${detectedDomainsCount} unique domains cached`));
     // Cloudflare cache statistics
     const cloudflareStats = getCacheStats();
     if (cloudflareStats.size > 0) {
       console.log(formatLogMessage('debug', '=== Cloudflare Cache Statistics ==='));
       console.log(formatLogMessage('debug', `Cache hit rate: ${cloudflareStats.hitRate}, Total hits: ${cloudflareStats.hits}, Misses: ${cloudflareStats.misses}`));
       console.log(formatLogMessage('debug', `Cached detections: ${cloudflareStats.size}`));
     }
     if (cloudflareScanStats.errorPages > 0) {
       console.log(formatLogMessage('debug', `Cloudflare 5xx origin-error pages: ${cloudflareScanStats.errorPages} (no bypass possible — origin unreachable)`));
     }
     if (dnsPrecheckEnabled && (dnsPrecheckSkips > 0 || dnsPositiveSkips > 0)) {
       // Two skip mechanisms, each with its own counter + unique-host count:
       //   - dnsPrecheckSkips:  URLs short-circuited via the NXDOMAIN-cache
       //     (dnsNegativeCache). Unique-host count = dnsNegativeCache.size.
       //   - dnsPositiveSkips:  URLs short-circuited via dig/whois cache
       //     proof of resolution (knownResolvedHostnames index in nettools).
       //     Unique-host count = dnsPositiveSkippedHosts.size (this Set is
       //     populated only on actual skip events, not on every Set add in
       //     nettools, so it's a true per-scan visibility metric).
       const parts = [];
       if (dnsPrecheckSkips > 0) {
         parts.push(`${dnsPrecheckSkips} URL(s) via ${dnsNegativeCache.size} unresolvable host(s)`);
       }
       if (dnsPositiveSkips > 0) {
         parts.push(`${dnsPositiveSkips} URL(s) via ${dnsPositiveSkippedHosts.size} resolved host(s)`);
       }
       console.log(formatLogMessage('debug', `DNS pre-check skipped: ${parts.join(', ')}`));
     }
     // Blocked-pattern hit stats. Surfaces which patterns are actually
     // doing work this scan and (by absence) which are stale enough to
     // prune from config. Top 10 by hit count to keep the log scannable
     // on configs with dozens of patterns; full counts available via
     // _blockedPatternHits if needed for tooling. Fires only when at
     // least one pattern matched -- silent on scans with no blocks.
     if (_blockedPatternHits.size > 0) {
       let totalBlocks = 0;
       for (const n of _blockedPatternHits.values()) totalBlocks += n;
       console.log(formatLogMessage('debug', `${messageColors.blocked('[blocked-stats]')} ${_blockedPatternHits.size} pattern(s) hit ${totalBlocks} time(s) total`));
       const sorted = [..._blockedPatternHits.entries()].sort((a, b) => b[1] - a[1]);
       const top = sorted.slice(0, 10);
       for (const [pattern, hits] of top) {
         console.log(formatLogMessage('debug', `${messageColors.blocked('[blocked-stats]')}   ${hits.toString().padStart(6)} × ${pattern}`));
       }
       if (sorted.length > top.length) {
         console.log(formatLogMessage('debug', `${messageColors.blocked('[blocked-stats]')}   ... and ${sorted.length - top.length} more pattern(s)`));
       }
     }
     // Log smart cache statistics (if cache is enabled)
     // Adblock statistics
     if (adblockEnabled) {
       console.log(formatLogMessage('debug', '=== Adblock Statistics ==='));
       const blockRate = ((adblockStats.blocked / (adblockStats.blocked + adblockStats.allowed)) * 100).toFixed(1);
       console.log(formatLogMessage('debug', `Blocked: ${adblockStats.blocked} requests (${blockRate}% block rate), Allowed: ${adblockStats.allowed}`));

       // Engine-specific stats from the matcher itself. Both engines expose
       // getStats() but with slightly different cache shapes — JS engine
       // tracks urlCacheSize + resultCacheSize separately, rust wrapper
       // tracks a single size. Handle both.
       if (adblockMatcher && typeof adblockMatcher.getStats === 'function') {
         try {
           const es = adblockMatcher.getStats();
           const engine = es.engine || 'js';
           console.log(formatLogMessage('debug', `Engine: ${engine}${es.fromDiskCache ? ' (loaded from disk cache)' : ''}`));
           if (es.cache && (es.cache.hits != null || es.cache.misses != null)) {
             // rust wrapper: single `size`; JS engine: split into urlCacheSize + resultCacheSize
             const sizeDesc = es.cache.size != null
               ? `${es.cache.size}/${es.cache.maxSize}`
               : `url ${es.cache.urlCacheSize}, result ${es.cache.resultCacheSize}, cap ${es.cache.maxSize}`;
             console.log(formatLogMessage('debug', `Matcher cache: ${es.cache.hits} hits / ${es.cache.misses} misses (${es.cache.hitRate}), ${sizeDesc}`));
           }
           if (es.exceptions != null && es.exceptions > 0) {
             console.log(formatLogMessage('debug', `Whitelist exceptions: ${es.exceptions}`));
           }
           if (es.errors != null && es.errors > 0) {
             console.log(formatLogMessage('debug', `Engine errors: ${es.errors}`));
           }
         } catch (_) { /* getStats shape mismatch — don't crash the exit path */ }
       }
     }
    if (smartCache) {
    const cacheStats = smartCache.getStats();  
    console.log(formatLogMessage('debug', '=== Smart Cache Statistics ==='));
    console.log(formatLogMessage('debug', `Runtime: ${cacheStats.runtime}s, Total entries: ${cacheStats.totalCacheEntries}`));
    console.log(formatLogMessage('debug', `Hit Rates - Domain: ${cacheStats.hitRate}, Pattern: ${cacheStats.patternHitRate}`));
    console.log(formatLogMessage('debug', `Response: ${cacheStats.responseHitRate}, NetTools: ${cacheStats.netToolsHitRate}`));
    console.log(formatLogMessage('debug', `Regex compilations saved: ${cacheStats.regexCacheHits}`));
    console.log(formatLogMessage('debug', `Similarity cache hits: ${cacheStats.similarityHits}`));
    if (config.cache_persistence) {
      console.log(formatLogMessage('debug', `Persistence - Loads: ${cacheStats.persistenceLoads}, Saves: ${cacheStats.persistenceSaves}`));
    }
    }
  }
  
  // Flush any remaining buffered log entries before compression/exit
  flushLogBuffersSync();
  if (_logFlushTimer) {
    clearInterval(_logFlushTimer);
  }

  // Compress log files if --compress-logs is enabled
  if (compressLogs && dumpUrls && !dryRunMode) {
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

  // Tear down any remaining VPN interfaces/connections
  wgDisconnectAll(forceDebug);
  ovpnDisconnectAll(forceDebug);

  // Keep browser open if --keep-open flag is set (useful with --headful for inspection)
  if (keepBrowserOpen && !launchHeadless) {
    console.log(messageColors.info('Browser kept open.') + ' Close the browser window or press Ctrl+C to exit.');
    const cleanup = async () => {
      try {
        if (browser.connected) await browser.close();
      } catch {}
      process.exit(0);
    };
    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
    await new Promise((resolve) => {
      browser.on('disconnected', resolve);
    });
    process.removeListener('SIGINT', cleanup);
    process.removeListener('SIGTERM', cleanup);
  }

  // Perform comprehensive final cleanup using enhanced browserexit module
  if (forceDebug) console.log(formatLogMessage('debug', `Starting comprehensive browser cleanup...`));

  // Enhanced final validation for Puppeteer 23.x
  try {
    const isStillConnected = browser.connected;
    if (forceDebug) console.log(formatLogMessage('debug', `Browser connection status before cleanup: ${isStillConnected}`));
  } catch (connErr) {
    if (forceDebug) console.log(formatLogMessage('debug', `Browser connection check failed: ${connErr.message}`));
  }

  // Obscura: just disconnect, don't kill — we don't own the browser process
  let cleanupResult;
  if (browser._nwssIsObscura) {
    try { await browser.disconnect(); } catch {}
    cleanupResult = { success: true, browserClosed: true, tempFilesCleanedCount: 0, userDataCleaned: false, errors: [] };
    if (forceDebug) console.log(formatLogMessage('debug', `Disconnected from Obscura (process left running)`));
  } else {
    cleanupResult = await handleBrowserExit(browser, {
      forceDebug,
      timeout: 10000,
      exitOnFailure: true,
      cleanTempFiles: true,
      comprehensiveCleanup: removeTempFiles,
      userDataDir: browser._nwssUserDataDir,
      verbose: !silentMode && removeTempFiles
    });
  }

  if (forceDebug) {
    console.log(formatLogMessage('debug', `Final cleanup results: ${cleanupResult.success ? 'success' : 'failed'}`));
    console.log(formatLogMessage('debug', `Browser closed: ${cleanupResult.browserClosed}, Temp files cleaned: ${cleanupResult.tempFilesCleanedCount || 0}, User data cleaned: ${cleanupResult.userDataCleaned}`));

    if (cleanupResult.errors.length > 0) {
      cleanupResult.errors.forEach(err => console.log(formatLogMessage('debug', `Cleanup error: ${err}`)));
    }
  }

  // Final aggressive cleanup to catch any remaining temp files
  if (forceDebug) console.log(formatLogMessage('debug', 'Performing final aggressive temp file cleanup...'));
  await cleanupChromeTempFiles({
    includeSnapTemp: true,
    forceDebug,
    comprehensive: true
  });
  await fastTimeout(TIMEOUTS.BROWSER_STABILIZE_DELAY); // Give filesystem time to sync

  // Calculate timing, success rates, and provide summary information
  if (forceDebug) console.log(formatLogMessage('debug', `Calculating timing statistics...`));
  const endTime = Date.now();
  const durationMs = endTime - startTime;
  const totalSeconds = Math.floor(durationMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  // Final summary report with timing and success statistics
  // Clean up smart cache (if it exists)
  if (smartCache) {
    smartCache.destroy();
  }
 
  if (!silentMode) {
    if (pagesWithMatches > outputResult.successfulPageLoads) {
      console.log(`\n${messageColors.success(dryRunMode ? 'Dry run completed.' : 'Scan completed.')} ${outputResult.successfulPageLoads} of ${totalUrls} URLs loaded successfully, ${pagesWithMatches} had matches in ${messageColors.timing(`${hours}h ${minutes}m ${seconds}s`)}`);

    } else {
      console.log(`\n${messageColors.success(dryRunMode ? 'Dry run completed.' : 'Scan completed.')} ${outputResult.successfulPageLoads} of ${totalUrls} URLs processed successfully in ${messageColors.timing(`${hours}h ${minutes}m ${seconds}s`)}`);


    }
    if (outputResult.totalRules > 0 && !dryRunMode) {
      console.log(messageColors.success('Generated') + ` ${outputResult.totalRules} unique rules`);
    } else if (outputResult.totalRules > 0 && dryRunMode) {
      console.log(messageColors.success('Found') + ` ${outputResult.totalRules} total matches across all URLs`);
    }
    if (totalDomainsSkipped > 0) {
      console.log(messageColors.info('Performance:') + ` ${totalDomainsSkipped} domains skipped (already detected)`);
    }
    if (ignoreCache && forceDebug) {
      console.log(messageColors.info('Cache:') + ` Smart caching was disabled`);
    }
    // DNS cache statistics
    const dnsStats = getDnsCacheStats();
    if (dnsStats.digHits + dnsStats.digMisses > 0 || dnsStats.whoisHits + dnsStats.whoisMisses > 0) {
      const parts = [];
      if (dnsStats.digHits + dnsStats.digMisses > 0) {
        parts.push(`${messageColors.success(dnsStats.digHits)} dig cached, ${messageColors.timing(dnsStats.digMisses)} fresh`);
      }
      if (dnsStats.whoisHits + dnsStats.whoisMisses > 0) {
        parts.push(`${messageColors.success(dnsStats.whoisHits)} whois cached, ${messageColors.timing(dnsStats.whoisMisses)} fresh`);
      }
      console.log(messageColors.info('DNS cache:') + ` ${parts.join(' | ')}`);
      if (dnsStats.freshDig.length > 0) {
        console.log(messageColors.info('  Fresh dig:') + ` ${dnsStats.freshDig.join(', ')}`);
      }
      if (dnsStats.freshWhois.length > 0) {
        console.log(messageColors.info('  Fresh whois:') + ` ${dnsStats.freshWhois.join(', ')}`);
      }
    }
  }
  
  // Run the same cleanup the SIGINT/SIGTERM emergency handler does, so normal
  // scan completion isn't left depending on process.exit(0) to override
  // lingering setInterval handles (the cloudflare detection cache schedules
  // one that's otherwise only stopped on signal-driven shutdown).
  try { cleanupCloudflareCache(); } catch (_) {}
  try { wgDisconnectAll(forceDebug); } catch (_) {}
  try { ovpnDisconnectAll(forceDebug); } catch (_) {}
  try { await closeAllSocksRelays(forceDebug); } catch (_) {}

  // Clean process termination
  if (forceDebug) console.log(formatLogMessage('debug', `About to exit process...`));
  process.exit(0);

})();
