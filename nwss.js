// === Network scanner script (nwss.js) v2.0.25 ===

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
// Curl functionality (replace searchstring curl handler)
const { validateCurlAvailability, createCurlHandler: createCurlModuleHandler } = require('./lib/curl');
// Rule validation
const { validateRulesetFile, validateFullConfig, testDomainValidation, cleanRulesetFile } = require('./lib/validate_rules');
// CF Bypass
const { 
  handleCloudflareProtection,
  getCacheStats,
  clearDetectionCache,
  parallelChallengeDetection
} = require('./lib/cloudflare');
// FP Bypass
const { handleFlowProxyProtection, getFlowProxyTimeouts } = require('./lib/flowproxy');
// ignore_similar rules
const { shouldIgnoreSimilarDomain, calculateSimilarity } = require('./lib/ignore_similar');
// Graceful exit
const { handleBrowserExit, cleanupChromeTempFiles } = require('./lib/browserexit');
// Whois & Dig
const { createNetToolsHandler, createEnhancedDryRunCallback, validateWhoisAvailability, validateDigAvailability } = require('./lib/nettools');
// File compare
const { loadComparisonRules, filterUniqueRules } = require('./lib/compare');
// CDP functionality
const { createCDPSession, createPageWithTimeout, setRequestInterceptionWithTimeout } = require('./lib/cdp');
// Post-processing cleanup
const { processResults } = require('./lib/post-processing');
// Colorize various text when used
const { colorize, colors, messageColors, tags, formatLogMessage } = require('./lib/colorize');
// Enhanced mouse interaction and page simulation
const { performPageInteraction, createInteractionConfig } = require('./lib/interaction');
// Domain detection cache for performance optimization
const { createGlobalHelpers, getTotalDomainsSkipped, getDetectedDomainsCount } = require('./lib/domain-cache');
const { createSmartCache } = require('./lib/smart-cache'); // Smart cache system
const { clearPersistentCache } = require('./lib/smart-cache');
// Dry run functionality
const { initializeDryRunCollections, addDryRunMatch, addDryRunNetTools, processDryRunResults, writeDryRunOutput } = require('./lib/dry-run');
// Enhanced site data clearing functionality
const { clearSiteData } = require('./lib/clear_sitedata');

// Fast setTimeout helper for Puppeteer 22.x compatibility
// Uses standard Promise constructor for better performance than node:timers/promises
function fastTimeout(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// --- Configuration Constants ---
const TIMEOUTS = {
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
  PROTOCOL_TIMEOUT: 180000,           // Chrome DevTools Protocol timeout
  REDIRECT_JS_TIMEOUT: 5000           // JavaScript redirect detection timeout
};

const CACHE_LIMITS = {
  DISK_CACHE_SIZE: 52428800, // 50MB
  MEDIA_CACHE_SIZE: 52428800, // 50MB
  DEFAULT_CACHE_PATH: '.cache',
  DEFAULT_MAX_SIZE: 5000
};

const CONCURRENCY_LIMITS = {
  MIN: 1,
  MAX: 50,
  DEFAULT: 6,
  HIGH_CONCURRENCY_THRESHOLD: 12  // Auto-enable aggressive caching above this
};

const REALTIME_CLEANUP_THRESHOLD = 8; // Default pages to keep for realtime cleanup

/**
 * Detects the installed Puppeteer version dynamically
 * @returns {Object} Version info and compatibility settings
 */
function detectPuppeteerVersion() {
  try {
    const puppeteer = require('puppeteer');
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
const { monitorBrowserHealth, isBrowserHealthy, isQuicklyResponsive, performGroupWindowCleanup, performRealtimeWindowCleanup, trackPageForRealtime, updatePageUsage, cleanupPageBeforeReload } = require('./lib/browserhealth');

// --- Script Configuration & Constants --- 
const VERSION = '2.0.25'; // Script version

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

const headfulMode = args.includes('--headful');
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
const dryRunMode = args.includes('--dry-run');
const compressLogs = args.includes('--compress-logs');
const removeTempFiles = args.includes('--remove-tempfiles');
const validateConfig = args.includes('--validate-config');
const validateRules = args.includes('--validate-rules');
const testValidation = args.includes('--test-validation');
let cleanRules = args.includes('--clean-rules');
const clearCache = args.includes('--clear-cache');
const ignoreCache = args.includes('--ignore-cache');
const cacheRequests = args.includes('--cache-requests');

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

if (validateConfig) {
  console.log(`\n${messageColors.processing('Validating configuration file...')}`);
  try {
    const validation = validateFullConfig(config, { forceDebug, silentMode });
    
    // Validate referrer_headers format
    for (const site of sites) {
       if (site.referrer_headers && typeof site.referrer_headers === 'object' && !Array.isArray(site.referrer_headers)) {
         const validModes = ['random_search', 'social_media', 'direct_navigation', 'custom'];
         if (site.referrer_headers.mode && !validModes.includes(site.referrer_headers.mode)) {
           console.warn(`⚠ Invalid referrer_headers mode: ${site.referrer_headers.mode}. Valid modes: ${validModes.join(', ')}`);
         }
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
  --custom-json <file>           Use a custom config JSON file instead of config.json
  --headful                      Launch browser with GUI (not headless)
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
  --validate-config              Validate config.json file and exit
  --validate-rules [file]        Validate rule file format (uses --output/--compare files if no file specified)
  --clean-rules [file]           Clean rule files by removing invalid lines and optionally duplicates (uses --output/--compare files if no file specified)
  --test-validation              Run domain validation tests and exit
  --clear-cache                  Clear persistent cache before scanning (improves fresh start performance)
  --ignore-cache                 Bypass all smart caching functionality during scanning
  
Global config.json options:
  ignoreDomains: ["domain.com", "*.ads.com"]     Domains to completely ignore (supports wildcards)
  blocked: ["regex1", "regex2"]                   Global regex patterns to block requests (combined with per-site blocked)
  whois_server_mode: "random" or "cycle"      Default server selection mode for all sites (default: random)
  ignore_similar: true/false                      Ignore domains similar to already found domains (default: true)
  ignore_similar_threshold: 80                    Similarity threshold percentage for ignore_similar (default: 80)
  ignore_similar_ignored_domains: true/false      Ignore domains similar to ignoreDomains list (default: true)
  max_concurrent_sites: 8                        Maximum concurrent site processing (1-50, default: 8)
  resource_cleanup_interval: 80                  Browser restart interval in URLs processed (1-1000, default: 80)

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
  delay: <milliseconds>                        Delay after load (default: 4000)
  reload: <number>                             Reload page n times after load (default: 1)
  forcereload: true/false or ["domain1.com", "domain2.com"]  Force cache-clearing reload for all URLs or specific domains
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
  even_blocked: true/false                     Add matching rules even if requests are blocked (default: false)
  
  bypass_cache: true/false                     Skip all caching for this site's URLs (default: false)
  referrer_headers: "url" or ["url1", "url2"] Set referrer header for realistic traffic sources
  custom_headers: {"Header": "value"}         Add custom HTTP headers to requests

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
  blocked: globalBlocked = [], 
  whois_delay = 3000, 
  whois_server_mode = 'random', 
  ignore_similar = true, 
  ignore_similar_threshold = 80, 
  ignore_similar_ignored_domains = true, 
  max_concurrent_sites = 6,
  resource_cleanup_interval = 80,
  comments: globalComments, 
  ...otherGlobalConfig 
} = config;

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
        console.log(formatLogMessage('debug', `[SmartCache] Error marking domain: ${cacheErr.message}`));
      }
    }
  }
}

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

// Add global cycling index tracker for whois server selection
let globalWhoisServerIndex = 0;

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
  // Track active frames and clear on navigation to prevent detached frame access
  let activeFrames = new Set(); // Use Set to track frame references
  
  // Clear frame tracking on navigation to prevent stale references
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) {
      // Main frame navigated - clear all tracked frames
      activeFrames.clear();
    }
  });

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
        // Test frame accessibility first
        frameUrl = frame.url();
        
        // Check if frame is detached (if method exists)
        if (frame.isDetached && frame.isDetached()) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Skipping detached frame`));
          }
          return;
        }
      } catch (frameAccessError) {
        // Frame is not accessible (likely detached)
        return;
      }
      
      activeFrames.add(frame);
    } catch (detachError) {
      // Frame state checking can throw in 23.x, handle gracefully
      if (forceDebug) {
        console.log(formatLogMessage('debug', `Frame state check failed: ${detachError.message}`));
      }
      return;
    }

    // Store frame with timestamp for tracking
    activeFrames.add(frame);
    
    if (frame !== page.mainFrame() && frame.parentFrame()) { // Only handle child frames
      try {       
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
    let frameUrl;

    // Skip if frame is not in our active set
    if (!activeFrames.has(frame)) return;

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
    
    // Skip logging if we can't access frame URL
    let frameUrl;
    if (forceDebug) {
      try {
        frameUrl = frame.url();
      } catch (urlErr) {
        // Frame already detached, can't get URL
        return;
      }
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
  async function createBrowser() {
    // Create temporary user data directory that we can fully control and clean up
    const tempUserDataDir = `/tmp/puppeteer-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    userDataDir = tempUserDataDir; // Store for cleanup tracking (use outer scope variable)

    // Try to find system Chrome installation to avoid Puppeteer downloads

    // Detect Puppeteer version for headless mode compatibility
    let headlessMode = launchHeadless;
    if (launchHeadless) {
      const puppeteerInfo = detectPuppeteerVersion();
      
      if (puppeteerInfo.useShellMode) {
        headlessMode = 'shell'; // Use fast chrome-headless-shell for 22.x+
        if (forceDebug) console.log(formatLogMessage('debug', `Using chrome-headless-shell (Puppeteer ${puppeteerInfo.version || 'v' + puppeteerInfo.majorVersion + '.x'})`));
      } else {
        headlessMode = true; // Use regular headless for older versions
        if (forceDebug) console.log(formatLogMessage('debug', 'Could not detect Puppeteer version, using regular headless mode'));
      }
    } else {
      headlessMode = false; // Headful mode
    }

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
    const browser = await puppeteer.launch({
      // Use system Chrome if available to avoid downloads
      executablePath: executablePath,
      // Force temporary user data directory for complete cleanup control
      userDataDir: tempUserDataDir,
      // Puppeteer 22.x headless mode optimization
      // Auto-detect best headless mode based on Puppeteer version
      headless: headlessMode,
      args: [
        // Disk space controls - 50MB cache limits
        '--disable-features=VizDisplayCompositor',
        `--disk-cache-size=${CACHE_LIMITS.DISK_CACHE_SIZE}`, // 50MB disk cache
        `--media-cache-size=${CACHE_LIMITS.MEDIA_CACHE_SIZE}`, // 50MB media cache
        '--disable-application-cache',
        '--disable-offline-load-stale-cache',
        '--disable-background-downloads',
        // PERFORMANCE: Enhanced Puppeteer 23.x optimizations
        '--disable-features=AudioServiceOutOfProcess,VizDisplayCompositor',
        '--disable-features=TranslateUI,BlinkGenPropertyTrees,Translate',
        '--disable-features=BackForwardCache,AcceptCHFrame',
        '--disable-ipc-flooding-protection',
        '--aggressive-cache-discard',
        '--memory-pressure-off',
        '--max_old_space_size=2048',
        '--no-first-run',
        '--disable-prompt-on-repost',  // Fixes form popup on page reload
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
        '--max_old_space_size=1024',
        '--ignore-ssl-errors',
        '--ignore-certificate-errors',
        '--ignore-certificate-errors-spki-list',
        '--ignore-certificate-errors-ca-list',
        '--disable-web-security',
        '--allow-running-insecure-content',
        '--disable-features=HttpsFirstBalancedModeAutoEnable',
        // Puppeteer 23.x: Enhanced performance and stability args
        '--disable-renderer-backgrounding',
        '--disable-backgrounding-occluded-windows',
        '--disable-background-timer-throttling',
        '--disable-features=site-per-process', // Better for single-site scanning
        '--disable-blink-features=AutomationControlled', // Avoid detection
        '--no-zygote', // Better process isolation
        ],
        // Optimized timeouts for Puppeteer 23.x performance
        protocolTimeout: TIMEOUTS.PROTOCOL_TIMEOUT,
        slowMo: 0, // No artificial delays
        defaultViewport: null, // Use system default viewport
        ignoreDefaultArgs: ['--enable-automation'] // Avoid automation detection
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
    console.log(formatLogMessage('debug', `Using chrome-headless-shell for maximum performance`));
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
    await performEmergencyCleanup();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    if (forceDebug) console.log(formatLogMessage('debug', 'SIGTERM received, performing cleanup...'));
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
    const allowFirstParty = siteConfig.firstParty === true || siteConfig.firstParty === 1;
    const allowThirdParty = siteConfig.thirdParty === undefined || siteConfig.thirdParty === true || siteConfig.thirdParty === 1;
    const perSiteSubDomains = siteConfig.subDomains === 1 ? true : subDomainsMode;
    const siteLocalhostIP = siteConfig.localhost || null;
    const cloudflarePhishBypass = siteConfig.cloudflare_phish === true;
    const cloudflareBypass = siteConfig.cloudflare_bypass === true;
    // Add redirect and same-page loop protection
    const MAX_REDIRECT_DEPTH = siteConfig.max_redirects || 10;
    const redirectHistory = new Set();
    let redirectCount = 0;
    const pageLoadHistory = new Map(); // Track same-page reloads
    const MAX_SAME_PAGE_LOADS = 3;
    let currentPageUrl = currentUrl;

    const sitePrivoxy = siteConfig.privoxy === true;
    const sitePihole = siteConfig.pihole === true;
    const flowproxyDetection = siteConfig.flowproxy_detection === true;
    
    const evenBlocked = siteConfig.even_blocked === true;
    // Log site-level comments if debug mode is enabled
    if (forceDebug && siteConfig.comments) {
      const siteComments = Array.isArray(siteConfig.comments) ? siteConfig.comments : [siteConfig.comments];
      console.log(formatLogMessage('debug', `Site comments for ${currentUrl}: ${siteComments.length} item(s)`));
      siteComments.forEach((comment, idx) => 
        console.log(formatLogMessage('debug', `  Site comment ${idx + 1}: ${comment}`))
      );
    }

   // Log bypass_cache setting if enabled
   if (forceDebug && siteConfig.bypass_cache === true) {
     console.log(formatLogMessage('debug', `Cache bypass enabled for all URLs in site: ${currentUrl}`));
   }

    if (siteConfig.firstParty === 0 && siteConfig.thirdParty === 0) {
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
    const CRITICAL_BROWSER_ERRORS = [
      'Protocol error',
      'Target closed',
      'Browser has been closed',
      'Browser protocol broken',
      'Browser process exited',
      'Browser disconnected'
    ];

    try {

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
          console.log(formatLogMessage('debug', `[realtime_cleanup] Using extended delay for Cloudflare site: ${totalDelay}ms (${siteDelay}ms + ${bufferTime}ms CF buffer)`));
        }
        
        const realtimeResult = await performRealtimeWindowCleanup(browserInstance, threshold, forceDebug, totalDelay);
        if (realtimeResult.success && realtimeResult.closedCount > 0 && forceDebug) {
          console.log(formatLogMessage('debug', `[realtime_cleanup] Cleaned ${realtimeResult.closedCount} old pages, ${realtimeResult.remainingPages} remaining`));
        }
      } 
    
      // Set aggressive timeouts for problematic operations
      // Optimized timeouts for Puppeteer 23.x responsiveness
      page.setDefaultTimeout(Math.min(timeout, TIMEOUTS.DEFAULT_PAGE_REDUCED));
      page.setDefaultNavigationTimeout(Math.min(timeout, TIMEOUTS.DEFAULT_NAVIGATION));
      // Aggressive timeouts prevent hanging in Puppeteer 23.x while maintaining speed
      
      page.on('console', (msg) => {
        if (forceDebug && msg.type() === 'error') console.log(`[debug] Console error: ${msg.text()}`);
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
      
      page.on('response', (response) => {
        // Response handler - removed incorrect error logging
      });

      // Apply flowProxy timeouts if detection is enabled
      if (flowproxyDetection) {
        const flowproxyTimeouts = getFlowProxyTimeouts(siteConfig);
        page.setDefaultTimeout(Math.min(flowproxyTimeouts.pageTimeout, TIMEOUTS.DEFAULT_NAVIGATION));
        page.setDefaultNavigationTimeout(Math.min(flowproxyTimeouts.navigationTimeout, TIMEOUTS.DEFAULT_PAGE));
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
                  console.log(formatLogMessage('debug', `[evalOnDoc] Global Fetch/XHR interception enabled, applying to: ${currentUrl}`));
              } else { // siteConfig.evaluateOnNewDocument must be true
                  console.log(formatLogMessage('debug', `[evalOnDoc] Site-specific Fetch/XHR interception enabled for: ${currentUrl}`));
              }
          }
          
          // Strategy 1: Try full injection with health check
          let browserResponsive = false;
          try {
              // Check if browser is still connected before attempting health check
              if (!browserInstance.isConnected()) {
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
                  console.log(formatLogMessage('debug', `[evalOnDoc] Browser health check failed: ${healthErr.message}`));
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
                      console.log(formatLogMessage('debug', `[evalOnDoc] Full injection successful for ${currentUrl}`));
                  }
              } catch (fullInjectionErr) {
                  // Enhanced error detection for CDP issues
                  const isCDPError = fullInjectionErr.constructor.name === 'ProtocolError' ||
                                    fullInjectionErr.name === 'ProtocolError' ||
                                    fullInjectionErr.message.includes('addScriptToEvaluateOnNewDocument timed out') ||
                                    fullInjectionErr.message.includes('Protocol error');
                  
                  if (forceDebug) {
                      const errorType = isCDPError ? 'CDP/Protocol error' : 'timeout/other';
                      console.log(formatLogMessage('debug', `[evalOnDoc] Full injection failed (${errorType}): ${fullInjectionErr.message}`));
                  }

                  // Skip fallback for CDP errors - they indicate browser communication issues
                  if (isCDPError) {
                      console.warn(formatLogMessage('warn', `[evalOnDoc] CDP communication failure - skipping injection for ${currentUrl}`));
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
                              
                              const pageUrl = await page.url().catch(() => 'about:blank');
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
                          console.log(formatLogMessage('debug', `[evalOnDoc] Minimal injection successful for ${currentUrl}`));
                      }
                  } catch (minimalInjectionErr) {
                      if (forceDebug) {
                          console.log(formatLogMessage('debug', `[evalOnDoc] Minimal injection also failed: ${minimalInjectionErr.message}`));
                      }
                      evalOnDocSuccess = false;
                  }
              }
           } 
          } else {
              if (forceDebug) {
                  console.log(formatLogMessage('debug', `[evalOnDoc] Browser unresponsive, skipping injection for ${currentUrl}`));
              }
              evalOnDocSuccess = false;
          }
          
          // Final status logging
          if (!evalOnDocSuccess) {
              console.warn(formatLogMessage('warn', `[evalOnDoc] All injection strategies failed for ${currentUrl} - continuing with standard request monitoring only`));
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
          console.warn(formatLogMessage('warn', `[css_blocked] Failed to set up CSS element blocking for ${currentUrl}: ${cssErr.message}`));
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
          if (forceDebug) console.log(formatLogMessage('debug', `[clear_sitedata] Failed for ${currentUrl}: ${clearErr.message}`));
        }
      }

      // --- Apply all fingerprint spoofing (user agent, Brave, fingerprint protection) ---
      try {
        await applyAllFingerprintSpoofing(page, siteConfig, forceDebug, currentUrl);
        
        // Client Hints protection for Chrome user agents
        if (siteConfig.userAgent && siteConfig.userAgent.toLowerCase().includes('chrome')) {
          let platform = 'Windows';
          let platformVersion = '15.0.0';
          let arch = 'x86';
          
          if (siteConfig.userAgent.toLowerCase() === 'chrome_mac') {
            platform = 'macOS';
            platformVersion = '13.5.0';
            arch = 'arm';
          } else if (siteConfig.userAgent.toLowerCase() === 'chrome_linux') {
            platform = 'Linux';
            platformVersion = '6.5.0';
            arch = 'x86';
          }
          
          await page.setExtraHTTPHeaders({
            'Sec-CH-UA': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
            'Sec-CH-UA-Platform': `"${platform}"`,
            'Sec-CH-UA-Platform-Version': `"${platformVersion}"`,
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Arch': `"${arch}"`,
            'Sec-CH-UA-Bitness': '"64"',
            'Sec-CH-UA-Full-Version': '"140.0.7339.208"',
            'Sec-CH-UA-Full-Version-List': '"Chromium";v="140.0.7339.208", "Not=A?Brand";v="24.0.0.0", "Google Chrome";v="140.0.7339.208"'
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

      const regexes = Array.isArray(siteConfig.filterRegex)
        ? siteConfig.filterRegex.map(r => new RegExp(r.replace(/^\/(.*)\/$/, '$1')))
        : siteConfig.filterRegex
          ? [new RegExp(siteConfig.filterRegex.replace(/^\/(.*)\/$/, '$1'))]
          : [];

      // NEW: Get regex_and setting (defaults to false for backward compatibility)
      const useRegexAnd = siteConfig.regex_and === true;

   // Parse searchstring patterns using module
   const { searchStrings, searchStringsAnd, hasSearchString, hasSearchStringAnd } = parseSearchStrings(siteConfig.searchstring, siteConfig.searchstring_and);
   const useCurl = siteConfig.curl === true; // Use curl if enabled, regardless of searchstring
   let useGrep = siteConfig.grep === true && useCurl; // Grep requires curl to be enabled

   // Get user agent for curl if needed
   let curlUserAgent = '';
   if (useCurl && siteConfig.userAgent) {
     const userAgents = {
       chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
       chrome_mac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
       chrome_linux: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
       firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/143.0",
       firefox_mac: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/143.0",
       firefox_linux: "Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/143.0",
       safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15"
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
   
   // Validate curl availability if needed
   if (useCurl) {
     const curlCheck = validateCurlAvailability();
     if (!curlCheck.isAvailable) {
       console.warn(formatLogMessage('warn', `Curl not available for ${currentUrl}: ${curlCheck.error}. Skipping curl-based analysis.`));
       useCurl = false;
       useGrep = false; // Grep requires curl
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
               console.log(formatLogMessage('debug', `[SmartCache] Used cached similarity: ${domain} ~= ${existingDomain} (${cachedSimilarity}%)`));
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
           console.log(formatLogMessage('debug', `[SmartCache] Skipping cached domain: ${domain}`));
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
             console.log(formatLogMessage('debug', `[ignore_similar] Skipping ${domain}: ${similarCheck.reason}`));
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
            console.log(formatLogMessage('debug', `[ignore_similar_ignored_domains] Skipping ${domain}: ${ignoredSimilarCheck.reason} (similar to ignoreDomains)`));
          }
          return; // Skip adding this domain
        }
      }

      // Mark full subdomain as detected for future reference
      markDomainAsDetected(cacheKey);
      
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
      console.log(formatLogMessage('debug', `[SmartCache] Error marking domain: ${cacheErr.message}`));
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
        const checkedRootDomain = safeGetDomain(checkedUrl, false); // Root domain for first-party detection
        // Check against ALL first-party domains (original + all redirects)
        // This prevents redirect destinations from being marked as third-party
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
            request.url().includes('go.dmzjmp.com/api/models')) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Blocking potential infinite iframe loop: ${request.url()}`));
          }
          request.abort();
          return;
        }

        // Enhanced debug logging to show which frame the request came from
        if (forceDebug) {
          let frameUrl = 'unknown-frame';
          let isMainFrame = false;
          
          try {
            const frame = request.frame();
            if (frame) {
              frameUrl = frame.url();
              isMainFrame = frame === page.mainFrame();
            }
          } catch (frameErr) {
            frameUrl = 'detached-frame';
          }
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
        
        // ALWAYS extract the FULL subdomain for cache checking to preserve unique subdomains
        const fullSubdomain = safeGetDomain(reqUrl, true); // Always get full subdomain for cache
        const reqDomain = safeGetDomain(reqUrl, perSiteSubDomains); // Output domain based on config

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
          
          // NEW: Check if even_blocked is enabled and this URL matches filter regex
          if (evenBlocked) {
            // reqDomain already defined above
            if (reqDomain && !matchesIgnoreDomain(reqDomain, ignoreDomains)) {
              for (const re of regexes) {
                if (re.test(reqUrl)) {
                  const resourceType = request.resourceType();
                  
                  // Apply same filtering logic as unblocked requests
                  const allowedResourceTypes = siteConfig.resourceTypes;
                  if (!allowedResourceTypes || !Array.isArray(allowedResourceTypes) || allowedResourceTypes.includes(resourceType)) {
                    if (dryRunMode) {
                      addDryRunMatch(matchedDomains, {
                        regex: matchedRegexPattern,
                        domain: reqDomain,
                        resourceType: resourceType,
                        fullUrl: reqUrl,
                        isFirstParty: isFirstParty,
                        wasBlocked: true
                      });
                    } else {
                      addMatchedDomain(reqDomain, resourceType, fullSubdomain);
                    }
                    
                    const simplifiedUrl = getRootDomain(currentUrl);
                    if (siteConfig.verbose === 1) {
                      const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
                      console.log(formatLogMessage('match', `[${simplifiedUrl}] ${reqUrl} matched regex: ${matchedRegexPattern} and resourceType: ${resourceType}${resourceInfo}`));
                    }
                    if (dumpUrls) {
                      const timestamp = new Date().toISOString();
                      const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
                      fs.appendFileSync(matchedUrlsLogFile, `${timestamp} [match][${simplifiedUrl}] ${reqUrl} (resourceType: ${resourceType})${resourceInfo} [BLOCKED BUT ADDED]\n`);
                    }
                    break; // Only match once per URL
                  }
                }
              }
            }
          }
          
          request.abort();
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
           const allowedResourceTypes = siteConfig.resourceTypes;
           if (allowedResourceTypes && Array.isArray(allowedResourceTypes) && allowedResourceTypes.length > 0) {
             if (!allowedResourceTypes.includes(resourceType)) {
               if (forceDebug) {
                 console.log(formatLogMessage('debug', `URL ${reqUrl} matches regex but resourceType '${resourceType}' not in allowed types [${allowedResourceTypes.join(', ')}]. Skipping ALL processing.`));
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
                whoisDelay: siteConfig.whois_delay !== undefined ? siteConfig.whois_delay : whois_delay,
                whoisServer,
                whoisServerMode: siteConfig.whois_server_mode || whois_server_mode,
                debugLogFile,
                fs,
                digTerms,
                digOrTerms,
                digRecordType,
                digSubdomain: siteConfig.dig_subdomain === true,
                dryRunCallback: dryRunMode ? createEnhancedDryRunCallback(matchedDomains, forceDebug) : null,
                matchedDomains,
                addMatchedDomain,
                isDomainAlreadyDetected,
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
                fs
              });
              
              // Execute nettools check asynchronously
              const originalDomain = fullSubdomain;
              setImmediate(() => netToolsHandler(reqDomain, originalDomain));
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
             const simplifiedUrl = getRootDomain(currentUrl);
             if (siteConfig.verbose === 1) {
               const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
              console.log(formatLogMessage('match', `[${simplifiedUrl}] ${reqUrl} matched regex: ${matchedRegexPattern} and resourceType: ${resourceType}${resourceInfo}`));
             }
             if (dumpUrls) {
               const timestamp = new Date().toISOString();
               const resourceInfo = (adblockRulesMode || siteConfig.adblock_rules) ? ` (${resourceType})` : '';
               fs.appendFileSync(matchedUrlsLogFile, `${timestamp} [match][${simplifiedUrl}] ${reqUrl} (resourceType: ${resourceType})${resourceInfo}\n`);
             }
            } else if (hasNetTools && !hasSearchString && !hasSearchStringAnd) {
             // If nettools are configured (whois/dig), perform checks on the domain
             // Skip nettools check if full subdomain was already detected
             if (isDomainAlreadyDetected(fullSubdomain)) {
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
               console.log(formatLogMessage('debug', `[SmartCache] Using cached nettools results for ${reqDomain}`));
             }
             
             // Create nettools handler with cache callbacks (if cache is enabled)
             const netToolsHandler = createNetToolsHandler({
               whoisTerms,
               whoisOrTerms,
               whoisDelay: siteConfig.whois_delay !== undefined ? siteConfig.whois_delay : whois_delay, // Site-specific or global fallback
	       whoisServer, // Pass whois server configuration
               whoisServerMode: siteConfig.whois_server_mode || whois_server_mode,
               debugLogFile, // Pass debug log file for whois error logging
               fs, // Pass fs module for file operations
               digTerms,
               digOrTerms,
               digRecordType,
               digSubdomain: siteConfig.dig_subdomain === true,
               // Add dry run callback for nettools results
               dryRunCallback: dryRunMode ? createEnhancedDryRunCallback(matchedDomains, forceDebug) : null,
               matchedDomains,
               addMatchedDomain,
               isDomainAlreadyDetected,
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
               fs
             });
             
             // Execute nettools check asynchronously
            const originalDomain = fullSubdomain; // Use full subdomain for nettools
            setImmediate(() => netToolsHandler(reqDomain, originalDomain));

             // Do NOT continue processing this request for immediate domain addition
             // The nettools handler is responsible for adding the domain if validation passes
             if (forceDebug) {
               console.log(formatLogMessage('debug', `Request processing halted for ${reqUrl} - awaiting nettools validation`));
             }
           } else {
             // If searchstring or searchstring_and IS defined (with or without nettools), queue for content checking
             // Skip searchstring check if full subdomain was already detected
             if (isDomainAlreadyDetected(fullSubdomain)) {
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
             // Check bypass_cache before attempting cache lookup
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
               console.log(formatLogMessage('debug', `[SmartCache] Using cached response content for ${reqUrl.substring(0, 50)}...`));
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
                   isDomainAlreadyDetected,
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
                   hasSearchString: hasSearchString || hasSearchStringAnd,
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
                   isDomainAlreadyDetected,
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
           }

          // No break needed since we've already determined if regex matched
        }
        request.continue();
      });

      // Mark page as actively processing network requests
      updatePageUsage(page, true);

     // Add response handler ONLY if searchstring/searchstring_and is defined AND neither curl nor grep is enabled
     if ((hasSearchString || hasSearchStringAnd) && !useCurl && !useGrep) {
       const responseHandler = createResponseHandler({
         searchStrings,
         searchStringsAnd,
         hasSearchStringAnd,
         regexes,
         matchedDomains,
         addMatchedDomain, // Pass the helper function
         bypassCache: (url) => shouldBypassCacheForUrl(url, siteConfig),
         isDomainAlreadyDetected,
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
            const referrerUrl = Array.isArray(siteConfig.referrer_headers) 
              ? siteConfig.referrer_headers[0] 
              : siteConfig.referrer_headers;
            // Ensure referrer is a valid string URL, not an object
            return typeof referrerUrl === 'string' && referrerUrl.startsWith('http') 
              ? { referer: referrerUrl } 
              : {};
          })())
        };
        const gotoOptions = siteConfig.goto_options 
          ? { ...defaultGotoOptions, ...siteConfig.goto_options } : defaultGotoOptions;

        // Enhanced navigation with redirect handling - passes existing gotoOptions
        const navigationResult = await navigateWithRedirectHandling(page, currentUrl, siteConfig, gotoOptions, forceDebug, formatLogMessage);
        
        const { finalUrl, redirected, redirectChain, originalUrl, redirectDomains } = navigationResult;
        
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
            if (!silentMode) {
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
              // Invalid final URL - don't update currentUrl, treat as failed redirect
              console.warn(`⚠ Redirect to invalid URL ignored: ${originalDomain} → ${finalUrl}`);
              if (forceDebug) {
                console.log(formatLogMessage('debug', `Redirect chain ended with invalid URL, keeping original: ${originalUrl}`));
              }
              // Keep processing with the original URL or throw an error
              throw new Error(`Redirect resulted in invalid URL: ${finalUrl}`);
            }
          }
        }
        
        siteCounter++;

        // Enhanced Cloudflare handling with parallel detection
        if (siteConfig.cloudflare_parallel_detection !== false) { // Enable by default
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

        // Handle all Cloudflare protections using the enhanced module
        const cloudflareResult = await handleCloudflareProtection(page, currentUrl, siteConfig, forceDebug);

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
        } else if (cloudflareResult.verificationChallenge?.success && forceDebug) {
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
        await page.evaluate(() => { console.log('Safe to evaluate on loaded page.'); });
        
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
          console.log(`⚠ Partial redirect timeout recovered: ${safeGetDomain(currentUrl)} → ${safeGetDomain(timeoutResult.finalUrl)}`);
          currentUrl = timeoutResult.finalUrl; // Use the partial redirect URL
          siteCounter++;
          // Continue processing with the redirected URL instead of throwing error
        } else {
          console.error(formatLogMessage('error', `Failed on ${currentUrl}: ${err.message}`));
          throw err;
        }
      }
      }

      if (interactEnabled && !disableInteract) {
        if (forceDebug) console.log(formatLogMessage('debug', `interaction simulation enabled for ${currentUrl}`));
        
        // Mark page as processing during interactions
        updatePageUsage(page, true);
        // Use enhanced interaction module
        await performPageInteraction(page, currentUrl, interactionConfig, forceDebug);
      }

      const delayMs = DEFAULT_DELAY;
      
      // Optimized delays for Puppeteer 23.x performance
      const isFastSite = timeout <= TIMEOUTS.FAST_SITE_THRESHOLD;
      const networkIdleTime = TIMEOUTS.NETWORK_IDLE;  // Balanced: 2s for reliable network detection
      const networkIdleTimeout = Math.min(timeout / 2, TIMEOUTS.NETWORK_IDLE_MAX);  // Balanced: 10s timeout
      const actualDelay = Math.min(delayMs, TIMEOUTS.NETWORK_IDLE);  // Balanced: 2s delay for stability
      
      await page.waitForNetworkIdle({ 
        idleTime: networkIdleTime, 
        timeout: networkIdleTimeout 
      });
      // Use fast timeout helper for Puppeteer 23.x compatibility with better performance
      await fastTimeout(actualDelay);

      // Apply additional delay for flowProxy if detected
      if (flowproxyDetection) {
        const additionalDelay = Math.min(siteConfig.flowproxy_additional_delay || 3000, 3000);
        if (forceDebug) console.log(formatLogMessage('debug', `Applying flowProxy additional delay: ${additionalDelay}ms`));
        await fastTimeout(additionalDelay);
      }

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
            const clearResult = await clearSiteData(page, currentUrl, forceDebug, true); // Quick mode for reloads
            if (forceDebug) console.log(formatLogMessage('debug', `Cleared site data before reload #${i} for ${currentUrl}`));
          } catch (reloadClearErr) {
            if (forceDebug) console.log(formatLogMessage('debug', `[clear_sitedata] Before reload failed for ${currentUrl}`));
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
        const formattedRules = formatRules(matchedDomains, siteConfig, globalOptions);
        
        return { 
          url: currentUrl, 
          rules: formattedRules, 
          success: true,
          finalUrl: finalUrlAfterRedirect || currentUrl,
          redirectDomains: redirectDomainsToExclude
        };
      }
      
    } catch (err) {
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
         
      // For other errors, preserve any matches we found before the error
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
          rules: formattedRules, 
          success: false, 
          hasMatches: true,
          finalUrl: finalUrlAfterRedirect || currentUrl,
          redirectDomains: redirectDomainsToExclude
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

  // Create a flat list of all URL tasks with their site configs for true concurrency
  const allTasks = [];
  for (const site of sites) {
    const urlsToProcess = Array.isArray(site.url) ? site.url : [site.url];
    urlsToProcess.forEach(url => {
      allTasks.push({
        url,
        config: { ...site, _originalUrl: url }, // Preserve original URL for CDP domain checking
        taskId: allTasks.length // For tracking
      });
    });
  }
  
  const totalUrls = allTasks.length;

  let results = [];
  let processedUrlCount = 0;
  let urlsSinceLastCleanup = 0;
  
  if (!silentMode && totalUrls > 0) {
    console.log(`\n${messageColors.processing('Processing')} ${totalUrls} URLs with TRUE concurrency ${MAX_CONCURRENT_SITES}...`);
    if (totalUrls > RESOURCE_CLEANUP_INTERVAL) {
      console.log(messageColors.processing('Browser will restart every') + ` ~${RESOURCE_CLEANUP_INTERVAL} URLs to free resources`);
    }
  }

  // Hang detection for debugging concurrency issues
  let currentBatchInfo = { batchStart: 0, batchSize: 0 };
  const hangDetectionInterval = setInterval(() => {
  // Only show hang detection messages in debug mode
  if (forceDebug) {
    const currentBatch = Math.floor(currentBatchInfo.batchStart / RESOURCE_CLEANUP_INTERVAL) + 1;
    const totalBatches = Math.ceil(totalUrls / RESOURCE_CLEANUP_INTERVAL);
    console.log(formatLogMessage('debug', `[HANG CHECK] Processed: ${processedUrlCount}/${totalUrls} URLs, Batch: ${currentBatch}/${totalBatches}, Current batch size: ${currentBatchInfo.batchSize}`));
    console.log(formatLogMessage('debug', `[HANG CHECK] URLs since cleanup: ${urlsSinceLastCleanup}, Recent failures: ${results.slice(-3).filter(r => !r.success).length}/3`));
    }
  }, 30000); // Check every 30 seconds

  // Process URLs in batches to maintain concurrency while allowing browser restarts
  let siteGroupIndex = 0;
  for (let batchStart = 0; batchStart < totalUrls; batchStart += RESOURCE_CLEANUP_INTERVAL) {
    const batchEnd = Math.min(batchStart + RESOURCE_CLEANUP_INTERVAL, totalUrls);
    const currentBatch = allTasks.slice(batchStart, batchEnd);

    
    // Group tasks by their source site configuration for window cleanup
    const tasksBySite = new Map();
    currentBatch.forEach(task => {
      const siteKey = `site_${sites.indexOf(task.config)}`;
      if (!tasksBySite.has(siteKey)) {
        tasksBySite.set(siteKey, []);
      }
      tasksBySite.get(siteKey).push(task);
    });
    
    // IMPROVED: Only check health if we have indicators of problems
    let healthCheck = { shouldRestart: false, reason: null };
    const recentResults = results.slice(-8); // Check more results for better pattern detection
    const recentFailureRate = recentResults.length > 0 ? 
      recentResults.filter(r => !r.success).length / recentResults.length : 0;
    const hasHighFailureRate = recentFailureRate > 0.75; // 75% failure threshold (more conservative)
    const hasCriticalErrors = recentResults.filter(r => r.needsImmediateRestart).length > 2;
    
    // Only run health checks when we have STRONG indicators of problems
    if (urlsSinceLastCleanup > 15 && (
        (hasHighFailureRate && recentResults.length >= 5) ||  // Need sufficient sample size
        hasCriticalErrors ||
        urlsSinceLastCleanup > RESOURCE_CLEANUP_INTERVAL * 0.9  // Very close to cleanup limit
    )) {
      healthCheck = await monitorBrowserHealth(browser, {}, {
        siteIndex: Math.floor(batchStart / RESOURCE_CLEANUP_INTERVAL),
        totalSites: Math.ceil(totalUrls / RESOURCE_CLEANUP_INTERVAL),
        urlsSinceCleanup: urlsSinceLastCleanup,
        cleanupInterval: RESOURCE_CLEANUP_INTERVAL,
        forceDebug,
        silentMode
      });
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
    
    // Restart browser if we've processed enough URLs, health check suggests it, and this isn't the last site
    if ((wouldExceedLimit || shouldRestartFromHealth || (hasHighFailureRate && recentResults.length >= 6)) && urlsSinceLastCleanup > 8 && isNotLastBatch) {
      
      let restartReason = 'Unknown';
      if (shouldRestartFromHealth) {
        restartReason = healthCheck.reason;
      } else if (hasHighFailureRate) {
        restartReason = `High failure rate: ${Math.round(recentFailureRate * 100)}% in recent batch`;
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
            console.log(formatLogMessage('debug', `[SmartCache] Cleared ${clearedCount} request cache entries during browser restart`));
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
        if (userDataDir && fs.existsSync(userDataDir)) {
          fs.rmSync(userDataDir, { recursive: true, force: true });
          if (forceDebug) console.log(formatLogMessage('debug', `Cleaned user data dir: ${userDataDir}`));
        }

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
      
      // Create new browser for next batch
      browser = await createBrowser();
      if (forceDebug) console.log(formatLogMessage('debug', `New browser instance created for batch ${Math.floor(batchStart / RESOURCE_CLEANUP_INTERVAL) + 1}`));
      
      // Reset cleanup counter and add delay
      urlsSinceLastCleanup = 0;
      await fastTimeout(TIMEOUTS.BROWSER_STABILIZE_DELAY);
    }
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Processing batch ${Math.floor(batchStart / RESOURCE_CLEANUP_INTERVAL) + 1}: ${batchSize} URL(s) (total processed: ${processedUrlCount})`));
    }
    
    // Log start of concurrent processing for hang detection
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[CONCURRENCY] Starting ${batchSize} concurrent tasks with limit ${MAX_CONCURRENT_SITES}`));
    }
    
    // Create tasks with current browser instance and process them with TRUE concurrency
    const batchTasks = currentBatch.map(task => originalLimit(() => processUrl(task.url, task.config, browser)));
    const batchResults = await Promise.all(batchTasks);

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
      console.log(formatLogMessage('debug', `[CONCURRENCY] Completed ${batchSize} concurrent tasks, ${batchResults.filter(r => r.success).length} successful`));
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
    
    processedUrlCount += batchSize;
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
            console.log(formatLogMessage('debug', `[SmartCache] Cleared ${clearedCount} request cache entries during emergency restart`));
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
        // Additional cleanup after emergency restart
        if (removeTempFiles) {
          await cleanupChromeTempFiles({ 
            includeSnapTemp: true, 
            forceDebug,
            comprehensive: true 
          });
        }
        browser = await createBrowser();
        urlsSinceLastCleanup = 0; // Reset counter
        await fastTimeout(TIMEOUTS.EMERGENCY_RESTART_DELAY); // Give browser time to stabilize
      } catch (emergencyRestartErr) {
        if (forceDebug) console.log(formatLogMessage('debug', `Emergency restart failed: ${emergencyRestartErr.message}`));
      }
    }
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
        console.log(`\n🗑️  Cleared request cache: ${clearedCount} entries after JSON processing`);
      }
      if (forceDebug) {
        console.log(formatLogMessage('debug', 
          `[SmartCache] Request cache cleared after JSON scan completion (hit rate: ${requestCacheStats.hitRate})`
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
     // Log smart cache statistics (if cache is enabled)
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
 
  // Perform comprehensive final cleanup using enhanced browserexit module
  if (forceDebug) console.log(formatLogMessage('debug', `Starting comprehensive browser cleanup...`));

  // Enhanced final validation for Puppeteer 23.x
  try {
    const isStillConnected = browser.isConnected();
    if (forceDebug) console.log(formatLogMessage('debug', `Browser connection status before cleanup: ${isStillConnected}`));
  } catch (connErr) {
    if (forceDebug) console.log(formatLogMessage('debug', `Browser connection check failed: ${connErr.message}`));
  }

  const cleanupResult = await handleBrowserExit(browser, {
    forceDebug,
    timeout: 10000,
    exitOnFailure: true,
    cleanTempFiles: true,
    comprehensiveCleanup: removeTempFiles,  // Use --remove-tempfiles flag
    userDataDir: browser._nwssUserDataDir,
    verbose: !silentMode && removeTempFiles  // Show verbose output only if removing temp files and not silent
  });

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
  }
  
  // Clean process termination
  if (forceDebug) console.log(formatLogMessage('debug', `About to exit process...`));
  process.exit(0);
  
})();
