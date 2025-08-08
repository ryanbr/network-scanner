// === Network scanner script (nwss.js) v1.0.60 ===

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
// Rule validation
const { validateRulesetFile, validateFullConfig, testDomainValidation, cleanRulesetFile } = require('./lib/validate_rules');
// CF Bypass
const { handleCloudflareProtection } = require('./lib/cloudflare');
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
const { createCDPSession } = require('./lib/cdp');
// Colorize various text when used
const { colorize, colors, messageColors, tags, formatLogMessage } = require('./lib/colorize');
// Enhanced mouse interaction and page simulation
const { performPageInteraction, createInteractionConfig } = require('./lib/interaction');
// Domain detection cache for performance optimization
const { createGlobalHelpers, getTotalDomainsSkipped, getDetectedDomainsCount } = require('./lib/domain-cache');
const { createSmartCache } = require('./lib/smart-cache'); // Smart cache system
const { clearPersistentCache } = require('./lib/smart-cache');
// Enhanced redirect handling
const { navigateWithRedirectHandling, handleRedirectTimeout } = require('./lib/redirect');
// Ensure web browser is working correctly
const { monitorBrowserHealth, isBrowserHealthy } = require('./lib/browserhealth');

// --- Script Configuration & Constants ---
const VERSION = '1.0.60'; // Script version

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
const dryRunMode = args.includes('--dry-run');
const compressLogs = args.includes('--compress-logs');
const removeTempFiles = args.includes('--remove-tempfiles');
const validateConfig = args.includes('--validate-config');
const validateRules = args.includes('--validate-rules');
const testValidation = args.includes('--test-validation');
let cleanRules = args.includes('--clean-rules');
const clearCache = args.includes('--clear-cache');
const ignoreCache = args.includes('--ignore-cache');

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
    cachePath: '.cache' // Default path, will be updated after config loads if needed
  });
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
  max_concurrent_sites: 6                        Maximum concurrent site processing (1-50, default: 6)
  resource_cleanup_interval: 180                  Browser restart interval in URLs processed (1-1000, default: 180)

Per-site config.json options:
  url: "site" or ["site1", "site2"]          Single URL or list of URLs
  filterRegex: "regex" or ["regex1", "regex2"]  Patterns to match requests
  
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
  userAgent: "chrome"|"firefox"|"safari"        Custom desktop User-Agent
  interact_intensity: "low"|"medium"|"high"     Interaction simulation intensity (default: medium)
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
  even_blocked: true/false                     Add matching rules even if requests are blocked (default: false)
  
  referrer_headers: "url" or ["url1", "url2"] Set referrer header for realistic traffic sources
  custom_headers: {"Header": "value"}         Add custom HTTP headers to requests

Cloudflare Protection Options:
  cloudflare_phish: true/false                 Auto-click through Cloudflare phishing warnings (default: false)
  cloudflare_bypass: true/false               Auto-solve Cloudflare "Verify you are human" challenges (default: false)

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
  whois_retry_on_error: false                Retry on connection/other errors (default: false)
  whois_delay: <milliseconds>                Delay between whois requests for this site (default: global whois_delay)
  dig: ["term1", "term2"]                     Check dig output for ALL specified terms (AND logic)
  dig-or: ["term1", "term2"]                  Check dig output for ANY specified term (OR logic)
  goto_options: {"waitUntil": "domcontentloaded"} Custom page.goto() options (default: {"waitUntil": "load"})
  dig_subdomain: true/false                    Use subdomain for dig lookup instead of root domain (default: false)
  digRecordType: "A"                          DNS record type for dig (default: A)

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
  resource_cleanup_interval = 180,
  comments: globalComments, 
  ...otherGlobalConfig 
} = config;

// Apply global configuration overrides with validation
// Priority: Command line args > config.json > defaults
const MAX_CONCURRENT_SITES = (() => {
  // Check command line argument first
  if (maxConcurrentSites !== null) {
    if (maxConcurrentSites > 0 && maxConcurrentSites <= 50) {
      if (forceDebug) console.log(formatLogMessage('debug', `Using command line max_concurrent_sites: ${maxConcurrentSites}`));
      return maxConcurrentSites;
    } else {
      console.warn(`⚠ Invalid --max-concurrent value: ${maxConcurrentSites}. Must be 1-50. Using config/default value.`);
    }
  }
  
  // Check config.json value
  if (typeof max_concurrent_sites === 'number' && max_concurrent_sites > 0 && max_concurrent_sites <= 50) {
    if (forceDebug) console.log(formatLogMessage('debug', `Using config max_concurrent_sites: ${max_concurrent_sites}`));
    return max_concurrent_sites;
  } else if (max_concurrent_sites !== 6) {
    console.warn(`⚠ Invalid config max_concurrent_sites value: ${max_concurrent_sites}. Using default: 6`);
  }
  
  // Use default
  return 6;
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
  } else if (resource_cleanup_interval !== 180) {
    console.warn(`⚠ Invalid config resource_cleanup_interval value: ${resource_cleanup_interval}. Using default: 180`);
  }
  
  // Use default
  return 180;
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
if (clearCache && !dryRunMode && config.cache_path && config.cache_path !== '.cache') {
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
  forceDebug,
  max_concurrent_sites: MAX_CONCURRENT_SITES,  // Pass concurrency info
  cache_aggressive_mode: MAX_CONCURRENT_SITES > 12,  // Auto-enable for high concurrency
  cache_persistence: false, // Disable persistence completely
  cache_autosave: false, // Disable auto-save completely
  cache_autosave_minutes: config.cache_autosave_minutes || 1,
  cache_max_size: config.cache_max_size || 5000
});
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
 * Outputs dry run results to console with formatted display
 * If outputFile is specified, also captures output for file writing
 * @param {string} url - The URL being processed  
 * @param {Array} matchedItems - Array of matched items with regex, domain, and resource type
 * @param {Array} netToolsResults - Array of whois/dig results
 * @param {string} pageTitle - Title of the page (if available)
 */
function outputDryRunResults(url, matchedItems, netToolsResults, pageTitle) {
  const lines = [];
  
  lines.push(`\n=== DRY RUN RESULTS === ${url}`);

  console.log(`\n${messageColors.scanning('=== DRY RUN RESULTS ===')} ${url}`);
  
  if (pageTitle && pageTitle.trim()) {
    lines.push(`Title: ${pageTitle.trim()}`);
    console.log(`${messageColors.info('Title:')} ${pageTitle.trim()}`);
  }
  
  if (matchedItems.length === 0 && netToolsResults.length === 0) {
    lines.push(`No matching rules found on ${url}`);
    
    // Store output for file writing if outputFile is specified
    if (outputFile) {
      dryRunOutput.push(...lines);
      dryRunOutput.push(''); // Add empty line
    }
    console.log(messageColors.warn(`No matching rules found on ${url}`));
    return;
  }
  
  const totalMatches = matchedItems.length + netToolsResults.length;
  lines.push(`Matches found: ${totalMatches}`);
  console.log(`${messageColors.success('Matches found:')} ${totalMatches}`);
  
  matchedItems.forEach((item, index) => {
    lines.push('');
    lines.push(`[${index + 1}] Regex Match:`);
    lines.push(`  Pattern: ${item.regex}`);
    lines.push(`  Domain: ${item.domain}`);
    lines.push(`  Resource Type: ${item.resourceType}`);
    lines.push(`  Full URL: ${item.fullUrl}`);

    console.log(`\n${messageColors.highlight(`[${index + 1}]`)} ${messageColors.match('Regex Match:')}`);
    console.log(`  Pattern: ${item.regex}`);
    console.log(`  Domain: ${item.domain}`);
    console.log(`  Resource Type: ${item.resourceType}`);
    console.log(`  Full URL: ${item.fullUrl}`);
    
    // Show searchstring results if available
    if (item.searchStringMatch) {
      lines.push(`  ✓ Searchstring Match: ${item.searchStringMatch.type} - "${item.searchStringMatch.term}"`);
      console.log(`  ${messageColors.success('✓ Searchstring Match:')} ${item.searchStringMatch.type} - "${item.searchStringMatch.term}"`);
    } else if (item.searchStringChecked) {
      lines.push(`  ✗ Searchstring: No matches found in content`);
      console.log(`  ${messageColors.warn('✗ Searchstring:')} No matches found in content`);
    }
    
    // Generate adblock rule
    const adblockRule = `||${item.domain}^$${item.resourceType}`;
    lines.push(`  Adblock Rule: ${adblockRule}`);
    console.log(`  ${messageColors.info('Adblock Rule:')} ${adblockRule}`);
  });
  
  // Display nettools results
  netToolsResults.forEach((result, index) => {
    const resultIndex = matchedItems.length + index + 1;
    lines.push('');
    lines.push(`[${resultIndex}] NetTools Match:`);
    lines.push(`  Domain: ${result.domain}`);
    lines.push(`  Tool: ${result.tool.toUpperCase()}`);
    lines.push(`  ✓ Match: ${result.matchType} - "${result.matchedTerm}"`);
    if (result.details) {
      lines.push(`  Details: ${result.details}`);
    }
    console.log(`\n${messageColors.highlight(`[${resultIndex}]`)} ${messageColors.match('NetTools Match:')}`);
    console.log(`  Domain: ${result.domain}`);
    console.log(`  Tool: ${result.tool.toUpperCase()}`);
    console.log(`  ${messageColors.success('✓ Match:')} ${result.matchType} - "${result.matchedTerm}"`);
    if (result.details) {
      console.log(`  Details: ${result.details}`);
    }
    
    // Generate adblock rule for nettools matches
    const adblockRule = `||${result.domain}^`;
    lines.push(`  Adblock Rule: ${adblockRule}`);
    console.log(`  ${messageColors.info('Adblock Rule:')} ${adblockRule}`);
  });

  // Store output for file writing if outputFile is specified
  if (outputFile) {
    dryRunOutput.push(...lines);
    dryRunOutput.push(''); // Add empty line between sites
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
        '--max_old_space_size=1024',
        '--ignore-ssl-errors',
        '--ignore-certificate-errors',
        '--ignore-certificate-errors-spki-list',
        '--ignore-certificate-errors-ca-list',
        '--disable-web-security',
        '--allow-running-insecure-content',
	    '--disable-background-timer-throttling',
	    '--disable-backgrounding-occluded-windows',
	    '--disable-renderer-backgrounding',
	    '--disable-features=TranslateUI',
	    '--disable-features=VizDisplayCompositor',
	    '--run-all-compositor-stages-before-draw',
	    '--disable-threaded-animation',
	    '--disable-threaded-scrolling',
	    '--disable-checker-imaging',
	    '--disable-image-animation-resync'
        ],
        headless: launchHeadless ? 'shell' : false,
        protocolTimeout: 60000  // 60 seconds
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
    const cloudflarePhishBypass = siteConfig.cloudflare_phish === true;
    const cloudflareBypass = siteConfig.cloudflare_bypass === true;
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

    if (siteConfig.firstParty === 0 && siteConfig.thirdParty === 0) {
      console.warn(`⚠ Skipping ${currentUrl} because both firstParty and thirdParty are disabled.`);
      return { url: currentUrl, rules: [], success: false, skipped: true };
    }

    let page = null;
    let cdpSession = null;
    let cdpSessionManager = null;
    // Use Map to track domains and their resource types for --adblock-rules or --dry-run
    const matchedDomains = (adblockRulesMode || siteConfig.adblock_rules || dryRunMode) ? new Map() : new Set();
    
    // Initialize dry run matches collection
    if (dryRunMode) {
      matchedDomains.set('dryRunMatches', []);
      matchedDomains.set('dryRunNetTools', []);
      matchedDomains.set('dryRunSearchString', new Map()); // Map URL to search results
    }
    const timeout = siteConfig.timeout || 30000;

    if (!silentMode) console.log(`\n${messageColors.scanning('Scanning:')} ${currentUrl}`);

    // Track redirect domains to exclude from matching
    let redirectDomainsToExclude = [];
    
    // Track the effective current URL for first-party detection (updates after redirects)
    let effectiveCurrentUrl = currentUrl;

    try {
      // Health check before creating new page
      const isHealthy = await isBrowserHealthy(browserInstance);
      if (!isHealthy) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Browser health degraded before processing ${currentUrl} - forcing immediate restart`));
        }
        // Return special code to trigger immediate browser restart
        return { 
          url: currentUrl, 
          rules: [], 
          success: false, 
          needsImmediateRestart: true,
          error: 'Browser health degraded - restart required'
        };
      }
      // Check for Protocol timeout errors that indicate browser is broken
      if (browserInstance.process() && browserInstance.process().killed) {
        throw new Error('Browser process was killed - restart required');
      }
      page = await browserInstance.newPage();
      
      // Set aggressive timeouts for problematic operations
      page.setDefaultTimeout(Math.min(timeout, 20000));  // Use site timeout or 20s max
      page.setDefaultNavigationTimeout(Math.min(timeout, 25000));  // Use site timeout or 25s max
      // Note: timeout variable from siteConfig.timeout || 30000 is overridden for stability
      
      page.on('console', (msg) => {
        if (forceDebug && msg.type() === 'error') console.log(`[debug] Console error: ${msg.text()}`);
      });
      
      // Add page crash handler
      page.on('error', (err) => {
        if (forceDebug) console.log(formatLogMessage('debug', `Page crashed: ${err.message}`));
        // Don't throw here as it might cause hanging - let the timeout handle it
      });

      // Apply flowProxy timeouts if detection is enabled
      if (flowproxyDetection) {
        const flowproxyTimeouts = getFlowProxyTimeouts(siteConfig);
        page.setDefaultTimeout(flowproxyTimeouts.pageTimeout);
        page.setDefaultNavigationTimeout(flowproxyTimeouts.navigationTimeout);
        if (forceDebug) {
          console.log(formatLogMessage('debug', `Applied flowProxy timeouts - page: ${flowproxyTimeouts.pageTimeout}ms, nav: ${flowproxyTimeouts.navigationTimeout}ms`));
        }
      }

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
      
      try {
        cdpSessionManager = await createCDPSession(page, currentUrl, {
          enableCDP,
          siteSpecificCDP: siteConfig.cdp,
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
       chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
       firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
       safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15"
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
        smartCache.markDomainProcessed(domain, context, { resourceType, fullSubdomain });
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
        // Use effectiveCurrentUrl which gets updated after redirects
        // This ensures first-party detection uses the final redirected domain
        const effectiveCurrentHostname = safeGetDomain(effectiveCurrentUrl, true);
      const isFirstParty = checkedHostname && effectiveCurrentHostname && checkedHostname === effectiveCurrentHostname;
        
        // Block infinite iframe loops
        const frameUrl = request.frame() ? request.frame().url() : '';
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
                      matchedDomains.get('dryRunMatches').push({
                        regex: re.source,
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
                      console.log(formatLogMessage('match', `[${simplifiedUrl}] ${reqUrl} matched regex: ${re} and resourceType: ${resourceType}${resourceInfo} [BLOCKED BUT ADDED]`));
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
           
           // Check party filtering AFTER regex match but BEFORE domain processing
           if (isFirstParty && siteConfig.firstParty === false) {
             if (forceDebug) {
               console.log(formatLogMessage('debug', `Skipping first-party match: ${reqUrl} (firstParty disabled)`));
             }
             break; // Skip this URL - it's first-party but firstParty is disabled
           }
           if (!isFirstParty && siteConfig.thirdParty === false) {
             if (forceDebug) {
               console.log(formatLogMessage('debug', `Skipping third-party match: ${reqUrl} (thirdParty disabled)`));
             }
             break; // Skip this URL - it's third-party but thirdParty is disabled
           }

           // Check ignoreDomains AFTER regex match but BEFORE domain processing
           if (matchesIgnoreDomain(fullSubdomain, ignoreDomains)) {
             if (forceDebug) {
               console.log(formatLogMessage('debug', `Ignoring domain ${fullSubdomain} (matches ignoreDomains pattern)`));
             }
            break; // Skip this URL - domain is in ignore list
          }
 
            // REMOVED: Check if this URL matches any blocked patterns - if so, skip detection but still continue browser blocking
            // This check is no longer needed here since even_blocked handles it above

           
           // If NO searchstring AND NO nettools are defined, match immediately (existing behavior)
           if (!hasSearchString && !hasSearchStringAnd && !hasNetTools) {
             if (dryRunMode) {
               matchedDomains.get('dryRunMatches').push({
                 regex: re.source,
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
              console.log(formatLogMessage('match', `[${simplifiedUrl}] ${reqUrl} matched regex: ${re} and resourceType: ${resourceType}${resourceInfo}`));
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
               break; // Skip to next URL
             }
             
             if (forceDebug) {
               console.log(formatLogMessage('debug', `${reqUrl} matched regex ${re} and resourceType ${resourceType}, queued for nettools check`));
             }

             if (dryRunMode) {
               // For dry run, we'll collect the domain for nettools checking
               matchedDomains.get('dryRunMatches').push({
                 regex: re.source,
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
               whoisDelay: siteConfig.whois_delay || whois_delay, // Site-specific or global fallback
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
           } else {
             // If searchstring or searchstring_and IS defined (with or without nettools), queue for content checking
             // Skip searchstring check if full subdomain was already detected
             if (isDomainAlreadyDetected(fullSubdomain)) {
               if (forceDebug) {
                 console.log(formatLogMessage('debug', `Skipping searchstring check for already detected subdomain: ${fullSubdomain}`));
               }
               break; // Skip to next URL
             }
             if (forceDebug) {
               const searchType = hasSearchStringAnd ? 'searchstring_and' : 'searchstring';
               console.log(formatLogMessage('debug', `${reqUrl} matched regex ${re} and resourceType ${resourceType}, queued for ${searchType} content search`));
             }
             if (dryRunMode) {
               matchedDomains.get('dryRunMatches').push({
                 regex: re.source,
                 domain: reqDomain,
                 resourceType: resourceType,
                 fullUrl: reqUrl,
                 isFirstParty: isFirstParty,
                 needsSearchStringCheck: true
               });
             }
           }
           
           // If curl is enabled, download and analyze content immediately
           if (useCurl) {
             // Check response cache first if smart cache is available and caching is enabled
             const cachedContent = smartCache ? smartCache.getCachedResponse(reqUrl) : null;
             
             if (cachedContent && forceDebug) {
               console.log(formatLogMessage('debug', `[SmartCache] Using cached response content for ${reqUrl.substring(0, 50)}...`));
               // Process cached content instead of fetching
             } else {
             try {
               // Use grep handler if both grep and searchstring/searchstring_and are enabled
               if (useGrep && (hasSearchString || hasSearchStringAnd)) {
                 const grepHandler = createGrepHandler({
                   searchStrings,
				   searchStringsAnd,
                   regexes,
                   matchedDomains,
                   addMatchedDomain, // Pass the helper function
                   isDomainAlreadyDetected,
                   onContentFetched: smartCache && !ignoreCache ? (url, content) => {
                     smartCache.cacheResponse(url, content);
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
                   isDomainAlreadyDetected,
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
         isDomainAlreadyDetected,
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

        // Use faster defaults for sites with long timeouts to improve responsiveness
        const isFastSite = timeout <= 15000;
        const defaultWaitUntil = isFastSite ? 'load' : 'domcontentloaded';
        const defaultGotoOptions = {
          waitUntil: defaultWaitUntil,
          timeout: timeout
        };
        const gotoOptions = siteConfig.goto_options 
          ? { ...defaultGotoOptions, ...siteConfig.goto_options }
          : defaultGotoOptions;

        // Enhanced navigation with redirect handling - passes existing gotoOptions
        const navigationResult = await navigateWithRedirectHandling(page, currentUrl, siteConfig, gotoOptions, forceDebug, formatLogMessage);
        
        const { finalUrl, redirected, redirectChain, originalUrl, redirectDomains } = navigationResult;
        
        // Handle redirect to new domain
        if (redirected) {
          const originalDomain = safeGetDomain(originalUrl);
          const finalDomain = safeGetDomain(finalUrl);
          
          if (originalDomain !== finalDomain) {
            if (!silentMode) {
              console.log(`🔄 Redirect detected: ${originalDomain} → ${finalDomain}`);
            }
            
            if (forceDebug) {
              console.log(formatLogMessage('debug', `Full redirect chain: ${redirectChain.join(' → ')}`));
            }
            
            // Update currentUrl for all subsequent processing to use the final redirected URL
            currentUrl = finalUrl;

            // IMPORTANT: Also update effectiveCurrentUrl for first-party detection
            // This ensures the request handler uses the redirected domain for party detection
            effectiveCurrentUrl = finalUrl;
            
            // Update the redirect domains to exclude from matching
            if (redirectDomains && redirectDomains.length > 0) {
              redirectDomainsToExclude = redirectDomains;
              
              if (forceDebug) {
                console.log(formatLogMessage('debug', `Excluding redirect domains from matching: ${redirectDomains.join(', ')}`));
              }
            }
          }
        }
        
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

      if (interactEnabled && !disableInteract) {
        if (forceDebug) console.log(formatLogMessage('debug', `interaction simulation enabled for ${currentUrl}`));
        // Use enhanced interaction module
        await performPageInteraction(page, currentUrl, interactionConfig, forceDebug);
      }

      const delayMs = siteConfig.delay || 4000;
      
      // Optimize network idle and delay times for better responsiveness
      const isFastSite = timeout <= 15000;
      const networkIdleTime = isFastSite ? 4000 : 2000;  // Faster idle for slow sites
      const networkIdleTimeout = isFastSite ? timeout : Math.min(timeout / 2, 12000);
      const actualDelay = isFastSite ? delayMs : Math.min(delayMs, 2000);  // Cap delay for slow sites
      
      await page.waitForNetworkIdle({ 
        idleTime: networkIdleTime, 
        timeout: networkIdleTimeout 
      });
      await new Promise(resolve => setTimeout(resolve, actualDelay));

      // Apply additional delay for flowProxy if detected
      if (flowproxyDetection) {
        const additionalDelay = siteConfig.flowproxy_additional_delay || 5000;
        if (forceDebug) console.log(formatLogMessage('debug', `Applying flowProxy additional delay: ${additionalDelay}ms`));
        await new Promise(resolve => setTimeout(resolve, additionalDelay));
      }

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

      if (dryRunMode) {
        // Get page title for dry run output
        let pageTitle = '';
        try {
          pageTitle = await page.title();
        } catch (titleErr) {
          if (forceDebug) {
            console.log(formatLogMessage('debug', `Failed to get page title for ${currentUrl}: ${titleErr.message}`));
          }
        }
        
        // Get collected matches and enhance with searchstring results
        const dryRunMatches = matchedDomains.get('dryRunMatches') || [];
        const dryRunNetTools = matchedDomains.get('dryRunNetTools') || [];
        const dryRunSearchString = matchedDomains.get('dryRunSearchString') || new Map();
        
        // Enhance matches with searchstring results
        const enhancedMatches = dryRunMatches.map(match => {
          const searchResult = dryRunSearchString.get(match.fullUrl);
          return {
            ...match,
            searchStringMatch: searchResult && searchResult.matched ? searchResult : null,
            searchStringChecked: match.needsSearchStringCheck
          };
        });
        
        // Wait a moment for async nettools/searchstring operations to complete
        await new Promise(resolve => setTimeout(resolve, 3000)); // Increased for nettools operations
        
        outputDryRunResults(currentUrl, enhancedMatches, dryRunNetTools, pageTitle);
        
        return { url: currentUrl, rules: [], success: true, dryRun: true, matchCount: dryRunMatches.length + dryRunNetTools.length };
      } else {
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
      }
      
    } catch (err) {
    // Enhanced error handling with rule preservation for partial matches
    if (err.message.includes('Runtime.callFunctionOn timed out') || 
        err.message.includes('Protocol error') ||
        err.message.includes('Target closed') ||
        err.message.includes('Browser has been closed')) {
      console.error(formatLogMessage('error', `Critical browser protocol error on ${currentUrl}: ${err.message}`));
      return { 
        url: currentUrl, 
        rules: [], 
        success: false, 
        needsImmediateRestart: true,
        error: `Critical protocol error: ${err.message}`
      };
    }
    
      if (err.message.includes('Protocol error') || 
          err.message.includes('Target closed') ||
          err.message.includes('Browser process was killed') ||
          err.message.includes('Browser protocol broken')) {
        console.error(formatLogMessage('error', `Critical browser error on ${currentUrl}: ${err.message}`));
        return { 
          url: currentUrl, 
          rules: [], 
          success: false, 
          needsImmediateRestart: true,
          error: err.message
        };
      }
      
      // For other errors, preserve any matches we found before the error
      if (matchedDomains && (matchedDomains.size > 0 || (matchedDomains instanceof Map && matchedDomains.size > 0))) {
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
      
      if (cdpSessionManager) {
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
    
    // Check browser health before processing each site
    const healthCheck = await monitorBrowserHealth(browser, {}, {
      siteIndex,
      totalSites: siteGroups.length,
      urlsSinceCleanup: urlsSinceLastCleanup,
      cleanupInterval: RESOURCE_CLEANUP_INTERVAL,
      forceDebug,
      silentMode
    });

    // Also check if browser was unhealthy during recent processing
    const recentResults = results.slice(-3);
    const hasRecentFailures = recentResults.filter(r => !r.success).length >= 2;
    const shouldRestartFromFailures = hasRecentFailures && urlsSinceLastCleanup > 5;

    const siteUrlCount = siteGroup.urls.length;
    
    // Check if processing this entire site would exceed cleanup interval OR health check suggests restart
    const wouldExceedLimit = urlsSinceLastCleanup + siteUrlCount >= RESOURCE_CLEANUP_INTERVAL;
    const isNotLastSite = siteIndex < siteGroups.length - 1;
    
    // Restart browser if we've processed enough URLs, health check suggests it, and this isn't the last site
    if ((wouldExceedLimit || healthCheck.shouldRestart || shouldRestartFromFailures) && urlsSinceLastCleanup > 0 && isNotLastSite) {
      
      let restartReason = 'Unknown';
      if (healthCheck.shouldRestart) {
        restartReason = healthCheck.reason;
      } else if (shouldRestartFromFailures) {
        restartReason = 'Multiple recent failures detected';
      } else if (wouldExceedLimit) {
        restartReason = `Processed ${urlsSinceLastCleanup} URLs`;
      }

      if (!silentMode) {
        console.log(`\n${messageColors.fileOp('🔄 Browser restart triggered:')} ${restartReason}`);
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
      if (forceDebug) console.log(formatLogMessage('debug', `New browser instance created for site ${siteIndex + 1}`));
      
      // Reset cleanup counter and add delay
      urlsSinceLastCleanup = 0;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    if (forceDebug) {
      console.log(formatLogMessage('debug', `Processing site ${siteIndex + 1}/${siteGroups.length}: ${siteUrlCount} URL(s) (total processed: ${processedUrlCount})`));
    }
    
    // Create tasks with current browser instance and process them
    const siteTasks = siteGroup.urls.map(url => originalLimit(() => processUrl(url, siteGroup.config, browser)));
    const siteResults = await Promise.all(siteTasks);

    // Check if any results indicate immediate restart is needed
    const needsImmediateRestart = siteResults.some(r => r.needsImmediateRestart);

    results.push(...siteResults);
    
    processedUrlCount += siteUrlCount;
    urlsSinceLastCleanup += siteUrlCount;

    // Force browser restart if any URL had critical errors
    if (needsImmediateRestart && siteIndex < siteGroups.length - 1) {
      if (!silentMode) {
        console.log(`\n${messageColors.fileOp('🔄 Emergency browser restart:')} Critical browser errors detected`);
      }
      
      // Force browser restart immediately
      try {
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
        await new Promise(resolve => setTimeout(resolve, 2000)); // Give browser time to stabilize
      } catch (emergencyRestartErr) {
        if (forceDebug) console.log(formatLogMessage('debug', `Emergency restart failed: ${emergencyRestartErr.message}`));
      }
    }
  }

  // Handle dry run output file writing
  if (dryRunMode && outputFile && dryRunOutput.length > 0) {
    try {
      const dryRunContent = dryRunOutput.join('\n');
      fs.writeFileSync(outputFile, dryRunContent);
      if (!silentMode) {
        console.log(`${messageColors.fileOp('📄 Dry run results saved to:')} ${outputFile}`);
      }
    } catch (writeErr) {
      console.error(`❌ Failed to write dry run output to ${outputFile}: ${writeErr.message}`);
    }
  }

  let outputResult;
  
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
     console.log(formatLogMessage('debug', `Performance: ${totalDomainsSkipped} domains skipped (already detected), ${detectedDomainsCount} unique domains cached`));
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
  await new Promise(resolve => setTimeout(resolve, 1000)); // Give filesystem time to sync

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
