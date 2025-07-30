A Puppeteer-based tool for scanning websites to find third-party (or optionally first-party) network requests matching specified patterns, and generate Adblock-formatted rules.

## Features

- Scan websites and detect matching third-party or first-party resources
- Output Adblock-formatted blocking rules
- Support for multiple filters per site
- Grouped titles (! <url>) before site matches
- Ignore unwanted domains (global and per-site)
- Block unwanted domains during scan (simulate adblock)
- Support Chrome, Firefox, Safari user agents (desktop or mobile)
- Advanced fingerprint spoofing and referrer header simulation
- Delay, timeout, reload options per site
- Verbose and debug modes
- Dump matched full URLs into `matched_urls.log`
- Save output in normal Adblock format or localhost (127.0.0.1/0.0.0.0)
- Subdomain handling (collapse to root or full subdomain)
- Optionally match only first-party, third-party, or both
- Enhanced redirect handling with JavaScript and meta refresh detection

---

## Command Line Arguments

### Output Options

| Argument                  | Description |
|:---------------------------|:------------|
| `-o, --output <file>`       | Output file for rules. If omitted, prints to console |
| `--compare <file>`          | Remove rules that already exist in this file before output |
| `--color, --colour`         | Enable colored console output for status messages |
| `--append`                  | Append new rules to output file instead of overwriting (requires `-o`) |

### Output Format Options

| Argument                  | Description |
|:---------------------------|:------------|
| `--localhost`               | Output as `127.0.0.1 domain.com` |
| `--localhost-0.0.0.0`       | Output as `0.0.0.0 domain.com` |
| `--plain`                   | Output just domains (no adblock formatting) |
| `--dnsmasq`                 | Output as `local=/domain.com/` (dnsmasq format) |
| `--dnsmasq-old`             | Output as `server=/domain.com/` (dnsmasq old format) |
| `--unbound`                 | Output as `local-zone: "domain.com." always_null` (unbound format) |
| `--privoxy`                 | Output as `{ +block } .domain.com` (Privoxy format) |
| `--pihole`                  | Output as `(^\|\\.)domain\\.com$` (Pi-hole regex format) |
| `--adblock-rules`           | Generate adblock filter rules with resource type modifiers (requires `-o`) |

### General Options

| Argument                  | Description |
|:---------------------------|:------------|
| `--verbose`                 | Force verbose mode globally |
| `--debug`                   | Force debug mode globally |
| `--silent`                  | Suppress normal console logs |
| `--titles`                  | Add `! <url>` title before each site's group |
| `--dumpurls`                | Dump matched URLs into matched_urls.log |
| `--remove-tempfiles`        | Remove Chrome/Puppeteer temporary files before exit |
| `--compress-logs`           | Compress log files with gzip (requires `--dumpurls`) |
| `--sub-domains`             | Output full subdomains instead of collapsing to root |
| `--no-interact`             | Disable page interactions globally |
| `--custom-json <file>`      | Use a custom config JSON file instead of config.json |
| `--headful`                 | Launch browser with GUI (not headless) |
| `--cdp`                     | Enable Chrome DevTools Protocol logging (now per-page if enabled) |
| `--remove-dupes`            | Remove duplicate domains from output (only with `-o`) |
| `--dry-run`                 | Console output only: show matching regex, titles, whois/dig/searchstring results, and adblock rules |
| `--eval-on-doc`             | Globally enable evaluateOnNewDocument() for Fetch/XHR interception |
| `--help`, `-h`              | Show this help menu |
| `--version`                 | Show script version |
| `--max-concurrent <number>` | Maximum concurrent site processing (1-50, overrides config/default) |
| `--cleanup-interval <number>` | Browser restart interval in URLs processed (1-1000, overrides config/default) |

### Validation Options

| Argument                  | Description |
|:---------------------------|:------------|
| `--validate-config`         | Validate config.json file and exit |
| `--validate-rules [file]`   | Validate rule file format (uses --output/--compare files if no file specified) |
| `--clean-rules [file]`      | Clean rule files by removing invalid lines and optionally duplicates (uses --output/--compare files if no file specified) |
| `--test-validation`         | Run domain validation tests and exit |

---

## config.json Format

Example:

```json
{
  "ignoreDomains": [
    "googleapis.com",
    "googletagmanager.com"
  ],
  "sites": [
    {
      "url": "https://example.com/",
      "userAgent": "chrome",
      "filterRegex": "ads|analytics",
      "resourceTypes": ["script", "xhr", "image"],
      "reload": 2,
      "delay": 5000,
      "timeout": 30000,
      "verbose": 1,
      "debug": 1,
      "interact": true,
      "fingerprint_protection": "random",
      "referrer_headers": {
        "mode": "random_search",
        "search_terms": ["example reviews", "best deals"]
      },
      "custom_headers": {
        "X-Custom-Header": "value"
      },
      "firstParty": 0,
      "thirdParty": 1,
      "subDomains": 0,
      "blocked": [
        "googletagmanager.com",
        ".*tracking.*"
      ]
    }
  ]
}
```

---

## config.json Field Table

### Basic Configuration

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `url`                | String or Array |   -     | Website URL(s) to scan |
| `userAgent`          | `chrome`, `firefox`, `safari` | - | User agent for page (latest versions: Chrome 131, Firefox 133, Safari 18.2) |
| `filterRegex`        | String or Array | `.*` | Regex or list of regexes to match requests |
| `comments`           | String or Array | - | String of comments or references |
| `resourceTypes`      | Array | `["script", "xhr", "image", "stylesheet"]` | What resource types to monitor |
| `reload`             | Integer | `1` | Number of times to reload page |
| `delay`              | Milliseconds | `4000` | Wait time after loading/reloading |
| `timeout`            | Milliseconds | `30000` | Timeout for page load |
| `verbose`            | `0` or `1` | `0` | Enable verbose output per site |
| `debug`              | `0` or `1` | `0` | Dump matching URLs for the site |
| `interact`           | `true` or `false` | `false` | Simulate user interaction (hover, click) |
| `firstParty`         | `0` or `1` | `0` | Match first-party requests |
| `thirdParty`         | `0` or `1` | `1` | Match third-party requests |
| `subDomains`         | `0` or `1` | `0` | 1 = preserve subdomains in output |
| `blocked`            | Array | - | Domains or regexes to block during scanning |
| `even_blocked`       | Boolean | `false` | Add matching rules even if requests are blocked |

### Redirect Handling Options

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `follow_redirects`   | Boolean | `true` | Follow redirects to new domains |
| `max_redirects`      | Integer | `10` | Maximum number of redirects to follow |
| `js_redirect_timeout` | Milliseconds | `5000` | Time to wait for JavaScript redirects |
| `detect_js_patterns` | Boolean | `true` | Analyze page source for redirect patterns |
| `redirect_timeout_multiplier` | Number | `1.5` | Increase timeout for redirected URLs |

When a page redirects to a new domain, first-party/third-party detection is based on the **final redirected domain**, and all intermediate redirect domains (like `bit.ly`, `t.co`) are automatically excluded from the generated rules.


### Advanced Stealth & Fingerprinting

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `fingerprint_protection` | `true`, `false`, `"random"` | `false` | Enable navigator/device spoofing |
| `referrer_headers`   | String, Array, or Object | - | Set referrer header for realistic traffic sources |
| `custom_headers`     | Object | - | Add custom HTTP headers to requests |

#### Referrer Header Options

**Simple formats:**
```json
"referrer_headers": "https://google.com/search?q=example"
"referrer_headers": ["url1", "url2"]
```

**Smart modes:**
```json
"referrer_headers": {"mode": "random_search", "search_terms": ["reviews"]}
"referrer_headers": {"mode": "social_media"}
"referrer_headers": {"mode": "direct_navigation"}
"referrer_headers": {"mode": "custom", "custom": ["https://news.ycombinator.com/"]}
```

### Protection Bypassing

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `cloudflare_phish`   | Boolean | `false` | Auto-click through Cloudflare phishing warnings |
| `cloudflare_bypass`  | Boolean | `false` | Auto-solve Cloudflare "Verify you are human" challenges |
| `flowproxy_detection` | Boolean | `false` | Enable flowProxy protection detection and handling |
| `flowproxy_page_timeout` | Milliseconds | `45000` | Page timeout for flowProxy sites |
| `flowproxy_nav_timeout` | Milliseconds | `45000` | Navigation timeout for flowProxy sites |
| `flowproxy_js_timeout` | Milliseconds | `15000` | JavaScript challenge timeout |
| `flowproxy_delay`    | Milliseconds | `30000` | Delay for rate limiting |
| `flowproxy_additional_delay` | Milliseconds | `5000` | Additional processing delay |

### WHOIS/DNS Analysis Options

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `whois`              | Array | - | Check whois data for ALL specified terms (AND logic) |
| `whois-or`           | Array | - | Check whois data for ANY specified term (OR logic) |
| `whois_delay`        | Integer | `3000` | Delay whois requests to avoid throttling | 
| `whois_server`       | String or Array | - | Custom whois server(s) - single server or randomized list |
| `whois_server_mode`  | String | `"random"` | Server selection mode: `"random"` or `"cycle"` |
| `whois_max_retries`  | Integer | `2` | Maximum retry attempts per domain |
| `whois_timeout_multiplier` | Number | `1.5` | Timeout increase multiplier per retry |
| `whois_use_fallback` | Boolean | `true` | Add TLD-specific fallback servers |
| `whois_retry_on_timeout` | Boolean | `true` | Retry on timeout errors |
| `whois_retry_on_error` | Boolean | `false` | Retry on connection/other errors |
| `dig`                | Array | - | Check dig output for ALL specified terms (AND logic) |
| `dig-or`             | Array | - | Check dig output for ANY specified term (OR logic) |
| `dig_subdomain`      | Boolean | `false` | Use subdomain for dig lookup instead of root domain |
| `digRecordType`      | String | `"A"` | DNS record type for dig (A, CNAME, MX, etc.) |

### Content Analysis Options

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `searchstring`       | String or Array | - | Text to search in response content (OR logic) |
| `searchstring_and`   | String or Array | - | Text to search with AND logic - ALL terms must be present |
| `curl`               | Boolean | `false` | Use curl to download content for analysis |
| `grep`               | Boolean | `false` | Use grep instead of JavaScript for pattern matching (requires curl=true) |

### Advanced Browser Options

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `goto_options`       | Object | `{"waitUntil": "load"}` | Custom page.goto() options |
| `clear_sitedata`     | Boolean | `false` | Clear all cookies, cache, storage before each load |
| `forcereload`        | Boolean | `false` | Force an additional reload after reloads |
| `isBrave`            | Boolean | `false` | Spoof Brave browser detection |
| `evaluateOnNewDocument` | Boolean | `false` | Inject fetch/XHR interceptor in page |
| `cdp`                | Boolean | `false` | Enable CDP logging for this site |
| `css_blocked`        | Array | - | CSS selectors to hide elements |
| `source`             | Boolean | `false` | Save page source HTML after load |
| `screenshot`         | Boolean | `false` | Capture screenshot on load failure |
| `headful`            | Boolean | `false` | Launch browser with GUI for this site |
| `adblock_rules`      | Boolean | `false` | Generate adblock filter rules with resource types for this site |

### Global Configuration Options

These options go at the root level of your config.json:

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `ignoreDomains`      | Array | - | Domains to completely ignore (supports wildcards like `*.ads.com`) |
| `blocked`            | Array | - | Global regex patterns to block requests (combined with per-site blocked) |
| `whois_server_mode`  | String | `"random"` | Default server selection mode for all sites |
| `ignore_similar`     | Boolean | `true` | Ignore domains similar to already found domains |
| `ignore_similar_threshold` | Integer | `80` | Similarity threshold percentage for ignore_similar |
| `ignore_similar_ignored_domains` | Boolean | `true` | Ignore domains similar to ignoreDomains list |
| `max_concurrent_sites` | Integer | `6` | Maximum concurrent site processing (1-50) |
| `resource_cleanup_interval` | Integer | `180` | Browser restart interval in URLs processed (1-1000) |

---

## Usage Examples

### Basic Scanning
```bash
# Scan with default config and output to console
node nwss.js

# Scan and save rules to file
node nwss.js -o blocklist.txt

# Append new rules to existing file
node nwss.js --append -o blocklist.txt

# Clean existing rules and append new ones
node nwss.js --clean-rules --append -o blocklist.txt
```

### Advanced Options
```bash
# Debug mode with URL dumping and colored output
node nwss.js --debug --dumpurls --color -o rules.txt

# Dry run to see what would be matched
node nwss.js --dry-run --debug

# Validate configuration before running
node nwss.js --validate-config

# Clean rule files
node nwss.js --clean-rules existing_rules.txt

# Maximum stealth scanning
node nwss.js --debug --color -o stealth_rules.txt
```

### Performance Tuning
```bash
# High-performance scanning with custom concurrency
node nwss.js --max-concurrent 12 --cleanup-interval 300 -o rules.txt
```

### Stealth Configuration Examples

#### E-commerce Site Scanning
```json
{
  "url": "https://shopping-site.com",
  "userAgent": "chrome",
  "fingerprint_protection": "random",
  "referrer_headers": {
    "mode": "random_search",
    "search_terms": ["product reviews", "best deals", "price comparison"]
  },
  "interact": true,
  "delay": 6000,
  "filterRegex": "analytics|tracking|ads"
}
```

#### News Site Analysis
```json
{
  "url": "https://news-site.com",
  "userAgent": "firefox",
  "fingerprint_protection": true,
  "referrer_headers": {"mode": "social_media"},
  "custom_headers": {
    "Accept-Language": "en-US,en;q=0.9"
  },
  "filterRegex": "doubleclick|googletagmanager"
}
```

#### Tech Blog with Custom Referrers
```json
{
  "url": "https://tech-blog.com",
  "fingerprint_protection": "random",
  "referrer_headers": {
    "mode": "custom",
    "custom": [
      "https://news.ycombinator.com/",
      "https://www.reddit.com/r/programming/",
      "https://lobste.rs/"
    ]
  }
}
```

---

## Notes

- If both `firstParty: 0` and `thirdParty: 0` are set for a site, it will be skipped.
- `ignoreDomains` applies globally across all sites.
- `ignoreDomains` supports wildcards (e.g., `*.ads.com` matches `tracker.ads.com`)
- Blocking (`blocked`) can match full domains or regex.
- If a site's `blocked` field is missing, no extra blocking is applied.
- `--clean-rules` with `--append` will clean existing files first, then append new rules
- `--remove-dupes` works with all output modes and removes duplicates from final output
- Validation tools help ensure rule files are properly formatted before use
- `--remove-tempfiles` removes Chrome/Puppeteer temporary files before exiting, avoids disk space issues
- For maximum stealth, combine `fingerprint_protection: "random"` with appropriate `referrer_headers` modes
- User agents are automatically updated to latest versions (Chrome 131, Firefox 133, Safari 18.2)
- Referrer headers work independently from fingerprint protection - use both for best results

---
