A Puppeteer-based tool (v1.0.7) for scanning websites to find third-party (or optionally first-party) network requests matching specified patterns, and generate Adblock-formatted rules.

## Features

- Global `blocked` list now supported (applies to all sites)
- Scan websites and detect matching third-party or first-party resources
- Output Adblock-formatted blocking rules
- Support for multiple filters per site
- Grouped titles (! <url>) before site matches
- Ignore unwanted domains (global and per-site)
- Block unwanted domains during scan (simulate adblock)
- Support Chrome, Firefox, Safari user agents (desktop or mobile)
- Delay, timeout, reload options per site
- Verbose and debug modes
- Dump matched full URLs into `matched_urls.log`
- Save output in normal Adblock format or localhost (127.0.0.1/0.0.0.0)
- Subdomain handling (collapse to root or full subdomain)
- Optionally match only first-party, third-party, or both
- **Custom whois servers with intelligent retry logic**
- **Enhanced whois/dig domain verification with fallback servers**

---

## Command Line Arguments

| Argument                  | Description |
|:---------------------------|:------------|
| `-o, --output <file>`       | Output file for rules. If omitted, prints to console |
| `--compare <file>`          | Remove rules that already exist in this file before output |
| `--verbose`                 | Force verbose mode globally |
| `--debug`                   | Force debug mode globally |
| `--silent`                  | Suppress console output |
| `--titles`                  | Add `! <url>` before each site's rules |
| `--compress-logs`           | Compress log files with gzip (requires --dumpurls) |
| `--no-interact`             | Disable page interactions globally |
| `--custom-json <file>`      | Use a custom config JSON file instead of config.json |
| `--headful`                 | Launch browser with GUI (not headless) |
| `--dumpurls`                | Save full matched URLs to `matched_urls.log` |
| `--sub-domains`             | Output full subdomains (default collapses) |
| `--localhost`               | Output format as `127.0.0.1 domain.com` |
| `--localhost-0.0.0.0`       | Output format as `0.0.0.0 domain.com` |
| `--plain`                   | Output non formated domain.com` |
| `--cdp`                     | Enable Chrome DevTools Protocol logging |
| `--remove-dupes`            | Remove duplicate domains from output (only with -o) |
| `--adblock-rules`           |  Generate adblock filter rules with resource type modifiers (requires -o, ignored if used with --localhost/--localhost-0.0.0.0/--plain) |
| `--eval-on-doc`             | Inject JS fetch/XHR interception globally |
| `--help`, `-h`              | Show help menu |

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
      "searchstring": "specificString",
      "resourceTypes": ["script", "xhr", "image"],
      "reload": 2,
      "forcereload": true,
      "clear_sitedata": true,
      "delay": 5000,
      "timeout": 30000,
      "verbose": 1,
      "whois": ["term1", "term2"],
      "whois_server": ["whois.verisign-grs.com", "whois.internic.net"],
      "whois_max_retries": 3,
      "whois_timeout_multiplier": 2.0,
      "whois_retry_on_timeout": true,
      "whois_retry_on_error": true,
      "dig": ["term1", "term2"],
      "debug": 1,
      "interact": true,
      "fingerprint_protection": "random",
      "firstParty": 0,
      "thirdParty": 1,
      "subDomains": 0,
      "goto_options": {"waitUntil": "networkidle2", "timeout": 45000 },
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

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `url`                | String |   -     | Website URL to scan |
| `userAgent`          | `chrome`, `firefox`, `safari`, `mobile-chrome`, etc. | - | User agent for page |
| `filterRegex`        | String or Array | `.*` | Regex or list of regexes to match requests |
| `searchstring`       | String or Array | - |  Text to search in response content (requires filterRegex match) |
| `curl`               | `true` or `false` | `false` | Use curl to download content for analysis |
| `grep`               | `true` or `false` | `false` | Use grep instead of JavaScript for pattern matching |
| `resourceTypes`      | Array | `["script", "xhr", "image", "stylesheet"]` | What resource types to monitor |
| `reload`             | Integer | `1` | Number of times to reload page |
| `forcereload`        | `true` or `false` | `false` | Force page reload |
| `site_cleardata`     | `true` or `false` | `false` | Clear site data before loading |
| `delay`              | Milliseconds | `2000` | Wait time after loading/reloading |
| `timeout`            | Milliseconds | `30000` | Timeout for page load |
| `verbose`            | `0` or `1` | `0` | Enable verbose output per site |
| `isBrave`            | `true` or `false` | `false` | Spoof Brave browser detection |
| `localhost`          | `true` or `false` | `false` | Force localhost output (127.0.0.1) |
| `localhost_0_0_0_0`  | `true` or `false` | `false` | Force localhost output (0.0.0.0) |
| `debug`              | `0` or `1` | `0` | Dump matching URLs for the site |
| `interact`           | `true` or `false` | `false` | Simulate user interaction (hover, click) |
| `fingerprint_protection` | `true`, `false`, `random` | `false` | Enable navigator/device spoofing |
| `cloudflare_phish`   | `true` or `false` | `false` | Enable Cloudflare Phishing Warning bypass |
| `headful`            | `true` or `false` | `false` |  Launch browser with GUI for this site |
| `cloudflare_bypass`  | `true` or `false` | `false` | Auto-solve Cloudflare "Verify you are human" challenges |
| `whois`          | Array | `["term1", "term2"]` | Check whois data for ALL specified terms (AND logic) |
| `whois-or`       | Array | `["term1", "term2"]` | Check whois data for ANY specified term (OR logic) |
| `whois_server`   | String or Array | System default | Custom whois server(s) - single server or randomized list |
| `whois_max_retries` | Integer | `2` | Maximum retry attempts per domain |
| `whois_timeout_multiplier` | Number | `1.5` | Timeout increase multiplier per retry (e.g. 1.5 = 50% increase) |
| `whois_use_fallback` | `true` or `false` | `true` | Add TLD-specific fallback servers automatically |
| `whois_retry_on_timeout` | `true` or `false` | `true` | Retry whois lookups on timeout errors |
| `whois_retry_on_error` | `true` or `false` | `false` | Retry whois lookups on connection/other errors |
| `dig`                | Array | `["term1", "term2"]` | Check dig output for ALL specified terms (AND logic) |
| `dig-or`             | Array | `["term1", "term2"]` | Check dig output for ANY specified term (OR logic) |
| `digRecordType`      | String | `"A"`               | DNS record type for dig (default: A) |
| `dig_subdomain`      | `true` or `false` | `false` | Use subdomain for dig lookup instead of root domain |
| `firstParty`         | `0` or `1` | `0` | Match first-party requests |
| `thirdParty`         | `0` or `1` | `1` | Match third-party requests |
| `subDomains`         | `0` or `1` | `0` | 1 = preserve subdomains in output |
| `plain`              | `true` or `false` | `false` | Output nonformated domain urls |
| `blocked`            | Array | - | Domains or regexes to block during scanning |
| `css_blocked`        | Array | - | css cosmetics to block during scanning |
| `goto_options`       | `load` or `domcontentloaded` or `networkidle0` or `networkidle2` | `load` | How to wait for resources to load |
| `evaluateOnNewDocument`    | `true` or `false` | `false` | Inject JS fetch/XHR logging on page load |
| `cdp`                     | `true` or `false` | `false` | Enable Chrome DevTools Protocol logging per site |

---

## Whois Server Configuration

### Basic Usage
```json
{
  "whois": ["cloudflare"],
  "whois_server": "whois.verisign-grs.com"
}
```

### Advanced Retry Configuration
```json
{
  "whois": ["suspicious-registrar"],
  "whois_server": ["whois.verisign-grs.com", "whois.internic.net", "whois.iana.org"],
  "whois_max_retries": 3,
  "whois_timeout_multiplier": 2.0,
  "whois_retry_on_timeout": true,
  "whois_retry_on_error": true,
  "whois_use_fallback": true
}
```

### Load Balanced Servers
```json
{
  "whois_server": [
    "whois.verisign-grs.com",
    "whois.internic.net", 
    "whois.iana.org",
    "whois.markmonitor.com"
  ]
}
```

## Whois Retry Behavior

### Timeout Escalation
- **Attempt 1**: Base timeout (8000ms)
- **Attempt 2**: 8000ms × multiplier (e.g., 12000ms with 1.5 multiplier)  
- **Attempt 3**: 12000ms × multiplier (e.g., 18000ms)

### Server Selection Strategy
1. **Primary servers**: Uses servers from `whois_server` array (randomly selected per domain)
2. **Fallback servers**: Automatically adds TLD-specific reliable servers if `whois_use_fallback` is true
3. **Retry logic**: Tries each server once before moving to next, with escalating timeouts

### Example Debug Output
```
[debug][whois-retry] Starting whois lookup for suspicious-domain.com with 5 server(s) to try
[debug][whois-retry] Attempt 1/5: trying server whois.slow-server.com (timeout: 8000ms)
[debug][whois] TIMEOUT after 8000ms
[debug][whois-retry] Attempt 2/5: trying server whois.fast-server.com (timeout: 12000ms)
[debug][whois-retry] SUCCESS on attempt 2/5 using server whois.fast-server.com
```

---

## Notes

- If both `firstParty: 0` and `thirdParty: 0` are set for a site, it will be skipped.
- `ignoreDomains` applies globally across all sites.
- Blocking (`blocked`) can match full domains or regex.
- If a site's `blocked` field is missing, no extra blocking is applied.
- **Whois servers are randomized per domain lookup** for load balancing and fault tolerance.
- **Fallback servers are automatically selected** based on domain TLD (e.g., `.com` domains use Verisign servers).
- **Retry logic significantly improves success rates** from ~70% to ~95%+ for whois lookups.

---
