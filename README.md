A Puppeteer-based tool for scanning websites to find third-party (or optionally first-party) network requests matching specified patterns, and generate Adblock-formatted rules.

## Features

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

---

## Command Line Arguments

### Output Options

| Argument                  | Description |
|:---------------------------|:------------|
| `-o, --output <file>`       | Output file for rules. If omitted, prints to console |
| `--compare <file>`          | Remove rules that already exist in this file before output |
| `--color, --colour`         | Enable colored console output for status messages |

### Output Format Options

| Argument                  | Description |
|:---------------------------|:------------|
| `--localhost`               | Output as `127.0.0.1 domain.com` |
| `--localhost-0.0.0.0`       | Output as `0.0.0.0 domain.com` |
| `--plain`                   | Output just domains (no adblock formatting) |
| `--dnsmasq`                 | Output as `local=/domain.com/` (dnsmasq format) |
| `--dnsmasq-old`             | Output as `server=/domain.com/` (dnsmasq old format) |
| `--unbound`                 | Output as `local-zone: "domain.com." always_null` (unbound format) |
| `--adblock-rules`           | Generate adblock filter rules with resource type modifiers (requires `-o`) |

### General Options

| Argument                  | Description |
|:---------------------------|:------------|
| `--verbose`                 | Force verbose mode globally |
| `--debug`                   | Force debug mode globally |
| `--silent`                  | Suppress normal console logs |
| `--titles`                  | Add `! <url>` title before each site's group |
| `--dumpurls`                | Dump matched URLs into matched_urls.log |
| `--compress-logs`           | Compress log files with gzip (requires `--dumpurls`) |
| `--sub-domains`             | Output full subdomains instead of collapsing to root |
| `--no-interact`             | Disable page interactions globally |
| `--custom-json <file>`      | Use a custom config JSON file instead of config.json |
| `--headful`                 | Launch browser with GUI (not headless) |
| `--cdp`                     | Enable Chrome DevTools Protocol logging (now per-page if enabled) |
| `--remove-dupes`            | Remove duplicate domains from output (only with `-o`) |
| `--eval-on-doc`             | Globally enable evaluateOnNewDocument() for Fetch/XHR interception |
| `--help`, `-h`              | Show this help menu |
| `--version`                 | Show script version |

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

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `url`                | String |   -     | Website URL to scan |
| `userAgent`          | `chrome`, `firefox`, `safari`, `mobile-chrome`, etc. | - | User agent for page |
| `filterRegex`        | String or Array | `.*` | Regex or list of regexes to match requests |
| `resourceTypes`      | Array | `["script", "xhr", "image", "stylesheet"]` | What resource types to monitor |
| `reload`             | Integer | `1` | Number of times to reload page |
| `delay`              | Milliseconds | `2000` | Wait time after loading/reloading |
| `timeout`            | Milliseconds | `30000` | Timeout for page load |
| `verbose`            | `0` or `1` | `0` | Enable verbose output per site |
| `debug`              | `0` or `1` | `0` | Dump matching URLs for the site |
| `interact`           | `true` or `false` | `false` | Simulate user interaction (hover, click) |
| `fingerprint_protection` | `true`, `false`, `random` | `false` | Enable navigator/device spoofing |
| `firstParty`         | `0` or `1` | `0` | Match first-party requests |
| `thirdParty`         | `0` or `1` | `1` | Match third-party requests |
| `subDomains`         | `0` or `1` | `0` | 1 = preserve subdomains in output |
| `blocked`            | Array | - | Domains or regexes to block during scanning |

### WHOIS/DNS Analysis Options

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `whois`              | Array | - | Check whois data for ALL specified terms (AND logic) |
| `whois-or`           | Array | - | Check whois data for ANY specified term (OR logic) |
| `whois_delay`        | Integer | 2000 | Delay whois requests to avoid throttling (2sec Default) | 
| `whois_server`       | String or Array | - | Custom whois server(s) - single server or randomized list |
| `whois_max_retries`  | Integer | `2` | Maximum retry attempts per domain |
| `whois_timeout_multiplier` | Number | `1.5` | Timeout increase multiplier per retry |
| `whois_use_fallback` | Boolean | `true` | Add TLD-specific fallback servers |
| `whois_retry_on_timeout` | Boolean | `true` | Retry on timeout errors |
| `whois_retry_on_error` | Boolean | `false` | Retry on connection/other errors |
| `dig`                | Array | - | Check dig output for ALL specified terms (AND logic) |
| `dig-or`             | Array | - | Check dig output for ANY specified term (OR logic) |
| `dig_subdomain`      | Boolean | `false` | Use subdomain for dig lookup instead of root domain |
| `digRecordType`      | String | `"A"` | DNS record type for dig (A, CNAME, MX, etc.) |

### Advanced Browser Options

| Field                | Values | Default | Description |
|:---------------------|:-------|:-------:|:------------|
| `goto_options`       | Object | `{"waitUntil": "load"}` | Custom page.goto() options |
| `clear_sitedata`     | Boolean | `false` | Clear all cookies, cache, storage before each load |
| `forcereload`        | Boolean | `false` | Force an additional reload after reloads |
| `isBrave`            | Boolean | `false` | Spoof Brave browser detection |
| `evaluateOnNewDocument` | Boolean | `false` | Inject fetch/XHR interceptor in page |
| `cdp`                | Boolean | `false` | Enable CDP logging for this site |
| `cloudflare_phish`   | Boolean | `false` | Auto-click through Cloudflare phishing warnings |
| `cloudflare_bypass`  | Boolean | `false` | Auto-solve Cloudflare "Verify you are human" challenges |
| `css_blocked`        | Array | - | CSS selectors to hide elements |
| `searchstring`       | String or Array | - | Text to search in response content (OR logic) |
| `searchstring_and`   | String or Array | - | Text to search with AND logic - ALL terms must be present |
| `curl`               | Boolean | `false` | Use curl to download content for analysis |
| `grep`               | Boolean | `false` | Use grep instead of JavaScript for pattern matching (requires curl=true) |
| `source`             | Boolean | `false` | Save page source HTML after load |
| `screenshot`         | Boolean | `false` | Capture screenshot on load failure |
| `headful`            | Boolean | `false` | Launch browser with GUI for this site |

---

## Notes

- If both `firstParty: 0` and `thirdParty: 0` are set for a site, it will be skipped.
- `ignoreDomains` applies globally across all sites.
- Blocking (`blocked`) can match full domains or regex.
- If a site's `blocked` field is missing, no extra blocking is applied.

---
