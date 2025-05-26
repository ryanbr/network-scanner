A Puppeteer-based tool (v0.9.0) for scanning websites to find third-party (or optionally first-party) network requests matching specified patterns, and generate Adblock-formatted rules.

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

---

## Command Line Arguments

| Argument                  | Description |
|:---------------------------|:------------|
| `-o, --output <file>`       | Output file for rules. If omitted, prints to console |
| `--verbose`                 | Force verbose mode globally |
| `--debug`                   | Force debug mode globally |
| `--silent`                  | Suppress console output |
| `--titles`                  | Add `! <url>` before each site's rules |
| `--dumpurls`                | Save full matched URLs to `matched_urls.log` |
| `--sub-domains`             | Output full subdomains (default collapses) |
| `--localhost`               | Output format as `127.0.0.1 domain.com` |
| `--localhost-0.0.0.0`       | Output format as `0.0.0.0 domain.com` |
| `--plain`                   | Output non formated domain.com` |
| `--cdp`                    | Enable Chrome DevTools Protocol logging |
| `--eval-on-doc`           | Inject JS fetch/XHR interception globally |
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
      "resourceTypes": ["script", "xhr", "image"],
      "reload": 2,
      "forcereload": true,
      "clear_sitedata": true,
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
| `forcereload`        | `true` or `false` | `false` | Force page reload |
| `site_cleardata`     | `true` or `false` | `false` | Clear site data before loading |
| `delay`              | Milliseconds | `2000` | Wait time after loading/reloading |
| `timeout`            | Milliseconds | `30000` | Timeout for page load |
| `verbose`            | `0` or `1` | `0` | Enable verbose output per site |
| `debug`              | `0` or `1` | `0` | Dump matching URLs for the site |
| `interact`           | `true` or `false` | `false` | Simulate user interaction (hover, click) |
| `fingerprint_protection` | `true`, `false`, `random` | `false` | Enable navigator/device spoofing |
| `cloudflare_phish`   | `true` or `false` | `false` | Enable Cloudflare Phishing Warning bypass |
| `cloudflare_bypass`  | `true` or `false` | `false` | Auto-solve Cloudflare "Verify you are human" challenges |
| `firstParty`         | `0` or `1` | `0` | Match first-party requests |
| `thirdParty`         | `0` or `1` | `1` | Match third-party requests |
| `subDomains`         | `0` or `1` | `0` | 1 = preserve subdomains in output |
| `plain`              | `true` or `false` | `false` | Output nonformated domain urls |
| `blocked`            | Array | - | Domains or regexes to block during scanning |
| `css_blocked`        | Array | - | css cosmetics to block during scanning |
| `evaluateOnNewDocument`    | `true` or `false` | `false` | Inject JS fetch/XHR logging on page load |
| `cdp`                     | `true` or `false` | `false` | Enable Chrome DevTools Protocol logging per site |

---

## Notes

- If both `firstParty: 0` and `thirdParty: 0` are set for a site, it will be skipped.
- `ignoreDomains` applies globally across all sites.
- Blocking (`blocked`) can match full domains or regex.
- If a site's `blocked` field is missing, no extra blocking is applied.

---
