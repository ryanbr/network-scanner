# JSON Configuration Manual for scanner-script.js (v0.8.7)

This document provides detailed explanations for each option available in the `config.json` file used by `scanner-script.js`.

---

## Root Fields

| Field           | Type             | Required | Description                                       |
| --------------- | ---------------- | -------- | ------------------------------------------------- |
| `sites`         | Array of objects | Yes      | List of site config entries to scan               |
| `ignoreDomains` | Array of strings | No       | Domains to ignore (e.g., known CDN, safe domains) |
| `blocked`       | Array of strings | No       | Regex patterns to block globally during scan      |

---

## Per-Site Fields

| Field                    | Type                                   | Default | Description                                       |
| ------------------------ | -------------------------------------- | ------- | ------------------------------------------------- |
| `url`                    | String or Array                        | –       | Target URL(s) to scan                             |
| `filterRegex`            | String or Array (regex)                | –       | Regex(es) to match request URLs for detection     |
| `blocked`                | Array of strings (regex)               | –       | Regex patterns to block network requests          |
| `interact`               | Boolean                                | false   | Simulate mouse movement/clicks on page            |
| `isBrave`                | Boolean                                | false   | Spoof `navigator.brave` to bypass Brave detection |
| `userAgent`              | String (`chrome`, `firefox`, `safari`) | –       | Spoof User-Agent string                           |
| `timeout`                | Number (ms)                            | 40000   | Max time to wait before aborting page load        |
| `delay`                  | Number (ms)                            | 2000    | Delay after page load before evaluating requests  |
| `reload`                 | Number                                 | 1       | How many times to reload the page                 |
| `subDomains`             | Number (0 or 1)                        | 0       | Output full subdomains if set to 1                |
| `localhost`              | Boolean                                | false   | Output rules as `127.0.0.1 domain.com`            |
| `localhost_0_0_0_0`      | Boolean                                | false   | Output rules as `0.0.0.0 domain.com`              |
| `source`                 | Boolean                                | false   | Save HTML source after page load                  |
| `firstParty`             | Boolean                                | false   | Include first-party requests                      |
| `thirdParty`             | Boolean                                | true    | Include third-party requests                      |
| `screenshot`             | Boolean                                | false   | Capture screenshot on load failure                |
| `headful`                | Boolean                                | false   | Run browser in non-headless mode for this site    |
| `fingerprint_protection` | Boolean or "random"                    | false   | Enable spoofing of device memory, screen, etc.    |
| `evaluateOnNewDocument`  | Boolean                                | false   | Inject JS to log `fetch`/XHR calls from page      |
| `cdp`                    | Boolean                                | false   | Enable Chrome DevTools Protocol logging           |

---

## Field Descriptions (Detailed)

### `url`

Specifies the webpage(s) to scan. Can be a single URL string or an array of URLs. This is the entry point for Puppeteer to navigate to.

### `filterRegex`

One or more regex patterns that determine which request URLs should be matched and turned into adblock rules. For example, `/track/`, `/analytics.js$/`.

### `blocked`

Used to actively block specific network requests using Puppeteer's interception. This prevents those requests from being sent at all.

### `interact`

If enabled, simulates basic user interactions such as mouse movements and clicks. Useful for triggering lazy-loaded elements or interactive trackers.

### `isBrave`

Spoofs `navigator.brave` object so sites that detect Brave browser will believe it's running. Helps bypass anti-Brave scripts.

### `userAgent`

Overrides the default user-agent string with one that mimics Chrome, Firefox, or Safari on desktop. Useful for evading UA-based fingerprinting.

### `delay`

Milliseconds to wait after page load completes before evaluating network requests. Helps ensure trackers that load late are included.

### `reload`

If set to >1, reloads the page multiple times. Each reload allows scanning additional resources that load inconsistently or dynamically.

### `subDomains`

When enabled (`1`), uses full subdomains in adblock output (e.g., `cdn.ads.example.com`). If disabled, collapses to root domain (`example.com`).

### `localhost` / `localhost_0_0_0_0`

If enabled, outputs domains in the form `127.0.0.1 domain.com` or `0.0.0.0 domain.com` respectively—useful for local blacklists.

### `source`

If true, saves the full HTML source of the page after it finishes loading. Helpful for debugging or archival.

### `firstParty` and `thirdParty`

Controls which types of requests to include in detection. `firstParty` includes requests to the same domain; `thirdParty` includes cross-origin requests.

### `screenshot`

Takes a full-page screenshot **only if** the page fails to load. Useful for debugging.

### `headful`

Overrides headless mode to show the browser GUI. Can be useful for debugging visual elements or captcha gates.

### `fingerprint_protection`

Injects spoofed browser characteristics (like screen size, platform, memory, CPU). Can be static (`true`) or randomized (`"random"`).

### `evaluateOnNewDocument`

Injects JS into the page before any script runs. Overrides `fetch()` and `XMLHttpRequest` to log third-party requests made from within the page’s JavaScript.

### `timeout`

Maximum time (in milliseconds) the browser should wait when loading a page before timing out. Default is 40000ms (40 seconds). Increase this if scanning slow-loading sites.

### `cdp`

Enables Chrome DevTools Protocol for full visibility of network requests, including types like `HEAD`, WebSockets, preloads, and others missed by Puppeteer. for full visibility of network requests, including types like `HEAD`, WebSockets, preloads, and others missed by Puppeteer.

---

For questions or examples, see the README or run with `--help`.

