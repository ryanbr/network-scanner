# Network Scanner (NWSS)

Puppeteer-based network scanner for analyzing web traffic, generating adblock filter rules, and identifying third-party requests. Features fingerprint spoofing, Cloudflare bypass, content analysis with curl/grep, VPN/proxy routing, and multiple output formats.

## Project Structure

- `nwss.js` — Main entry point (~4,600 lines). CLI args, URL processing, orchestration.
- `config.json` — Default scan configuration (sites, filters, options).
- `lib/` — 28 focused, single-purpose modules:
  - `fingerprint.js` — Bot detection evasion (device/GPU/timezone spoofing)
  - `cloudflare.js` — Cloudflare challenge detection and solving
  - `browserhealth.js` — Memory management and browser lifecycle
  - `interaction.js` — Human-like mouse/scroll/typing simulation
  - `smart-cache.js` — Multi-layer caching with persistence
  - `nettools.js` — WHOIS/dig integration
  - `output.js` — Multi-format rule output (adblock, dnsmasq, unbound, pihole, etc.)
  - `proxy.js` — SOCKS5/HTTP proxy support
  - `wireguard_vpn.js` / `openvpn_vpn.js` — VPN routing
  - `adblock.js` — Adblock filter parsing and validation
  - `validate_rules.js` — Domain and rule format validation
  - `colorize.js` — Console output formatting and colors
  - `domain-cache.js` — Domain detection cache for performance
  - `post-processing.js` — Result cleanup and deduplication
  - `redirect.js`, `referrer.js`, `cdp.js`, `curl.js`, `grep.js`, `compare.js`, `compress.js`, `dry-run.js`, `browserexit.js`, `clear_sitedata.js`, `flowproxy.js`, `ignore_similar.js`, `searchstring.js`
- `.github/workflows/npm-publish.yml` — Automated npm publishing
- `nwss.1` — Man page

## Tech Stack

- **Node.js** >=20.0.0
- **puppeteer** >=20.0.0 — Headless browser automation
- **psl** — Public Suffix List for domain parsing
- **lru-cache** — LRU cache implementation
- **p-limit** — Concurrency limiting (dynamically imported)
- **eslint** — Linting (`npm run lint`)

## Conventions

- Store modular functionality in `./lib/` with focused, single-purpose modules
- Use `messageColors` and `formatLogMessage` from `./lib/colorize` for consistent console output
- Implement timeout protection for all Puppeteer operations using `Promise.race` patterns
- Handle browser lifecycle with comprehensive cleanup in try-finally blocks
- Validate all external tool availability before use (grep, curl, whois, dig)
- Use `forceDebug` flag for detailed logging, `silentMode` for minimal output
- Use `Object.freeze` for constant configuration objects (TIMEOUTS, CACHE_LIMITS, CONCURRENCY_LIMITS)
- Use `fastTimeout(ms)` helper instead of `node:timers/promises` for Puppeteer 22.x compatibility

## Running

```bash
node nwss.js                          # Run with default config.json
node nwss.js config-custom.json       # Run with custom config
node nwss.js --validate-config        # Validate configuration
node nwss.js --dry-run                # Preview without network calls
node nwss.js --headful                # Launch with browser GUI
```

## Files to Ignore

- `node_modules/**`
- `logs/**`
- `sources/**`
- `.cache/**`
- `*.log`
- `*.gz`
