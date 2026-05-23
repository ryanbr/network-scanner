# Network Scanner (NWSS)

Puppeteer-based network scanner for analyzing web traffic, generating adblock filter rules, and identifying third-party requests. Features fingerprint spoofing, Cloudflare bypass, content analysis with curl/grep, VPN/proxy routing, and multiple output formats.

## Project Structure

- `nwss.js` — Main entry point (~5,600 lines). CLI args, URL processing, orchestration.
- `config.json` — Default scan configuration (sites, filters, options).
- `lib/` — 32 focused, single-purpose modules:
  - `fingerprint.js` — Bot detection evasion (device/GPU/timezone spoofing)
  - `cloudflare.js` — Cloudflare challenge detection and solving
  - `browserhealth.js` — Memory management and browser lifecycle
  - `interaction.js` — Human-like mouse/scroll/typing simulation
  - `ghost-cursor.js` — Bezier-curve cursor pathing for human-like mouse movement
  - `smart-cache.js` — Multi-layer caching with persistence
  - `nettools.js` — WHOIS/dig integration
  - `output.js` — Multi-format rule output (adblock, dnsmasq, unbound, pihole, etc.)
  - `proxy.js` — SOCKS5/HTTP proxy support
  - `socks-relay.js` — Local SOCKS proxy relay/chain helper
  - `wireguard_vpn.js` / `openvpn_vpn.js` — VPN routing
  - `adblock.js` — Adblock filter parsing and validation (native JS engine)
  - `adblock-rust.js` — Drop-in adblock.js replacement backed by Brave's `adblock-rs` Rust engine; same matcher shape (`shouldBlock`, `getStats`, `rules`) so callers swap with one `require()`
  - `validate_rules.js` — Domain and rule format validation
  - `colorize.js` — Console output formatting and colors
  - `domain-cache.js` — Domain detection cache for performance
  - `post-processing.js` — Result cleanup and deduplication
  - `spawn-async.js` — Shared `runProcess(cmd, args, opts)` helper used by curl/grep/searchstring; resolves (never rejects) with `{code, signal, stdout, stderr, truncated, error}`, enforces timeout + stdout caps
  - `redirect.js`, `referrer.js`, `cdp.js`, `curl.js`, `grep.js`, `compare.js`, `compress.js`, `dry-run.js`, `browserexit.js`, `clear_sitedata.js`, `flowproxy.js`, `ignore_similar.js`, `searchstring.js`
- `.github/workflows/npm-publish.yml` — Automated npm publishing
- `nwss.1` — Man page

## Tech Stack

- **Node.js** >=22.0.0
- **puppeteer** >=20.0.0 — Headless browser automation
- **psl** — Public Suffix List for domain parsing (prefer this over hand-curated TLD lists)
- **lru-cache** — LRU cache implementation
- **p-limit** — Concurrency limiting (dynamically imported)
- **adblock-rs** — Optional native Rust filter engine, used by `lib/adblock-rust.js`. Install with `npm install adblock-rs` (requires Rust toolchain). Not a hard dep — `lib/adblock.js` is the default.
- **eslint** — Linting (`npm run lint`)

## Conventions

- Store modular functionality in `./lib/` with focused, single-purpose modules
- Use `messageColors` and `formatLogMessage` from `./lib/colorize` for consistent console output
- Prefix every log line with a subsystem tag, e.g. `const TAG = messageColors.processing('[adblock]');` then `formatLogMessage('warn', `${TAG} ...`)`. Keeps mixed-module output attributable; every module in `lib/` follows this — match it when adding new ones.
- Pick severities deliberately: `warn` for actual errors/failures (cache write fail, native exception), `debug` for diagnostic chatter (cache misses, parse summaries, per-match traces)
- Implement timeout protection for all Puppeteer operations using `Promise.race` patterns
- Handle browser lifecycle with comprehensive cleanup in try-finally blocks
- Validate all external tool availability before use (grep, curl, whois, dig)
- Use `forceDebug` flag for detailed logging, `silentMode` for minimal output
- Use `Object.freeze` for constant configuration objects (TIMEOUTS, CACHE_LIMITS, CONCURRENCY_LIMITS)
- Use `fastTimeout(ms)` helper instead of `node:timers/promises` for Puppeteer 22.x compatibility
- Prefer `runProcess` from `./lib/spawn-async` over bare `child_process.spawn`/`spawnSync` for new external-tool calls. It resolves (never rejects), enforces a SIGKILL timeout + stdout cap, and returns a uniform result object. `lib/wireguard_vpn.js` intentionally stays on `spawnSync` — startup-only validation paths where sync is simpler. Don't follow that exception unless you have the same justification.
- Prefer `net.isIP()` over hand-rolled IPv4/IPv6 regexes for IP validation
- For disk-cache writes use the atomic `tmpPath = path + '.' + pid + '.tmp'` + `fs.renameSync` pattern (see `lib/adblock-rust.js`) so a killed process never leaves a half-written cache file
- Keep `module.exports` minimal — trim helpers that have no external consumers (grep the repo before deciding); internal-only functions stay as functions but leave the exports surface

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
