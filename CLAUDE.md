# Network Scanner (NWSS)

Puppeteer-based network scanner for analyzing web traffic, generating adblock filter rules, and identifying third-party requests. Features fingerprint spoofing, Cloudflare bypass, content analysis with curl/grep, VPN/proxy routing, and multiple output formats.

## Project Structure

- `nwss.js` — Main entry point (~7,200 lines). CLI args, URL processing, orchestration. `processUrl` is ~3,200 lines of it; the tractable extractions left are the popup cluster (~460 lines) and the request handler (~250), both needing an explicit context object for ~14 closure dependencies.
- `config.json` — Default scan configuration (sites, filters, options).
- `lib/` — 36 focused, single-purpose modules:
  - `fingerprint.js` — Bot detection evasion (device/GPU/timezone spoofing)
  - `cloudflare.js` — Cloudflare challenge detection and solving
  - `browserhealth.js` — Memory management and browser lifecycle
  - `interaction.js` — Human-like mouse/scroll/typing simulation
  - `ghost-cursor.js` — Bezier-curve cursor pathing for human-like mouse movement
  - `smart-cache.js` — Multi-layer caching with persistence
  - `nettools.js` — WHOIS/dig integration
  - `dns.js` — DNS pre-check resolver: multi-nameserver rotation + `--dns` override (pre-check only; not Chrome/dig)
  - `output.js` — Multi-format rule output (adblock, dnsmasq, unbound, pihole, etc.)
  - `proxy.js` — SOCKS5/HTTP proxy support
  - `socks-relay.js` — Local SOCKS proxy relay/chain helper
  - `wireguard_vpn.js` / `openvpn_vpn.js` — VPN routing
  - `adblock.js` — Adblock filter parsing and validation (native JS engine). Also exports `createPopupSignalMatcher(lists)`, a standalone report-only matcher for `$popup` rules — neither engine can block those, so they are used as popunder-endpoint *signal* during popup capture. Standalone on purpose: it is called with the rust engine selected too
  - `adblock-rust.js` — Drop-in adblock.js replacement backed by Brave's `adblock-rs` Rust engine; same matcher shape (`shouldBlock`, `getStats`, `rules`) so callers swap with one `require()`
  - `cookies.js` / `storage.js` — Pre-navigation seeding of cookies and `localStorage`/`sessionStorage`, for gates that decide during the first document load. Both scope what they set to the `url` entry and reference-count teardown so concurrent same-host URLs can't tear down each other's state, and both resolve "which site is this" through `site-scope.js` — a seeded cookie defaults to `.` + the registrable domain, the same breadth the storage seed matches, so an apex↔www redirect keeps both (it used to keep storage and drop every cookie). `storage.js` seeds via `evaluateOnNewDocument` (storage is only reachable from a document on the origin) and matches on the registrable domain (via `psl`), not the origin or the exact hostname, so an http→https upgrade, a port change or a redirect to another subdomain still gets seeded, while a different registrable domain is refused
  - `eval-on-doc.js` — Fetch/XHR interception injected before page scripts (`evaluateOnNewDocument: true` per site, or `--eval-on-doc`). Three strategies: browser health check, full injection, then a minimal fetch-only fallback — but never after a CDP/Protocol error, which means the browser link is broken. Also exports `watchForReloadLoop()`, which REPORTS a page reloading itself and leaves it running: it counts main-frame navigations to the same URL (so it sees `reload`, `replace`, `href` and `<meta refresh>` alike) and warns once when the count passes `reload: N` plus slack. Driver-side because it has to be — `location.reload` is `[[Unforgeable]]`, and the in-page version this replaces had never once run. Report-only by choice: both ways of stopping a loop cost more than the loop does — aborting the navigation was measured leaving the page on `chrome-error://chromewebdata/` (grep/searchstring/screenshot then see an error page), and disabling script execution stops every other script too. The warning latches so it cannot repeat per reload
  - `css-blocking.js` — `css_blocked` selector hiding, at both application points: `injectCssBlocking()` before navigation and `applyCssBlockingNow()` as a post-load fallback, plus the one `getCssBlockedSelectors()` gate both share
  - `site-scope.js` — Registrable-domain (eTLD+1) derivation via `psl`, shared by `cookies.js` and `storage.js`. `registrableDomain()` returns null when there is no wider scope than the host (IP literal, single-label host, bare public suffix) — for SETTING a scope; `siteScope()` falls back to the host itself — for MATCHING one
  - `browserexit.js` — Browser teardown and temp-file cleanup. The Chrome/Puppeteer temp sweep is **guarded**: it removes paths the run declares as its own (`ownPaths`, which `handleBrowserExit` derives from both the caller's `userDataDir` and the browser's own `--user-data-dir` spawnarg), skips anything a live browser is using (`SingletonLock` → `<host>-<pid>`, plus the `/tmp/com.google.Chrome.*` directory a live profile's `SingletonSocket` points at), and otherwise only removes entries older than `LEFTOVER_MIN_AGE_MS` (15 min). Unguarded, it deleted any match on the machine — a concurrent run's live profile, a desktop Chrome's temp dir, and even the profile of the browser this run had just launched, since the startup sweep runs after launch
  - `validate_rules.js` — Domain and rule format validation
  - `colorize.js` — Console output formatting and colors
  - `post-processing.js` — Result cleanup and deduplication
  - `spawn-async.js` — Shared `runProcess(cmd, args, opts)` helper used by curl/grep/searchstring; resolves (never rejects) with `{code, signal, stdout, stderr, truncated, error}`, enforces timeout + stdout caps
  - `redirect.js`, `referrer.js`, `cdp.js`, `curl.js`, `grep.js`, `compare.js`, `compress.js`, `dry-run.js`, `browserexit.js`, `clear_sitedata.js`, `flowproxy.js`, `ignore_similar.js`, `searchstring.js`
- `.github/workflows/npm-publish.yml` — Automated npm publishing
- `nwss.1` — Man page

## Tech Stack

- **Node.js** >=22.12.0 (required for stable `require()` of ESM-only puppeteer 25)
- **puppeteer** >=24.0.0 — Headless browser automation. Range permits both v24 and v25; dev lockfile is on v25.
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
- Use `fastTimeout(ms)` helper instead of `node:timers/promises` for delays — project convention since the Puppeteer 22.x `page.waitForTimeout` removal, retained as the standard for all Promise-based sleeps
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

## Stealth Testing

`scripts/test-stealth.js` is a smoke-test harness for the fingerprint spoofing
stack. Launches Puppeteer with `applyAllFingerprintSpoofing` applied (same
call shape nwss.js uses), navigates to public bot-detection pages, and
reports what they concluded. Use it to A/B a stealth change — run before the
edit, run after, diff. Found 3 real bugs that 5 rounds of static review
missed (PHANTOM/SELENIUM own-goal, PluginArray instanceof, Plugin toString).

A self-consistency check runs first for whichever `--ua` is selected (offline,
`about:blank`): it flags Chromium-only APIs surviving a non-Chrome UA,
Firefox-only props on the wrong family, platform/vendor disagreeing with the UA,
and plugins/mimeTypes mismatches. Run it per family — the third-party targets
are built to detect headless *Chrome*, so under `--ua=firefox` their red cells
mostly mean "doesn't look like Chrome" and real contradictions hide in the noise.

```bash
node scripts/test-stealth.js                  # all targets, human-readable
node scripts/test-stealth.js sannysoft        # one target
node scripts/test-stealth.js --no-spoof       # baseline (spoof disabled)
node scripts/test-stealth.js --format=json    # machine-readable for diff/jq
node scripts/test-stealth.js --help           # full flag list
```

Set `PUPPETEER_NO_SANDBOX=1` when running as root (CI containers). Off by
default so local dev doesn't silently drop the sandbox. The harness depends
on `USER_AGENT_COLLECTIONS` exported from `lib/fingerprint.js` — keep that
export in sync if the UA list changes.

## Injection / Seeding Tests

`scripts/test-seeding.js` is the assertion-based suite for everything nwss
injects into a page before its own scripts run: `cookies`, `local_storage`,
`session_storage`, `css_blocked`, Fetch/XHR interception and the `$popup`
capture signal. It exits non-zero on failure, so unlike `test-stealth.js` it is a gate,
not a report. Three groups, selectable with `--group=`:

- `unit` — scope derivation, cookie/storage config normalisation, the signal
  matcher against an inline filter list (never `easylist.txt`, which is not
  tracked and whose counts move every update)
- `browser` — Puppeteer harnesses for behaviour only the browser can settle:
  cookie scope across an apex→www redirect (via `--host-resolver-rules`, since an
  IP literal has no subdomains), per-key storage writes, refcounted teardown,
  partial failure
- `e2e` — real `nwss.js` scans against generated configs and a loopback fixture
  server

```bash
node scripts/test-seeding.js                  # all groups
node scripts/test-seeding.js --group=unit     # fast, no browser
node scripts/test-seeding.js --list           # check names
```

Every check pins a bug a review pass found, most of them things static reading
got wrong. **When changing anything in `lib/cookies.js`, `lib/storage.js`,
`lib/site-scope.js`, `lib/css-blocking.js`, `lib/eval-on-doc.js` or the
popup-signal path, add a check here** — these
behaviours are set by Chrome and CDP, not by our code, so they cannot be
verified by reading.

After adding a check, confirm it FAILS with the fix reverted — a check that
cannot fail is decoration. Mutate by removing or inverting the guard itself
(rethrow from the catch, negate the condition); never add a failure *inside* the
region the guard protects, or the guard catches it and the run reports a coverage
gap that does not exist. The suite's ten existing checks were verified this way
on 2026-09-26. Done ad hoc rather than with a committed tool on purpose: a
mutation script is a list of exact source strings, which rot into silent
no-op "skips" on the next refactor of the files they target.

## Adblock Parity Tests

`scripts/test-adblock-parity.js` asserts that `lib/adblock.js` and
`lib/adblock-rust.js` return the same VERDICT (`blocked`), not the same `reason` —
each names its own matching bucket. It exists because the two are swapped by one
`require()` and `--adblock-engine` defaults to whichever loads, so a scan's
blocking depends on which engine ran, and their disagreements are silent.

```bash
node scripts/test-adblock-parity.js                 # ~0.5s, no browser
node scripts/test-adblock-parity.js --group=corpus  # verdicts | corpus | asymmetries
```

Skips when `adblock-rs` is absent (optional dep) and the easylist-backed checks
skip without `./easylist.txt` (untracked). The `asymmetries` group pins the
differences that DO exist, measured: an empty `resourceType` blocks a
type-restricted rule in the JS engine but not in rust (nwss always has a type, so
it is recorded rather than fixed), and for `document` requests the JS engine blocks
where rust does not while rust is never stricter — that direction is asserted,
because nwss never aborts a main-frame document and an ad iframe arrives as
`sub_frame`, which must agree exactly.

**A directional assertion needs inputs on both sides.** The document check first
shipped with a corpus built only from urls the JS engine blocks, so "rust blocks
where js does not" could never be observed — forcing rust to block every document
request left it green. It now carries innocuous control urls, asserted innocuous
first.

## Files to Ignore

- `node_modules/**`
- `logs/**`
- `sources/**`
- `.cache/**`
- `*.log`
- `*.gz`
