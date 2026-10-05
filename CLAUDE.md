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
  - `smart-cache.js` — Multi-layer **in-memory** caching (domain / pattern / response / nettools / similarity / regex / request LRUs). It does not persist: the load/save/auto-save machinery was deleted because it could not run — `nwss.js` passed `cache_persistence: false` *after* spreading `...config`, so even a user asking for it got false. Only v1.0.57 (2025-08-06) ever wrote `.cache/smart-cache.json`, before it was hardcoded off two days later, which is the one reason `clearPersistentCache` survives: `--clear-cache` removes that leftover (and the Cloudflare detection cache). That clear is **guarded** like the temp sweep in `browserexit.js` — only `smart-cache.json` and its `<pid>.tmp` siblings, by name; a temp whose pid is still alive is left alone (only `ESRCH` means gone); never `rmdir` through a symlink; the directory goes only if that leaves it empty. Unguarded it was `fs.rmSync(cache_path, { recursive: true, force: true })` on a user-supplied path — a recursive delete of any directory the config happened to name
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

`scripts/test-socks-relay-identity.js` checks what makes two authenticated SOCKS5 upstreams the same local relay: the password is part of the identity (hashed), identical credentials still dedupe, and neither the key nor `getRelayStats` output carries a credential. ~1s, no network — `ensureRelay` binds a local listener and the upstream is never dialled.

`scripts/adshield-rule.js` derives a rotation-proof filter for AdShield-style loaders. Their HOST rotates through a fallback list (html-load.cc -> exceptlone.com -> quitcertify.com), so host-anchored rules die at each rotation, but the PATH does not: it is /script/<base64(site hostname), padding stripped>.js, identical on every host in the chain. Verified against a real capture where four hosts all served /script/am10eS5qcA.js and base64("jmty.jp") reproduces that token exactly. Give it a hostname to get the rule, or --har <file> to detect the pattern in a capture and decode the token back to the site. Detection only needs the FIRST host, which ordinary scans already see — the fallback chain never has to be reproduced.

`scripts/win-har-capture.ps1` drives the user's REAL Windows Firefox (their own profile, their own uBO with its custom rules) to produce HARs that WSL can read, because that is the only environment where the AdShield fallback chain has ever been observed. Run it from Windows with Firefox closed; it sets the HAR auto-export prefs in user.js, launches with --devtools, visits each URL, then restores user.js. Auto-export may not fire — it never did on a fresh profile in testing and the reason is unproven — in which case fall back to F12 > Network > Save All As HAR. Either way the output goes to har-rules.js.

`scripts/har-rules.js` turns a browser-saved HAR into rules using a site config's own matching settings (filterRegex, resourceTypes, first/third-party, ignoreDomains) and emits through the same formatRules() the live scan uses. It exists because some request chains only appear in a REAL browser with a real content blocker: anti-adblock loaders of the AdShield family walk a fallback list (html-load.cc -> exceptlone.com -> quitcertify.com) only once an actual blocker cancels the earlier hosts, and CDP request interception does not trigger it — verified across twelve puppeteer configurations. Save a HAR (F12 > Network > right-click > Save All As HAR) and feed it in. Blocked requests (status 0) are reported but excluded from rules unless --include-blocked. `scripts/har-capture.js` is PARKED — it aimed to automate the export by driving a Windows Firefox from WSL with devtools.netmonitor.har.* prefs. Launch, uBO install, --devtools toolbox opening and cleanup all verified working; no HAR is ever written and no log directory is created, so the export step is never reached. Its header records everything ruled out, so don't re-derive it. Use the manual save with har-rules.js.

`scripts/test-ua-consistency.js` checks that the spoofed Chrome identity is coherent across all four surfaces that carry it — userAgentData.brands and fullVersionList in lib/fingerprint.js, Sec-CH-UA and Sec-CH-UA-Full-Version-List in nwss.js — by running a real scan against a local server that records the request headers while the page reports its own JS view. It re-derives the GREASE brand/version/order from the pinned major, and asks Google's version-history API whether the pinned major.0.build actually exists (network-optional, skips offline) because every surface derives from CHROME_BUILD and so a stale build agrees with itself. It also covers the Firefox family, where coherence means the opposite — the Chromium-only surfaces (userAgentData, window.chrome) must be ABSENT and the Gecko-only ones (oscpu, a 14-digit buildID, productSub 20100101) present. It pins each UA's exact SHAPE (rather than comparing it to the collection entry it came from, which would pass if that entry were edited) and checks both majors against the vendors' own release data — Google's version-history API and Mozilla's product-details — network-optional, skipping offline. Run it after any Chrome- or Firefox-version bump. 49 checks, ~15s measured, needs a browser.

`scripts/test-cloudflare-guards.js` checks that lib/cloudflare.js only reports success on evidence that supports it: a failed quick detection is not cached and not reported as "no indicators"; checkChallengeCompletion never passes safePageEvaluate's truthy defaults object back as isCompleted; cf_clearance is read over CDP (it is HttpOnly); the retry ladder stops before its page.reload() when the caller's adaptive timeout gives up; the JS-challenge wait requires positive evidence and does not pre-empt the Turnstile solver; the phishing bypass confirms the warning is gone; and clickInShadowDOM pays its render wait once rather than per selector, so two calls still fit inside the solve cap; and a solved JS challenge is reported solved rather than being pushed past that cap by a post-solve redirect wait. It compiles the module with one appended line to reach unexported internals rather than widening module.exports. ~2min (measured 125s), browser part needs puppeteer — the slowest suite here, because proving a challenge is NOT solved means letting the module's own 10s JS_CHALLENGE wait expire, several times over.

`scripts/test-flowproxy-budget.js` checks that flowproxy_detection's deliberate waits are represented in nwss.js's per-URL ceiling, so the hang check's emergency restart can't fire during a rate-limit or challenge wait. It extracts the shipped PER_URL_TIMEOUT_MS and restartAfterMs expressions from nwss.js and evaluates them, rather than re-typing the formula, and asserts the term is one-time (not multiplied by reloadCount). <1s, no browser.

`scripts/test-redirect-detector.js` checks that the injected JS-redirect detector installs one MutationObserver per document however many times navigateWithRedirectHandling adds it (nwss can call it three times for one page, and evaluateOnNewDocument scripts accumulate). It counts real constructions by wrapping window.MutationObserver from a script installed first. ~5s, needs a browser.

`scripts/test-interaction-cancel.js` checks that a hard-capped interaction stops rather than running on (a stub page with 3s calls, asserting at most one further call — the one already in flight), and that the impl receives the work-aware budget instead of a hardcoded 15000. ~25s, no browser, no network.

`scripts/test-whois-retry.js` drives the whois path with a fake `whois` on `PATH` and reads the attempt count from what the subprocess was invoked with. It covers the handler running at all without a `siteConfig` (that used to throw and be swallowed at debug level), the documented 2-attempt default, `whois_max_retries` being honoured, `--dry-run` reporting the count the run really uses, and an unexpected error being reported without `--debug`. ~1s, no network.

`scripts/test-dig-resolver.js` asserts what `dig` is actually invoked with for a given `--dns` spec, by putting a fake `dig` on `PATH` and reading the recorded argv. It exists because `--dns` feeds both the pre-check and `dig`, and nettools used to strip an explicit `:port` — pointing the two paths at different servers, silently. ~1s, no browser, no network.

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
