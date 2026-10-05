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
  - `output.js` — Multi-format rule output (adblock, dnsmasq, unbound, pihole, etc.). `hostRejectionReason()` validates a hostname's STRUCTURE **and character set** before any rule is emitted. The character-set half is a security control, not tidiness: a hostname arrives from whatever a page asked the browser to fetch, `new URL()` accepts `*`, `$`, `,`, `!` and `@` in a host, and the output is published. Measured before it existed — `https://*.com/x.js` produced `||*.com^` (blocks every .com), `ads.com$all` produced `||ads.com$all^` (`$all` is a real uBO option). Applies to the live path and `--har` alike, since both emit through `formatDomain()`. Newlines cannot get through: URL parsing strips CR/LF/TAB, so rule *injection* was never possible — the risk was over-blocking. Pinned in test-output-format.js, mutation-verified
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

`scripts/adshield-rule.js` derives a rotation-proof filter for AdShield-style loaders. Their HOST rotates through a fallback list (html-load.cc -> exceptlone.com -> quitcertify.com), so host-anchored rules die at each rotation, but the PATH does not: it is /script/<base64(site hostname), padding stripped>.js, identical on every host in the chain. Verified against a real capture in which four hosts all served the same `/script/<token>.js`, and base64 of that site's own hostname reproduced the token exactly. Give it a hostname to get the rule, or --har <file> to detect the pattern in a capture and decode the token back to the site. Detection only needs the FIRST host, which ordinary scans already see — the fallback chain never has to be reproduced.

`scripts/win-har-capture.ps1` drives the user's REAL Windows Firefox (their own profile, their own uBO with its custom rules) to produce HARs that WSL can read, because that is the only environment where the AdShield fallback chain has ever been observed. Run it from Windows with Firefox closed; it sets the HAR auto-export prefs in user.js, launches with --devtools, visits each URL, then restores user.js. **Auto-export does not produce a file on Firefox 157**, established over two runs against the real profile. Run 1 wrote the log directory into `user.js` with four backslashes instead of two (PowerShell's `-replace` takes backslashes literally in the replacement), so the pref held `C:\\nwss-har` — a path that cannot exist. That was a real defect, is fixed (`.Replace('\','\\')`), and it masked the rest. Run 2: `prefs.js` confirms the directory is correct, `enableAutoExportToFile` and `forceExport` are true, and the toolbox opened on the Network panel (`devtools.everOpened=true`, `toolbox.selectedTool=netmonitor`) — and no file was written anywhere on disk. So neither the path nor the toolbox is the cause; don't re-investigate prefs, paths, timeouts or launch flags. Prefer `win-mozlog-capture.ps1` (no DevTools, no prefs) or the manual F12 > Network > Save All As HAR. Note prefs persist into `prefs.js` once read, so restoring `user.js` does not unset them.

`scripts/win-mozlog-capture.ps1` + `lib/mozlog.js` are the Firefox twin of the net-log route, and **the one to prefer when the blocker matters**. Firefox dumps every HTTP channel when `MOZ_LOG=timestamp,nsHttp:5` is set — an environment variable, so no DevTools, no toolbox, no prefs to write or restore, nothing to click. It matters because Chrome is MV3-only now, so uBO there is uBO Lite on declarativeNetRequest; Firefox still runs full uBO with the user's own rules, and that is the only place the AdShield fallback chain has been seen. The parser takes URLs from `uri=` lines (authoritative, carries the scheme) and resource types from the self-contained `http request [` blocks, joined on host+path rather than by correlating `[this=<pointer>]`, which is reused after a free; per-process sibling logs (`ff.log.child-N.moz_log`) are read automatically. **This route captured the full AdShield fallback chain for the first time** — on a real profile with real uBO, one 45s run walked the full `html-load.cc` -> `exceptlone.com` -> `quitcertify.com` fallback (plus its `0..9.stg.` shards), every host serving the identical `/script/<token>.js`, confirming what `adshield-rule.js` derives from the path token alone. Also verified on a 424MB capture of one page load: 846 requests in 2.7s. Strings that outlive a read chunk are FLATTENED via `flat()`: V8 keeps a substring as a SlicedString referencing its parent, so retaining one 40-char url out of a 4MB chunk pins the whole 4MB. Measured on a real 49MB capture — 43.8MB heap retained for 350 entries and 187MB RSS, versus 0.6MB and 144MB after, parse time unchanged. `(' ' + s).slice(1)` is the idiom (2ms per 200k strings vs 22ms for a Buffer round-trip, both verified to break the reference); the type key needs it too, being a concatenation of two slices that pins BOTH parents. Only mozlog is affected — netlog and har go through `JSON.parse`, which yields fresh flat strings (0.4MB/0.3MB retained, measured). Pinned by a check that re-runs itself under `--expose-gc`. Beyond that, don't bother optimising the parser:  the regex is 2ms of a 190ms sweep, read+split is 94% of it, throughput is ~500MB/s locally, and reading from `/mnt/c` is 35x slower than the Linux FS and dominates everything. An `indexOf` prefilter to skip the regex measured SLOWER than the regex. Request blocks are tracked PER PROCESS+THREAD: the log interleaves line by line, a socket thread's bare `]` lands inside the main thread's block, and a thread-blind parser truncates before `Sec-Fetch-Dest` — every request then types as `other`, including the document, so the page misresolves to whatever Firefox fetched first (a Mozilla cert-chain URL, in the capture that exposed it) and no configured site matches. Quiet captures don't interleave and hid it through three runs. **Blocked requests generally DO appear** here (the channel is logged before a blocker cancels it), which shows what the page *tried* to load — but a cached response also leaves no request block, so nothing is marked blocked from this source; use a HAR for that distinction. Capture at **`nsHttp:1`, not `:5`** — every line the reader uses (`uri=`, `http request [` and the `Sec-Fetch-Dest` inside it) is logged at E, while the verbose levels are connection-manager chatter (141k of 210k lines in one capture). Verified on three existing captures filtered to E-only and on a live run at the new default: zero urls lost, identical entries, page, type histograms and rules, at ~8% of the size — one 45s run went 31.7MB -> 2.4MB and 210ms -> 44ms. `-LogLevel 5` restores the old volume. **Opening a new tab in an already-running Firefox does NOT get captured** — `MOZ_LOG` is read when a process starts, so a second `firefox.exe` with it set just initialises logging, hands its URL to the running instance and exits. Measured: a 0-byte log, which looks like a capture until read (the parser rejects it with a clear message, and the script now names this cause). The graceful close is why `-ForceClose` is safe — Firefox writes sessionstore, so tabs are restored.

**Target urls are NOT in the repo.** All four Windows capture scripts read `<OutDir>\targets.txt` (gitignored; `scripts/targets.example.txt` ships as the template), one url per line, `-Urls` overriding for a one-off. With neither you get a named error, not a silent wrong-site capture. The sites being worked on are not something to publish — and note the AdShield path token is as identifying as the hostname, since it is base64 of it, so worked examples use `<token>` rather than a real one.

`scripts/bait-confirm.js` checks that the domains the walk found really belong to the loader's operator, via dig and whois. Config keys mirror the live-scan vocabulary exactly — `bait_dig` / `bait_whois` are ALL-terms (AND), `bait_dig-or` / `bait_whois-or` are ANY (OR), matched case-insensitively against raw tool output, so an existing `dig: "104.26."` style prefix works unchanged. They are registered in `lib/validate_rules.js` so the validator does not call them typos and claim they are ignored — they ARE read, just by a different consumer than the scan. A tool failure is kept distinct from a mismatch — `dig: err` / UNKNOWN, never MISMATCH — because conflating them meant a missing binary or a dns blip reported every genuine bait as unconfirmed (measured with dig off PATH: 0/6) and `--strict` rejected the lot. Exit codes: 0 all confirmed, 1 a real mismatch, 2 could not be checked. Discovery stays regex-only and confirmation is **report-only by default**: the operator controls their own DNS, so a genuine bait moved to another account would fail a strict check and be dropped. `--strict` exits non-zero when that is what you want. Verified discriminating: the six real baits confirm on both signals, while `insiad.com`, `im-apps.net`, `browsiprod.com` and `example.com` do not.

`scripts/win-bait-walk.ps1` enumerates an anti-adblock fallback chain without naming any host in advance. These loaders stop at the first host the blocker does NOT cancel, so one capture only reveals hosts up to the one that answers — block it, load again, and the next appears. Each round finds hosts by the loader PATH (`/script/<base64(page hostname)>.js`, token DERIVED from the target, never configured), blocks their registrable domains via a PAC pointed at an unroutable proxy in the clone's `user.js`, and relaunches, stopping when a round reveals nothing new. **PAC was chosen by measurement**: in Chrome neither CDP interception (five abort modes) nor a declarativeNetRequest block with a genuine `ERR_BLOCKED_BY_CLIENT` made the loader advance, while in Firefox a plain PAC connection failure does — so the deciding factor is the browser, not the block type. An INCOMPLETE walk never overwrites a complete list: only "exhausted" counts as complete, anything else writes `<name>-baits.partial.txt` and names the reason. Measured — a run capped at one round replaced a six-host list with two while still reporting success. A complete walk UNIONS with the existing list, since a session may offer fewer hosts than a previous one. A SKIPPED capture is detected by the log's mtime, not its exit code: the capture script exits 0 when the lock is held, so the walk would otherwise analyse the PREVIOUS capture and report "nothing new" when nothing ran. Registrable domains use a short multi-part-suffix list — taking the last two labels would turn a `.co.uk` bait into `co.uk` and PAC-block the whole TLD mid-walk. Round 1 runs with NO PAC and is the capture that is kept; rounds 2+ are deliberately distorted scratch, cleaned in `finally` (the loop exits by `break`, so in-loop cleanup never ran for the last round). Enumerated six hosts in three rounds on a real site, all six matching the operator fingerprint — `houston.ns.cloudflare.com` + `veda.ns.cloudflare.com`, which unrelated ad domains on the same pages do not share. Discovered `poppyrimpace.com` and `deployfondly.com` before either had served the capture profile.

`scripts/win-capture-scheduled.ps1` is the unattended twin: `-Install` registers a Task Scheduler job (default every 2h via `-IntervalHours`, `-Uninstall` removes it; keep the consuming pipeline's staleness limit in step with it), and each run captures HEADLESS against a CLONE of the default profile, so the user's own Firefox stays open and untouched. `-no-remote` is essential — without it the url is handed to the running instance and the log is empty. The clone copies `extensions/`, `extensions.json`, `addonStartup.json.lz4`, `prefs.js` (extension UUID map) and each extension's storage — uBO keeps its filter lists AND the user's custom rules in its IndexedDB there — but not site storage/history/cache: 35MB vs 270MB. It is a SNAPSHOT, so `-RefreshProfile` is needed to pick up filter-list or rule changes. Each run PRUNES the clone afterwards — one browsing session took it 35MB -> 177MB (cache2, startupCache, security_state, site storage, safebrowsing, places/favicons), which unattended would grow without bound. Everything regenerable goes; `extensions/`, `prefs.js`, `cookies.sqlite` and `storage/default/moz-extension*` stay. Measured 180MB -> 57MB with the chain still walking all three hosts, i.e. uBO's lists and custom rules survived the prune. **Headless loses nothing**, measured across 3 headful and 2 headless captures: zero hosts appeared in every headful run and never headless, the chain is identical in both, and headless additionally caught 16 header-bidding endpoints (adnxs, rubicon, openx, pubmatic, criteo…). Runs are serialised by a `<name>.lock` holding the owning pid: a manual run and the scheduled run can land on the same second, and they share one clone profile and one output path — Firefox then refuses the second profile lock ("Firefox is already running", `Telemetry.FailedProfileLocks.txt`), the second run deletes the files the first is still writing, and BOTH end with a 0-byte capture. Measured: task 19:33:41, manual 19:33:42. `MultipleInstances=IgnoreNew` only stops the task double-running; it cannot see a manual run. A lock whose owner is dead or older than 15 min is cleared, so a crash cannot block the schedule. The capture window defaults to 20s, not 45: measured across four captures, every host that produced a RULE appeared within 3.7s (the anti-adblock chain at +1.2s to +3.2s). Traffic continues for the rest of the window — one capture was still logging at +44.9s — but none of it reaches the filter regex, so it only costs run time and log volume. Run time 50s → 25s, capture 8.2MB → 6.6MB. Raise `-SecondsPerUrl` for a site that loads ads lazily; the symptom would be thin rules rather than an error. `-Status` prints the task state, last/next run, the target, the capture's age and its TOP HOSTS — that last line is the one that proves which site was really visited, since it is read from the capture's contents rather than from configuration. Each run deletes the previous capture family first and appends to `<name>-runs.log`, recording the target and whether that host actually appears in the capture (`contacted: yes|NO`) — a target can be requested and never reached, and that used to look identical to success.  closing matches the clone path on the command line so the user's browser can never be hit.

`scripts/test-mozlog-parse.js` pins that parser, 16 checks, <1s. The headline one is CRLF: captures come from a Windows browser and are CRLF, and **in a JavaScript regex `\r` is a line terminator, so `.` does not match it** — a pattern as ordinary as `/foo (.*)$/` matches *nothing* on such a file. That cost a real debugging cycle: the first parser returned 0 requests from a 424MB log that plainly contained the text, while every regex tested fine against a hand-typed copy of the same line without its `\r`. `lib/linereader.js` strips it for both parsers. All five guards mutation-verified.

`scripts/win-netlog-capture.ps1` captures a net-log from the user's REAL Windows Chrome (their profile, their uBO), which needs no DevTools and nothing to click — Chrome writes the log itself from `--log-net-log`. It closes Chrome first because a running instance swallows the new flags and just opens a tab in the old process, producing no log silently; it matches processes on the command line via `Get-CimInstance`, never on a PID diff (Chrome spawns and retires renderers constantly, so a before/after PID set kills innocent ones). Verified on Windows Chrome with a throwaway profile: 58MB, 511 requests, 136 hosts, parsed clean. Captures use a FIXED filename (`capture.log.moz_log`, `netlog.json`) so the reading command never changes; `-Name` renames, `-Timestamped` keeps every run. A fixed name obliges the script to clear its own previous family first — Firefox writes one log per content process, so a shorter run leaves stale `child-N` siblings that share the stem and would fold a previous page load into this one. `--har <dir>` also works and takes the NEWEST capture; reading them all merged two real runs of 350 and 288 requests into 498. Output goes to har-rules.js.

`lib/netlog.js` reads a Chrome net-log — `chrome --log-net-log=out.json --net-log-capture-mode=IncludeSensitive <url>` — which needs no DevTools and nothing to click, so it is the capture format to automate. It streams the file line by line rather than `JSON.parse`-ing it, because a killed browser leaves the events array unterminated: a 12.9MB log from a SIGKILLed Chrome yields nothing to `JSON.parse` and 520 requests this way, and the parse reports `truncated`. Type comes from Sec-Fetch-Dest via `typeFromHeaders()` shared with har.js (net-log's own `request_type` is only other/subframe/main frame). **A net-log does not contain extension-blocked requests at all** — measured: a declarativeNetRequest extension blocked `html-load.cc`, puppeteer reported `ERR_BLOCKED_BY_CLIENT`, and `html-load` appears zero times in the 530-request net-log from that run. So it records what the browser really fetched (which is what finds a late host in a fallback chain) but cannot show what a blocker stopped — use a HAR, where those are status 0.

**`nwss.js --har <capture>`** builds rules from a saved browser capture with no browser launched, through the live path's own machinery — same per-site matching, same `formatRules()`, same `processResults()` and `handleOutput()` — so every output format, `--output`, `--append` and `--compare` behave as in a scan. `lib/capture.js` identifies the format by content (HAR / Chrome net-log / Firefox MOZ_LOG) and is shared with har-rules.js. Without `--site`, the capture is matched to a configured site by registrable domain, and nwss STOPS if none matches rather than attributing rules to pages that were never loaded. A capture is one page load, so it is matched once per SITE, not once per configured URL — doing the latter emitted every rule two or three times for a multi-URL site. `siteConfig.even_blocked` decides whether blocked requests count, the same question the live path asks of its own blocker — and **har-rules.js honours it too**, because the two tools read the same config and the same capture and must not disagree. They did: har-rules excluded blocked requests while nwss included them, so the same HAR gave 2 rules through one tool and 5 through the other. Pinned by a check that runs both and compares. With `even_blocked` set, a HAR and a MOZ_LOG of the same page now yield the identical domain set.

`scripts/test-capture-mode.js` pins that flag, 18 checks, ~5s, no browser. Each one is a bug that happened while building it: rules duplicated per configured URL; the output-format flags silently ignored because `formatRules()` got `{}` instead of `globalOptions` (every format emitted adblock syntax and looked plausible); and a positional config file ignored unless an optional `.nwssconfig` existed. All mutation-verified — note the first attempt at the globalOptions mutation renamed one key and survived, because no check exercised `--localhost`; disabling the whole object is what makes it fail.

**Pre-existing bug fixed in passing:** the positional-`.json` → `--custom-json` wiring lived INSIDE `if (fs.existsSync('.nwssconfig'))`, so without that optional file `node nwss.js myconfig.json` silently scanned `config.json` — wrong sites, no warning. Hoisted to always run. Worth knowing when reading old results: a clone without `.nwssconfig` was never scanning the config it was told to.

`scripts/har-rules.js` turns a browser capture — HAR or Chrome net-log, detected by content rather than extension — into rules using a site config's own matching settings (filterRegex, resourceTypes, first/third-party, ignoreDomains) and emits through the same formatRules() the live scan uses. It exists because some request chains only appear in a REAL browser with a real content blocker: anti-adblock loaders of the AdShield family serve a fallback list (html-load.cc -> exceptlone.com -> quitcertify.com), which NO local configuration reproduces but a real Firefox with real uBO walks in full (captured via `win-mozlog-capture.ps1`). **"CDP interception is why" is disproved** — that was the theory across twelve puppeteer configurations, and a thirteenth killed it: a declarativeNetRequest extension, cancelling inside Chrome's own network stack exactly as uBO does and indistinguishable from it to the page, blocked html-load.cc with a real `ERR_BLOCKED_BY_CLIENT` and the loader still never requested exceptlone.com. The block is not what drives the rotation; what does is unidentified. Capture from the real browser instead of trying to reproduce the chain. Save a HAR (F12 > Network > right-click > Save All As HAR) and feed it in. Blocked requests (status 0) are reported but excluded from rules unless --include-blocked. `scripts/har-capture.js` is PARKED — it aimed to automate the export by driving a Windows Firefox from WSL with devtools.netmonitor.har.* prefs. Launch, uBO install, --devtools toolbox opening and cleanup all verified working; no HAR is ever written and no log directory is created, so the export step is never reached. Its header records everything ruled out, so don't re-derive it. Use the manual save with har-rules.js.

`scripts/test-netlog-parse.js` pins how `lib/netlog.js` reads a Chrome net-log, against generated fixtures with the real file's structure (a real log is 10-30MB and the parser's job is structural). It covers the shapes that break a reasonable-looking parser: the events array's `]` is appended to the last event line rather than written on its own, a `polledData` section follows it, and a killed browser leaves the array unterminated so `JSON.parse` returns nothing for the whole file. 24 checks, <1s, no browser, no network. All four guards were mutation-verified — note the first attempt had the bracket land on an ignored event, so a parser handling only a trailing comma passed the whole suite; the last event line must belong to a request the checks assert on.

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
