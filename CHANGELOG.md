# Changelog

All notable changes to the Network Scanner (nwss.js) project.

## [Unreleased]

### Added
- **`click_elements` site option** — after a page loads, click a list of CSS selectors **in order** (e.g. `["a[href*='/movie/']", ".play"]` to click a movie link then a play button). Reaches content via organic navigation/gesture instead of a direct deep-load, which some sites JS-redirect away, and triggers click-only content like video players. Each selector is `waitForSelector`-ed (visible) up to `click_wait` before clicking, so JS-rendered targets like video players aren't missed by racing ahead of them. The request interceptor stays attached, so the post-click page's requests run through the same `filterRegex`/`dig` matching; a click that navigates is followed and later selectors query the resulting page. Honors `realistic_click` (genuine trusted gesture) and `cursor_mode: "ghost"` (Bezier travel to the element); missing elements are skipped and never fail the scan. Settle/nav wait per click via `click_wait` (default 5000ms, capped at half the per-URL timeout).
- **`--dns` now also pins Chrome's page-navigation resolver via DoH.** Chrome ignores `--dns` for navigation and reads `/etc/resolv.conf` directly, so a broken or filtering system resolver could `ERR_NAME_NOT_RESOLVED` a domain the pre-check had already resolved. When the `--dns` servers map to a known public DoH provider — **Google, Cloudflare, Quad9, OpenDNS, AdGuard, CleanBrowsing, DNS.SB, Mullvad** (incl. malware/family/unfiltered variants) — Chrome is launched with secure-DNS `automatic` mode pointed at that provider, so page navigation resolves through the same resolver as the pre-check. `automatic` (not `secure`) keeps a system-DNS fallback if DoH is unreachable rather than failing the batch. **Applied to direct connections only** — skipped when a proxy (`--proxy-server`) or VPN is active, since the exit/tunnel does the resolution and local DoH would be redundant or resolve geo-split domains to the wrong region. Unmapped resolvers (custom/ISP, per-account providers like NextDNS, IPv6) fall back to system DNS with a warning naming the supported providers.
- **`--doh-disable`** site/CLI option (`doh_disable` in `.nwssconfig`), default off — opt out of the Chrome-navigation DoH pinning entirely. Chrome then resolves page navigation via the system `resolv.conf` even when `--dns` maps to a known provider, while the pre-check and `dig` still honor `--dns`. For networks where DoH adds latency or is blocked, or when system-path resolution is specifically wanted.

### Changed
- **DNS pre-check is paced and more tolerant under concurrency** — a concurrent scan fired up to `max_concurrent` simultaneous c-ares UDP queries at the pinned `--dns` servers; the burst (rough on WSL2's UDP-through-NAT path, and rate-limited by public resolvers) produced timeouts / `EREFUSED` that tripped the circuit breaker (`resolver errors N/M — suspending DNS pre-check`) and lost the dead-host-skip optimization. The pre-check timeout is raised 2s → 4s (a clean NXDOMAIN still returns fast, so the higher ceiling only costs time when the resolver is genuinely slow), and `createRotatingResolver` now caps in-flight queries with a counting semaphore (default 6) so the burst is paced and excess callers queue and drain quickly. The circuit breaker itself is unchanged — these reduce the error rate so it stops tripping on healthy resolvers.

### Fixed
- **`whois` availability probe is now platform-aware** — the fallback used `which whois` (Unix-only), which on native Windows would false-negative an installed `whois.exe` whose `whois --version` errors (e.g. Sysinternals whois). Uses `where` on Windows, `which` elsewhere. No change on Linux/macOS/WSL.

## [3.3.0] - 2026-06-06

### Added
- **DNS dead-domain skip + corroborated persistence** — within a scan, once a host resolves NXDOMAIN/ENODATA it is remembered and repeat URLs on that host are skipped without re-resolving. With `--dns-cache`, a host that *also* fails navigation (`ERR_NAME_NOT_RESOLVED` / `ERR_ADDRESS_UNREACHABLE`) is corroborated and persisted to the negative cache (`.dnsnegcache`, 12h TTL) so it is skipped on the next run too. Only definitive non-existence is cached — resolver errors fail open and never poison a live host.
- **`acceptInsecureCerts` on browser launch** — TLS/cert errors (expired, self-signed, name-mismatch) no longer abort navigation, so streaming/pirate domains with broken certs are still scanned.
- **`--disable-popup-blocking` when a site uses `capture_popups`** — Chrome's pop-up blocker (`chrome://settings/content/popups`) is turned off only for popup-capture scans, so non-gesture popunders (document-level `onclick` / timer SDKs) fire and get captured too. Non-popup scans keep the blocker on (stealthier — a real browser blocks non-gesture `window.open()`); gesture-triggered popups already worked via the synthetic-click path.

### Changed
- **The main-frame document is never blocked** — the scanned page (and any main-frame redirect target) is exempt from adblock / `blocked` / `blockDomainsByUrl` aborts. Aborting it made the navigation never commit (`about:blank` → timeout), silently breaking scanned URLs that matched our own filter lists (common on adult/pirate/stream domains). The request still flows through the matcher, so a main-frame redirect destination (e.g. a filecrypt → ad-domain hop) is still captured; sub-frame / ad iframes stay blockable.
- **Navigation timeouts are recovered, not discarded** — on a nav timeout the scanner retries leniently and proceeds with the partially-loaded page instead of dropping the URL (a page still at `about:blank` is still treated as a failure).
- **whois disk-cache TTL raised to 36h** (dig stays 20h) — registrar data is stable and whois servers rate-limit aggressively, so a longer TTL cuts repeat queries; dig keeps its 20h TTL.
- **VPN is Linux-only with a clear guard** — `vpn` / `openvpn` on macOS/Windows now returns an explicit "Linux-only" error instead of cryptic `ip` / `/proc` failures.

### Performance
- **`psl.parse` memoized by hostname** in the request hot path — both per-request handlers (main page + popup capture) parsed the root domain of *every* request, while a page hammers the same handful of hosts (CDN, analytics, ad domains). A hostname-keyed memo turns almost all of those into `Map` hits, replacing the URL-keyed cache (fewer + shorter keys, far higher hit rate).
- **Lower per-request overhead** — the iframe-loop guard's `frame().url()` lookup is now gated behind a cheap URL string test instead of running on every request.
- **Removed redundant disk I/O** — a leaked adblock combined-list temp file in `tmpdir` is now cleaned up, and a redundant `existsSync` before each forced screenshot's recursive `mkdir` was dropped.

### Fixed
- **Periodic debug/`--dumpurls` log flush is now synchronous** — the 2s timer used async `fs.writeFile({flag:'a'})` with no in-flight guard, so two ticks could append to the same file concurrently and interleave lines, and it cleared the buffer *before* the write confirmed (silently dropping entries on a failed write). It now uses `appendFileSync`, clears only after a successful write (transient failures retry next tick), and is bounded so a permanently-unwritable path can't grow memory.
- **Dead-domain skip works without `--show-dead-domains`** — the in-scan skip recorded into the dead set only when the report flag was on, which made the skip dead code; recording is now unconditional and the flag gates only the end-of-scan report. Transient DNS errors were also dropped from the dead-domain match so only `ERR_NAME_NOT_RESOLVED` / `ERR_ADDRESS_UNREACHABLE` mark a host dead.

### Removed
- **Hardcoded `dmzjmp` iframe-loop guard** — the domain-specific abort for a `creative.dmzjmp.com` frame requesting `go.dmzjmp.com/api/models` (added mid-2025 to stop a runaway request loop) has not recurred and was removed from the request hot path; the per-URL timeout remains the backstop. Recoverable from git history — prefer a config-driven `iframe_loop_guards` entry if it ever returns.

### Documentation
- **README + man page now document `--block-ads` and `--adblock-engine`** — blocking ads/trackers *during* the scan with EasyList-format list(s) (comma-separated), and the `js` (default, native parser) vs `rust` (Brave `adblock-rs`) matcher backends.

## [3.2.0] - 2026-06-04

### Added
- **`output_regex`** site option — a per-site regex whose capture group 1 (or whole match) becomes the rule body, so output can be a path-prefix rule like `||host/script/` instead of `||host^`. Collapses randomized filenames under a stable path into one rule and lets you block a folder on a host that also serves legit content; falls back to `||host^` when the regex doesn't match. Adblock-only — domain-based formats (dnsmasq/unbound/pi-hole/hosts/plain) emit the bare host. Compiled once per pattern (memoized) and validated at config load.
- **dig resolver failover** — `digLookup` now fails over through the `--dns` resolvers on timeout / no-reply / `REFUSED` / `SERVFAIL` (up to 3 attempts, `+time=2 +tries=1` each), matching the resilience the whois retry and DNS pre-check rotation already had. With no `--dns`, the system-resolver path keeps dig's native `resolv.conf` rotation unchanged.

### Changed
- **Ghost-cursor coordinate clicks now use the same realistic press as the built-in content clicks** (`humanClick`): hover dwell + mousedown/hold/mouseup, plus hand-tremor during the hold and a mouseup drift (so mousedown ≠ mouseup coordinates) when `realistic_click` is set — replacing a 0ms `page.mouse.click`.
- **Ghost-cursor clicks honor `interact_click_count`** (default 3, cap 20) instead of firing a single click — ad SDKs often swallow the 1st/2nd click as warmup. The bezier movement loop reserves part of `ghost_cursor_duration` for the clicks (raise the duration to fit more; the default 2000ms fits ~1 realistic click).
- **`dig` success is judged by RCODE, not stderr** — a dig that prints a transient `communications error` warning but still returns a valid `ANSWER SECTION` is no longer discarded.
- **dig-only configs skip the whois root-domain parse** per request (small per-request saving when no `whois`/`whois-or` is configured).

### Fixed
- **`max_redirects: 0`** now means "follow none" instead of silently becoming 10 (the `|| 10` falsy-zero bug in `nwss.js` and `lib/redirect.js`).
- **A `REFUSED`/`SERVFAIL` dig that exhausts all resolvers returns failure** so it isn't cached — a transient resolver-side error no longer poisons a domain for the cache TTL.
- **Ghost-cursor coordinate click no longer reports false success** — it returned `true` (and logged "Clicked") even when the click was silently skipped for lack of a page; it now returns `false` and logs the skip.

### Removed
- **`follow_redirects`** site option — documented in `--help`, the man page, the README, and example configs but never wired to any runtime behavior; removed from the docs. Use `max_redirects` instead (`0` = follow none).

### Security
- **dig argv-injection guard** — `digLookup` rejects non-hostname-shaped input before shelling out. `dig` has no `--` end-of-options marker (unlike whois) and parses `@`/`-`/`+`-leading argv tokens as options, so a crafted "domain" like `@evil-resolver` (redirects the query to an arbitrary server) or `-f /path` (reads a file as a query batch) is now rejected — out-of-charset or dash-leading values fall back to no-match.

## [3.1.2] - 2026-05-30

### Changed
- **Fingerprint identity pinned to Stable Chrome 148**, not whatever Chrome-for-Testing puppeteer bundles (currently 149, ahead of Stable). The spoof must blend with the real-world population; claiming an unreleased build is itself a tell. The Chrome major + build (`CHROME_BUILD`) + GREASE brand (`CHROME_GREASE_BRAND`) are now single constants — see `lib/fingerprint.md`.
- **UA Client Hints made fully consistent and matched to real Chrome 148** (verified field-for-field against a live desktop): brand-list order + GREASE string (`Not/A)Brand`), and the full-version build (`148.0.7778.217`) sourced from one place so JS `getHighEntropyValues` and the HTTP `Sec-CH-UA-Full-Version*` headers can't drift. Added `wow64`, `model`, `formFactors`, `uaFullVersion`, and `Sec-CH-UA-WoW64`/`-Model`/`-Form-Factors` headers; Windows `platformVersion` → `19.0.0`.
- **`navigator.deviceMemory` and `Sec-CH-Device-Memory` both pinned to `8`** (consistent JS↔HTTP), hiding the host's real RAM; `hardwareConcurrency` reports 4–8 (hides datacenter core count).
- **Dependencies**: puppeteer / puppeteer-core 25.1.0, lru-cache 11.5.1.

### Fixed
- **Timezone is now spoofed via CDP `emulateTimezone`** instead of JS overrides, so `Date`, `Intl`, and `getTimezoneOffset` are all consistent and DST-correct. The old JS patching left the real `Date` in the host zone — an 8-hour `Date`-vs-`Intl` contradiction and a leaked host timezone.
- **Closed several headless tells**: Battery now reports the plugged-in default (`charging:true, level:1`); `navigator.bluetooth`, `navigator.share`/`canShare` stubs added (present in real Chrome, absent in headless); `speechSynthesis.getVoices()` returns the claimed-OS voice set (`instanceof`-correct).
- **proxy**: a string `proxy_bypass`/`socks5_bypass` (instead of an array) no longer throws `bypass.join is not a function` in the browser-launch path.
- **socks-relay**: a client that disconnects during the upstream-connect await is now handled, so a tunnel isn't opened for a gone client and the watchdog clears immediately.
- **smart-cache**: the memory-check and auto-save `setInterval`s are now `unref`'d, so an error path that skips `destroy()` can no longer hang the process.

### Removed
- Dead code: `browserhealth` `testNetworkCapability` + `purgeStaleTrackers` (zero callers), and a redundant 2-voice `speechSynthesis` block superseded by the full voice set.

### Added
- **`lib/fingerprint.md`** — fingerprint spoofing coverage tables (surfaces, mitigations, gating flags) and known limitations.

## [3.1.0] - 2026-05-29

### Added
- **`realistic_click`** site flag — denser mouse approach, hold tremor, and mouseup drift for sites that score click realism.
- **`interact_click_count`** site override for popunder-discovery click volume (default content-click count also raised 2 → 3).
- **`clear_sitedata_full_on_reload`** site flag — full storage clear between reloads; quick mode now also clears localStorage/sessionStorage.
- **regex-tool rewritten** as a real `filterRegex` builder/tester: literal↔standard↔JSON conversion, multi-pattern + `regex_and`, and testing against real request URLs (matching mirrors the scanner exactly).
- **Fingerprint coverage**: per-domain-seeded Battery / `navigator.connection` values, `AudioBuffer` fingerprint defeat, `PerformanceNavigationTiming` jitter, `userActivation`; UA strings bumped to Chrome 148 / Firefox 151 / Safari 19.5.

### Changed
- **`userAgent` now defaults to `"chrome"`** when a site doesn't set one — previously sites without it leaked the bundled `HeadlessChrome` UA.
- **`Sec-CH-UA` headers and the curl content-fetch UA derive from the single UA source**, so Client Hints can't drift from `navigator.userAgent`.
- **VPN configs force scan concurrency to 1** — the shared system routing table isn't concurrency-safe.
- **Interaction time ceiling scales with the work envelope** (click count / `realistic_click`) instead of a flat 15s.

### Fixed
- **Per-URL timeout scales** with site timeout/delay/reload (+8s recovery grace) instead of a flat 75s that discarded partial-match recovery on multi-URL scans.
- **Interaction hard cap is now actually enforced** (was cooperative, overshooting to 20s+ under concurrency).
- **WireGuard** inline temp-config leaked the private key on failed connect and broke retries; temp dir is now per-PID so concurrent processes can't wipe each other's config.
- **nettools**: fixed a dig dedup race (concurrent same-domain double lookups); whois no longer discards valid records over non-fatal stderr.
- **Orphan resource leaks** on `Promise.race` timeout (cdp.js, clear_sitedata.js, browserhealth.js) and several un-`unref`'d `setTimeout` handles.
- **Config keys validated at startup** with boolean-like coercion, preventing silent misconfiguration.

### Security
- **OpenVPN** `pkill`/`ping`/`curl` calls moved from shell-interpolated `execSync` to `spawnSync` arg arrays (command-injection).
- **WireGuard/OpenVPN interface & connection names validated** against a strict charset before use in paths/commands.

### Performance
- **adblock**: O(1) exact-domain lookup for `$third-party` / `$first-party` rules.
- Parallelized site-data clearing and window-cleanup checks.
- Removed dead code across cdp, domain-cache, searchstring, compress, adblock-rust, and nettools.

## [3.0.3] - 2026-05-26

### Improved
- **3 DataDome-targeted gaps closed in `lib/fingerprint.js`** (inside `applyFingerprintProtection`, so gated on `siteConfig.fingerprint_protection` like every other spoof in that function):
  - **`Notification.permission` static property** now returns `'default'` (real Chrome's no-granted-permission state). Previously only `Notification.requestPermission()` (the method) was patched; the static property still returned the headless default `'denied'` — a live tell for DataDome and similar detectors that read it directly.
  - **`screen.orientation` interface** is now provided as a stable `{type: 'landscape-primary', angle: 0, addEventListener, lock, unlock, ...}` object when missing. Modern browsers always expose ScreenOrientation; absence is a "real browser?" check signal.
  - **`<html>` `webdriver` DOM attribute** stripped if present. Defensive — modern Puppeteer with `ignoreDefaultArgs: ['--enable-automation']` doesn't emit this, but older driver setups do, and detectors check both `navigator.webdriver` AND `documentElement.getAttribute('webdriver')`. Appended to the existing `'webdriver removal'` safeExecute block so all webdriver cleanup lives together.

  Targeted at sites running DataDome's `ct.captcha-delivery.com/i.js` (and similar fingerprint suites: PerimeterX, Akamai Bot Manager). Most other surfaces these detectors probe were already covered (chrome.app/csi/loadTimes, userAgentData, maxTouchPoints, permissions.query, WebGL UNMASKED_VENDOR/RENDERER, etc.). `scripts/test-stealth.js sannysoft` regression smoke holds at 29 passed / 1 warn / 0 failed (the warn is `CHR_DEBUG_TOOLS`, a CDP-attached signal that's fundamental to Puppeteer and unrelated to these additions). JS-only spoofing can't address TLS fingerprint, HTTP/2 fingerprint, IP reputation, or behavioural analysis — those still depend on proxy choice and `interact` / `ghost-cursor` config.

### Added
- **`scripts/test-stealth.js` now reports warn-row labels** for sannysoft, not just failure-row labels. Previously a cell moving from `passed` → `warn` between runs was invisible (only the count changed), making soft-regression debugging require `--headful`. Now the warn-row table contents print inline so you can see e.g. `warn rows: CHR_DEBUG_TOOLS` directly. Schema additive: result object gains a `warnings: string[]` array alongside the existing `failures: string[]`.
- **`scripts/test-stealth.js` extracts CreepJS's actual current metrics** instead of stale `Trust Score` regex that returned `n/a` for every field. New extracted fields: `fpId` (CreepJS's stable fingerprint hash, lets you A/B before/after a spoof change), `isChromium` (engine identification), `headlessPct` (HARD headless detection score, lower = better), `likeHeadlessPct` (SOFT headless signals), `stealthPct` (spoof-detection probes score, HIGHER = better since it means our spoofs LOOK convincing). Formatter prints all five with directionality hints inline. Excerpt now 40 lines / 2KB (was 15 / 400 bytes) so future UI rotations are debuggable from the output without `--headful`.
- **Additional headless-mode spoofs in `lib/fingerprint.js`** (all inside `applyFingerprintProtection`, gated on `siteConfig.fingerprint_protection`):
  - **`matchMedia` hover/pointer queries**: `(any-hover: hover)`, `(any-hover: none)`, `(any-pointer: fine)`, `(any-pointer: none)`, `(any-pointer: coarse)` plus the legacy non-`any-` aliases. Headless Chrome reports no hover device and no fine pointer (no mouse hardware); detectors probe these as a binary 'real desktop hardware?' signal. Pass-through for all other queries (responsive, color-scheme, reduced-motion, etc.).
  - **`screenLeft` / `screenTop` mirror `screenX` / `screenY`**. Real Chrome exposes these as identical-value legacy aliases; spoofers often leave them undefined or 0, which is inconsistent with the non-zero `screenX/Y` our existing patch produces.
  - **Modern Chrome API stubs**: `document.hasStorageAccess()` → `Promise<true>`, `navigator.userActivation` → `{hasBeenActive: true, isActive: true}`, `navigator.getInstalledRelatedApps()` → `Promise<[]>`. Each gated on absence check so real-Chrome paths skip the override.

  Honest measurement: CreepJS's specific `headless score` did NOT move after these additions (stayed at 67%). My prior estimate of '~-10 to -15 percentage points' was over-optimistic — CreepJS apparently doesn't weight matchMedia hover/pointer heavily in its headless calculation. The additions are still correct spoofs that close real fingerprint gaps and likely help against DataDome / PerimeterX which use different scoring; they're net-positive but score-neutral against CreepJS specifically. The remaining ~67% headless detection is architectural (CDP attachment, software-rasterizer GPU, no real mouse cursor) and can't be lowered without `--headful`.

### Security
- **WebRTC public-IP leak closed** in `lib/fingerprint.js` (`applyFingerprintProtection`). The previous local-IP filter only stripped RFC1918 private ranges (`10.x / 172.16-31.x / 192.168.x`), missing `srflx` (STUN-discovered PUBLIC IP), `prflx`, `relay`, and host candidates with non-RFC1918 addresses (CGNAT 100.64.0.0/10, link-local IPv6, real public IPs on bare-metal hosts). STUN traffic is UDP and **bypasses the SOCKS5 proxy entirely**, so the leaked IP was the real host IP regardless of proxy config — visible to any page that listened on `icecandidate` events. Caught by `test-stealth.js creepjs` which surfaced the candidate string `122.252.155.250 typ srflx` and the corresponding `ip:` field in its WebRTC panel. Fix: strip EVERY ICE candidate; deliver only the null-candidate sentinel (end-of-gathering signal). Side note: the property-based `pc.onicecandidate = fn` setter was also broken (stored handler but never wired it up); now mirrors the same filter as the addEventListener path. Side effect: any site that REQUIRES functional WebRTC peer connections sees ICE gathering produce zero candidates. For nwss.js's scanning use case this is correct.

### Stealth hardening (toString masking)
- **Added 8 session-introduced spoofs to `Function.prototype.toString` bulk masking** (`matchMedia`, `hasStorageAccess`, `getInstalledRelatedApps`, `userActivation` getter, `Notification.permission` getter, `screen.orientation` getter, `screenLeft`/`screenTop` getters). Without this, each new spoof was detectable via `.toString()` returning the override source instead of `[native code]`.
- **Masked per-instance WebRTC `onicecandidate` getter/setter + `addEventListener` wrap.** The bulk-mask block only runs once at injection; per-RTCPeerConnection closures created inside the factory weren't covered. A site doing `Object.getOwnPropertyDescriptor(pc, 'onicecandidate').get.toString()` could see the spoof.
- **Spoofed `navigator.productSub` + `vendorSub`** (UA-aware: `'20030107'` for Chrome/Safari/etc., `'20100101'` for Firefox; `vendorSub` always `''`). Companion legacy properties to the already-spoofed `vendor`/`product`. Common bot-detection signal since anti-detection libraries often spoof UA but forget these. `vendor`/`product` getters also added to the maskAsNative list (pre-existing oversight folded in).

### Fixed
- **`validatePageForInjection`'s 1.5s race timer is now `unref`'d.** Last remaining Node-side `setTimeout` that wasn't unref'd; could hold the event loop alive for up to 1.5s past scan completion. All Node-side timers in `lib/fingerprint.js`, `lib/nettools.js`, and `lib/socks-relay.js` are now unref'd.

### Performance
- **Canvas noise application now cached per `HTMLCanvasElement`** via WeakMap. `toDataURL` and `toBlob` previously did a `getImageData` + `putImageData` round-trip on every call (~500k iterations for size-capped canvases) to bake noise into the export. Now the round-trip runs once per canvas; subsequent exports skip it (the canvas backing store still has the noised pixels from the first call). Trade-off: animated canvases that redraw between exports won't have new content re-noised — acceptable for the common fingerprinter pattern (single probe → single toDataURL).

## [3.0.2] - 2026-05-25

### Security
- **Credentials redacted in `lib/proxy.js` 'Invalid proxy URL' warn** — `getProxyArgs` echoed the raw user-configured `proxyUrl` when parseProxyUrl returned null. For a URL like `socks5://user:pass@host:port` that fails parse (mistyped protocol, port out of range, etc.) this emitted the full credentials to stderr. Regex-strips the `user:pass@` segment (handles both scheme-prefixed and bare host:port forms) before logging. Same redaction policy as `getProxyInfo()` and the socks-relay logs already fixed in 3.0.1. The new port-range validation in this release expanded the trigger surface (one more parse-failure path) which made me find the leak.
- **`applyProxyAuth` debug log redacted** — the `Auth set for USER@host:port` debug-only log line emitted the raw username. Now `[redacted]@host:port`. Same leak class as above, third site of the same kind.

### Added
- **`scripts/test-stealth.js --format=json`** (already shipped in 3.0.1, listed here only because the harness gained a real consumer via the next item) — `getRelayStats()` exposed from `lib/socks-relay.js`, returning `[{key, port, activeConnections, errors}]` per active relay (`key` with the username segment stripped for safety, IPv6-aware). Diagnostic surface for answering "is the proxy slow because the upstream is saturated or because the scan is opening too many parallel tunnels?" without enabling `forceDebug`.
- **`delay_uncapped: true` site-config flag** — lifts the 2s post-networkidle delay cap; honors the configured `delay` up to half the per-URL timeout. Targets sites with setTimeout-deferred lazy ad/tracker loaders (weather.com / cbssports.com class) where late requests fire well past the standard window. Default behavior unchanged (still 2s) so fast sites stay fast.

### Fixed
- **Race: late-completing dig/whois validations were orphaned.** Per-URL async nettools handlers were scheduled via fire-and-forget `setImmediate(() => netToolsHandler(...))`; if the handler's full async chain (dig spawn + match check + addMatchedDomain) resolved AFTER the result snapshot ran, the addMatchedDomain call landed in a Set that was no longer referenced by any in-flight result. Most visible symptom: domains appearing in the end-of-scan "Fresh dig:" list with no corresponding rule in the output. Now tracked via `trackNetToolsHandler` (closure over per-URL `pendingNetTools[]`) and drained via `drainPendingNetTools()` with a 3s hard cap (`TIMEOUTS.NETTOOLS_DRAIN_TIMEOUT`), called BEFORE `formatRules` at all three snapshot sites (dry-run, success, partial-success/catch path). All three setImmediate call sites (popup observer, main request handler, secondary request handler) migrated.
- **Race: scan-exit hang up to ~100s when a dig/whois lookup hung.** Four `setTimeout`s in `lib/nettools.js` (outer exec timer, overall 65s timer, whois progressive retry delay up to ~30s, whois server-switch delay ~8s) were not `unref`'d, so a genuinely-hung lookup that survived the new 3s drain could hold the Node event loop alive for the remainder. All four now `unref`'d with defensive `typeof timer.unref === 'function'` guards; the previously-unref'd inner SIGKILL tail-timer makes 5/5 setTimeout sites in the module now safe for scan-exit. Natural-completion paths still `clearTimeout` on resolution, so this only affects the hung-process case.
- **`parseProxyUrl` accepted ports > 65535.** Now rejects ports outside 1-65535 at parse time, surfacing misconfiguration immediately instead of passing an invalid value to Chromium and getting an opaque downstream error.
- **`@version 1.1.0` JSDoc** in `lib/proxy.js` was stale (const said `1.2.0`). Aligned to 1.2.0; the const + export then went away in the export trim — see Improved.
- **Site-config `delay` field was a no-op.** `nwss.js` per-URL handler hardcoded `const delayMs = DEFAULT_DELAY` regardless of `siteConfig.delay`. Now reads `siteConfig.delay || DEFAULT_DELAY`. Visible only with the new `delay_uncapped: true` flag (without it, the configured value is still capped at 2s as before).
- **"Something went wrong when opening your profile" popup in `--keep-open` headful mode.** `--disable-sync` was conditionally dropped when `--keep-open` was set, which let Chrome's sync subsystem initialise against our temp `userDataDir` (which has no real profile), error out, and pop a modal that blocked the page until dismissed. Three-flag fix: `--disable-sync` is now always-on (was the only one of five `--keep-open`-conditional flags actually causing user-visible breakage), plus `--allow-browser-signin=false` and `AccountConsistencyMirror,AccountConsistencyDice` appended to the existing `--disable-features=` list as defence in depth across Chromium's multiple account-subsystem entry points. The other four conditional-on-keep-open flags (`--disable-component-extensions-with-background-pages`, `--disable-component-update`, `--disable-background-networking`, `--disable-extensions`) stay conditional so user-loaded extensions and live inspection still work normally.
- **Race: `socks-relay.ensureRelay` concurrent-init created orphan servers.** Two concurrent callers for the same upstream both passed the `_relays.get(key)` check, both created `net.Server` listeners, both raced to `_relays.set` — second overwrote first, first server was orphaned (listening forever, never closed by `closeAllRelays`). Not triggered by current usage (proxy.js's `prepareSocksRelays` uses a sequential await loop) but a latent bug for future parallel-init paths. Fix: singleflight via new `_pendingRelays` Map; second caller for an in-flight upstream rides the existing promise. Cleanup uses `.finally()` on the returned promise (not try/finally inside the IIFE) so a hypothetical sync-throw in the init body can't leave a permanent rejected entry in `_pendingRelays`. Mirrors the `pendingDigLookups`/`pendingWhoisLookups` pattern in `lib/nettools.js`.
- **Race: handshake watchdog firing during upstream connect orphaned the upstream socket.** `HANDSHAKE_TIMEOUT_MS = 10000` vs `SocksClient.createConnection` timeout = `20000` left a 10-second window where the watchdog could fire mid-await, destroy the client, and set `settled = true`. When the upstream connect then resolved into a fresh socket, the subsequent `cleanup()` short-circuited via the settled guard, leaving an open TCP connection to the upstream that was never destroyed — held alive until OS-level timeout or remote close. Fix: disarm the watchdog at the `phase = 'connecting'` transition (client has completed its part of the handshake; `SocksClient`'s own 20s timeout covers the upstream connect), plus a defence-in-depth `if (settled) destroy + return` after `upstreamSock = info.socket` for any other path that could call cleanup before upstreamSock registers.
- **Race: `closeAllRelays` didn't wait for in-flight `ensureRelay` inits.** A relay whose `listen()` completed AFTER `closeAllRelays` snapshotted `_relays` landed in `_relays` unowned by the close pass — leaked until next call or process exit. Pre-existing, more visible after `_pendingRelays` became a separate Map for the singleflight. Fix: `await Promise.allSettled(Array.from(_pendingRelays.values()))` at the head of `closeAllRelays` so the snapshot is guaranteed-complete. `allSettled` (not `all`) because rejected inits have already cleaned up their `_pendingRelays` entries via `.finally()`.

### Improved
- **socks-relay handshake buffer cap** (`MAX_HANDSHAKE_BYTES = 4096`) on pre-piping growth. Prior code absorbed arbitrary bytes for the full 10s handshake watchdog window, letting a hostile/buggy local process pin memory by drip-feeding garbage. Sends a protocol-appropriate failure reply per phase before closing.
- **socks-relay TCP keep-alive on upstream socket** (`setKeepAlive(true, 60000)`). Catches silently-dead upstreams (NAT timeout, mobile-tower drop, proxy crash without FIN/RST) in ~12 minutes (60s idle + kernel-default 9 × 75s probes) instead of the Linux default ~2 hours. Comment is honest about the kernel-default probe math — `60000` is `TCP_KEEPIDLE` only, not the full detection time.
- **socks-relay auth-misconfig warn** — `ensureRelay` warns once per unique upstream when `username && !password`, since RFC 1929 auth will almost certainly fail. Surfaces the misconfiguration at relay start instead of as opaque per-request failures inside `forceDebug`-gated logs.
- **socks-relay `server.maxConnections = 256` cap** per relay. Sheds excess Chromium connections at the TCP-accept layer (where HTTP retry handles them cleanly) instead of letting all N tunnels open to the upstream and have the provider silently drop past-quota ones — which looks to the scan like random missed requests.
- **socks-relay per-relay error counter** tracked in `relayEntry.errors`, bumped on `SocksClient.createConnection` failures, surfaced via `getRelayStats()` as the `errors` field. Lets a post-scan reader see "X of N upstream connects failed" without re-running with forceDebug.
- **socks-relay graceful drain on `closeAllRelays`** — `DRAIN_TIMEOUT_MS = 2000` window via `Promise.race(closePromise, drainTimeout)` for in-flight tunnels to flush their last response bytes into Chromium / Puppeteer. Stragglers past 2s get force-destroyed (server.close callback then fires immediately). SIGINT mid-scan no longer amputates in-flight responses, but a hung tunnel can't block exit beyond 2s. Drain timer `unref`'d so it doesn't hold the event loop open when the close-promise wins the race.
- **`lib/proxy.js` exports trimmed 12 → 8** — removed `getModuleInfo`, `PROXY_MODULE_VERSION`, `SUPPORTED_PROTOCOLS`, `getConfiguredProxy` (zero external callers in each case, grep-verified). Mirrors the same trim already done in `lib/cloudflare.js`. `SUPPORTED_PROTOCOLS` and `getConfiguredProxy` stay as module-local since they're used internally.
- **`lib/proxy.js` code cleanup** — two `require('./socks-relay')` calls consolidated into one destructured import (with `closeAllRelays` renamed inline), `net` module require hoisted from `testProxy()` body to top of file, `applyProxyAuth` JSDoc enumerates the 5 distinct `false` return scenarios (caller treating false as "auth failed" would incorrectly retry on the SOCKS5 → relay handles it case).

### CI
- **GitHub Release names now include date suffix** (`v3.0.2 (YYYY-MM-DD)`), matching the convention used by the backfilled v2.0.10 through v2.0.66 releases. Auto-applied via the already-computed `steps.version.outputs.date` in `softprops/action-gh-release`.

## [3.0.1] - 2026-05-24

### Security
- **Proxy credentials redacted in debug logs** — `lib/proxy.js` `getProxyInfo()` now replaces the `username:password@` segment with `[redacted]@` before logging; `lib/socks-relay.js` strips the username from both the relay-startup log (`auth: [redacted]` / `no auth`) and the close log (regex-trims the `:username` suffix from the relay key, IPv6-safe). Prior output exposed SOCKS5 credentials to anyone the user shared a debug dump, screenshot, or support ticket with.

### Added
- `scripts/test-stealth.js` — stealth smoke-test harness. Launches Puppeteer with `applyAllFingerprintSpoofing` applied and reports what bot.sannysoft.com / creepjs / browserleaks.com/javascript concluded. Flags: `--headful`, `--no-spoof` (baseline), `--ua=<family>` (validated against `USER_AGENT_COLLECTIONS`), `--format=json` (stable schema for diff/jq A/B), `--help`, positional target filtering. `PUPPETEER_NO_SANDBOX=1` env-var opt-in for CI/root containers (sandbox is on by default). Caught 3 real bugs that 5 rounds of static review missed.
- `USER_AGENT_COLLECTIONS` exported from `lib/fingerprint.js` — single source of truth for valid UA families, consumed by the test harness so the list isn't duplicated.

### Fixed
- **Puppeteer 25 compatibility** — `browser.isConnected()` (removed in Puppeteer 25 per [puppeteer#14910](https://github.com/puppeteer/puppeteer/pull/14910)) replaced with the `browser.connected` property at 14 call sites across 6 files. Compatible with both Puppeteer 24 and 25.
- **Fingerprint own-goal — PHANTOM_PROPERTIES + SELENIUM_DRIVER** — spoofing did `delete window[prop]` followed by `defineProperty(prop, { get: () => undefined })`. The undefined-returning getters left the properties detectable via the `in` operator, defeating the delete. Now only deletes. (caught by `scripts/test-stealth.js` sannysoft)
- **`navigator.plugins instanceof PluginArray` failed** — the spoof returned a plain array. Now `Object.setPrototypeOf(pluginsArray, PluginArray.prototype)` with fallback to `Object.getPrototypeOf(navigator.plugins)` for environments where `PluginArray` isn't a global.
- **`navigator.plugins[0].toString() === '[object Plugin]'` failed** — plain plugin objects returned `[object Object]`. Each plugin now wraps via `Object.create(Plugin.prototype)` with `Symbol.toStringTag` fallback.
- **`window.chrome` descriptor was a fingerprinting tell** — had `writable: false, enumerable: false`; real Chrome has both `true`. Aligned.
- **`_fingerprintCache` cross-UA poisoning** — was keyed by domain only, so the same domain visited under a different UA returned cached values from the wrong OS. Now keyed by `${domain}|${userAgent}`.
- **7 broken regex patterns** in the fingerprint error-suppression list — double backslashes (`\\.X`) parsed as literal-backslash + wildcard and never matched real errors. All 7 repaired.
- Constructor `.name` / `.length` preserved through 5 wrapper sites (Error, Image, RTCPeerConnection, PointerEvent, WheelEvent) — wrapped ctors had `.name = ''` and `.length = 0`, a fingerprinting tell.
- `Error` static properties (`stackTraceLimit`, `captureStackTrace`, `prepareStackTrace`) forward to the OriginalError via live getter/setter instead of snapshot-copy (snapshot diverged once any caller mutated the wrapped Error).
- `navigator.connection` fallback returns a closure-captured stable object — was re-allocating per call, so object identity changed every access.
- `chrome.runtime.getManifest()` derives version from the spoofed UA instead of returning a hardcoded older version.

### Improved
- `isBrowserDead` helper extracted — deduped 3 spoof sites that hand-rolled the same `isConnected`/`closed` check.
- `preserveCtorIdentity` helper added — applied at the 5 wrapper sites above.
- GPU pool seeded by `domain + ':gpu'` (was just `domain`) — keeps per-domain GPU stable while decoupling it from any other per-domain seed we might add.
- 10 dead module-level exports trimmed from `lib/fingerprint.js`.
- `safeDefinePropertyLocal` forces `configurable: true` instead of merging it from the caller's descriptor (caller-side opt-in was unreliable).

## [3.0.0] - 2026-05-23

### Changed
- **Engines floor bumped**: `engines.node` from `>=22.0.0` to `>=22.12.0` to match Puppeteer 25's stable `require()`-of-ESM requirement. Anyone running on Node 22.0–22.11 will see an npm engine warning and should upgrade.
- **Puppeteer dependency floor bumped**: `puppeteer` and `puppeteer-core` from `>=20.0.0` to `>=24.0.0`. Range still permits both v24 and v25 — pick via `npm install puppeteer@24` or `npm install puppeteer@25` according to taste. Dev lockfile moved to `puppeteer@25.0.4`.
- Audit confirms no breaking-change impact from Puppeteer 25's `executablePath`/`defaultArgs` Promise return — neither is called in this codebase. `require('puppeteer')` continues to work on the now-ESM-only package thanks to Node 22.12+'s stable require-of-ESM.

### Added
- `blockDomainsByUrl` config key (top-level) — regex patterns mirroring `ignoreDomainsByUrl` but for active blocking. A matching request URL triggers Puppeteer `request.abort()` on the triggering request, the request's root domain, and all subsequent requests to that domain or its subdomains for the rest of the scan
- Cloudflare aggregate stats accessible via `getAggregateStats({reset})` — returns `byOutcome`, `bySolveMethod`, `maxDurationMs`, `avgDurationMs`, `failures`, `timedOut` counts; bumped on every URL regardless of debug mode
- Cloudflare per-stage timing breakdown in outcome lines: `q=Xms p=Xms c=Xms` (zero-stage suffixes omitted)
- Production-level Cloudflare outcome logs: `warn` severity for `!overallSuccess || timedOut`, `info` for 5xx origin-error pages, debug-only on success
- DNS pre-check positive-resolution shortcut — hosts already proven live by dig or whois within the cache TTL skip the c-ares pre-check via a `knownResolvedHostnames` index (also warmed at startup from disk-loaded dig/whois caches)
- DNS pre-check skip summary now reports both NXDOMAIN-cache and positive-cache savings: `DNS pre-check skipped: N URL(s) via M unresolvable host(s), N URL(s) via M resolved host(s)`
- `[blocked-stats]` per-pattern hit counters reported at scan end — surfaces which `blocked` patterns are doing work vs. which are stale
- `disable_adblock` per-site config flag to escape global ad-blocking layers
- `capture_popups` now runs whois/dig validation on matched popup URLs
- `lib/spawn-async.js` shared async-spawn helper module — consolidates 4 near-identical Promise wrappers across curl/grep/searchstring

### Fixed
- **Security**: nettools shell-injection vector closed — `exec(string)` replaced with `execFile(cmd, args)` (no shell); config-supplied `whois_server` and `recordType` values can no longer execute commands via `$()`/backticks/etc.
- Cloudflare `detectChallengeLoop` off-by-one bug — counted the current URL against itself, tripping `>= 2` threshold one iteration early
- Cloudflare `detectChallengeLoop` threshold was unreachable with default `cloudflare_max_retries = 2`; new exact-match path catches reload-to-same-URL loops at attempt 2
- Cloudflare outcome cache namespace collision — now stored in a separate Map (was sharing keys with the detection cache, getting evicted by detection-cache pressure)
- `ignoreDomains` dynamic Set didn't cascade to subdomains — `ignoreDomainsByUrl` dynamic adds now apply parent-walk just like static config (e.g. dynamically-ignored `example.com` now also catches `cdn.example.com`)
- `blocked` / `blockDomainsByUrl` / `ignoreDomainsByUrl` regex compile failures unified — was silent-drop for *byUrl and hard-throw for blocked; now all warn loudly with `[config] X pattern dropped (compile error): "..." -- regex msg` and continue
- adblock pattern-cache key mismatch — anchored patterns (`||example.com`) were missing their own cache because get/set used different keys
- grep AND-logic silently dropped non-matching rules; ENOBUFS silently truncated output on large pages
- Cloudflare debug logs rendered literal `"undefined"` when detection short-circuited on non-HTTP pages (popup → about:blank case)
- Outcome label `no_indicators` was lying when detection short-circuited on non-HTTP page URL; now correctly reports `skipped(non-http)`
- Cloudflare `handleLegacyCheckbox` selector list aligned with detection — dropped orphan `.cf-turnstile input[type="checkbox"]` selector that had no matching detection entry
- Cloudflare `safeWaitForNavigation` warn was unconditional; now `forceDebug`-gated (was spamming stderr on phishing-bypass nav failures in production)
- Cloudflare `enhancedParallelChallengeDetection` had zero callers — deleted
- `analyzeCloudflareChallenge` ignored managed-challenge signals (`.cf-managed-challenge`, `[data-cf-managed]`); now folded into `isChallengePresent`
- `isChallengeCompleted` double-queried the same DOM element; cached once
- Various correctness fixes across compare (inline hosts-comment stripping), curl, dry-run, flowproxy (error-path bug, cookie parsing), referrer, searchstring, validate_rules modules
- 30+ dead exports trimmed across nettools (11), cloudflare (18 → then re-trimmed after refactor), adblock, adblock-rust, compare, dry-run

### Improved
- Dig/whois cache TTL 14h → 20h, capacity 1000 → 2000 entries each — covers overnight scan-then-rescan cadence without forcing fresh lookups
- nettools disk-cache writes now atomic (tmp + rename) — surviving SIGKILL/OOM/power-loss mid-write no longer leaves a truncated file that wipes the cache on next load
- Corrupt `.digcache`/`.whoiscache` files surface a `[dns-cache] X was unreadable (...); starting fresh` warn instead of silently resetting
- `dnsCacheStats.freshDig`/`freshWhois` arrays capped at 1000 entries (FIFO) — no more unbounded growth on scans with thousands of unique fresh lookups
- nettools `enableDiskCache` made idempotent (uses the previously-dead `diskCacheEnabled` flag); also warms the resolved-hostnames index from loaded entries
- 200+ log sites unified through `formatLogMessage` + subsystem tags across cloudflare, adblock, adblock-rust, compare, ignore_similar, validate_rules, wireguard_vpn, dry-run, smart-cache, flowproxy, browserexit, redirect, post-processing, cdp, output, interaction modules
- Cloudflare `runWithRetries` helper extracted — verification-challenge and phishing-warning retry harnesses collapsed from ~150 lines of duplication to thin hook-driven wrappers
- Cloudflare 14-line debug block in `handleVerificationChallenge` collapsed to one structured line: `Challenge detected: turnstile=t js=f ... title="..."`
- Cloudflare timing constants pruned (4 dead, 1 dead local var); `waitForTimeout(page, ms)` renamed to `fastTimeout(ms)`, unused `page` arg dropped
- Cloudflare `attemptChallengeSolve` post-failure diagnostic + `JS challenge` body.textContent now capped (2KB) per poll — was materializing MB on content-heavy pages
- adblock-rust: zero-copy deserialize, eager buffer release, FIFOCache rename for honest naming
- `interaction.js` performance: ~350ms saved per no-click interaction, ~750ms per with-click
- nwss per-URL timeout 120s → 75s for faster hang recovery
- Popup handler honors both `ignoreDomainsByUrl` and `blockDomainsByUrl`
- Early `ignoreDomains` gate added at main request handler — skips dig/whois/regex cycles on ignored hostnames
- `--dns-cache` help text refreshed (was stale "3hr/4hr TTL"; now "20h TTL, 2000-entry cap each")

## [2.0.66] - 2026-05-20

### Added
- DNS pre-check before `page.goto()` to skip unresolvable hosts fast — `--no-dns-precheck` to disable
- In-process SOCKS5 auth relay so `socks5://user:pass@host` URLs work end-to-end
- socks-relay handshake-phase watchdog so stalled clients can't sit forever
- DNS pre-check EAI_AGAIN retry-once + FIFO cap on negative cache

### Fixed
- proxy.js: SOCKS auth false-success + SOCKS4 remote-DNS footgun
- DNS pre-check was starving under scan load (`dns.lookup` queued behind Puppeteer's libuv threadpool); switched to `dns.resolve` (c-ares, no threadpool contention)
- DNS pre-check: clear the timeout timer when lookup wins the race
- Bumped `ws` override to >=8.20.1 (CVE-2026-45736, GHSA-58qx-3vcg-4xpx)

### Improved
- Neutralize Fullscreen API so sites can't hijack the window in `--headful` mode
- socks-relay: disable Nagle + reject unoffered no-auth selection

## [2.0.65] - 2026-05-15

### Added
- Cloudflare 5xx origin-error page detection — recognizes `<domain> | 5xx: <reason>` titles, marks as `error_page(522)` etc. instead of treating as a bypass target
- Per-URL Cloudflare outcome summary log with cookie state + error-code signal
- HTTP status + cf-ray captured at `page.goto()` time and threaded through to the Cloudflare outcome line
- Surface Cloudflare 5xx origin-error page count in scan stats
- HANG CHECK: per-URL progress counter + per-URL timeout + short-circuit queued URLs on restart flag
- Surface adblock-rust engine stats in debug exit output

### Fixed
- HANG CHECK detection logic was debug-gated and never fired in production
- `--validate-config` TDZ crash by moving block below config load
- Scan-exit hang: cleanups now run on normal completion (was relying on `process.exit(0)` to skip them)
- nettools: pending-lookup leak + signal-handler conflict with nwss.js cleanup
- cloudflare: null-safe error categorization, unref'd cache timer, body.textContent reuse
- Suppressed contradictory "no indicators / error page detected" log pair

### Improved
- cloudflare: precompile skip-proto regex, combine within-category selectors, rename outcome key
- redirect.js: skip `detectCommonJSRedirects` in production, cap `outerHTML`, filter `chrome-error://`
- Cloudflare module banner + "no indicators" log deduped (was firing once per URL)
- npm update: adblock-rs, lru-cache, puppeteer patch bumps
- Removed dead `scanner-script-org.js` prototype

## [2.0.64] - 2026-05-02

### Added
- `--adblock-engine=rust` option using Brave's adblock-rs (faster on large filter lists; requires `npm install adblock-rs`)
- Cache hygiene: atomic write, version key, 30-day prune, JSDoc

### Fixed
- adblock-rs always returning `no_match` (4th arg to `engine.check` was missing — caused silent total-block-failure)
- Drop existsSync before readFileSync in cache load path (avoids redundant stat + TOCTOU)

### Improved
- Reduce wrapper memory: zero-copy deserialize, eager buffer release
- Bumped `engines.node` floor to >=22
- npm update: `p-limit` 4.0 → 7.x (ESM API unchanged), `lru-cache` 10.4 → 11.3 (drop-in), `globals` 16.5 → 17.6 (dev-dep), `eslint` patch bump
- V8 micro-opts in adblock-rs hot path (null-proto resource-type map, bound engine.check)

## [2.0.63] - 2026-04-25

### Added
- `ignoreDomainsByUrl` config (top-level) — regex patterns; if any request URL matches, the request's root domain is dynamically ignored for the rest of the scan
- Redirect source and matching regex now included in `adblock_rules` log titles

### Fixed
- Positional `.json` arg was ignored by config loader (always defaulted to `config.json`)
- ReferenceError on `allowedResourceTypes` in debug log
- ReferenceError on `matchedRegexPattern` in even_blocked path

### Improved
- Convert resourceTypes filter to Set for O(1) lookups in hot path
- Sample `config.json` filterRegex values updated

## [2.0.62] - 2026-04-25

### Fixed
- TypeError in `SmartCache.getStats` when `requestCache` fails to initialize

## [2.0.61] - 2026-03-17

### Added
- `.nwssconfig` file for per-config-file CLI settings — define output, concurrency, flags per JSON config
- `--no-color` / `--no-colour` flag to disable colors (colors now enabled by default)
- Navigation timeout fallback — retries with `waitUntil: networkidle2` on timeout, 10s cap
- Skip domains after 3 consecutive timeouts in the same scan to avoid wasting time on down sites
- Fingerprint cache capped at 500 entries with LRU eviction

### Fixed
- `chrome-error://` popup redirects no longer throw errors — continue processing captured requests
- Suppressed noisy `about:blank` and `chrome-error://` redirect warnings (visible with `--debug` only)
- Fallback retry skipped for `chrome-error://` redirects (instant failure, not genuine timeout)
- Page URL checked before fallback retry to detect already-failed state
- `.nwssconfig` keys support both hyphens and underscores (`dns-cache` and `dns_cache` both work)

### Improved
- Colors enabled by default — no need for `--color` flag or `color: true` in `.nwssconfig`
- Chrome UA bumped to 146, Firefox UA bumped to 148
- Sec-CH-UA headers updated to match Chrome 146

## [2.0.60] - 2026-03-16

### Added
- `--dns-cache` flag for persistent dig/whois disk caching between runs (`.digcache`, `.whoiscache`)
- `--load-extension <path>` flag to load unpacked Chrome extensions (supports multiple)
- `--block-ads` now supports comma-separated list files (`--block-ads=easylist.txt,easyprivacy.txt`)
- `disable_ad_tagging` config option to control Chrome AdTagging (default: true)
- DNS cache hit/miss statistics in scan summary output with fresh domain names listed
- Concurrent dig/whois deduplication — multiple pages requesting the same domain share one lookup
- SIGINT/SIGTERM handlers for `--keep-open` to prevent orphaned Chrome processes

### Fixed
- Adblock pipe (`|`) character handling — mid-pattern pipes were incorrectly treated as anchors, causing broad false positives on EasyList rules like `/addyn|*|adtech;`
- Domain Map fast path was skipping resource type checks — `$ping`, `$script` etc. now correctly enforced
- Domain extraction for `||domain.com/path` rules — path was incorrectly included in domain name
- `--keep-open` now skips extension-blocking Chrome flags so Chrome Web Store and extensions work
- Corrupt disk cache files are deleted instead of persisted
- `getBaseDomain()` now uses `psl` for correct multi-part TLD handling (`.co.uk`, `.com.au`)
- Merged 7 separate `--disable-features` flags into one — Chrome only reads the last occurrence

### Improved
- `$document` rules treated as full domain blocks (matches all resource types)
- `adblock.js`: regex cache for compiled patterns, Set for resource type lookups, lazy parentDomains, two-level result cache with LRU eviction (32K), hoisted constants, freed parsed options after rule parsing
- `output.js`: capped wildcard regex cache at 500, simplified `*.domain.com` suffix matching, hoisted resource type map
- `compare.js`: pre-compiled and deduplicated 6 normalization regexes
- `grep.js`: build grep args once outside pattern loop
- `domain-cache.js`: use Set iterator for eviction instead of full array copy
- `nettools.js`: hoisted ANSI strip regex, disk cache flushes once on exit instead of per-lookup
- Dig/whois cache: 14-hour TTL, 1000 entry limit, pretty-printed JSON files

## [2.0.59] - 2026-03-15

### Added
- `--keep-open` flag to keep browser and all tabs open after scan completes (use with `--headful` for debugging)
- `--use-puppeteer-core` flag to use `puppeteer-core` with system Chrome instead of bundled Chromium
- `puppeteer-core` as optional dependency in package.json
- Ghost-cursor integration for Bezier-based mouse movements (`--ghost-cursor` flag)
- Help text entries for `--keep-open`, `--use-puppeteer-core`

### Fixed
- Simulated mouse events now include `pageX`/`pageY`/`screenX`/`screenY` properties — scripts reading `event.pageX`/`pageY` for bot detection (e.g. dkitac.js) previously saw zero movement
- Stale comment reference to removed function
- CDP timeout leaks and dead code in `cdp.js`

### Improved
- Mouse interaction runs concurrently with post-load delay for better performance
- `maxTouchPoints` hardcoded to 0 for desktop Linux Chrome consistency

## [2.0.58] - 2026-03-14

### Fixed
- Race condition: re-check `isProcessing` before `page.close()` in realtime cleanup
- Page tracker stale entries during concurrent execution (added `untrackPage()`)
- ElementHandle leak in `interaction.js` — dispose body handle in `finally` block

### Improved
- macOS compatibility: add Chrome path detection and use `os.tmpdir()` for cross-platform temp dirs
- Harden `interaction.js` with page lifecycle checks to prevent mid-close errors
- Fingerprint interaction-gated trigger with scroll/keydown events and readyState check
- Low-impact optimisations across 6 modules (grep, flowproxy, dry-run, adblock, interaction, openvpn_vpn)
- Remove redundant `fs.existsSync()` guards in openvpn_vpn.js, compress.js, compare.js, validate_rules.js, output.js
- Hoist regex constants in `validate_rules.js`, cache wildcard regex in `output.js`
- Optimise `browserexit.js`: replace shell spawns with native fs operations
- Deduplicate session-closed error checks in `fingerprint.js`
- Remove dead code (`performMinimalInteraction`, unused `filteredArgs`)
- Migrate `.clauderc` to `CLAUDE.md`

## [2.0.57] - 2026-03-14

### Improved
- Optimise `ignore_similar.js`

## [2.0.56] - 2026-03-13

### Fixed
- Cloudflare challenge/solver scanning issues
- Browser health monitoring improvements

### Improved
- Cloudflare detection reliability and performance
- Chrome/Puppeteer performance tuning
- Smart cache optimisations in `smart-cache.js`
- Post-processing optimisations

## [2.0.55] - 2026-03-12

### Fixed
- Browser cleanup missing `com.google.Chrome` temp files
- Interaction.js reload interaction issues

### Improved
- Fingerprint.js improvements
- Interaction.js cleanup

## [2.0.54] - 2026-03-11

### Improved
- WebGL fingerprinting improvements, revert to `--disable-gpu`
- Reduce DIG and Whois request volume with domain caching
- Update user agents

## [2.0.53] - 2026-03-10

### Fixed
- Headless/GPU crash issues
- Fingerprint protection hardening

### Added
- Screenshot support using `force` option

### Improved
- Fingerprint protection improvements

## [2.0.52] - 2026-03-10

### Fixed
- Headless/GPU crash and fingerprint improvements

## [2.0.51] - 2026-02-24

### Added
- SOCKS/HTTP/HTTPS proxy support (`proxy.js`)

### Improved
- Update packages
- Compatibility improvements

## [2.0.50] - 2026-02-17

### Fixed
- Fingerprint `random` mode improvements
- CDP round-trips reduced to 1, cache bodyText
- `safeClick`/`safeWaitForNavigation` timeout leaks
- Redundant context validation removed
- Shadowroot compatibility on `cloudflare.js`

### Improved
- `interact: true` performance
- Canvas noise optimisation for large canvases
- Fingerprint consistency fixes (mousemove WeakMap, human simulation timing)
- `measureText` read-only property fix
- Support for larger lists
- `ignoreDomains` improvements
- Hot path performance optimisations (indexed loops, single-pass regex matching, URL parsing)
- Adblock domain matcher precomputation

## [2.0.49] - 2026-02-17

### Improved
- Fingerprint protection `random` mode enhancements

## [2.0.48] - 2026-02-17

### Improved
- Adblock rule parser: V8 optimisations, cached hostname split, Map-based lookups
- Precompute parent domains for whitelist and block checks
- Remove dead code in `grep.js`

## [2.0.47] - 2026-02-17

### Added
- Support for `$counter` adblock rules
- Support for `$1p`, `$~third-party`, `$first-party` adblock options

### Fixed
- Missing variable fix
- More adblock rule format support

## [2.0.46] - 2026-02-16

### Fixed
- Potential memory leaks
- Timing range miscalculation
- `TEXT_PREVIEW_LENGTH` unreachable inside `page.evaluate()`
- Unused variables cleanup

### Improved
- Processing termination to avoid stale processes

## [2.0.45] - 2026-02-16

### Improved
- Processing termination reliability

## [2.0.44] - 2026-02-16

### Added
- OpenVPN support (`openvpn_vpn.js`) — [#45](https://github.com/ryanbr/network-scanner/issues/45)

## [2.0.43] - 2026-02-16

### Added
- Initial WireGuard VPN support (`wireguard_vpn.js`) — [#45](https://github.com/ryanbr/network-scanner/issues/45)

## [2.0.42] - 2026-02-16

### Fixed
- `maxTouchPoints` potentially overridden twice
- Duplicate `console.error` overrides in fingerprint
- `hardwareConcurrency` returning different values on every read
- Brave UA getter infinite recursion

### Improved
- General cleanups and unused function removal

## [2.0.41] - 2026-02-16

### Fixed
- Binary issue with `smart-cache.js`

## [2.0.40] - 2026-02-16

### Fixed
- Missing `requestCache` in smart-cache clear/destroy
- Duplicate `totalCacheEntries` in `getStats`
- Undefined `forceDebug` reference in `cacheRequest`
- Missing `normalizedUrl` declaration in `cacheRequest`

## [2.0.39] - 2026-02-16

### Improved
- Nettools: buffered log writer instead of `fs.appendFileSync`

## [2.0.38] - 2026-02-16

### Fixed
- Catch-and-rethrow doing nothing in nettools
- Double timeout in `createNetToolsHandler`

### Improved
- Replace global whois server index with module-level variable
- Hoist `execSync` and move `tldServers` to module scope

## [2.0.37] - 2026-02-16

### Improved
- Browser health: store timestamp in page creation tracker
- Cleanup `formatMemory` redefinition
- Hoist `require('child_process')` in `checkBrowserMemory`
- Replace `Page.prototype` monkey-patch with explicit tracker cleanup

## [2.0.36] - 2026-02-16

### Improved
- `browserexit.js`: remove duplicate pattern, hoist requires

## [2.0.35] - 2026-02-16

### Improved
- Buffer log writes, pre-compile regexes, deduplicate request handler

## [2.0.34] - 2026-02-16

### Improved
- General cleanup

## [2.0.33] - 2025-11-14

### Added
- Adblock list support for blocking URLs during scanning
- V8 optimised adblock parser with LRU cache and Map-based domain lookups

### Improved
- Bump Firefox user agent
- Rename `adblock_rules.js` to `adblock.js`

## [2.0.32] - 2025-11-08

### Fixed
- Race conditions: atomic `checkAndMark()` in domain cache
- Performance improvements and V8 optimisations

### Improved
- `referrer.js` V8 optimisations
- Update packages

## [2.0.31] - 2025-10-31

### Added
- `referrer_disable` support
- `referrer_headers` support

### Fixed
- `url is not defined` errors
- Referrer.js incorrectly added to nwss.js
- Page state checks before reload, network idle, CSS blocking evaluation

### Improved
- `grep.js` improvements

## [2.0.30] - 2025-10-29

### Added
- Location URL masking
- Additional automation property hiding

### Improved
- Font enumeration protection
- Fingerprint platform matching
- Bump Chrome to 142.x

## [2.0.29] - 2025-10-21

### Improved
- Hang check loop and browser restart on hang
- Chrome launch arguments
- Permissions API fingerprinting
- Realistic Chrome browser behaviour simulation
- Chrome runtime simulation strengthening

## [2.0.28] - 2025-10-11

### Improved
- Page method caching optimisations
- Consistent return objects in health checks
- CDP.js V8 optimisations
- Bump overall timeout from 30s to 65s
- Nettools optimisations

## [2.0.27] - 2025-10-07

### Improved
- Whois retry on TIMEOUT/FAIL to avoid throttling

## [2.0.26] - 2025-10-06

### Improved
- V8 optimisations: `Object.freeze()`, destructuring, pre-allocated arrays, Maps
- Bump Chrome version

## [2.0.25] - 2025-10-05

### Fixed
- Frame handling `frameUrl is not defined` errors
- `activeFrames.add is not a function`
- `spoofNavigatorProperties is not defined`

### Improved
- Frame URL improvements
- Allow grep without curl

## [2.0.24] - 2025-10-04

### Improved
- Fingerprint.js V8 performance: pre-compiled mocks, monomorphic object shapes, cached descriptors
- Address [#41](https://github.com/ryanbr/network-scanner/issues/41)

## [2.0.23] - 2025-10-01

### Improved
- Whois retry enabled by default with tuned retries/delay

## [2.0.22] - 2025-10-01

### Added
- `--dry-run` split into separate module (`dry-run.js`)

## [2.0.21] - 2025-09-30

### Added
- Domain-based `forcereload` support (`forcereload=domain.com,domain2.com`)
- Input validation and domain cleaning for forcereload

### Improved
- Update man page and `--help` args

## [2.0.20] - 2025-09-29

### Improved
- `--localhost` now configurable (`--localhost=x.x.x.x`)

## [2.0.19] - 2025-09-27

### Improved
- `--remove-dupes` reliability

## [2.0.18] - 2025-09-27

### Fixed
- Whois logic occasionally missing records

## [2.0.17] - 2025-09-27

### Improved
- `window_cleanup` realtime less aggressive, added validation checks

## [2.0.16] - 2025-09-25

### Fixed
- `tar-fs` security vulnerability

## [2.0.15] - 2025-09-25

### Improved
- Font, canvas, WebGL, permission, hardware concurrency, plugin fingerprinting

## [2.0.14] - 2025-09-24

### Improved
- Fingerprinting updates
- Bump Firefox version
- Wrap errors in `--debug`

## [2.0.13] - 2025-09-24

### Improved
- Bump Firefox version

## [2.0.12] - 2025-09-23

### Fixed
- Navigator.brave checks
- Fingerprint.js error handling

## [2.0.11] - 2025-09-23

### Improved
- Bump timeouts, make delay a const

## [2.0.10] - 2025-09-23

### Fixed
- Occasional detach issues during scanning

## [2.0.9] - 2025-09-21

### Added
- `cdp_specific` support for per-URL CDP without global `cdp: true`

## [2.0.8] - 2025-09-20

### Added
- User agents for Linux and macOS

## [2.0.7] - 2025-09-20

### Added
- `clear_sitedata.js` for CDP fixes

### Improved
- Bump Cloudflare version

## [2.0.6] - 2025-09-19

### Improved
- CDP.js reliability with retry support

## [2.0.5] - 2025-09-19

### Fixed
- Race condition with `window_cleanup=realtime` and Cloudflare

## [2.0.4] - 2025-09-17

### Improved
- Cloudflare.js v2.6.1

## [2.0.3] - 2025-09-17

### Fixed
- Frame detach errors — [#38](https://github.com/ryanbr/network-scanner/issues/38)

### Improved
- Cloudflare.js v2.6.0

## [2.0.2] - 2025-09-15

### Improved
- Cloudflare.js v2.5.0

## [2.0.1] - 2025-09-15

### Fixed
- Pi-hole regex slash handling
- Allow latest Puppeteer version

## [2.0.0] - 2025-09-15

### Changed
- Major version bump — Puppeteer compatibility and architecture updates

## [1.0.99] - 2025-09-13

### Improved
- Bump user agents
- Increase browser health thresholds

## [1.0.98] - 2025-09-09

### Added
- Realtime `window_cleanup` for larger URL lists

## [1.0.97] - 2025-09-06

### Added
- `window_cleanup` to close old tabs, releasing memory on larger URL lists

## [1.0.96] - 2025-09-05

### Improved
- CDP timeout improvements

## [1.0.95] - 2025-09-05

### Fixed
- Persistent failure recovery — move to next URL instead of error

## [1.0.94] - 2025-09-04

### Fixed
- ForceReload fallback for Puppeteer v23.x compatibility

## [1.0.93] - 2025-09-03

### Improved
- Health checks and fallback on `evaluateOnNewDocument` failure

## [1.0.92] - 2025-09-03

### Improved
- Interaction.js tweaks

## [1.0.91] - 2025-09-03

### Improved
- Minor version bumps

## [1.0.88] - 2025-09-01

### Added
- Split curl functions from `grep.js` — [#33](https://github.com/ryanbr/network-scanner/issues/33)

### Improved
- Cloudflare.js v2.4.1

## [1.0.86] - 2025-08-31

### Fixed
- Puppeteer 24.x compatibility and browser health issues — [#28](https://github.com/ryanbr/network-scanner/issues/28)

## [1.0.85] - 2025-08-31

### Improved
- Post-processing first-party item checks

## [1.0.83] - 2025-08-30

### Fixed
- ForceReload logic to apply after each reload

## [1.0.82] - 2025-08-29

### Improved
- Cloudflare.js v2.4

## [1.0.81] - 2025-08-28

### Fixed
- Endless loops caused by some sites

## [1.0.80] - 2025-08-27

### Fixed
- Performance issues with interact and resource cleanup

## [1.0.78] - 2025-08-27

### Added
- INSTALL suggestions

## [1.0.77] - 2025-08-26

### Improved
- Cloudflare.js v2.3

## [1.0.76] - 2025-08-21

### Added
- Cached network requests for duplicate URLs in same JSON

### Fixed
- Duplicate function removal

## [1.0.75] - 2025-08-19

### Fixed
- Nettools not firing

## [1.0.74] - 2025-08-19

### Fixed
- Nettools being ignored

## [1.0.73] - 2025-08-19

### Added
- `regex_and` to apply AND logic on filterRegex

## [1.0.72] - 2025-08-18

### Improved
- Cloudflare.js v2.2

## [1.0.70] - 2025-08-17

### Improved
- Regex tool GitHub compatibility

## [1.0.69] - 2025-08-17

### Improved
- Convert magic numbers to constants in nwss.js

## [1.0.68] - 2025-08-15

### Fixed
- URL popup protection — don't treat main URL changes as third-party

## [1.0.67] - 2025-08-14

### Fixed
- `third-party: true` never matches root URL

## [1.0.66] - 2025-08-12

### Improved
- Interaction.js performance
- Fingerprint.js refactor
- Puppeteer 23 compatibility

## [1.0.63] - 2025-08-11

### Fixed
- Occasional interaction.js delays
- Security vulnerabilities in `tar-fs` and `ws`

### Improved
- Puppeteer 23.x support

## [1.0.60] - 2025-08-10

### Changed
- Pin to Puppeteer 20.x for stability

## [1.0.59] - 2025-08-08

### Improved
- Searchstring improvements
- Update dependencies for Node.js 20+

## [1.0.58] - 2025-08-08

### Added
- `--clear-cache` / `--ignore-cache` options

### Improved
- Smart cache memory management

## [1.0.57] - 2025-08-06

### Added
- Smart caching system (`smart-cache.js`)

## [1.0.53] - 2025-08-06

### Added
- Automated npm publishing workflow

## [1.0.49] - 2025-08-04

### Added
- ESLint configuration

### Improved
- CDP functionality separated into own module

## [1.0.47] - 2025-08-03

### Improved
- Mouse simulator made more modular
- Cloudflare and FlowProxy skip non-HTTP URLs

### Fixed
- Regression on `subDomains=1`

## [1.0.46] - 2025-08-01

### Improved
- Skip previously detected domains
- Magic numbers converted to constants
- Cloudflare.js documentation

## [1.0.45] - 2025-07-31

### Added
- Whois and dig result caching

### Improved
- Dig/nettools with multiple URLs

## [1.0.44] - 2025-07-30

### Added
- User-configurable `maxConcurrentSites` and `cleanup-interval`

## [1.0.43] - 2025-07-20

### Fixed
- Browser restart on `protocolTimeout`

### Improved
- Cloudflare wait times and timeouts

## [1.0.42] - 2025-07-16

### Added
- Referrer options support

### Improved
- Redirecting domains compatibility
- Fingerprint.js improvements

## [1.0.41] - 2025-07-14

### Added
- `ignore_similar` domains feature

## [1.0.40] - 2025-07-02

### Added
- `even_blocked` option

### Fixed
- Puppeteer old headless deprecation warnings

### Improved
- Domain validation — [#27](https://github.com/ryanbr/network-scanner/issues/27)
- `--append` output support

## [1.0.39] - 2025-06-24

### Added
- `--dry-run` option with file output

### Improved
- `ignoreDomains` fallback removal

## [1.0.38] - 2025-06-21

### Fixed
- First-party/third-party and ignoreDomains prioritisation

## [1.0.37] - 2025-06-17

### Added
- `--remove-tempfiles` option

## [1.0.36] - 2025-06-16

### Added
- FlowProxy DDoS protection support — [#24](https://github.com/ryanbr/network-scanner/issues/24)

### Improved
- Browser health checks and restart on degradation
- Chrome process killing
- Insecure site loading support

## [1.0.35] - 2025-06-15

### Added
- Whois and dig debug file output with ANSI stripping

### Improved
- Whois reliability

## [1.0.34] - 2025-06-13

### Fixed
- Out-of-space issues from `puppeteer_dev_chrome_profile` temp files
- Error handling crash
- `about:srcdoc`, `data:`, `about:`, `chrome:`, `blob:` URL handling — [#21](https://github.com/ryanbr/network-scanner/issues/21)

## [1.0.33] - 2025-06-11

### Added
- Pi-hole output format (`--pihole`)
- Privoxy output format
- Comments value in JSON config

## [1.0.32] - 2025-06-10

### Added
- `whois_server_mode` (random/cycle)
- Configurable whois delay
- Whois error logging to `logs/debug`
- Coloured console output

### Improved
- Browser detection with custom userAgent

## [1.0.31] - 2025-06-09

### Changed
- Rename `scanner-script.js` to `nwss.js`

## [1.0.30] - 2025-06-08

### Added
- Searchstring AND logic
- Unbound, DNSMasq output formats

### Fixed
- Iframe debug errors

## [1.0.29] - 2025-06-06

### Added
- Custom whois servers with retry/fallback

### Improved
- WSL compatibility

## [1.0.28] - 2025-06-05

### Added
- Global blocked domains support
- `goto_options` config

### Improved
- Scanning method improvements

## [1.0.27] - 2025-06-04

### Added
- `--compare` with `--titles` support — [#1](https://github.com/ryanbr/network-scanner/issues/1)
- `--remove-dupes` alias

### Improved
- Resource management with service restarts

## [1.0.26] - 2025-06-02

### Added
- Whois/dig support — [#18](https://github.com/ryanbr/network-scanner/issues/18)
- `--debug` and `--dumpurls` file output

## [1.0.25] - 2025-05-31

### Added
- Curl and grep alternative scan method
- Adblock rules output format

### Improved
- Cloudflare bypass split to own module
- Output split to `output.js`
- Fingerprinting split to own module

## [1.0.24] - 2025-05-30

### Added
- Searchstring support (search within regex-matched content)
- `--remove-dupes` on output
- Wildcard support in ignored domains

## [1.0.23] - 2025-05-27

### Added
- `--debug` logging improvements

### Improved
- Graceful exit handling
- Module split: CDP, interact, evaluateOnNewDocument, Cloudflare, CSS blocking, fingerprint

## [1.0.22] - 2025-05-26

### Added
- Cloudflare phishing warning bypass
- CSS blocking support — [#2](https://github.com/ryanbr/network-scanner/issues/2)

### Improved
- Concurrent site scanning resource management

## [1.0.21] - 2025-05-23

### Added
- Multithread/concurrent support
- CDP logging improvements
- Address [#14](https://github.com/ryanbr/network-scanner/issues/14), [#15](https://github.com/ryanbr/network-scanner/issues/15)

## [1.0.20] - 2025-05-21

### Added
- Per-site verbose output with matching regex
- Scan timer
- Scan counter

### Improved
- First-party/third-party detection

## [1.0.19] - 2025-05-19

### Added
- `package.json` for npm

### Fixed
- Sandboxing issue on Linux

## [1.0.18] - 2025-05-03

### Added
- JSON manual (`JSONMANUAL.md`)

### Improved
- Scanner methods — [#3](https://github.com/ryanbr/network-scanner/issues/3)
- `--plain` unformatted domain output
- Global blocked items

## [1.0.17] - 2025-05-01

### Added
- Headful browser mode
- Screenshot option for debugging
- Custom JSON file support

### Fixed
- Regex crash on undefined `.replace()`

## [1.0.16] - 2025-04-29

### Added
- Fingerprinting support — [#7](https://github.com/ryanbr/network-scanner/issues/7)
- Multiple URL support and `--no-interact`
- HTML source output — [#12](https://github.com/ryanbr/network-scanner/issues/12)

### Fixed
- Execution context destroyed crash in Puppeteer

## [1.0.15] - 2025-04-28

### Added
- Localhost JSON configs — [#11](https://github.com/ryanbr/network-scanner/issues/11)

## [1.0.14] - 2025-04-27

### Added
- SubDomains support
- Delay option — [#8](https://github.com/ryanbr/network-scanner/issues/8)
- UserAgent support — [#6](https://github.com/ryanbr/network-scanner/issues/6)
- Mouse interaction — [#5](https://github.com/ryanbr/network-scanner/issues/5)

### Fixed
- Blocked JSON requests — [#4](https://github.com/ryanbr/network-scanner/issues/4)
- Subdomain and localhost output

## [1.0.0] - 2025-04-27

### Added
- Initial release of network scanner
- Puppeteer-based browser automation for network request analysis
- JSON configuration for site-specific scanning rules
- Regex-based URL matching with domain extraction
- First-party/third-party request classification
- Multiple output formats (hosts, adblock)
- `--dumpurls` matched URL logging
- `--debug` mode
- `--localhost` format output
