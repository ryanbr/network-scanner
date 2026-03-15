# Changelog

All notable changes to the Network Scanner (nwss.js) project.

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
