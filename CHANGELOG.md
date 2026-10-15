# Changelog

All notable changes to the Network Scanner (nwss.js) project.

## [Unreleased]

### Highlights
Seventy-six commits since 4.0.0, most of them circling one problem: an anti-adblock
loader that serves from a ROTATING host list and only reveals the next host once a
real content blocker cancels the current one. A scan sees the first host. The list
is longer, and a rule written against the host it happened to see goes stale on the
next rotation.

**If you only read one thing:** a hostname could carry filter SYNTAX into a
published rule. `hostRejectionReason()` checked a host's structure — a dot,
non-empty labels, TLD length — and never its character set, so `https://*.com/x.js`
emitted `||*.com^`, a rule blocking every `.com` domain, while `$` opened rule
options (`||a$b.example^`, and `$all` is a real one) and a 300-character host
produced a 300-character rule. Injection was never possible, since URL parsing
strips CR, LF and TAB — the exposure was over-blocking, which at `||*.com^` is
severe enough. Hostnames arrive from whatever a page asked the browser to fetch and
this scanner's output is published, so a page could influence a filter list.

**New: rules from a capture, not only a scan.** `nwss.js --har <file>` reads a
browser capture — HAR, Chrome net-log or Firefox MOZ_LOG, identified by content —
and runs it through the live path's own per-site matching, `formatRules()` and every
output format. That exists because the rotation only walks in a real browser with a
real blocker: thirteen puppeteer configurations failed to reproduce it, including a
declarativeNetRequest extension producing a genuine `ERR_BLOCKED_BY_CLIENT`, so
"CDP interception is why" is retracted here. Three readers and a format sniffer
come with it, four capture scripts drive the browsers, and the whole path agrees with a live scan on
`subDomains`, `output_regex`, array `filterRegex`, a `/.../`-wrapped pattern and
first/third-party — five divergences found by making the two paths share one
chokepoint rather than two copies of a rule.

**New: enumerate the chain by walking it.** `scripts/win-bait-walk.ps1` finds loader
hosts by PATH shape, PAC-blocks what it found, captures again, and repeats until a
round turns up nothing new — no host named in advance, driven entirely from the
config. `scripts/bait-confirm.js` then asks dig and whois whether each find really
belongs to the same operator, with lookup FAILURE kept distinct from mismatch
throughout: conflating them reported every genuine find as unconfirmed the moment a
binary was off PATH.

**Safety:** `lib/baitguard.js` is the gate before publication, because the publish
step writes `||${domain}^` with no `formatDomain()` on that path. It refuses a bait
whose root is a public suffix — measured publishing `||co.il^`, which blocks every
domain under a ccTLD — and anything that is not a usable hostname. `--dns 8.8.8.8:0`
ABORTED the process inside c-ares, below any try/catch, and `:99999` silently
wrapped to a dead port that de-fanged dig-gated matching.

**Breaking:** none. No config key was removed, no per-site key changed meaning, and
the only narrowed behaviour is the hostname guard above — which refuses eleven
hostile forms while punycode, IPv4, underscore and hyphenated hosts still emit.

### Added
- **`nwss.js --har <file>` — build rules from a saved capture, with no browser launched.** Everything downstream is the live path's own, so per-site matching, `formatRules()`, `processResults()`, `handleOutput()` and every output format behave exactly as they do for a scan. `lib/capture.js` identifies HAR, Chrome net-log and Firefox MOZ_LOG **by content** rather than by extension, and is shared with `scripts/har-rules.js` instead of duplicated in it. Without `--site` the capture is matched to a configured site by registrable domain, and nwss stops if none matches rather than attributing rules to pages that were never loaded. Three bugs were found building it, each now pinned by a mutation-verified check: a capture is ONE page load, so matching it once per configured URL emitted every rule two or three times for a multi-URL site; `formatRules()` was handed `{}` instead of the globalOptions the live path builds, so `--plain`, `--dnsmasq`, `--unbound`, `--privoxy`, `--pihole` and `--localhost` were silently ignored and every format emitted adblock syntax, which looked plausible; and — pre-existing — the positional-`.json` → `--custom-json` wiring lived inside the optional `.nwssconfig` block, so without that file `node nwss.js myconfig.json` silently scanned `config.json` instead. Wrong sites, no warning. Hoisted so it always runs.
- **`lib/mozlog.js` — read Firefox MOZ_LOG captures, which keep real uBO in the loop.** Chrome is MV3-only now, so uBO there is uBO Lite on declarativeNetRequest — a weaker blocker, measured not to move an anti-adblock loader to the next host in its list even with a real `ERR_BLOCKED_BY_CLIENT`. Firefox still runs full uBO with the user's own rules, so this is the capture route that matters, and MOZ_LOG is an environment variable: no DevTools, no toolbox, and unlike the HAR path no prefs to write or restore. URLs come from `uri=` lines, which carry the scheme and are written whether or not the request reaches the network; resource types come from the self-contained `http request [` blocks, joined on host+path rather than by correlating `[this=<pointer>]`, which is reused after a free. Firefox's per-process sibling logs are read automatically. Verified on a real 424MB capture of one page load: 846 requests in 2.7s. Blocked requests generally DO appear, since the channel is logged before a blocker cancels it — but a cached response leaves no request block either, so nothing is marked blocked from this source. The shared reader strips a trailing `\r`, which is not cosmetic: captures from a Windows browser are CRLF, and in a JavaScript regex `\r` is a LINE TERMINATOR, so `.` will not match it and a pattern as ordinary as `/foo (.*)$/` matches nothing. The first version of this parser returned 0 requests from that 424MB log while every regex tested fine against a hand-typed copy of the same line without its `\r`. The suite pins CRLF first and reports it by name rather than throwing, because the symptom is silence.
- **`lib/netlog.js` — read Chrome's own net-log, which a command-line flag produces with no DevTools and nothing to click.** It streams line by line instead of `JSON.parse`-ing the file, because a killed browser leaves the events array unterminated: a 12.9MB log from a SIGKILLed Chrome yields nothing to `JSON.parse` and 520 requests this way, and the result reports truncated. Entries come out in the shape `lib/har.js` produces, so `matchEntries` consumes either source and the `Sec-Fetch-Dest` type derivation is shared rather than duplicated. A net-log does not contain extension-blocked requests at all: with a declarativeNetRequest extension blocking the loader host, puppeteer reported `ERR_BLOCKED_BY_CLIENT` and that host appears **zero** times in the 530-request net-log from the same run. It records what the browser really fetched; a HAR remains the way to see what a blocker stopped.
- **`scripts/win-bait-walk.ps1` — enumerate a fallback chain by walking it, with nothing hardcoded.** These loaders serve from a rotating host list and stop at the first host the blocker does not cancel, so a single capture only ever reveals hosts up to the one that answers; blocking that one and loading again reveals the next. No host is named in advance — each round finds hosts by the loader PATH, with the token derived from the target url, so a rotated host is found by shape and a new site needs no configuration. Blocking uses a PAC pointed at an unroutable proxy, chosen by measurement: in Chrome neither CDP request interception across five abort modes nor a declarativeNetRequest extension producing a genuine `ERR_BLOCKED_BY_CLIENT` made the loader advance, while in Firefox a plain PAC connection failure does. The deciding factor is the browser, not how the block is delivered — which also explains twelve earlier puppeteer configurations failing to reproduce the chain. Round 1 runs with no PAC and is the capture that is kept, so a consuming pipeline still sees what a normal visitor gets; rounds 2+ are deliberately distorted and are scratch, with cleanup in a `finally` because the loop exits by `break` and an in-loop cleanup never ran for the last round. On a real site it enumerated six hosts in three rounds, all six matching the operator fingerprint that the unrelated ad domains on the same pages do not share, and surfaced two hosts before either had served the capture profile.
- **`scripts/bait-confirm.js` and the `bait_*` config keys — a second opinion on every host the walk found.** Discovery is regex alone and PAC-blocks what it matches, so a loose pattern could drag an unrelated domain into the block set and quietly distort every later round. Keys mirror the vocabulary nwss already uses: `bait_dig` / `bait_whois` take ALL terms (AND), `bait_dig-or` / `bait_whois-or` take ANY (OR), matched case-insensitively against raw tool output, so an existing `dig: "104.26."` style prefix works unchanged; site-level first, then global. `bait_detect` carries the loader pattern and `bait_rounds` the round count, so the fingerprint, the pattern and the cap live beside the other keys rather than in the script and the caller's command line — the count previously existed in both a parameter default and the pipeline's invocation, which is how two copies of one number drift. All are registered in `lib/validate_rules.js`; without that the validator called `bait_whois-or` a typo and reported it as "value will be ignored at runtime", which would have been actively misleading, since they ARE read, just by a different consumer than the scan. Confirmation is **report-only by default**: the operator controls their own DNS, so a genuine bait moved to another account would fail a strict check and be silently dropped, which is the expensive direction to be wrong in. `--strict` exits non-zero for callers that want enforcement. Verified discriminating rather than merely passing: the real baits confirm on both signals while four unrelated ad hosts and `example.com` do not. Results cache to a SEPARATE `.baitcache` with the scan's own TTLs (dig 20h, whois 36h) because nettools stores its own object shape in `.whoiscache` and writing a different one there would corrupt the scan's whois path — 6.2s cold, 0.024s warm, and FAILURES ARE NEVER CACHED, since a missing binary would otherwise pin "unknown" for the whole TTL.
- **`lib/baitguard.js` and `scripts/test-bait-guard.js` (81 checks) — the gate before publication.** The publish step writes `||${domain}^` verbatim with no `formatDomain()` on that path, so this module is the only thing between a walk's finding and a filter list. It refuses a bait whose root is a public suffix, and anything that is not a usable hostname — `*.bait.example`, `host.example:8443`, `user@host.example`, `a$b.example`, a name with a space, a leading dot, an empty label — by reusing `output.js`'s exported `hostRejectionReason()` rather than reimplementing its rules, so a second copy cannot drift from the one all other output goes through. Bare IPv4 stays allowed, as it is there. Repair comes before refusal: the dig-gate sidecar records the name that actually matched, so a bait one label too short recovers its real registrable domain via psl and the find survives — refusing loses one bait, publishing a suffix breaks every site beneath it. Three distinct refusal reasons, the third reachable rather than dead code, since psl's wildcard rules make names like `foo.kawasaki.jp` suffixes in their own right.
- **`scripts/psl-root.js` — reduce bait hosts with the real public suffix list.** The walk carried 26 multi-part suffixes by hand on the premise that "there is no PSL here (node lives in WSL, this runs on Windows)". That premise was wrong: Windows node is on PATH and loads a script plus `node_modules` over the same `\\wsl.localhost` path the walk already uses for `-Config`, in ~100ms. The hand list was not close — psl carries 9,778 suffix rules, 8,330 of them multi-part, and of fifteen suffixes probed thirteen were missing, including `co.il`, `com.pl`, `com.ua`, `co.th`, `com.ng`, `co.id`, `com.vn`, `com.ph`, `co.ke` and the private `github.io`, `vercel.app`, `pages.dev` and `web.app`. Hosts go in on stdin and come back as `<normalised host>\t<root>`, batched to ONE call per round rather than one per host. A bare public suffix returns an EMPTY root so the caller can tell "psl says there is no registrable domain" from "the call never arrived"; the walk then caches the host itself, because blocking one host is narrow and wrong while blocking the suffix is the failure being prevented. The 26 rules stay as a labelled degraded mode: with the helper removed the walk prints one NOTE and completes with an identical enumeration rather than aborting.
- **`scripts/win-mozlog-capture.ps1` and `scripts/win-netlog-capture.ps1` — capture from the real Windows browser.** Chrome writes a full network log from a command-line flag, so the net-log route needs no DevTools, no prefs and nothing to save by hand — the part the Firefox HAR route could never get right. It closes Chrome first because a running instance swallows the new flags and opens a tab in the old process, producing no log and no error. Processes are matched on their COMMAND LINE via `Get-CimInstance`, never by diffing PIDs: a browser spawns and retires renderers constantly and a before/after PID set kills innocent ones. Verified against Windows Chrome on a throwaway profile: 58MB log, 511 requests over 136 hosts, parsing clean with no extensions installed at all. The MOZ_LOG script is the one that matters for blocker-dependent chains, and it is the route that captured a full fallback chain for the first time — one run produced three chained hosts plus their numbered serving subdomains, every host serving the identical loader path.
- **`scripts/win-capture-scheduled.ps1` — an unattended capture that leaves your browser alone.** The interactive script closes Firefox, which is fine when asked for and unacceptable on a timer. This one runs headless against a CLONE of the default profile, so the user keeps browsing while it works: no window, no focus stolen, their own instance never touched. `-no-remote` is essential — without it a second `firefox.exe` hands its url to the running instance and exits, and MOZ_LOG is read when a process STARTS, so the capture comes back as a 0-byte file. The clone carries what makes the blocker real (`extensions/`, `extensions.json`, `addonStartup.json.lz4`, `prefs.js` for the extension UUID map, and each extension's own storage, where uBO keeps its filter lists and the user's custom rules) while leaving out site storage, history and cache: 35MB rather than 270MB. It is a snapshot, so `-RefreshProfile` picks up later filter-list changes. Headless loses nothing, measured across three headful and two headless captures: ZERO hosts appeared in every headful run and never headless, the fallback chain is identical in both — which only walks when a real blocker cancels the first host, so uBO is demonstrably live — and headless additionally caught 16 header-bidding endpoints. `-Status` prints task state, last and next run, the configured target, the capture's age and its TOP HOSTS, that last line read from the capture's contents rather than from configuration, so it reflects where the browser actually went. Each run records the target and whether that host appears in the capture (`contacted: yes|NO`), because a target can be requested and never reached — dns failure, redirect, stale task arguments — and that previously looked identical to success: a file of the right size, written on time, containing the wrong thing.
- **`scripts/cbcdn-hosts.js` — harvest hosts a beacon NAMES but the browser never fetches.** Matching runs over REQUEST urls, so it can only ever publish a host that was actually contacted. One loader family announces its next CDN host in a query parameter on an earlier beacon, which makes the name available a step BEFORE the request — and still available when that request never happens, because the host is held in reserve or whatever would have triggered it was blocked. Measured across a set of real captures plus one live run: of the rotating hosts seen, one appeared ONLY as a parameter value and was requested zero times, so no `filterRegex` over request urls could have reached it. This cannot be a config key: `output_regex` looks like the right tool and is not, because `outputKeyFromUrl` requires the capture to be shaped host/path and falls back to the REQUEST's own domain for a bare hostname, so a parameter holding just a host publishes the beacon's apex instead of the host it named — silently, and with a plausible-looking rule. Validity is `hostRejectionReason()`, the same guard the publish path uses, not a printable test, since a parameter can hold filter syntax. `--dig` keeps only hosts on given address prefixes, and a dns FAILURE keeps the host and flags it rather than dropping it. `--not-in` omits what a list already carries, so per-run counts do not report published hosts as finds.
- **Targets are read from a file and are not in the repo.** All four Windows capture scripts read `<OutDir>\targets.txt` (gitignored, one url per line), with `scripts/targets.example.txt` as the template, `-Urls` still overriding for a one-off and `-TargetsFile` selecting another list. With neither they stop with a message naming the file they want rather than capturing the wrong site silently. One place to change the site; every capture script follows.
- **Seven new test suites, all offline except where noted.** `test-capture-mode` (59 checks) pins the capture path against the live path, `test-bait-guard` (81) the publication gate, `test-mozlog-parse` (24) and `test-netlog-parse` (24) the two parsers against generated fixtures with the real files' structure, `test-adshield-rule` (31) the derived-rule guards, `test-cbcdn-hosts` (27) the beacon harvest, and `test-dns-resolver-spec` (23) the two `--dns` port failures — the abort case in a child process, since a native abort cannot be caught in-process. `test-seeding` grows 28 → 38. Every new guard in this release was mutation-verified: the change was reverted and the suite had to fail BY NAME. Several of those mutation runs were themselves wrong first time and are documented as such in the commits, because a mutation that does not disable the guard reads as a coverage gap.
- **`scripts/win-har-capture.ps1` — capture from the browser that actually sees the chain.** Fifteen automated attempts from WSL failed to reproduce the AdShield fallback: CDP interception at five failure modes, EasyList+EasyPrivacy through the rust engine (112,691 rules), cosmetic filtering, profile persistence across seven loads and a restart, a *real* uBO in a fresh Linux Firefox under puppeteer (which did block `cdn-apex.example` — and still no fallback), and mitmproxy. The established Windows profile reproduces it every time. So this drives that browser instead of competing with it: it resolves the real default profile from `profiles.ini` (the `[Install…] Default=` line, not the misleading `[Profile1] Default=1`), writes the HAR auto-export prefs to `user.js`, launches with `--devtools`, visits each URL — subsequent ones as new tabs in the same armed session — then restores `user.js`. Requires Firefox closed, since the profile locks and the prefs are read only at startup. Auto-export may still not fire (it never did on a fresh profile, cause unproven), in which case the script says so and the two-click `Save All As HAR` remains the working path. Output feeds `har-rules.js` either way.
- **`scripts/adshield-rule.js` — a rule that survives the domain rotation.** The loader these anti-adblock chains serve rotates its HOST (`cdn-apex.example` → `apex-two.example` → `apex-three.example` → …), so a host-anchored rule has to be rediscovered after every rotation. The PATH does not rotate: it is `/script/<base64(site hostname) with padding stripped>.js`, and it was **identical on all four hosts** in a real capture, with base64 of that site's own hostname reproducing the observed token exactly. So the filter can be written from the site's hostname alone — `/script/<token>.js$script,domain=<site>` — before the next domain exists, and keeps working after it changes. `--har <file>` runs it in reverse: finds loader-shaped URLs in a capture, decodes the token back to the site, and lists every host seen serving it. The practical consequence is that reproducing the fallback chain was never necessary: detection only needs the FIRST host, which ordinary scans see every time (it is what the existing `\/[A-Za-z0-9]{8,12}\.js$` pattern already matches), and the rotation-proof rule follows from decoding its token. **Later correction:** that last sentence was drawn from one capture and does not generalise — the base64 path is one shape of several (a non-base64 fixed-length token, the hostname in clear with a `?hash=`, the hostname as a `/session/` path segment, and `/preload/`, `/theme/`, `/vendor-libs/`, `/build-output/` variants have all been measured since), so enumerating the chain IS necessary and is what catches rotations in practice. See CLAUDE.md for the current description.
- **`scripts/har-rules.js` — generate rules from a browser-saved HAR.** Some request chains cannot be reproduced by the scanner at all. A site in testing loads an AdShield anti-adblock loader that walks a fallback list — `cdn-apex.example` → `apex-two.example` → `apex-three.example`, all serving `/script/<base64(hostname)>.js` — but it only walks it once a *real* content blocker cancels the earlier hosts. Twelve puppeteer configurations failed to trigger it: varying delay (2s to 59s), page (homepage vs article), UA family, which ad entry points were blocked, cosmetic filtering, EasyList+EasyPrivacy through the rust engine (112,691 rules), profile persistence across seven loads and a browser restart, and all five CDP request-failure modes. A HAR saved from Firefox with uBO contains the whole chain, so this reads one and applies the site config's own `filterRegex`, `resourceTypes`, first/third-party and `ignoreDomains` rules, then emits through the same `formatRules()` the live path uses so output is identical in shape. Verified end to end against a real capture: 363 requests → 216 considered → 4 matched → `||apex-three.example^`. Requests the blocker cancelled are identified (status 0 — confirmed against a HAR where uBO-blocked hosts carried 0 while allowed ones carried 200/302) and reported but kept out of the rules, since a blocked request is evidence about the blocker rather than about the site; `--include-blocked` overrides. Firefox HARs carry no `_resourceType`, so the type comes from the request's `Sec-Fetch-Dest` header (present on 321 of 374 entries in the sample) with a mimeType fallback.
- **`scripts/har-capture.js` — automating that export (UNPROVEN).** Firefox can write a HAR per page load by itself via `devtools.netmonitor.har.enableAutoExportToFile` / `defaultLogDir` / `forceExport`, which would need no ports, no CDP and no interaction. The driver builds a capture profile with the real uBO `.xpi`, launches Windows Firefox from WSL through interop, waits for the file and hands it to the matcher. Launch, uBO installation and cleanup all work; **no HAR is produced yet** — `HarAutomation.initialize()` attaches to a devtools *toolbox*, so `-devtools` may not satisfy it on a fresh profile. **Parked**, with its header recording what was ruled out: `--devtools` (two dashes) does open the toolbox (window title and `devtools.everOpened` confirm it), `HarAutomation` is live code constructed at `toolbox.js:4685` from `initHarAutomation()` at toolbox open, and the pref gate is satisfied — yet no HAR is written and no log directory is created under either an absolute `defaultLogDir` or Firefox's `<profile>/har/logs` default, at 2.5s or 12s `pageLoadedTimeout`. Since the directory is never created, the export step is never reached, which rules out path and permission causes. Best remaining theory: the collector brackets a page-load event, and the toolbox finishes opening after the command-line URL has already started loading. Testing that needs navigation *after* the toolbox settles, i.e. driving an already-open window — the remote control this approach existed to avoid. One design note worth keeping: processes are matched by COMMAND LINE, never by diffing process lists — a live browser spawns and retires content processes constantly, and an earlier PID-diff approach killed four of the user's own processes and left orphaned instances behind.

### Changed
- **Dependencies refreshed again (`npm update`): puppeteer 25.13.0, and three transitive MAJORS with it.** `package.json` is untouched and no pin changed, but the resolution crossed three major boundaries pulled in by puppeteer's own ranges — `chromium-bidi` 17.0.2 → 157.0.8090-0, `zod` 3.25.76 → 4.6.7, `webdriver-bidi-protocol` 0.4.3 → 1.0.1, plus `devtools-protocol`, `@puppeteer/browsers` 3.2.3 → 3.2.4, eslint 10.12.0, globals 17.13.0, acorn 8.19.0 and ip-address 10.7.4. A zod 3→4 and chromium-bidi 17→157 jump is not something lint can vouch for, so it was verified at every level that exercises the DRIVER rather than the parser: eslint clean, seven suites green, `test-stealth` launching a real browser (29 passed, 1 warn, 0 failed — the suite that would break on a bidi or zod change), and a live scan emitting its rules in 50s. 0 vulnerabilities, 118 packages audited. `test-output-format` reports in its own format, so it was checked that it RAN — a bare exit 0 with no count proves nothing.
- **MOZ_LOG captures are taken at level 1, not 5.** Every line the reader uses — `uri=`, `http request [` and the `Sec-Fetch-Dest` inside it — is logged at E (level 1); the verbose levels are connection-manager chatter, 141k of 210k lines in one capture. Verified on three existing captures by filtering them to E-only and then on a live run at the new default: zero urls lost, identical entry counts, identical page, identical type histograms, identical rules. One 45s capture went 31.7MB → 2.4MB and 210ms → 44ms. `-LogLevel 5` restores the old behaviour. Profiling the parser first found nothing worth changing: the regex is 2ms of a 190ms sweep, read+split is 94% of it, throughput is ~500MB/s on a local disk, reading from `/mnt/c` is 35x slower than the Linux filesystem and dominates everything, and an `indexOf` prefilter to skip the regex on irrelevant lines measured SLOWER than the regex it replaced, because two full-line scans cost more than a pattern that fails on the prefix. The win was capturing less.
- **Captures run for 20 seconds instead of 45.** Measured across four captures: every host that produced a RULE appeared within 3.7 seconds of the first request. Traffic does continue for the rest of the window — one capture was still logging at +44.9s — but none of it reaches the filter regex, so the extra 25 seconds bought nothing but run time and log volume. Run time 50s → 24.8s, capture 8.2MB → 6.6MB, chain intact, target still contacted. 20s leaves roughly six times the margin over the slowest observed, and the rationale is recorded in the script so the number is not mistaken for arbitrary. This is tuned to one site: a site that lazy-loads ads could need longer and the symptom would be rules quietly going missing rather than an error, so `-SecondsPerUrl` stays available and is the first thing to raise when a new target produces thin output.
- **Captures use a fixed filename rather than a timestamp.** The command that reads one changed every run; they are now `capture.log.moz_log` and `netlog.json`, with `-Name` to rename and `-Timestamped` to keep history. A fixed name needs the script to clear its own previous family first, matched by an exact escaped pattern so nothing else can be caught by it.
- **The scheduled capture defaults to every 2 hours**, down from 4: a chain host was observed rotating twice inside one 90-minute window. `-IntervalHours` still overrides, and a consuming pipeline's staleness limit has to move with it — too generous and a dead task goes unnoticed, too tight and one skipped run fails the run.
- **Example domains in this repo are placeholders, and the convention is written down.** Comments, docs and test fixtures had named the sites being scanned, the loader operator's apexes and serving subdomains, a live fingerprint token, two live IP addresses and two nameserver pairs. None of it belongs in a public repo: the targets are not ours to publish, and naming a live chain host dates the comment the moment it rotates — which happened twice in one day on two different sites. Everything now uses reserved or documentation values only (`*.example`, `*.invalid`, `*.test`, RFC 5737 addresses), and chains are described by SHAPE instead — parked apex vs CDN-fronted apex, serving subdomain, shared CNAME endpoint — because the shape is what the code reasons about and it stays true after a rotation. 78 lines across 13 files, no production code affected, every occurrence confirmed to be a comment, a doc line or a fixture by grepping for non-comment matches first. Three things went wrong on the way, each left in the commit for the next reader: the first verification grep was case-SENSITIVE and reported clean while two fixtures still held mixed-case copies of a real host (every sweep since is `-i`); blind substitution made a comment assert that an RFC 5737 address IS a particular cloud accelerator, so placeholder values must not inherit claims that were only true of the real ones; and two edits silently failed to match because the pattern was copied from indented terminal output rather than from the file.
- **`scripts/adshield-rule.js` narrows its claim, guards its output, and reads the captures this project produces.** Its premise was one shape of several, documented as universal: the header, CLAUDE.md and the 4.0.0-era changelog all stated the loader path "does not rotate: it is `/script/<base64(site hostname)>.js`, identical on every host in the chain", drawn from a single capture. Measured since: a fixed-length token that is NOT base64 of the hostname; the hostname in clear with a `?hash=`; the hostname as a path SEGMENT with no `.js` at all; and `/preload/`, `/theme/`, `/vendor-libs/` and `/build-output/` variants. So a derived rule is a bonus on sites using the first shape, never a substitute for enumerating the chain — the walk is what has actually been catching rotations. A rotating token that happens to decode to printable ASCII also emitted a rule whose `$domain=` contained filter syntax, reachable about 1 token in 220 over 655 random 8-character tokens; a round-trip check CANNOT catch that, because base64 is bijective and those tokens round-trip perfectly, so the tests assert it explicitly to stop the idea being re-proposed. Two real checks now gate a rule: the decoded value must pass `hostRejectionReason()`, and in capture mode it must equal the page the capture is OF, since the premise is that the token encodes that site's own hostname. `ruleAnySubdomain` is removed — `$domain=example.com` already covers subdomains in ABP/uBO syntax, so there was no looser variant to offer, and the appended `|~nonexistent.invalid` negated a domain that can never match. Capture mode went through `har.log.entries` directly and so could read only HAR, while the pipeline produces MOZ_LOG exclusively; it now goes through `lib/capture.js` and `--har` stays as an alias.
- **A `--har` scan now names the actuator keys it is NOT applying.** A capture is a recording: there is no request to cancel and no interceptor to install, so `blocked`, `blockDomainsByUrl` and `ignoreDomainsByUrl` are never read on that path, and nothing in the output said so. That silence is expensive — measured in the field, a 245-entry global `blocked` list including the exact domain under investigation, plus a `blockDomainsByUrl` pattern written specifically to abort it, both inert for eight days while that domain answered 200 in every capture taken. The investigation went looking for a broken regex, a stale filter list and a browser fingerprint before the dead config was found, because every layer above it looked correct. One line listing each non-empty key with its entry count, one saying what they need, no behaviour change, and a config carrying none of them prints nothing.
- **The release workflow refuses an over-long release body before anything is published.** GitHub rejects a body over 125,000 characters and the 4.0.0 notes came in at 101,927 — 82% of the cap — so another release of that size would have failed at the API call, after `npm publish` had already made an immutable version. The check runs in the extract step, ahead of both publish and push, and warns past 90%.
- **Dependencies refreshed (`npm update`).** Lockfile only — `package.json`'s ranges are untouched and all six direct dependencies were already at their newest satisfying version, so this is three transitive bumps: `ws` 8.21.3 → 8.22.0, `ansi-regex` 6.3.0 → 6.4.0, `typed-query-selector` 2.12.2 → 2.12.3. puppeteer stays 25.12.0 (already latest), 0 vulnerabilities. `ws` is puppeteer's CDP transport, so this was verified with a real browser rather than by lint alone: all twelve suites pass and a live scan emits its rule with zero WebSocket/protocol errors.
- **Firefox spoof bumped to 157.0** across the win/mac/linux collection entries, confirmed against Mozilla's product-details API (`LATEST_FIREFOX_VERSION 157.0`). `rv:` and `Firefox/` carry the same number, as the UA convention requires; `Gecko/20100101` is a frozen trail and does not move with releases.
- **Chrome spoof bumped to 154.0.8037.93**, tracking the Stable channel the population is actually on rather than the build puppeteer bundles (154.0.8037.57 — same major this time, different build, and it is the build UA-CH exposes). Per Google's version-history API (win/stable, `endtime=none`, fractions normalised because entries duplicate per architecture), 154 is **99.5%** of served Stable with **8037.93 alone at 50%**, while 153 and 155 sit at 0.2% each. The UA-CH GREASE trio is re-derived rather than guessed: for major 154 the brand is **`Not A(Brand`** (`154 % 11 = 0` → `" "`, `155 % 11 = 1` → `"("`), the version stays **99** (`154 % 3 = 1`) and the brand order becomes **Chromium, Google Chrome, grease** (`154 % 6 = 4` → slots `[2,0,1]`, the same order 148 had). The derivation was re-verified against the three majors whose values were already confirmed against real Chrome (148, 150, 151) before being applied.

### Fixed
- **A hostname could carry filter SYNTAX into a published rule.** `hostRejectionReason()` checked a hostname's structure — a dot, non-empty labels, TLD length — and never its character set, while several characters that survive URL parsing are filter syntax. Measured end to end before the change: `https://*.com/x.js` → `||*.com^`, which blocks every `.com` domain; `https://a$b.com/x.js` → `||a$b.com^`, where `$` begins rule options; `https://ads.com$all/x.js` → `||ads.com$all^`, and `$all` is a real option; and a 300-character host produced a 300-character rule. This was never capture-specific — the live path emits through the same `formatDomain()` and `formatRules()` reproduced all of them directly — so fixing it in `hostRejectionReason()` covers both. Rule INJECTION was never possible, since URL parsing strips CR, LF and TAB from a host so a second line cannot be smuggled in; the exposure was over-blocking. DNS allows letters, digits, hyphen and in practice underscore, and punycode is already ASCII here, so an allowlist costs nothing legitimate: verified that punycode, IPv4, underscore and hyphenated hosts still emit while eleven hostile forms are refused, with the 253-host and 63-label caps from DNS stopping the padding case. Both guards mutation-verified.
- **`--dns <addr>:<port>` with an out-of-range port could abort the process.** `isResolverSpec` admitted any `\d{1,5}` and `setServers()` hands the value straight to c-ares, which does not validate it. `--dns 8.8.8.8:0` ABORTED: `cares_wrap.cc`'s `SetServers` fails a native `CHECK` (`Assertion failed: portValue->Int32Value(...).FromJust()`), so the try/catch around `setServers()` never saw it and `node nwss.js --dns 8.8.8.8:0 --help` exited 134 with a core dump, at module load. `--dns 8.8.8.8:99999` silently wrapped mod 65536 to port 34463: no throw, no warning, and the pre-check then queried a dead port, so every resolve timed out, burned twice the timeout on the retry and tripped the circuit breaker — and since nwss feeds these servers to `setDigResolvers` too, a mistyped port quietly de-fanged dig-gated matching as well. nettools' `digSpecPort()` already range-checked the port before handing it to dig's `-p` and its comment names this exact looseness as the reason, but it only ever protected the dig half of one flag. Both port captures now go through `isResolverPort` (1–65535) at the source, a bare address is unchanged, and an out-of-range port is warned and dropped like any other invalid entry. Against the pre-fix module 10 of 23 new checks fail.
- **A bait whose root was a public suffix could be published as a rule blocking an entire ccTLD.** The walk reduced a serving host to its registrable domain with a hand-maintained suffix list, so a bait under any unlisted suffix arrived one label too short — `deer.bait.co.il` → `co.il`, `x.bait.com.pl` → `com.pl`, `x.bait.github.io` → `github.io` — and nothing downstream re-derived it. The dig gate is satisfied by EITHER the root or the sidecar name, so the serving host alone could carry a bogus root to "confirmed": measured, a bait list of `co.il` with a legitimate sidecar returned verdict "confirmed", and the publish step writes `||${domain}^` with no `formatDomain()` on that path. Latent rather than live, since every bait observed so far is on `.com` or `.cc`. The first version of the guard was then found BYPASSABLE on re-review: psl normalises internally and reports tld `co.il` for `CO.IL` and for `co.il.`, but the check compared psl's answer against the RAW name, so both answered "not a public suffix" and went straight through to `||CO.IL^`. Reachable, not hypothetical — the walk returns a capture's match with no case folding and output.js's own comment notes Chrome preserves a root-anchoring trailing dot. Normalised at both ends now: at the producer so the walk's report, its PAC and the published name agree, and again at the consumer so the guard holds whatever a producer sends. A no-op on real data: 0 of 26 lines across every production bait list change. The suffix test is `psl.tld === name` deliberately, not "psl yields no registrable domain", because that is also true of an unknown TLD and would refuse `.invalid` and `.test`, which every fixture in this repo uses.
- **`"subDomains": true` was honoured in a capture and silently ignored in a live scan.** `matchEntries()` accepted `1` OR `true`; nwss.js tested `subDomains === 1` only, so the same config produced different rules from the two paths with nothing reporting the difference — and the README documents the field as `0 or 1`, which is what makes `true` plausible to write. The predicate moves into `useSubDomainsFor()` and both callers use it. The live half cannot be exercised offline, so the suite also pins the SOURCE: nwss.js must route through the shared predicate and must not reintroduce a bare `subDomains === 1`. That is a drift canary, not a behaviour test, and it is the only offline check that can see the live path re-diverge.
- **`output_regex` was read by the live scan and silently ignored from a capture.** It had zero references in `lib/har.js`, `lib/capture.js` and `scripts/har-rules.js`, so one site config produced a narrowed `||host/path/` rule live and a whole-host `||host^` rule from a MOZ_LOG or HAR. The key derivation moves to `matchEntries()`, the single chokepoint both capture consumers reach, and the acceptance test is now SHARED rather than copied — nwss.js loses its inline copy and calls `outputKeyFromUrl()` — because two copies of that rule is exactly how `subDomains` came to be honoured in one path and ignored in the other. Inert for every config in the tree, and verified against a real config and a real capture with an empty diff.
- **An array `filterRegex` matched nothing in the capture path.** The live scan accepts a string OR an array with `regex_and` choosing ALL vs ANY; `matchEntries` did `new RegExp(siteConfig.filterRegex)`, which coerces an array to a comma-joined string, so `["a$","b$"]` compiled to `/a$,b$/`. It failed SILENTLY, which is what made it worth catching: every url was still counted as considered, so the output read "2518 requests → 2071 considered → 0 matched", indistinguishable from a site that genuinely has no matching requests. Found on a real site whose loader token is 36 characters and needed a second pattern alongside the existing `{8,12}` one.
- **A `/.../`-wrapped regex compiled differently in the two paths.** `getCompiledRegex()` strips a surrounding `/.../` before compiling; `lib/har.js` called `new RegExp()` directly, so `"/\/[A-Za-z0-9]{8,12}\.js$/"` became a pattern needing a literal leading slash AND a slash after the anchor — it matches nothing, and the site silently produces no rules. Pre-existing for `filterRegex`; it was reproduced for `output_regex` while closing this very class of divergence, which is why it is closed rather than noted.
- **A multi-page HAR decided first/third-party from the wrong page.** A Chrome HAR recorded with "Preserve log" keeps recording across navigations and carries one page per navigation, but `pageUrl` was hardcoded to `pages[0]` — the page used to decide first vs third party — so the SCANNED site was classified third-party against an unrelated earlier page and, with `firstParty: false`, was published as a rule for itself. Measured on a two-page HAR: 5 matched including a rule for the target, where the same traffic as a single-page HAR matched 4. `--site` rescued the site selection but not the party call. `parseHar` now exposes every page and `pageUrlForSite()` picks the one whose registrable domain matches the site being matched, falling back to the site's configured url and only then to the capture's first page. `har-rules.js` resolves it the same way — it was deciding party from `har.pageUrl`, so after the nwss fix the two tools disagreed on a multi-page capture, and the check that pins them together could not see it because its fixture was single-page. That fixture gap is closed too.
- **On a busy MOZ_LOG capture, every request came back typed "other".** MOZ_LOG interleaves threads line by line, so a socket thread's bare `]` lands inside the main thread's `http request [` block; taking any `]` as the end truncated before `Sec-Fetch-Dest`. That mistyped the top-level document as well, which made the page resolve to a Mozilla cert-chain URL and no configured site match it. Blocks are now tracked per process+thread, which also keeps two concurrently open blocks from taking each other's headers. Quiet captures never interleaved and hid this through three earlier runs.
- **Pointing the reader at a DIRECTORY merged separate page loads.** It read every capture in it, folding two real runs of 350 and 288 requests into 498. A directory now means the newest capture, and `parseMozLog` on a directory takes one run's log family rather than all of them. The same fixed-filename change needed each run to clear its own previous family first, since Firefox writes one log per content process and a run that spawns fewer processes than the last leaves stale `child-N` siblings that share the stem — verified with a planted `child-99`: cleared, with no stale content reaching the result.
- **Retained urls were pinning the read chunks they were cut from.** V8 represents a substring as a `SlicedString` that keeps a reference to its parent, so holding one 40-character url out of a 4MB read chunk pins the entire 4MB. The parser keeps a url per request and a type key per header block — a handful of short strings, but spread across a large capture that was one retained slice per chunk, and so the whole file. Measured on a real 49MB capture: 43.8MB of heap retained for 350 entries and 187MB RSS, against 0.6MB retained and 144MB RSS after flattening the strings that outlive the chunk, with parse time unchanged (335ms → 352ms, inside noise). `(' ' + s).slice(1)` is the idiom, picked by measurement at 2ms per 200k strings against 22ms for a Buffer round-trip, with both verified to actually break the reference and a raw substring verified to keep it; the type key needs it too, being a concatenation of two slices that pins BOTH parents. Only mozlog is affected — netlog and har parse through `JSON.parse`, which produces fresh flat strings (0.4MB and 0.3MB retained, measured). Pinned by a check that re-runs itself under `--expose-gc`, since retention is only observable after a forced collection.
- **A skipped capture was indistinguishable from a real one.** The capture script exits 0 when another run holds the lock, so the walk proceeded and re-read the PREVIOUS capture — drawing conclusions from stale data, and able to report "nothing new, exhausted" when nothing had been captured at all. It now compares the log's mtime across the call, which covers any other no-op path rather than just the lock.
- **A lookup that could not RUN was recorded as a mismatch.** With dig and whois off PATH every genuine bait came back unconfirmed and `--strict` exited 1, so a missing binary or a transient dns failure rejected real domains. Tool failure is now its own state — `dig: err`, UNKNOWN (lookup failed), never MISMATCH — and the exit codes separate them: 0 all confirmed, 1 a real mismatch, 2 could not be checked, so a caller can tell "this domain is not theirs" from "ask again later". The walk's own report had the identical bug, calling a failed ns lookup "fingerprint differs" when nothing had been resolved.
- **An incomplete walk overwrote a complete list.** Measured: a run capped at one round replaced six hosts with two and still printed "enumerated in 1 round(s)" with nothing marking it partial — and a lock collision with the scheduled task, or a failed capture, takes the same path. Only "exhausted" counts as complete now; every other exit writes a `.partial.txt`, names the reason and leaves the authoritative list alone. A complete walk UNIONS rather than replaces, because a session may offer fewer hosts than a previous one and a retired bait costs nothing to keep.
- **A chain that ends in ONE hop could never report complete.** `$completed` was only ever set at the "nothing new, the list is exhausted" exit, which needs a round to still see the loader served from an already-blocked host — and a one-hop chain cannot get there: block its only host and the loader stops serving at all, so the round sees zero loader urls and leaves through the failure path. Such a walk was structurally incapable of completing, and the cost was not cosmetic: because an incomplete walk deliberately does not touch its authoritative list, three configured sites had no list written at any point, the staleness check fired on every run, and one list sat frozen for six days on a host its own partial file had already superseded — the walk found the rotation and then discarded it. Round 1 seeing no loader urls still means a failed capture or a page that does not carry the loader and must stay incomplete, so the round number is what separates the two cases. Verified both directions, and a full pipeline run took all seven walks to complete with every host still accounted for.
- **The dig gate dug the registrable domain only, so a whole family of hosts was found and then skipped.** This operator runs two shapes: one puts the apex behind a CDN, the other parks the apex and keeps its footprint only on the SERVING subdomain, where the parked apex resolves to accelerator addresses shared by countless unrelated parked domains. Both gates dug the root, so the second shape failed every term — the walk enumerated those hosts and then SKIPped them, and the confirmer reported MISMATCH for hosts already enumerated. Widening the gate to the parked-apex addresses was the tempting shortcut and would have matched half the internet. The walk now digs the serving host as well as the root and takes a match from either, keeps "unknown" distinct from "mismatch" on both, and records WHICH name satisfied the gate in a `<name>-baits-hosts.txt` sidecar that `bait-confirm.js --hosts` re-checks — a sidecar rather than a second column, because every existing reader treats a baits line as a bare domain. The end-of-walk report no longer re-derives its own verdict either: it printed a hardcoded nameserver check against the root and so read "fingerprint differs" for hosts the gate had just confirmed, and now prints the gate's own recorded value with the host it came from, which cannot disagree.
- **A blind dig failure was reported as a real mismatch.** One bait reported MISMATCH for a day while being live, its serving subdomains still pointing at the operator's shared CNAME endpoint, because its sidecar row was MISSING — it had entered the bait list before the sidecar feature existed and the chain had since rotated away, so no later walk re-discovered it. Adding the row alone made it confirm, and the publish loop went from 3 rules to 4; both files had been written 3ms apart in the same walk, so this was never staleness. A dig that fails with NO sidecar name to fall back on is now `unconfirmable` rather than `mismatch`: the two were indistinguishable and they mean opposite things — one says the bait moved, the other says we never recorded how to check it, and only the first is evidence. Neither publishes, and under `--strict` `unconfirmable` groups with "could not check" rather than with "mismatch".
- **An incomplete walk's partial list had no dig-gate sidecar beside it.** A rotation found in the round that failed can only be published from that partial, and it was written as bare roots — which makes the publisher dig the root and nothing else, and this operator's parked apexes match no `bait_dig` term. Measured: round 1 enumerated a host and CONFIRMED it via its serving subdomain, round 2 returned no loader urls, and confirming that partial without a sidecar reported mismatch — with one, confirmed. The host would have been found and then dropped one step later, the same failure the sidecar was added to fix on the complete path. The partial's sidecar is written fresh and removed when empty rather than unioned, since a partial describes a single run and a leftover sidecar beside a newer partial would attribute the wrong name to a host.
- **The capture lock was keyed on the run name, not the shared profile.** The Firefox profile clone is shared by every capture regardless of `-Name`, so the lock only serialised runs that happened to share a name — and almost nothing did, since the walk names each round `$Name-r$round`, each site's walk has its own name and the scheduled task has another. Several captures could therefore start Firefox on one profile at once, which yields "Firefox is already running" and a near-empty log: the truncated-capture failure this setup had hit repeatedly and which was never explained. The lock is now derived from the profile directory, verified with two captures started 5s apart under different names.
- **Two capture runs could corrupt each other even with the lock working.** A manual run and the scheduled run can land on the same second and share one clone profile and one output path: Firefox refuses the second profile lock, the second run deletes the files the first is still writing, and both end with a 0-byte capture — measured, with a Telemetry.FailedProfileLocks file to show for it. `MultipleInstances=IgnoreNew` only stops the TASK double-running and cannot see a manual run. The lock file now holds the owning pid; a second run checks whether that pid is alive and records "skipped: capture already running" and exits 0 rather than trampling the run in flight, while a lock whose owner is dead or older than 15 minutes is treated as stale so a crashed run cannot block the schedule indefinitely. Each run also clears a leftover `parent.lock` in the clone, but only after confirming no process is using the profile — that leftover is what makes the "already running" dialog reappear on the following run.
- **The scheduled capture stole the foreground every two hours.** The task ran `powershell.exe -WindowStyle Hidden`, but powershell CREATES its console and only then hides it; that moment takes foreground, so an exclusive-fullscreen game loses its mode and the player is dropped to the desktop — for a capture that is otherwise completely invisible. Firefox was never the cause (it already launches `--headless`), and this cannot be fixed by running the task whether or not the user is logged on, because headless Firefox still needs a logged-on session, which is why the principal is Interactive. A `.vbs` launcher runs it instead: `wscript.exe` has no console of its own and `WshShell.Run` with window style 0 starts powershell hidden from the outset, so nothing is created to be shown or focused, while `bWaitOnReturn` keeps the task Running for the real duration so its Last Result reflects the capture rather than reporting success the instant it detaches. `-Install` registers the launcher so a reinstall cannot regress it. Verified mid-run: wscript, powershell and firefox all report `MainWindowHandle 0`.
- **`-Install` without an explicit url baked an empty `-Urls ""` into the scheduled task.** The resolver treated a one-element array holding an empty string as an explicit target, so it beat `targets.txt` and would have launched the browser with no url at all. Caught by reading the registered task's arguments before its first run. The task now carries `-Urls` only when one was given, which is also what makes `targets.txt` useful, and the resolver filters blank entries so neither half can reintroduce it.
- **An unattended run reported "contacted: NO" on a capture that plainly contained the host.** The pattern was passed through `[regex]::Escape()` and then matched with `-SimpleMatch`, which takes it literally, so it searched for an escaped form including the backslash. Caught by running it rather than reading it. It now searches the whole log family too, since a request can be logged by a content process rather than the parent, and both directions are verified: the real host reports yes, a nonexistent one reports NO.
- **A failing capture's own output went to `Out-Null`.** When captures started coming back truncated — 4KB where 4MB was expected, 3 child logs instead of 44 — the only thing the walk could say was "capture failed; stopping", while the capture script's own "ok: NMB across N file(s) | contacted: yes" line and whatever error replaced it went to the bit bucket, so the cause was never recoverable from a walk log. The output is kept now: on failure the exit code and every line, on success the summary line that says how much was written and whether the target was contacted — a silent success is what let a 4KB capture pass for a 4MB one. `2>&1` needed care, because it turns a native command's stderr into ErrorRecords and this script runs with `$ErrorActionPreference='Stop'`, so one stderr line from a capture TERMINATED the walk before the handling below could run — worse than the `Out-Null` it replaced. The invocation runs under `Continue` and restores it in a `finally`, verified against four capture stubs including a lock skip.
- **A 0-byte log from an already-running Firefox now explains itself.** MOZ_LOG is read when a process STARTS, so a new tab in a running Firefox is never captured: measured, a second `firefox.exe` with MOZ_LOG set initialises logging — creating the file — then hands its URL to the running instance and exits, so the browsing happens where there is no logging and what is left behind looks like a capture. Turning logging on at runtime through `about:logging` URL params was also tried, with `logging.config.LOG_FILE` seeded so the page had somewhere to write: still 0 bytes. The tooling already refuses an empty log with an actionable message rather than reporting zero rules; the capture script now names the cause and points at `-ForceClose`, which is safe precisely because the close is graceful, so Firefox writes sessionstore and the tabs come back.
- **The HAR auto-export prefs were written with a doubled path, and the earlier conclusion drawn from that is retracted.** PowerShell's `-replace` takes backslashes literally in the replacement string, so the log directory was written into `user.js` with four backslashes and Firefox stored a path that cannot exist. That was the real defect, found by viewing the pref in `about:config`, and it had masked the actual question. Re-run with it fixed: `prefs.js` confirms `defaultLogDir` correct, `enableAutoExportToFile` and `forceExport` true, and the toolbox opened on the Network panel — and still no file was written, not in the log directory, not in the profile, not in Downloads, nowhere on disk. So auto-export does not produce a file on Firefox 157 with every precondition met; neither the path nor the toolbox is the cause, and exiting is not either, since `HarAutomation` exports on page load rather than at shutdown. Prefs also persist into `prefs.js` once read, so restoring `user.js` does not unset them — noted in the script.
- **A browser process exiting mid-close aborted the script after the capture was already written.** A browser spawns and retires content processes constantly, so one can exit between `Get-CimInstance` enumerating it and `CloseMainWindow` being called on it; `CloseMainWindow` then throws, and with `$ErrorActionPreference='Stop'` that aborted the whole script before the run was reported — so a successful run looked like a failure. Losing a race with a process we wanted dead anyway is success, so it is caught, and the sibling script's `Stop-Process` had the same race.
- **The Cloudflare adaptive timeout was not cleared when handling REJECTED.** The cleanup was in a `.then()`, which does not run on rejection, so a handling error left the timer pending for up to the adaptive timeout and it then fired for a url that had already failed — setting `cfSignal.cancelled`, logging "continuing with scan" while the scan had moved on, and holding the event loop open until it did. `cfSignal` is what makes that more than a stray warning: it exists because the race previously only stopped WAITING for handling while the handling itself kept going, including `page.reload()` against a page the scanner was already capturing, so a cancellation signal that trips late is a signal delivered to the wrong url. Reproduced both paths before and after. The rest of the file was reviewed for the same class and found clean: no `page.on()` listeners at all, every `Promise.race` guard paired with a clear, the detection cache bounded at 1000 entries with its interval `unref()`ed, and its `cache`/`outcomes` Maps deliberately separate so eviction cannot drop timeout records and re-permit expensive retries.
- **The 10-minute batch timer was never cleared, so every completed batch left one pending** — holding its reject closure and the event loop. `process.exit(0)` at the end of the scan masks it today, and the comment at that exit says scan completion should not DEPEND on it, so this path should not either. Verified by whether the timer FIRES, not by inspecting the handle: an earlier attempt used `hasRef()`, which does not reflect `clearTimeout` and reported the same value for fixed and broken code. The error message is unchanged, so the catch that routes a real hang to a browser restart still matches.
- **A seeded cookie could be deleted by the URL that was leaving.** The teardown refcount closed the OVERLAP — two concurrent URLs both holding a claim before either releases — but not the HANDOFF, where the last holder releases while a replacement is still seeding; the replacement then navigated ungated with nothing logged, reachable from `--max-concurrent >= 2` whenever two same-host URLs finish within a round trip of each other. Re-checking the refcount inside `removeCookies` does NOT fix it at either placement: over one CDP WebSocket the messages are processed in order, so the real interleaving is `A getCookies → C setCookie → A deleteCookies`, meaning A's READ resolves before C's WRITE does and A's decision point always precedes C's claim. Measured at both placements, with C claiming in good time by wall clock and still losing its cookie. The fix is ordering, not placement: `applySiteCookies()` and `applySiteStorage()` take a `retain` flag and register the claim themselves, synchronously, ahead of every round trip. nwss passes `retain: true` on a URL's initial seed and leaves it false on the per-reload re-seed, so the once-per-URL contract is unchanged. The late re-check stays, because it is what makes the claim effective, and both halves are pinned separately — the load-bearing check being a unit check with a stub context pinning the MESSAGE ORDER, since a real connection will not reproduce it on demand and that order is exactly what defeated the first two attempts.
- **The teardown leak warning counted keys that had not leaked.** `removeStorage()` checked the refcount twice — once filtering a `releasable` list, once per item immediately before each removal — and the gap between them is where the bug sat: a claim landing in between was skipped by the per-item check but stayed in the list the warning counted. Measured with the claim injected from inside `createCDPSession()`: "Could not clear 2" when only one key was ever at risk, asserting that a later URL would inherit a key that had in fact been retained on purpose. That matters more than the arithmetic, because the warning exists to flag real inheritance — which silently changes what a later page serves — and one that fires when nothing leaked is one that gets read as noise. One check now, recording its skips, with the leak warning as a condition rather than an `else` so nothing is reported when every key was re-claimed. `lib/cookies.js` had the same defect on its error path. A follow-up pass found the other kind that cannot leak: a cookie the browser REJECTED at seed time, which `applySiteCookies` lists by design, so the count now starts at everything releasable — the honest answer while the jar is unread — and narrows to what was really attempted once the read lands.
- **Three cookie warnings fired on configs Chrome is perfectly happy with.** A negative `expires` is CDP's own way to say "session cookie" — measured at -1, -2, -0.5 and -86400, all four stored and read back as `expires: -1, session: true`, living for the whole run, which is exactly what a load-time gate wants — and the past check fired on them and told the operator a working config would "never be sent". The boundary is 0, not now: `expires: 0` is not stored, nor is `expires: 1`. Separately, the dedupe ran on `cookieKey()`, which ignores the leading dot: measured, setting the same name on `.site` and on `site` leaves TWO entries in the jar and the apex request carries both, so the collapse dropped a cookie the config had asked for, kept the host-only one, and blamed the browser for it in the warning. Dedupe now runs on a separate `storedCookieKey()` — the browser's own identity, dot significant, domain lowercased because Chrome does fold a case-only repeat into one cookie — while `cookieKey()` keeps its leniency where it belongs, so the pair still shares one refcount identity and teardown stays symmetric. `--validate-config` shares the normalizer and drops two false warnings while keeping the genuine one. Also now reported rather than silent: a non-boolean `secure` / `httpOnly`, since `"secure": "true"` — a string, which is what a hand-edited JSON config tends to carry — produced a cookie that was quietly NOT secure.
- **A browser check failed 1 run in 8 by reading the wrong request.** The new cookie check was caught on run 8 of ten full-suite runs in prod, having passed six times before: the fixture helper handed back an APEX request after the check had navigated to a subdomain, because the gate page's inline script ends with `new Image().src = '/report?…'` and that request can reach the fixture server after the NEXT `page.goto` has already resolved at `domcontentloaded`. The module was never involved. The hit is now selected by host and path; the two other callers are not exposed, landing on a page that fetches nothing. 30 browser-group runs clean afterwards, where at the old rate 30 consecutive passes is a 1.8% event.
- **Page-sourced values were interpolated straight into log lines, one real title spanning twelve of them.** The Cloudflare quick-detection log put the page's `<title>` and a body snippet into a debug line, and those come OUT OF THE PAGE, so the log read as one prefixed line followed by eleven bare ones and a lone closing quote. That is not only ugly: every consumer that classifies log lines by prefix keeps the continuation lines while dropping the line that identified them, so a debug message leaks into output meant to exclude it — measured on a real run log, a `grep -vE '^\[debug\]'` filter let 32 such lines through, which is how it was noticed. A prefix filter cannot be made reliable against a multi-line value, so the fix belongs where the value is logged: `oneLine()` collapses whitespace runs, trims and truncates to 120 characters, applied at both call sites. Other page-sourced values elsewhere have the same hazard and are NOT audited here; the helper is available for them.
- **A single-match config lookup collapsed to a scalar and the walk searched for one character.** `Where-Object` collapses a single match to a scalar, and indexing a scalar string yields a CHAR, so a one-element `bait_detect` returned its first letter as the pattern. The dig lists had escaped it only by having more than one element. All four config lookups are wrapped in `@()` now. The run itself failed safe — INCOMPLETE, "a capture contained no loader urls", authoritative list untouched, which is what that guard exists for — but the symptom was one quiet character in the output rather than an error.
- **Under a Firefox UA, `navigator.buildID` was 8 characters where every real Firefox has 14.** The value was `'20100101'` — the Gecko trail copied out of the UA string, not a build id. Real Firefox reports a `YYYYMMDDHHMMSS` stamp, frozen at `20181001000000` since Firefox 64 for anti-fingerprinting, so the old value was catchable on length alone next to a Firefox UA. Now a single `FIREFOX_BUILD_ID` constant, and *not* part of a version bump since the real value does not move with releases. The first attempt at this referenced that constant directly inside the `evaluateOnNewDocument` block, where a Node module constant is not in scope: it threw, `safeExecute` swallowed the throw, and `buildID` ended up **unspoofed** — worse than a wrong value, since no real Firefox lacks the property. It is passed into the page as an argument like `CHROME_BUILD` is.
- **Under a non-Chromium UA, `navigator.userAgentData` was left in place — the genuine Chromium API, reporting the genuine Chrome.** The spoof returned early for non-Chrome UAs rather than removing it, so a Firefox or Safari UA still answered a Client-Hints API that Gecko and WebKit do not implement, and its contents named the real headless Chrome and its real version. It is now deleted from both the instance and `Navigator.prototype`, not stubbed: a getter returning `undefined` would leave `'userAgentData' in navigator` true, which is the own-goal already documented in this file for the `callPhantom` properties.
- **`window.chrome` removal was silently binary-dependent.** The non-Chrome branch did `try { delete window.chrome; } catch (e) {}` and trusted it. Measured: puppeteer's bundled Chrome 154 exposes `window.chrome` as `{configurable: true}` so the delete works, but the **system Chrome 145** this scanner also launches has `{configurable: false, writable: true}` — where `delete` is a no-op in non-strict mode, throws nothing for the `catch` to see, and left the full native object (`loadTimes`, `csi`, `app`) exposed under a Firefox UA: the property existing at all plus a Chromium API surface behind it. The value is now blanked when the delete does not take, which the descriptor still permits, so `typeof window.chrome` reads `'undefined'` as in real Firefox. `'chrome' in window` can remain true on such builds; that residue is unreachable from JS once the property is non-configurable, and the suite reports it with the descriptor rather than pretending otherwise.
- **The UA-consistency suite was checking the user agent against itself.** It asserted `navigator.userAgent === USER_AGENT_COLLECTIONS.get('chrome')`, which is true by construction and stays green if someone edits that collection entry — so the one string the whole spoof rests on had no real guard. Both families' UAs are now matched against a strict template that admits exactly the tokens a real reduced-Chrome or Gecko UA carries and nothing else (a stray `Edg/154.0.0.0` appended to the Chrome UA now fails, where before it passed), Firefox's `rv:` and `Firefox/` are required to agree, and each major is checked against the vendor's own release data: Google's version-history API for Chrome, Mozilla's product-details for Firefox, both network-optional. Verified first that all four live values — JS and HTTP `User-Agent`, per family — are byte-identical to the intended strings (111 and 80 characters), so the templates pin what is actually being sent rather than what is hoped for. 49 checks, 15s.
- **Under a Firefox UA, `navigator.appVersion` handed over the entire user-agent string.** appVersion is not set by this module — the browser derives it, and Chromium's rule is "UA minus the leading `Mozilla/`", which under our Firefox UA produced `5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0`. Gecko builds it a completely different way. From Firefox's own source, `dom/base/Navigator.cpp`'s `GetAppVersion` is `legacyAppVersion + " (" + platform + ")"`, where `platform` is the literal `"Windows"` / `"Macintosh"` / `"X11"` assigned in `netwerk/protocol/http/nsHttpHandler.cpp` (X11 for every `XP_UNIX` build, per its own backwards-compatibility comment) — so a real Firefox reports the short **`5.0 (Windows)`**. `nsRFPService.h`'s `SPOOFED_APPVERSION` is that same shape, which confirms the derivation independently. Chromium's long form under a Gecko UA is therefore a one-property contradiction, and a verbose one: it restates the whole UA in a place Firefox never would. Now overridden per OS for the three Firefox families. This was flagged as an open question in the preceding commit because there is no Firefox binary on this machine; reading Mozilla's source settled it rather than a guess either way, and the suite pins both the exact value and the absence of `Gecko/` from it (45 checks).
- **Two more hardcoded Chrome majors removed from `lib/fingerprint.js`.** `chrome.runtime.getManifest()` and the `userAgentData` block each carried a `'150'` fallback for a regex that cannot miss — both blocks only run when the UA contains `Chrome/`. Unreachable today, but it is the same stale-literal class `nwss.js`'s `chromeMajor` fallback comment describes: the number said 150 while the spoof was on 151 and then 154, and it would have paired a stale manifest version with a current UA the moment either guard changed. They now bail rather than invent a number, and the suite asserts `chrome.runtime.getManifest().version`'s major equals the UA's (43 checks).
- **`scripts/test-ua-consistency.js` gained a Firefox family section** (41 checks total across both families): `rv:` matching `Firefox/`, the frozen Gecko trail, `userAgentData` and the Chromium surface absent, `productSub` `20100101` rather than Chrome's `20030107`, empty `vendor`, a 14-digit `buildID` that is not the Gecko trail, `oscpu` present, and plugins/mimeTypes agreeing. Each of the three fixes above was found by this section rather than by reading the code. Note on the stealth harness: with `--ua=firefox` its self-consistency check reports OK and one third-party row (`Chrome (New)`) fails — measured identical with and without these changes, since those pages test *for* Chrome and score a non-Chrome UA's Chrome-specific rows as failures, which is the documented reason the self-consistency check exists.
- **The JS `fullVersionList` had been left on Chrome 150's brand order since the 151 bump, so JS and HTTP disagreed about something a tracker can cross-check.** The brand order is deterministic per major and hardcoded in four places that must agree — `brands` and `fullVersionList` in `lib/fingerprint.js`, and `Sec-CH-UA` / `Sec-CH-UA-Full-Version-List` in `nwss.js`. The 151 bump updated three: `brands` and both headers moved to `grease, Google Chrome, Chromium` while `fullVersionList` stayed on 150's `grease, Chromium, Google Chrome`. A site requesting the hints via `accept-ch` gets `Sec-CH-UA-Full-Version-List` over HTTP and can read `navigator.userAgentData.getHighEntropyValues(['fullVersionList'])` in JS — the same data in a different order is a contradiction no real Chrome produces. All four now derive from the same documented order.
- **`scripts/test-ua-consistency.js`** (29 checks) closes the gap that allowed it: it runs a real scan against a local server that records the request headers while the page reports its own `userAgentData`, then compares all four brand-order surfaces, all four full-version surfaces, the grease value on each, and every platform hint HTTP-vs-JS. It also re-derives the GREASE brand/version/order from the pinned major, so the constants cannot drift from the major they describe. Mutation-tested three ways: restoring the stale `fullVersionList` order, keeping 151's grease brand, and pairing a stale `CHROME_BUILD` with the new major. That third one initially **survived** — every surface derives from `CHROME_BUILD`, so a stale build agrees with itself perfectly, and `154.0.7922.174` (a 151 build behind a 154 UA) passed all 27 internal checks. It is also the precise tell `nwss.js`'s `chromeMajor` fallback comment warns about, so the suite now asks Google's version-history API whether `major.0.BUILD` is a build that actually exists and is currently served, reporting its share; that check is network-optional and skips rather than fails when offline. With it, the stale build is caught and the failure names the real served builds for the major.

## [4.0.0] - 2026-09-28

### Highlights
Four months of work since 3.5.0: 81 entries, dominated by cases where the scanner
reported something it had not actually established.

**If you only read one thing:** every domain of six characters or fewer was silently
dropped from *every* output format — `bit.ly`, `t.co`, `vk.com`, `goo.gl`, `x.com` and
`ok.ru` among them, 11 of 14 real domains tested. They were matched, counted, cached
and reported in the stats, then emitted as nothing at all. If you have scanned for
short domains and found them missing, that was this.

**New:** per-site `cookies`, `local_storage` and `session_storage`, all seeded *before*
the first request so consent walls, A/B buckets and terms-accepted gates decide the way
your config asked — with teardown scoped per URL entry and reference-counted, so
concurrent URLs on one host cannot pull each other's state out from under them. Plus an
end-of-scan Cloudflare summary, which the module had been collecting data for all along
without anyone printing it.

**Safety:** `--clear-cache` was `rm -rf` on whatever directory `cache_path` named —
demonstrated removing a directory of nothing but user files — and now removes only its
own. Two SOCKS5 upstreams sharing a username but not a password shared one relay, so
the second site authenticated with the first's credentials, silently.

**Cloudflare:** a cluster of false-success paths, each measured. A challenge reported
`solved` in 11ms with the interstitial still on screen; a failed page evaluation read as
`solved`; one transient evaluation error hid Cloudflare across a whole domain for five
minutes; an abandoned solver kept reloading the page while the scanner was capturing it.

**Breaking:** four removals and two narrowed behaviours, detailed immediately below. No
per-site config key was removed, so existing configs keep working unchanged.

Everything above, and the other 60-odd entries, are documented in full below — each with
the measurement that found it.

### Removed
Nothing in a per-site config needs changing for this release: no site-config key was removed (five were added — `cookies`, `local_storage`, `session_storage`, `interact_popups`, `capture_popups_signal`). What went away is code and documentation that could not do what it claimed:

- **`lib/domain-cache.js`** (253 lines). Its only product was one debug line, and that line was wrong: `getDetectedDomainsCount()` returned `cache.size` while eviction trimmed to 90% of `maxCacheSize`, so 250 detected domains reported as 96. Replaced in `nwss.js` by a plain `Set` built only under `--debug`.
- **The smart cache's persistence layer**, with the documented options `cache_persistence` and `cache_autosave_minutes`. It was unreachable — `nwss.js` placed `cache_persistence: false` *after* `...config`, so a user setting it to true was overridden by key order — and it carried a latent bug that would have destroyed a good cache file the day anyone enabled it. `clearPersistentCache` deliberately stays, because v1.0.57 shipped with persistence on by default and `--clear-cache` is how that leftover goes away. All caches are in-memory, which is what every supported release has actually done.
- **`cloudflare_cache_ttl`**, from `--help`, the README and `nwss.1`. It was read by nobody (the cache is built at module load with a hardcoded 300000) *and* absent from the validator's known-key list, so following the documentation earned `unknown siteConfig key 'cloudflare_cache_ttl' — did you mean 'cloudflare_phish'?`.
- **`bySolveMethod`** from `getAggregateStats()`. `byOutcome` already carried the same numbers under `solved(turnstile)`, `solved(js_challenge_wait)` and friends, derived from the same fields in the same branch order.

Two behaviours were also narrowed on purpose, both detailed below: `--clear-cache` now removes only this module's own files rather than recursively deleting whatever directory `cache_path` named, and `cloudflare_parallel_detection` runs only under `--debug`, since its result was never fed into the bypass decision.

### Added
- **End-of-scan Cloudflare summary.** `lib/cloudflare.js` has always tallied per-URL outcomes on *every* URL regardless of debug mode — its own comments state this exists so the orchestration layer can print a summary "without threading per-URL results back" — but nothing ever called `getAggregateStats()`, so the numbers were collected and discarded every run. nwss now prints them, e.g. `Cloudflare: 3 of 47 URL(s) met Cloudflare — solved(js) 2, timeout 1 (handling avg 1800ms, max 9200ms)`. Info level rather than `--debug`, matching the dig-failure report: a run where challenges were hit or timed out is worth seeing by default. Silent when nothing met Cloudflare, since `total` counts every URL that passed *through* the handler (a plain page lands there as `no_indicators`) — the `no_indicators` and `skipped(non-http)` outcomes are subtracted so a clean run prints nothing. Labels come from the module's own `buildOutcomeString()` keys rather than re-invented names, so they cannot drift from it.

- **`scripts/test-stealth.js` now runs a self-consistency check** for whichever `--ua` is selected, before the third-party targets. The bot-detection pages are built to catch headless *Chrome*, so a non-Chrome UA scores their checks as "doesn't look like Chrome" and real contradictions hide in that noise; this instead asks whether the spoofed identity is coherent with itself — Chromium-only APIs under a non-Chrome UA, Firefox-only props present or missing for the wrong family, platform/vendor disagreeing with the UA, and a plugins/mimeTypes mismatch. Offline (`about:blank`), so it costs nothing and needs no third-party page. It also asserts collection **types** (`plugins instanceof PluginArray`, `mimeTypes instanceof MimeTypeArray`) rather than just lengths, since a plain array passes a length check and fails `instanceof`. It is what surfaced every fingerprint fix in this release, and all families now report OK.
- **Per-site `cookies` — set cookies BEFORE the page loads.** Sites that gate content on a cookie read it during the initial document load (consent walls, A/B buckets, "seen the interstitial" flags, paywall meters); setting a cookie after navigation is too late, because the gate has already decided. Cookies are now applied to the browser context before `page.goto()`, so they ride on the very first request. Two forms: short `"cookies": {"consent": "granted", "ab_bucket": "b"}`, which scopes each cookie to the site's own host at path `/`; and long `"cookies": [{"name": "sid", "value": "abc", "domain": ".example.com", "path": "/", "secure": true, "httpOnly": false, "sameSite": "Lax", "expires": 1790000000}]` for full control, where only `name` is required. Non-string values are stringified, since a JSON config naturally carries `"n": 1`. `sameSite` accepts any casing and `None` implies `secure` (Chrome drops the cookie silently otherwise). Cookie names and values are rejected if they carry control characters or the delimiters that would let a value break out into another cookie or header — the same guard class as the CR/LF header filter in `lib/curl.js`. Ordering matters and is handled: seeding runs **after** `clear_sitedata` (which would otherwise wipe it) and is **re-applied before each reload**, so load #2 measures the same gated page as load #1 rather than an un-authenticated one. Invalid entries are reported and skipped rather than aborting the scan, and `--validate-config` checks the shape through the same normalizer the runtime uses, so the two cannot disagree. New module `lib/cookies.js`. Verified end-to-end against a local gate server: the first document request already carried all four cookies and the cookie-gated resource was fetched, and all four reload shapes (`reload`, `reload`+`clear_sitedata`, `reload`+`forcereload`, both) show the cookie on 3 of 3 document loads.
- **Seeded cookies are scoped to their `url` entry.** One browser serves the whole run and nwss creates no per-site browser context, so a cookie set for one entry persisted on the shared context: measured, a second site on the **same host** that declared no cookies still received `consent=granted` from the first, which can change what that page serves and therefore what the scan captures — silently. Cookies seeded for a URL are now removed once it finishes, in the guaranteed-cleanup block so a failed or timed-out URL cannot leak them either. Reloads are unaffected (removal happens after all reloads), and each URL in a multi-URL entry re-seeds its own. Cookies the *page* sets are untouched; only the keys nwss seeded are removed. Teardown is **reference-counted**, because `processUrl` runs up to `--max-concurrent` URLs at once against that one shared context: without it the first URL to finish deleted a cookie a concurrent same-host URL was still using, and that URL's next load arrived with no cookie at all (measured — two same-host entries, the slower one's reload came through empty). A cookie is only removed once the last URL relying on it is done, with the leading `.` of a domain ignored so host-only and domain forms share one slot. Note `browserContext.deleteCookie()` maps to `Storage.setCookies` and requires complete `Cookie` objects, so the live cookies are read back and matched on name/domain/path (leading-dot-insensitive) rather than passing a partial triple, which fails with "mandatory field missing".
- **Cookie config problems are reported instead of failing silently.** `expires` is seconds since the epoch; a **past** value makes the browser discard the cookie with no error anywhere (confirmed: the cookie simply never arrives), and a **millisecond** value only appears to work because Chrome clamps it to its 400-day cap. Both now warn, as do unrecognised per-cookie keys (`secue`, `Domain`, `url`) that would otherwise be dropped in silence, leaving a cookie that is not the one the config asked for. Re-seeds before a reload no longer repeat the same config warning once per reload.
- **Per-site `local_storage` and `session_storage` — seed Web Storage BEFORE the page loads.** The sibling of `cookies`, for gates that read Web Storage instead of a cookie (terms-accepted flags, CMP consent state, `visited` markers that suppress an interstitial). Short form `{"rta_terms_accepted": true}`, or a long form array of `{name, value}` for keys awkward as JSON object keys. Values are stringified the way `setItem()` requires: numbers and booleans via `String()`, and objects/arrays via `JSON.stringify`, since a JSON blob under one key is the usual shape for consent state — `{"cmp": {"ok": true}}` stores the JSON rather than `"[object Object]"`.
- **Storage seeding survives `clear_sitedata` and every reload with no re-seeding.** Storage is origin-scoped and only reachable from a document on that origin, so unlike a cookie it cannot be planted on the browser context before navigating. Seeding therefore installs a `page.evaluateOnNewDocument()` hook, which runs before any of the page's own scripts on *every* document the page creates. Verified with a page whose first inline script reports what it read: values present on both loads of a `reload: 2` run, and still present with `clear_sitedata` **and** `clear_sitedata_full_on_reload` wiping storage before each one. `cookies` needs an explicit re-seed for that case; this does not.
- **Seeded storage is scoped to its `url` entry, written only in the top document, and matched on the registrable domain.** `evaluateOnNewDocument` runs in child frames too, so the injected code writes only when it is the top document — a cross-origin ad frame would otherwise get the entries written into *its* origin (verified: an iframe on another origin reads `null` while the main document reads the seeded value). The host comparison is against the registrable domain resolved with `psl`, not the origin or the exact hostname, because an `http`→`https` upgrade, a port change and a redirect to another subdomain are all a different origin but the same site — and all three are routine. Stricter matching was measured skipping the seed outright: a target that 302s to another host read the key back as `null`. This gives storage the same breadth a `.domain.com` cookie has, while a redirect to a *different* registrable domain is still refused (verified both ways). IP literals match exactly, since `psl.get('127.0.0.1')` returns `'0.1'` and `'10.0.0.1'.endsWith('.0.1')` is true, which would otherwise span unrelated hosts — `net.isIP()` guards it. `localStorage` persists per-origin in the `userDataDir` for the whole run, so it is removed once the URL finishes — verified by a second site on the same host declaring no storage, which reads `null`. Because the landed origin varies per URL, teardown clears every origin the site's URLs were seen on; with two URLs of one site landing on different subdomains, the last one out clears both. Reference-counted like cookies, so a URL that finishes early cannot tear down a key a concurrent URL of the same site still needs, and the count is released even when the browser-side removal fails (a closed page), since a retained count no later URL could clear would leak for the rest of the run. Removal goes through CDP with explicit origins rather than an in-page eval, which by teardown time would be running on the wrong document. `sessionStorage` needs no teardown: it is scoped to the page, which closes. Config problems are reported through the same normalizer `--validate-config` uses, so the two cannot disagree.

### Changed
- **The smart cache's persistence layer is gone (~170 lines), because it could not run.** `nwss.js` built the cache with `cache_persistence: false` placed *after* `...config`, so a user setting `cache_persistence: true` in their own config was overridden by key order and got false anyway — making `_loadPersistentCache`, `savePersistentCache` (with its 10-second debounce, `pendingSave`/`saveInProgress` state machine, pid-suffixed temp and atomic rename), `_setupAutoSave`, the `destroy()` save branch and the `persistenceLoads`/`persistenceSaves` counters all unreachable. A latent bug went with them: `destroy()` cleared `saveTimeout`, called `savePersistentCache()` — which early-returns on the debounce — and then `clear()`, so the final save was either lost or, if the process lingered, fired against emptied caches and wrote an empty file over a good one. That would have surfaced the day anyone enabled the feature. `cache_autosave_minutes` is removed from the README and man page, since it configured a timer that never started, and the dead `Persistence - Loads: 0, Saves: 0` debug line is gone. **`clearPersistentCache` deliberately stays**: v1.0.57 (2025-08-06) shipped with persistence *on by default* — verified by tagging, it is the one release that contains the enable-by-default commit and not the hardcoded-off one that followed two days later in v1.0.58 — so `.cache/smart-cache.json` can still exist on a machine that ran it, and `--clear-cache` is how it goes away. A leftover is otherwise inert now, since nothing reads it: confirmed by running a scan against a directory holding a valid-looking cache file and getting zero load activity, then clearing it with the flag. `cache_path`'s documented meaning is corrected to match — it locates that leftover rather than a live cache. All caches are in-memory (domain / pattern / response / nettools / similarity / regex / request LRUs), which is what every supported version has actually done.

### Fixed
- **A solved JS challenge was reported unsolved, because of a 10-second wait for a redirect that had already happened.** After `waitForJSChallengeCompletion` succeeds, `attemptChallengeSolve` waited up to 10000ms for a post-challenge navigation — but the corrected completion predicate only reports success once every interstitial marker is gone, which is what the redirect *produces*, so that wait timed out in full on every solve. Measured against a challenge that clears itself in place: detection took **1013ms** while the solve returned at **11008ms**. Worse, the whole solve runs inside `FAST_TIMEOUTS.CHALLENGE_SOLVING` (12000ms), so a challenge clearing in 4s took 14005ms and the caller saw **`success=false method=null`** at the 12s cap — a challenge that had in fact been solved, reported as a failure, with the method lost from the scan summary. The wait is now `TIMEOUTS.POST_SOLVE_REDIRECT_MS` (2000ms), enough to catch an imminent redirect while leaving the cap for the detection that matters: the 1s case returns in **3004ms** and the 4s case in **6017ms**, both `success=true method=js_challenge_wait`. Pinned by 6 checks; restoring the 10000ms value turns 4 red, including the false failure itself. A re-review checked the case the wait exists for, rather than assuming the shorter window is harmless: with the redirect firing at **3500ms**, well outside the 2000ms window, the solve returns at 2505ms and the page still reaches the target — title `Real Site`, the target's own subresource request captured, no unhandled rejection — because the scanner's delay phase continues after the solve returns. A redirect inside the window is still waited for (1503ms for one firing at 1500ms).
- **Measured and left alone, since the numbers say there is nothing there:** the DOM and CDP work this module does per URL is not worth optimising. On a 304KB, 4000-element page, `quickCloudflareDetection` takes **2ms**, `analyzeCloudflareChallenge` **2ms** and `page.cookies()` **1ms** (0-1ms on a small page), and a cached detection — what every URL after the first on a host pays — is **0ms**. So the domain-level cache, the short-circuit detection stages and the debug-only cookie reads are all already far below the noise floor; every second this module spends is in a deliberate wait, which is where the fix above was found.
- **The phishing bypass reported success without checking whether it had worked.** `handlePhishingWarning` clicks `a[href*="continue"]` and then waits for navigation — but `safeWaitForNavigation` **swallows its own timeout** (it catches and, under `--debug`, warns), so reaching the next line only means the click didn't throw. `result.success = true` was asserted there unconditionally. Measured against an interstitial whose continue link is an in-page anchor (`href="#continue-anyway"`, which is what a mis-matched selector effectively gives you): `attempted=true success=true error=null` after 9031ms, with the title still `Attention Required!` and the phishing text still in the body — and the scan recorded `solved(phishing_continue)`. It now re-analyses the page and claims success only if the warning is gone, treating an inconclusive re-check (the analyzer's own error shape) as failure rather than as a bypass. This was the last of the four solve paths still asserting success from the absence of an exception; the other three were fixed above.
- **A missed Turnstile checkbox cost 9 seconds of the 12-second solve budget, twice per attempt.** `clickInShadowDOM` waited its full `waitMs` on *each* of the six candidate selectors its two call sites pass, but that wait exists for **delayed rendering** — a property of the frame, not of each selector: once the widget has rendered, every candidate is queryable at once. Measured on a Turnstile container with no pierce-able checkbox: **9011ms** for one call, and `handleTurnstileChallenge` reaches it twice in one attempt (embedded-iframe path, then legacy path) for **~18s** against the 12000ms `FAST_TIMEOUTS.CHALLENGE_SOLVING` cap on the whole solve — so the attempt was killed before its completion check ever ran. The first candidate now gets the full wait and the rest get a 250ms probe: **2757ms**, leaving room for both calls inside the cap. Verified not to cost coverage: a later candidate present from the start is still clicked, and so is one that renders **800ms** late.
- **`bySolveMethod` was tallied on every URL and read by nobody.** `byOutcome` already carries the same numbers under `solved(turnstile)`, `solved(js_challenge_wait)`, `solved(legacy_checkbox)` and `solved(phishing_continue)` — `bumpAggregate` derived both from the same fields in the same branch order — and nwss's summary prints only `byOutcome`. Removed, along with the two header comments that advertised the breakdown it was for.
- **Checked and deliberately left alone:** a Cloudflare 5xx origin-error verdict is cached per hostname like any other detection result, so every URL on a dead origin reports `error_page(5xx)` for up to 5 minutes without re-checking. That matches the module's domain-level caching design and a 5xx origin failure really is host-wide, so the only cost is a slow recovery if the origin comes back inside the TTL. And the detection cache keys on the **live** page URL while the outcome cache keys on the **requested** URL: after a redirect those differ, but each is right for its own lookup — detection describes the page that was analysed, while the outcome cache is consulted with the requested URLs that later config entries will supply.
- **One transient page-evaluation failure hid Cloudflare on an entire domain for five minutes.** `quickCloudflareDetection` runs its detection through `safePageEvaluate` with `maxRetries: 1` — the one path in the module that never retries — and `safePageEvaluate` resolves with its **defaults object** when every attempt fails. That object carries no `hasIndicators` key, and the cache write below it was unconditional, so a single failure stored "indicators: undefined" under the **hostname** and every later URL on that host read it back as a clean page for the full 300s TTL, with no second detection attempted. Measured: `URL1 (evaluate threw once): CF handling ran? false` → `URL2 (evaluate healthy): CF handling ran? false`, `evaluate calls total: 1`. The error it sees most often is `Attempted to use detached Frame`, which is what Cloudflare pages produce *because they navigate* — so detection fails hardest exactly where it matters and the domain is then recorded as clean. A detection that never ran is now not cached and not reported as `no_indicators`: the outcome tag is `detection_failed`, and when the user explicitly set `cloudflare_bypass`/`cloudflare_phish` the handler falls through and attempts handling anyway, because skipping on a transient glitch is how a challenge page gets scanned as if it were the real site. A successful detection is still cached per hostname (verified: 1 evaluation serves 2 URLs). A re-review caught the knock-on effect of the honest label: `detection_failed` used to arrive as `no_indicators`, which nwss's end-of-scan Cloudflare summary suppresses, so relabelling it would have made a scan of Cloudflare-free pages announce **"1 of 1 URL(s) met Cloudflare"** off a single flaky evaluation. Whether such a URL met Cloudflare is precisely what isn't known, so it no longer counts toward that total and gets its own line instead — `detection did not complete on N URL(s)` — which is worth having, since those pages were never bypass-checked.
- **The JS-challenge wait reported success in 11ms on pages it had not solved, and made the Turnstile solver unreachable.** `waitForJSChallengeCompletion`'s predicate tested only for the *absence* of `Checking your browser`, `Please wait while we verify`, `.cf-challenge-running` and `[data-cf-challenge]` — all four absent from a Turnstile or managed-challenge interstitial, so it resolved on the first poll. Measured against a fixture carrying the real challenge-platform script and a `Verify you are human` body: `success=true after 11ms` on a page still titled `Just a moment...`, Turnstile widget still present, no token; `attemptChallengeSolve` then returned `success=true method=js_challenge_wait` and burned a further 10006ms in a post-challenge `waitForNavigation` that had nothing to wait for. The scan recorded `solved(js_challenge_wait)` and captured the interstitial's requests instead of the site's, and the aggregate summary over-reported solves. Two fixes: the predicate now requires **positive** evidence — no challenge-platform script, no challenge chrome, no Turnstile widget, and a title/body that no longer reads as an interstitial, which is what a JS challenge completing and navigating to the target actually produces; and because `isJSChallenge` is set by the mere presence of that script, which real *interactive* challenges also load, the passive wait is **deferred behind** the Turnstile and legacy methods on any page carrying a Turnstile widget, then retried last (a managed challenge can still clear on its own, so it stays a real path). After: the same fixture gives `success=false` after waiting out its timeout, and `attemptChallengeSolve` honestly reports `success=false method=null`. A page with no challenge markers is still reported complete, so real JS-challenge detection is intact.
- **A failed evaluation read as "challenge solved".** `checkChallengeCompletion` returned `{ isCompleted }` straight from `safePageEvaluate`, and its callers test `if (completionCheck.isCompleted)` — so the truthy defaults object meant `handleLegacyCheckbox` and the container-Turnstile path reported success whenever the post-click evaluation failed. Clicking a Cloudflare checkbox is precisely what detaches the frame, so the failure arrived exactly when a false success was most damaging; the fallback object even carries `isChallengeCompleted: false`, the honest answer, unread. The in-page function now returns a tagged `{__cfCheck: true, domClear, hasToken}` so a result that really came from the page can be told apart from the failure shape, and a failure reports `isCompleted: false` plus the reason. Same false-success shape removed from `handleEmbeddedIframeChallenge`, whose completion predicate ORed in `!body.textContent.includes('Verify you are human')` — true on any challenge page not using that exact phrase, so it reported success whether or not the click did anything. It now waits for the Turnstile token alone.
- **`cf_clearance` was being read where it cannot be seen.** Two predicates tested `document.cookie.includes('cf_clearance')`; `cf_clearance` is HttpOnly, so that term could never fire and quietly reduced both checks to DOM signals only. Both now read it over CDP via the module's existing `getCfCookieState`, which does see it — including as a fallback in the iframe path, since a managed challenge can clear without ever creating a Turnstile input.
- **The adaptive timeout abandoned the solver, which kept reloading the page.** `handleCloudflareProtection` races `performCloudflareHandling` against a 15s/25s adaptive timeout, but the race only ever stopped *waiting*; nothing cancelled the work, and `runWithRetries`' `betweenAttempts` hook calls `page.reload()`. Measured with `cloudflare_max_retries: 5`: after the call returned at 25006ms, the abandoned ladder reloaded the page **3 more times over the next 44 seconds** — while nwss was in the delay/interaction/capture phase for that same page, discarding requests mid-collection. A cancellation signal is now tripped when the timeout fires and threaded into both stages and the retry harness, which re-checks it after the backoff specifically so the destructive step is skipped. After: **0** page calls once the scanner has moved on. An uncancelled ladder still runs all its attempts and still reloads between them. Two things a re-review turned up: the signal check shares its `else` with the stage's "Challenge bypass disabled" debug line, so a cancelled stage was blaming the config for what the clock did (it now says the caller stopped waiting); and the cancellation stops the ladder but not the attempt already in flight, which was measured both ways before deciding to leave it — with hanging selectors the abandoned attempt makes **8 further calls over 19s**, all `waitForSelector`/`waitForFunction` reads, and with selectors that resolve it makes **0**. No clicks and no reloads land after cancellation in either case, so the destructive part is covered and threading the signal deeper would only trim harmless waits.
- **Two documented Cloudflare options that did not exist as documented.** `cloudflare_max_retries` was given as default **3** in `--help`, README and `nwss.1` while `RETRY_CONFIG.maxAttempts` is **2** — the same drift as `whois_max_retries`. And `cloudflare_cache_ttl` was documented in all three places but read by nobody (the cache is constructed at module load with the hardcoded 300000) *and* absent from `KNOWN_SITE_CONFIG_KEYS`, so following the documentation earned a typo warning: `unknown siteConfig key 'cloudflare_cache_ttl' — did you mean 'cloudflare_phish'? — value will be ignored at runtime`. The docs now state 2, the phantom option is gone from all three, and `cloudflare_parallel_detection` is described as what it is — a `--debug` diagnostic that does not feed the bypass logic. A duplicated `cloudflare_retry_on_error` line in `--help` is also gone.
- **`parallelChallengeDetection` did uncapped full-DOM text extraction for a result production threw away.** It was the one body-text read in the file with no 2KB cap, against the header's own "Capped body.textContent" note, and `nwss.js` called it on every Cloudflare-configured URL while logging the answer only under `--debug` — `handleCloudflareProtection` runs its own detection regardless. The read is now capped like every other, and the call is `forceDebug`-gated.
- **Two comments that my own change made false.** The `TIMEOUTS` note explaining why the `ADAPTIVE_TIMEOUT_*_WITHOUT_INDICATORS` constants were deleted, and the matching claim in `handleCloudflareProtection` that "hasIndicators is guaranteed truthy here", both rested on the no-indicators early return catching every such case. The detection-failure fall-through breaks that: it reaches the adaptive-timeout block with `hasIndicators` false. The branch taken is still the right one (that path is explicit config by definition, so it gets the WITH_INDICATORS value and the deleted constants stay deleted), but the reasoning a future reader would rely on was wrong, and the debug line now prints `indicators: unknown (detection failed)` rather than a bare `false`.
- **Not changed, for the record:** `PER_URL_TIMEOUT_MS` still has no Cloudflare term, and does not need one. Measured, the module's whole ceiling is 2s quick detection + 25s adaptive race = **27s**, against 30s of slack plus the 45s restart grace; the worst realistic configs leave a 48s margin. That is unlike flowproxy, where a single config value could push one URL's spend to 185s.
- **`flowproxy_page_timeout` and `flowproxy_nav_timeout` could not raise anything, and the debug line reported values that were never applied.** Both options exist because protection pages are slow — `nwss.js` deliberately sets fast-failure ceilings of `min(timeout, 15000)` / `min(timeout, 25000)` for normal pages, and the flowProxy block that follows is meant to lift them. It ran them through `Math.min` against nwss's own constants instead, **and against the crossed pair**: the page timeout was capped by `DEFAULT_NAVIGATION` (25000) and the navigation timeout by `DEFAULT_PAGE` (35000). So both documented **45000** defaults were silently capped to 25000/35000, and raising either option above its cap did **nothing at all** — `flowproxy_page_timeout: 60000` and `90000` measured as **25000 / 35000** actually handed to puppeteer. The adjacent `--debug` line printed the *requested* numbers, so a run reported `Applied flowProxy timeouts - page: 45000ms` for a page that got 25000 — the log actively confirmed a setting that wasn't in force. The clamp is gone; the configured values are applied as configured, and the log now names them plus the ceilings they replace. Nothing replaces the clamp because the blast radius was checked rather than assumed: every `goto`/`reload` in the repo passes an explicit timeout (`<= min(timeout, 15000)`), so the default **navigation** timeout is not read by anything today, and a sweep of every implicit-wait call across `nwss.js` and `lib/` found exactly **one** consumer of the default **page** timeout — `lib/cloudflare.js`'s `page.click(selector)` — where a large value is the user's own config choice. `getFlowProxyTimeouts` now validates like `getFlowProxyOverheadMs`, so a zero, negative or non-numeric value falls back to the default rather than reaching `setDefaultTimeout`, where a negative would make every implicit wait fail instantly. Verified in a real browser by wrapping both setters: **60000 / 90000** applied where the clamp gave 25000 / 35000, the debug line matching, the rule still emitted and 0 emergency restarts. Pinned by 11 more checks in `scripts/test-flowproxy-budget.js` (30 total), which extract the two `setDefault*` argument expressions from `nwss.js` and evaluate them rather than re-typing them; mutation-tested three ways — restoring the crossed clamp (4 red, the original bug), dropping the input validation (2 red), and swapping the two applied values (2 red). Note this does not change the per-URL budget: the navigation default is unused, and the one page-default consumer is on the Cloudflare path, which `PER_URL_TIMEOUT_MS` does not model at all.
- **The hang check could kill a page in the middle of a flowProxy wait the config had asked for.** `flowproxy_detection` deliberately spends time: `handleFlowProxyProtection` pays a 1500ms page-load settle on every call, then — when protection is detected — `flowproxy_delay` for a rate limit (30000 default), `flowproxy_js_timeout` for a JS challenge (15000), and `flowproxy_additional_delay` to settle (3000), with `nwss.js` adding its own capped post-delay wait of up to 3000 in the same pass. None of it appeared in `PER_URL_TIMEOUT_MS`, which budgets the page timeout, `delay`, interaction, the click phase and the dig drain, and which feeds the hang check's `restartAfterMs` — so flowProxy's waits looked like a hang to the very watchdog that is supposed to distinguish the two. Measured: `flowproxy_delay: 120000` (a plausible value; the module's own rate-limit branch exists because these pages ask for minutes) spends **~182.5s** against a restart deadline that sat at its **150s floor**, so an **emergency browser restart fires ~32s before the wait it is waiting for completes** — losing the page, its captured requests and the rate-limit progress, and then re-requesting the same rate-limited site with a fresh browser, which is the one thing guaranteed to make a rate limit worse. Defaults were safe only by luck of the 30s slack term (**92.5s** spend against the 150s floor). The numbers now live in `lib/flowproxy.js` as an exported `getFlowProxyOverheadMs(siteConfig)`, next to the code that spends them rather than copied into the caller — the copy that already existed drifted, with `--help` documenting `flowproxy_additional_delay` as 5000 while the module uses `FAST_TIMEOUTS.ADDITIONAL_DELAY_DEFAULT` of 3000 (help text corrected). Defaults now reserve **52.5s** (deadline 167.5s), and the 120s case **172.5s** (deadline 257.5s, clear of its 182.5s spend). The term is **not** multiplied by `reloadCount`: both spend sites are on the initial-load path — the handler before the delay/interact phase, nwss's wait inside it — and the reload loop touches neither, so it is one-time like the click phase. All-branches-taken is the right bias for a ceiling that must not fire early; an undetected page really pays only the 1500ms settle. Pinned by `scripts/test-flowproxy-budget.js` (19 checks), which **extracts nwss.js's shipped `Math.max(...)` and `restartAfterMs` expressions from source and evaluates them** rather than re-typing the formula, so deleting the term goes red instead of passing against a copy; it also reproduces the pre-fix overrun as an explicit check. Mutation-tested four ways — deleting the `+ FLOWPROXY_OVERHEAD_MS` line (3 red, the original bug), zeroing the settle wait (7 red), hardcoding `flowproxy_delay` to its default (2 red), and loosening the `=== true` gate (1 red). Verified end to end against a fixture serving vendor headers, a `flowproxy_session` cookie, a rate-limit signal and a never-clearing `Processing` state, so every branch is taken: all three waits run (4000 + 2000 + 1000ms), a temporary probe reports the live term as **9500ms** with detection on and **0** with it off, the rule is still emitted, and **0** emergency restarts fire.
- **The debug log was 15% out of chronological order, because two writers shared it with different buffering.** `nwss.js` batches its lines through `bufferedLogWrite` and flushes every 2s with one `appendFileSync`; `lib/nettools.js`'s `logToConsoleAndFile` appended each line immediately with its own. Measured on a 40-URL `--debug` scan: **47 single-line appends** from nettools against **26 batched calls carrying 120 lines** from nwss, and **26 of 167 lines out of order** — with every inversion sitting exactly on a `nettools → nwss` boundary and **none** within either writer, which is what identifies mixed buffering as the cause rather than concurrency. For a log whose purpose is reconstructing what happened in what order, that is worse than the syscall cost: an immediate line lands ahead of buffered lines written up to 2s earlier, so reading the file to decide whether a dig finished before a navigation gives the wrong answer. `createNetToolsHandler` now takes an optional `logWrite`, which nwss supplies as `bufferedLogWrite` at all three call sites, so both writers share one buffer and one flush. After: **0 appends from nettools, 0 inversions**, and the same **167** lines in the file with the same 120/47 split — nothing dropped, just batched. The direct-`fs` path is kept for the library shape this module shipped with (only `fs` + `debugLogFile`), verified both ways: 21 lines on disk with no writer passed, 21 handed to the writer and 0 written directly when one is. Write amplification scales with domains × log lines, so the saving grows with real configs; the fixture here only gives nettools one or two domains.
- **A warning when the local SOCKS5 relay count gets high.** Keying relays on the full credential set (see the fix above) means one loopback listener per *distinct* credential set — correct, and for a proxy product that rotates a session token in the password that is one relay per site. Each holds a listening socket and file descriptors that compete with Chrome's: comfortable against a Linux default of 1024+, tight against macOS's default soft limit of 256. `lib/socks-relay.js` now warns **once** past 64 open relays, naming the likely cause (configs varying the password per site), and never blocks — a hard cap would fail scans that legitimately need many. The notice resets when the relays are torn down, so a caller running several scan phases in one process is judged on each phase's own count. Pinned by four checks in `scripts/test-socks-relay-identity.js`: silent at 63, exactly one warning at 64, still one at 70, and a fresh set after teardown warns again. Mutation-tested: removing the warning, never setting the one-shot, moving the threshold, and dropping the teardown reset each turn the matching check red.
- **Two SOCKS5 upstreams sharing a username but not a password shared one relay, and the wrong credentials.** Chromium cannot authenticate to a SOCKS proxy, so `lib/proxy.js` points it at a local no-auth relay that does the upstream auth — and `lib/socks-relay.js` keyed those relays on `host:port:username`, leaving the password out of the upstream's identity. Measured: `socks5://user1:passAAA@10.0.0.9:1080` and `socks5://user1:passBBB@10.0.0.9:1080` both resolved to **relay port 40789**, so the second site's traffic authenticated as the first's credentials, silently and with no warning, while a different *username* correctly got its own relay. Two realistic ways to hit it: credentials rotated for some sites but not others, and proxy products that encode a session or rotation token in the **password** with a constant username — per-site rotation then collapses onto whichever session started first, which is the opposite of what configuring per-site proxies is for. The password is now part of the key as a 12-char SHA-256 prefix, so no credential is held in a Map key that could reach stats output or a heap dump. `getRelayStats` reports a stored `display` field (`host:port`) instead of deriving redaction with `key.replace(/:[^:]*$/, '')` — that stripped the *last* segment, so appending the hash would have started exposing the username in output that previously hid it. `prepareSocksRelays` now dedupes via the relay module's exported `upstreamKey` rather than its own copy of the rule: the two happened to agree before, and a stale copy turns a silent wrong-credential reuse into a silent connection failure (`getRelayPort` finds no relay for a key nobody started). Pinned by `scripts/test-socks-relay-identity.js` (7 checks, no network): distinct passwords get distinct relays, a different username still does, identical credentials still share one, the key carries no cleartext, stats leak neither field, and `prepareSocksRelays` starts exactly one relay per distinct credential set. Mutation-tested four ways — dropping the password from the key, reverting the stats redaction, constant-folding the hash, and restoring proxy.js's private key copy — each turns the expected checks red.
- **The injected JS-redirect detector installed a fresh MutationObserver on every navigation attempt.** `navigateWithRedirectHandling` adds its detector with `page.evaluateOnNewDocument` on each call, and `nwss.js` calls it up to three times for one page: the initial navigation, an options fallback, and a resolved-URL retry. `evaluateOnNewDocument` does **not** replace a previous script — measured directly, three installs run three times per document — and this puppeteer version returns no handle to remove one, so the only place to de-duplicate is inside the injected script. Every page that needed the fallback or retry therefore carried two or three `MutationObserver`s on `<head>` doing identical work, plus duplicate `DOMContentLoaded` listeners. Measured by wrapping `window.MutationObserver` from a script installed before the detector: **1 / 2 / 3** observers across three navigations before, **1 / 1 / 1** after. The per-document flags (`_jsRedirectDetected` and friends) stay unguarded, since resetting those is free and they are the state the poll loop reads. **De-duplicating has a trap that the first version of this fix fell into**: the surviving observer belongs to the copy that installed *first*, and each copy closes over the `maxWaitMs` of the call that installed it, so the first call's wait budget became authoritative for every later navigation on that page. `noteMetaRefresh` rejects a refresh whose delay exceeds the budget, so with `/x` navigations at `js_redirect_timeout: 300` followed by a page carrying `content="2;url=..."` at 3000, the stale 300ms budget rejected the 2s refresh and detection silently stopped: **detected=false on all three attempts and the page never followed the refresh**, versus working on all three without the guard. nwss's three call sites pass the same `siteConfig` today so this was latent, but it is exactly what a caller with a longer fallback timeout would hit. The budget therefore lives on `window` and every copy updates it, so one observer serves whatever the current call asked for. Pinned by `scripts/test-redirect-detector.js`, which counts real constructions rather than trusting the guard's own sentinel, and goes red (1/2/3) with the guard removed.
- **`handleRedirectTimeout`'s cross-domain-only rule is now written down.** A navigation timeout that landed on a different *domain* is reported as recovered; a same-domain URL change is not, and `nwss.js` routes that into the failure path (proxy diagnostics, the URL counted as failed) even though a page is loaded and its requests were captured. That is deliberate — a cross-domain landing is positive evidence the original navigation was redirected away, while a same-domain change cannot be told apart from an in-page route change or a load that genuinely timed out — but nothing said so, and the asymmetry reads like an oversight. Comment added recording both the reasoning and the cost of widening it.
- **`--cdp` said nothing when it could do nothing.** `createCDPSession` returns early unless `--debug` is also on — correctly, since the session's only consumer is a debug-gated `Network.requestWillBeSent` listener and `--cdp` is documented as enabling CDP *logging*. But a user running `--cdp` alone got no session, no output and no hint the flag was inert. It now warns **once per process** (not per URL) that CDP was requested with `--debug` off and setup was skipped — and honours `--silent`, since this is a configuration notice rather than an error and `--silent` is documented as suppressing normal console output (the *failure* warning further down stays unconditional: a quiet run still needs to know CDP broke). Verified across all three combinations on a two-site config: `--cdp` alone gives exactly **1** warning; `--cdp --debug` gives 2 sessions created, 2 detached, 0 warnings and working request logs; no flag at all stays silent. Also removed a dead `let cdpSession = null;` in `nwss.js` (the live variable is `cdpSessionManager`) — invisible because this repo's eslint config flags undefined identifiers but not unused ones, and refreshed the module header, which claimed "Tested with Puppeteer 13+" and "Chrome/Chromium 60+" in a repo pinned to Puppeteer 25 / Chrome 154 and quoted a "~10-20% overhead" that predates the skip-without-debug short circuit.
- **A hard-capped interaction kept clicking the page after the scanner moved on.** `performPageInteraction` races the interaction against a work-aware ceiling, but the race only ever stopped *waiting* for the work — nothing cancelled it. Measured against a stub page whose every call takes 3s: the call returned at 15004ms as designed, then the abandoned interaction made **3 further page calls over the next 9s**, and its own overrun warning arrived at 18068ms, 3s after the caller had already logged the cap. Requests triggered by those late clicks land after `matchedDomains` is snapshotted. A cancellation signal is now threaded into the loops where the time actually goes — `humanLikeMouseMove`'s per-step loop (15+ CDP round-trips in one call), `simulateScrolling`'s and `performContentClicks`' — because the impl's own cooperative check runs only *between* high-level steps and so could never stop a run in progress. After: **1** further call, which is the floor (the call already in flight cannot be recalled) and the overrun warning lands 77ms past the cap instead of 3s. `simulateScrolling` checks the signal in its inner smoothness loop as well as per scroll, since that inner loop is where its CDP round-trips are — it matters for direct callers (the JSDoc example uses `smoothness: 8`; `performPageInteraction` itself passes 1–2, where the per-scroll check already suffices). One `mouse.move` still escapes cancellation: the final resting-position move after the scroll block, a single bounded call.
- **The interaction budget was three different numbers.** `computeInteractionCeilingMs` is work-aware (15000ms for a default config, 21700 with content clicks, 30700 with `realistic_click`, 46900 at high intensity with 5 clicks) and `nwss.js` reserves exactly that per URL as `INTERACTION_OVERHEAD_MS` — but the impl enforced a hardcoded `MAX_INTERACTION_TIME = 15000`, so every heavier config was silently truncated at 15s however much had been budgeted, and the reservation was never usable. The impl now receives the caller's budget (the ceiling minus a 750ms margin, so it winds down between steps rather than being abandoned mid-step); a direct caller that passes no control object still gets the old 15000. The slow-interaction warning was a third number — a flat `> 8000ms`, which warned about runs comfortably inside a 15000ms budget and would have warned on every heavier config — and now fires only on a genuine overrun of the budget in force. Verified in a real browser scan with `realistic_click`: `Budget 29950ms`, interaction completed in 4121ms, 0 warnings.
- **The module's "avoids clicking destructive elements" claim is now scoped to the function that does it.** That filter lives in `interactWithElements`, which has **no callers anywhere in the repo**; the path nwss actually uses, `performContentClicks`, clicks random coordinates inside a content zone and cannot consult an element blocklist — which is the point of it (popunder discovery). Both are opt-in (`interact_clicks` defaults to false), and the header now says which is which instead of presenting the filter as a module-wide property.
- **The whois path died on a missing `siteConfig`, and the error was hidden at debug level.** `createNetToolsHandler` destructured `siteConfig` with no default — alone among its options — while the whois branch read `siteConfig.whois_max_retries` unconditionally, so a caller that omitted it got `Cannot read properties of undefined (reading 'whois_max_retries')`. The handler's `catch` then logged that as a debug line, so on a normal run **whois silently did nothing**: no lookup, no error, no clue. `nwss.js` passes a `siteConfig` at all three call sites, so this was latent rather than live, and the dig branch is immune only by accident (it touches `siteConfig` solely inside a `forceDebug` guard, which is why dig tests passed without one). `siteConfig` is defaulted now, and that `catch` no longer hides an unexpected throw behind `--debug`: it warns unconditionally, with the top stack frames added under `--debug`. Making it loud immediately exposed a second instance of the same shape — the match sink's `matchedDomains.add(domain)` fallback, unguarded, which threw the same way for a caller that passed neither `addMatchedDomain` nor `matchedDomains`, silently discarding a confirmed match. It now warns and names the missing option instead of dying mid-path. Both warnings route through `logToConsoleAndFile` with a `'warn'` level rather than a bare `console.warn`, because that helper is what writes `debugLogFile` — a bare warn would have made the loudest message the one line MISSING from a log file the user collected, while every routine line was in it. Checked for noise before shipping the unconditional warning: **19** awkward domain shapes driven straight through the handler — trailing dot, uppercase, punycode, a 60-character label, underscores, a bare IPv4, `::1` and `[::1]`, `localhost`, the empty string, `..`, embedded quotes/semicolons/`$`, a 300-character name — produce **0** warnings and **0** throws, so it fires for programming errors rather than for input.
- **`whois_max_retries` ran 3 attempts where the docs, `--help` and `--dry-run` all said 2.** The live `retryOptions` defaulted to `|| 3` while the `--dry-run` report, README, `nwss.1` and `--help` said 2, so an unconfigured site quietly made 50% more attempts than documented, and `--dry-run` — whose entire job is reporting what a run will do — printed a number the run would not use. Both readers now share one `DEFAULT_WHOIS_MAX_RETRIES = 2`, following the documented contract. Measured against a `whois` that never answers: the ladder drops from **3 attempts / 48.2s** (attempts at +0s, +12s, +30s) to **2 attempts / 24.1s** (+0s, +12s) for a single server. `whoisDelay`'s phantom defaults are gone too — it read 8000 in `whoisLookupWithRetry`'s signature, 4000 in the handler and 2000 in the JSDoc, none of which nwss ever used; all three now resolve to one `DEFAULT_WHOIS_DELAY_MS = 3000`, matching the documented `whois_delay`, and the worked example in the backoff comment is recomputed at that value instead of the 8000 it was written for. README now also says `whois_delay` is multiplied into a progressive backoff rather than being a flat per-request pause.
- **The `catch` in `whoisLookupWithRetry` was unreachable** — `whoisLookup`'s body is a single `try/catch` whose `try` is its first statement and whose `catch` runs to the end, with every `return` inside, so it always resolves with a result object. The 30 lines there duplicated the retry decision (its own `lastError` shape, its own `isRetryableException` test on timeout/ECONNRESET/ENOTFOUND) and could drift from the real one taken from `result.isTimeout`. Collapsed to a one-liner that records and moves on, kept rather than deleted because a bare `try` is a syntax error and because a future refactor that does make it throw should be visible.
- **A `dig` lookup waiting out its retry backoff no longer holds a concurrency slot.** `dig_max_concurrent` exists to cap concurrent `dig` **subprocesses**, but the slot was acquired once for the whole lookup — including the pauses between attempts, where nothing is running. With the default cap of 6 and `--dig-retry-failed`, six failing domains could hold every slot for minutes (the backoff is 3s by default, up to 60s, times the retry count) while no subprocess existed. The slot is now taken immediately around each `execFile` and released in a `finally`, so every exit path — success return, `continue` on SERVFAIL/REFUSED, throw — frees it, and the backoff runs unslotted. Measured with a one-slot cap: a healthy lookup completes at **602ms** while a domain that SERVFAILs its whole ladder runs to 1907ms; under the old structure the healthy one finished at **1907ms**, i.e. it waited for the failing lookup's entire ladder. `releaseDigSlot` is also floored at zero now, so a future double-release can't push the counter negative and silently raise the cap.
- **`.dnsignore` matching no longer scans the whole file per candidate.** `isDnsIgnored` looped every entry testing `name.endsWith('.' + entry)` — O(entries) per lookup, on a list that `--dnsignore-auto` appends to on every run, so it got slower the longer it grew. It now walks the candidate's own parent domains (`a.b.example.com` → `b.example.com`, `example.com`, `com`), at most one `Set` lookup per label whatever the file's size. Exactly equivalent, and verified so rather than assumed: **36,000** generated comparisons between the old and new forms over random names and entry sets (13,443 of them true results) produced **0** mismatches, with the awkward cases spelled out — `notexample.com` still false against an `example.com` entry, a leading-dot entry still matches only itself, `a..b` still behaves as before.
- **The dig test suite could be silently truncated and still report success.** Found while mutation-testing the slot change: a leaked slot deadlocks `acquireDigSlot()`, Node then has nothing left to do and exits **0**, so the suite printed its first six PASS lines and looked green. `scripts/test-dig-resolver.js` now fails on an exit that happens before the final report, which turns that class of hang into a visible failure.
- **`--dns` sent the DNS pre-check and `dig` to different servers when the spec carried a port.** `lib/dns.js` deliberately accepts `ipv4:port` and `[ipv6]:port` — the form `Resolver.setServers()` understands, with `8.8.8.8:5353` in its own JSDoc and "optionally with :port" in its warning text — and the pre-check queries that port. `digServerFromSpec` in `lib/nettools.js` matched the same shape and returned **only the address**, then invoked `dig @ip` with no `-p`, so half of one flag went to the stated port and the other half to 53. Silent, and precisely wrong for a split-DNS / dnsmasq-or-unbound-on-5353 setup — the kind of local resolver this code's WSL2-oriented failover exists for. Measured with a UDP listener on `127.0.0.1:5353` and `--dns 127.0.0.1:5353`: **7** pre-check queries arrived there while dig ran as `dig @127.0.0.1 +tcp +time=3 +tries=2 lvh.me A`, and **0** dig queries reached the listener. The port is now carried through the resolver list and passed as `-p`, for both IPv4 and bracketed IPv6; an out-of-range port (`lib/dns.js` validates only `\d{1,5}`, so `:0` and `:99999` get through) is ignored rather than handed to dig, which would fail the lookup outright instead of just using the default port. The resolver label in debug output now names the port too, so `via 127.0.0.1:5353` says where the query actually went. Verified end to end against a real responder on 5353: the query arrives over the custom port and the dig-gated domain is captured from its answer (`||lvh.me^`). Pinned by `scripts/test-dig-resolver.js` (8 checks) which reads the **real argv** — a fake `dig` on `PATH` records what the subprocess was invoked with — covering ip:port, bare ip, bracketed IPv6 with and without a port, both out-of-range ports, no `--dns` at all, and a **mixed list** (`1.1.1.1,127.0.0.1:5353`) where the ported entry must carry `-p` and the bare one must not — the fake dig can answer SERVFAIL on request so the failover ladder really runs every attempt, which is the only way that case is reachable. Mutation-tested against five mutations: dropping the port (the original bug), hoisting it to the first resolver's, removing the range validation, unanchoring the IPv6 regex, and always passing `-p`.
- **`--clear-cache` was a recursive delete of any directory the config named.** `SmartCache.clearPersistentCache` ran `fs.rmSync(cachePath, { recursive: true, force: true })` on `config.cache_path` verbatim. Two things made that worse than it sounds: persistence is off by default and `nwss.js` hardcodes `cache_persistence: false`, so the directory is usually not one nwss ever wrote; and nothing else keeps anything there either, since the adblock-rs disk cache lives under `os.tmpdir()/nwss-adblock-rs-cache`. Demonstrated against a directory holding only user files — `source.js` plus a `nested/` subtree — the old line left **no directory at all**. A `cachePath` pointing at a *file* was likewise unlinked whatever it was. Now only this module's own files are removed, by name: `smart-cache.json` and its pid-suffixed `.tmp` siblings, which `savePersistentCache` can strand when a write fails. The directory itself goes only when removing them leaves it empty, so a dedicated `.cache` still disappears while a shared one survives with its contents and a `Kept <path>: N file(s) in it are not ours` line under `--debug`. A `cachePath` that is a file is honoured only when it *is* `smart-cache.json`; anything else is refused with an error rather than deleted. Note `fs.rmdirSync` replaces `rmSync` here, which is the actual enforcement — it is non-recursive, so the OS refuses a non-empty directory with `ENOTEMPTY` independently of the emptiness check, and mutating that check out changes nothing except the debug line. Same shape as the guarded Chrome temp sweep in `lib/browserexit.js`: name what you own, leave everything else, say so. Pinned by `scripts/test-clear-cache.js` (15 checks) covering a dedicated dir, a shared dir, a directory with no cache in it at all, an arbitrary file, a direct `smart-cache.json` path and a missing path; mutation-tested against five mutations (restoring the recursive `rmSync`, making `isOwnFile` always true, removing the arbitrary-file refusal, removing the emptiness check, and no longer collecting stranded temps). Verified end to end through the CLI: `nwss --clear-cache` against a mixed directory removes `smart-cache.json`, leaves `keep-me.txt`, and reports both actions. A re-review then found two more cases, both fixed: a temp file whose **pid is still alive** was deleted mid-write, which would make that process's rename fail — the pid is parsed out of the name and skipped when live, using the repo's convention that only `ESRCH` means gone (`EPERM` means alive but owned by another user, pinned with a `smart-cache.json.1.tmp` fixture); and a **symlinked** `cache_path` reported `success: false` with a spurious `ENOTDIR: not a directory, rmdir` even though the clear had worked, because `rmdir` was being called on the link itself — `lstat` now detects that and leaves the link alone, since removing someone's symlink is not this tool's business either. Both are reported under `--debug` as reasons the directory was kept.
- **Every domain of six characters or fewer was silently dropped from the output, in every format.** `formatDomain` in `lib/output.js` opened with `if (!domain || domain.length <= 6 || !domain.includes('.')) return null`, and each of its five callers discards a null with a bare `if (formatted)`. So `bit.ly`, `goo.gl`, `vk.com`, `qq.com`, `adf.ly`, `t.co`, `x.com`, `ok.ru` and `is.gd` were matched, counted, marked processed in the smart cache and reported in the end-of-scan unique-domain stat — and then produced **no rule at all**, in adblock, plain, hosts, dnsmasq, unbound, privoxy and pi-hole alike, with nothing logged. **11 of 14** real domains tested were affected. Found while reviewing `lib/smart-cache.js`: a fixture serving trackers from four registrable domains reported 4 matched and wrote 2 rules, identically across three runs, and reversing the DOM order lost the *same* two hosts rather than the last two — `lvh.me` and `nip.io` are 6 characters, while `sslip.io`, `localtest.me` and `vcap.me` (7) survived, putting the boundary exactly at `<= 6`. The length was also measured against the whole key including any path, so `t.co/ads/` (9 characters) sailed through where the bare host did not — proof the number was not protecting anything structural. What the guard is actually for is junk from `output_regex` captures, so the checks are now structural and applied to the **host** rather than the whole key: a dot, no empty labels, a two-character-minimum TLD, and at least `x.yy`. IP literals are accepted explicitly, since a request to a bare address is a legitimate rule and a numeric last label would otherwise fail the TLD check. A refusal is no longer silent — it logs `[output-filter] Not emitting <key>: <reason>` under `--debug`, which required threading `forceDebug` through `globalOptions` into `formatRules`. Verified end to end: the fixture that exposed it goes from 2 rules to 4 (`||lvh.me^ ||nip.io^ ||sslip.io^ ||localtest.me^`), debug and non-debug output are byte-identical, all six repo configs still validate, and `bit.ly` now formats correctly in all nine format variants. Pinned by `scripts/test-output-format.js` (12 checks), which was mutation-tested against eleven mutations: restoring the old `length <= 6`, deleting the guard, dropping the IP allowance, dropping the empty-label check, dropping the TLD check, suppressing the debug line, and validating the whole key instead of the host. The TLD mutation initially survived — `a.b` and `x.y` are caught by the length floor regardless — so `abc.d` and `foobar.x` were added, which is what actually exercises it. A re-review then caught two shapes where the new guard *changed* behaviour rather than restoring it, both now handled: a **trailing-dot host** (`ads.example.com.`, which Chrome preserves — `new URL('http://ads.example.com./t.js').hostname` keeps the dot) was newly dropped, reintroducing the very failure being fixed, so a single trailing dot is normalised away instead; emitting it raw as `||ads.example.com.^` would match nothing, so this is better than the old behaviour too, and the adblock branches now build from the normalised host plus the path rather than the raw key. And the IP carve-out was narrowed from `net.isIP(host)` to `=== 4`, since a bare IPv6 host would have started being emitted as `local=/::1/` or `0.0.0.0 ::1`; it cannot reach `formatDomain` from a scan in any case, because URL parsing keeps the brackets and `[2001:db8::1]` has no dot.
- **The "unique domains cached" stat was capped by an eviction nobody needed, and `lib/domain-cache.js` is gone.** `getDetectedDomainsCount()` returned the *retained* size of a `Set` that `markDomainAsDetected` evicted down to `maxCacheSize * 0.9` once it passed 10,000 — so the end-of-scan `Performance: N unique domains cached` line reported the residual set, not the number of uniques, on any scan finding more than 10,000 subdomains. Measured with a cap of 100: marking **250** distinct domains reported **96**. `stats.totalDetected` was not a fallback — re-marking an evicted domain reports `wasNew=true`, so it overcounted by as much as the size undercounted — and it was never exposed anyway, since `nwss.js` destructured only `markDomainAsDetected` from `createHelpers()`. The eviction existed to bound a cache whose membership nothing read: the `isDomainAlreadyDetected` that `curl.js`, `nettools.js`, `grep.js` and `searchstring.js` receive is `nwss.js`'s own per-URL `isLocallyDetected`, a different function, so this cache's skip-check, `totalSkipped`, `cacheHits`, `cacheMisses`, `getStats().hitRate` (permanently `'0%'`), `has()` and `clear()` had no callers at all. Its debug logging could not fire either: `domainCacheOptions` hardcoded `enableLogging: false` with a comment telling you to edit the source, where comparable modules get `enableLogging: forceDebug` — which also made the "options differ from the live singleton" warning doubly unreachable, since it gated on the live instance's own `enableLogging` and the only second caller passed no options. Replaced with a plain `Set` in `nwss.js`: 253 lines out, 7 in. The count is now exact and uncapped, and because its only consumer sits inside `if (forceDebug)`, the insert is gated on `forceDebug` too — a normal run no longer pays a `Set` insert per matched domain for a number nobody asks for. Verified against an independent oracle: a page pulling trackers from four distinct registrable domains (`lvh.me`, `nip.io`, `sslip.io`, `localtest.me`, all resolving to loopback so the smart cache cannot collapse them) reports exactly **4**, matching the four distinct hosts the request log shows matching the filter, and a non-debug run of the same config produces byte-identical output with no errors. One measurement worth recording for anyone reading the stat: with fewer distinct registrable domains the number is lower than the subresource count by design — seven subdomains of one registrable domain report **1**, because smart-cache dedup skips the rest before they are ever counted.
- **`$popup` rules are dropped instead of silently widened.** `PARSE_TYPE_MAP` only knows resource types, and the option filter had no else branch, so `popup` was discarded while the pattern was kept — turning `/adclick.$popup` into a rule matching *every* request type. It blocked a stylesheet request in testing. Dropping a restriction widens a rule, which is the unsafe direction for a scanner: it aborts requests a real browser would have made and hides the traffic being captured. `lib/adblock.js` now drops any rule gated on an option it cannot evaluate, deriving the options segment exactly as `parseRule` does so the two cannot disagree. This matches `adblock-rs`, which discards such rules outright — verified directly: a `$popup` rule matches nothing there for any request type, negated or not (easylist contains 0 `$~popup` rules in any case). **3,813 easylist rules** are affected, and the change only ever *stops* blocking: on the 2000-URL sample, 6 verdicts became allowed and **0 became blocked**, while js/rust disagreements on typed requests fell from 23 to 18. `lib/adblock-rust.js`'s rule counter skips them too, so the startup banner keeps the engine-count parity established earlier (both now report 62,286 rather than 66,099); that engine still receives every line via `addFilters`, only the count changed.
- **`matchedTypes` is de-duplicated, so its length means what two checks assume.** `PARSE_TYPE_MAP` has aliases — `css`/`stylesheet` both map to `stylesheet`, `xhr`/`xmlhttprequest` both to `xhr` — so a rule written `$css,stylesheet` produced `['stylesheet','stylesheet']`, a length of 2 for one distinct type. Two conditions key off that length as a proxy for "how many distinct types": the `$document` special case, and the script-only test that decides bucketing. Purely defensive — **0** easylist rules trigger it today, and neither `document` nor `script` has an alias, so nothing is currently mis-bucketed — but a near-true count is exactly what breaks when an alias or another length-based check is added later. Verified inert: bucket sizes unchanged (357 / 1061 / 0) and 0 verdict changes across the 2000-URL sample, while `$css,stylesheet` now reports one type and still blocks a stylesheet request without blocking an image.
- **Multi-type adblock rules containing `script` were unreachable for their other types.** `lib/adblock.js` set `isScript` whenever `script` appeared *among* a rule's type options, which filed the rule in the `scriptRules` bucket — and that bucket is only consulted when `resourceType === 'script' || url.endsWith('.js')`. So `/adserver3.$image,script` parsed correctly, with `resourceTypes` of `{image, script}`, and then never matched an image request. **47 easylist path rules** are multi-type including script. `isScript` is now set only when script is the *sole* type, which restores the invariant the bucket and its gate were written against: the bucket and gate date from the original implementation, where `isScript` meant "script-only", and a later commit widened the assignment to "script among others" without revisiting either consumer. Found by comparing the JS engine against `adblock-rs`, which blocks it correctly. Measured on a 2000-URL sample drawn from varied easylist rule shapes: `scriptRules` 403 → 357 and `pathRules` 1016 → 1061, two verdicts change and **both are new blocks, none newly allowed**, and js/rust disagreements on requests carrying a resource type drop from 24 to 23. The one new divergence involves an *empty* resource type, where `matchesRule` skips the type check entirely (`if (resourceType && …)`) — pre-existing, and unreachable in real scans since `request.resourceType()` always returns a value.
- **OpenVPN teardown reported a live root-owned process as exited.** `waitForProcessExit()` wrapped both the liveness probe and its wait in one `try` with a bare `catch { return true }`, so any throw was read as "the process exited". `process.kill(pid, 0)` throws **EPERM**, not `ESRCH`, when the target exists but we may not signal it — and openvpn is started under `sudo`, so it is root-owned while nwss is not. The first probe therefore threw EPERM and the function returned `true` in 0ms (demonstrated against pid 1, which is plainly running), so `stopConnection` skipped its `pkill -9` escalation and `activeConnections.delete()` forgot a still-live root daemon. The wait throwing was also misread the same way. Only `ESRCH` now means gone; EPERM and anything unexpected keep waiting so the caller escalates on timeout. The wait moved outside the `try` and no longer shells out to `sleep 0.2` per poll — `Atomics.wait` blocks the same way without a subprocess, and stays synchronous deliberately, since an `await` here would put VPN shutdown after a yield, which is where puppeteer's synchronous SIGINT handler pre-empts async cleanup. Verified: a process that genuinely dies returns at ~1s rather than the 5s ceiling, a live root-owned pid returns `false` so escalation fires, and 1s of waiting costs 0.3ms CPU.
- **`--validate-config` printed a count and threw away every finding.** A failing config reported only `Errors: 0 global, 1 site-specific`, with no way to learn which key was wrong short of reading `lib/validate_rules.js` — every message was already collected in `validation.siteValidations[].errors/.warnings` and simply never read. Both the failure and success branches now print them. Exit codes are unchanged; this is visibility only. On the repo's own configs it immediately surfaced live problems that had been invisible: `blocked` given as a string rather than an array (silently dropped by `compilePatternList`, so those patterns never applied), `resourceTypes` as a string (yields `null`, i.e. no resource-type filtering at all), and an unknown `resourceType: 'all'`.
- **`js_redirect_timeout` and `max_redirects` are now type-checked.** Both were in the known-keys allowlist but absent from the validator's `numericFields`, so degenerate values passed through silently. `lib/redirect.js` derives its poll interval as `js_redirect_timeout / 3`, so `-3000` gives a negative interval and `"abc"` gives `NaN` — `setTimeout` treats both as "fire immediately", meaning the loop spins its three polls with no wait and JS redirects stop being tracked at all, with nothing reported. `max_redirects` was better protected (that module does its own `typeof === 'number' && >= 0` check and falls back to 10), so adding it is for the error message rather than for safety. Zero is accepted for both, since `max_redirects: 0` legitimately means "track no redirects". The shared message now reads `must be a number >= 0` instead of `must be a positive number`, which is what the check has always enforced — it also applies to `delay`, `reload` and `timeout`. All six configs in the repo still validate.
- **`js_redirect_timeout` can now be set globally**, as the default for any site that doesn't specify its own; per-site values still win. It was a per-site key only, and since the wait costs roughly a third of its value on *every* URL whether or not that URL redirects, turning it down across a 63-site config meant 63 duplicated lines. Applied immediately after the config destructure — before both the `--validate-config` block and the scan loop — so the two paths see the same effective config rather than diverging. A non-numeric or negative global is warned about and ignored rather than applied. Verified: a site with no key inherits the global and logs the skip, a site with an explicit `3000` still polls at `3x1000ms`, and a global of `"abc"` is rejected with both sites falling back to their own values.
- **`js_redirect_timeout: 0` now skips the JavaScript-redirect wait instead of being swallowed.** The value was read with `|| 5000`, so zero — the only way to express "don't wait" — was treated as falsy and silently replaced by the default, meaning the per-URL cost could not be turned off. It now uses the same `typeof === 'number' && >= 0` check as `max_redirects` immediately below it, and the poll loop is skipped outright at zero. Measured saving of ~`timeout/3` per URL, which is the whole of the wait: a plain page went 6628ms → 5619ms and an HTTP 302 6604ms → 5619ms at a configured 3000. What it gives up is narrower than it sounds, and was measured rather than assumed: only redirects landing **after** navigation settles stop being tracked. At `0`, an HTTP 302 is still tracked and so is an inline `location.href` that runs on parse — both commit during `page.goto` and are caught by the `framenavigated` handler, which doesn't depend on this wait — while a `setTimeout(…, 2000)` redirect is not. In every case the landed page still loads and its requests are still captured; only the chain, `finalUrl` and the first-party promotion miss the late hop.
- **The injected JS-redirect detector was entirely dead, and now works.** `lib/redirect.js` injected hooks over `location.replace`, `location.assign` and the `location.href` setter. None could install: in current Chrome `window.location`'s properties are non-writable and non-configurable, so the assignments silently no-opped and `Object.defineProperty(window.location, 'href', …)` threw `TypeError: Cannot redefine property: href` (measured directly, with `configurable: false` on the descriptor). Because the throw happened inside an `evaluateOnNewDocument` script, Puppeteer never surfaced it as a page error — and it aborted the rest of that function, so the `MutationObserver` that detects **meta refresh** was never installed either. `window._jsRedirectDetected` was therefore permanently `false`, which is why every tracked hop logged as `URL change detected` (the `framenavigated` handler comparing URLs, doing all the real work) rather than `JavaScript redirect detected`, and why the poll loop's detected-branches were unreachable. The dead hooks are removed, the body is wrapped so one failure can't cascade again, and a sweep for an already-present `meta[http-equiv=refresh]` backstops the observer, which only sees *added* nodes. Verified before/after: a dynamically appended meta refresh and one present in the served HTML both go from undetected to `meta.refresh`, and a meta refresh landing at 2000ms with `js_redirect_timeout: 3000` goes from **not tracked** to tracked. Cost: a page whose meta refresh can actually fire inside the wait window now spends the full `js_redirect_timeout` rather than a third of it, since the loop no longer breaks early on it (6627ms → 8619ms at 3000) — bounded by the configured value, and no change for plain pages, JS-redirect pages or `js_redirect_timeout: 0`. The detector is delay-aware for exactly that reason: flagging *every* refresh made pages carrying a long one pay the whole wait for a redirect that can never land during a scan (`content="3600"` is a real cache/poll-hint pattern, measured at 4606ms → 6601ms), so the parsed delay is compared against the budget and anything that cannot fire in time is ignored. An unparseable delay counts as immediate, matching browser behaviour. `_jsRedirectUrl` also holds an actual URL now rather than the raw `content` attribute — it was being handed things like `"2;url=/landed.html"` or a bare `"3"`, neither of which is a URL. The `;url=` part is parsed case-insensitively with surrounding quotes and stray whitespace stripped, a refresh with no `url=` resolves to the current document (which is what it reloads), relative targets resolve against `document.baseURI` so a `<base href>` is honoured, and an unresolvable target falls back to the raw string rather than being dropped. Verified: `2;url=/landed.html` → the absolute landed URL, bare `2` → the current page URL, `URL="…"` and `url='…'` → the quoted target, `2 ;   URL   =   /x  ` → the trimmed target, and `<base href="/sub/dir/">` with `url=rel.html` → `/sub/dir/rel.html`. Verified: `content=3600` back to 6603ms with no tracking lost, while `content=2;url=` and a dynamically appended `content=2` are still detected and tracked. The pending-detection log now names the target too — `JS redirect detected (meta.refresh) -> http://…/landed.html but not yet executed, waiting...` — which is the one place the destination is known *before* the navigation commits, and it was the only detection log omitting it. The landed-hop log additionally distinguishes the requested target from where it actually committed when the two differ, though in practice that branch rarely fires: the `framenavigated` handler records the hop first, so the poll finds `currentPageUrl` already equal to `finalUrl` and skips the block. URLs in both detection logs are capped at 80 characters with an ellipsis, matching `truncateUrl()` in `lib/dry-run.js`, because a meta refresh can target a `data:` URL that resolves to an arbitrarily long string and then lands in a debug line verbatim. The helper is duplicated rather than imported: `truncateUrl` is an unexported internal helper there, and this module deliberately has no `require`s at all — it takes `formatLogMessage` as a parameter for that reason. Verified: a normal URL is printed in full, while a 300-character `data:` target is capped at exactly 80 characters ending in `...`.
- **The JS-redirect wait no longer misrepresents itself.** `lib/redirect.js` looked like it polled three times for a total of `js_redirect_timeout`, and logged `Waiting {js_redirect_timeout}ms for potential JavaScript redirects`. It does not: it sleeps one interval of `js_redirect_timeout / 3`, checks, and normally stops — so the effective budget is a **third** of the configured value, and a redirect landing later than that is not tracked. The reason it stops is that the in-page detector is installed with `evaluateOnNewDocument`, so `window._jsRedirectDetected` resets to `false` on every new document; once a hop commits, the next poll reads the fresh document's flag as false and the no-activity break fires. The retry path is genuinely reachable, but only for the race it was written for — the hooks saw `location.href`/`replace`/`assign` execute while the navigation had not committed, so the flag is true with the URL unchanged. Renamed to `JS_REDIRECT_POLLS` / `pendingRedirectRechecks` with the interval derived explicitly, documented at the loop, and the debug line now reads `Polling up to 3x1000ms … (first quiet poll stops it, so normally ~1000ms)`. No behaviour change: timings match within run-to-run noise (≤24ms on ~6s scans, at timeouts of 3000 and 9000, plain and redirecting pages) and the `max_redirects` tracking matrix is identical (0→0, 1→1, 2→2, 3→3, 4→3).
- **`max_redirects` now means what it says, and was documented wrongly in every respect.** README, `--help` and `nwss.1` all read "Maximum number of redirects to follow (default: 10; 0 = follow none)". Measured: it does **not** govern whether redirects are followed — Chrome follows them natively whatever the value, and even at `0` the landed page is still loaded and its requests still captured. What it caps is how many redirects nwss **tracks**. It also counted one too few: `lib/redirect.js` seeds `redirectChain` with the original URL, so the length was already 1 before any redirect was recorded and the guard `>= maxRedirects` meant `N` tracked `N-1` — `0` and `1` were indistinguishable, both tracking none. The guard is now `> maxRedirects`, so `0` tracks none, `1` tracks one and the default `10` tracks ten. There are **four** of these guards in `lib/redirect.js` — the `framenavigated` handler, the HTTP-redirect path, the JS-redirect polling loop and the final-URL update — and all four are converted; an earlier pass changed only the first, leaving the other three capping at `N-1` and the semantics inconsistent between paths. Measured across 0/1/2/3/4 against a three-hop chain — before: 0, 0, 1, 2, 3; after: 0, 1, 2, 3, 3 (capped by the chain) — with the landed page reached and captured in every single case, confirming tracking never gates the load. One further correction the testing produced: the count is of *committed navigations*, so a server-side 30x chain is a **single** hop however many times it bounces (Chrome commits once — `curl` reporting 3 redirects showed up as 1), while JS and meta-refresh redirects each count separately. **Scope of the behaviour change:** a config setting `max_redirects: 1` previously tracked no redirects and now tracks one, so `redirected` becomes true, `finalUrl` follows the redirect and `redirectDomains` is populated. That also makes the first-party promotion block reachable at that value (it runs when `redirected` is true and `redirect_first_party !== false`). What could **not** be demonstrated is any resulting change to what gets captured: with a genuinely cross-registrable-domain redirect (`lvh.me` → `nip.io`, both resolving to loopback), the landed host's resource was matched as third-party identically before and after, for a request firing at page load and again for one firing 1.5s later, well after the promotion block runs. Treat the effect as confined to redirect tracking until someone demonstrates otherwise. Only `config-clean-mini.json` sites 9 and 10 set the key at all, and nothing sets it globally.
- **`--validate-config` now runs the scan-path normaliser too.** It only ever ran `validateFullConfig`, never `normalizeSiteConfig` — so the typo detector and its "did you mean" suggestions, the boolean coercions and the string→array coercions were invisible until a scan was already underway, which is precisely when they are least useful. A config could therefore report `✅ Configuration is valid!` while every scan warned that an unknown key's value was being ignored. Found exactly that in this repo: two sites carrying a bogus `follow_redirects`, which validated clean and warned on every run. Normalisation runs *before* validation now, so the validator also checks the values a scan would really see, and its errors (only "site is not an object") count toward the exit status. Verified: no config's exit code changes, and the previously-hidden warnings are reported.
- **`reload` was documented backwards, and `interact_popups` warned on every scan.** `reload` is the TOTAL number of page loads — `totalReloads = (reload || 1) - 1` — so the default of `1` loads once and never reloads, and `2` is what produces one reload; anyone asking for a single reload with `reload: 1` silently got none. Corrected in README, `--help` and `nwss.1`. Separately, `interact_popups` was missing from `KNOWN_SITE_CONFIG_KEYS`, so `normalizeSiteConfig` warned "unknown siteConfig key … value will be ignored at runtime" on every scan using it — untrue, since `nwss.js` reads and honours it.
- **`lib/spawn-async.js` refuses a `cmd` that is not shaped like an executable** (PR #49, thanks @anupamme / OrbisAI Security). Defence-in-depth rather than a fix: `spawn()` already uses no shell, verified — `spawn('curl; touch /tmp/pwned', ['-V'])` fails ENOENT with nothing executed — so metacharacters in `cmd` become part of a literal filename and CWE-78 does not apply. Merged because every caller today passes a hardcoded literal (`'curl'`, `'grep'`), so nothing changes now, while a user-supplied path reaching this helper later would fail loudly instead of silently. Note the guard also rejects paths containing spaces, so loosen the pattern rather than debug a silent spawn failure if a configurable binary path is ever added.
- **`blocked` accepts a bare string, like every other pattern field.** `filterRegex`, `searchstring`, `comments`, `url` and `referrer_headers` all take `"one"` or `["one", "two"]`, but `blocked` was array-only — and it failed *silently*: `compilePatternList()` gates on `Array.isArray()` and returns `[]` for anything else, so a string pattern looked configured and blocked nothing, with no warning at scan time (only `--validate-config`, which the code's own comment notes most users never run, said anything). `lib/validate_rules.js` already had a `STRING_TO_ARRAY_FIELDS` coercion for exactly this failure shape on `dig`/`whois`; `blocked` has joined it, `compilePatternList()` coerces as well so the **global** `blocked` list is covered too (`normalizeSiteConfig` only walks per-site config), and the validator now accepts a string just as it already did for `filterRegex`, so `--validate-config` can't reject a config the scanner runs. An **empty** string stays no-patterns rather than becoming `['']`: `new RegExp('')` is `/(?:)/`, which matches every URL, so coercing it would silently turn an obviously-empty setting into block-everything — the same trap the `dig` coercion documents. Verified: string blocks (was 0 blocks), array unchanged, global string blocks, `blocked: ""` blocks nothing while all 6 requests still flow, a malformed string pattern is still reported as an invalid regex, and a number is still rejected.
- **`resourceTypes` accepts a bare string too, with the same silent failure behind it.** `nwss.js` built `allowedResourceTypesSet` only when `Array.isArray()` passed and otherwise left it `null`, which means *no* resource-type filtering at all — so `resourceTypes: "image"` quietly processed every type instead of only images. It now joins the same `STRING_TO_ARRAY_FIELDS` coercion as `blocked`, the consumer coerces as well for any path that skips normalisation, and the validator accepts a string (which also means the valid-type vocabulary check now reaches string values, so a bogus `"all"` is reported as an unknown type rather than a shape error). An empty string stays `null` — no filtering — rather than becoming a set containing `''`, which no request's type ever equals and would therefore match nothing. Verified against a page issuing script, image and fetch requests: no key → 3 matches, `"image"` → 1 match and it is the `.png`, `["image"]` → 1, `""` → 3, `42` → rejected.
- **`click_elements`, `cdp_specific` and `css_blocked` accept a bare string too.** Found by sweeping every `Array.isArray(siteConfig.X)` gate for the same silent-drop shape as `blocked`/`resourceTypes`: a string meant `click_elements` skipped the clicking step entirely (`nwss.js:3667`/`5168`), `cdp_specific` never enabled per-domain CDP logging (`nwss.js:2541`), and `css_blocked` hid nothing (`nwss.js:3032`). All three are per-site only, so joining `STRING_TO_ARRAY_FIELDS` covers every consumer — no call-site duplication needed, unlike `blocked` with its global list. The `css_blocked` validator now accepts a string as well. Worth recording that its `Array.isArray` guard was load-bearing rather than redundant: `selectors.map()` over the string `"#ad"` would iterate **per character** and inject `a { display: none }`, hiding every link on the page — the coercion keeps it an array of one, and the injected selector list was checked to be exactly `#ad`. A/B against the previous commit: each string form goes from doing nothing to working, while array forms are byte-identical (1/1, 2/2, 2/2 on their respective signals) and empty strings stay inert in both.
- **Two code paths disagreed on what an empty `resourceTypes` means.** The main matcher gates on `allowedResourceTypesSet.size > 0`, so an empty set means "no filtering", but the `even_blocked` path had no size check and so read the same empty set as "match nothing" — despite its comment claiming it applied "the same filtering logic as unblocked requests". `resourceTypes: []` together with `even_blocked: true` therefore silently recorded no matches. The `even_blocked` gate now includes the same `size === 0` arm. A/B against the previous commit: `[]` goes 0 → 1 match, while `["fetch"]` stays 1 and `["image"]` stays 0, so real filtering is untouched in both directions.
- **`config.json` sites 1 and 2 carried `resourceTypes: ["all"]`, which matched nothing.** `'all'` is not a resource type, so the set contained only that and excluded every real type — measured at 0 matches versus 3 with the key absent. The key is now dropped from both sites, which is the documented default (all types). Their `filterRegex` values are placeholders (`"anotherstrng"`, `"morestrings"`), so no real results were being lost, but `["all"]` reads like a natural "match everything" idiom and this is the file people copy from.
- **The compiled-engine disk cache is no longer trusted blindly.** `lib/adblock-rust.js` serialises the parsed engine to a fixed folder under `os.tmpdir()` — a `1777` directory any local user may create entries in — under a filename that is `sha256(adblock-rs version + raw list bytes)`. Filter lists are public, so that name is computable by anyone who knows which lists are in use, and the read path handed the file straight to the native deserialiser with no ownership check: a local user could pre-create the directory and plant a `.bin`, choosing the scan's blocking verdicts silently (or feeding malformed input to a Rust deserialiser). The cache directory is now created `0700` and the entry `0600`; a directory that exists but is a symlink, not a directory, owned by someone else, or group/other-writable is refused outright, falling back to a normal parse. `mkdirSync({recursive: true})` accepts an existing directory and does **not** apply its `mode` to it (verified), so the mode alone would not have helped — the ownership gate is what closes it. Reads open the file first and `fstat` the **descriptor** rather than stat-ing the path, since a path check leaves a window to swap the file between check and read. Writes `unlink` any stale tmp first (removing a planted symlink rather than following it) and use `'wx'`, so the write cannot be redirected. Verified: `/etc` as a cache dir is refused ("owned by uid 0"), a `0777` dir is refused, a symlinked dir is refused, a symlink planted at the tmp write path leaves its target untouched while the cache still writes normally, and the normal path still hits warm. An existing `0755` cache dir stays `0755` and remains trusted — delete it once to get `0700`.
- **Filter-list headers were parsed as real blocking rules.** `lib/adblock.js` skipped blanks and `!`/`#` comments but had no case for `[Adblock Plus 2.0]`-style headers, so a header fell through to the parser and became a live entry in `pathRules` — the linear-scan bucket — as `{pattern: '[Adblock Plus 2.0]', raw: null}`. It genuinely matched: a URL containing that literal was blocked, attributed to a rule whose `raw` is `null`. Unreachable in practice, but it was one junk entry per list in the hottest matching path and inflated the reported rule total. `lib/adblock-rust.js` already skipped them, so the two engines disagreed on the count for identical input; this was the side that was wrong. Verified against easylist (90,103 lines): only `pathRules` changes, 1017 → 1016, with zero verdict or reason differences across 400 url/type pairs.
- **The two adblock engines reported wildly different rule counts for the same list.** The startup banner read `Loaded 66099 blocking rules` under `--adblock-engine=js` and `Loaded 89825` under `rust` — a 23,726-rule gap that looked like the Rust backend loading far more than it does. `lib/adblock-rust.js` counted every non-comment line, including element-hiding filters, which can never block a request: `shouldBlock()` only does network matching. It now applies the same cosmetic skips as the JS engine (`##`/`#@#` and the `elemhide`/`generichide`/`specifichide`/`genericblock` options). On easylist that is 23,587 element-hiding lines plus 139 cosmetic-option lines, and 89,825 − 23,587 − 139 is exactly 66,099 — both engines now report the same number for every line kind tested. Count only: `addFilters()` still receives every line, and 200 sampled easylist domains still block identically under both engines.
- **The compiled-engine cache never pruned while it was being used, then deleted itself when it did.** `pruneOldCacheFiles()` ran only after a cold parse's cache write, so a cache that keeps hitting — the normal state for an unchanged list — never pruned, and stale `.bin`/`.tmp` files from older lists accumulated indefinitely. Pruning now also runs on the warm path, where there is no just-written entry to protect. That exposed a second problem in testing: the prune deletes any file past the TTL *including the one just deserialized*, so a cache older than the TTL was read successfully and then destroyed, forcing a pointless cold reparse next run. The entry's mtime is now refreshed on a hit, which is what the TTL's own comment intends — it is there to drop files "unlikely to be reused", and one just used plainly is. Verified: aged entry survives a hit, an unrelated aged file is still pruned.
- **`lib/adblock-rust.js` no longer claims a `rules` field it never had.** Both the module header and the `@returns` JSDoc advertised the matcher shape as `{ shouldBlock, getStats, rules }`, but the returned object has only the two methods — `rules` is `lib/adblock.js`'s own parsed state (`domainMap`, `pathRules`, `whitelist`, …) with no adblock-rust equivalent, since the rules live inside the native engine and a disk-cache hit never reads the rule text at all. Nothing in the tree reads `matcher.rules`, so the drop-in swap holds; the claim is now stated accurately instead of promising a field that returns `undefined`. Also dropped an unreachable `''` entry from `RESOURCE_TYPE_MAP` — `shouldBlock` short-circuits on a falsy resource type and never performs the lookup.
- **A hung batch no longer discards the URLs that already finished, or blackholes the rest of the host.** When the 10-minute batch ceiling fired, the timeout branch threw away `Promise.all`'s results and synthesised an all-failed batch, losing the rules of every URL that had already succeeded — up to `batchSize - 1` of them, and batches run to 80. Worse, those synthesised `'Batch timeout'` errors then fed the `domainTimeoutCounts` tally, so one hung URL scored `batchSize` timeout strikes against its host; past `DOMAIN_TIMEOUT_THRESHOLD` (3) every remaining URL on that host is skipped for the rest of the scan, and since a site's `url` array is normally all one host, a single hang blackholed the whole site. Measured on a 6-URL/2-batch repro with one stalling URL: **0 of 6 URLs survived; now 5 of 6**, only the genuinely hung one failing. Each task's result is now stashed as it settles, and only the URLs still in flight become timeout failures.
- **The batch-timeout path no longer restarts the browser twice.** It restarts the browser itself, then marked all N results `needsImmediateRestart`, which cleared `restartThreshold` (`max(3, batchSize/2)`) for any batch of 3 or more — so the emergency restart killed the browser the timeout branch had just built and created a third. The hang-fallback path already guarded against this double restart; the timeout path now does too, which also keeps the restart decision from silently depending on how many URLs happened to finish.
- **In-flight URLs no longer act on the wrong browser after a restart.** `processUrl` read the shared `browser` binding in three places (the popup `targetcreated` listener, its deregistration, and the pre-reload health check) instead of the `browserInstance` it was handed. They are the same object at call time, but a restart reassigns `browser` mid-call for any task still running — a batch-timeout orphan, or a grace-timeout orphan that was deliberately abandoned. That attached the popup listener to the *replacement* browser while the URL's page lived on the old one (and an intervening second restart made `off()` miss the browser `on()` had used), and made the health check report on a browser the URL was not using, so the "skip remaining reloads" bail fired on the wrong evidence in both directions.
- **Non-Chrome UA families no longer advertise Chrome-only APIs.** Spoofing `userAgent: "firefox"` or `"safari"` left `window.chrome` in place — worse, the spoof *built it out* (`chrome.runtime`, `.app`, `.storage`, `.loadTimes`, `.csi`) unconditionally, so a page told it was Firefox 154 exposed a populated Chrome extension surface. `navigator.userAgent.includes('Firefox') && window.chrome` is a one-line detection, and it made the spoofed identity *more* distinctive than plain headless Chrome. Chromium ships `window.chrome` natively, so it is now deleted rather than merely left unbuilt, gated on the UA actually claiming Chrome. Same own-goal class as the `callPhantom` bug documented in that file, and missed for the same reason: `scripts/test-stealth.js` only exercised `--ua=chrome`. Two configs (`config-clean0-mini`, `config-clean2-mini`) do use the firefox family, so this was live.
- **Firefox UA reported 5 PDF plugins with 0 mime types.** The `mimeTypes` spoof only had a `Chrome` branch, so Firefox fell through to an empty list while the plugins spoof gave it 5 `internal-pdf-js` entries — a browser advertising a PDF viewer that handles no PDF type, checkable in one line. Firefox now gets the HTML-spec pair (`application/pdf` + `text/pdf`) and notably *not* `application/x-google-chrome-pdf`, which is Chrome-specific. Safari keeps both lists empty, which was already self-consistent.

- **Chromium-only APIs removed under a non-Chrome UA.** `performance.memory`, `navigator.deviceMemory`, `navigator.connection` and `navigator.scheduling` all survived a `firefox`/`safari` UA — none exist in real Firefox or real Safari, so each was a one-line tell against the advertised identity. `deviceMemory` and `connection` were being *defined by the spoof itself*, so they are no longer created for non-Chrome families; the rest are Chromium natives and are deleted. Deleting from the **prototype** is what works — all four are configurable getters on `Navigator.prototype`/`Performance.prototype`, not own properties, so `delete navigator.connection` alone is a no-op — and it was verified afterwards that `prop in navigator` reads false, since leaving a property present-but-undefined is exactly the `callPhantom` own-goal recorded in that file. The removal runs in `applyFingerprintProtection`, the last injection pass, because `connection` is defined back in `applyUserAgentSpoofing` and an earlier removal would simply be undone.
- **Client-hint major version no longer hardcoded.** `Sec-CH-UA`'s Chrome major fell back to a literal `'150'` when the UA string had no `Chrome/`, which went stale the moment the spoof moved to 151 — it would have paired major 150 with `CHROME_BUILD` `7922.174`, a 151 build, i.e. an impossible version. Unreachable today (the header block only runs for chrome UAs, which always match), but it now derives from the `chrome` entry in `USER_AGENT_COLLECTIONS` so it self-heals on every spoof bump instead of failing silently if that guard ever changes.
- **`navigator.mimeTypes` was a plain array, not a `MimeTypeArray`.** `navigator.mimeTypes instanceof MimeTypeArray` returned **false**, which is false on no real browser (verified on unspoofed Chromium: ctor `MimeTypeArray`, tag `[object MimeTypeArray]`, instanceof true). This hit the **default `chrome` family**, so it was live for every config. It now carries the real prototype plus `item`/`namedItem`/iterator/`toStringTag`, mirroring what the plugins shim already did for `PluginArray` — the same bug class the harness caught for plugins previously, which `mimeTypes` never got.

## [3.5.0] - 2026-08-28

### Added
- **`.dnsignore` — skip dig confirmation on known-dead domains.** A user-maintained file in the project root (one domain per line; `#` comments and blanks ignored), loaded at startup. A dig-gated candidate that **equals, or is a subdomain of**, any listed entry (so `xptidujgjktk.com` also covers `www.xptidujgjktk.com`) is skipped **before any lookup** — no `dig`, no `SERVFAIL`/failure count, not captured. Purpose: kill the repeat noise from cloak/ad domains that were captured while live, added to your list, and have since been taken down (they `SERVFAIL` every run because the pages still reference them). Distinct from `ignoreDomains`, which runs the dig and only drops the *capture* — this skips the dig itself. Gitignored (per-clone user data); absent file is a no-op.
- **`--dnsignore-auto` (`dnsignore_auto` in `.nwssconfig`), default off** — after the run, auto-append newly-detected dead domains to `.dnsignore` so they're skipped next run. **Only `SERVFAIL`/`REFUSED`** (a resolver reached the authoritative NS and got nothing valid — genuinely dead); a **`timeout` is never added** (flaky link, possibly live). Deduped against existing entries (equals-or-subdomain aware, so an already-covered domain isn't re-added) — only *new* domains are appended, stamped with the date. Opt-in because it mutates a user file; the manual workflow (copy from the `Failed dig:` line) still works without it.
- **`--dig-retry-failed [n]` (`dig_retry_failed` in `.nwssconfig`), default off** — when a `dig` lookup exhausts its normal UDP failover + TCP fallback without an answer, make `n` extra TCP attempts (default 2, capped 5), each after a ~3s backoff, before giving up. Targets bursty/flaky resolvers where the first pass fails but a fresh attempt a few seconds later succeeds (the `digFailures` case). The recovered result flows through the **normal match path**, so the domain is captured **this run** — no re-run needed and no dependency on the (possibly rotated-away) domain reappearing. Backoff before each attempt is configurable via **`--dig-retry-backoff <ms>`** (`dig_retry_backoff`, default 3000, capped 60000) — raise it to outlast longer resolver bursts (a short pause only clears a brief drop; a longer one waits out a resolver that stays flaky for tens of seconds). The drain/per-URL budgets scale with the configured backoff so a late-completing retry is still captured. Bounded (retries capped at 5) and only reached on total failure, so extra latency applies to already-failing lookups only; healthy lookups are unaffected. To ensure a recovered late-firing lookup is actually captured (not cut off), the end-of-URL nettools drain ceiling and the per-URL timeout budget both grow by the retry latency **only when the flag is set** — the drain still resolves the instant all lookups finish, so the higher ceiling costs time only while a dig is genuinely still retrying. Off by default.
- **`--dig-max-concurrent <n>` (`dig_max_concurrent` in `.nwssconfig`), default `6`** — caps how many `dig` subprocesses run at once. A high `--max-concurrent` (e.g. 15) otherwise lets the scanner fire that many simultaneous lookups at the same handful of public resolvers; the burst gets rate-limited / dropped (and is rough on WSL2's UDP-through-NAT path), which is a common cause of `dig` timeouts on Cloudflare-fronted ad domains. A counting semaphore (mirroring the DNS pre-check's) paces the burst — excess lookups queue and drain as slots free. Only genuine **cache-miss** lookups contend for a slot: in-memory/disk-cache hits and single-flight-deduped callers bypass it entirely, and the cap is bounded by `--max-concurrent`, not the total URL count, so it never backs up a large batch. Set `0` (or negative) to disable the cap.

### Changed
- **Fingerprint spoof bumped Chrome 148 → 151, Firefox 151 → 154, Safari 19.5 → 26.6.** Chrome targets **151, not the newer 152 puppeteer bundles or the 153 the version-history API lists first** — the spoof exists to blend with the real population, and per Google's version-history API (win/stable, `endtime=none`) the serving split is 151 ≈74.5% (build `7922.174` alone 49%), 152 ≈25%, 153 ≈0.5%, so claiming the newest release would stand out rather than blend in. `CHROME_BUILD` → `7922.174`. The deterministic UA-CH GREASE is recomputed for the new major — brand `Not=A?Brand`, version `99`, and the brand-list **order** becomes `<grease>, Google Chrome, Chromium` (151 % 6 = 1); the order is hardcoded in two places that must agree or a detector cross-checking JS against HTTP sees the mismatch, so both `fingerprint.js`'s brands array and nwss.js's `Sec-CH-UA` / `-Full-Version-List` headers were updated. The derivation was verified by reproducing the documented 148 and 150 values before applying it to 151. Firefox per Mozilla's product-details API (`LATEST_FIREFOX_VERSION` 154.0.1); Safari per Apple's security-content page for 26.6.1 (2026-08-18) — Apple moved Safari to year-aligned versioning with macOS 26 Tahoe, so the 19.x → 26.x jump is real, not a typo. Also fixes a hardcoded fallback UA in nwss.js that had silently drifted a major behind the collection, so `curl` advertised a different Chrome than the browser did. Verified with `scripts/test-stealth.js` (sannysoft 29 passed / 0 failed) plus a live browser run confirming UA, brands and `uaFullVersion` all self-consistent.
- **puppeteer 25.1.0 → 25.9.0** (bundled Chromium → Chrome 152). Lockfile-only bump; `package.json` range (`>=24.0.0`) unchanged. The spoof deliberately presents **stable 151** regardless of the bundled 152 build — see the spoof entry above.
- **dig result cache enlarged: cap 2000 → 10000 entries, TTL 20h → 28 days.** Far more headroom so a large multi-URL run doesn't evict still-hot domains mid-run, and a much longer TTL so recurring domains survive across runs. Entries are tiny (a domain string + short dig output), so the memory cost is negligible. Two answers now stay pinned for the full window: a **changed A-record** (a domain that moves off a matched IP range, e.g. leaves Cloudflare) and an **NXDOMAIN** — which arrives as `success: true` because it is a real DNS answer rather than a failure, so a re-registered or restored domain still reads as dead until the entry expires. Delete `.digcache` when either case matters. Transient failures (timeout / SERVFAIL / REFUSED) are `success: false` and still never cached, so a flaky drop never persists.
- **`--adblock-engine` now defaults to `auto`** — Brave's `adblock-rs` when it is importable, the pure-JS matcher otherwise. Passing an explicit `js` or `rust` still pins the choice. The JS matcher is fast only when a URL's host hits its O(1) domain map; everything else falls through ~1,400 path/script rules **linearly**, and that miss path is *most real traffic* since ordinary page requests match no rule at all. Measured over `easylist.txt` (66,100 rules): **2.5µs** for a domain-map hit against **190µs** for a miss, and **148µs (js) vs 4µs (rust)** on the same miss workload. The result cache masks this until URLs are unique, which cache-busting query strings routinely make them — throughput falls from ~262k to ~6.5k URL/s. Verified as a speed change and **not** a behaviour change before switching the default: the two engines agreed on **4,118 of 4,118** verdicts over 3,118 real blocked domains sampled from EasyList plus 1,000 non-matching hosts. Selection resolves lazily inside the `--block-ads` path, so a run without it never attempts the native require; an auto-selected `rust` that fails to load warns and falls back to `js`, while an explicit `--adblock-engine=rust` still errors, so a deliberate choice is never silently downgraded.
- **Dependency refresh** — `ip-address` 10.2.0 → 10.5.0 (clears three Dependabot advisories: octal-octet parsing, CIDR-suffix special-use suppression, IPv4-mapped/NAT64 misclassification — all SSRF / trust-boundary bypasses). It arrives transitively via `socks`, whose `^10.1.1` range already permitted the fix, so no `overrides` entry was needed. Also eslint 10.6.0 → 10.9.1, globals 17.7.0 → 17.11.0, lru-cache 11.5.1 → 11.5.2, p-limit 7.3.0 → 7.3.1, adblock-rs 0.12.5 → 0.12.6. `npm audit` reports 0 vulnerabilities.

### Security
- **OpenVPN `extra_args` deny-list** — openvpn runs under `sudo`, so a config could previously hand it directives that execute code as root. `--config` is the entry that makes the rest necessary: it points openvpn at a second config file which can itself carry `script-security 2` plus `up`/`down`, reinstating everything else the list blocks. `--iproute` names the command openvpn shells out to for route setup. Plus the script hooks (`--script-security`, `--up`, `--down`, `--tls-verify`, `--plugin`, `--route-up`, `--ipchange`, `--auth-user-pass-verify`, `--auth-user-pass`, `--client-connect`, `--client-disconnect`, `--learn-address`, `--tls-crypt-v2-verify`, `--route-pre-down`, `--askpass`). `--writepid` is blocked for a different reason — not code execution but a root-controlled file create/clobber: openvpn's duplicate-option precedence is **last-wins** for it, so an `extra_args` copy overrode the one the scanner sets and pointed the root-written pid file at any path. (`--log`/`--log-append` are deliberately *not* blocked: measured on openvpn 2.6.19 they are **first-wins** and the scanner emits its own first, so a config copy is already inert.) A config naming a blocked flag is rejected at validation with an error naming it, and `buildArgs` drops the flag *and its value* as defence in depth.
- **curl/grep confined to http/https** — both `lib/curl.js` and `lib/grep.js` now pass `--proto '=http,https'` alongside `--proto-redir`. `--proto` is the load-bearing half: without it a `file://` *initial* URL was read straight off disk (verified — `file:///etc/passwd` returned 1539 bytes). Measured on curl 8.5, `--proto-redir` alone mostly restates curl's own defaults (file/dict/gopher/ldap/smb/scp/sftp/imap/tftp redirect hops are already refused) and adds only ftp/ftps. `lib/grep.js` also gains the `--` end-of-options marker `lib/curl.js` already had, and `lib/curl.js` drops CR/LF-bearing custom headers (header injection).
- **One connection-name rule for OpenVPN** — `validateOvpnConfig` and the `pkill -f` guard previously used two different charsets, so they disagreed and the looser one could never fire for a config-provided `name`, while names derived from a config *filename* (which may contain dots) were checked only by the looser one. Unified on the dot-permitting rule, and the name is now regex-escaped where it reaches `pkill -f` — unescaped, `us.east` also matched `usXeast` and could `TERM` an unrelated openvpn process. Traversal stays impossible: no path separator is permitted and every `path.join` site appends an extension.
- **Tightened file permissions** — the OpenVPN log is pre-created `0o600` (was `0o666`, world-readable/tamperable), `auth_file` is confined to the project directory or system temp (blocking `--auth-user-pass /etc/shadow`), `verbosity` is clamped to `1-6`, and the smart-cache disk write is `0o600`.

### Fixed
- **Subdomain fallback for the dig gate** — in default root-dig mode (`digSubdomain: false`), the `dig`/`dig-or` confirmation queried only the registrable root of a requested host. For a domain that serves DNS on a **subdomain** (dead/parked apex, but `abc.example.com` resolves — common for CDN/ad infra), the root-dig came back empty/SERVFAIL and the domain was **dropped even though the requested subdomain is live and matches**. Now, when the root-dig doesn't confirm and the request was to a *distinct* subdomain, the gate **re-digs the exact requested name** before giving up. Recovers those captures, and makes the failure report honest — the failure count is now **deferred until after the fallback** (counted once per candidate, on the root's reason) so a subdomain-recovered domain is no longer mislabeled a `SERVFAIL`/dead failure. Zero cost on the common path (only fires after an already-unconfirmed root-dig, only when a distinct subdomain exists); output rule is unchanged (`||root^`, which covers subdomains anyway).
- **End-of-run dig-failure report, with cause codes** — a `warn` line reports how many `dig` lookups exhausted every attempt (UDP failover + TCP fallback) without an answer, followed by a `Failed dig:` line **naming each domain and its failure reason** — `SERVFAIL`, `REFUSED`, or `timeout` (mirrors the `Fresh dig:` sample). The reason distinguishes a **dead/broken domain** (`SERVFAIL`/`REFUSED` — a resolver reached the authoritative NS and got nothing valid; **no capture was lost**, retries can't help) from a **flaky link** (`timeout` — never got a reply; worth `--dig-retry-failed` or a caching resolver). Previously a fully-failed dig was silent, and even once surfaced it couldn't tell "the resolver dropped a live domain" from "the domain is dead" — so a rotated-away cloak domain returning SERVFAIL looked identical to real link flakiness. A one-line legend explains the codes. Prints only when non-zero (healthy runs stay quiet) and respects `--silent`; failures aren't cached, so a re-run retries them.
- **`dig` lookups fall back to TCP after UDP fails** — on flaky links (notably WSL2's UDP-through-NAT path, where datagrams to public resolvers vanish silently and a bare retry then succeeds) a single failed UDP burst made the whole lookup fail, and since transient failures aren't cached the domain silently dropped out of `dig`/`dig-or` matching for that run. Each lookup now appends a **TCP fallback** as its last attempt (`+tcp`, which retransmits through the NAT where UDP is dropped), preceded by a short 400ms backoff on the already-failing path to let a transient burst clear. UDP is still tried first (fast on a healthy link), so successful lookups are unaffected; the fallback only runs after UDP has failed. Applies to both the system-resolver path and the pinned `--dns` failover.
- **Cloudflare `Promise.race` timer leak** — five challenge-handling races created a `setTimeout` that was never cleared when the Puppeteer side won, which is the common, fast path. Each now captures the timer and clears it in `.finally()`. Buffer ordering verified (10s vs 12s, 3s vs 3.5s), so the Puppeteer promise always rejects first and the timer arm is a pure safety net.
- **`.nwssconfig` flags matched by substring** — the presence check used `includes()` against the joined argv, so `--dns` matched inside `--dns-cache` and a config's `dns` setting was silently dropped whenever `--dns-cache` was on the CLI. Now an exact-token match against a snapshot of the args, taken once rather than re-split per settings key, and `--flag=value` counts as present so a config value isn't appended as a duplicate the parser then ignores.
- **`processResults` was skipped for most configs** — the post-scan pass ran only when at least one site had `firstParty: false`, despite a comment claiming it always ran, so the `ignoreDomains` safety net and dedup never fired for any other config. It now always runs; the first-party steps remain internally guarded, so this is a no-op for configs that don't need them.
- **Random-coordinate generation could go out of bounds** — the guard against a viewport smaller than its own margins covered only the standard branch, leaving `preferEdges`/`avoidCenter` exposed, and the fixed 200px edge zone overflowed narrow viewports (101×101 produced `y = -124`). The range guard is now hoisted above every branch and the edge zone is clamped to the usable span. Output is byte-identical to before on any viewport with a ≥200px usable span (verified across 3,600 seeded cases).
- **Smart-cache temp files were orphaned on failure** — the pid-suffixed temp file is now unlinked on write/rename error. The pid suffix (which fixes concurrent clobbering) meant every failure stranded a file permanently, where the old fixed `.tmp` name was simply overwritten on the next save.
- **`shouldIgnoreSimilarDomain` threw on a null list** — `Array.from(undefined)` throws, contrary to the comment claiming the guard handled it safely. Null-checked first.
- **Redirect-chain dedup was O(n²)** — the chain array was scanned with `.includes()` on every candidate hop; a parallel `Set` now backs the membership check.
- **Regex cache cleared wholesale at its cap** — `_compiledRegexCache` called `.clear()` on reaching 2000 entries, forcing every live pattern to recompile at once. Now evicts the single oldest entry (FIFO).
- **Content-type check precompiled** — `shouldAnalyzeContentType` scanned a 15-entry array with `.some(startsWith)` per response; replaced with one `^`-anchored regex, verified equivalent across 20 content types including near-misses.

## [3.4.0] - 2026-06-13

### Added
- **`redirect_first_party` site option** (default `true`) — by default a redirect's destination domains (and chain hops) are registered first-party so the landed site's own resources aren't captured as third-party. Set `false` to keep redirect targets **third-party**, so `filterRegex`/`dig` apply to them under `thirdParty: true` — e.g. capturing the end domain of an ad/cloak redirect chain (which Chrome reaches via the `ERR_TOO_MANY_REDIRECTS` curl-resolve recovery). The originally-scanned domain stays first-party either way.
- **`ERR_TOO_MANY_REDIRECTS` is recovered, not hard-failed** — a redirect-cloaking chain (rotating throwaway domains) can exceed Chrome's ~20-hop ceiling. The scanner now recovers via two complementary paths: **(1)** it first waits briefly for the browser to *ride through* on its own — a JS/meta hop on a committed page resets Chrome's hop counter and often carries the page to the end site for free; **(2)** if the page parked on `chrome-error://` instead **and the site has `curl: true`**, it resolves the chain endpoint with `curl` (which, unlike headless Chrome, isn't served the endless-loop variant) and navigates there directly — a short hop that lands on the real end site. Either way it captures the end site's ad/tracker requests; falls back to the captured chain requests when neither path lands. The curl step is opt-in via the existing `curl` site option (so `curl: false`/unset never shells out to curl) and is also **skipped under a proxy/VPN** (curl runs direct and would leak the real IP / resolve from the wrong network); the free ride-through always applies.
- **`click_elements` site option** — after a page loads, click a list of CSS selectors **in order** (searched across the main frame and any iframe) (e.g. `["a[href*='/movie/']", ".play"]` to click a movie link then a play button). Reaches content via organic navigation/gesture instead of a direct deep-load, which some sites JS-redirect away, and triggers click-only content like video players. Each selector is `waitForSelector`-ed (visible) up to `click_wait` before clicking, so JS-rendered targets like video players aren't missed by racing ahead of them. The request interceptor stays attached, so the post-click page's requests run through the same `filterRegex`/`dig` matching; a click that navigates is followed and later selectors query the resulting page. Honors `realistic_click` (genuine trusted gesture) and `cursor_mode: "ghost"` (Bezier travel to the element); missing elements are skipped and never fail the scan. Settle/nav wait per click via `click_wait` (default 5000ms, capped at half the per-URL timeout).
- **`--dns` now also pins Chrome's page-navigation resolver via DoH.** Chrome ignores `--dns` for navigation and reads `/etc/resolv.conf` directly, so a broken or filtering system resolver could `ERR_NAME_NOT_RESOLVED` a domain the pre-check had already resolved. When the `--dns` servers map to a known public DoH provider — **Google, Cloudflare, Quad9, OpenDNS, AdGuard, CleanBrowsing, DNS.SB, Mullvad** (incl. malware/family/unfiltered variants) — Chrome is launched with secure-DNS `automatic` mode pointed at that provider, so page navigation resolves through the same resolver as the pre-check. `automatic` (not `secure`) keeps a system-DNS fallback if DoH is unreachable rather than failing the batch. **Applied to direct connections only** — skipped when a proxy (`--proxy-server`) or VPN is active, since the exit/tunnel does the resolution and local DoH would be redundant or resolve geo-split domains to the wrong region. Unmapped resolvers (custom/ISP, per-account providers like NextDNS, IPv6) fall back to system DNS with a warning naming the supported providers.
- **`--doh-disable`** site/CLI option (`doh_disable` in `.nwssconfig`), default off — opt out of the Chrome-navigation DoH pinning entirely. Chrome then resolves page navigation via the system `resolv.conf` even when `--dns` maps to a known provider, while the pre-check and `dig` still honor `--dns`. For networks where DoH adds latency or is blocked, or when system-path resolution is specifically wanted.

### Changed
- **A clamped `delay` is now logged (`--debug`)** — when `delay` exceeds its ceiling (the default 2s cap, or `timeout/2` under `delay_uncapped: true`) it was silently reduced, so `delay: 48000` quietly running as 29000ms looked like the flag was ignored. A debug line now reports the clamp and which ceiling applied (raise `timeout`, or set `delay_uncapped: true`, to lift it). The per-URL budget already reserves the full configured `delay`; this only surfaces the post-load dwell clamp.
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
