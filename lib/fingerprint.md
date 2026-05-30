# `lib/fingerprint.js` — Fingerprint Spoofing Coverage

Bot-detection evasion for the scanner's headless Chromium. The goal is to make a
scanned page see a coherent, real-Chrome **Stable** desktop profile rather than a
headless/automation signature — and, just as important, to keep every spoofed
value **internally consistent** (JS ↔ HTTP, claimed-value ↔ observable reality)
so a detector cross-checking two surfaces can't catch a mismatch.

## How it works

Spoofing is applied per page, before navigation, by `applyAllFingerprintSpoofing(page, siteConfig, …)`, which runs three stages:

| Stage | Gate (siteConfig) | What it covers |
|---|---|---|
| `applyUserAgentSpoofing` | **`userAgent`** (defaults to `"chrome"`) | Browser identity, automation/headless tells, and the bulk of the navigator/JS-API suite |
| `applyBraveSpoofing` | Brave-mode only | Brave-specific surfaces |
| `applyFingerprintProtection` | **`fingerprint_protection`** (`true` \| `"random"`) | Hardware fingerprint *values* (canvas/WebGL/audio noise, screen, memory) + CDP timezone. `"random"` seeds them per-domain (stable per site, varies across sites) |

HTTP **Client Hints** request headers are set separately in `nwss.js` (gated on a `chrome` userAgent). Identity is pinned to **Stable Chrome** via two constants in `fingerprint.js` (`CHROME_BUILD`, `CHROME_GREASE_BRAND`) + the major in `USER_AGENT_COLLECTIONS` — see `feedback_chrome_spoof_version_bump`.

**Gate legend:** `UA` = runs with `userAgent` set (on by default) · `FP` = runs with `fingerprint_protection` · `HTTP` = request header set in nwss.js.

## Browser identity

| Surface | Mitigation | Gate |
|---|---|---|
| `navigator.userAgent` / `appVersion` | Pinned to Stable Chrome 148 desktop UA | UA |
| `navigator.userAgentData` (brands, platform, mobile) | Spoofed; brand order + GREASE string match real Chrome of the major exactly | UA |
| `getHighEntropyValues()` | Full set: architecture, bitness, model, **wow64**, platformVersion, **uaFullVersion**, fullVersionList, **formFactors** — build from `CHROME_BUILD`, consistent with HTTP | UA |
| `navigator.platform` / `vendor` / `productSub` / `vendorSub` | Spoofed UA-consistent (`Win32`, `Google Inc.`, `20030107`, `""`) | UA |
| `Sec-CH-UA`, `-Platform`, `-Platform-Version`, `-Mobile`, `-Arch`, `-Bitness`, `-WoW64`, `-Model`, `-Full-Version`, `-Full-Version-List`, `-Form-Factors` | Set to match the JS values (same brand order/grease/build) | HTTP |

## Automation & headless tells

| Surface | Mitigation | Gate |
|---|---|---|
| `navigator.webdriver` | Forced `false` (launch flag + JS) | UA |
| `cdc_…` / `$cdc_…` / selenium / phantom props | Removed | UA |
| `window.chrome` + `chrome.runtime` | Provided / simulated | UA |
| `<html webdriver>` attribute | Stripped | UA |
| `navigator.plugins` / `mimeTypes` | Native 5-PDF set preserved (matches real Chrome) | UA |
| `navigator.bluetooth` | Stub added (`getAvailability()→false`) — real Chrome always exposes it | UA |
| `navigator.share` / `canShare` | Stubs added (Web Share; absent in headless) | UA |
| `speechSynthesis.getVoices()` | Claimed-OS voice set (Windows → Microsoft + Google, 22 voices) | UA |
| `Notification.permission` / `permissions.query` | `default` / consistent results | UA |
| `navigator.userActivation` / `getInstalledRelatedApps` / `document.hasStorageAccess` | Stubs (present in real Chrome) | UA |

## Hardware & rendering

| Surface | Mitigation | Gate |
|---|---|---|
| WebGL `UNMASKED_VENDOR/RENDERER` | Spoofed GPU from an OS-appropriate pool (per-domain seeded) | UA + FP |
| Canvas (`toDataURL`/`getImageData`) | Per-canvas noise (WeakMap-cached) | UA + FP |
| AudioContext / `AudioBuffer` | `getChannelData`/`copyFromChannel` intercepted to defeat audio fingerprint | UA + FP |
| Fonts (`measureText`/offset probes) | Normalized font metrics | UA |
| `screen.*` (width/height/avail/colorDepth) | Spoofed (1920×1080, colorDepth 24) | UA + FP |
| `navigator.hardwareConcurrency` | Spoofed down to 4–8 (hides datacenter core count; no HTTP counterpart) | FP |
| `navigator.deviceMemory` (JS) + `Sec-CH-Device-Memory` (HTTP) | Both pinned to **8** (hides 32 GB host; JS = HTTP, gated together on FP) | FP / HTTP |
| `PerformanceNavigationTiming` | Jittered to defeat timing fingerprint | UA |

## Sensors, locale & network

| Surface | Mitigation | Gate |
|---|---|---|
| Battery Status API | Plugged-in default (`charging:true, level:1, dischargingTime:Infinity`) — blends with the majority | UA |
| `navigator.connection` (rtt/downlink/effectiveType) | **Native** (left untouched when present) — truthful to the real network so it survives a timing cross-check | — |
| `navigator.languages` / `language` | `["en-US","en"]` / `en-US` | UA |
| **Timezone** (`Date`, `Intl`, `getTimezoneOffset`) | CDP `emulateTimezone()` — makes all three consistent + DST-correct (replaced broken JS overrides) | FP |
| `matchMedia` hover/pointer/color-scheme | Desktop-consistent (`hover`, `fine` pointer) | UA |
| `maxTouchPoints` | UA-consistent (`0` on desktop) | UA |
| WebRTC ICE candidates | All candidates stripped → no STUN public-IP leak past the proxy | UA |
| `mediaDevices.enumerateDevices` | Plausible device set | UA |

## Anti-introspection

| Surface | Mitigation | Gate |
|---|---|---|
| `Function.prototype.toString` | Every overridden function masked to `function X() { [native code] }` (bulk + per-instance) | UA |
| `Error.stack` / `prepareStackTrace` | Sanitized so injected frames don't leak | UA |
| Console error noise from spoofs | Suppressed | UA |

## Known limitations (not fixable at the browser layer)

| Vector | Why it's out of scope | Mitigation |
|---|---|---|
| **IP reputation** | A datacenter IP is the single biggest tell; no JS/header spoof touches it | Residential **proxy/VPN** (`lib/proxy.js`, `lib/wireguard_vpn.js`, `lib/openvpn_vpn.js`) |
| **TLS (JA3/JA4) + HTTP/2 fingerprint** | Negotiated below the JS layer | Puppeteer's Chromium already presents a genuine Chrome stack; a MITM proxy can alter it |
| **Timezone vs exit-IP geolocation** | Timezone is now internally consistent, but the *chosen* zone should match the proxy's country | Per-proxy geo config (not yet wired) |
| **Behavioural / mouse dynamics** | Statistical, not a property | `interact` / `ghost-cursor` config (`lib/interaction.js`) |

## Verification

- **`scripts/test-stealth.js`** — automated smoke test against sannysoft / creepjs / browserleaks. Run before/after a spoof change and diff.
- **Manual reference diff** — launch with the spoof applied and compare each surface against a real Chrome of the pinned major (the coverage above was validated field-for-field against a live Chrome 148 desktop). The unspoofed deviations are deliberate: `hardwareConcurrency`/`deviceMemory` downscaled to hide the host, and `connection` left native.
