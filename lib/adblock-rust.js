// === Adblock Rust Engine Wrapper (adblock-rust.js) ===
// Drop-in replacement for ./lib/adblock that delegates matching to Brave's
// adblock-rust engine (npm: adblock-rs) for higher throughput on large lists.
//
// Exposes the same parseAdblockRules(filePath, options) factory and the same
// matcher METHODS ({ shouldBlock, getStats }) so nwss.js can switch engines with
// a single require() swap.
//
// It deliberately does NOT expose lib/adblock.js's `rules` object. That is that
// engine's own parsed state (domainMap, pathRules, whitelist, ...) with no
// adblock-rust equivalent: the rules live inside the native engine, and on a
// disk-cache hit the rule text is never read at all. Nothing in the tree reads
// matcher.rules, so the swap holds -- but a caller that wants it cannot be
// served by this backend, which is why the claim is spelled out rather than
// implied.

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { formatLogMessage, messageColors } = require('./colorize');
// Subsystem tag matches the project convention used by other modules
// (lib/adblock.js, flowproxy, cloudflare, curl, grep, etc.).
const ADBLOCK_RUST_TAG = messageColors.processing('[adblock-rust]');

// Mirrors lib/adblock.js:13. Used only for the startup rule COUNT -- every line
// is still handed to the engine; these options merely mean a line cannot block
// a network request, so counting it as a "blocking rule" overstates the banner.
const COSMETIC_OPTIONS = ['generichide', 'elemhide', 'specifichide', 'genericblock'];

let adblockRust = null;
let adblockRustVersion = null;
function loadAdblockRust() {
  if (adblockRust) return adblockRust;
  try {
    adblockRust = require('adblock-rs');
    // Read once for the cache key — serialized engine format is not promised
    // stable across versions, so partitioning cache files by version means
    // upgrades cleanly invalidate without producing confusing deserialize
    // failures on the warm path.
    adblockRustVersion = require('adblock-rs/package.json').version;
  } catch (err) {
    throw new Error(
      "adblock-rs is not installed. Install with: npm install adblock-rs " +
      "(requires Rust toolchain for native build). Original error: " + err.message
    );
  }
  return adblockRust;
}

/**
 * True when the optional adblock-rs native module can be loaded. Lets nwss.js
 * auto-select the faster Rust backend without making a Rust toolchain a hard
 * requirement. Swallows the load error deliberately: absence is a normal,
 * supported state here, not a failure — parseAdblockRules still throws the
 * descriptive install message for anyone who asked for rust explicitly.
 * @returns {boolean} true when adblock-rs is importable
 */
function isAvailable() {
  try {
    loadAdblockRust();
    return true;
  } catch {
    return false;
  }
}

// Best-effort cleanup of stale serialized engines. Filter lists change roughly
// monthly; cache files older than this are unlikely to be reused and only cost
// disk space. Runs once per cold parse and swallows all errors — cleanup
// failure must never block a scan.
function pruneOldCacheFiles(cacheDir, maxAgeMs) {
  try {
    const cutoff = Date.now() - maxAgeMs;
    const files = fs.readdirSync(cacheDir);
    for (const name of files) {
      // Only touch our own files; `.tmp` covers stray writes from killed
      // processes. Skip anything else (in case the dir is shared).
      if (!name.endsWith('.bin') && !name.endsWith('.tmp')) continue;
      const full = path.join(cacheDir, name);
      try {
        if (fs.statSync(full).mtimeMs < cutoff) fs.unlinkSync(full);
      } catch (_) { /* file vanished mid-walk — fine */ }
    }
  } catch (_) { /* dir doesn't exist or unreadable — fine */ }
}

/**
 * Is the compiled-engine cache directory safe to read from / write to?
 *
 * The cache path is PREDICTABLE: a fixed folder under os.tmpdir() (mode 1777,
 * so any local user may create entries) holding files named
 * sha256(adblock-rs version + raw list bytes). Filter lists are public, so the
 * filename is computable by anyone who knows which lists are in use. Without a
 * check, a local user could pre-create the directory (mkdirSync with
 * recursive:true silently accepts an existing one and does NOT apply its mode
 * argument to it -- verified) and plant a .bin that we would hand straight to
 * the native deserializer: at best they choose our blocking verdicts, silently;
 * at worst it is malformed input to a Rust deserializer.
 *
 * Absent is fine -- we create it 0700 below. Present is only trusted when it is
 * a real directory we own with no group/other write bit. Untrusted means the
 * cache is skipped entirely, which costs one parse and nothing else.
 * @param {string} dir - Candidate cache directory
 * @returns {{ok: boolean, reason: string|null}}
 */
function cacheDirIsTrustworthy(dir) {
  // No POSIX ownership model to check against (Windows): trust it rather than
  // disabling the cache on every run there.
  if (typeof process.getuid !== 'function') return { ok: true, reason: null };
  let st;
  try {
    st = fs.lstatSync(dir);
  } catch (err) {
    if (err.code === 'ENOENT') return { ok: true, reason: null };
    return { ok: false, reason: err.message };
  }
  if (st.isSymbolicLink()) return { ok: false, reason: 'is a symlink' };
  if (!st.isDirectory()) return { ok: false, reason: 'is not a directory' };
  if (st.uid !== process.getuid()) return { ok: false, reason: `owned by uid ${st.uid}` };
  if ((st.mode & 0o022) !== 0) return { ok: false, reason: 'writable by group/other' };
  return { ok: true, reason: null };
}

// Map Puppeteer/CDP resource type names to adblock-rust request types.
// Uses a null-prototype object so lookups skip the prototype chain — small but
// free win on a hot-path lookup that runs once per network request.
const RESOURCE_TYPE_MAP = Object.assign(Object.create(null), {
  'document':            'main_frame',
  'subdocument':         'sub_frame',
  'stylesheet':          'stylesheet',
  'script':              'script',
  'image':               'image',
  'font':                'font',
  'media':               'media',
  'texttrack':           'media',
  'xhr':                 'xmlhttprequest',
  'fetch':               'xmlhttprequest',
  'xmlhttprequest':      'xmlhttprequest',
  'eventsource':         'other',
  'websocket':           'websocket',
  'manifest':            'other',
  'signedexchange':      'other',
  'ping':                'ping',
  'cspviolationreport':  'other',
  'preflight':           'other',
  'other':               'other'
  // No '' entry: shouldBlock short-circuits on a falsy resourceType and never
  // performs the lookup, so one here would be dead weight on a hot-path object.
});

// Removed: normalizeResourceType() helper. The hot path in shouldBlock
// inlines the (RESOURCE_TYPE_MAP[rt] || 'other') lookup directly to skip
// the function-call frame; the standalone helper had zero callers.

// Small FIFO cache keyed on (url \0 sourceUrl \0 resourceType). Eviction
// is insertion-order — `get()` does not promote. For this workload
// (per-page request bursts whose working set fits in maxSize) FIFO and
// true LRU produce the same evictions, so the simpler path wins. If
// cache effectiveness becomes a concern with larger working sets,
// promote on hit by re-inserting (delete + set). Renamed from ResultLRU
// since the previous name lied about the eviction policy — matches
// the FIFOCache rename in lib/adblock.js.
class FIFOCache {
  constructor(maxSize) {
    this.cache = new Map();
    this.maxSize = maxSize;
  }
  get(k) { return this.cache.get(k); }
  set(k, v) {
    if (this.cache.size >= this.maxSize) {
      this.cache.delete(this.cache.keys().next().value);
    }
    this.cache.set(k, v);
  }
}

/**
 * Build a request-blocking matcher backed by Brave's adblock-rs engine.
 *
 * @param {string|string[]} filePathOrArray - One filter list path, or an array
 *   of paths to load in order. Order is significant: it affects rule
 *   precedence and the cache key.
 * @param {object} [options]
 * @param {boolean} [options.enableLogging=false] - Print parse + cache events.
 * @param {number} [options.resultCacheSize=32000] - Max entries in the
 *   per-matcher result cache (FIFO eviction).
 * @param {boolean} [options.useDiskCache=true] - Persist the compiled engine
 *   to disk and reload on next run with the same input lists + library version.
 * @param {string} [options.cacheDir] - Directory for compiled-engine cache
 *   files. Defaults to a folder under the OS temp dir.
 * @param {number} [options.cacheTtlMs=2592000000] - Files in cacheDir older
 *   than this are pruned during cold parse. Default 30 days.
 * @returns {{shouldBlock: Function, getStats: Function}} No `rules` field --
 *   see the note at the top of this file.
 */
function parseAdblockRules(filePathOrArray, options = {}) {
  const {
    enableLogging = false,
    resultCacheSize = 32000,
    useDiskCache = true,
    cacheDir = path.join(os.tmpdir(), 'nwss-adblock-rs-cache'),
    cacheTtlMs = 30 * 24 * 60 * 60 * 1000
  } = options;
  const rust = loadAdblockRust();

  // Accept a single path or an array of paths — caller no longer needs to
  // materialize a temp concatenation file for multi-list scans.
  const filePaths = Array.isArray(filePathOrArray) ? filePathOrArray : [filePathOrArray];

  // Read all files up front; hash the raw bytes so the disk cache key reflects
  // both content changes and list-order changes. Mix in the adblock-rs version
  // so a library upgrade (which may change the serialized format) doesn't try
  // to deserialize an incompatible blob.
  const buffers = [];
  const hash = crypto.createHash('sha256');
  hash.update('adblock-rs:' + adblockRustVersion + '\0');
  let totalBytes = 0;
  for (const fp of filePaths) {
    let buf;
    try {
      buf = fs.readFileSync(fp);
    } catch (err) {
      throw new Error(`Adblock rules file not found: ${fp}`);
    }
    buffers.push(buf);
    hash.update(buf);
    hash.update('\0');
    totalBytes += buf.length;
  }
  const cacheKey = hash.digest('hex');
  const cachePath = path.join(cacheDir, cacheKey + '.bin');

  let engine = null;
  let ruleCount = 0;
  let cacheHit = false;

  // Fast path: deserialize a previously-compiled engine if available.
  // Skip the existsSync/readFileSync double-syscall pattern — let readFileSync
  // throw ENOENT and treat it as a clean cache-miss. Avoids a redundant stat()
  // and the TOCTOU race where the cache file could be removed between the
  // exists check and the read.
  const dirTrust = useDiskCache ? cacheDirIsTrustworthy(cacheDir) : { ok: false, reason: null };
  if (useDiskCache && !dirTrust.ok && enableLogging) {
    console.log(formatLogMessage('warn', `${ADBLOCK_RUST_TAG} Ignoring cache dir ${cacheDir} (${dirTrust.reason}); parsing from source`));
  }
  if (useDiskCache && dirTrust.ok) {
    let compiled;
    // Open first, then fstat the DESCRIPTOR. Checking the path with stat and
    // then reading it would leave a TOCTOU window in which the file could be
    // swapped for someone else's between check and read; a descriptor cannot be
    // substituted underneath us.
    let fd = null;
    try {
      fd = fs.openSync(cachePath, 'r');
      const fst = fs.fstatSync(fd);
      if (!fst.isFile()) throw new Error('cache entry is not a regular file');
      if (typeof process.getuid === 'function' && fst.uid !== process.getuid()) {
        throw new Error(`cache entry owned by uid ${fst.uid}, not us`);
      }
      compiled = fs.readFileSync(fd);
    } catch (err) {
      if (err.code !== 'ENOENT' && enableLogging) {
        console.log(formatLogMessage('debug', `${ADBLOCK_RUST_TAG} Cache read failed (${err.message}); reparsing`));
      }
    } finally {
      if (fd !== null) { try { fs.closeSync(fd); } catch (_) {} }
    }
    if (compiled) {
      try {
        engine = new rust.Engine(new rust.FilterSet(enableLogging), true);
        // Avoid copying the ~10MB serialized engine when the underlying
        // ArrayBuffer is exclusively ours (true for any read above Node's
        // ~4KB Buffer pool threshold — i.e. always for compiled engines).
        // Fall back to slicing only when the Buffer is a view into a pooled
        // backing store, which would otherwise leak unrelated data.
        const ab = (compiled.byteOffset === 0 &&
                    compiled.byteLength === compiled.buffer.byteLength)
          ? compiled.buffer
          : compiled.buffer.slice(
              compiled.byteOffset,
              compiled.byteOffset + compiled.byteLength
            );
        engine.deserialize(ab);
        cacheHit = true;
        // Mark the entry as freshly used BEFORE the prune below. The TTL exists
        // to drop files that "are unlikely to be reused" -- an entry we just
        // deserialized is by definition still in use, but its mtime is the
        // original write time, so a cache older than the TTL would be read
        // successfully and then deleted by our own prune, forcing a pointless
        // cold reparse on the next run with unchanged lists. Measured before
        // this: hit on an aged file, then `file still present: false`.
        try {
          const nowTs = new Date();
          fs.utimesSync(cachePath, nowTs, nowTs);
        } catch (_) { /* read-only dir or file vanished — prune just skips it */ }
      } catch (err) {
        // Corrupt cache or version mismatch — fall through to a fresh parse.
        engine = null;
        if (enableLogging) {
          console.log(formatLogMessage('debug', `${ADBLOCK_RUST_TAG} Cache deserialize failed (${err.message}); reparsing`));
        }
      }
    }
    // Prune on the WARM path as well. Previously this ran only after a cold
    // parse's cache write, so a cache that keeps hitting -- the normal state for
    // an unchanged list -- never pruned at all, and stale .bin/.tmp files from
    // older lists accumulated indefinitely, which is exactly what the TTL is
    // for. Safe here because the hit path writes nothing, so there is no
    // just-created entry to protect.
    if (cacheHit) pruneOldCacheFiles(cacheDir, cacheTtlMs);
  }

  if (!engine) {
    // Slow path: parse every list. Use addFilters per-file so a single bad
    // line in one list does not blast the whole input, and so the per-list
    // line count is correct. Release each buffer's reference as soon as it
    // is consumed so GC can reclaim the file bytes mid-loop instead of
    // holding all input files (~3-5MB combined for easylist+easyprivacy)
    // alive until the function returns.
    const filterSet = new rust.FilterSet(enableLogging);
    for (let i = 0; i < buffers.length; i++) {
      const buf = buffers[i];
      buffers[i] = null;
      const lines = buf.toString('utf-8').split('\n');
      // Count actual rules for the startup banner. Skip:
      //   - empty lines
      //   - whitespace-only lines (trim then re-check length)
      //   - '!'-prefixed comments (standard adblock)
      //   - '['-prefixed filter list headers (e.g. '[Adblock Plus 2.0]')
      // Previously only the first two skip conditions ran on the raw line,
      // so whitespace lines + headers inflated the displayed count.
      for (let j = 0; j < lines.length; j++) {
        const line = lines[j];
        if (line.length === 0) continue;
        const trimmed = line.trim();
        if (trimmed.length === 0) continue;
        const c = trimmed.charCodeAt(0);
        if (c === 0x21 || c === 0x5B) continue;  // '!' or '['
        // Cosmetic filters are NOT blocking rules. shouldBlock() only does
        // network matching, so element-hiding rules can never block a request --
        // counting them made the banner report 89825 "blocking rules" for
        // easylist where the js engine reported 66099, a 23726-rule gap that
        // looked like the rust backend loading far more than it does. Measured
        // on easylist: 23587 '##'/'#@#' lines + 139 cosmetic-option lines, and
        // 89825 - 23587 - 139 is exactly the js engine's 66099. Skipped for the
        // count only; addFilters() below still receives every line.
        if (trimmed.includes('##') || trimmed.includes('#@#')) continue;
        let cosmeticOnly = false;
        for (let k = 0; k < COSMETIC_OPTIONS.length; k++) {
          const opt = COSMETIC_OPTIONS[k];
          if (trimmed.includes('$' + opt) || trimmed.includes(',' + opt)) { cosmeticOnly = true; break; }
        }
        if (cosmeticOnly) continue;
        ruleCount++;
      }
      filterSet.addFilters(lines);
    }
    engine = new rust.Engine(filterSet, true);

    if (useDiskCache && dirTrust.ok) {
      try {
        // 0700 so the compiled engine cannot be swapped by another local user.
        // Only effective on a directory WE create -- recursive:true leaves an
        // existing one's mode alone, which is why cacheDirIsTrustworthy() gates
        // the whole cache above instead of relying on this.
        fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
        const serialized = engine.serialize();
        // Atomic write: writeFileSync to a per-pid tmp path then rename. If
        // the process is killed mid-write we leave a stray .tmp file (cleaned
        // up by the TTL prune on a future run) but the final cachePath is
        // either complete or absent — never half-written.
        const tmpPath = cachePath + '.' + process.pid + '.tmp';
        // Buffer.from(buffer) ALWAYS copies — wasteful when adblock-rs's
        // serialize() already returns a Buffer (binding-version dependent).
        // For a ~10MB compiled engine that's a pointless 5-10ms allocate+
        // memcpy on the cold-cache-write path.
        const out = Buffer.isBuffer(serialized) ? serialized : Buffer.from(serialized);
        // Drop any stale tmp first -- unlink removes the LINK, so a symlink
        // planted at this path is deleted rather than followed. Then 'wx'
        // (O_CREAT|O_EXCL) refuses to open anything that already exists, so the
        // write cannot be redirected into a file of someone else's choosing.
        try { fs.unlinkSync(tmpPath); } catch (_) { /* nothing there — expected */ }
        fs.writeFileSync(tmpPath, out, { mode: 0o600, flag: 'wx' });
        fs.renameSync(tmpPath, cachePath);
        // Best-effort prune of stale cache files. Done after our own write so
        // we never delete the entry we just created.
        pruneOldCacheFiles(cacheDir, cacheTtlMs);
      } catch (err) {
        if (enableLogging) {
          console.log(formatLogMessage('warn', `${ADBLOCK_RUST_TAG} Cache write failed (${err.message}); continuing`));
        }
      }
    }
  }

  const stats = {
    // When deserialized from cache we don't see the rules; report bytes instead
    // so the startup banner remains informative.
    total: cacheHit ? null : ruleCount,
    bytes: totalBytes,
    engine: 'adblock-rust',
    fromDiskCache: cacheHit,
    listCount: filePaths.length,
    blocked: 0,
    allowed: 0,
    exceptions: 0,
    errors: 0,
    cacheHits: 0,
    cacheMisses: 0
  };

  const resultCache = new FIFOCache(resultCacheSize);
  // Hot-path optimization: shared "no_match" object — most checks return this,
  // skip per-call object allocation. Safe because callers only read fields.
  const NO_MATCH = Object.freeze({ blocked: false, rule: null, reason: 'no_match' });
  // Bind once: skips the prototype property lookup for `engine.check` on every
  // call. The adblock-rs forwarder still does an internal name concat per
  // invocation; bypassing that further would require reaching into the native
  // binding (engine.boxed + blocker.Engine_check), which is brittle across
  // library versions.
  const engineCheck = engine.check.bind(engine);

  if (enableLogging) {
    if (cacheHit) {
      console.log(formatLogMessage('debug', `${ADBLOCK_RUST_TAG} Restored compiled engine from ${cachePath} (${(totalBytes/1024/1024).toFixed(2)}MB source, ${filePaths.length} list${filePaths.length>1?'s':''})`));
    } else {
      console.log(formatLogMessage('debug', `${ADBLOCK_RUST_TAG} Compiled ${ruleCount} rules from ${filePaths.length} list${filePaths.length>1?'s':''} (${(totalBytes/1024/1024).toFixed(2)}MB)`));
    }
  }

  return {
    shouldBlock(url, sourceUrl, resourceType) {
      // Avoid default-parameter syntax in the hot path — explicit null/undefined
      // checks are slightly cheaper for V8's argument adaptor.
      const src = sourceUrl || '';
      const rt = resourceType || '';
      // Single null-proto object lookup; falls back to 'other' for unknown types.
      const normType = rt ? (RESOURCE_TYPE_MAP[rt] || 'other') : '';
      const key = url + '\0' + src + '\0' + normType;
      const cached = resultCache.get(key);
      if (cached !== undefined) {
        stats.cacheHits++;
        return cached;
      }
      stats.cacheMisses++;

      // Narrow try/catch to the native call only — keeps the rest of the
      // function on TurboFan's fast path and avoids exception-handler overhead
      // on stats updates and Map operations.
      let result;
      try {
        // Pass empty string (not the request URL) when source is unknown — the
        // engine then skips first/third-party determination instead of treating
        // the request as same-origin to itself, which would suppress
        // $third-party rules entirely.
        // The 4th arg MUST be true: with false adblock-rs returns a bare
        // boolean instead of the {matched, exception, filter, important}
        // object we read below, which silently breaks matching.
        result = engineCheck(url, src, normType, true);
      } catch (err) {
        stats.errors++;
        if (enableLogging) {
          console.log(formatLogMessage('warn', `${ADBLOCK_RUST_TAG} Error checking ${url}: ${err.message}`));
        }
        // Don't cache errors — next call may succeed (transient native panic).
        return { blocked: false, rule: null, reason: 'error' };
      }

      // engine.check is contract-bound to return an object; no null guard
      // needed. Reading each field once into a local keeps the IC monomorphic.
      let r;
      if (result.matched) {
        const exception = result.exception;
        if (exception) {
          stats.exceptions++;
          r = { blocked: false, rule: exception, reason: 'whitelisted' };
        } else {
          stats.blocked++;
          r = {
            blocked: true,
            rule: result.filter || null,
            reason: result.important ? 'important_rule' : 'adblock_rust'
          };
        }
      } else {
        stats.allowed++;
        r = NO_MATCH;
      }

      resultCache.set(key, r);
      return r;
    },

    getStats() {
      const total = stats.cacheHits + stats.cacheMisses;
      const hitRate = total > 0 ? ((stats.cacheHits / total) * 100).toFixed(1) + '%' : '0%';
      return {
        ...stats,
        cache: {
          hits: stats.cacheHits,
          misses: stats.cacheMisses,
          hitRate,
          size: resultCache.cache.size,
          maxSize: resultCache.maxSize
        }
      };
    }
  };
}

module.exports = {
  parseAdblockRules,
  isAvailable
};
