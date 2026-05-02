// === Adblock Rust Engine Wrapper (adblock-rust.js) ===
// Drop-in replacement for ./lib/adblock that delegates matching to Brave's
// adblock-rust engine (npm: adblock-rs) for higher throughput on large lists.
//
// Exposes the same parseAdblockRules(filePath, options) factory and the same
// matcher shape ({ shouldBlock, getStats, rules }) so nwss.js can switch
// engines with a single require() swap.

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

let adblockRust = null;
function loadAdblockRust() {
  if (adblockRust) return adblockRust;
  try {
    adblockRust = require('adblock-rs');
  } catch (err) {
    throw new Error(
      "adblock-rs is not installed. Install with: npm install adblock-rs " +
      "(requires Rust toolchain for native build). Original error: " + err.message
    );
  }
  return adblockRust;
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
  'other':               'other',
  '':                    ''
});

function normalizeResourceType(type) {
  if (!type) return '';
  return RESOURCE_TYPE_MAP[type] || 'other';
}

// Small FIFO cache keyed on (url \0 sourceUrl \0 resourceType). Despite the
// class name, eviction is insertion-order, not access-order — `get()` does not
// promote. For this workload (per-page request bursts whose working set fits
// in maxSize) FIFO and true LRU produce the same evictions, so the simpler
// path wins. If cache effectiveness becomes a concern with larger working
// sets, promote on hit by re-inserting (delete + set).
class ResultLRU {
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

function parseAdblockRules(filePathOrArray, options = {}) {
  const {
    enableLogging = false,
    resultCacheSize = 32000,
    useDiskCache = true,
    cacheDir = path.join(os.tmpdir(), 'nwss-adblock-rs-cache')
  } = options;
  const rust = loadAdblockRust();

  // Accept a single path or an array of paths — caller no longer needs to
  // materialize a temp concatenation file for multi-list scans.
  const filePaths = Array.isArray(filePathOrArray) ? filePathOrArray : [filePathOrArray];

  // Read all files up front; hash the raw bytes so the disk cache key reflects
  // both content changes and list-order changes.
  const buffers = [];
  const hash = crypto.createHash('sha256');
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
  if (useDiskCache) {
    try {
      if (fs.existsSync(cachePath)) {
        const compiled = fs.readFileSync(cachePath);
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
      }
    } catch (err) {
      // Corrupt cache or version mismatch — fall through to a fresh parse.
      engine = null;
      if (enableLogging) {
        console.log(`[Adblock-Rust] Cache load failed (${err.message}); reparsing`);
      }
    }
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
      for (let j = 0; j < lines.length; j++) {
        const line = lines[j];
        if (line.length === 0) continue;
        if (line.charCodeAt(0) === 0x21) continue;
        ruleCount++;
      }
      filterSet.addFilters(lines);
    }
    engine = new rust.Engine(filterSet, true);

    if (useDiskCache) {
      try {
        fs.mkdirSync(cacheDir, { recursive: true });
        const serialized = engine.serialize();
        fs.writeFileSync(cachePath, Buffer.from(serialized));
      } catch (err) {
        if (enableLogging) {
          console.log(`[Adblock-Rust] Cache write failed (${err.message}); continuing`);
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

  const resultCache = new ResultLRU(resultCacheSize);
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
      console.log(`[Adblock-Rust] Restored compiled engine from ${cachePath} (${(totalBytes/1024/1024).toFixed(2)}MB source, ${filePaths.length} list${filePaths.length>1?'s':''})`);
    } else {
      console.log(`[Adblock-Rust] Compiled ${ruleCount} rules from ${filePaths.length} list${filePaths.length>1?'s':''} (${(totalBytes/1024/1024).toFixed(2)}MB)`);
    }
  }

  return {
    rules: { stats },

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
          console.log(`[Adblock-Rust] Error checking ${url}: ${err.message}`);
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
  parseAdblockRules
};
