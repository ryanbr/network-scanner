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
// adblock-rust accepts the strings used by the WebRequest API.
const RESOURCE_TYPE_MAP = {
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
};

function normalizeResourceType(type) {
  if (!type) return '';
  return RESOURCE_TYPE_MAP[type] || 'other';
}

// Small LRU keyed on (url \0 sourceUrl \0 resourceType). Mirrors the JS engine's
// 32K result cache — page reloads and repeated subresources hit this often.
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
        engine.deserialize(compiled.buffer.slice(
          compiled.byteOffset,
          compiled.byteOffset + compiled.byteLength
        ));
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
    // line count is correct.
    const filterSet = new rust.FilterSet(enableLogging);
    for (const buf of buffers) {
      const lines = buf.toString('utf-8').split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].length === 0) continue;
        if (lines[i].charCodeAt(0) === 0x21) continue;
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

  if (enableLogging) {
    if (cacheHit) {
      console.log(`[Adblock-Rust] Restored compiled engine from ${cachePath} (${(totalBytes/1024/1024).toFixed(2)}MB source, ${filePaths.length} list${filePaths.length>1?'s':''})`);
    } else {
      console.log(`[Adblock-Rust] Compiled ${ruleCount} rules from ${filePaths.length} list${filePaths.length>1?'s':''} (${(totalBytes/1024/1024).toFixed(2)}MB)`);
    }
  }

  return {
    rules: { stats },

    shouldBlock(url, sourceUrl = '', resourceType = '') {
      const normType = resourceType ? (RESOURCE_TYPE_MAP[resourceType] || 'other') : '';
      const key = url + '\0' + sourceUrl + '\0' + normType;
      const cached = resultCache.get(key);
      if (cached) {
        stats.cacheHits++;
        return cached;
      }
      stats.cacheMisses++;

      try {
        // Pass empty string (not the request URL) when source is unknown — the
        // engine then skips first/third-party determination instead of treating
        // the request as same-origin to itself, which would suppress
        // $third-party rules entirely.
        const result = engine.check(url, sourceUrl, normType, enableLogging);

        let r;
        if (result && result.matched) {
          if (result.exception) {
            stats.exceptions++;
            r = { blocked: false, rule: result.exception, reason: 'whitelisted' };
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
      } catch (err) {
        stats.errors++;
        if (enableLogging) {
          console.log(`[Adblock-Rust] Error checking ${url}: ${err.message}`);
        }
        return { blocked: false, rule: null, reason: 'error' };
      }
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
