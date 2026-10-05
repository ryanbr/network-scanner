/**
 * mozlog.js — read a Firefox MOZ_LOG network log and match its requests the way
 * a live scan would.
 *
 * Why this and not the HAR route: Firefox's HAR export has to be driven through
 * DevTools, and MOZ_LOG is a plain environment variable, so the capture needs
 * no toolbox, no prefs and nothing to click:
 *
 *   set MOZ_LOG=timestamp,nsHttp:5
 *   set MOZ_LOG_FILE=C:\nwss-har\ff.log
 *   firefox.exe https://example.com/
 *
 * It is the Firefox equivalent of Chrome's --log-net-log, and it matters
 * because Firefox is where a real uBO (full webRequest blocking plus the user's
 * own rules) still runs -- Chrome is MV3-only now, so what runs there is uBO
 * Lite on declarativeNetRequest, which is a weaker blocker and demonstrably
 * does not drive anti-adblock loaders the same way.
 *
 * Format notes, all verified against a real 424MB capture of one page load:
 *  - Every line is prefixed "<timestamp> - [Parent N: Thread]: <level>/nsHttp ".
 *  - Channel creation logs "uri=<full url>", which is the authoritative URL
 *    list: it carries the scheme, and it is written whether or not the request
 *    goes on to hit the network.
 *  - Request headers arrive in a self-contained "http request [" block holding
 *    the request line, Host and Sec-Fetch-Dest, so the resource type comes from
 *    the same header the HAR and net-log readers use. The block is joined to
 *    the URL on host+path rather than by correlating [this=<pointer>], which is
 *    reused once an object is freed.
 *  - Firefox spawns per-process logs beside the main file
 *    (ff.log.child-N.moz_log), so siblings are read too.
 *
 * ON BLOCKED REQUESTS: do not read anything into a request's absence or
 * presence here. A uri= line is written when the channel is created, which is
 * before a content blocker cancels it, so blocked requests generally DO appear
 * -- useful, since it shows what the page TRIED to load. But a cached response
 * produces no request block either, so "no request block" does not mean
 * "blocked". Nothing is marked blocked from this source; use a HAR, where a
 * blocked request is status 0, if that distinction is the question.
 */

const fs = require('fs');
const path = require('path');
const { eachLine } = require('./linereader');
const { rootDomainForHost, typeFromHeaders } = require('./har');

// "...: E/nsHttp uri=https://host/path"
const RE_URI = /\buri=(https?:\/\/\S+)/;
// "<timestamp> - [Parent 75652: Main Thread]: E/nsHttp <payload>"
// The bracketed part is captured because the log is MULTI-THREADED and the
// threads interleave line by line -- see parseMozLog.
const RE_LINE = /\[([^\]]+)\]: [A-Z]\/nsHttp (.*)$/;
/**
 * Force a flat copy of a string taken out of a huge parent.
 *
 * V8 represents a substring as a SlicedString that KEEPS A REFERENCE to its
 * parent, so retaining one 40-character url out of a 4MB chunk pins the whole
 * 4MB. Measured on a real 49MB capture: 43.8MB of heap retained for 350
 * entries, and 187MB RSS. Copying the few strings that outlive the chunk drops
 * that to the size of the strings themselves.
 *
 * (' ' + s).slice(1) is the cheap idiom -- 2ms per 200k strings, against 22ms
 * for a Buffer round-trip, both verified to actually break the reference.
 */
const flat = s => (' ' + s).slice(1);

const RE_REQUEST_LINE = /^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+(\S+)\s+HTTP\//;

/** The main log plus any per-process siblings Firefox wrote next to it. */
function logFamily(filePath) {
  const st = fs.statSync(filePath);
  if (st.isDirectory()) {
    // Every .moz_log in the directory is NOT one capture: each run leaves its
    // own timestamped family behind, and returning them all merged separate
    // page loads into one result (measured: two runs of 350 and 288 requests
    // came back as 498). Group by stem and take the newest run only.
    const files = fs.readdirSync(filePath).filter(f => f.endsWith('.moz_log'));
    const newest = new Map();                       // stem -> newest mtime in it
    for (const f of files) {
      const stem = f.replace(/\.moz_log$/, '').replace(/\.child-\d+$/, '');
      const m = fs.statSync(path.join(filePath, f)).mtimeMs;
      if (!newest.has(stem) || m > newest.get(stem)) newest.set(stem, m);
    }
    if (newest.size === 0) return [];
    const pick = [...newest.entries()].sort((a, b) => b[1] - a[1])[0][0];
    return files.filter(f => f === `${pick}.moz_log` || f.startsWith(`${pick}.child-`))
      .map(f => path.join(filePath, f)).sort();
  }
  const dir = path.dirname(filePath);
  const base = path.basename(filePath);
  // ff.log.moz_log -> ff.log.child-3.moz_log
  const stem = base.replace(/\.moz_log$/, '').replace(/\.child-\d+$/, '');
  let siblings = [];
  try {
    siblings = fs.readdirSync(dir)
      .filter(f => f.endsWith('.moz_log') && f.startsWith(stem) && f !== base)
      .map(f => path.join(dir, f));
  } catch { /* unreadable directory: just use the file given */ }
  return [filePath, ...siblings.sort()];
}

function parseMozLog(filePath) {
  const urls = [];                 // in first-seen order
  const seenUrl = new Set();
  const typeByKey = new Map();     // "host/path" -> Sec-Fetch-Dest
  let sawNsHttp = false;

  // State for the multi-line "http request [" block, kept PER ORIGIN
  // (process + thread). The log is multi-threaded and interleaves line by line:
  // a socket thread's "] idle conns [" lands in the middle of the main thread's
  // request block. Tracking a single global block took that "]" as the end and
  // truncated before Sec-Fetch-Dest, so on a busy capture every request came
  // back typed "other" -- including the top-level document, which then made the
  // page look like whatever Firefox happened to fetch first. Quieter captures
  // did not interleave and hid it.
  const blocks = new Map();   // origin -> { path, host, dest }

  const flushBlock = (origin) => {
    const b = blocks.get(origin);
    if (!b) return;
    // Both outlive the chunk: the key is a concatenation of two slices, which
    // pins BOTH parents until it is flattened.
    if (b.host && b.path) typeByKey.set(flat(b.host + b.path), flat(b.dest));
    blocks.delete(origin);
  };

  for (const file of logFamily(filePath)) {
    eachLine(file, line => {
      const pm = RE_LINE.exec(line);
      if (!pm) return;
      sawNsHttp = true;
      const origin = pm[1];
      const payload = pm[2];

      if (payload.startsWith('http request [')) {
        blocks.set(origin, { path: '', host: '', dest: '' });
        return;
      }

      const block = blocks.get(origin);
      if (block) {
        const body = payload.trim();
        if (body === ']') { flushBlock(origin); return; }
        const rl = RE_REQUEST_LINE.exec(body);
        if (rl) { block.path = rl[2]; return; }
        const colon = body.indexOf(':');
        if (colon > 0) {
          const name = body.slice(0, colon).trim().toLowerCase();
          const value = body.slice(colon + 1).trim();
          if (name === 'host') block.host = value;
          else if (name === 'sec-fetch-dest') block.dest = value;
        }
        return;
      }

      const um = RE_URI.exec(payload);
      if (um) {
        // Trailing punctuation from the surrounding log text, never part of a URL.
        // flat(): this string outlives the chunk it was cut from.
        const url = flat(um[1].replace(/[)\]',;]+$/, ''));
        if (!seenUrl.has(url)) { seenUrl.add(url); urls.push(url); }
      }
    });
    for (const origin of [...blocks.keys()]) flushBlock(origin);  // cut off at EOF
  }

  if (!sawNsHttp) {
    throw new Error(`${filePath}: no nsHttp lines -- is this a MOZ_LOG capture made with MOZ_LOG=timestamp,nsHttp:5?`);
  }

  const entries = [];
  for (const url of urls) {
    let u;
    try { u = new URL(url); } catch { continue; }
    const dest = typeByKey.get(u.hostname + u.pathname + u.search) ||
                 typeByKey.get(u.hostname + u.pathname) || '';
    entries.push({
      url,
      host: u.hostname,
      rootDomain: rootDomainForHost(u.hostname),
      status: undefined,
      blocked: false,              // not knowable here; see the header comment
      failed: false,
      resourceType: dest ? typeFromHeaders([{ name: 'Sec-Fetch-Dest', value: dest }], '') : 'other',
      mimeType: ''
    });
  }

  const doc = entries.find(e => e.resourceType === 'document');
  return {
    pageUrl: (doc && doc.url) || (entries[0] && entries[0].url) || '',
    creator: 'Firefox MOZ_LOG (nsHttp)',
    truncated: false,              // a text log has no terminator to miss
    entries
  };
}

module.exports = { parseMozLog };
