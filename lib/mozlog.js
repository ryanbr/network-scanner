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
// The log prefix ends at "<level>/nsHttp "; everything after it is the payload.
const RE_PAYLOAD = /\b[A-Z]\/nsHttp (.*)$/;
const RE_REQUEST_LINE = /^(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+(\S+)\s+HTTP\//;

/** The main log plus any per-process siblings Firefox wrote next to it. */
function logFamily(filePath) {
  const st = fs.statSync(filePath);
  if (st.isDirectory()) {
    return fs.readdirSync(filePath).filter(f => f.endsWith('.moz_log'))
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

  // State for the multi-line "http request [" block.
  let inBlock = false;
  let blockPath = '', blockHost = '', blockDest = '';

  const flushBlock = () => {
    if (blockHost && blockPath) typeByKey.set(blockHost + blockPath, blockDest);
    inBlock = false; blockPath = ''; blockHost = ''; blockDest = '';
  };

  for (const file of logFamily(filePath)) {
    eachLine(file, line => {
      const pm = RE_PAYLOAD.exec(line);
      if (!pm) return;
      sawNsHttp = true;
      const payload = pm[1];

      if (inBlock) {
        const body = payload.trim();
        if (body === ']') { flushBlock(); return; }
        const rl = RE_REQUEST_LINE.exec(body);
        if (rl) { blockPath = rl[2]; return; }
        const colon = body.indexOf(':');
        if (colon > 0) {
          const name = body.slice(0, colon).trim().toLowerCase();
          const value = body.slice(colon + 1).trim();
          if (name === 'host') blockHost = value;
          else if (name === 'sec-fetch-dest') blockDest = value;
        }
        return;
      }

      if (payload.startsWith('http request [')) {
        inBlock = true; blockPath = ''; blockHost = ''; blockDest = '';
        return;
      }

      const um = RE_URI.exec(payload);
      if (um) {
        // Trailing punctuation from the surrounding log text, never part of a URL.
        const url = um[1].replace(/[)\]',;]+$/, '');
        if (!seenUrl.has(url)) { seenUrl.add(url); urls.push(url); }
      }
    });
    if (inBlock) flushBlock();     // a block cut off at end of file
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
