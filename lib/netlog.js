/**
 * netlog.js — read a Chrome/Chromium net-log and match its requests the way a
 * live scan would.
 *
 * Why this exists alongside har.js: a HAR has to be saved by hand from DevTools
 * (Firefox's devtools.netmonitor.har.enableAutoExportToFile does not produce a
 * file on 157 -- verified on a fresh profile and an established one). Chrome
 * writes a net-log itself, from a command-line flag, with no DevTools involved
 * and nothing to click:
 *
 *   chrome --log-net-log=out.json --net-log-capture-mode=IncludeSensitive <url>
 *
 * So the browsing and the blocking stay in the user's real browser with their
 * real extensions, and we only read the file afterwards. Entries come out in
 * exactly the shape har.js produces, so matchEntries() consumes either source.
 *
 * Format notes, all verified against real captures:
 *  - Line 1 is {"constants":{...}, line 2 is "events": [, and every event is on
 *    its own line. Clean shutdown closes with ]}; a killed browser leaves the
 *    array unterminated, so JSON.parse on the whole file fails. Reading line by
 *    line recovers everything up to the cut, which is why this does not just
 *    JSON.parse -- a 12.9MB log from a SIGKILLed Chrome parsed to 0 bytes that
 *    way and to its full event list this way.
 *  - A request is a source of type URL_REQUEST; its events share source.id.
 *  - params.request_type is only "other" / "subframe" / "main frame", too coarse
 *    for resourceTypes, so the type comes from the Sec-Fetch-Dest request header
 *    (har.js's own derivation, reused) with the response mime type as fallback.
 *  - REQUEST_ALIVE's end phase carries net_error when the request did not
 *    succeed, which is how network-level failures (DNS, connection, cache) are
 *    reported here.
 *
 * THE ONE THING A NET-LOG DOES NOT HAVE: requests an extension blocked are not
 * in it at all -- not as an error, not as an entry. Measured, on a run where a
 * declarativeNetRequest extension blocked cdn-apex.example: puppeteer reported
 * ERR_BLOCKED_BY_CLIENT for it, and the string "cdn-apex" appeared zero times
 * in the 530-request net-log from that same run. The block lands before the
 * network stack ever creates a URL_REQUEST. So a net-log is a record of what the
 * browser REALLY FETCHED, which is what matters for discovering a late host in a
 * fallback chain, but it cannot tell you what your blocker stopped -- use a HAR
 * (status 0) for that. `blocked` stays on each entry for matchEntries()'s sake
 * and simply never fires from this source.
 */

const fs = require('fs');
const { rootDomainForHost, typeFromHeaders } = require('./har');
const { eachLine } = require('./linereader');

// Event lines are "{...}" with a structural suffix that depends on where the
// line falls: "," mid-array, "]" or "]," on the last one (the bracket is
// appended to the final event, which can be a 110KB line), and nothing at all on
// a log cut short by a kill. Rather than enumerate those, try the longest parse
// that works -- at most three structural characters can follow the object.
function parseEventLine(line) {
  const s = line.trim();
  if (!s || !s.startsWith('{')) return null;        // "events": [, polledData, ]
  for (let cut = 0; cut <= 3; cut++) {
    const cand = cut === 0 ? s : s.slice(0, -cut);
    if (!cand.endsWith('}')) continue;
    try { return JSON.parse(cand); } catch { /* try a shorter suffix */ }
  }
  return null;                                      // the truncated tail
}

function headerList(params) {
  if (!params) return null;
  if (Array.isArray(params.headers)) return params.headers;
  if (params.request_headers && Array.isArray(params.request_headers.headers)) {
    return params.request_headers.headers;
  }
  return null;
}

// "name: value" lines -> the {name, value} pairs har.js's type derivation wants.
function toPairs(lines) {
  const out = [];
  for (const h of lines) {
    const str = String(h);
    const i = str.indexOf(':', str.startsWith(':') ? 1 : 0);   // HTTP/2 pseudo-headers lead with ':'
    if (i === -1) continue;
    out.push({ name: str.slice(0, i).trim(), value: str.slice(i + 1).trim() });
  }
  return out;
}

/**
 * Parse a net-log into the flat request list parseHar() also returns.
 */
function parseNetLog(filePath) {
  let constants = null;
  const requests = new Map();        // source.id -> accumulating record
  let truncated = true;              // until a closing ]} is seen
  let lineNo = 0;

  eachLine(filePath, line => {
    lineNo++;
    if (lineNo === 1) {
      // {"constants":{...},  -- close it to parse on its own
      const head = line.trim().replace(/,\s*$/, '');
      try { constants = indexConstants(JSON.parse(head + '}').constants); } catch { /* handled below */ }
      return;
    }
    // "Complete" means the events array got closed. Its bracket is appended to
    // the last event line ("...}]" or "...}],", since a polledData section
    // follows), and every mid-array line ends with "}," -- an event object can
    // never end with "]" itself -- so a trailing bracket is an unambiguous close.
    if (/\]\s*,?$/.test(line.trim())) truncated = false;
    if (!constants) return;
    const e = parseEventLine(line);
    if (!e || !e.source || e.source.type !== constants._srcUrlRequest) return;

    const id = e.source.id;
    let rec = requests.get(id);
    if (!rec) { rec = { url: '', method: '', initiator: '', status: undefined, mimeType: '', headerPairs: [], netError: undefined }; requests.set(id, rec); }

    const name = constants._eventName[e.type];
    if (e.params && typeof e.params.url === 'string' && !rec.url) rec.url = e.params.url;
    if (name === 'URL_REQUEST_START_JOB' && e.params) {
      if (e.params.method) rec.method = e.params.method;
      if (e.params.initiator) rec.initiator = e.params.initiator;
      if (e.params.url) rec.url = e.params.url;
    }
    if (name === 'REQUEST_ALIVE' && e.phase === 2 && e.params && typeof e.params.net_error === 'number') {
      rec.netError = e.params.net_error;
    }
    if (name === 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS' && e.params) {
      const hs = headerList(e.params) || [];
      const statusLine = hs.find(h => /^HTTP\//i.test(String(h)));
      if (statusLine) {
        const m = String(statusLine).match(/\s(\d{3})\b/);
        if (m) rec.status = Number(m[1]);
      }
      const ct = hs.find(h => /^content-type\s*:/i.test(String(h)));
      if (ct) rec.mimeType = String(ct).split(':').slice(1).join(':').trim();
    }
    if (!rec.headerPairs.length) {
      const hs = headerList(e.params);
      // Only REQUEST-side header events carry Sec-Fetch-Dest; response events
      // are excluded by name so a response content-type cannot be read as one.
      if (hs && name !== 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS') rec.headerPairs = toPairs(hs);
    }
  });

  if (!constants) {
    throw new Error(`${filePath}: no net-log constants on line 1 -- is this a Chrome --log-net-log file?`);
  }

  const entries = [];
  for (const rec of requests.values()) {
    if (!rec.url || !/^https?:/i.test(rec.url)) continue;
    let host = '';
    try { host = new URL(rec.url).hostname; } catch { continue; }
    const netErrorName = rec.netError !== undefined ? (constants._errName[rec.netError] || String(rec.netError)) : '';
    entries.push({
      url: rec.url,
      host,
      rootDomain: rootDomainForHost(host),
      status: rec.status,
      blocked: netErrorName === 'ERR_BLOCKED_BY_CLIENT',
      failed: rec.netError !== undefined && rec.netError < 0,
      netError: netErrorName,
      initiator: rec.initiator,
      method: rec.method,
      resourceType: typeFromHeaders(rec.headerPairs, rec.mimeType),
      mimeType: rec.mimeType
    });
  }

  const mainFrame = entries.find(e => e.resourceType === 'document');
  return {
    pageUrl: (mainFrame && mainFrame.url) || (entries[0] && entries[0].url) || '',
    creator: `Chrome net-log${constants.clientInfo && constants.clientInfo.name ? ' (' + constants.clientInfo.name + ')' : ''}`,
    truncated,
    entries
  };
}

/** Build the number->name lookups the parse needs, from a log's own constants. */
function indexConstants(constants) {
  const eventName = {};
  for (const k in (constants.logEventTypes || {})) eventName[constants.logEventTypes[k]] = k;
  const errName = {};
  for (const k in (constants.netError || {})) errName[constants.netError[k]] = k;
  constants._eventName = eventName;
  constants._errName = errName;
  constants._srcUrlRequest = (constants.logSourceType || {}).URL_REQUEST;
  return constants;
}

module.exports = { parseNetLog, indexConstants };
