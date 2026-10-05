/**
 * capture.js — one entry point for reading a saved browser capture.
 *
 * Three formats exist and they are told apart by CONTENT, never by extension:
 * both net-logs and HARs are commonly .json, and Firefox names HARs .har.
 *
 *   HAR      DevTools   F12 > Network > right-click > Save All As HAR
 *   net-log  Chrome     chrome --log-net-log=out.json <url>
 *   MOZ_LOG  Firefox    MOZ_LOG=timestamp,nsHttp:5 MOZ_LOG_FILE=... firefox <url>
 *
 * Which to reach for: the net-log and MOZ_LOG need no clicking, so they are the
 * ones to automate; prefer MOZ_LOG when the content blocker matters, since
 * Chrome is MV3-only and runs the weaker declarativeNetRequest blocker. Reach
 * for a HAR when the question is specifically "what did my blocker stop" --
 * only there is a blocked request distinguishable, as status 0.
 */

const fs = require('fs');
const { parseHar, matchEntries, rootDomainForHost } = require('./har');
const { parseNetLog } = require('./netlog');
const { parseMozLog } = require('./mozlog');

const LABELS = { har: 'HAR', netlog: 'Chrome net-log', mozlog: 'Firefox MOZ_LOG' };

/** Identify a capture from the head of the file. Returns a key of LABELS, or null. */
function sniffFormat(filePath) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.allocUnsafe(4096);
    const n = fs.readSync(fd, buf, 0, 4096, 0);
    const head = buf.toString('utf8', 0, n);
    if (/^\s*\{\s*"constants"\s*:/.test(head)) return 'netlog';
    if (/"log"\s*:/.test(head)) return 'har';
    if (/[A-Z]\/nsHttp /.test(head)) return 'mozlog';
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Parse any capture. Returns the parser's own result plus `format` and
 * `formatLabel`. Throws with an actionable message on an unreadable or
 * unrecognised file rather than returning something empty that looks like a
 * capture with no requests in it.
 */
function parseCapture(filePath) {
  if (!fs.existsSync(filePath)) throw new Error(`capture not found: ${filePath}`);
  const format = sniffFormat(filePath);
  if (!format) {
    throw new Error(
      `${filePath}: not a recognised capture. Expected a DevTools HAR (top-level "log"), ` +
      'a Chrome net-log ("constants"), or a Firefox MOZ_LOG (nsHttp lines).'
    );
  }
  const parsed = format === 'netlog' ? parseNetLog(filePath)
    : format === 'mozlog' ? parseMozLog(filePath)
      : parseHar(filePath);
  return { ...parsed, format, formatLabel: LABELS[format] };
}

const urlsOf = site => (Array.isArray(site.url) ? site.url : [site.url]).filter(Boolean);

/**
 * Decide which configured sites a capture applies to.
 *
 * With no selector, sites are matched to the capture's own page by registrable
 * domain. That matters: applying a capture of one site to every site in the
 * config would emit rules attributed to pages that were never loaded. Returning
 * nothing is the honest answer, and the caller turns it into an error telling
 * the user to pass a selector.
 */
function selectSitesForCapture(sites, capture, selector = null) {
  if (selector !== null && selector !== undefined && selector !== '') {
    if (/^\d+$/.test(String(selector))) {
      const one = sites[Number(selector)];
      return one ? [one] : [];
    }
    return sites.filter(s => urlsOf(s).some(u => String(u).includes(selector)));
  }
  let pageRoot = '';
  try { pageRoot = rootDomainForHost(new URL(capture.pageUrl).hostname); } catch { /* no page url */ }
  if (!pageRoot) return [];
  return sites.filter(s => urlsOf(s).some(u => {
    try { return rootDomainForHost(new URL(u).hostname) === pageRoot; } catch { return false; }
  }));
}

module.exports = { sniffFormat, parseCapture, selectSitesForCapture, matchEntries, urlsOf, LABELS };
