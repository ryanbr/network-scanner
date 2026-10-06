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
const path = require('path');
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
/**
 * Resolve a directory to the newest capture inside it, so a command can name a
 * folder once instead of a filename that changes on every run (captures are
 * timestamped so they do not overwrite each other). Per-process MOZ_LOG
 * siblings are skipped as candidates -- the main log of that run represents
 * them, and parseMozLog picks its own siblings up.
 */
function newestCaptureIn(dir) {
  const entries = fs.readdirSync(dir)
    .filter(f => !/\.child-\d+\.moz_log$/.test(f))
    .map(f => path.join(dir, f))
    .filter(f => { try { return fs.statSync(f).isFile(); } catch { return false; } })
    .filter(f => { try { return sniffFormat(f) !== null; } catch { return false; } });
  if (entries.length === 0) {
    throw new Error(`no capture found in ${dir} (looked for a HAR, a Chrome net-log or a Firefox MOZ_LOG)`);
  }
  return entries.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
}

function parseCapture(inputPath) {
  if (!fs.existsSync(inputPath)) throw new Error(`capture not found: ${inputPath}`);
  const filePath = fs.statSync(inputPath).isDirectory() ? newestCaptureIn(inputPath) : inputPath;
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
  return { ...parsed, format, formatLabel: LABELS[format], filePath };
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

/**
 * The captured page that belongs to a given site, for first/third-party calls.
 *
 * Why not just capture.pageUrl: that is pages[0], and a Chrome HAR recorded with
 * "Preserve log" carries one page per navigation. Taking the first one made the
 * SCANNED site read as third-party -- and with firstParty:false it was then
 * published as a rule for itself. Prefer a captured page whose registrable
 * domain matches this site; the caller falls back to the site's own url.
 */
function pageUrlForSite(capture, siteUrls) {
  const rootOf = u => { try { return rootDomainForHost(new URL(u).hostname); } catch { return ''; } };
  const roots = (siteUrls || []).map(rootOf).filter(Boolean);
  if (!roots.length) return '';
  const candidates = (capture && capture.pageUrls && capture.pageUrls.length)
    ? capture.pageUrls
    : [capture && capture.pageUrl].filter(Boolean);
  for (const pageUrl of candidates) {
    if (roots.includes(rootOf(pageUrl))) return pageUrl;
  }
  return '';
}

module.exports = { sniffFormat, parseCapture, newestCaptureIn, selectSitesForCapture, matchEntries, urlsOf, pageUrlForSite, LABELS };
