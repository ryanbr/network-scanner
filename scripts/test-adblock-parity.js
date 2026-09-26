#!/usr/bin/env node
/**
 * Verdict parity between the two adblock engines.
 *
 * `lib/adblock.js` (native JS) and `lib/adblock-rust.js` (Brave's adblock-rs) are
 * swapped by one `require()`, and `--adblock-engine` defaults to whichever is
 * available -- so a scan's blocking behaviour depends on which one loaded. That
 * only holds together while they agree, and their disagreements are silent: a
 * request is either aborted or it is not, with nothing to compare against.
 *
 * This repo has been bitten twice by exactly that. adblock-rs 0.13 renamed
 * `matched` to `should_block` AND changed its meaning (0.12's `matched` was true
 * for an exception), which would have disabled blocking entirely while every scan
 * still reported success. And a `$popup` rule, which neither engine can act on,
 * was over-blocking in the JS engine alone.
 *
 * WHAT IS COMPARED is the verdict -- `blocked` true/false -- not `reason` or
 * `rule`. Each engine names its own matching bucket ('path_rule' vs
 * 'adblock_rust'), which is by design and not a disagreement.
 *
 * KNOWN ASYMMETRIES, measured rather than assumed, and pinned in the
 * 'asymmetries' group so a change to any of them shows up as a failure:
 *
 *   - resourceType '': a type-restricted rule ($script) blocks in the JS engine,
 *     which skips the type check when the type is falsy, and does not in rust,
 *     which cannot satisfy $script without a type. Unreachable from nwss --
 *     request.resourceType() always returns a type -- so it is recorded, not
 *     fixed. 21 of 2000 synthetic URLs against easylist.
 *   - resourceType 'document': the JS engine blocks where rust does not -- 150 of
 *     2000 synthetic urls built from easylist's path rules; ||host^ rules show no
 *     divergence at all -- and rust NEVER blocks where the JS engine does not.
 *     nwss never aborts a main-frame document (see the isMainFrameDoc guard in its
 *     request handler), and an ad iframe arrives as 'sub_frame', which has zero
 *     divergence in either direction. So the direction is what matters here, and
 *     that is what is asserted: rust must never be the stricter engine.
 *
 * Everything else -- real resource types with a source URL, which is the only
 * shape nwss ever produces -- must agree exactly. Measured: 0 divergences over
 * 2000 URL/type pairs against easylist.
 *
 * Usage:
 *   node scripts/test-adblock-parity.js                 # everything
 *   node scripts/test-adblock-parity.js --group=corpus  # verdicts | corpus | asymmetries
 *   node scripts/test-adblock-parity.js --list
 *   node scripts/test-adblock-parity.js --verbose
 *
 * Skips rather than fails when `adblock-rs` is not installed (it is an optional
 * dependency), and the easylist-backed checks skip when ./easylist.txt is absent
 * (it is not tracked). Exit 0 = every selected check passed, 1 = a failure,
 * 2 = bad usage.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const { messageColors } = require('../lib/colorize');
const jsEngine = require('../lib/adblock');
const rustEngine = require('../lib/adblock-rust');

const REPO_ROOT = path.resolve(__dirname, '..');
const EASYLIST = path.join(REPO_ROOT, 'easylist.txt');

// Resource types nwss actually passes through (Puppeteer's names). 'document' and
// '' are handled separately in the asymmetries group, for the reasons in the
// header.
const REAL_TYPES = Object.freeze(['script', 'image', 'stylesheet', 'xhr', 'sub_frame', 'font', 'media']);

// A list covering the rule shapes whose semantics could plausibly drift between
// two independent implementations.
const TEST_LIST = [
  '[Adblock Plus 2.0]',
  '! parity fixture',
  '||ads.example.com^',                        // plain domain, any type
  '||tracker.test^$third-party',               // third-party only
  '||first.test^$first-party',                 // first-party only
  '/banner-ad.',                               // path substring
  '||scripts.test^$script',                    // single type
  '||mixed.test^$script,image',                // multiple types
  '@@||ads.example.com/allowed.js',            // exception beats the block above
  '||popup.test^$popup',                       // neither engine can act on this
  '##.cosmetic-only',                          // never a network rule
  '||sub.deep.test^',                          // deeper host
  '/regex-ish.*\\.js/',                        // regex rule
  '||domainopt.test^$domain=publisher.test'    // domain= restricted
].join('\n');

const args = process.argv.slice(2);
const HELP = args.includes('--help') || args.includes('-h');
const LIST = args.includes('--list');
const VERBOSE = args.includes('--verbose');
const GROUP = (args.find(a => a.startsWith('--group=')) || '').split('=')[1] || null;
const KNOWN_FLAGS = new Set(['--help', '-h', '--list', '--verbose']);
const GROUPS = ['verdicts', 'corpus', 'asymmetries'];

function printHelp() {
  console.log(`
Verdict parity between lib/adblock.js and lib/adblock-rust.js.

Usage:
  node scripts/test-adblock-parity.js [flags]

Flags:
  --group=<verdicts|corpus|asymmetries>   run one group
  --list                                  print check names and exit
  --verbose                               per-check detail
  --help, -h                              this message

Skips when adblock-rs is not installed; the easylist checks skip without
./easylist.txt. Exit 0 = passed, 1 = failure, 2 = bad usage.
`);
}

class SkipCheck extends Error {}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function assertEqual(actual, expected, what) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) throw new Error(`${what}: got ${a}, want ${e}`);
}

/**
 * Literal path fragments taken from easylist's own simple path rules, so a corpus
 * built from them hits real rules instead of proving the engines agree that
 * nothing matches.
 * @returns {string[]}
 */
function easylistPathFragments(limit = 400) {
  const out = [];
  for (const line of fs.readFileSync(EASYLIST, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('!') || t.startsWith('[') || t.startsWith('@@') || t.includes('##') || t.includes('#@#')) continue;
    if (t.includes('$')) continue;                        // options are handled elsewhere
    const m = t.match(/^\/([A-Za-z0-9._-]{4,30})\.?$/);
    if (m) out.push(m[1]);
    if (out.length >= limit) break;
  }
  return out;
}

/** Both engines over one filter list, or a skip if rust cannot load. */
function loadPair(listPath) {
  if (!rustEngine.isAvailable()) {
    throw new SkipCheck('adblock-rs is not installed (optional dependency)');
  }
  return {
    js: jsEngine.parseAdblockRules(listPath, {}),
    // No disk cache: a cached engine from another run would make this test depend
    // on state it did not create.
    rust: rustEngine.parseAdblockRules(listPath, { useDiskCache: false })
  };
}

/** Write the fixture list to a temp file for the duration of one check. */
function withTestList(fn) {
  const listPath = path.join(os.tmpdir(), `nwss-parity-${process.pid}-${Math.random().toString(36).slice(2)}.txt`);
  fs.writeFileSync(listPath, TEST_LIST);
  try {
    return fn(listPath);
  } finally {
    try { fs.unlinkSync(listPath); } catch (_) { /* best effort */ }
  }
}

/**
 * Compare both engines over a set of cases.
 * @returns {{checked: number, divergences: Array<object>}}
 */
function compare(pair, cases) {
  const divergences = [];
  for (const [url, src, type, note] of cases) {
    const a = pair.js.shouldBlock(url, src, type).blocked;
    const b = pair.rust.shouldBlock(url, src, type).blocked;
    if (a !== b) divergences.push({ url, src, type, note, js: a, rust: b });
  }
  return { checked: cases.length, divergences };
}

function describe(divergences, limit = 5) {
  return divergences.slice(0, limit)
    .map(d => `js=${d.js} rust=${d.rust} type=${d.type || "''"} src=${d.src || "''"} ${d.url}${d.note ? ` (${d.note})` : ''}`)
    .join('\n          ');
}

/** URLs built from the fixture list's own hosts and paths, plus non-matching noise. */
function buildCorpus() {
  const hosts = ['ads.example.com', 'sub.ads.example.com', 'tracker.test', 'first.test',
    'scripts.test', 'mixed.test', 'popup.test', 'sub.deep.test', 'domainopt.test',
    'cosmetic-only.test', 'unrelated.test', 'deep.test', 'example.com'];
  const paths = ['/a.js', '/allowed.js', '/banner-ad.png', '/x.png', '/x.css', '/t.gif',
    '/regex-ish-thing.js', '/regex-ish.js', '/nothing-special', '/ad', '/sub/banner-ad.jpg'];
  const sources = ['https://publisher.test/', 'https://elsewhere.test/page', 'https://ads.example.com/'];
  const cases = [];
  for (const host of hosts) {
    for (const p of paths) {
      for (let i = 0; i < REAL_TYPES.length; i++) {
        cases.push([`https://${host}${p}`, sources[i % sources.length], REAL_TYPES[i], null]);
      }
    }
  }
  return cases;
}

const CHECKS = [];
const check = (group, name, run) => CHECKS.push({ group, name, run });

// ----- verdicts: curated cases, one per rule shape -----

check('verdicts', 'every rule shape agrees on a real request', async () => {
  return withTestList((listPath) => {
    const pair = loadPair(listPath);
    const cases = [
      ['https://ads.example.com/a.js', 'https://site.test/', 'script', 'plain domain'],
      ['https://sub.ads.example.com/a.js', 'https://site.test/', 'script', 'subdomain of a domain rule'],
      ['https://ads.example.com/allowed.js', 'https://site.test/', 'script', 'exception beats the block'],
      ['https://tracker.test/t.gif', 'https://site.test/', 'image', '$third-party, is third party'],
      ['https://tracker.test/t.gif', 'https://tracker.test/', 'image', '$third-party, same site'],
      ['https://first.test/x.js', 'https://first.test/', 'script', '$first-party, same site'],
      ['https://first.test/x.js', 'https://other.test/', 'script', '$first-party, cross site'],
      ['https://cdn.test/banner-ad.png', 'https://site.test/', 'image', 'path substring'],
      ['https://scripts.test/x.js', 'https://site.test/', 'script', 'type matches'],
      ['https://scripts.test/x.png', 'https://site.test/', 'image', 'type does not match'],
      ['https://mixed.test/x.png', 'https://site.test/', 'image', 'multi-type, second type'],
      ['https://mixed.test/x.css', 'https://site.test/', 'stylesheet', 'multi-type, absent type'],
      ['https://popup.test/x', 'https://site.test/', 'script', '$popup: neither engine acts'],
      ['https://cosmetic-only.test/x.js', 'https://site.test/', 'script', 'cosmetic rule is not a network rule'],
      ['https://sub.deep.test/x.js', 'https://site.test/', 'script', 'deeper host'],
      ['https://x.test/regex-ish-thing.js', 'https://site.test/', 'script', 'regex rule'],
      ['https://domainopt.test/x.js', 'https://publisher.test/', 'script', '$domain= matches'],
      ['https://domainopt.test/x.js', 'https://elsewhere.test/', 'script', '$domain= does not match'],
      ['https://unrelated.test/x.js', 'https://site.test/', 'script', 'nothing matches'],
      ['data:text/javascript,1', 'https://site.test/', 'script', 'hostless url'],
      ['about:blank', 'https://site.test/', 'document', 'about:blank']
    ];
    const { checked, divergences } = compare(pair, cases);
    assert(divergences.length === 0, `${divergences.length} of ${checked} diverge:\n          ${describe(divergences)}`);
    // Not vacuous: the fixture must actually be blocking things.
    const blocked = cases.filter(([u, s, t]) => pair.js.shouldBlock(u, s, t).blocked).length;
    assert(blocked >= 8, `only ${blocked} of ${checked} cases block at all -- fixture is not exercising the engines`);
    return `${checked} cases, ${blocked} of them blocking`;
  });
});

check('verdicts', 'an exception rule wins in both engines', async () => {
  return withTestList((listPath) => {
    const pair = loadPair(listPath);
    // Explicit, because getting exceptions backwards is exactly what the 0.13
    // `matched` -> `should_block` rename did (0.12's `matched` was TRUE for an
    // exception, so a naive port inverted every whitelist).
    const blockedUrl = 'https://ads.example.com/tracker.js';
    const allowedUrl = 'https://ads.example.com/allowed.js';
    for (const engine of ['js', 'rust']) {
      assertEqual(pair[engine].shouldBlock(blockedUrl, 'https://site.test/', 'script').blocked, true,
        `${engine}: the plain domain rule blocks`);
      assertEqual(pair[engine].shouldBlock(allowedUrl, 'https://site.test/', 'script').blocked, false,
        `${engine}: the exception unblocks`);
    }
    return 'block and exception both behave in both engines';
  });
});

// ----- corpus: every host x path x type combination -----

check('corpus', 'no divergence across the fixture corpus', async () => {
  return withTestList((listPath) => {
    const pair = loadPair(listPath);
    const cases = buildCorpus();
    const { checked, divergences } = compare(pair, cases);
    assert(divergences.length === 0,
      `${divergences.length} of ${checked} diverge:\n          ${describe(divergences)}`);
    const blocked = cases.filter(([u, s, t]) => pair.rust.shouldBlock(u, s, t).blocked).length;
    assert(blocked > 50, `only ${blocked} of ${checked} block -- corpus is not exercising the rules`);
    return `${checked} url/type pairs, ${blocked} blocking, 0 divergent`;
  });
});

check('corpus', 'no divergence across easylist', async () => {
  if (!fs.existsSync(EASYLIST)) {
    throw new SkipCheck('./easylist.txt not present (it is not tracked); fetch one to run this');
  }
  const pair = loadPair(EASYLIST);
  // URLs built from easylist's own patterns: take literal fragments out of the
  // rules themselves, so the corpus hits real rules instead of testing that two
  // engines agree about nothing matching.
  const fragments = easylistPathFragments();
  if (fragments.length < 50) throw new SkipCheck(`only ${fragments.length} usable path rules found in easylist`);

  const sources = ['https://publisher.test/', 'https://elsewhere.test/a', 'https://news.test/x'];
  const cases = fragments.map((frag, i) => [
    `https://sample-${i % 40}.example/${frag}`,
    sources[i % sources.length],
    REAL_TYPES[i % REAL_TYPES.length],
    null
  ]);
  const { checked, divergences } = compare(pair, cases);
  assert(divergences.length === 0,
    `${divergences.length} of ${checked} diverge:\n          ${describe(divergences)}`);
  const blocked = cases.filter(([u, s, t]) => pair.rust.shouldBlock(u, s, t).blocked).length;
  assert(blocked > checked / 4, `only ${blocked} of ${checked} block -- corpus is not hitting real rules`);
  return `${checked} pairs from easylist's own patterns, ${blocked} blocking, 0 divergent`;
});

// ----- asymmetries: the differences that DO exist, pinned so a change is noticed -----

check('asymmetries', "empty resourceType: the JS engine ignores a rule's type, rust does not", async () => {
  return withTestList((listPath) => {
    const pair = loadPair(listPath);
    const url = 'https://scripts.test/x';        // matched by ||scripts.test^$script
    const src = 'https://publisher.test/';
    // With a type, they agree.
    assertEqual(pair.js.shouldBlock(url, src, 'script').blocked, true, 'js with the matching type');
    assertEqual(pair.rust.shouldBlock(url, src, 'script').blocked, true, 'rust with the matching type');
    // With NO type they do not, and this is the direction: js blocks, rust does not.
    assertEqual(pair.js.shouldBlock(url, src, '').blocked, true, "js ignores the rule's type when none is given");
    assertEqual(pair.rust.shouldBlock(url, src, '').blocked, false, 'rust cannot satisfy $script without a type');
    // Unreachable from nwss, which always has a type -- recorded, not fixed. An
    // untyped RULE agrees either way, so the asymmetry is specific to $type rules.
    assertEqual(pair.js.shouldBlock('https://ads.example.com/a.js', src, '').blocked, true, 'js, untyped rule, no type');
    assertEqual(pair.rust.shouldBlock('https://ads.example.com/a.js', src, '').blocked, true, 'rust, untyped rule, no type');
    return 'divergence confined to type-restricted rules asked without a type';
  });
});

check('asymmetries', 'rust is never the stricter engine on document requests', async () => {
  if (!fs.existsSync(EASYLIST)) {
    throw new SkipCheck('./easylist.txt not present (it is not tracked); fetch one to run this');
  }
  const pair = loadPair(EASYLIST);
  // Path-fragment urls, not ||host^ rules: measured, domain rules show NO document
  // divergence at all, so a corpus of those would assert the direction without ever
  // exercising it. These reproduce it.
  const fragments = easylistPathFragments();
  if (fragments.length < 50) throw new SkipCheck(`only ${fragments.length} usable path rules found in easylist`);
  const urls = fragments.map((frag, i) => `https://sample-${i % 40}.example/${frag}`);

  // Innocuous urls belong in this corpus too, and their absence was a real hole:
  // with only urls the JS engine blocks, "rust blocks where js does not" cannot be
  // observed at all. Verified by mutation -- forcing rust to block every document
  // request left this check green until these were added.
  const innocuous = [];
  for (let i = 0; i < 40; i++) {
    innocuous.push(`https://ordinary-${i}.example/articles/story-${i}.html`);
    innocuous.push(`https://ordinary-${i}.example/assets/site-${i}.css`);
  }
  for (const url of innocuous) {
    assertEqual(pair.js.shouldBlock(url, 'https://publisher.test/', 'document').blocked, false,
      `the JS engine must not block ${url} -- the control set has to be innocuous`);
  }
  urls.push(...innocuous);

  let jsOnly = 0;
  const rustOnly = [];
  for (const url of urls) {
    const a = pair.js.shouldBlock(url, 'https://publisher.test/', 'document').blocked;
    const b = pair.rust.shouldBlock(url, 'https://publisher.test/', 'document').blocked;
    if (a && !b) jsOnly++;
    else if (b && !a) rustOnly.push(url);
  }
  // The direction is what matters. nwss never aborts a main-frame document, and an
  // ad iframe arrives as 'sub_frame' (asserted below), so rust being more
  // permissive here changes nothing -- rust being STRICTER would mean it aborts
  // documents the JS engine allows, which is the direction that breaks scans.
  assertEqual(rustOnly.length, 0,
    `rust blocks ${rustOnly.length} document request(s) the JS engine allows, e.g. ${rustOnly.slice(0, 3).join(', ')}`);

  // sub_frame is the type an ad iframe actually arrives as, and it must agree
  // exactly -- on the same urls that diverge for 'document'.
  let frameDiff = 0;
  for (const url of urls) {
    const a = pair.js.shouldBlock(url, 'https://publisher.test/', 'sub_frame').blocked;
    const b = pair.rust.shouldBlock(url, 'https://publisher.test/', 'sub_frame').blocked;
    if (a !== b) frameDiff++;
  }
  assertEqual(frameDiff, 0, 'sub_frame verdicts must agree exactly');
  // Reported, not asserted: if the engines ever converge here that is an
  // improvement, and a test that fails on an improvement is a nuisance.
  return `${urls.length} urls (${innocuous.length} of them innocuous controls): sub_frame exact, document js-only=${jsOnly}, rust-only=0`;
});

check('asymmetries', 'hostless URLs agree, and neither engine calls them an error', async () => {
  return withTestList((listPath) => {
    const pair = loadPair(listPath);
    // The rust wrapper used to throw on these and log a warning per request; both
    // engines now report the same non-match with the same reason.
    //
    // The last four matter more than they look. A hostless URI carries its own
    // content in the url, so a path or regex rule can match a substring INSIDE it:
    // measured, `data:text/html,<img src="/banner-ad.png">` was blocked by the rule
    // `/banner-ad.` in the JS engine while rust left it alone -- an inert inline
    // resource aborted for no benefit, and a silent difference between the default
    // engine and its fallback. Both now decline all of them.
    for (const url of ['data:text/javascript,1', 'data:image/png;base64,iVBORw0K', 'about:blank',
      'blob:https://x.test/abc', 'javascript:void(0)',
      'data:text/html,<img src="/banner-ad.png">',
      'data:text/html,%3Cimg%20src%3D%22/banner-ad.png%22%3E',
      'about:blank?/banner-ad.',
      'blob:https://ads.example.com/uuid']) {
      const a = pair.js.shouldBlock(url, 'https://site.test/', 'script');
      const b = pair.rust.shouldBlock(url, 'https://site.test/', 'script');
      assertEqual([a.blocked, a.reason], [false, 'no_match'], `js on ${url}`);
      assertEqual([b.blocked, b.reason], [false, 'no_match'], `rust on ${url}`);
    }
    assertEqual(pair.rust.getStats().errors, 0, 'no engine errors were recorded for hostless URLs');
    // Not vacuous: the same substrings and host DO block when they arrive over http.
    assertEqual(pair.js.shouldBlock('https://cdn.test/banner-ad.png', 'https://site.test/', 'image').blocked, true,
      'the same pattern still blocks over http in the JS engine');
    assertEqual(pair.rust.shouldBlock('https://ads.example.com/uuid', 'https://site.test/', 'image').blocked, true,
      'the same host still blocks over http in rust');
    return '9 hostless urls incl. 4 carrying blockable substrings, same verdict and reason, 0 engine errors';
  });
});

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

async function main() {
  if (HELP) { printHelp(); process.exit(0); }
  const badFlags = args.filter(a => a.startsWith('-') && !KNOWN_FLAGS.has(a) && !a.startsWith('--group='));
  if (badFlags.length) {
    console.error(`Unrecognised flag(s): ${badFlags.join(', ')}. See --help.`);
    process.exit(2);
  }
  if (GROUP && !GROUPS.includes(GROUP)) {
    console.error(`--group must be one of ${GROUPS.join(', ')} (got: ${GROUP}).`);
    process.exit(2);
  }
  if (LIST) {
    for (const c of CHECKS) console.log(`  [${c.group}] ${c.name}`);
    process.exit(0);
  }

  const selected = GROUP ? CHECKS.filter(c => c.group === GROUP) : CHECKS;
  let failures = 0;
  let skipped = 0;
  let lastGroup = null;
  const started = Date.now();

  for (const c of selected) {
    if (c.group !== lastGroup) {
      console.log(`\n${messageColors.highlight(`== ${c.group} ==`)}`);
      lastGroup = c.group;
    }
    const t0 = Date.now();
    try {
      const detail = await c.run();
      console.log(`  ${messageColors.success('PASS')}  ${c.name}${VERBOSE && detail ? `\n          ${detail} (${Date.now() - t0}ms)` : ''}`);
    } catch (err) {
      if (err instanceof SkipCheck) {
        skipped++;
        console.log(`  ${messageColors.warn('SKIP')}  ${c.name}`);
        console.log(`          ${err.message}`);
        continue;
      }
      failures++;
      console.log(`  ${messageColors.error('FAIL')}  ${c.name}`);
      console.log(`          ${err.message}`);
    }
  }

  const secs = ((Date.now() - started) / 1000).toFixed(1);
  console.log('');
  if (failures === 0) {
    console.log(messageColors.success(`All ${selected.length - skipped} check(s) passed in ${secs}s${skipped ? `, ${skipped} skipped` : ''}`));
    process.exit(0);
  }
  console.log(messageColors.error(`${failures} of ${selected.length} check(s) FAILED in ${secs}s`));
  process.exit(1);
}

main().catch((err) => {
  console.error(`test-adblock-parity: unexpected failure: ${err && err.stack ? err.stack : err}`);
  process.exit(1);
});
