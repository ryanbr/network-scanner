#!/usr/bin/env node
/**
 * How nettools invokes `dig`: the argv for a given --dns spec, when the
 * concurrency slot is held, and when a lookup is skipped entirely.
 *
 * `--dns` feeds three consumers: the DNS pre-check (lib/dns.js), nettools' dig,
 * and Chrome's DoH mapping. lib/dns.js deliberately accepts an address WITH a
 * port -- `8.8.8.8:5353`, `[2001:db8::1]:5353`, the form Resolver.setServers()
 * understands -- and the pre-check queries that port. nettools used to strip it
 * and invoke `dig @8.8.8.8`, so one flag pointed the two paths at DIFFERENT
 * servers. Measured before the fix with a UDP listener on 127.0.0.1:5353 and
 * `--dns 127.0.0.1:5353`: 7 pre-check queries arrived there, while dig ran as
 * `dig @127.0.0.1 +tcp +time=3 +tries=2 lvh.me A` -- port 53. Silent, and
 * exactly wrong for a split-DNS/dnsmasq-on-5353 setup.
 *
 * These checks read the real argv by putting a fake `dig` on PATH (execFile
 * resolves through PATH), so they assert what the subprocess is invoked with
 * rather than what the parser returns.
 *
 * Two later groups cover behaviour around the invocation:
 *
 *   - The dig_max_concurrent slot is held around the SUBPROCESS only, not
 *     across the retry backoff. It used to wrap the whole lookup, so one
 *     failing domain sitting in a dig_retry_backoff pause (default 3s, up to
 *     60s, times the retry count) blocked every other lookup from a slot while
 *     nothing was running.
 *   - .dnsignore skips a lookup entirely -- no dig at all -- for an entry or
 *     any subdomain of one. Its matcher walks the candidate's parent domains
 *     instead of scanning every entry, which --dnsignore-auto keeps appending
 *     to; the two forms were verified equivalent over 36,000 generated
 *     comparisons before the swap.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { createNetToolsHandler, setDigResolvers } = require('../lib/nettools');

// A truncated run must not look like a passing one. If a lookup never
// resolves -- a leaked dig slot deadlocks acquireDigSlot(), and Node then
// simply exits 0 with nothing left to do -- the suite would otherwise print
// its first few PASS lines and appear green. Found exactly that while
// mutation-testing the slot fix: the run stopped after 6 checks, exit 0.
let finished = false;
process.on('exit', (code) => {
  if (!finished && code === 0) {
    console.log('\n  FAIL  the suite exited before finishing — a lookup never resolved (leaked dig slot?)');
    process.exitCode = 1;
  }
});

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};

// A fake dig: records its argv, then prints a minimal NOERROR answer so the
// lookup succeeds on the first attempt and the ladder stops there.
const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-digshim-'));
const argvLog = path.join(shimDir, 'argv.log');
fs.writeFileSync(path.join(shimDir, 'dig'), `#!/bin/sh
printf '%s\\n' "$*" >> ${argvLog}
if [ -n "$NWSS_TEST_DIG_SERVFAIL" ] && { [ "$NWSS_TEST_DIG_SERVFAIL" = "1" ] || case "$*" in *"$NWSS_TEST_DIG_SERVFAIL"*) true ;; *) false ;; esac; }; then
  # A resolver-side failure: digLookup falls through to the next attempt, so
  # every entry in the plan runs and each one's argv is recorded.
  printf ';; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\\n'
  exit 0
fi
cat <<'OUT'
; <<>> DiG fake <<>>
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; ANSWER SECTION:
example.test.\t300\tIN\tA\t127.0.0.1

OUT
`, { mode: 0o755 });
process.env.PATH = shimDir + path.delimiter + process.env.PATH;

let caseNo = 0;
async function digArgvFor(spec, { servfail = false } = {}) {
  fs.writeFileSync(argvLog, '');
  if (servfail) process.env.NWSS_TEST_DIG_SERVFAIL = '1';
  else delete process.env.NWSS_TEST_DIG_SERVFAIL;
  setDigResolvers(spec === null ? [] : (Array.isArray(spec) ? spec : [spec]));
  const handler = createNetToolsHandler({
    digTerms: ['127.0.0.1'],
    processedDigDomains: new Set(),
    processedWhoisDomains: new Set(),
    // a real match sink, so these checks exercise the whole path instead of
    // stopping at an unguarded matchedDomains.add() deep inside it
    matchedDomains: new Set()
  });
  // A fresh domain per case: the dig cache is global and keyed by domain+type.
  await handler(`case${++caseNo}.example.test`, `case${caseNo}.example.test`);
  return fs.readFileSync(argvLog, 'utf8').trim().split('\n').filter(Boolean);
}

(async () => {
  let argv = await digArgvFor('127.0.0.1:5353');
  check('an ip:port spec passes -p to dig',
    argv.length > 0 && argv[0].includes('@127.0.0.1') && / -p 5353( |$)/.test(argv[0]),
    JSON.stringify(argv[0] || '(no dig invocation)'));

  argv = await digArgvFor('8.8.8.8');
  check('a bare ip passes no -p', argv.length > 0 && argv[0].includes('@8.8.8.8') && !argv[0].includes('-p'),
    JSON.stringify(argv[0] || '(none)'));

  argv = await digArgvFor('[2001:db8::1]:5353');
  check('a bracketed IPv6 spec keeps address and port',
    argv.length > 0 && argv[0].includes('@2001:db8::1') && / -p 5353( |$)/.test(argv[0]),
    JSON.stringify(argv[0] || '(none)'));

  argv = await digArgvFor('[2001:db8::1]');
  check('a bracketed IPv6 spec without a port passes no -p',
    argv.length > 0 && argv[0].includes('@2001:db8::1') && !argv[0].includes('-p'),
    JSON.stringify(argv[0] || '(none)'));

  // lib/dns.js validates only \d{1,5}, so :0 and :99999 can reach nettools. A
  // bad -p makes dig fail outright, so they fall back to the default port.
  // (:0 is belt-and-braces -- 0 is falsy at the call-site guard, so removing
  // digSpecPort's lower bound leaves this case passing and only :99999 red.)
  for (const bad of ['127.0.0.1:0', '127.0.0.1:99999']) {
    argv = await digArgvFor(bad);
    check(`an out-of-range port (${bad.split(':')[1]}) is ignored, not passed`,
      argv.length > 0 && argv[0].includes('@127.0.0.1') && !argv[0].includes('-p'),
      JSON.stringify(argv[0] || '(none)'));
  }

  // Mixed list: the port belongs to its own entry, not to the lookup. Every
  // resolver is tried in turn for one lookup (rotation + failover), so a port
  // hoisted out of the per-entry mapping would leak onto the wrong server.
  // Each attempt is a separate dig invocation, hence separate log lines.
  argv = await digArgvFor(['1.1.1.1', '127.0.0.1:5353'], { servfail: true });
  const portedLines = argv.filter(l => l.includes('@127.0.0.1'));
  const plainLines = argv.filter(l => l.includes('@1.1.1.1'));
  check('in a mixed list each resolver carries only its own port',
    portedLines.length > 0 && portedLines.every(l => / -p 5353( |$)/.test(l)) &&
    plainLines.length > 0 && plainLines.every(l => !l.includes('-p')),
    `ported=${JSON.stringify(portedLines)} plain=${JSON.stringify(plainLines)}`);

  argv = await digArgvFor(null);
  check('no --dns means no @server and no -p',
    argv.length > 0 && !argv[0].includes('@') && !argv[0].includes('-p'),
    JSON.stringify(argv[0] || '(none)'));

  // === the concurrency slot is not held across the backoff ===
  // A: a domain whose every attempt SERVFAILs, with one extra retry behind a
  // 1.5s backoff. B: a healthy domain, started right after. With a cap of one
  // slot, B can only finish while A is still pausing if A isn't holding it.
  {
    const { setDigConcurrency, setDigExtraRetries, setDigRetryBackoff } = require('../lib/nettools');
    setDigConcurrency(1);
    setDigExtraRetries(1);
    setDigRetryBackoff(1500);

    const slow = createNetToolsHandler({ digTerms: ['127.0.0.1'], processedDigDomains: new Set(), processedWhoisDomains: new Set(),
    // a real match sink, so these checks exercise the whole path instead of
    // stopping at an unguarded matchedDomains.add() deep inside it
    matchedDomains: new Set() });
    const fast = createNetToolsHandler({ digTerms: ['127.0.0.1'], processedDigDomains: new Set(), processedWhoisDomains: new Set(),
    // a real match sink, so these checks exercise the whole path instead of
    // stopping at an unguarded matchedDomains.add() deep inside it
    matchedDomains: new Set() });
    setDigResolvers(['127.0.0.1']);

    // Per-domain failure: only A's name SERVFAILs, so A runs its full ladder
    // (UDP, TCP after 400ms, then the extra retry after the 1500ms backoff)
    // while B's dig answers normally and needs the single slot mid-backoff.
    process.env.NWSS_TEST_DIG_SERVFAIL = 'servfail.example.test';
    const t0 = Date.now();
    const slowDone = slow('servfail.example.test', 'servfail.example.test').then(() => Date.now() - t0);
    await new Promise(r => setTimeout(r, 600));      // A is now in its 1500ms backoff
    const fastMs = await fast('healthy.example.test', 'healthy.example.test').then(() => Date.now() - t0);
    const slowMs = await slowDone;
    delete process.env.NWSS_TEST_DIG_SERVFAIL;
    check('a lookup in its retry backoff does not hold the slot',
      fastMs < 1500 && slowMs > 1800 && slowMs > fastMs,
      `healthy finished at ${fastMs}ms while the servfailing lookup ran to ${slowMs}ms (400ms TCP pause + 1500ms retry backoff, cap 1 slot)`);

    setDigConcurrency(6);
    setDigExtraRetries(0);
    setDigRetryBackoff(3000);
  }

  // === .dnsignore skips the lookup entirely ===
  // The real list lives at the repo root and is gitignored, so these checks
  // used to be SKIPPED whenever one existed — refusing to clobber it, which
  // is right, but that is every production clone, i.e. the only place the
  // feature is used (13 checks in a clone without the file, 9 with it). They
  // now point NWSS_DNSIGNORE_FILE at a temp file instead, so they run
  // everywhere and the operator's list is never opened: pinned below by
  // asserting the repo-root file is byte-for-byte untouched across the group.
  {
    const { loadDnsIgnore, getDnsCacheStats } = require('../lib/nettools');
    const realFile = path.join(__dirname, '..', '.dnsignore');
    const realBefore = fs.existsSync(realFile) ? fs.readFileSync(realFile) : null;
    const ignoreFile = path.join(shimDir, 'dnsignore-fixture');
    const prevEnv = process.env.NWSS_DNSIGNORE_FILE;
    process.env.NWSS_DNSIGNORE_FILE = ignoreFile;
    {
      try {
        fs.writeFileSync(ignoreFile, '# test\nignored.example.test\n');
        const loaded = loadDnsIgnore();
        setDigResolvers([]);
        const h = createNetToolsHandler({ digTerms: ['127.0.0.1'], processedDigDomains: new Set(), processedWhoisDomains: new Set(),
    // a real match sink, so these checks exercise the whole path instead of
    // stopping at an unguarded matchedDomains.add() deep inside it
    matchedDomains: new Set() });

        fs.writeFileSync(argvLog, '');
        await h('ignored.example.test', 'ignored.example.test');
        const exact = fs.readFileSync(argvLog, 'utf8').trim();
        check('an exact .dnsignore entry runs no dig', loaded === 1 && exact === '', `entries=${loaded} argv=${JSON.stringify(exact)}`);

        fs.writeFileSync(argvLog, '');
        await h('sub.deep.ignored.example.test', 'sub.deep.ignored.example.test');
        const sub = fs.readFileSync(argvLog, 'utf8').trim();
        check('a subdomain of an entry runs no dig', sub === '', `argv=${JSON.stringify(sub)}`);

        fs.writeFileSync(argvLog, '');
        await h('notignored.example.test', 'notignored.example.test');
        const other = fs.readFileSync(argvLog, 'utf8').trim();
        check('an unlisted domain still runs dig', other.includes('notignored.example.test'), `argv=${JSON.stringify(other)}`);

        fs.writeFileSync(argvLog, '');
        await h('xignored.example.test', 'xignored.example.test');
        const near = fs.readFileSync(argvLog, 'utf8').trim();
        check('a name merely ENDING in an entry is not skipped', near.includes('xignored.example.test'), `argv=${JSON.stringify(near)}`);

        // The same fallback, UNLISTED: it must still run. The checks below
        // assert only that an ignored subdomain is NOT dug, so a change that
        // disabled the fallback outright — or kept the count while dropping
        // the lookup — would leave them green. Its reason to exist is an ad
        // domain live on a subdomain with a dead or parked apex, so dropping
        // it loses the capture, silently.
        process.env.NWSS_TEST_DIG_SERVFAIL = 'fb-apex.example.test A';
        const beforeLive = getDnsCacheStats().digIgnored;
        fs.writeFileSync(argvLog, '');
        await h('fb-apex.example.test', 'live-sub.fb-apex.example.test');
        delete process.env.NWSS_TEST_DIG_SERVFAIL;
        const liveArgv = fs.readFileSync(argvLog, 'utf8').trim().split('\n').filter(Boolean);
        check('an unlisted subdomain is still dug after the root fails',
          liveArgv.some(l => l.includes('live-sub.fb-apex.example.test'))
            && getDnsCacheStats().digIgnored === beforeLive,
          `argv=${JSON.stringify(liveArgv)} digIgnored=${getDnsCacheStats().digIgnored}`);

        // The run total the DNS summary prints. UNIQUE domains, not lookups:
        // the handler runs per request, and the whole point of the list is
        // domains requested over and over. Two skips above (the entry and a
        // subdomain of it), and the two that ran dig must not be counted.
        const ignoredAfterFour = getDnsCacheStats().digIgnored;
        check('skipped digs are counted for the summary', ignoredAfterFour === 2,
          `digIgnored=${ignoredAfterFour} (expected 2: the entry and its subdomain)`);

        fs.writeFileSync(argvLog, '');
        await h('ignored.example.test', 'ignored.example.test');
        const repeatArgv = fs.readFileSync(argvLog, 'utf8').trim();
        const ignoredAfterRepeat = getDnsCacheStats().digIgnored;
        check('a domain skipped twice counts once', ignoredAfterRepeat === 2 && repeatArgv === '',
          `digIgnored=${ignoredAfterRepeat} argv=${JSON.stringify(repeatArgv)}`);
        // An entry naming a SUBDOMAIN, with its apex unlisted: the gate sees
        // only the root (default dig mode digs the apex), so the root dig runs
        // and the subdomain dig is suppressed further down, in the fallback
        // that exists for ad domains live on a sub but dead at a parked apex.
        // That skip used to be invisible — 0 reported while a lookup had been
        // prevented.
        fs.writeFileSync(ignoreFile, '# test\nsub.apex-live.example.test\n');
        const loadedSub = loadDnsIgnore();
        const before = getDnsCacheStats().digIgnored;
        process.env.NWSS_TEST_DIG_SERVFAIL = 'apex-live.example.test';
        fs.writeFileSync(argvLog, '');
        await h('apex-live.example.test', 'sub.apex-live.example.test');
        delete process.env.NWSS_TEST_DIG_SERVFAIL;
        const subArgv = fs.readFileSync(argvLog, 'utf8').trim();
        const digged = subArgv.split('\n').filter(Boolean);
        check('a subdomain entry suppresses the fallback dig, and is counted',
          loadedSub === 1 && getDnsCacheStats().digIgnored === before + 1
            && digged.length > 0 && !digged.some(l => l.includes('sub.apex-live.example.test')),
          `entries=${loadedSub} digIgnored ${before}->${getDnsCacheStats().digIgnored} argv=${JSON.stringify(digged)}`);
        // === the list against the dig cache ===
        // Note for anything added here: the shim matches NWSS_TEST_DIG_SERVFAIL
        // as a SUBSTRING of its argv, and a root domain is a suffix of its own
        // subdomain, so failing `root.example.test` fails `sub.root.example.test`
        // too. A probe written that way reported the fallback cache broken when
        // it was the pattern — pick non-nesting names when only one must fail.

        // A skipped domain must leave NO cache entry: nothing was looked up, so
        // there is no verdict to remember. Otherwise removing a domain from the
        // list would keep reading a skip-shaped answer from cache instead of
        // digging — the list would be sticky after an edit, which is the
        // opposite of what an operator editing it expects.
        fs.writeFileSync(ignoreFile, '# test\nrelist.example.test\n');
        loadDnsIgnore();
        fs.writeFileSync(argvLog, '');
        await h('relist.example.test', 'relist.example.test');
        const whileListed = fs.readFileSync(argvLog, 'utf8').trim();
        fs.writeFileSync(ignoreFile, '# emptied\n');
        loadDnsIgnore();
        fs.writeFileSync(argvLog, '');
        await h('relist.example.test', 'relist.example.test');
        const afterDelisting = fs.readFileSync(argvLog, 'utf8').trim();
        check('a skipped domain is not cached — delisting it digs for real',
          whileListed === '' && afterDelisting.includes('relist.example.test'),
          `while listed=${JSON.stringify(whileListed)} after=${JSON.stringify(afterDelisting)}`);

        // And the skip comes BEFORE the cache is consulted: a domain with a warm
        // entry, then listed, is skipped rather than served from cache. Asserted
        // on digHits, because "no dig ran" alone cannot tell a skip from a hit —
        // and a skip counted as a cache hit would inflate the hit rate with
        // lookups that never happened.
        fs.writeFileSync(argvLog, '');
        const warm = createNetToolsHandler({ digTerms: ['127.0.0.1'], processedDigDomains: new Set(),
          processedWhoisDomains: new Set(), matchedDomains: new Set() });
        await warm('cachewarm.example.test', 'cachewarm.example.test');
        const warmed = fs.readFileSync(argvLog, 'utf8').trim();
        fs.writeFileSync(ignoreFile, '# test\ncachewarm.example.test\n');
        loadDnsIgnore();
        const hitsBefore = getDnsCacheStats().digHits;
        const ignoredBefore = getDnsCacheStats().digIgnored;
        fs.writeFileSync(argvLog, '');
        const afterListing = createNetToolsHandler({ digTerms: ['127.0.0.1'], processedDigDomains: new Set(),
          processedWhoisDomains: new Set(), matchedDomains: new Set() });
        await afterListing('cachewarm.example.test', 'cachewarm.example.test');
        const st = getDnsCacheStats();
        check('the skip short-circuits ahead of the cache, not counted as a hit',
          warmed.includes('cachewarm.example.test') && fs.readFileSync(argvLog, 'utf8').trim() === ''
            && st.digHits === hitsBefore && st.digIgnored === ignoredBefore + 1,
          `warmed=${JSON.stringify(warmed.split('\n')[0])} hits ${hitsBefore}->${st.digHits} digIgnored ${ignoredBefore}->${st.digIgnored}`);
      } finally {
        fs.rmSync(ignoreFile, { force: true });
        delete process.env.NWSS_TEST_DIG_SERVFAIL;
        if (prevEnv === undefined) delete process.env.NWSS_DNSIGNORE_FILE;
        else process.env.NWSS_DNSIGNORE_FILE = prevEnv;
      }
      const realAfter = fs.existsSync(realFile) ? fs.readFileSync(realFile) : null;
      const untouched = realBefore === null ? realAfter === null : (realAfter !== null && realBefore.equals(realAfter));
      check('the operator\'s own .dnsignore was never written', untouched,
        realBefore === null ? 'no repo-root file, and none was created' : `${realBefore.length} bytes, unchanged`);
    }
  }

  fs.rmSync(shimDir, { recursive: true, force: true });
  finished = true;
  console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error('harness error:', e); process.exit(2); });
