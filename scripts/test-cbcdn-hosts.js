#!/usr/bin/env node
/**
 * test-cbcdn-hosts.js — pins scripts/cbcdn-hosts.js.
 *
 * Every check here is a defect the script would otherwise have:
 *
 *  - captures are CRLF, and a greedy value match swallows the trailing \r. In a
 *    JS regex \r is a LINE TERMINATOR, so any later `$`-anchored test on that
 *    value matches NOTHING -- silently, which is the whole hazard.
 *  - `cbcdn=` unanchored also matches `xcbcdn=`, harvesting a parameter that
 *    belongs to something else.
 *  - a host inside an encoded query is encoded twice, so one decode is not
 *    enough and zero decodes yields a name with %2E in it.
 *  - a parameter can hold filter SYNTAX; only hostname VALIDITY refuses it,
 *    which is why hostRejectionReason is used rather than a printable test.
 *
 *   node scripts/test-cbcdn-hosts.js        # <1s, no browser, no network
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { fullyDecode, valuesIn, hostsFrom, alreadyListed, digKeep } = require('./cbcdn-hosts');

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name}\n         got  ${JSON.stringify(got)}\n         want ${JSON.stringify(want)}`); }
};

console.log('\ncbcdn host harvest\n');

// ---- the value cut ---------------------------------------------------------
check('a value ends at &', valuesIn('?a=1&cbcdn=host.example&b=2', 'cbcdn'), ['host.example']);
check('a value ends at end of input', valuesIn('?cbcdn=host.example', 'cbcdn'), ['host.example']);
// The CRLF defect: without an explicit cut the value is "host.example\r", and
// `/^[a-z.]+$/.test()` on that returns false while LOOKING like a hostname.
check('a CRLF line does not leave \\r on the value',
  valuesIn('uri=https://a.example/?cbcdn=host.example\r\n', 'cbcdn'), ['host.example']);
check('and the cut really matters (\\r would defeat a $ anchor)',
  /^[a-z.]+$/.test('host.example\r'), false);
check('several values in one line are all taken',
  valuesIn('?cbcdn=one.example&x=1&cbcdn=two.example', 'cbcdn'), ['one.example', 'two.example']);
check('an empty value yields nothing', valuesIn('?cbcdn=&b=2', 'cbcdn'), []);

// ---- the anchor ------------------------------------------------------------
check('a parameter merely ENDING with the name is not harvested',
  valuesIn('?xcbcdn=other.example', 'cbcdn'), []);
check('a parameter at the start of the query is harvested',
  valuesIn('?cbcdn=host.example', 'cbcdn'), ['host.example']);
check('the name is matched case-insensitively',
  valuesIn('?CbCdn=host.example', 'cbcdn'), ['host.example']);
check('a different parameter can be asked for',
  valuesIn('?cdn=host.example', 'cdn'), ['host.example']);

// ---- decoding --------------------------------------------------------------
check('a single-encoded value decodes', fullyDecode('host%2Eexample'), 'host.example');
check('a double-encoded value decodes too (a host in an encoded query)',
  fullyDecode('host%252Eexample'), 'host.example');
check('a plain value is unchanged', fullyDecode('host.example'), 'host.example');
check('a malformed escape does not throw', fullyDecode('host%2'), 'host%2');

// ---- validity, not printability -------------------------------------------
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nwss-cbcdn-'));
  const write = (name, body) => { const p = path.join(dir, name); fs.writeFileSync(p, body); return p; };

  // A MOZ_LOG, CRLF, naming one good host and three that are not hostnames.
  const moz = write('c.log.moz_log',
    '2026-01-01 00:00:00.000000 UTC - [Parent 1: Main Thread]: E/nsHttp uri=https://page.example/\r\n' +
    '2026-01-01 00:00:00.000000 UTC - [Parent 1: Main Thread]: E/nsHttp http request [\r\n' +
    '2026-01-01 00:00:00.000000 UTC - [Parent 1: Main Thread]: E/nsHttp   Sec-Fetch-Dest: document\r\n' +
    '2026-01-01 00:00:00.000000 UTC - [Parent 1: Main Thread]: E/nsHttp ]\r\n' +
    '2026-01-01 00:00:01.000000 UTC - [Parent 1: Main Thread]: E/nsHttp uri=https://apex.example/b.php?cbcdn=named.example&x=1\r\n' +
    '2026-01-01 00:00:01.000000 UTC - [Parent 1: Main Thread]: E/nsHttp http request [\r\n' +
    '2026-01-01 00:00:01.000000 UTC - [Parent 1: Main Thread]: E/nsHttp   Sec-Fetch-Dest: script\r\n' +
    '2026-01-01 00:00:01.000000 UTC - [Parent 1: Main Thread]: E/nsHttp ]\r\n' +
    '2026-01-01 00:00:02.000000 UTC - [Parent 1: Main Thread]: E/nsHttp uri=https://apex.example/c.php?cbcdn=a%24b.example\r\n' +
    '2026-01-01 00:00:02.000000 UTC - [Parent 1: Main Thread]: E/nsHttp http request [\r\n' +
    '2026-01-01 00:00:02.000000 UTC - [Parent 1: Main Thread]: E/nsHttp   Sec-Fetch-Dest: script\r\n' +
    '2026-01-01 00:00:02.000000 UTC - [Parent 1: Main Thread]: E/nsHttp ]\r\n' +
    '2026-01-01 00:00:03.000000 UTC - [Parent 1: Main Thread]: E/nsHttp uri=https://apex.example/d.php?cbcdn=localhost\r\n' +
    '2026-01-01 00:00:03.000000 UTC - [Parent 1: Main Thread]: E/nsHttp http request [\r\n' +
    '2026-01-01 00:00:03.000000 UTC - [Parent 1: Main Thread]: E/nsHttp   Sec-Fetch-Dest: script\r\n' +
    '2026-01-01 00:00:03.000000 UTC - [Parent 1: Main Thread]: E/nsHttp ]\r\n' +
    '2026-01-01 00:00:04.000000 UTC - [Parent 1: Main Thread]: E/nsHttp uri=https://apex.example/e.php?cbcdn=*.example\r\n' +
    '2026-01-01 00:00:04.000000 UTC - [Parent 1: Main Thread]: E/nsHttp http request [\r\n' +
    '2026-01-01 00:00:04.000000 UTC - [Parent 1: Main Thread]: E/nsHttp   Sec-Fetch-Dest: script\r\n' +
    '2026-01-01 00:00:04.000000 UTC - [Parent 1: Main Thread]: E/nsHttp ]\r\n');

  const r = hostsFrom(moz, 'cbcdn');
  check('a MOZ_LOG is read as a capture, not as text', r.via, 'Firefox MOZ_LOG');
  check('only the valid hostname survives', [...r.found.keys()], ['named.example']);
  check('filter syntax in the value is refused', r.found.has('a$b.example'), false);
  check('a dotless name is refused', r.found.has('localhost'), false);
  check('a wildcard host is refused', r.found.has('*.example'), false);

  // A HAR carrying the same parameter -- the reader must not be MOZ_LOG-only.
  const har = write('c.har', JSON.stringify({ log: {
    version: '1.2', creator: { name: 'x', version: '1' },
    pages: [{ id: 'p', title: 'https://page.example/', pageTimings: {} }],
    entries: [
      { request: { url: 'https://page.example/', method: 'GET', headers: [{ name: 'Sec-Fetch-Dest', value: 'document' }] },
        response: { status: 200, content: { mimeType: 'text/html' } } },
      { request: { url: 'https://apex.example/b.php?cbcdn=named.example', method: 'GET', headers: [{ name: 'Sec-Fetch-Dest', value: 'script' }] },
        response: { status: 200, content: { mimeType: 'application/javascript' } } }
    ]
  } }));
  const rh = hostsFrom(har, 'cbcdn');
  check('a HAR is read too', rh.via, 'HAR');
  check('and yields the same host', [...rh.found.keys()], ['named.example']);

  // A plain debug log is NOT a capture; the live path's --debug output is this
  // shape and carries these parameters, so a text fallback is required.
  const log = write('debug.log',
    '[debug] [blockDomainsByUrl] aborting https://apex.example/b.php?cbcdn=named.example&r=1 (domain apex.example dynamically blocked)\n' +
    '[debug] something else entirely\n');
  const rl = hostsFrom(log, 'cbcdn');
  check('a non-capture log falls back to a text scan', rl.via, 'text');
  check('and still finds the host', [...rl.found.keys()], ['named.example']);

  // Counting, so output can say how much evidence there is.
  const twice = write('twice.log',
    '?cbcdn=named.example\n?cbcdn=named.example\n?cbcdn=other.example\n');
  const rt = hostsFrom(twice, 'cbcdn');
  check('repeats are counted, not duplicated', [...rt.found.entries()].sort(),
    [['named.example', 2], ['other.example', 1]]);

  // --not-in, in both shapes a list file comes in.
  const list = write('list.txt', '||named.example^\n! a comment\nother.example\n\n');
  const listed = alreadyListed(list);
  check('an adblock rule is read from the list', listed.has('named.example'), true);
  check('a bare hostname is read from the list', listed.has('other.example'), true);
  check('a comment is not read as a host', listed.has('! a comment'), false);

  fs.rmSync(dir, { recursive: true, force: true });
}

// ---- the gate ---------------------------------------------------------------
// digKeep decides what gets PUBLISHED and had no coverage at all. The resolver
// is injected rather than stubbed on the dns module: this script uses node's
// dns, so the house trick of a fake `dig` on PATH cannot reach it.
(async () => {
  const stub = (records) => async () => records;
  const boom = (code) => async () => { const e = new Error('nope'); e.code = code; throw e; };

  // A records, ANY -- the behaviour that shipped, pinned for the first time.
  check('A/any: a prefix match keeps the host',
    (await digKeep('h.example', ['192.0.2.', '198.51.100.'], { resolve: stub(['192.0.2.7']) })).keep, true);
  check('A/any: no prefix match drops it',
    (await digKeep('h.example', ['192.0.2.'], { resolve: stub(['203.0.113.9']) })).keep, false);
  check('no terms means no gate',
    (await digKeep('h.example', [], { resolve: boom('ESERVFAIL') })).keep, true);

  // Failures are never a mismatch: losing a real host to a dns blip is the
  // expensive direction, so it is kept and flagged.
  const failed = await digKeep('h.example', ['192.0.2.'], { resolve: boom('ESERVFAIL') });
  check('a dns failure keeps the host', failed.keep, true);
  check('and says it is unconfirmed', /kept unconfirmed/.test(failed.note), true);
  // An empty answer is the same situation: no records is not evidence of a
  // mismatch. `.find()` over [] returned undefined, which DROPPED the host.
  const empty = await digKeep('h.example', ['192.0.2.'], { resolve: stub([]) });
  check('an empty answer keeps the host too', empty.keep, true);
  check('and says so rather than claiming a mismatch', /no A records/.test(empty.note), true);

  // NS + ALL: the nameserver PAIR. This is the whole point of the two new
  // options -- a single Cloudflare nameserver name is shared across unrelated
  // accounts, so only the pair identifies the operator.
  const PAIR = ['ns1.operator.example', 'ns2.operator.example'];
  check('NS/all: both nameservers present keeps the host',
    (await digKeep('h.example', PAIR, { recordType: 'NS', mode: 'all',
      resolve: stub(['ns2.operator.example', 'ns1.operator.example']) })).keep, true);
  check('NS/all: only ONE of the pair drops it',
    (await digKeep('h.example', PAIR, { recordType: 'NS', mode: 'all',
      resolve: stub(['ns1.operator.example', 'someone.else.example']) })).keep, false);
  // ...and the mode is load-bearing: the same records pass under ANY.
  check('NS/any: one of the pair is enough',
    (await digKeep('h.example', PAIR, { recordType: 'NS', mode: 'any',
      resolve: stub(['ns1.operator.example', 'someone.else.example']) })).keep, true);
  // A resolver may apply DNS 0x20 mixed-case randomisation to the answer.
  check('NS matching is case-insensitive',
    (await digKeep('h.example', PAIR, { recordType: 'NS', mode: 'all',
      resolve: stub(['Ns1.Operator.Example', 'NS2.operator.example']) })).keep, true);

  // The real-world case the record type exists for: an A-record gate on shared
  // CDN ranges confirms hosts that are not the operator's at all -- measured,
  // including the first-party site. Same records, two gates, opposite verdicts.
  const CDN_RANGES = ['192.0.2.', '198.51.100.'];
  const notOperator = stub(['192.0.2.9', '192.0.2.44']);
  check('A/any on shared CDN ranges confirms a host that is not the operator',
    (await digKeep('firstparty.example', CDN_RANGES, { resolve: notOperator })).keep, true);
  check('NS/all on the pair rejects that same host',
    (await digKeep('firstparty.example', PAIR, { recordType: 'NS', mode: 'all',
      resolve: stub(['ns7.unrelated.example', 'ns8.unrelated.example']) })).keep, false);

  // The note is what an operator reads beside a host before it is published,
  // so it has to carry the RECORD, not just the term they already typed.
  const prefixNote = await digKeep('h.example', ['192.0.2.'], { resolve: stub(['192.0.2.7']) });
  check('a prefix match names the record it matched', prefixNote.note, '192.0.2. in 192.0.2.7');
  const exactNote = await digKeep('h.example', ['ns1.operator.example'],
    { recordType: 'NS', resolve: stub(['ns1.operator.example']) });
  check('a term that IS the whole record is not printed twice',
    exactNote.note, 'ns1.operator.example');

  // A flag that is present must carry a value. Both ways of getting this wrong
  // used to pass silently and make the gate answer a different question: an
  // empty --dig left NO terms, so every harvested host was published
  // unconfirmed, and a trailing --dig-type fell back to A while NS was asked
  // for. Driven through the CLI because that is where the parsing lives.
  const cli = (args) => {
    try {
      execFileSync(process.execPath, [path.join(__dirname, 'cbcdn-hosts.js'), ...args],
        { stdio: ['ignore', 'pipe', 'pipe'] });
      return { code: 0, err: '' };
    } catch (e) {
      return { code: e.status, err: String(e.stderr || '') };
    }
  };
  const emptyDig = cli(['--dig', '', os.devNull]);
  check('an empty --dig is refused, not treated as "no gate"', emptyDig.code, 1);
  check('and says which flag', /--dig needs a value/.test(emptyDig.err), true);
  const danglingType = cli(['--dig', '192.0.2.', os.devNull, '--dig-type']);
  check('a trailing --dig-type is refused, not silently A', danglingType.code, 1);
  check('and says which flag', /--dig-type needs a value/.test(danglingType.err), true);

  // An unknown type must not quietly answer a different question.
  const bogus = await digKeep('h.example', ['x'], { recordType: 'MX' });
  check('an unsupported record type is named, not silently treated as A', bogus.keep, true);
  check('and says which types exist', /unsupported dig type MX \(want A\/NS\)/.test(bogus.note), true);

  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})();
