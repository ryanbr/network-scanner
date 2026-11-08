#!/usr/bin/env node
// === Referrer module tests ===
//
// Pins lib/referrer.js: referrer generation, the referrer_disable matcher and
// both config validators. <1s, no browser, no network.
//
// Every check here is a bug that was found by review on 2026-11-09, in a module
// that had no test file at all while being read by two callers (nwss.js and
// lib/curl.js). The three fixes all share one shape -- a setting that reads as
// if it works, does nothing, and says nothing:
//
//   1. a referrer_disable entry with a path but no scheme was INERT, so the
//      referrer was still sent for a url the operator had listed. The worst of
//      the three: the failure direction is "privacy control silently off".
//   2. `context` could never take effect in `mixed` mode, because it was copied
//      only alongside search_terms -- the one case where it is ignored.
//   3. `mixed` forwards search_terms to random_search but had no validation
//      case, so a non-array was accepted at load and dropped at runtime.
//
// The negative checks matter as much as the positive ones: fix 1 widens what
// counts as a disable match, and widening a privacy control is exactly where an
// over-broad match would hide. 'notexample.com' must NOT match 'example.com'.

const { getReferrerForUrl, validateReferrerConfig, validateReferrerDisable } = require('../lib/referrer');

let passed = 0, failed = 0;
function check(name, cond, detail) {
  if (cond) { console.log(`  ✓ ${name}`); passed++; }
  else { console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`); failed++; }
}
function eq(name, actual, expected) {
  check(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

// A fixed, valid referrer so a disable result is unambiguous: '' means disabled,
// anything else means the referrer survived.
const REF = 'https://ref.example/';
const disabled = (target, list) => getReferrerForUrl(target, REF, list) === '';

// Terms that appear ONLY in TECH_TERMS, never in DEFAULT_SEARCH_TERMS. 'review'
// is excluded on purpose -- DEFAULT has the plural 'reviews', and a substring
// test would pass on it and make this check meaningless.
const TECH_ONLY = ['software', 'app', 'comparison', 'features', 'specs', 'performance', 'benchmark'];
const ECOM_ONLY = ['buy online', 'shopping', 'sale', 'coupon', 'free shipping', 'best price', 'outlet', 'marketplace'];

// Sampling, because mode/term/engine selection is random. 4000 iterations makes
// a missed term collection a certainty rather than a coin flip: the chance of
// drawing zero of 11 tech terms in 4000 tries when the collection IS selected is
// nil, and 'mixed' still picks random_search about a third of the time.
function sampleTerms(cfg, n = 4000) {
  const terms = new Set();
  for (let i = 0; i < n; i++) {
    const url = getReferrerForUrl('https://target.example/', cfg, []);
    const m = /[?&](?:q|p|wd|text|query)=(.+)$/.exec(url);
    if (m) terms.add(decodeURIComponent(m[1]));
  }
  return terms;
}
const seenAny = (set, list) => list.some(t => set.has(t));

(function main() {
  console.log('\n=== referrer_disable: a listed url must not send a referrer ===');

  eq('a bare hostname disables', disabled('https://example.com/x', ['example.com']), true);
  eq('a full url disables', disabled('https://example.com/x', ['https://example.com/private']), true);
  // FIX 1. Measured before the fix: this returned a referrer, with no warning
  // from validateReferrerDisable either (the string contains a '.').
  eq('a scheme-less pattern WITH A PATH disables',
    disabled('https://example.com/private', ['example.com/private']), true);
  eq('   ...and for any path on that host, matching how a full url already behaved',
    disabled('https://example.com/other', ['example.com/private']), true);
  eq('a subdomain of a path-carrying pattern disables',
    disabled('https://cdn.example.com/a', ['example.com/private']), true);

  console.log('\n--- and must NOT over-match (fix 1 widens this matcher) ---');
  eq('a different host does not match', disabled('https://other.example/x', ['example.com']), false);
  // The suffix guard: endsWith('.' + p), not endsWith(p). Without the dot,
  // 'notexample.com' matches 'example.com' and an unrelated site loses its
  // referrer -- a silent behaviour change on an unrelated target.
  eq('a host merely ENDING in the pattern does not match',
    disabled('https://notexample.com/x', ['example.com']), false);
  eq('   ...nor with a path-carrying pattern',
    disabled('https://notexample.com/x', ['example.com/private']), false);
  eq('a pattern that is a longer host does not match a shorter target',
    disabled('https://example.com/x', ['cdn.example.com']), false);
  eq('an empty disable list leaves the referrer alone', disabled('https://example.com/x', []), false);
  eq('a non-string entry is skipped, not thrown on',
    disabled('https://example.com/x', [null, 42, {}, 'example.com']), true);
  eq('case differences in the host still match',
    disabled('https://EXAMPLE.com/x', ['example.com']), true);

  console.log('\n=== mixed mode must honour `context` (fix 2) ===');
  // Before the fix: 7 tech-only terms via random_search, 0 via mixed.
  const directTech = sampleTerms({ mode: 'random_search', context: 'tech' });
  const mixedTech = sampleTerms({ mode: 'mixed', context: 'tech' });
  check('random_search + context=tech reaches TECH_TERMS', seenAny(directTech, TECH_ONLY));
  check('mixed + context=tech reaches TECH_TERMS too', seenAny(mixedTech, TECH_ONLY),
    'no tech-only term in 4000 samples -- context is being dropped');
  const mixedEcom = sampleTerms({ mode: 'mixed', context: 'ecommerce' });
  check('mixed + context=ecommerce reaches ECOMMERCE_TERMS', seenAny(mixedEcom, ECOM_ONLY));

  // The other half of fix 2: search_terms must still win over context, since
  // generateSearchTerm returns a custom term and never reads context. If the
  // fix had copied context in a way that changed precedence, this fails.
  const bothSet = sampleTerms({ mode: 'mixed', context: 'tech', search_terms: ['zzsentinel'] });
  check('explicit search_terms still win over context in mixed',
    bothSet.has('zzsentinel') && !seenAny(bothSet, TECH_ONLY));
  const noCtx = sampleTerms({ mode: 'mixed' });
  check('mixed with no context still produces terms', noCtx.size > 0);

  console.log('\n=== validation: both modes that read search_terms validate it (fix 3) ===');
  for (const mode of ['random_search', 'mixed']) {
    const bad = validateReferrerConfig({ mode, search_terms: 'reviews' });
    eq(`${mode}: a non-array search_terms is a config ERROR`, bad.isValid, false);
    check(`${mode}: and the message names the key`,
      bad.errors.some(e => /search_terms must be an array/.test(e)), JSON.stringify(bad.errors));
    const good = validateReferrerConfig({ mode, search_terms: ['deals', 'price'] });
    eq(`${mode}: a valid array passes`, good.isValid, true);
    const nonStr = validateReferrerConfig({ mode, search_terms: ['ok', 7] });
    eq(`${mode}: a non-string ITEM is an error`, nonStr.isValid, false);
    const empty = validateReferrerConfig({ mode, search_terms: [] });
    check(`${mode}: an empty array warns but stays valid`, empty.isValid && empty.warnings.length > 0);
    const absent = validateReferrerConfig({ mode });
    eq(`${mode}: omitting search_terms is valid`, absent.isValid, true);
  }

  console.log('\n=== validation: the rest of the surface must not have moved ===');
  eq('a valid string config passes', validateReferrerConfig('https://ok.example/').isValid, true);
  eq('a non-http string is rejected', validateReferrerConfig('ftp://x.example/').isValid, false);
  eq('an unknown mode is rejected', validateReferrerConfig({ mode: 'telepathy' }).isValid, false);
  eq('an object with no mode is rejected', validateReferrerConfig({}).isValid, false);
  eq('custom with no url is rejected', validateReferrerConfig({ mode: 'custom' }).isValid, false);
  eq('custom with a bad url is rejected',
    validateReferrerConfig({ mode: 'custom', url: 'notaurl' }).isValid, false);
  eq('custom with a good url passes',
    validateReferrerConfig({ mode: 'custom', url: 'https://ok.example/' }).isValid, true);
  eq('a missing config is rejected', validateReferrerConfig(undefined).isValid, false);
  // Every item is validated, not just the first and last -- the array validator
  // used to spot-check the ends when length > 10.
  const midBad = ['https://a.example/', 'https://b.example/', 'nope', 'https://d.example/',
    'https://e.example/', 'https://f.example/', 'https://g.example/', 'https://h.example/',
    'https://i.example/', 'https://j.example/', 'https://k.example/', 'https://l.example/'];
  const midRes = validateReferrerConfig(midBad);
  check('a bad item in the MIDDLE of a long array is caught',
    midRes.isValid === false && midRes.errors.some(e => /item 2/.test(e)), JSON.stringify(midRes.errors));

  eq('referrer_disable: a non-array is rejected', validateReferrerDisable('example.com').isValid, false);
  eq('referrer_disable: absent is fine (optional key)', validateReferrerDisable(undefined).isValid, true);
  eq('referrer_disable: a non-string item is an error',
    validateReferrerDisable(['ok.example', 7]).isValid, false);

  console.log('\n=== isValidUrl: a scheme is not a url (fix 4) ===');
  // A prefix test cannot see whether there is a HOST, so 'https://' passed
  // validation and then became a Referer header with no origin in it.
  eq('"https://" with no host is rejected', validateReferrerConfig('https://').isValid, false);
  eq('"http://" with no host is rejected', validateReferrerConfig('http://').isValid, false);
  eq('a space in the authority is rejected',
    validateReferrerConfig('https://ex ample.com/').isValid, false);
  eq('a real url still passes', validateReferrerConfig('https://ok.example/').isValid, true);
  eq('a single-label host still passes', validateReferrerConfig('http://a/').isValid, true);

  // STRICTLY a tightening: the scheme prefix test is kept, so nothing that was
  // rejected before is accepted now. Parsing alone would have widened these two
  // -- schemes are case-insensitive to the parser, and the WHATWG parser is
  // lenient about the slashes for special schemes. Pinned so a later "simplify
  // this to new URL().protocol" cannot quietly widen what a config may hold.
  eq('an uppercase scheme stays rejected, as before',
    validateReferrerConfig('HTTPS://ok.example/').isValid, false);
  eq('a slash-less scheme stays rejected, as before',
    validateReferrerConfig('https:ok.example').isValid, false);
  eq('a non-http scheme stays rejected', validateReferrerConfig('ftp://x.example/').isValid, false);

  // ...and it must reach every consumer of isValidUrl, not just the string case.
  eq('a hostless url inside an ARRAY config is rejected',
    validateReferrerConfig(['https://ok.example/', 'https://']).isValid, false);
  eq('a hostless url in custom mode is rejected',
    validateReferrerConfig({ mode: 'custom', url: 'https://' }).isValid, false);
  eq('generation returns empty for a hostless string config',
    getReferrerForUrl('https://t.example/', 'https://', []), '');
  eq('generation returns empty for a hostless custom url',
    getReferrerForUrl('https://t.example/', { mode: 'custom', url: 'https://' }, []), '');

  console.log('\n=== generation: the modes themselves ===');
  eq('direct_navigation yields no referrer',
    getReferrerForUrl('https://t.example/', { mode: 'direct_navigation' }, []), '');
  eq('an unknown mode yields no referrer',
    getReferrerForUrl('https://t.example/', { mode: 'telepathy' }, []), '');
  eq('custom returns the url', getReferrerForUrl('https://t.example/',
    { mode: 'custom', url: 'https://ok.example/' }, []), 'https://ok.example/');
  eq('custom with a bad url returns empty',
    getReferrerForUrl('https://t.example/', { mode: 'custom', url: 'nope' }, []), '');
  eq('an empty array config returns empty', getReferrerForUrl('https://t.example/', [], []), '');
  eq('a string config is passed through',
    getReferrerForUrl('https://t.example/', 'https://ok.example/', []), 'https://ok.example/');
  const searchUrl = getReferrerForUrl('https://t.example/', { mode: 'random_search' }, []);
  check('random_search builds a search url with an encoded term', /^https:\/\/\S+[?&]\w+=\S+$/.test(searchUrl), searchUrl);
  check('   ...and the term is percent-encoded, not raw',
    !/ /.test(searchUrl), searchUrl);
  const social = getReferrerForUrl('https://t.example/', { mode: 'social_media' }, []);
  check('social_media returns an http(s) url', /^https?:\/\//.test(social), social);
  const news = getReferrerForUrl('https://t.example/', { mode: 'news_sites' }, []);
  check('news_sites returns an http(s) url', /^https?:\/\//.test(news), news);
  // disable wins over generation, whatever the mode would have produced
  eq('a disabled target overrides a valid generating config',
    getReferrerForUrl('https://example.com/x', { mode: 'social_media' }, ['example.com']), '');

  console.log(`\n${failed === 0 ? '✅' : '❌'} ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})();
