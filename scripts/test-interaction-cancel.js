#!/usr/bin/env node
/**
 * That a hard-capped interaction actually STOPS, and that the budget the impl
 * honours is the one the caller reserved.
 *
 * performPageInteraction races the interaction against a work-aware ceiling. The
 * race only ever stopped WAITING for the work: nothing cancelled it, so the page
 * kept being clicked and scrolled after nwss had moved on to collecting results
 * — measured with a slow stub page at 3 further page calls 9s past the cap, with
 * the impl's own overrun warning arriving 3s after the caller's capped-at
 * message. Requests from those late clicks land after matchedDomains is
 * snapshotted.
 *
 * Cancellation has to reach the inner loops to mean anything: the impl's
 * cooperative check runs only BETWEEN high-level steps, while the time under
 * contention goes inside humanLikeMouseMove's per-step loop (15+ CDP round
 * trips). The signal is threaded into that loop, simulateScrolling's and
 * performContentClicks'. One further call after cancellation is the floor — the
 * call already in flight cannot be recalled — so that is what is asserted.
 *
 * Separately, the impl used a hardcoded 15000ms budget while the ceiling is
 * work-aware, so heavier configs were silently truncated at 15s however much had
 * been reserved (a realistic_click config reserves 30700ms, and nwss reserves
 * that per URL via INTERACTION_OVERHEAD_MS). That wiring is asserted from the
 * debug line rather than by waiting out a 30s interaction.
 */

const { performPageInteraction, computeInteractionCeilingMs } = require('../lib/interaction');

let failures = 0;
let checks = 0;
const check = (name, ok, detail) => {
  checks++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
};
const slow = (ms) => new Promise(r => setTimeout(r, ms));
const stubPage = (onCall, url) => ({
  isClosed: () => false,
  mouse: { move: onCall, down: onCall, up: onCall, click: onCall, wheel: onCall },
  evaluate: async () => { await onCall(); return { width: 1280, height: 800 }; },
  viewport: () => ({ width: 1280, height: 800 }),
  $$: async () => [], $: async () => null, frames: () => [],
  waitForSelector: async () => null, url: () => url
});

(async () => {
  const ceilDefault = computeInteractionCeilingMs({});
  const ceilRealistic = computeInteractionCeilingMs({ includeElementClicks: true, realistic: true });
  check('the ceiling scales with the work asked for',
    ceilDefault === 15000 && ceilRealistic > ceilDefault,
    `default ${ceilDefault}ms, realistic-clicks ${ceilRealistic}ms`);

  // 2. the impl must receive the work-aware budget, not a flat 15000
  const logs = [];
  const realLog = console.log;
  console.log = (...a) => logs.push(a.join(' ').replace(/\x1b\[[0-9;]*m/g, ''));
  await performPageInteraction(stubPage(async () => {}, 'http://budget.test/'),
    'http://budget.test/', { includeElementClicks: true, realistic: true }, true);
  console.log = realLog;
  const got = Number((logs.join('\n').match(/Budget (\d+)ms/) || [])[1]);
  check('the impl receives the work-aware budget, not a flat 15000',
    got > 15000 && got === ceilRealistic - 750,
    `logged ${got || 'nothing'}ms for a ${ceilRealistic}ms ceiling`);

  // 3. the cap stops the work, not just the waiting
  let callsAfterReturn = 0, returned = false;
  const onCall = async () => { if (returned) callsAfterReturn++; await slow(3000); };
  const t0 = Date.now();
  await performPageInteraction(stubPage(onCall, 'http://stub.test/'), 'http://stub.test/', { intensity: 'medium' }, false);
  returned = true;
  const returnedAt = Date.now() - t0;
  check('the cap is enforced', returnedAt >= ceilDefault && returnedAt < ceilDefault + 2000,
    `returned at ${returnedAt}ms against a ${ceilDefault}ms ceiling`);

  await slow(9000);
  check('the capped work stops instead of running on', callsAfterReturn <= 1,
    `${callsAfterReturn} page call(s) after the cap (1 = the one already in flight, which cannot be recalled)`);

  console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error('harness error:', e); process.exit(2); });
