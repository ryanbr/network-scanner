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

const { performPageInteraction, computeInteractionCeilingMs, simulateScrolling } = require('../lib/interaction');

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

  // 4. simulateScrolling's INNER smoothness loop, tested directly. Going through
  //    performPageInteraction cannot exercise it: the impl passes
  //    `smoothness: 1 + random(2)`, so that loop is 1-2 iterations and the outer
  //    per-scroll check already covers it -- an earlier version of this check went
  //    through the cap and passed with the inner guard deleted, i.e. proved
  //    nothing. Direct callers do use more (the JSDoc example is smoothness 8), and
  //    that is where a cancelled scroll would otherwise run to completion.
  {
    let wheels = 0;
    const signal = { cancelled: false };
    const page = {
      isClosed: () => false,
      // Cancel from the third wheel itself rather than on a timer: the outcome is
      // then a property of the code, not of how loaded the machine is. A timer
      // version let ~8 wheels through when the event loop was busy, which is close
      // enough to the threshold to flake.
      mouse: {
        wheel: async () => { wheels++; if (wheels === 3) signal.cancelled = true; },
        move: async () => {}
      },
      evaluate: async () => ({ width: 1280, height: 800 }),
      viewport: () => ({ width: 1280, height: 800 })
    };
    await simulateScrolling(page, { amount: 1, smoothness: 20, signal });
    check('a cancelled scroll abandons the rest of its smoothness loop',
      wheels === 3,
      `${wheels} of 20 wheel call(s) ran (3 = it stopped at the cancellation; 20 = it ran the loop out)`);
  }

  console.log(failures === 0 ? `\nAll ${checks} check(s) passed` : `\n${failures} of ${checks} check(s) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error('harness error:', e); process.exit(2); });
