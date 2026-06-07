/**
 * Enhanced Mouse Interaction and Page Simulation Module
 * ====================================================
 * 
 * This module provides sophisticated, human-like interaction simulation for web scraping
 * and automation tasks. It replaces basic mouse movements with realistic behavior patterns
 * that are harder to detect by anti-bot systems.
 * 
 * KEY FEATURES:
 * - Human-like mouse movements with curves and jitter
 * - Realistic scrolling simulation with smooth increments
 * - Safe element interaction (avoids destructive actions)
 * - Typing simulation with mistakes and variable timing
 * - Configurable intensity levels (low/medium/high)
 * - Site-specific optimization based on URL patterns
 * 
 * USAGE EXAMPLES:
 * 
 * Basic interaction:
 *   await performPageInteraction(page, url, {}, debug);
 * 
 * Custom configuration:
 *   const config = createInteractionConfig(url, siteConfig);
 *   await performPageInteraction(page, url, config, debug);
 * 
 * Manual mouse movement:
 *   await humanLikeMouseMove(page, 0, 0, 500, 300, {
 *     steps: 20, curve: 0.5, jitter: 3
 *   });
 * 
 * CONFIGURATION OPTIONS:
 * - intensity: 'low' | 'medium' | 'high' - Overall interaction intensity
 * - duration: number - Total interaction time in milliseconds
 * - mouseMovements: number - Number of mouse movements to perform
 * - includeScrolling: boolean - Enable scrolling simulation
 * - includeElementClicks: boolean - Enable safe element clicking
 *
 * ANTI-DETECTION FEATURES:
 * - Variable timing between actions
 * - Curved mouse movements (not straight lines)
 * - Random jitter and pauses
 * - Site-specific behavior patterns
 * - Realistic scrolling with momentum
 * - Human-like typing with occasional mistakes
 * 
 * SAFETY FEATURES:
 * - Avoids clicking destructive elements (delete, buy, submit)
 * - Bounded coordinate generation (stays within viewport)
 * - Graceful error handling (failures don't break main scan)
 * - Optional element interaction (disabled by default)
 * 
 * @version 1.0
 * @requires puppeteer
 */
 
const { formatLogMessage, messageColors } = require('./colorize');

// Precomputed colored '[interaction]' subsystem prefix. formatLogMessage only
// colors the [severity] tag; this constant colors the subsystem prefix so
// '[debug] [interaction] X' has both tags visually distinct, matching how
// every other module in the codebase emits its subsystem logs.
const INTERACTION_TAG = messageColors.processing('[interaction]');

// Fast setTimeout helper for Puppeteer 22.x compatibility
// Uses standard Promise constructor for better performance than node:timers/promises
function fastTimeout(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Human-timed click — page.mouse.click() fires mousedown+mouseup ~10-30ms
 * apart, which many ad-network popunder loaders (AdsCore/PropellerAds
 * family) specifically filter as a bot signal: real users hold the
 * button 50-150ms. This helper splits the click into explicit
 * mousedown / hold / mouseup with realistic hold timing, plus optional
 * hover-before-click pause and small click-offset jitter so clicks
 * don't land pixel-perfect at the same (x,y) every time.
 *
 * Drop-in replacement for `page.mouse.click(x, y)` at popunder-trigger
 * sites; bounded per-call cost is ~300-700ms (hover pause + hold + jitter)
 * vs ~30ms for plain .click().
 *
 * @param {object} page - Puppeteer page
 * @param {number} x - target X
 * @param {number} y - target Y
 * @param {object} options
 * @param {number} options.offsetRange - ± px jitter from (x,y); default 5
 * @param {number} options.hoverMin - min hover pause ms; default 150
 * @param {number} options.hoverMax - max hover pause ms; default 450
 * @param {number} options.holdMin - min mouse-down hold ms; default 50
 * @param {number} options.holdMax - max mouse-down hold ms; default 150
 * @param {boolean} options.realistic - emit hold-tremor + mouseup drift;
 *   default false. Opt-in for sites that score mouse-click realism
 *   (DataDome, Akamai BM, PerimeterX). Adds ~0ms latency (events fit
 *   inside the existing hold) but generates 1–3 extra mousemove events
 *   between mousedown and mouseup at ±1px tremor, plus a final ±1.5px
 *   drift before mouseup so mousedown.x !== mouseup.x. Pure event-stream
 *   change — no behavioral difference for the click itself.
 */
async function humanClick(page, x, y, options = {}) {
  const {
    offsetRange = 5,
    hoverMin = 150, hoverMax = 450,
    holdMin = 50,   holdMax = 150,
    forceDebug = false,
    realistic = false
  } = options;
  // ±offsetRange-px jitter so we don't click pixel-perfect (x,y) every
  // time -- real users have spatial scatter even when aiming for the
  // 'same' visible button.
  const jx = x + (Math.random() - 0.5) * 2 * offsetRange;
  const jy = y + (Math.random() - 0.5) * 2 * offsetRange;
  try {
    // Hover/move first -- many bot detectors check that mouse position
    // matches the click point at mousedown time (browser fires mousemove
    // before mousedown for real cursor hardware).
    await page.mouse.move(jx, jy);
    await fastTimeout(hoverMin + Math.random() * (hoverMax - hoverMin));
    await page.mouse.down();

    if (realistic) {
      // Split the hold into (tremorCount + 1) chunks; emit a ±1px micromove
      // between each chunk so the page sees mousemove events during the
      // press window (real human hand tremor). Then drift ±MOUSEUP_DRIFT_PX
      // before firing mouseup so mousedown.x/y !== mouseup.x/y.
      const holdMs = holdMin + Math.random() * (holdMax - holdMin);
      const tremorCount = CONTENT_CLICK.TREMOR_COUNT_MIN +
        Math.floor(Math.random() * (CONTENT_CLICK.TREMOR_COUNT_MAX - CONTENT_CLICK.TREMOR_COUNT_MIN + 1));
      const chunkMs = holdMs / (tremorCount + 1);
      for (let i = 0; i < tremorCount; i++) {
        await fastTimeout(chunkMs);
        const tjx = jx + (Math.random() - 0.5) * 2 * CONTENT_CLICK.TREMOR_RANGE_PX;
        const tjy = jy + (Math.random() - 0.5) * 2 * CONTENT_CLICK.TREMOR_RANGE_PX;
        await page.mouse.move(tjx, tjy);
      }
      await fastTimeout(chunkMs);
      // Final drift before mouseup. Move first (mouseup fires at current
      // position) so the up event lands at slightly different coords than
      // the down event — real humans almost always drift during the hold.
      const ux = jx + (Math.random() - 0.5) * 2 * CONTENT_CLICK.MOUSEUP_DRIFT_PX;
      const uy = jy + (Math.random() - 0.5) * 2 * CONTENT_CLICK.MOUSEUP_DRIFT_PX;
      await page.mouse.move(ux, uy);
      await page.mouse.up();
    } else {
      await fastTimeout(holdMin + Math.random() * (holdMax - holdMin));
      await page.mouse.up();
    }
  } catch (err) {
    // Page closed / target detached mid-click is the expected non-fatal
    // path; everything else is unusual enough to surface in debug mode so
    // a site silently failing 100% of clicks (CSP, broken input pipeline,
    // CDP session collapse) is at least visible without --headful.
    if (forceDebug && !/closed|detached|Target|Session closed|Protocol error/i.test(err.message || '')) {
      try {
        console.log(formatLogMessage('debug', `${INTERACTION_TAG} humanClick failed at (${jx.toFixed(0)}, ${jy.toFixed(0)}): ${err.message}`));
      } catch (_) { /* logging itself shouldn't throw, but belt-and-braces */ }
    }
  }
}

// === VIEWPORT AND COORDINATE CONSTANTS ===
// These control the default viewport assumptions and coordinate generation
const DEFAULT_VIEWPORT = {
  WIDTH: 1200,   // Default viewport width if not detected
  HEIGHT: 800    // Default viewport height if not detected
};

const COORDINATE_MARGINS = {
  DEFAULT_X: 50,           // Minimum distance from left/right edges
  DEFAULT_Y: 50,           // Minimum distance from top/bottom edges
  EDGE_ZONE_SIZE: 200,     // Size of "edge" zones for preferEdges mode
  CENTER_AVOID_RATIO: 0.25 // Percentage of viewport to avoid in center (0.25 = 25%)
};

// === MOUSE MOVEMENT CONSTANTS ===
// Values reflect what the code ACTUALLY uses after the perf scale-back —
// the original 5-30 step plan was cut to 2-8 to keep per-URL interaction
// under ~300ms. Curve/jitter math is mostly cosmetic at these step counts;
// the scanner doesn't need elaborate anti-bot curves to trigger onclick/
// scroll handlers, so this is the right size.
const MOUSE_MOVEMENT = {
  MIN_STEPS: 2,              // Minimum steps for any movement
  DEFAULT_STEPS: 6,          // Default steps when distance-derived
  MAX_STEPS: 8,              // Hard cap to keep movements under ~300ms
  MIN_DELAY: 5,              // Minimum milliseconds between movement steps
  MAX_DELAY: 25,             // Maximum milliseconds between movement steps
  MAX_TOTAL_MS: 300,         // Emergency cap on total movement time
  DEFAULT_CURVE: 0.2,        // Default curve intensity (mostly cosmetic at low step counts)
  DEFAULT_JITTER: 2,         // Default random jitter in pixels
  DISTANCE_STEP_RATIO: 200,  // Pixels per step when auto-calculating step count
  CURVE_INTENSITY_RATIO: 0.01 // Multiplier for curve calculation
};

// === SCROLLING CONSTANTS ===
// Control scrolling behavior - adjust for different site types
const SCROLLING = {
  DEFAULT_AMOUNT: 3,           // Default number of scroll actions
  DEFAULT_SMOOTHNESS: 5,       // Default smoothness (higher = more increments)
  SCROLL_DELTA: 200,           // Pixels to scroll per action
  PAUSE_BETWEEN: 50,          // Milliseconds between scroll actions
  SMOOTH_INCREMENT_DELAY: 20   // Milliseconds between smooth scroll increments
};

// === INTERACTION TIMING CONSTANTS ===
// All timing values in milliseconds - adjust for faster/slower interaction
const TIMING = {
  CLICK_PAUSE_MIN: 100,           // Minimum pause before clicking
  CLICK_PAUSE_MAX: 200,           // Maximum pause before clicking
  POST_CLICK_MIN: 300,            // Minimum pause after clicking
  POST_CLICK_MAX: 500,            // Maximum pause after clicking
  DEFAULT_INTERACTION_DURATION: 2000 // Default total interaction time
  // Note: TYPING_*, MISTAKE_PAUSE_*, BACKSPACE_DELAY_* removed along with
  // simulateTyping() — they were only consumed by that dead-code function.
};

// === ELEMENT INTERACTION CONSTANTS ===
// Safety and behavior settings for element interaction
const ELEMENT_INTERACTION = {
  MAX_ATTEMPTS: 3,           // Maximum attempts to find clickable elements
  TIMEOUT: 2000,             // Timeout for element operations
  TEXT_PREVIEW_LENGTH: 50    // Characters to capture for element text preview
  // Note: MISTAKE_RATE removed with simulateTyping() — it was that function's
  // only consumer.
};

// === CONTENT CLICK CONSTANTS ===
// For triggering document-level onclick handlers (e.g., Monetag onclick_static)
// These clicks target the page content area, not specific UI elements
// NOTE: No preDelay needed — mouse movements + scrolling already provide ~1s
// of activity before clicks fire, which is enough for async ad script registration
const CONTENT_CLICK = {
  CLICK_COUNT: 3,            // Three attempts (primary + 2 backup; ad SDKs sometimes suppress first OR second click as warmup before firing)
  CLICK_COUNT_MAX: 20,       // Hard cap when overridden via siteConfig.interact_click_count — a typo of 500 shouldn't run for minutes
  INTER_CLICK_MIN: 300,      // Minimum ms between clicks (above Monetag 250ms cooldown)
  INTER_CLICK_MAX: 500,      // Maximum ms between clicks
  // PRE_CLICK_DELAY: most ad scripts register document-level listeners
  // within 50–100ms of DOMContentLoaded. The prior mouse/scroll activity
  // (~500ms+) gives them plenty of head start before this fires, so the
  // 300ms buffer here was mostly defensive. Reduced to 100ms.
  PRE_CLICK_DELAY: 100,
  VIEWPORT_INSET: 0.2,       // Avoid outer 20% of viewport (menus, overlays)
  MOUSE_APPROACH_STEPS: 3,   // Minimal steps — just enough for non-instant movement
  // Realistic-mode opt-in (siteConfig.realistic_click). Higher step count
  // raises the mousemove event rate to ~80–125Hz (real mouse minimum is
  // 125Hz USB default) so per-event movementX/Y deltas land in the 5–30px
  // range a real cursor produces — fixes the strongest movement tell.
  // Cost: +~80–120ms per click over the approach. Off by default.
  MOUSE_APPROACH_STEPS_REALISTIC: 15,
  // Realistic-mode hold tremor: 1–3 ±1px micromoves spread across the
  // mousedown→mouseup hold to defeat the "zero events during hold" tell.
  TREMOR_COUNT_MIN: 1,
  TREMOR_COUNT_MAX: 3,
  TREMOR_RANGE_PX: 1,
  // Realistic-mode mouseup drift: real human clicks drift 0–2px between
  // mousedown and mouseup, especially with longer holds. Without this,
  // mousedown.x === mouseup.x is a robotic signal.
  MOUSEUP_DRIFT_PX: 1.5
};

// === INTENSITY SETTINGS ===
// Pre-configured intensity levels - modify these to change overall behavior
const INTENSITY_SETTINGS = {
  LOW: {
    movements: 2,        // Fewer movements for minimal interaction
    scrolls: 1,          // Minimal scrolling
    pauseMultiplier: 1.5 // 50% longer pauses
  },
  MEDIUM: {
    movements: 3,        // Balanced movement count
    scrolls: 2,          // Moderate scrolling
    pauseMultiplier: 1.0 // Normal timing
  },
  HIGH: {
    movements: 5,        // More movements for thorough interaction
    scrolls: 3,          // More scrolling activity
    pauseMultiplier: 0.7 // 30% shorter pauses for faster interaction
  }
};

// === SITE-SPECIFIC DURATION CONSTANTS ===
// Different interaction durations based on site type
const SITE_DURATIONS = {
  NEWS_BLOG: 3000,      // Longer duration for content-heavy sites
  SOCIAL_FORUM: 2500,   // Medium duration for social platforms
  DEFAULT: 2000         // Standard duration for most sites
};

// === PROBABILITY CONSTANTS ===
// Control randomness and behavior patterns
const PROBABILITIES = {
  // PAUSE_CHANCE: probability of a 25–75ms idle pause between mouse motions.
  // Bot detectors mainly look at timing variance WITHIN a single mouse trail
  // (the per-step delays in humanLikeMouseMove already cover that), so the
  // inter-movement pause is mostly cosmetic. Lowered from 0.3 to 0.1 to cut
  // ~30ms average per interaction while keeping enough variance to avoid
  // perfectly metronomic action spacing.
  PAUSE_CHANCE: 0.1,
  SCROLL_DOWN_BIAS: 0.7,    // 70% chance to scroll down (vs up)
  EDGE_PREFERENCE: {        // Probabilities for edge selection in preferEdges mode
    LEFT: 0.25,             // 0-25% = left edge
    RIGHT: 0.5,             // 25-50% = right edge  
    TOP: 0.75,              // 50-75% = top edge
    BOTTOM: 1.0             // 75-100% = bottom edge
  }
};

/**
 * Returns viewport dimensions, with a safe fallback to DEFAULT_VIEWPORT if
 * the page hasn't been given a viewport or the query throws. No caching —
 * page.viewport() is an in-memory getter, not a CDP round-trip, so there's
 * nothing to save by caching it.
 *
 * @param {import('puppeteer').Page} page - Puppeteer page object
 * @returns {Promise<object>} Viewport dimensions {width, height}
 */
async function getViewport(page) {
  try {
    return (await page.viewport()) || { width: DEFAULT_VIEWPORT.WIDTH, height: DEFAULT_VIEWPORT.HEIGHT };
  } catch (_) {
    return { width: DEFAULT_VIEWPORT.WIDTH, height: DEFAULT_VIEWPORT.HEIGHT };
  }
}

/**
 * Generates random coordinates within viewport bounds with intelligent placement
 * 
 * COORDINATE GENERATION MODES:
 * - Normal: Random coordinates within margins
 * - preferEdges: Bias towards viewport edges (more realistic)
 * - avoidCenter: Exclude center area (useful for ads/popups)
 * 
 * DEVELOPER NOTES:
 * - Always respects marginX/marginY to prevent edge clipping
 * - Edge zones are 200px from each edge by default
 * - Center avoidance creates a circular exclusion zone
 * - Returns {x, y} object with integer coordinates
 * 
 * @param {number} maxX - Maximum X coordinate (viewport width)
 * @param {number} maxY - Maximum Y coordinate (viewport height)
 * @param {object} options - Configuration options
 * @param {number} options.marginX - Minimum distance from left/right edges
 * @param {number} options.marginY - Minimum distance from top/bottom edges
 * @param {boolean} options.avoidCenter - Exclude center area (25% of viewport)
 * @param {boolean} options.preferEdges - Bias coordinates towards edges
 * @returns {object} Generated coordinates {x, y}
 * 
 * @example
 * // Basic random coordinates
 * const pos = generateRandomCoordinates(1920, 1080);
 * 
 * // Prefer edges for more natural movement
 * const edgePos = generateRandomCoordinates(1920, 1080, { preferEdges: true });
 * 
 * // Avoid center area (useful for avoiding ads)
 * const safePos = generateRandomCoordinates(1920, 1080, { avoidCenter: true });
 */
function generateRandomCoordinates(maxX = DEFAULT_VIEWPORT.WIDTH, maxY = DEFAULT_VIEWPORT.HEIGHT, options = {}) {
  const {
    marginX = COORDINATE_MARGINS.DEFAULT_X,
    marginY = COORDINATE_MARGINS.DEFAULT_Y,
    avoidCenter = false,
    preferEdges = false
  } = options;

  let x, y;

  if (preferEdges) {
    // Prefer coordinates near edges for more realistic behavior
    const edge = Math.random();
    if (edge < PROBABILITIES.EDGE_PREFERENCE.LEFT) {
      // Left edge
      x = Math.floor(Math.random() * COORDINATE_MARGINS.EDGE_ZONE_SIZE) + marginX;
      y = Math.floor(Math.random() * (maxY - 2 * marginY)) + marginY;
    } else if (edge < PROBABILITIES.EDGE_PREFERENCE.RIGHT) {
      // Right edge
      x = Math.floor(Math.random() * COORDINATE_MARGINS.EDGE_ZONE_SIZE) + (maxX - COORDINATE_MARGINS.EDGE_ZONE_SIZE - marginX);
      y = Math.floor(Math.random() * (maxY - 2 * marginY)) + marginY;
    } else if (edge < PROBABILITIES.EDGE_PREFERENCE.TOP) {
      // Top edge
      x = Math.floor(Math.random() * (maxX - 2 * marginX)) + marginX;
      y = Math.floor(Math.random() * COORDINATE_MARGINS.EDGE_ZONE_SIZE) + marginY;
    } else {
      // Bottom edge
      x = Math.floor(Math.random() * (maxX - 2 * marginX)) + marginX;
      y = Math.floor(Math.random() * COORDINATE_MARGINS.EDGE_ZONE_SIZE) + (maxY - COORDINATE_MARGINS.EDGE_ZONE_SIZE - marginY);
    }
  } else if (avoidCenter) {
    // Avoid center area
    const centerX = maxX / 2;
    const centerY = maxY / 2;
    const avoidRadius = Math.min(maxX, maxY) * COORDINATE_MARGINS.CENTER_AVOID_RATIO;

    // Iteration cap: for sensible viewports a valid point is found in ~1
    // try, but a pathologically small viewport could in principle have
    // every candidate inside avoidRadius. After 50 attempts give up and
    // return the last sample — a near-center point is preferable to an
    // infinite loop.
    let attempts = 0;
    do {
      x = Math.floor(Math.random() * (maxX - 2 * marginX)) + marginX;
      y = Math.floor(Math.random() * (maxY - 2 * marginY)) + marginY;
    } while (
      Math.sqrt((x - centerX) ** 2 + (y - centerY) ** 2) < avoidRadius &&
      ++attempts < 50
    );
  } else {
    // Standard random coordinates
    x = Math.floor(Math.random() * (maxX - 2 * marginX)) + marginX;
    y = Math.floor(Math.random() * (maxY - 2 * marginY)) + marginY;
  }

  return { x, y };
}

/**
 * Simulates human-like mouse movement with realistic timing and curves
 * 
 * MOVEMENT CHARACTERISTICS:
 * - Uses easing curves (slow start, fast middle, slow end)
 * - Adds slight curve to path (not straight lines)
 * - Random jitter for micro-movements
 * - Variable timing between steps
 * - Automatically calculates optimal step count based on distance
 * 
 * PERFORMANCE NOTES:
 * - Longer distances automatically use more steps
 * - Very short movements use minimum steps to prevent slowness
 * - Maximum steps cap prevents excessive delays
 * 
 * ANTI-DETECTION FEATURES:
 * - No perfectly straight lines
 * - Realistic acceleration/deceleration
 * - Micro-movements simulate hand tremor
 * - Variable timing prevents pattern detection
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page object
 * @param {number} fromX - Starting X coordinate
 * @param {number} fromY - Starting Y coordinate  
 * @param {number} toX - Target X coordinate
 * @param {number} toY - Target Y coordinate
 * @param {object} options - Movement configuration
 * @param {number} options.steps - Number of movement steps (auto-calculated if not specified)
 * @param {number} options.minDelay - Minimum delay between steps in ms
 * @param {number} options.maxDelay - Maximum delay between steps in ms
 * @param {number} options.curve - Curve intensity (0.0 = straight, 1.0 = very curved)
 * @param {number} options.jitter - Random jitter amount in pixels
 * 
 * @example
 * // Basic movement
 * await humanLikeMouseMove(page, 0, 0, 500, 300);
 * 
 * // Slow, very curved movement
 * await humanLikeMouseMove(page, 0, 0, 500, 300, {
 *   steps: 25, curve: 0.8, minDelay: 20, maxDelay: 50
 * });
 * 
 * // Fast, minimal curve movement
 * await humanLikeMouseMove(page, 0, 0, 500, 300, {
 *   steps: 8, curve: 0.1, minDelay: 2, maxDelay: 8
 * });
 */
async function humanLikeMouseMove(page, fromX, fromY, toX, toY, options = {}) {
  const {
    steps = MOUSE_MOVEMENT.DEFAULT_STEPS,
    minDelay = MOUSE_MOVEMENT.MIN_DELAY,
    maxDelay = MOUSE_MOVEMENT.MAX_DELAY,
    curve = MOUSE_MOVEMENT.DEFAULT_CURVE,
    jitter = MOUSE_MOVEMENT.DEFAULT_JITTER,
    realistic = false  // bypass MAX_STEPS / MAX_TOTAL_MS caps for high-cadence approach
  } = options;

  const distance = Math.sqrt((toX - fromX) ** 2 + (toY - fromY) ** 2);

  // Step count: caller-provided value capped at MAX_STEPS, otherwise derived
  // from distance and clamped to [MIN_STEPS, DEFAULT_STEPS]. Realistic mode
  // skips the MAX_STEPS cap so callers can push 12–15 steps to match real
  // mouse hardware event rates (~125Hz vs the default's ~30–60Hz).
  let actualSteps;
  if (options.steps) {
    actualSteps = realistic ? options.steps : Math.min(options.steps, MOUSE_MOVEMENT.MAX_STEPS);
  } else {
    const calculatedSteps = Math.floor(distance / MOUSE_MOVEMENT.DISTANCE_STEP_RATIO);
    actualSteps = Math.max(
      MOUSE_MOVEMENT.MIN_STEPS,
      Math.min(calculatedSteps, MOUSE_MOVEMENT.DEFAULT_STEPS)
    );
  }

  // Emergency cap on total movement time — if step count × max-per-step delay
  // would exceed the budget, reduce step count to fit. Realistic mode raises
  // the cap to 600ms so the higher step count survives the trim.
  // Floor-clamp to MIN_STEPS: if a caller passes a maxDelay larger than
  // totalMsLimit (e.g. maxDelay: 1000), the floor division yields 0, and the
  // i=0 iteration then computes progress = 0/0 = NaN, propagating into
  // page.mouse.move(NaN, NaN). Clamping preserves at least MIN_STEPS moves.
  const totalMsLimit = realistic ? 600 : MOUSE_MOVEMENT.MAX_TOTAL_MS;
  const estimatedTime = actualSteps * maxDelay;
  if (estimatedTime > totalMsLimit) {
    actualSteps = Math.max(MOUSE_MOVEMENT.MIN_STEPS, Math.floor(totalMsLimit / maxDelay));
  }

  for (let i = 0; i <= actualSteps; i++) {
    // Bail out if page closed mid-movement
    try { if (page.isClosed()) return; } catch { return; }

    const progress = i / actualSteps;

    // Apply easing curve for more natural movement
    const easedProgress = progress < 0.5
      ? 2 * progress * progress
      : 1 - Math.pow(-2 * progress + 2, 2) / 2;

    // Calculate base position
    let currentX = fromX + (toX - fromX) * easedProgress;
    let currentY = fromY + (toY - fromY) * easedProgress;

    // Add slight curve to movement (more human-like).
    // distance > 0 guard: when fromX === toX AND fromY === toY (integer-quantized
    // random targets in performContentClicks can collide; or external caller passes
    // from === to deliberately) the perpX/perpY divisions become -0/0 = NaN and
    // poison currentX/currentY, causing page.mouse.move(NaN, NaN) to reject via CDP.
    if (curve > 0 && distance > 0 && i > 0 && i < actualSteps) {
      const curveIntensity = Math.sin((i / actualSteps) * Math.PI) * curve * distance * MOUSE_MOVEMENT.CURVE_INTENSITY_RATIO;
      const perpX = -(toY - fromY) / distance;
      const perpY = (toX - fromX) / distance;

      currentX += perpX * curveIntensity;
      currentY += perpY * curveIntensity;
    }

    // Add small random jitter for realism
    if (jitter > 0 && i > 0 && i < actualSteps) {
      currentX += (Math.random() - 0.5) * jitter;
      currentY += (Math.random() - 0.5) * jitter;
    }

    await page.mouse.move(currentX, currentY);

    // Variable delay between movements
    if (i < actualSteps) {
      const delay = Math.floor(Math.random() * (maxDelay - minDelay + 1)) + minDelay;
      await fastTimeout(delay);
    }
  }
}

/**
 * Simulates realistic scrolling behavior with momentum and smoothness
 * 
 * SCROLLING FEATURES:
 * - Smooth scrolling broken into increments (not instant jumps)
 * - Configurable direction (up/down)
 * - Variable scroll amounts and speeds
 * - Pauses between scroll actions for realism
 * 
 * DEVELOPER NOTES:
 * - Uses page.mouse.wheel() for browser-native scrolling
 * - Smoothness parameter controls increment count (higher = smoother)
 * - Each scroll action is split into multiple small increments
 * - Automatically handles scroll failures gracefully
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page object
 * @param {object} options - Scrolling configuration
 * @param {string} options.direction - 'down' or 'up'
 * @param {number} options.amount - Number of scroll actions to perform
 * @param {number} options.smoothness - Smoothness level (1-10, higher = smoother)
 * @param {number} options.pauseBetween - Milliseconds pause between scroll actions
 * 
 * @example
 * // Basic downward scrolling
 * await simulateScrolling(page);
 * 
 * // Smooth upward scrolling
 * await simulateScrolling(page, {
 *   direction: 'up', amount: 5, smoothness: 8
 * });
 * 
 * // Fast scrolling with minimal smoothness
 * await simulateScrolling(page, {
 *   direction: 'down', amount: 2, smoothness: 2, pauseBetween: 100
 * });
 */
async function simulateScrolling(page, options = {}) {
  const {
    direction = 'down',
    amount = SCROLLING.DEFAULT_AMOUNT,
    smoothness = SCROLLING.DEFAULT_SMOOTHNESS,
    pauseBetween = SCROLLING.PAUSE_BETWEEN
  } = options;

  try {
    for (let i = 0; i < amount; i++) {
      try { if (page.isClosed()) return; } catch { return; }

      const scrollDelta = direction === 'down' ? SCROLLING.SCROLL_DELTA : -SCROLLING.SCROLL_DELTA;

      // Smooth scrolling by breaking into smaller increments
      for (let j = 0; j < smoothness; j++) {
        await page.mouse.wheel({ deltaY: scrollDelta / smoothness });
        await fastTimeout(SCROLLING.SMOOTH_INCREMENT_DELAY);
      }

      if (i < amount - 1) {
        await fastTimeout(pauseBetween);
      }
    }
  } catch (scrollErr) {
    // Silently handle scroll errors - not critical for functionality
  }
}

/**
 * Attempts to find and interact with clickable elements safely
 * 
 * SAFETY FEATURES:
 * - Avoids destructive actions (delete, buy, submit buttons)
 * - Only interacts with visible, clickable elements
 * - Bounded to viewport coordinates
 * - Graceful failure handling
 * 
 * ELEMENT DETECTION:
 * - Searches for buttons, links, and role="button" elements
 * - Filters by visibility (width/height > 0, within viewport)
 * - Text-based filtering to avoid dangerous actions
 * - Random selection from available safe elements
 * 
 * INTERACTION FLOW:
 * 1. Find all matching elements in viewport
 * 2. Filter out dangerous elements by text content
 * 3. Randomly select one element
 * 4. Move mouse to element center
 * 5. Pause briefly, then click
 * 6. Pause after clicking
 * 
 * DEVELOPER NOTES:
 * - Set avoidDestructive: false to disable safety filtering
 * - Customize elementTypes to target specific element types
 * - maxAttempts controls retry behavior
 * - All errors are caught to prevent breaking main scan
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page object
 * @param {object} options - Element interaction configuration
 * @param {number} options.maxAttempts - Maximum attempts to find elements
 * @param {string[]} options.elementTypes - CSS selectors for clickable elements
 * @param {boolean} options.avoidDestructive - Avoid dangerous actions
 * @param {number} options.timeout - Timeout for element operations
 * @param {boolean} options.forceDebug - Enable debug logging for skipped paths
 * 
 * @example
 * // Safe element interaction (default)
 * await interactWithElements(page);
 * 
 * // Custom element types
 * await interactWithElements(page, {
 *   elementTypes: ['button', '.custom-button', '#specific-id'],
 *   maxAttempts: 5
 * });
 * 
 * // Allow all interactions (dangerous!)
 * await interactWithElements(page, {
 *   avoidDestructive: false,
 *   elementTypes: ['button', 'input[type="submit"]']
 * });
 */
async function interactWithElements(page, options = {}) {
  const {
    maxAttempts = ELEMENT_INTERACTION.MAX_ATTEMPTS,
    elementTypes = ['button', 'a', '[role="button"]'],
    avoidDestructive = true,
    timeout = ELEMENT_INTERACTION.TIMEOUT,
    forceDebug = false,
    realistic = false
  } = options;

  try {
    // Ensure page is in valid state for element interaction
    try {
      // Check if page is closed before attempting interaction
      if (page.isClosed()) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${INTERACTION_TAG} Page is closed, skipping element interaction`));
        }
        return;
      }

      // Body wait honors the caller-provided timeout option (default 2000ms
      // via ELEMENT_INTERACTION.TIMEOUT) -- was previously hardcoded to 1000
      // and silently ignored the option. Explicitly dispose the returned handle
      // rather than relying on Puppeteer's FinalizationRegistry -- matches the
      // dispose pattern already used in performPageInteraction's final-hover block.
      const bodyHandle = await page.waitForSelector('body', { timeout });
      if (bodyHandle) { try { await bodyHandle.dispose(); } catch (_) {} }
      // Re-check after async wait — page may have closed during selector wait
      if (page.isClosed()) return;
    } catch (bodyWaitErr) {
      if (forceDebug) {
        console.log(formatLogMessage('debug', `${INTERACTION_TAG} Page not ready for element interaction: ${bodyWaitErr.message}`));
      }
      return;
    }

    // Use cached viewport for better performance
    const viewport = await getViewport(page);
    const maxX = viewport.width;
    const maxY = viewport.height;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        // Find visible, clickable elements
        const elements = await page.evaluate((selectors, avoidWords, textPreviewLen) => {
          const clickableElements = [];
          
          selectors.forEach(selector => {
            const elements = document.querySelectorAll(selector);
            elements.forEach(el => {
              const rect = el.getBoundingClientRect();
              const isVisible = rect.width > 0 && rect.height > 0 && 
                               rect.top >= 0 && rect.left >= 0 &&
                               rect.bottom <= window.innerHeight && 
                               rect.right <= window.innerWidth;
              
              if (isVisible) {
                const text = (el.textContent || el.alt || el.title || '').toLowerCase();
                // Word-boundary regex match -- prior `text.includes(word)`
                // produced false positives like 'submit' matching
                // 'resubmit'/'submitter', filtering out legitimate
                // clickables. \b ensures whole-word matches only.
                const shouldAvoid = avoidWords && avoidWords.length > 0 &&
                  new RegExp('\\b(' + avoidWords.join('|') + ')\\b').test(text);
                
                if (!shouldAvoid) {
                  clickableElements.push({
                    x: rect.left + rect.width / 2,
                    y: rect.top + rect.height / 2,
                    width: rect.width,
                    height: rect.height,
                    text: text.substring(0, textPreviewLen)
                  });
                }
              }
            });
          });
          
          return clickableElements;
        }, elementTypes, avoidDestructive ? ['delete', 'remove', 'submit', 'buy', 'purchase', 'order'] : [], ELEMENT_INTERACTION.TEXT_PREVIEW_LENGTH);

        if (elements.length > 0) {
          // Choose a random element to interact with
          const element = elements[Math.floor(Math.random() * elements.length)];
          
          // Move to element and click
          const currentPos = generateRandomCoordinates(maxX, maxY);
          await humanLikeMouseMove(page, currentPos.x, currentPos.y, element.x, element.y);
          
          // Brief pause before clicking
          await fastTimeout(TIMING.CLICK_PAUSE_MIN + Math.random() * (TIMING.CLICK_PAUSE_MAX - TIMING.CLICK_PAUSE_MIN));
          
          await humanClick(page, element.x, element.y, { forceDebug, realistic });
          
          // Brief pause after clicking
          await fastTimeout(TIMING.POST_CLICK_MIN + Math.random() * (TIMING.POST_CLICK_MAX - TIMING.POST_CLICK_MIN));
        }
      } catch (elementErr) {
        // Continue to next attempt if this one fails
        continue;
      }
    }
  } catch (mainErr) {
    // Silently handle errors - element interaction is supplementary
  }
}

/**
 * Clicks random spots in the page content area to trigger document-level
 * onclick handlers (Monetag onclick_static, similar popunder SDKs).
 *
 * WHY THIS EXISTS:
 * Ad onclick SDKs attach a single listener on `document` (capture phase)
 * that fires on ANY click with `isTrusted: true`. They don't care which
 * element was clicked — just that a real input event reached the document.
 * `interactWithElements()` hunts for <button>/<a> which may not exist or
 * may be excluded by the SDK's own filter. This function simply clicks
 * the content area of the page where the SDK will always accept the event.
 *
 * TIMING:
 * - 300ms preDelay: small buffer after mouse/scroll activity (~1.2s) for
 *   any late-loading async ad scripts to finish registering listeners.
 * - Spaces clicks 300-500ms apart (above Monetag's 250ms cooldown).
 * - Total time: ~1.1s for 2 clicks (preDelay + move + pause + click + gap).
 *
 * TARGETING:
 * - Clicks within the inner 60% of the viewport to avoid sticky headers,
 *   footers, sidebars, cookie banners, and overlay close buttons.
 * - Each click gets a fresh random position with natural mouse approach.
 *
 * @param {import('puppeteer').Page} page
 * @param {object} [options]
 * @param {number} [options.clicks]         Number of click attempts
 * @param {number} [options.preDelay]       Ms to wait before first click
 * @param {number} [options.interClickMin]  Min ms between clicks
 * @param {number} [options.interClickMax]  Max ms between clicks
 * @param {boolean} [options.forceDebug]    Log click coordinates
 */
async function performContentClicks(page, options = {}) {
  const {
    clicks = CONTENT_CLICK.CLICK_COUNT,
    preDelay = CONTENT_CLICK.PRE_CLICK_DELAY,
    interClickMin = CONTENT_CLICK.INTER_CLICK_MIN,
    interClickMax = CONTENT_CLICK.INTER_CLICK_MAX,
    forceDebug = false,
    realistic = false   // siteConfig.realistic_click — denser approach + hold tremor + mouseup drift
  } = options;
  const approachSteps = realistic
    ? CONTENT_CLICK.MOUSE_APPROACH_STEPS_REALISTIC
    : CONTENT_CLICK.MOUSE_APPROACH_STEPS;

  try {
    if (page.isClosed()) return;

    const viewport = await getViewport(page);
    const inset = CONTENT_CLICK.VIEWPORT_INSET;
    const minX = Math.floor(viewport.width * inset);
    const maxX = Math.floor(viewport.width * (1 - inset));
    const minY = Math.floor(viewport.height * inset);
    const maxY = Math.floor(viewport.height * (1 - inset));

    // Wait for ad scripts to register their listeners
    await fastTimeout(preDelay);

    let lastX = minX + Math.floor(Math.random() * (maxX - minX));
    let lastY = minY + Math.floor(Math.random() * (maxY - minY));

    for (let i = 0; i < clicks; i++) {
      try { if (page.isClosed()) break; } catch { break; }

      // Random position in content zone
      const targetX = minX + Math.floor(Math.random() * (maxX - minX));
      const targetY = minY + Math.floor(Math.random() * (maxY - minY));

      // Natural mouse approach (few steps, no need for elaborate curves)
      await humanLikeMouseMove(page, lastX, lastY, targetX, targetY, {
        steps: approachSteps,
        curve: 0.03 + Math.random() * 0.04,
        jitter: 1,
        realistic
      });

      // Brief human-like pause, then click
      await fastTimeout(TIMING.CLICK_PAUSE_MIN + Math.random() * (TIMING.CLICK_PAUSE_MAX - TIMING.CLICK_PAUSE_MIN));
      await humanClick(page, targetX, targetY, { forceDebug, realistic });

      if (forceDebug) {
        console.log(formatLogMessage('debug', `${INTERACTION_TAG} Content click ${i + 1}/${clicks} at (${targetX}, ${targetY})`));
      }

      lastX = targetX;
      lastY = targetY;

      // Inter-click gap (skip after last click)
      if (i < clicks - 1) {
        await fastTimeout(interClickMin + Math.random() * (interClickMax - interClickMin));
      }
    }
  } catch (err) {
    // Content clicks are supplementary — never break the scan
  }
}

/**
 * Performs comprehensive page interaction simulation - MAIN ENTRY POINT
 * 
 * This is the primary function called by nwss.js for page interaction.
 * It orchestrates multiple interaction types based on configuration.
 * 
 * INTERACTION SEQUENCE:
 * 1. Move mouse to random starting position
 * 2. Perform configured number of mouse movements
 * 3. Add occasional pauses for realism
 * 4. Simulate scrolling (if enabled)
 * 5. Interact with elements (if enabled)
 * 6. End with final hover position
 * 
 * INTENSITY LEVELS:
 * - LOW: 2 movements, 1 scroll, 50% longer pauses
 * - MEDIUM: 3 movements, 2 scrolls, normal timing
 * - HIGH: 5 movements, 3 scrolls, 30% faster timing
 * 
 * SAFETY FEATURES:
 * - All errors are caught and logged (won't break main scan)
 * - Element clicking is disabled by default
 * - Destructive actions are avoided
 * - Respects viewport boundaries
 * 
 * PERFORMANCE NOTES:
 * - Duration is distributed across all actions
 * - Actions are time-spaced for even distribution
 * - Intensity affects both quantity and timing
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page object
 * @param {string} currentUrl - Current page URL for logging
 * @param {object} options - Interaction configuration
 * @param {number} options.mouseMovements - Number of mouse movements
 * @param {boolean} options.includeScrolling - Enable scrolling simulation
 * @param {boolean} options.includeElementClicks - Enable element clicking
 * @param {number} options.duration - Total interaction time in milliseconds
 * @param {string} options.intensity - 'low' | 'medium' | 'high'
 * @param {boolean} forceDebug - Enable debug logging
 * 
 * @example
 * // Basic interaction
 * await performPageInteraction(page, 'https://example.com');
 * 
 * // High intensity interaction
 * await performPageInteraction(page, 'https://news.com', {
 *   intensity: 'high',
 *   duration: 5000,
 *   includeScrolling: true
 * });
 * 
 * // Minimal interaction
 * await performPageInteraction(page, 'https://shop.com', {
 *   intensity: 'low',
 *   mouseMovements: 1,
 *   includeScrolling: false,
 *   includeElementClicks: false
 * });
 */
/**
 * Work-aware ceiling (ms) for a single interaction pass.
 *
 * Interaction is a sequence of awaited steps (mouse moves, scrolls, content
 * clicks); under event-loop/CDP contention from many concurrent URLs each step
 * stretches well past its intrinsic cost (a default 3-click pass measured ~4s
 * solo but ~22s at the default concurrency of 6). A FLAT ceiling therefore
 * either truncates legitimate high interact_click_count / realistic_click
 * configs — dropping the very popunder clicks the pass exists to fire — or sits
 * loosely over light runs. Scale by the actual work envelope instead, same
 * philosophy as nwss's per-URL timeout. Per-unit allowances are sized to absorb
 * up to ~default-concurrency contention; the result is a SAFETY ceiling, not a
 * target — interaction returns as soon as its work is done, so a generous
 * ceiling never slows a fast pass, it only bounds a stuck one.
 *
 * @param {Object} options - same shape performPageInteraction receives
 * @returns {number} ceiling in ms (floored at 15000, the prior flat budget)
 */
function computeInteractionCeilingMs(options = {}) {
  const {
    intensity = 'medium',
    mouseMovements,
    includeScrolling = true,
    includeElementClicks = false,
    clickCount,
    realistic = false
  } = options;

  const settings = INTENSITY_SETTINGS[String(intensity).toUpperCase()] || INTENSITY_SETTINGS.MEDIUM;
  const movements = mouseMovements !== undefined ? mouseMovements : settings.movements;
  const scrolls = includeScrolling ? settings.scrolls : 0;
  const clicks = includeElementClicks
    ? (clickCount ? Math.min(Math.floor(clickCount), CONTENT_CLICK.CLICK_COUNT_MAX) : CONTENT_CLICK.CLICK_COUNT)
    : 0;

  const BASE_MS = 6000;        // setup, viewport, final move, slack
  const PER_MOVE_MS = 700;
  const PER_SCROLL_MS = 800;
  const PER_CLICK_MS = realistic ? 7000 : 4000;  // realistic clicks are denser (15-step approach + tremor)

  return Math.max(
    15000,  // floor = the prior flat budget, so light/default configs are unchanged
    BASE_MS + movements * PER_MOVE_MS + scrolls * PER_SCROLL_MS + clicks * PER_CLICK_MS
  );
}

async function performPageInteraction(page, currentUrl, options = {}, forceDebug = false) {
  // Hard wall-clock ceiling on the whole interaction. The impl's internal
  // checkTimeout() is cooperative — only evaluated BETWEEN steps — so a single
  // blocking await (a CDP round-trip, or a fastTimeout that fires late once
  // many URLs saturate the one event loop / CDP pipe) sails right past the 15s
  // soft budget; that's how interaction was clocking 21-22s under concurrency.
  // Racing the work against a real timer enforces the ceiling no matter where
  // the time actually goes. The timer RESOLVES (never rejects) — interaction
  // failures must not break the scan — and the impl is .catch()'d so the
  // orphaned run can't surface an unhandled rejection after the race settles.
  // Keeps nwss's per-URL INTERACTION_OVERHEAD_MS budget honest: one cycle now
  // stays <= the ceiling even under heavy contention.
  const HARD_CAP_MS = computeInteractionCeilingMs(options); // work-aware: scales with clicks/realistic/intensity
  let capTimer;
  let capped = false;
  const work = _performPageInteractionImpl(page, currentUrl, options, forceDebug).catch(() => {});
  try {
    await Promise.race([
      work,
      new Promise(resolve => { capTimer = setTimeout(() => { capped = true; resolve(); }, HARD_CAP_MS); })
    ]);
  } finally {
    if (capTimer) clearTimeout(capTimer);
  }
  if (capped && forceDebug) {
    console.log(formatLogMessage('debug', `${INTERACTION_TAG} Interaction hard-capped at ${HARD_CAP_MS}ms for ${currentUrl} (event-loop/CDP contention)`));
  }
}

async function _performPageInteractionImpl(page, currentUrl, options = {}, forceDebug = false) {
  // mouseMovements deliberately has no default in the destructure: we want
  // to distinguish 'caller didn't pass it' from 'caller explicitly passed 3'
  // so the actualMovements calculation below can let intensity drive the
  // count when nothing was specified. The old default-3 + Math.min(...) shape
  // silently capped HIGH intensity's intended 5 movements down to 3.
  const {
    mouseMovements,
    includeScrolling = true,
    includeElementClicks = false,
    duration = TIMING.DEFAULT_INTERACTION_DURATION,
    intensity = 'medium',
    clickCount,       // optional override; undefined -> performContentClicks uses CONTENT_CLICK.CLICK_COUNT default
    realistic = false // siteConfig.realistic_click — propagated to performContentClicks
  } = options;

  try {
    // CRITICAL: Emergency timeout wrapper for entire interaction
    const MAX_INTERACTION_TIME = 15000; // 15 seconds absolute maximum
    const interactionStartTime = Date.now();
    
    const checkTimeout = () => {
      return Date.now() - interactionStartTime > MAX_INTERACTION_TIME;
    };

    // Validate page state before starting interaction
    try {
      if (page.isClosed()) {
        if (forceDebug) {
          console.log(formatLogMessage('debug', `${INTERACTION_TAG} Page is closed for ${currentUrl}, skipping interaction`));
        }
        return;
      }
    } catch { return; }

    // Use cached viewport for better performance
    const viewport = await getViewport(page);
    const maxX = viewport.width;
    const maxY = viewport.height;

    if (forceDebug) {
      let hostname = currentUrl;
      try { hostname = new URL(currentUrl).hostname; } catch {}
      console.log(formatLogMessage('debug', `${INTERACTION_TAG} Starting enhanced interaction simulation for ${hostname} (${intensity} intensity)`));
    }

    // Configure intensity settings. When the caller didn't pass mouseMovements,
    // intensity drives the count (HIGH = 5, MEDIUM = 3, LOW = 2). When the
    // caller DID pass an explicit value, that wins — covers callers who want
    // a custom count regardless of the broader intensity profile.
    const settings = INTENSITY_SETTINGS[intensity.toUpperCase()] || INTENSITY_SETTINGS.MEDIUM;
    const actualMovements = mouseMovements !== undefined ? mouseMovements : settings.movements;
    
    // Start with random position
    let currentPos = generateRandomCoordinates(maxX, maxY, { preferEdges: true });
    
    // Batch mouse move operations for better performance
    try {
    await page.mouse.move(currentPos.x, currentPos.y);
    } catch (mouseMoveErr) {
      return; // Exit gracefully if mouse operations fail
    }


    // Inter-action spacers were a separate await-fastTimeout between every
    // movement/scroll (capped at 50ms each). Each movement already has its
    // own internal step delays (5–25ms per step) plus the PAUSE_CHANCE
    // pause path, so the cursor never visibly "rips through" actions —
    // the spacer was adding ~50ms × 5 actions = ~250ms of pure dead time
    // per interaction for no anti-detection benefit. Removed.

    // Start timing ONLY the actual interaction operations
    const actualInteractionStartTime = Date.now();

    // Perform mouse movements
    for (let i = 0; i < actualMovements; i++) {
      if (checkTimeout()) break; // Emergency timeout check
      const targetPos = generateRandomCoordinates(maxX, maxY, { 
        avoidCenter: i % 2 === 0,
        preferEdges: i % 3 === 0 
      });

      await humanLikeMouseMove(page, currentPos.x, currentPos.y, targetPos.x, targetPos.y, {
          steps: 3 + Math.floor(Math.random() * 4), // CRITICAL: 3-6 steps (was 8-18)
          curve: 0.05 + Math.random() * 0.05, // CRITICAL: Minimal curve
        jitter: 1 + Math.random() * 2
      });

      currentPos = targetPos;

      // Occasional pause — keep at lower probability than the prior 0.3
      // (PROBABILITIES.PAUSE_CHANCE) since bot detectors care more about
      // timing variance WITHIN mouse motion (the step delays handle that)
      // than about pauses BETWEEN motions.
      if (Math.random() < PROBABILITIES.PAUSE_CHANCE) {
        await fastTimeout(25 + Math.random() * 50);
      }
    }

    // Scrolling simulation
    if (includeScrolling) {
      for (let i = 0; i < settings.scrolls; i++) {
        if (checkTimeout()) break; // Emergency timeout check
        const direction = Math.random() < PROBABILITIES.SCROLL_DOWN_BIAS ? 'down' : 'up';
        await simulateScrolling(page, {
          direction,
          amount: 1 + Math.floor(Math.random() * 2), // CRITICAL: Less scrolling
          smoothness: 1 + Math.floor(Math.random() * 2) // CRITICAL: Much less smooth
        });
      }
    }

    // Click interaction — content-area clicks trigger document-level onclick
    // handlers (Monetag, similar popunder SDKs). Previously this branch ALSO
    // called interactWithElements afterward to hit element-specific listeners,
    // but document-level handlers cover ~all real-world ad-script patterns —
    // the secondary element-click pass added ~200–600ms for marginal coverage.
    // interactWithElements is still exported for callers that want it.
    if (includeElementClicks) {
      if (checkTimeout()) return; // Emergency timeout check
      // Pass clickCount only when caller set it (via siteConfig.interact_click_count)
      // -- omit otherwise so performContentClicks's default destructure
      // falls through to CONTENT_CLICK.CLICK_COUNT. realistic is always
      // forwarded (defaults to false at every layer).
      const ccOpts = { forceDebug, realistic };
      if (clickCount) ccOpts.clicks = clickCount;
      await performContentClicks(page, ccOpts);
    }

    // Final resting position — single mouse.move instead of the previous
    // humanLikeMouseMove + page.hover('body') sequence. The prior block paid
    // ~80–120ms (full anti-detection trajectory + a CDP $() lookup + hover
    // round-trip) just to leave the cursor at a random end position. The
    // anti-detection curves matter while actions are happening; the parking
    // move at the end doesn't need them, and hover('body') was mostly a no-op
    // since the cursor was already inside the body's bounding box anyway.
    const finalPos = generateRandomCoordinates(maxX, maxY);
    try { await page.mouse.move(finalPos.x, finalPos.y); }
    catch (_) { /* page closed or detached — non-critical */ }

    // End timing ONLY after actual interaction operations complete
    const interactionElapsedTime = Date.now() - actualInteractionStartTime

    // CRITICAL: Warn about slow interactions
    if (interactionElapsedTime > 8000) {
      console.warn(formatLogMessage('warn', `${INTERACTION_TAG} WARNING: Interaction took ${interactionElapsedTime}ms for ${currentUrl}`));
    }

    if (forceDebug) {
      console.log(formatLogMessage('debug', `${INTERACTION_TAG} Completed interaction simulation in ${interactionElapsedTime}ms (${actualMovements} movements, ${includeScrolling ? settings.scrolls : 0} scrolls)`));
    }

  } catch (interactionErr) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${INTERACTION_TAG} Interaction simulation failed for ${currentUrl}: ${interactionErr.message}`));
    }
    // Don't throw - interaction failures shouldn't break the main scan
  }
}

/**
 * Creates an optimized interaction configuration based on site characteristics
 * 
 * This function analyzes the target URL and creates an appropriate interaction
 * configuration automatically. It can be overridden by explicit site config.
 * 
 * AUTOMATIC SITE DETECTION:
 * - News/Blog sites: High intensity, longer duration, more scrolling
 * - Shopping sites: Low intensity, avoid clicking (safety)
 * - Social/Forum sites: Medium intensity, balanced interaction
 * - Default: Medium intensity for unknown sites
 * 
 * CONFIGURATION PRIORITY:
 * 1. Explicit siteConfig parameters (highest priority)
 * 2. URL-based automatic detection
 * 3. Default values (lowest priority)
 * 
 * SITE CONFIG OVERRIDES:
 * - interact_intensity: 'low' | 'medium' | 'high'
 * - interact_duration: milliseconds
 * - interact_scrolling: boolean
 * - interact_clicks: boolean
 * - interact_typing: boolean
 * 
 * DEVELOPER NOTES:
 * - Add new site patterns by modifying the hostname checks
 * - Site detection is case-insensitive substring matching
 * - Returns a complete config object with all required properties
 * - Gracefully handles malformed URLs
 * 
 * @param {string} url - Site URL for analysis
 * @param {object} siteConfig - Site-specific configuration overrides
 * @returns {object} Optimized interaction configuration
 * 
 * @example
 * // Automatic configuration
 * const config = createInteractionConfig('https://news.example.com');
 * // Returns: { intensity: 'high', duration: 3000, includeScrolling: true, ... }
 * 
 * // With manual overrides
 * const config = createInteractionConfig('https://shop.com', {
 *   interact_intensity: 'medium',
 *   interact_clicks: true
 * });
 * // Returns: { intensity: 'medium', includeElementClicks: true, ... }
 * 
 * // Custom site pattern
 * const config = createInteractionConfig('https://custom-forum.com');
 * // Falls back to default configuration
 */
function createInteractionConfig(url, siteConfig = {}) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();

    // Site-specific interaction patterns. mouseMovements is intentionally
    // unset by default so intensity drives the count downstream — the prior
    // hardcoded `mouseMovements: 3` silently masked the HIGH intensity's
    // intended 5 movements when news/blog sites flipped intensity='high'.
    const config = {
      includeScrolling: true,
      includeElementClicks: false,
      duration: 2000,
      intensity: 'medium'
    };

    // Adjust based on site type
    if (hostname.includes('news') || hostname.includes('blog')) {
      config.includeScrolling = true;
      config.intensity = 'high';
      config.duration = Math.min(SITE_DURATIONS.NEWS_BLOG, 4000); // FIXED: Cap at 4 seconds
    } else if (hostname.includes('shop') || hostname.includes('store')) {
      config.includeElementClicks = false; // Avoid accidental purchases
      config.intensity = 'low';
    } else if (hostname.includes('social') || hostname.includes('forum')) {
      config.includeScrolling = true;
      config.mouseMovements = 4;  // Explicit override — distinct from intensity
      config.intensity = 'medium';
      config.duration = SITE_DURATIONS.SOCIAL_FORUM;
    }

    // Override with explicit site configuration
    if (siteConfig.interact_intensity) {
      config.intensity = siteConfig.interact_intensity;
    }
    if (siteConfig.interact_duration) {
      config.duration = siteConfig.interact_duration;
    }
    if (siteConfig.interact_scrolling !== undefined) {
      config.includeScrolling = siteConfig.interact_scrolling;
    }
    if (siteConfig.interact_clicks !== undefined) {
      config.includeElementClicks = siteConfig.interact_clicks;
    }
    // interact_click_count: per-site override of how many random
    // content-zone clicks performContentClicks fires. Cap at
    // CLICK_COUNT_MAX to prevent runaway from typos. Coerce to integer
    // and clamp >= 1 (count of 0 should be expressed via
    // interact_clicks: false, not interact_click_count: 0).
    if (typeof siteConfig.interact_click_count === 'number' && siteConfig.interact_click_count > 0) {
      config.clickCount = Math.min(
        Math.floor(siteConfig.interact_click_count),
        CONTENT_CLICK.CLICK_COUNT_MAX
      );
    }
    // realistic_click: opt-in for sites that score click realism
    // (DataDome, Akamai BM, PerimeterX). Adds ~80–120ms per click for the
    // denser approach; hold-tremor and mouseup-drift fit inside the
    // existing hold window so they're free. Off by default since ad-network
    // popunder discovery doesn't need it and we'd rather keep scans fast.
    if (siteConfig.realistic_click === true) {
      config.realistic = true;
    }

    return config;
  } catch (urlErr) {
    // Return default config if URL parsing fails — mouseMovements unset so
    // the intensity-driven default applies in performPageInteraction.
    return {
      includeScrolling: true,
      includeElementClicks: false,
      duration: TIMING.DEFAULT_INTERACTION_DURATION,
      intensity: 'medium'
    };
  }
}

// === MODULE EXPORTS ===
// Export all public functions for use by nwss.js and other modules

/**
 * MAIN EXPORTS - Primary functions for page interaction
 * 
 * performPageInteraction: Main entry point for comprehensive interaction
 * createInteractionConfig: Auto-generates optimized config based on URL
 */

/**
 * COMPONENT EXPORTS - Individual interaction components
 * 
 * humanLikeMouseMove: Realistic mouse movement with curves
 * simulateScrolling: Smooth scrolling simulation
 * interactWithElements: Safe element clicking
 * generateRandomCoordinates: Smart coordinate generation
 */

/**
 * USAGE EXAMPLES:
 * 
 * // In nwss.js (main integration)
 * const { performPageInteraction, createInteractionConfig } = require('./lib/interaction');
 * const config = createInteractionConfig(url, siteConfig);
 * await performPageInteraction(page, url, config, debug);
 * 
 * // Custom interaction script
 * const { humanLikeMouseMove, simulateScrolling } = require('./lib/interaction');
 * await humanLikeMouseMove(page, 0, 0, 500, 300);
 * await simulateScrolling(page, { direction: 'down', amount: 3 });
 * 
 * // Advanced coordinate generation
 * const { generateRandomCoordinates } = require('./lib/interaction');
 * const pos = generateRandomCoordinates(1920, 1080, { preferEdges: true });
 */

/**
 * Click a list of CSS selectors in order, reaching content via organic
 * gesture/navigation instead of a direct page load. Each selector's first
 * match is clicked; if the click navigates (an <a href> / form submit), we wait
 * for it to commit, otherwise we wait a settle window for in-page actions
 * (e.g. a player starting). The page's request interceptor stays attached
 * throughout, so the post-click requests flow into the caller's normal
 * filterRegex/dig matching — this function only performs the clicks.
 *
 * Missing elements are skipped (sites change markup); a click error never
 * throws out of here. After a navigation, later selectors are queried against
 * the NEW page (so e.g. "movie link" then "play button" works).
 *
 * @param {import('puppeteer').Page} page
 * @param {string[]} selectors - CSS selectors, clicked in order
 * @param {object} [options]
 * @param {boolean} [options.realistic=false] - use humanClick (hover/tremor) vs elementHandle.click
 * @param {number}  [options.waitMs=5000] - per click: max wait for the element to
 *   appear+be visible (waitForSelector), AND the settle/nav window after the click
 * @param {function} [options.ghostClick] - optional (x,y)=>Promise that performs a
 *   ghost-cursor click (Bezier travel + press) at the element centre. Injected by the
 *   caller so this module needn't depend on ghost-cursor.js (which depends on this one).
 *   When provided it takes precedence over the humanClick/el.click paths.
 * @param {boolean} [options.forceDebug=false]
 * @returns {Promise<Array<{selector:string, clicked:boolean, reason?:string}>>}
 */
async function performTargetedClicks(page, selectors, options = {}) {
  const { realistic = false, waitMs = 5000, forceDebug = false, ghostClick = null } = options;
  const results = [];
  if (!Array.isArray(selectors)) return results;

  for (const raw of selectors) {
    const selector = typeof raw === 'string' ? raw.trim() : '';
    if (!selector) continue;
    if (page.isClosed()) break;

    // Wait for the element to appear AND be visible (up to waitMs) rather than
    // querying once — many targets (video players, lazy menus, post-consent
    // buttons) are injected by JS after DOMContentLoaded, so an immediate query
    // would race ahead of them and miss. Timeout → treat as not-found, skip.
    let el = null;
    try { el = await page.waitForSelector(selector, { visible: true, timeout: waitMs }); } catch (_) { el = null; }
    if (!el) {
      if (forceDebug) console.log(formatLogMessage('debug', `${INTERACTION_TAG} click_elements: "${selector}" not visible within ${waitMs}ms — skipping`));
      results.push({ selector, clicked: false, reason: 'not-found' });
      continue;
    }

    try {
      // Bring it into view so coordinate clicks land (elementHandle.click also
      // auto-scrolls, but humanClick clicks raw coordinates).
      try { await el.evaluate(e => e.scrollIntoView({ block: 'center', inline: 'center' })); } catch (_) { /* detached/odd element */ }

      // Arm a navigation wait BEFORE clicking so a link/submit is caught.
      const navP = page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: waitMs + 3000 }).catch(() => {});

      let box = null;
      try { box = await el.boundingBox(); } catch (_) { box = null; }
      if (typeof ghostClick === 'function' && box) {
        // Ghost-cursor path: Bezier travel to the element centre + realistic
        // press, matching the interact phase (caller-injected).
        await ghostClick(box.x + box.width / 2, box.y + box.height / 2);
      } else if (realistic && box) {
        await humanClick(page, box.x + box.width / 2, box.y + box.height / 2, { realistic: true, forceDebug });
      } else {
        await el.click({ delay: 30 }); // trusted gesture; auto-scrolls + handles non-visible coords
      }

      // Resolve on whichever comes first: a committed navigation, or the settle
      // window (in-page actions). Either way, requests fired in between are
      // already captured by the caller's interceptor.
      await Promise.race([navP, new Promise(r => setTimeout(r, waitMs))]);
      results.push({ selector, clicked: true });
      if (forceDebug) console.log(formatLogMessage('debug', `${INTERACTION_TAG} click_elements: clicked "${selector}"`));
    } catch (err) {
      if (forceDebug) console.log(formatLogMessage('debug', `${INTERACTION_TAG} click_elements: click failed for "${selector}": ${err.message}`));
      results.push({ selector, clicked: false, reason: err.message });
    } finally {
      try { await el.dispose(); } catch (_) { /* detached after navigation — fine */ }
    }
  }
  return results;
}

module.exports = {
  // Main interaction functions
  performPageInteraction,
  createInteractionConfig,
  computeInteractionCeilingMs,
  getViewport,
  // Component functions for custom implementations
  humanLikeMouseMove,
  simulateScrolling,
  interactWithElements,
  performContentClicks,
  // Realistic timed click (hover dwell + mousedown/hold/mouseup, optional
  // hand-tremor + mouseup drift). Reused by lib/ghost-cursor.js so the ghost
  // coordinate click gets the same press realism as built-in content clicks.
  humanClick,
  // Click specific CSS selectors in order (organic navigation / play-button /
  // link clicking) — site config `click_elements`.
  performTargetedClicks,
  generateRandomCoordinates
};