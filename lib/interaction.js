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
  CLICK_COUNT: 2,            // Two attempts (primary + backup if first suppressed)
  INTER_CLICK_MIN: 300,      // Minimum ms between clicks (above Monetag 250ms cooldown)
  INTER_CLICK_MAX: 500,      // Maximum ms between clicks
  PRE_CLICK_DELAY: 300,      // Small buffer for late-loading async ad scripts
  VIEWPORT_INSET: 0.2,       // Avoid outer 20% of viewport (menus, overlays)
  MOUSE_APPROACH_STEPS: 3    // Minimal steps — just enough for non-instant movement
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
  PAUSE_CHANCE: 0.3,        // 30% chance of random pause during movement
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
    jitter = MOUSE_MOVEMENT.DEFAULT_JITTER
  } = options;

  const distance = Math.sqrt((toX - fromX) ** 2 + (toY - fromY) ** 2);

  // Step count: caller-provided value capped at MAX_STEPS, otherwise derived
  // from distance and clamped to [MIN_STEPS, DEFAULT_STEPS].
  let actualSteps;
  if (options.steps) {
    actualSteps = Math.min(options.steps, MOUSE_MOVEMENT.MAX_STEPS);
  } else {
    const calculatedSteps = Math.floor(distance / MOUSE_MOVEMENT.DISTANCE_STEP_RATIO);
    actualSteps = Math.max(
      MOUSE_MOVEMENT.MIN_STEPS,
      Math.min(calculatedSteps, MOUSE_MOVEMENT.DEFAULT_STEPS)
    );
  }

  // Emergency cap on total movement time — if step count × max-per-step delay
  // would exceed the budget, reduce step count to fit.
  const estimatedTime = actualSteps * maxDelay;
  if (estimatedTime > MOUSE_MOVEMENT.MAX_TOTAL_MS) {
    actualSteps = Math.floor(MOUSE_MOVEMENT.MAX_TOTAL_MS / maxDelay);
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

    // Add slight curve to movement (more human-like)
    if (curve > 0 && i > 0 && i < actualSteps) {
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
    timeout = ELEMENT_INTERACTION.TIMEOUT
  } = options;

  try {
    // Ensure page is in valid state for element interaction
    try {
      // Check if page is closed before attempting interaction
      if (page.isClosed()) {
        if (options.forceDebug) {
          console.log(formatLogMessage('debug', `${INTERACTION_TAG} Page is closed, skipping element interaction`));
        }
        return;
      }

      // Very short timeout since page should already be loaded.
      // Explicitly dispose the returned handle rather than relying on
      // Puppeteer's FinalizationRegistry — matches the dispose pattern
      // already used in performPageInteraction's final-hover block.
      const bodyHandle = await page.waitForSelector('body', { timeout: 1000 });
      if (bodyHandle) { try { await bodyHandle.dispose(); } catch (_) {} }
      // Re-check after async wait — page may have closed during selector wait
      if (page.isClosed()) return;
    } catch (bodyWaitErr) {
      if (options.forceDebug) {
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
                const shouldAvoid = avoidWords && avoidWords.some(word => text.includes(word));
                
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
          
          await page.mouse.click(element.x, element.y);
          
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
    forceDebug = false
  } = options;

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
        steps: CONTENT_CLICK.MOUSE_APPROACH_STEPS,
        curve: 0.03 + Math.random() * 0.04,
        jitter: 1
      });

      // Brief human-like pause, then click
      await fastTimeout(TIMING.CLICK_PAUSE_MIN + Math.random() * (TIMING.CLICK_PAUSE_MAX - TIMING.CLICK_PAUSE_MIN));
      await page.mouse.click(targetX, targetY);

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
async function performPageInteraction(page, currentUrl, options = {}, forceDebug = false) {
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
    intensity = 'medium'
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


    const totalDuration = duration * settings.pauseMultiplier;
    // CRITICAL: Cap action intervals to prevent long waits
    const baseInterval = totalDuration / (actualMovements + (includeScrolling ? settings.scrolls : 0));
    const actionInterval = Math.min(baseInterval, 100); // Never wait more than 100ms
    
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

      // Occasional pause
      if (Math.random() < PROBABILITIES.PAUSE_CHANCE) {
        await fastTimeout(25 + Math.random() * 50); // CRITICAL: Much shorter pauses
      }

      // Time-based spacing
      await fastTimeout(Math.min(actionInterval, 50)); // CRITICAL: Cap at 50ms
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
        
        await fastTimeout(Math.min(actionInterval, 100)); // CRITICAL: Cap intervals
      }
    }

    // Click interaction — two strategies for maximum ad script coverage
    // 1. Content area clicks: triggers document-level onclick handlers
    //    (Monetag, similar popunder SDKs that listen on document)
    // 2. Element clicks: interacts with specific UI elements
    //    (ad scripts that attach to specific clickable elements)
    if (includeElementClicks) {
      if (checkTimeout()) return; // Emergency timeout check
      // Primary: content area clicks for document-level onclick handlers
      await performContentClicks(page, { forceDebug });
      // Secondary: targeted element clicks (fast, 1 attempt only).
      // Pass forceDebug so the function's existing 'page closed' / 'not ready'
      // debug logs actually surface — previously the option wasn't threaded
      // through, so both log branches were dead.
      if (!checkTimeout()) {
        await interactWithElements(page, {
          maxAttempts: 1,
          avoidDestructive: true,
          forceDebug
        });
      }
    }

    // Final hover position
    const finalPos = generateRandomCoordinates(maxX, maxY);
    await humanLikeMouseMove(page, currentPos.x, currentPos.y, finalPos.x, finalPos.y);
    
    // Safe hover with validation
    try {
      const bodyElement = await page.$('body');
      if (bodyElement) {
        try {
          await page.hover('body');
        } finally {
          await bodyElement.dispose();
        }
      }
    } catch (hoverErr) {
      // Silently handle hover failures - not critical
    }

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
module.exports = {
  // Main interaction functions
  performPageInteraction,
  createInteractionConfig,
  getViewport,
  // Component functions for custom implementations
  humanLikeMouseMove,
  simulateScrolling,
  interactWithElements,
  performContentClicks,
  generateRandomCoordinates
};