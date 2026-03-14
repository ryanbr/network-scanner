// === Ghost Cursor Module ===
// Optional wrapper around the ghost-cursor npm package for advanced Bezier-based mouse movements.
// Falls back gracefully to built-in interaction.js mouse if ghost-cursor is not installed.
//
// USAGE (JSON config):
//   "cursor_mode": "ghost"              Enable ghost-cursor for this site
//   "ghost_cursor_speed": 1.5           Movement speed multiplier (default: 1.0)
//   "ghost_cursor_hesitate": 100        Delay (ms) before clicking (default: 50)
//   "ghost_cursor_overshoot": 500       Max overshoot distance in px (default: auto)
//
// USAGE (CLI):
//   --ghost-cursor                      Enable ghost-cursor globally
//
// INSTALL:
//   npm install ghost-cursor            (optional dependency)

const { formatLogMessage } = require('./colorize');

let ghostCursorModule = null;
let ghostCursorAvailable = false;

// Attempt to load ghost-cursor at module init — optional dependency
try {
  ghostCursorModule = require('ghost-cursor');
  ghostCursorAvailable = true;
} catch {
  // ghost-cursor not installed — this is fine, built-in mouse will be used
}

/**
 * Check if ghost-cursor is available
 * @returns {boolean}
 */
function isGhostCursorAvailable() {
  return ghostCursorAvailable;
}

/**
 * Create a ghost-cursor instance bound to a Puppeteer page
 * @param {import('puppeteer').Page} page - Puppeteer page instance
 * @param {object} options - Configuration options
 * @param {boolean} options.forceDebug - Enable debug logging
 * @param {number} options.startX - Starting X coordinate (default: 0)
 * @param {number} options.startY - Starting Y coordinate (default: 0)
 * @returns {object|null} Ghost cursor instance or null if unavailable
 */
function createGhostCursor(page, options = {}) {
  if (!ghostCursorAvailable) {
    return null;
  }

  const { forceDebug, startX = 0, startY = 0 } = options;

  try {
    const cursor = ghostCursorModule.createCursor(page, { x: startX, y: startY });

    if (forceDebug) {
      console.log(formatLogMessage('debug', '[ghost-cursor] Cursor instance created'));
    }

    return cursor;
  } catch (err) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[ghost-cursor] Failed to create cursor: ${err.message}`));
    }
    return null;
  }
}

/**
 * Move cursor to coordinates using ghost-cursor Bezier paths
 * Drop-in replacement for humanLikeMouseMove when ghost-cursor is active
 *
 * @param {object} cursor - Ghost cursor instance from createGhostCursor()
 * @param {number} toX - Target X coordinate
 * @param {number} toY - Target Y coordinate
 * @param {object} options - Movement options
 * @param {number} options.moveSpeed - Speed multiplier (default: auto/random)
 * @param {number} options.moveDelay - Delay after movement in ms (default: 0)
 * @param {boolean} options.randomizeMoveDelay - Randomize move delay (default: true)
 * @param {number} options.overshootThreshold - Max overshoot distance in px
 * @param {boolean} options.forceDebug - Enable debug logging
 * @returns {Promise<boolean>} true if movement succeeded
 */
async function ghostMove(cursor, toX, toY, options = {}) {
  if (!cursor) return false;

  const {
    moveSpeed,
    moveDelay = 0,
    randomizeMoveDelay = true,
    overshootThreshold,
    forceDebug
  } = options;

  try {
    const moveOpts = {};
    if (moveSpeed !== undefined) moveOpts.moveSpeed = moveSpeed;
    if (moveDelay > 0) moveOpts.moveDelay = moveDelay;
    if (randomizeMoveDelay !== undefined) moveOpts.randomizeMoveDelay = randomizeMoveDelay;
    if (overshootThreshold !== undefined) moveOpts.overshootThreshold = overshootThreshold;

    await cursor.moveTo({ x: toX, y: toY }, moveOpts);

    if (forceDebug) {
      console.log(formatLogMessage('debug', `[ghost-cursor] Moved to (${Math.round(toX)}, ${Math.round(toY)})`));
    }

    return true;
  } catch (err) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[ghost-cursor] Move failed: ${err.message}`));
    }
    return false;
  }
}

/**
 * Click on a CSS selector or coordinates using ghost-cursor
 *
 * @param {object} cursor - Ghost cursor instance
 * @param {string|{x: number, y: number}} target - CSS selector or {x, y} coordinates
 * @param {object} options - Click options
 * @param {number} options.hesitate - Delay (ms) before clicking (default: 50)
 * @param {number} options.waitForClick - Delay (ms) between mousedown/mouseup (default: auto)
 * @param {number} options.moveDelay - Delay (ms) after moving to target
 * @param {number} options.paddingPercentage - Click point within element (0=edge, 100=center)
 * @param {boolean} options.forceDebug - Enable debug logging
 * @returns {Promise<boolean>} true if click succeeded
 */
async function ghostClick(cursor, target, options = {}) {
  if (!cursor) return false;

  const {
    hesitate = 50,
    waitForClick,
    moveDelay,
    paddingPercentage,
    forceDebug
  } = options;

  try {
    const clickOpts = { hesitate };
    if (waitForClick !== undefined) clickOpts.waitForClick = waitForClick;
    if (moveDelay !== undefined) clickOpts.moveDelay = moveDelay;
    if (paddingPercentage !== undefined) clickOpts.paddingPercentage = paddingPercentage;

    if (typeof target === 'string') {
      await cursor.click(target, clickOpts);
    } else {
      // For coordinate clicks, move first then use page click
      await cursor.moveTo(target);
      // Small hesitation before clicking
      if (hesitate > 0) {
        await new Promise(resolve => setTimeout(resolve, hesitate));
      }
      const page = cursor._page || cursor.page;
      if (page && typeof page.mouse?.click === 'function') {
        await page.mouse.click(target.x, target.y);
      }
    }

    if (forceDebug) {
      const label = typeof target === 'string' ? target : `(${Math.round(target.x)}, ${Math.round(target.y)})`;
      console.log(formatLogMessage('debug', `[ghost-cursor] Clicked ${label}`));
    }

    return true;
  } catch (err) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `[ghost-cursor] Click failed: ${err.message}`));
    }
    return false;
  }
}

/**
 * Perform a random idle mouse movement using ghost-cursor
 *
 * @param {object} cursor - Ghost cursor instance
 * @param {object} options - Options
 * @param {boolean} options.forceDebug - Enable debug logging
 * @returns {Promise<boolean>} true if movement succeeded
 */
async function ghostRandomMove(cursor, options = {}) {
  if (!cursor) return false;

  try {
    await cursor.randomMove();
    if (options.forceDebug) {
      console.log(formatLogMessage('debug', '[ghost-cursor] Random movement performed'));
    }
    return true;
  } catch (err) {
    if (options.forceDebug) {
      console.log(formatLogMessage('debug', `[ghost-cursor] Random move failed: ${err.message}`));
    }
    return false;
  }
}

/**
 * Generate a Bezier path between two points (standalone, no browser needed)
 *
 * @param {{x: number, y: number}} from - Start point
 * @param {{x: number, y: number}} to - End point
 * @param {object} options - Path options
 * @param {number} options.spreadOverride - Override curve spread
 * @param {number} options.moveSpeed - Movement speed
 * @returns {Array<{x: number, y: number}>|null} Array of path points or null
 */
function ghostPath(from, to, options = {}) {
  if (!ghostCursorAvailable || !ghostCursorModule.path) return null;

  try {
    return ghostCursorModule.path(from, to, options);
  } catch {
    return null;
  }
}

/**
 * Resolve ghost-cursor settings from site config and CLI flags.
 * Returns null if ghost-cursor should not be used.
 *
 * @param {object} siteConfig - Per-site JSON configuration
 * @param {boolean} globalGhostCursor - CLI --ghost-cursor flag
 * @param {boolean} forceDebug - Debug logging flag
 * @returns {object|null} Resolved ghost-cursor options or null
 */
function resolveGhostCursorConfig(siteConfig, globalGhostCursor, forceDebug) {
  const enabled = globalGhostCursor || siteConfig.cursor_mode === 'ghost';

  if (!enabled) return null;

  if (!ghostCursorAvailable) {
    console.warn(formatLogMessage('warn', '[ghost-cursor] cursor_mode "ghost" requested but ghost-cursor package is not installed. Run: npm install ghost-cursor'));
    return null;
  }

  return {
    moveSpeed: siteConfig.ghost_cursor_speed || undefined,
    hesitate: siteConfig.ghost_cursor_hesitate ?? 50,
    overshootThreshold: siteConfig.ghost_cursor_overshoot || undefined,
    duration: siteConfig.ghost_cursor_duration || siteConfig.interact_duration || 2000,
    forceDebug
  };
}

module.exports = {
  isGhostCursorAvailable,
  createGhostCursor,
  ghostMove,
  ghostClick,
  ghostRandomMove,
  ghostPath,
  resolveGhostCursorConfig
};
