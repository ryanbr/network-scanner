// === Color Utility Module (colorize.js) ===
// Centralized color management for nwss.js console output
// Provides consistent theming across all modules

/**
 * Decide whether to emit ANSI color escape sequences. Precedence:
 *   1. FORCE_COLOR env var (any truthy value other than '0'/'false') — on,
 *      even when piped (useful for `node nwss.js | less -R`).
 *   2. NO_COLOR env var (any non-empty value, per https://no-color.org) — off.
 *   3. --no-color / --no-colour CLI flag — off.
 *   4. Non-TTY stdout (piped, redirected to a file) — off, so log files
 *      don't end up with raw escape sequences embedded.
 *   5. Default — on.
 * @returns {boolean} True when colors should be emitted.
 */
function shouldEnableColors() {
  const force = process.env.FORCE_COLOR;
  if (force && force !== '0' && force !== 'false') return true;
  if (process.env.NO_COLOR) return false;
  if (process.argv.includes('--no-color') || process.argv.includes('--no-colour')) return false;
  if (!process.stdout.isTTY) return false;
  return true;
}

// Initialize color support based on command line flags
const enableColors = shouldEnableColors();

/**
 * ANSI color codes object
 * Only contains actual escape sequences if colors are enabled
 */
const colors = {
  // Reset and formatting
  reset: enableColors ? '\x1b[0m' : '',
  bright: enableColors ? '\x1b[1m' : '',
  dim: enableColors ? '\x1b[2m' : '',
  
  // Standard colors
  red: enableColors ? '\x1b[31m' : '',
  green: enableColors ? '\x1b[32m' : '',
  yellow: enableColors ? '\x1b[33m' : '',
  blue: enableColors ? '\x1b[34m' : '',
  magenta: enableColors ? '\x1b[35m' : '',
  cyan: enableColors ? '\x1b[36m' : '',
  white: enableColors ? '\x1b[37m' : '',
  
  // Extended colors
  gray: enableColors ? '\x1b[90m' : '',
  brightRed: enableColors ? '\x1b[91m' : '',
  brightGreen: enableColors ? '\x1b[92m' : '',
  brightYellow: enableColors ? '\x1b[93m' : '',
  brightBlue: enableColors ? '\x1b[94m' : '',
  brightMagenta: enableColors ? '\x1b[95m' : '',
  brightCyan: enableColors ? '\x1b[96m' : '',
  brightWhite: enableColors ? '\x1b[97m' : '',
  
  // Custom orange colors (using 256-color palette)
  orange: enableColors ? '\x1b[38;5;208m' : ''
};

/**
 * Applies color formatting to text if colors are enabled
 * @param {string} text - The text to colorize
 * @param {string} color - The ANSI color code to apply
 * @returns {string} Colored text (or plain text if colors disabled)
 */
function colorize(text, color) {
  return enableColors ? `${color}${text}${colors.reset}` : text;
}

/**
 * Pre-built color functions for common message types
 * These provide semantic coloring for different types of console output
 */
const messageColors = {
  // Status and logging
  debug: (text) => colorize(text, colors.gray),
  info: (text) => colorize(text, colors.blue),
  warn: (text) => colorize(text, colors.yellow),
  error: (text) => colorize(text, colors.red),
  success: (text) => colorize(text, colors.green),
  
  // Process states
  scanning: (text) => colorize(text, colors.yellow),
  loaded: (text) => colorize(text, colors.green),
  processing: (text) => colorize(text, colors.cyan),
  match: (text) => colorize(text, colors.green),
  blocked: (text) => colorize(text, colors.red),
  
  // Special emphasis
  highlight: (text) => colorize(text, colors.brightCyan),
  emphasis: (text) => colorize(text, colors.bright),
  timing: (text) => colorize(text, colors.cyan),
  
  // File operations
  fileOp: (text) => colorize(text, colors.magenta),
  compression: (text) => colorize(text, colors.cyan),

  // Post-processing cleanup summaries (referenced by lib/post-processing.js).
  // Without this entry the callers were falling through to plain console.log
  // because their `if (messageColors && messageColors.cleanup)` guard saw
  // undefined here.
  cleanup: (text) => colorize(text, colors.brightGreen),

  // Cloudflare specific
  cloudflare: (text) => colorize(text, colors.orange)
};

/**
 * Creates a colored tag with consistent formatting
 * Used for status tags like [debug], [info], [warn], etc.
 * @param {string} tag - The tag text (without brackets)
 * @param {string} color - The color to apply
 * @returns {string} Formatted colored tag
 */
function createTag(tag, color) {
  return colorize(`[${tag}]`, color);
}

/**
 * Pre-built tags for common log levels
 */
const tags = {
  debug: createTag('debug', colors.gray),
  info: createTag('info', colors.blue),
  warn: createTag('warn', colors.yellow),
  error: createTag('error', colors.red),
  match: createTag('match', colors.green),
  compare: createTag('compare', colors.blue),
  cloudflare: createTag('cloudflare', colors.orange),
  // proxy: referenced by lib/proxy.js and nwss.js via formatLogMessage('proxy', ...).
  // Was hitting the createTag(tag, colors.white) fallback, allocating a new
  // tag string per call AND rendering as default-white (indistinguishable
  // from regular terminal text). Precomputed in cyan for visibility.
  proxy: createTag('proxy', colors.cyan)
};

/**
 * Formats a complete log message with colored tag and message
 * @param {string} tag - The tag name (debug, info, warn, error, etc.)
 * @param {string} message - The message content
 * @returns {string} Formatted log message
 */
function formatLogMessage(tag, message) {
  const coloredTag = tags[tag] || createTag(tag, colors.white);
  return `${coloredTag} ${message}`;
}

/**
 * Utility function to check if colors are currently enabled
 * @returns {boolean} Current color enable status
 */
function isColorEnabled() {
  return enableColors;
}

/**
 * Creates a rainbow effect for special messages (like completion)
 * @param {string} text - Text to apply rainbow effect to
 * @returns {string} Text with rainbow coloring (if colors enabled)
 */
function rainbow(text) {
  if (!enableColors || text.length === 0) return text;
  
  const rainbowColors = [
    colors.red, colors.yellow, colors.green, 
    colors.cyan, colors.blue, colors.magenta
  ];
  
  return text
    .split('')
    .map((char, index) => {
      const colorIndex = index % rainbowColors.length;
      return `${rainbowColors[colorIndex]}${char}`;
    })
    .join('') + colors.reset;
}

module.exports = {
  // Core functions
  colorize,
  colors,

  // Semantic coloring
  messageColors,
  tags,
  createTag,
  formatLogMessage,

  // Utility functions
  isColorEnabled,
  shouldEnableColors,
  rainbow
};