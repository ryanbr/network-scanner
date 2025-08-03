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
 * - includeTyping: boolean - Enable typing simulation
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
// Fine-tune mouse movement behavior for realism vs. speed
const MOUSE_MOVEMENT = {
  MIN_STEPS: 5,              // Minimum steps for any movement
  DEFAULT_STEPS: 15,         // Default steps for mouse movement
  MAX_STEPS: 30,             // Maximum steps to prevent excessive slowness
  MIN_DELAY: 5,              // Minimum milliseconds between movement steps
  MAX_DELAY: 25,             // Maximum milliseconds between movement steps
  DEFAULT_CURVE: 0.3,        // Default curve intensity (0.0 = straight, 1.0 = very curved)
  DEFAULT_JITTER: 2,         // Default random jitter in pixels
  DISTANCE_STEP_RATIO: 10,   // Pixels per step (controls movement granularity)
  CURVE_INTENSITY_RATIO: 0.01 // Multiplier for curve calculation
};

// === SCROLLING CONSTANTS ===
// Control scrolling behavior - adjust for different site types
const SCROLLING = {
  DEFAULT_AMOUNT: 3,           // Default number of scroll actions
  DEFAULT_SMOOTHNESS: 5,       // Default smoothness (higher = more increments)
  SCROLL_DELTA: 200,           // Pixels to scroll per action
  PAUSE_BETWEEN: 200,          // Milliseconds between scroll actions
  SMOOTH_INCREMENT_DELAY: 20   // Milliseconds between smooth scroll increments
};

// === INTERACTION TIMING CONSTANTS ===
// All timing values in milliseconds - adjust for faster/slower interaction
const TIMING = {
  CLICK_PAUSE_MIN: 100,           // Minimum pause before clicking
  CLICK_PAUSE_MAX: 200,           // Maximum pause before clicking
  POST_CLICK_MIN: 300,            // Minimum pause after clicking
  POST_CLICK_MAX: 500,            // Maximum pause after clicking
  TYPING_MIN_DELAY: 50,           // Minimum delay between keystrokes
  TYPING_MAX_DELAY: 150,          // Maximum delay between keystrokes
  MISTAKE_PAUSE_MIN: 100,         // Minimum pause after typing mistake
  MISTAKE_PAUSE_MAX: 200,         // Maximum pause after typing mistake
  BACKSPACE_DELAY_MIN: 50,        // Minimum delay before backspace
  BACKSPACE_DELAY_MAX: 100,       // Maximum delay before backspace
  DEFAULT_INTERACTION_DURATION: 2000 // Default total interaction time
};

// === ELEMENT INTERACTION CONSTANTS ===
// Safety and behavior settings for element interaction
const ELEMENT_INTERACTION = {
  MAX_ATTEMPTS: 3,           // Maximum attempts to find clickable elements
  TIMEOUT: 2000,             // Timeout for element operations
  TEXT_PREVIEW_LENGTH: 50,   // Characters to capture for element text preview
  MISTAKE_RATE: 0.02         // Probability of typing mistakes (0.02 = 2% chance)
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
    
    do {
      x = Math.floor(Math.random() * (maxX - 2 * marginX)) + marginX;
      y = Math.floor(Math.random() * (maxY - 2 * marginY)) + marginY;
    } while (Math.sqrt((x - centerX) ** 2 + (y - centerY) ** 2) < avoidRadius);
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
  const actualSteps = Math.max(
    MOUSE_MOVEMENT.MIN_STEPS, 
    Math.min(steps, Math.floor(distance / MOUSE_MOVEMENT.DISTANCE_STEP_RATIO))
  );

  for (let i = 0; i <= actualSteps; i++) {
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
      const midpoint = actualSteps / 2;
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
      await new Promise(resolve => setTimeout(resolve, delay));
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
      const scrollDelta = direction === 'down' ? SCROLLING.SCROLL_DELTA : -SCROLLING.SCROLL_DELTA;
      
      // Smooth scrolling by breaking into smaller increments
      for (let j = 0; j < smoothness; j++) {
        await page.mouse.wheel({ deltaY: scrollDelta / smoothness });
        await new Promise(resolve => setTimeout(resolve, SCROLLING.SMOOTH_INCREMENT_DELAY));
      }
      
      if (i < amount - 1) {
        await new Promise(resolve => setTimeout(resolve, pauseBetween));
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
    // Get viewport dimensions for coordinate bounds
    const viewport = await page.viewport();
    const maxX = viewport ? viewport.width : DEFAULT_VIEWPORT.WIDTH;
    const maxY = viewport ? viewport.height : DEFAULT_VIEWPORT.HEIGHT;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        // Find visible, clickable elements
        const elements = await page.evaluate((selectors, avoidWords) => {
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
                    text: text.substring(0, ELEMENT_INTERACTION.TEXT_PREVIEW_LENGTH)
                  });
                }
              }
            });
          });
          
          return clickableElements;
        }, elementTypes, avoidDestructive ? ['delete', 'remove', 'submit', 'buy', 'purchase', 'order'] : []);

        if (elements.length > 0) {
          // Choose a random element to interact with
          const element = elements[Math.floor(Math.random() * elements.length)];
          
          // Move to element and click
          const currentPos = generateRandomCoordinates(maxX, maxY);
          await humanLikeMouseMove(page, currentPos.x, currentPos.y, element.x, element.y);
          
          // Brief pause before clicking
          await new Promise(resolve => setTimeout(resolve, TIMING.CLICK_PAUSE_MIN + Math.random() * TIMING.CLICK_PAUSE_MAX));
          
          await page.mouse.click(element.x, element.y);
          
          // Brief pause after clicking
          await new Promise(resolve => setTimeout(resolve, TIMING.POST_CLICK_MIN + Math.random() * TIMING.POST_CLICK_MAX));
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
 * Simulates realistic typing behavior with human characteristics
 * 
 * TYPING CHARACTERISTICS:
 * - Variable delay between keystrokes
 * - Optional typing mistakes with correction
 * - Realistic backspace timing
 * - Character-by-character typing (not paste)
 * 
 * MISTAKE SIMULATION:
 * - Random wrong characters (2% default rate)
 * - Pause after mistake (human realization delay)
 * - Backspace to correct
 * - Continue with correct character
 * 
 * DEVELOPER NOTES:
 * - Requires an active input field with focus
 * - All typing errors are silently handled
 * - Mistake rate should be low (0.01-0.05) for realism
 * - Use for form filling or search simulation
 * 
 * @param {import('puppeteer').Page} page - Puppeteer page object
 * @param {string} text - Text to type
 * @param {object} options - Typing configuration
 * @param {number} options.minDelay - Minimum delay between keystrokes
 * @param {number} options.maxDelay - Maximum delay between keystrokes
 * @param {boolean} options.mistakes - Enable typing mistakes
 * @param {number} options.mistakeRate - Probability of mistakes (0.0-1.0)
 * 
 * @example
 * // Basic typing
 * await simulateTyping(page, "hello world");
 * 
 * // Slow typing with mistakes
 * await simulateTyping(page, "search query", {
 *   minDelay: 100, maxDelay: 300, mistakes: true, mistakeRate: 0.03
 * });
 * 
 * // Fast typing without mistakes
 * await simulateTyping(page, "username", {
 *   minDelay: 30, maxDelay: 80, mistakes: false
 * });
 */
async function simulateTyping(page, text, options = {}) {
  const {
    minDelay = TIMING.TYPING_MIN_DELAY,
    maxDelay = TIMING.TYPING_MAX_DELAY,
    mistakes = false,
    mistakeRate = ELEMENT_INTERACTION.MISTAKE_RATE
  } = options;

  try {
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      
      // Simulate occasional typing mistakes
      if (mistakes && Math.random() < mistakeRate) {
        const wrongChar = String.fromCharCode(97 + Math.floor(Math.random() * 26));
        await page.keyboard.type(wrongChar);
        await new Promise(resolve => setTimeout(resolve, TIMING.MISTAKE_PAUSE_MIN + Math.random() * TIMING.MISTAKE_PAUSE_MAX));
        await page.keyboard.press('Backspace');
        await new Promise(resolve => setTimeout(resolve, TIMING.BACKSPACE_DELAY_MIN + Math.random() * TIMING.BACKSPACE_DELAY_MAX));
      }
      
      await page.keyboard.type(char);
      
      // Variable delay between keystrokes
      const delay = Math.floor(Math.random() * (maxDelay - minDelay + 1)) + minDelay;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  } catch (typingErr) {
    // Silently handle typing errors
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
 * @param {boolean} options.includeTyping - Enable typing simulation  
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
  const {
    mouseMovements = INTENSITY_SETTINGS.MEDIUM.movements,
    includeScrolling = true,
    includeElementClicks = false,
    includeTyping = false,
    duration = TIMING.DEFAULT_INTERACTION_DURATION,
    intensity = 'medium'
  } = options;

  try {
    // Get viewport dimensions
    const viewport = await page.viewport();
    const maxX = viewport ? viewport.width : DEFAULT_VIEWPORT.WIDTH;
    const maxY = viewport ? viewport.height : DEFAULT_VIEWPORT.HEIGHT;

    if (forceDebug) {
      console.log(`[interaction] Starting enhanced interaction simulation for ${new URL(currentUrl).hostname} (${intensity} intensity)`);
    }

    // Configure intensity settings
    const settings = INTENSITY_SETTINGS[intensity.toUpperCase()] || INTENSITY_SETTINGS.MEDIUM;
    const actualMovements = Math.min(mouseMovements, settings.movements);
    
    // Start with random position
    let currentPos = generateRandomCoordinates(maxX, maxY, { preferEdges: true });
    await page.mouse.move(currentPos.x, currentPos.y);

    const startTime = Date.now();
    const totalDuration = duration * settings.pauseMultiplier;
    const actionInterval = totalDuration / (actualMovements + (includeScrolling ? settings.scrolls : 0));

    // Perform mouse movements
    for (let i = 0; i < actualMovements; i++) {
      const targetPos = generateRandomCoordinates(maxX, maxY, { 
        avoidCenter: i % 2 === 0,
        preferEdges: i % 3 === 0 
      });

      await humanLikeMouseMove(page, currentPos.x, currentPos.y, targetPos.x, targetPos.y, {
        steps: 10 + Math.floor(Math.random() * 15),
        curve: 0.2 + Math.random() * 0.3,
        jitter: 1 + Math.random() * 2
      });

      currentPos = targetPos;

      // Occasional pause
      if (Math.random() < PROBABILITIES.PAUSE_CHANCE) {
        await new Promise(resolve => setTimeout(resolve, TIMING.CLICK_PAUSE_MIN + Math.random() * TIMING.POST_CLICK_MIN));
      }

      // Time-based spacing
      await new Promise(resolve => setTimeout(resolve, actionInterval));
    }

    // Scrolling simulation
    if (includeScrolling) {
      for (let i = 0; i < settings.scrolls; i++) {
        const direction = Math.random() < PROBABILITIES.SCROLL_DOWN_BIAS ? 'down' : 'up';
        await simulateScrolling(page, {
          direction,
          amount: 2 + Math.floor(Math.random() * 3),
          smoothness: 3 + Math.floor(Math.random() * 4)
        });
        
        await new Promise(resolve => setTimeout(resolve, actionInterval));
      }
    }

    // Element interaction
    if (includeElementClicks) {
      await interactWithElements(page, {
        maxAttempts: 2,
        avoidDestructive: true
      });
    }

    // Final hover position
    const finalPos = generateRandomCoordinates(maxX, maxY);
    await humanLikeMouseMove(page, currentPos.x, currentPos.y, finalPos.x, finalPos.y);
    await page.hover('body');

    const elapsedTime = Date.now() - startTime;
    if (forceDebug) {
      console.log(`[interaction] Completed interaction simulation in ${elapsedTime}ms (${actualMovements} movements, ${includeScrolling ? settings.scrolls : 0} scrolls)`);
    }

  } catch (interactionErr) {
    if (forceDebug) {
      console.log(`[interaction] Interaction simulation failed for ${currentUrl}: ${interactionErr.message}`);
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
    
    // Site-specific interaction patterns
    const config = {
      mouseMovements: 3,
      includeScrolling: true,
      includeElementClicks: false,
      includeTyping: false,
      duration: 2000,
      intensity: 'medium'
    };

    // Adjust based on site type
    if (hostname.includes('news') || hostname.includes('blog')) {
      config.includeScrolling = true;
      config.intensity = 'high';
      config.duration = SITE_DURATIONS.NEWS_BLOG;
    } else if (hostname.includes('shop') || hostname.includes('store')) {
      config.includeElementClicks = false; // Avoid accidental purchases
      config.intensity = 'low';
    } else if (hostname.includes('social') || hostname.includes('forum')) {
      config.includeScrolling = true;
      config.mouseMovements = 4;
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
    // Return default config if URL parsing fails
    return {
      mouseMovements: INTENSITY_SETTINGS.MEDIUM.movements,
      includeScrolling: true,
      includeElementClicks: false,
      includeTyping: false,
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
 * simulateTyping: Human-like typing with mistakes
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
  
  // Component functions for custom implementations
  humanLikeMouseMove,
  simulateScrolling,
  interactWithElements,
  simulateTyping,
  generateRandomCoordinates
};