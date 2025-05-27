// === Page Interaction Simulation Module ===
// This module handles simulated user interactions on web pages.
// It provides methods to simulate realistic mouse movements, clicks, scrolling, and keyboard input.

/**
 * InteractionSimulator class handles realistic simulation of user interactions.
 * Supports mouse movements, clicks, scrolling, hovering, and keyboard input.
 */
class InteractionSimulator {
  constructor() {
    this.debugMode = false;
    this.interactionStats = {
      totalInteractions: 0,
      mouseMovements: 0,
      clicks: 0,
      scrolls: 0,
      hovers: 0,
      keyPresses: 0
    };
  }

  /**
   * Initialize the interaction simulator
   * @param {boolean} debugMode - Enable debug logging
   */
  initialize(debugMode = false) {
    this.debugMode = debugMode;
    
    if (this.debugMode) {
      console.log(`[debug][interaction] Interaction simulator initialized`);
    }
  }

  /**
   * Generate random coordinates within viewport bounds
   * @param {object} viewport - Viewport dimensions {width, height}
   * @param {object} options - Options for coordinate generation
   * @returns {object} Random coordinates {x, y}
   */
  generateRandomCoordinates(viewport = { width: 1920, height: 1080 }, options = {}) {
    const {
      marginX = 50,
      marginY = 50,
      maxX = viewport.width - marginX,
      maxY = viewport.height - marginY
    } = options;

    return {
      x: Math.floor(Math.random() * (maxX - marginX)) + marginX,
      y: Math.floor(Math.random() * (maxY - marginY)) + marginY
    };
  }

  /**
   * Simulate realistic mouse movement with easing
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {object} from - Starting coordinates {x, y}
   * @param {object} to - Ending coordinates {x, y}
   * @param {object} options - Movement options
   * @returns {Promise<boolean>} Success status
   */
  async simulateMouseMovement(page, from, to, options = {}) {
    const {
      steps = 10,
      delayRange = [50, 200],
      curve = 'ease-in-out'
    } = options;

    try {
      if (this.debugMode) {
        console.log(`[debug][interaction] Moving mouse from (${from.x}, ${from.y}) to (${to.x}, ${to.y})`);
      }

      // Start from the initial position
      await page.mouse.move(from.x, from.y);
      
      // Add slight delay before movement
      await this.randomDelay(delayRange);

      // Simulate curved movement with multiple steps
      await page.mouse.move(to.x, to.y, { steps });
      
      // Add slight delay after movement
      await this.randomDelay(delayRange);

      this.interactionStats.mouseMovements++;
      this.interactionStats.totalInteractions++;
      
      return true;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][interaction] Mouse movement failed: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Simulate mouse clicks with realistic timing
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {object} coordinates - Click coordinates {x, y}
   * @param {object} options - Click options
   * @returns {Promise<boolean>} Success status
   */
  async simulateClick(page, coordinates, options = {}) {
    const {
      button = 'left',
      clickCount = 1,
      delay = [100, 300],
      moveToTarget = true
    } = options;

    try {
      if (this.debugMode) {
        console.log(`[debug][interaction] Clicking at (${coordinates.x}, ${coordinates.y})`);
      }

      // Move to target if requested
      if (moveToTarget) {
        const currentPos = await this.getCurrentMousePosition(page);
        await this.simulateMouseMovement(page, currentPos, coordinates);
      }

      // Simulate click with realistic timing
      await page.mouse.click(coordinates.x, coordinates.y, {
        button,
        clickCount,
        delay: this.getRandomDelay(delay)
      });

      this.interactionStats.clicks++;
      this.interactionStats.totalInteractions++;
      
      return true;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][interaction] Click failed: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Simulate hovering over an element
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {string|object} target - CSS selector or coordinates
   * @param {object} options - Hover options
   * @returns {Promise<boolean>} Success status
   */
  async simulateHover(page, target, options = {}) {
    const {
      duration = [1000, 3000],
      moveBeforeHover = true
    } = options;

    try {
      if (this.debugMode) {
        console.log(`[debug][interaction] Hovering over target:`, target);
      }

      let coordinates;
      
      if (typeof target === 'string') {
        // Target is a CSS selector
        const element = await page.$(target);
        if (!element) {
          if (this.debugMode) {
            console.log(`[debug][interaction] Hover target not found: ${target}`);
          }
          return false;
        }
        
        const box = await element.boundingBox();
        if (!box) {
          return false;
        }
        
        coordinates = {
          x: box.x + box.width / 2,
          y: box.y + box.height / 2
        };
      } else {
        // Target is coordinates
        coordinates = target;
      }

      // Move to hover position if requested
      if (moveBeforeHover) {
        const currentPos = await this.getCurrentMousePosition(page);
        await this.simulateMouseMovement(page, currentPos, coordinates);
      }

      // Hover using Puppeteer's hover method for CSS selector or mouse position for coordinates
      if (typeof target === 'string') {
        await page.hover(target);
      } else {
        await page.mouse.move(coordinates.x, coordinates.y);
      }

      // Stay hovered for a realistic duration
      await this.randomDelay(duration);

      this.interactionStats.hovers++;
      this.interactionStats.totalInteractions++;
      
      return true;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][interaction] Hover failed: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Simulate scrolling on the page
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {object} options - Scroll options
   * @returns {Promise<boolean>} Success status
   */
  async simulateScroll(page, options = {}) {
    const {
      direction = 'down',
      amount = 500,
      steps = 5,
      delayBetweenSteps = [100, 300]
    } = options;

    try {
      if (this.debugMode) {
        console.log(`[debug][interaction] Scrolling ${direction} by ${amount}px in ${steps} steps`);
      }

      const stepAmount = amount / steps;
      const deltaY = direction === 'down' ? stepAmount : -stepAmount;

      for (let i = 0; i < steps; i++) {
        await page.mouse.wheel({ deltaY });
        await this.randomDelay(delayBetweenSteps);
      }

      this.interactionStats.scrolls++;
      this.interactionStats.totalInteractions++;
      
      return true;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][interaction] Scroll failed: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Simulate keyboard input
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {string} text - Text to type
   * @param {object} options - Typing options
   * @returns {Promise<boolean>} Success status
   */
  async simulateKeyboardInput(page, text, options = {}) {
    const {
      delay = [50, 150],
      pressEnter = false
    } = options;

    try {
      if (this.debugMode) {
        console.log(`[debug][interaction] Typing text: "${text}"`);
      }

      await page.keyboard.type(text, { delay: this.getRandomDelay(delay) });
      
      if (pressEnter) {
        await page.keyboard.press('Enter');
      }

      this.interactionStats.keyPresses += text.length;
      this.interactionStats.totalInteractions++;
      
      return true;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][interaction] Keyboard input failed: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Perform basic interaction simulation (original scanner behavior)
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {boolean} enabled - Whether interaction is enabled
   * @param {boolean} disableInteract - Global interaction disable flag
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async performBasicInteraction(page, enabled, disableInteract, currentUrl = 'unknown') {
    if (!enabled || disableInteract) {
      return true; // Interaction not enabled or globally disabled
    }

    try {
      if (this.debugMode) {
        console.log(`[debug][interaction] Starting basic interaction simulation for ${currentUrl}`);
      }

      // Generate random coordinates for interactions
      const viewport = await page.viewport() || { width: 1920, height: 1080 };
      const coords1 = this.generateRandomCoordinates(viewport);
      const coords2 = {
        x: coords1.x + Math.floor(Math.random() * 100) - 50,
        y: coords1.y + Math.floor(Math.random() * 100) - 50
      };
      const clickCoords = {
        x: coords1.x + Math.floor(Math.random() * 50) - 25,
        y: coords1.y + Math.floor(Math.random() * 50) - 25
      };

      // Simulate mouse movements
      await this.simulateMouseMovement(page, coords1, coords2, { steps: 10 });
      
      // Simulate click
      await this.simulateClick(page, clickCoords);
      
      // Simulate hover on body
      await this.simulateHover(page, 'body', { duration: [500, 1500] });

      return true;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][interaction] Basic interaction failed for ${currentUrl}: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Perform advanced interaction simulation
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @param {object} config - Advanced interaction configuration
   * @param {string} currentUrl - Current URL being processed (for logging)
   * @returns {Promise<boolean>} Success status
   */
  async performAdvancedInteraction(page, config, currentUrl = 'unknown') {
    if (!config || typeof config !== 'object') {
      return true; // No advanced interaction configured
    }

    try {
      if (this.debugMode) {
        console.log(`[debug][interaction] Starting advanced interaction simulation for ${currentUrl}`);
      }

      const {
        clicks = [],
        hovers = [],
        scrolls = [],
        keyboardInput = [],
        randomMovements = 0
      } = config;

      // Random mouse movements
      if (randomMovements > 0) {
        const viewport = await page.viewport() || { width: 1920, height: 1080 };
        for (let i = 0; i < randomMovements; i++) {
          const from = this.generateRandomCoordinates(viewport);
          const to = this.generateRandomCoordinates(viewport);
          await this.simulateMouseMovement(page, from, to);
        }
      }

      // Clicks
      for (const clickConfig of clicks) {
        if (typeof clickConfig === 'string') {
          // CSS selector
          await this.simulateHover(page, clickConfig);
          await page.click(clickConfig);
        } else {
          // Coordinates or advanced config
          await this.simulateClick(page, clickConfig.coordinates || clickConfig, clickConfig.options);
        }
      }

      // Hovers
      for (const hoverConfig of hovers) {
        await this.simulateHover(page, hoverConfig.target || hoverConfig, hoverConfig.options);
      }

      // Scrolls
      for (const scrollConfig of scrolls) {
        await this.simulateScroll(page, scrollConfig);
      }

      // Keyboard input
      for (const inputConfig of keyboardInput) {
        if (typeof inputConfig === 'string') {
          await this.simulateKeyboardInput(page, inputConfig);
        } else {
          await this.simulateKeyboardInput(page, inputConfig.text, inputConfig.options);
        }
      }

      return true;

    } catch (error) {
      if (this.debugMode) {
        console.log(`[debug][interaction] Advanced interaction failed for ${currentUrl}: ${error.message}`);
      }
      return false;
    }
  }

  /**
   * Get current mouse position (approximation)
   * @param {import('puppeteer').Page} page - The Puppeteer page instance
   * @returns {Promise<object>} Current mouse coordinates
   */
  async getCurrentMousePosition(page) {
    try {
      // Since Puppeteer doesn't track mouse position, we'll use a reasonable default
      return { x: 100, y: 100 };
    } catch (error) {
      return { x: 100, y: 100 };
    }
  }

  /**
   * Generate a random delay within a range
   * @param {Array|number} range - Delay range [min, max] or fixed value
   * @returns {number} Random delay in milliseconds
   */
  getRandomDelay(range) {
    if (Array.isArray(range)) {
      const [min, max] = range;
      return Math.floor(Math.random() * (max - min)) + min;
    }
    return range;
  }

  /**
   * Wait for a random delay within a range
   * @param {Array|number} range - Delay range [min, max] or fixed value
   * @returns {Promise<void>}
   */
  async randomDelay(range) {
    const delay = this.getRandomDelay(range);
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Get interaction statistics
   * @returns {object} Statistics object
   */
  getStats() {
    return {
      ...this.interactionStats,
      averageInteractionsPerPage: this.interactionStats.totalInteractions / Math.max(1, this.interactionStats.totalInteractions)
    };
  }

  /**
   * Reset interaction statistics
   */
  resetStats() {
    this.interactionStats = {
      totalInteractions: 0,
      mouseMovements: 0,
      clicks: 0,
      scrolls: 0,
      hovers: 0,
      keyPresses: 0
    };
  }

  /**
   * Create a preset configuration for common interaction patterns
   * @param {string} preset - Preset name ('basic', 'browsing', 'form-filling')
   * @returns {object} Configuration object
   */
  getPresetConfig(preset) {
    const presets = {
      basic: {
        randomMovements: 2,
        hovers: [{ target: 'body', options: { duration: [1000, 2000] } }],
        scrolls: [{ direction: 'down', amount: 300 }]
      },
      browsing: {
        randomMovements: 5,
        clicks: ['a', 'button'],
        hovers: [
          { target: 'nav', options: { duration: [500, 1500] } },
          { target: 'main', options: { duration: [1000, 2000] } }
        ],
        scrolls: [
          { direction: 'down', amount: 500, steps: 3 },
          { direction: 'up', amount: 200, steps: 2 }
        ]
      },
      'form-filling': {
        randomMovements: 3,
        clicks: ['input', 'textarea', 'select'],
        keyboardInput: [
          { text: 'test@example.com', options: { delay: [80, 120] } },
          { text: 'Test User', options: { delay: [100, 150] } }
        ],
        hovers: [{ target: 'form', options: { duration: [800, 1200] } }]
      }
    };

    return presets[preset] || presets.basic;
  }
}

// Export the class and create a default instance
const interactionSimulator = new InteractionSimulator();

module.exports = {
  InteractionSimulator,
  interactionSimulator
};
