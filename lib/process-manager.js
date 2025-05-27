// === Process Management and Cleanup Module ===
// This module handles graceful shutdown, cleanup, and process management for the network scanner script.
// It provides methods to register cleanup handlers, manage timeouts, and ensure clean exits.

/**
 * ProcessManager class handles process lifecycle and cleanup operations.
 * Supports graceful shutdown, timeout management, and resource cleanup.
 */
class ProcessManager {
  constructor() {
    this.debugMode = false;
    this.cleanupHandlers = [];
    this.isShuttingDown = false;
    this.forceExitTimeout = null;
    this.resources = new Map(); // Track resources for cleanup
    this.exitCode = 0;
    this.shutdownReason = null;
    
    // Statistics
    this.stats = {
      startTime: Date.now(),
      shutdownInitiated: null,
      cleanupHandlersRun: 0,
      resourcesCleaned: 0,
      gracefulShutdown: false
    };

    // Setup signal handlers
    this.setupSignalHandlers();
  }

  /**
   * Initialize the process manager
   * @param {boolean} debugMode - Enable debug logging
   */
  initialize(debugMode = false) {
    this.debugMode = debugMode;
    this.stats.startTime = Date.now();
    
    if (this.debugMode) {
      console.log(`[debug][process] Process manager initialized with PID ${process.pid}`);
    }
  }

  /**
   * Setup signal handlers for graceful shutdown
   */
  setupSignalHandlers() {
    // Handle Ctrl+C (SIGINT)
    process.on('SIGINT', () => {
      this.initiateShutdown('SIGINT', 0);
    });

    // Handle termination request (SIGTERM)
    process.on('SIGTERM', () => {
      this.initiateShutdown('SIGTERM', 0);
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error(`[error][process] Uncaught exception: ${error.message}`);
      if (this.debugMode) {
        console.error(error.stack);
      }
      this.initiateShutdown('uncaughtException', 1);
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error(`[error][process] Unhandled promise rejection: ${reason}`);
      if (this.debugMode) {
        console.error('Promise:', promise);
      }
      this.initiateShutdown('unhandledRejection', 1);
    });

    // Handle warnings (for debugging)
    if (this.debugMode) {
      process.on('warning', (warning) => {
        console.warn(`[warn][process] Node.js warning: ${warning.message}`);
      });
    }
  }

  /**
   * Register a cleanup handler to be called during shutdown
   * @param {function} handler - Cleanup function to register
   * @param {string} name - Name for the handler (for debugging)
   */
  registerCleanupHandler(handler, name = 'anonymous') {
    if (typeof handler !== 'function') {
      throw new Error('Cleanup handler must be a function');
    }

    this.cleanupHandlers.push({
      handler,
      name,
      registeredAt: Date.now()
    });

    if (this.debugMode) {
      console.log(`[debug][process] Registered cleanup handler: ${name}`);
    }
  }

  /**
   * Register a resource for cleanup tracking
   * @param {string} id - Unique identifier for the resource
   * @param {object} resource - The resource object
   * @param {function} cleanupFn - Function to clean up the resource
   */
  registerResource(id, resource, cleanupFn) {
    this.resources.set(id, {
      resource,
      cleanupFn,
      registeredAt: Date.now()
    });

    if (this.debugMode) {
      console.log(`[debug][process] Registered resource: ${id}`);
    }
  }

  /**
   * Unregister a resource (when manually cleaned up)
   * @param {string} id - Resource identifier
   */
  unregisterResource(id) {
    if (this.resources.has(id)) {
      this.resources.delete(id);
      if (this.debugMode) {
        console.log(`[debug][process] Unregistered resource: ${id}`);
      }
    }
  }

  /**
   * Initiate graceful shutdown
   * @param {string} reason - Reason for shutdown
   * @param {number} exitCode - Exit code to use
   * @param {number} timeout - Maximum time to wait for cleanup (ms)
   */
  async initiateShutdown(reason = 'manual', exitCode = 0, timeout = 10000) {
    if (this.isShuttingDown) {
      if (this.debugMode) {
        console.log(`[debug][process] Shutdown already in progress, ignoring additional request`);
      }
      return;
    }

    this.isShuttingDown = true;
    this.shutdownReason = reason;
    this.exitCode = exitCode;
    this.stats.shutdownInitiated = Date.now();

    console.log(`\n[info][process] Initiating graceful shutdown (reason: ${reason})`);

    // Set a force exit timeout as a safety net
    this.forceExitTimeout = setTimeout(() => {
      console.error(`[error][process] Cleanup timeout exceeded, forcing exit`);
      this.forceExit(1);
    }, timeout);

    try {
      // Run cleanup
      await this.runCleanup();
      
      // Clear the force exit timeout
      if (this.forceExitTimeout) {
        clearTimeout(this.forceExitTimeout);
        this.forceExitTimeout = null;
      }

      this.stats.gracefulShutdown = true;
      
      if (!silentMode) {
        const duration = Date.now() - this.stats.startTime;
        console.log(`[info][process] Graceful shutdown completed in ${duration}ms`);
      }

      // Exit the process
      process.exit(this.exitCode);

    } catch (error) {
      console.error(`[error][process] Error during cleanup: ${error.message}`);
      this.forceExit(1);
    }
  }

  /**
   * Run all registered cleanup handlers
   */
  async runCleanup() {
    if (this.debugMode) {
      console.log(`[debug][process] Running ${this.cleanupHandlers.length} cleanup handlers`);
    }

    // Clean up registered resources first
    await this.cleanupResources();

    // Run cleanup handlers in reverse order (LIFO)
    const handlers = [...this.cleanupHandlers].reverse();
    
    for (const { handler, name } of handlers) {
      try {
        if (this.debugMode) {
          console.log(`[debug][process] Running cleanup handler: ${name}`);
        }

        // Support both async and sync handlers
        await Promise.resolve(handler());
        this.stats.cleanupHandlersRun++;

      } catch (error) {
        console.error(`[error][process] Cleanup handler '${name}' failed: ${error.message}`);
        // Continue with other handlers even if one fails
      }
    }
  }

  /**
   * Clean up all registered resources
   */
  async cleanupResources() {
    if (this.debugMode) {
      console.log(`[debug][process] Cleaning up ${this.resources.size} resources`);
    }

    for (const [id, { resource, cleanupFn }] of this.resources) {
      try {
        if (this.debugMode) {
          console.log(`[debug][process] Cleaning up resource: ${id}`);
        }

        await Promise.resolve(cleanupFn(resource));
        this.stats.resourcesCleaned++;

      } catch (error) {
        console.error(`[error][process] Failed to cleanup resource '${id}': ${error.message}`);
      }
    }

    this.resources.clear();
  }

  /**
   * Force exit without cleanup (emergency use only)
   * @param {number} exitCode - Exit code to use
   */
  forceExit(exitCode = 1) {
    console.error(`[error][process] Force exiting with code ${exitCode}`);
    process.exit(exitCode);
  }

  /**
   * Check if the process is currently shutting down
   * @returns {boolean} True if shutdown is in progress
   */
  isShuttingDownNow() {
    return this.isShuttingDown;
  }

  /**
   * Get process statistics
   * @returns {object} Statistics object
   */
  getStats() {
    return {
      ...this.stats,
      uptime: Date.now() - this.stats.startTime,
      registeredHandlers: this.cleanupHandlers.length,
      registeredResources: this.resources.size,
      pid: process.pid,
      memoryUsage: process.memoryUsage()
    };
  }

  /**
   * Create a timeout that automatically cleans up on shutdown
   * @param {function} callback - Function to call when timeout expires
   * @param {number} delay - Delay in milliseconds
   * @param {string} name - Name for debugging
   * @returns {object} Timeout object with clear method
   */
  createManagedTimeout(callback, delay, name = 'timeout') {
    const timeoutId = setTimeout(callback, delay);
    
    // Register cleanup for this timeout
    this.registerCleanupHandler(() => {
      clearTimeout(timeoutId);
    }, `timeout-${name}`);

    return {
      id: timeoutId,
      clear: () => {
        clearTimeout(timeoutId);
      }
    };
  }

  /**
   * Create an interval that automatically cleans up on shutdown
   * @param {function} callback - Function to call on each interval
   * @param {number} delay - Interval delay in milliseconds
   * @param {string} name - Name for debugging
   * @returns {object} Interval object with clear method
   */
  createManagedInterval(callback, delay, name = 'interval') {
    const intervalId = setInterval(callback, delay);
    
    // Register cleanup for this interval
    this.registerCleanupHandler(() => {
      clearInterval(intervalId);
    }, `interval-${name}`);

    return {
      id: intervalId,
      clear: () => {
        clearInterval(intervalId);
      }
    };
  }

  /**
   * Wrap a promise with shutdown detection
   * @param {Promise} promise - Promise to wrap
   * @param {string} name - Name for debugging
   * @returns {Promise} Wrapped promise that rejects if shutdown starts
   */
  wrapPromise(promise, name = 'operation') {
    return new Promise((resolve, reject) => {
      // Check if already shutting down
      if (this.isShuttingDown) {
        reject(new Error(`Operation '${name}' cancelled due to shutdown`));
        return;
      }

      promise
        .then(result => {
          if (this.isShuttingDown) {
            reject(new Error(`Operation '${name}' cancelled due to shutdown`));
          } else {
            resolve(result);
          }
        })
        .catch(error => {
          reject(error);
        });
    });
  }

  /**
   * Sleep for a specified duration, but wake up early if shutdown starts
   * @param {number} ms - Milliseconds to sleep
   * @returns {Promise<boolean>} True if completed normally, false if interrupted by shutdown
   */
  async sleep(ms) {
    return new Promise((resolve) => {
      if (this.isShuttingDown) {
        resolve(false);
        return;
      }

      const timeout = setTimeout(() => {
        resolve(true);
      }, ms);

      // Register cleanup to clear this timeout
      this.registerCleanupHandler(() => {
        clearTimeout(timeout);
        resolve(false);
      }, 'sleep-timeout');
    });
  }

  /**
   * Exit the process gracefully with statistics
   * @param {number} exitCode - Exit code to use
   * @param {string} message - Optional exit message
   */
  async gracefulExit(exitCode = 0, message = null) {
    if (message) {
      console.log(`[info][process] ${message}`);
    }

    await this.initiateShutdown('graceful', exitCode);
  }
}

// Export the class and create a default instance
const processManager = new ProcessManager();

// Make it available globally for convenience
global.processManager = processManager;

module.exports = {
  ProcessManager,
  processManager
};
