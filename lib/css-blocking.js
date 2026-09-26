/**
 * CSS element blocking — hide elements matching a site's `css_blocked` selectors.
 *
 * Two application points, and both are needed:
 *   - injectCssBlocking() installs the stylesheet through
 *     evaluateOnNewDocument, so it applies before the page's own scripts run and
 *     survives in-page navigations and reloads. This is the one that matters for
 *     anything that reacts to an element being visible.
 *   - applyCssBlockingNow() re-applies after load as a fallback for the case
 *     where the injection did not take (a hostile page replacing document.head,
 *     a CDP failure). It is id-guarded, so running both is not double work.
 *
 * Hiding rather than removing is deliberate: `display: none !important;
 * visibility: hidden !important` leaves the DOM shape intact, so a script that
 * measures its own container does not take a different path because we
 * intervened.
 */

const { formatLogMessage, messageColors } = require('./colorize');

const CSS_BLOCKED_TAG = messageColors.processing('[css_blocked]');

/**
 * The site's usable selector list, or null when there is nothing to block.
 * Centralised so the two call sites cannot disagree about what counts as set --
 * note `css_blocked` is one of the fields normalizeSiteConfig() coerces from a
 * bare string to an array, precisely because this Array.isArray gate would
 * otherwise skip it silently.
 * @param {object} siteConfig - Site config carrying optional `css_blocked`
 * @returns {string[]|null}
 */
function getCssBlockedSelectors(siteConfig) {
  const selectors = siteConfig && siteConfig.css_blocked;
  if (selectors && Array.isArray(selectors) && selectors.length > 0) return selectors;
  return null;
}

/**
 * Install the hiding stylesheet before navigation.
 * @param {object} page - Puppeteer page (not yet navigated)
 * @param {string[]} selectors - Output of getCssBlockedSelectors()
 * @param {object} [options]
 * @param {string} [options.currentUrl] - URL being loaded, for log lines
 * @param {boolean} [options.forceDebug=false] - Verbose logging
 * @returns {Promise<{installed: boolean}>}
 */
async function injectCssBlocking(page, selectors, { currentUrl = '', forceDebug = false } = {}) {
  if (!selectors || selectors.length === 0) return { installed: false };

  if (forceDebug) console.log(formatLogMessage('debug', `CSS element blocking enabled for ${currentUrl}: ${selectors.join(', ')}`));
  try {
    await page.evaluateOnNewDocument(({ selectors: blockedSelectors }) => {
      // Inject CSS to hide blocked elements
      const style = document.createElement('style');
      style.type = 'text/css';
      const cssRules = blockedSelectors.map(selector => `${selector} { display: none !important; visibility: hidden !important; }`).join('\n');
      style.innerHTML = cssRules;

      // Add the style as soon as DOM is available
      if (document.head) {
        document.head.appendChild(style);
      } else {
        document.addEventListener('DOMContentLoaded', () => document.head.appendChild(style));
      }
    }, { selectors });
    return { installed: true };
  } catch (cssErr) {
    console.warn(formatLogMessage('warn', `${CSS_BLOCKED_TAG} Failed to set up CSS element blocking for ${currentUrl}: ${cssErr.message}`));
    return { installed: false };
  }
}

/**
 * Re-apply the hiding stylesheet to the loaded document, as a fallback for an
 * injection that did not take. Id-guarded, so it is a no-op when the
 * pre-navigation injection worked.
 * @param {object} page - Puppeteer page (loaded)
 * @param {string[]} selectors - Output of getCssBlockedSelectors()
 * @param {object} [options]
 * @param {string} [options.currentUrl] - URL being scanned, for log lines
 * @returns {Promise<{applied: boolean}>}
 */
async function applyCssBlockingNow(page, selectors, { currentUrl = '' } = {}) {
  if (!selectors || selectors.length === 0) return { applied: false };
  // FIX: Check page state before evaluation
  if (!page || page.isClosed()) return { applied: false };

  try {
    await page.evaluate((blockedSelectors) => {
      const existingStyle = document.querySelector('#css-blocker-runtime');
      if (!existingStyle) {
        const style = document.createElement('style');
        style.id = 'css-blocker-runtime';
        style.type = 'text/css';
        const cssRules = blockedSelectors.map(selector => `${selector} { display: none !important; visibility: hidden !important; }`).join('\n');
        style.innerHTML = cssRules;
        document.head.appendChild(style);
      }
    }, selectors);
    return { applied: true };
  } catch (cssRuntimeErr) {
    console.warn(formatLogMessage('warn', `${CSS_BLOCKED_TAG} Failed to apply runtime CSS blocking for ${currentUrl}: ${cssRuntimeErr.message}`));
    return { applied: false };
  }
}

module.exports = {
  getCssBlockedSelectors,
  injectCssBlocking,
  applyCssBlockingNow
};
