// === WireGuard VPN Module ===
// Per-site VPN configuration for network scanner
// Manages WireGuard interfaces, routing, and lifecycle

const { spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { formatLogMessage, messageColors } = require('./colorize');
const VPN_TAG = messageColors.processing('[vpn]');

/**
 * Fetch external IP address through the active tunnel
 * @param {string} interfaceName - WireGuard interface name (optional)
 * @returns {string|null} External IP or null
 */
function getExternalIP(interfaceName) {
  const services = ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com'];
  for (const service of services) {
    const args = ['-s', '-m', '5'];
    if (interfaceName) args.push('--interface', interfaceName);
    args.push(service);
    // spawnSync (no shell) so a malicious interfaceName like
    // "wg-foo; rm -rf ~" can't be split into a second command.
    const result = spawnSync('curl', args, { encoding: 'utf8', timeout: 8000 });
    if (result.status === 0 && result.stdout) {
      return result.stdout.trim();
    }
  }
  return null;
}

// Track active interfaces for cleanup
const activeInterfaces = new Map();

// Temp config directory for inline configs
const TEMP_CONFIG_DIR = '/tmp/nwss-wireguard';

/**
 * Check if running with sufficient privileges
 * @returns {boolean}
 */
function hasRootPrivileges() {
  try {
    return process.getuid() === 0;
  } catch {
    return false;
  }
}

/**
 * Resolve interface name from config path or explicit name
 * @param {Object} vpnConfig - VPN configuration object
 * @returns {string} Interface name
 */
function resolveInterfaceName(vpnConfig) {
  if (vpnConfig.interface) {
    return vpnConfig.interface;
  }
  if (vpnConfig.config) {
    // Extract name from /etc/wireguard/wg-example.conf → wg-example
    return path.basename(vpnConfig.config, '.conf');
  }
  // Inline-only config without an explicit interface: derive a stable
  // name from a hash of the content so connect and disconnect resolve
  // to the same name across calls. The old `wg-nwss${activeInterfaces.size}`
  // used the live Map size, so disconnect computed a DIFFERENT name
  // than connect did (size had grown in between) and silently failed
  // to find the entry — the interface would leak until disconnectAll.
  //
  // Truncated SHA-1 to 8 hex chars keeps the total under Linux's
  // 15-char IFNAMSIZ limit ('wg-nwss' = 7 + 8 = 15).
  if (vpnConfig.config_inline) {
    const hash = crypto.createHash('sha1').update(vpnConfig.config_inline).digest('hex').slice(0, 8);
    return `wg-nwss${hash}`;
  }
  // Last resort — should be unreachable if validation ran first.
  return 'wg-nwss-unknown';
}

/**
 * Write inline config to temp file
 * @param {string} interfaceName - Interface name for the file
 * @param {string} configContent - WireGuard config content
 * @returns {string} Path to temp config file
 */
function writeInlineConfig(interfaceName, configContent) {
  if (!fs.existsSync(TEMP_CONFIG_DIR)) {
    fs.mkdirSync(TEMP_CONFIG_DIR, { recursive: true, mode: 0o700 });
  }

  const configPath = path.join(TEMP_CONFIG_DIR, `${interfaceName}.conf`);
  fs.writeFileSync(configPath, configContent, { mode: 0o600 });
  return configPath;
}

/**
 * Bring up a WireGuard interface
 * @param {string} configPath - Path to .conf file (without extension for wg-quick)
 * @param {string} interfaceName - Interface name
 * @param {boolean} forceDebug - Debug logging
 * @returns {Object} { success, interface, error }
 */
function interfaceUp(configPath, interfaceName, forceDebug = false) {
  if (activeInterfaces.has(interfaceName)) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${VPN_TAG} Interface ${interfaceName} already active`));
    }
    return { success: true, interface: interfaceName, alreadyActive: true };
  }

  try {
    // wg-quick accepts a config path or interface name in /etc/wireguard/.
    // spawnSync with arg array (no shell) — configPath comes from user
    // JSON, so naive `sudo wg-quick up "${configPath}"` was vulnerable
    // to a `";rm -rf ~;"` payload escaping the quotes.
    //
    // NOTE: an "already exists" failure here usually means a previous
    // run's teardown failed and left the kernel interface alive. Recover
    // manually with `sudo wg-quick down <name>` or `sudo ip link delete
    // <name>`. A self-heal mechanism was tried (commit e032bde) and
    // reverted because it raced with concurrent nwss processes sharing
    // the same VPN config — process B's self-heal would destroy process
    // A's live interface. Keep the manual-recovery default for safety.
    const upRes = spawnSync('sudo', ['wg-quick', 'up', configPath], {
      encoding: 'utf8',
      timeout: 15000
    });
    if (upRes.error) throw upRes.error;
    if (upRes.status !== 0) {
      throw new Error((upRes.stderr || '').trim() || `wg-quick up exited with status ${upRes.status}`);
    }

    activeInterfaces.set(interfaceName, {
      configPath,
      startedAt: Date.now(),
      sites: new Set()
    });

    if (forceDebug) {
      console.log(formatLogMessage('debug', `${VPN_TAG} Interface ${interfaceName} is up`));
      // Only fetch the external IP when debug-logging would actually
      // display it — getExternalIP runs 3 sequential 8s-timeout curls
      // (~24s worst case of blocking event loop). The result was
      // previously included in the return shape but no caller read
      // it; the work was pure waste outside debug runs.
      const externalIP = getExternalIP(interfaceName);
      if (externalIP) {
        console.log(formatLogMessage('debug', `${VPN_TAG} ${interfaceName} external IP: ${externalIP}`));
      }
    }

    return { success: true, interface: interfaceName };
  } catch (error) {
    return {
      success: false,
      interface: interfaceName,
      error: error.message.trim()
    };
  }
}

/**
 * Bring down a WireGuard interface
 * @param {string} interfaceName - Interface name
 * @param {boolean} forceDebug - Debug logging
 * @returns {Object} { success, error }
 */
function interfaceDown(interfaceName, forceDebug = false) {
  const info = activeInterfaces.get(interfaceName);
  if (!info) {
    return { success: true, alreadyDown: true };
  }

  try {
    // spawnSync with arg array (see interfaceUp comment for rationale).
    const downRes = spawnSync('sudo', ['wg-quick', 'down', info.configPath], {
      encoding: 'utf8',
      timeout: 10000
    });
    if (downRes.error) throw downRes.error;
    if (downRes.status !== 0) {
      throw new Error((downRes.stderr || '').trim() || `wg-quick down exited with status ${downRes.status}`);
    }

    activeInterfaces.delete(interfaceName);

    if (forceDebug) {
      console.log(formatLogMessage('debug', `${VPN_TAG} Interface ${interfaceName} is down`));
    }

    return { success: true };
  } catch (error) {
    // Force remove from tracking even if wg-quick fails
    activeInterfaces.delete(interfaceName);
    return { success: false, error: error.message.trim() };
  } finally {
    // Clean up temp config regardless of wg-quick outcome — a leaked
    // .conf in TEMP_CONFIG_DIR could collide on a re-connect with the
    // same hash-derived interface name, especially after a wg-quick
    // down failure where the kernel interface might persist briefly.
    // Was previously only inside the try block, so failure paths
    // leaked the temp file.
    const tempPath = path.join(TEMP_CONFIG_DIR, `${interfaceName}.conf`);
    if (fs.existsSync(tempPath)) {
      try { fs.unlinkSync(tempPath); } catch {}
    }
  }
}

/**
 * Check if a WireGuard interface is connected and passing traffic
 * @param {string} interfaceName - Interface name
 * @param {string} testHost - Host to ping (default: 1.1.1.1)
 * @param {boolean} forceDebug - Debug logging
 * @returns {Object} { connected, latencyMs, error }
 */
function checkConnection(interfaceName, testHost = '1.1.1.1', forceDebug = false) {
  try {
    // Check interface exists. spawnSync with arg array — interfaceName
    // can come from user JSON (siteConfig.vpn.interface) so the old
    // shell-interpolated `execSync(\`ip link show ${interfaceName}\`)`
    // was injection-vulnerable.
    const linkRes = spawnSync('ip', ['link', 'show', interfaceName], { encoding: 'utf8', timeout: 3000 });
    if (linkRes.status !== 0) {
      throw new Error((linkRes.stderr || '').trim() || `ip link show failed for ${interfaceName}`);
    }

    // Ping through the specific interface. testHost defaults to '1.1.1.1'
    // but can be overridden by user config — same injection concern.
    const pingRes = spawnSync('ping', ['-c', '1', '-W', '5', '-I', interfaceName, testHost], {
      encoding: 'utf8', timeout: 8000
    });
    if (pingRes.status !== 0) {
      // Combine stderr + stdout (no shell `2>&1` available with spawnSync)
      throw new Error((pingRes.stderr || pingRes.stdout || '').split('\n')[0] || `ping failed for ${testHost}`);
    }
    const result = pingRes.stdout;

    const latencyMatch = result.match(/time=([0-9.]+)\s*ms/);
    const latencyMs = latencyMatch ? parseFloat(latencyMatch[1]) : null;

    if (forceDebug) {
      console.log(formatLogMessage('debug',
        `${VPN_TAG} ${interfaceName} connected (${latencyMs ? latencyMs + 'ms' : 'ok'})`
      ));
    }

    return { connected: true, latencyMs };
  } catch (error) {
    if (forceDebug) {
      console.log(formatLogMessage('debug',
        `${VPN_TAG} ${interfaceName} health check failed: ${error.message.split('\n')[0]}`
      ));
    }
    return { connected: false, error: error.message.split('\n')[0] };
  }
}

/**
 * Parse and validate a VPN site config
 * @param {Object|string} vpnConfig - VPN config from site JSON
 * @returns {Object} Normalized config { config, config_inline, interface, health_check, ... }
 */
function normalizeVpnConfig(vpnConfig) {
  // String shorthand: just a path to config
  if (typeof vpnConfig === 'string') {
    return { config: vpnConfig, interface: null, health_check: true };
  }

  if (typeof vpnConfig !== 'object' || vpnConfig === null) {
    return null;
  }

  // Accept non-negative integers only — rejects:
  //   - undefined/null/false (would have hit '|| 2' fallback anyway)
  //   - strings like "3" (the old `|| 2` accepted those, then
  //     `vpnConfig.max_retries + 1` downstream string-concatenated
  //     to "31" and ran 31 retry attempts instead of 4)
  //   - negative numbers / non-integers
  // Explicit 0 IS accepted now ("no retries, fail fast") — the old
  // `|| 2` treated 0 as falsy and silently substituted 2.
  const mr = vpnConfig.max_retries;
  const max_retries = (typeof mr === 'number' && Number.isInteger(mr) && mr >= 0) ? mr : 2;

  return {
    config: vpnConfig.config || null,
    config_inline: vpnConfig.config_inline || null,
    interface: vpnConfig.interface || null,
    health_check: vpnConfig.health_check !== false,
    test_host: vpnConfig.test_host || '1.1.1.1',
    retry: vpnConfig.retry !== false,
    max_retries
  };
}

/**
 * Validate a VPN configuration
 * @param {Object} vpnConfig - Normalized VPN config
 * @returns {Object} { isValid, errors, warnings }
 */
function validateVpnConfig(vpnConfig) {
  const result = { isValid: true, errors: [], warnings: [] };

  if (!vpnConfig) {
    result.isValid = false;
    result.errors.push('VPN configuration is null or invalid');
    return result;
  }

  if (!vpnConfig.config && !vpnConfig.config_inline) {
    result.isValid = false;
    result.errors.push('VPN requires either "config" (path) or "config_inline" (content)');
    return result;
  }

  if (vpnConfig.config && vpnConfig.config_inline) {
    result.warnings.push('Both "config" and "config_inline" provided; "config" takes precedence');
  }

  // F1: Validate user-provided interface name to prevent path traversal via
  // resolveInterfaceName → writeInlineConfig's path.join. Also enforces
  // Linux IFNAMSIZ (15 chars max). User would need to attack their own
  // config (same trust boundary as rest of nwss + must run as root for WG),
  // so this is defensive rather than security-critical — but the validation
  // catches typos that would otherwise produce confusing wg-quick errors.
  if (vpnConfig.interface !== undefined && vpnConfig.interface !== null) {
    if (typeof vpnConfig.interface !== 'string' || !/^[a-zA-Z0-9_-]{1,15}$/.test(vpnConfig.interface)) {
      result.isValid = false;
      result.errors.push(
        `Invalid 'interface' name ${JSON.stringify(vpnConfig.interface)}: ` +
        `must match /^[a-zA-Z0-9_-]{1,15}$/ (Linux IFNAMSIZ limit + path-safe chars)`
      );
    }
  }

  // Validate config file exists
  if (vpnConfig.config) {
    const configPath = vpnConfig.config;
    // Accept both with and without .conf extension
    const pathsToCheck = [configPath, `${configPath}.conf`, `/etc/wireguard/${configPath}.conf`];
    const found = pathsToCheck.some(p => fs.existsSync(p));
    if (!found) {
      result.isValid = false;
      result.errors.push(`Config file not found: ${configPath} (also checked /etc/wireguard/)`);
    }
  }

  // Validate inline config has required sections
  if (vpnConfig.config_inline && !vpnConfig.config) {
    const content = vpnConfig.config_inline;
    if (!content.includes('[Interface]')) {
      result.isValid = false;
      result.errors.push('Inline config missing [Interface] section');
    }
    if (!content.includes('[Peer]')) {
      result.isValid = false;
      result.errors.push('Inline config missing [Peer] section');
    }
    if (!content.includes('PrivateKey')) {
      result.isValid = false;
      result.errors.push('Inline config missing PrivateKey');
    }
  }

  if (!hasRootPrivileges()) {
    result.warnings.push('WireGuard requires root privileges - run with sudo');
  }

  return result;
}

/**
 * Bring up VPN for a site, with health check and retry
 * @param {Object} siteConfig - Site configuration from JSON
 * @param {boolean} forceDebug - Debug logging
 * @returns {Promise<Object>} { success, interface, error }
 */
async function connectForSite(siteConfig, forceDebug = false) {
  const vpnConfig = normalizeVpnConfig(siteConfig.vpn);
  if (!vpnConfig) {
    return { success: false, error: 'Invalid VPN configuration' };
  }

  const validation = validateVpnConfig(vpnConfig);
  if (!validation.isValid) {
    return { success: false, error: validation.errors.join('; ') };
  }

  const interfaceName = resolveInterfaceName(vpnConfig);

  // Resolve config path
  let configPath;
  if (vpnConfig.config) {
    configPath = vpnConfig.config;
    // Resolve wg-quick style: if no path separators, look in /etc/wireguard/
    if (!configPath.includes('/')) {
      const etcPath = `/etc/wireguard/${configPath}.conf`;
      if (fs.existsSync(etcPath)) {
        configPath = etcPath;
      }
    }
  } else {
    configPath = writeInlineConfig(interfaceName, vpnConfig.config_inline);
  }

  const maxAttempts = vpnConfig.retry ? vpnConfig.max_retries + 1 : 1;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (forceDebug && attempt > 1) {
      console.log(formatLogMessage('debug',
        `${VPN_TAG} Retry ${attempt - 1}/${vpnConfig.max_retries} for ${interfaceName}`
      ));
    }

    // Ensure interface is down before retry
    if (attempt > 1) {
      interfaceDown(interfaceName, forceDebug);
      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    const upResult = interfaceUp(configPath, interfaceName, forceDebug);
    if (!upResult.success) {
      if (attempt === maxAttempts) {
        return upResult;
      }
      continue;
    }

    // Track which site is using this interface
    const info = activeInterfaces.get(interfaceName);
    if (info && siteConfig.url) {
      info.sites.add(siteConfig.url);
    }

    // Health check
    if (vpnConfig.health_check) {
      // Brief settle time for interface
      await new Promise(resolve => setTimeout(resolve, 1500));

      const health = checkConnection(interfaceName, vpnConfig.test_host, forceDebug);
      if (!health.connected) {
        if (attempt === maxAttempts) {
          interfaceDown(interfaceName, forceDebug);
          return {
            success: false,
            interface: interfaceName,
            error: `Health check failed: ${health.error}`
          };
        }
        continue;
      }
    }

    return { success: true, interface: interfaceName };
  }

  return { success: false, interface: interfaceName, error: 'All attempts failed' };
}

/**
 * Disconnect VPN for a site
 * If multiple sites share the interface, only removes the site reference
 * @param {Object} siteConfig - Site configuration from JSON
 * @param {boolean} forceDebug - Debug logging
 * @returns {Object} { success, tornDown, error }
 */
function disconnectForSite(siteConfig, forceDebug = false) {
  const vpnConfig = normalizeVpnConfig(siteConfig.vpn);
  if (!vpnConfig) return { success: true, tornDown: false };

  const interfaceName = resolveInterfaceName(vpnConfig);
  const info = activeInterfaces.get(interfaceName);

  if (!info) {
    return { success: true, tornDown: false };
  }

  // Remove this site from the interface's site set
  if (siteConfig.url) {
    info.sites.delete(siteConfig.url);
  }

  // Only tear down if no other sites are using it
  if (info.sites.size === 0) {
    const result = interfaceDown(interfaceName, forceDebug);
    return { success: result.success, tornDown: true, error: result.error };
  }

  if (forceDebug) {
    console.log(formatLogMessage('debug',
      `${VPN_TAG} ${interfaceName} still used by ${info.sites.size} site(s), keeping up`
    ));
  }

  return { success: true, tornDown: false };
}

/**
 * Tear down all active WireGuard interfaces
 * Call on process exit or cleanup
 * @param {boolean} forceDebug - Debug logging
 * @returns {Object} { tornDown, errors }
 */
function disconnectAll(forceDebug = false) {
  const results = { tornDown: 0, errors: [] };

  for (const [interfaceName] of activeInterfaces) {
    const result = interfaceDown(interfaceName, forceDebug);
    if (result.success) {
      results.tornDown++;
    } else {
      results.errors.push({ interface: interfaceName, error: result.error });
    }
  }

  // Clean up temp directory
  if (fs.existsSync(TEMP_CONFIG_DIR)) {
    try { fs.rmSync(TEMP_CONFIG_DIR, { recursive: true, force: true }); } catch {}
  }

  if (forceDebug && results.tornDown > 0) {
    console.log(formatLogMessage('debug',
      `${VPN_TAG} Disconnected ${results.tornDown} interface(s)`
    ));
  }

  return results;
}

// Public surface used by nwss.js. Internal helpers (checkConnection,
// interfaceUp, interfaceDown, resolveInterfaceName, hasRootPrivileges,
// getExternalIP, writeInlineConfig) stay module-private — none had
// external callers. validateWireGuardAvailability, getInterfaceStatus,
// and getActiveInterfaces were removed entirely (zero callers anywhere,
// including no internal ones once their downstream consumers were
// pruned).
module.exports = {
  validateVpnConfig,
  normalizeVpnConfig,
  connectForSite,
  disconnectForSite,
  disconnectAll
};