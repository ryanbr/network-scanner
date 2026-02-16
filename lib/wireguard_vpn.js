// === WireGuard VPN Module ===
// Per-site VPN configuration for network scanner
// Manages WireGuard interfaces, routing, and lifecycle

const { execSync, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { formatLogMessage } = require('./colorize');

/**
 * Fetch external IP address through the active tunnel
 * @param {string} interfaceName - WireGuard interface name (optional)
 * @returns {string|null} External IP or null
 */
function getExternalIP(interfaceName) {
  const services = ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com'];
  for (const service of services) {
    try {
      const iface = interfaceName ? `--interface ${interfaceName}` : '';
      return execSync(`curl -s -m 5 ${iface} ${service}`, { encoding: 'utf8', timeout: 8000 }).trim();
    } catch {}
  }
  return null;
}

// Track active interfaces for cleanup
const activeInterfaces = new Map();

// Temp config directory for inline configs
const TEMP_CONFIG_DIR = '/tmp/nwss-wireguard';

/**
 * Validate WireGuard availability on the system
 * @returns {Object} { isAvailable, version, error }
 */
function validateWireGuardAvailability() {
  try {
    const version = execSync('wg --version 2>&1', { encoding: 'utf8' }).trim();
    // Check wg-quick is also available
    execSync('which wg-quick', { encoding: 'utf8' });
    return { isAvailable: true, version };
  } catch (error) {
    return {
      isAvailable: false,
      error: 'WireGuard not found. Install with: sudo apt install wireguard'
    };
  }
}

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
    // Extract name from /etc/wireguard/wg-example.conf ? wg-example
    return path.basename(vpnConfig.config, '.conf');
  }
  // Auto-generate from index
  const index = activeInterfaces.size;
  return `wg-nwss${index}`;
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
      console.log(formatLogMessage('debug', `[vpn] Interface ${interfaceName} already active`));
    }
    return { success: true, interface: interfaceName, alreadyActive: true };
  }

  try {
    // wg-quick accepts a config path or interface name in /etc/wireguard/
    execSync(`wg-quick up "${configPath}"`, {
      encoding: 'utf8',
      timeout: 15000
    });

    activeInterfaces.set(interfaceName, {
      configPath,
      startedAt: Date.now(),
      sites: new Set()
    });

    if (forceDebug) {
      console.log(formatLogMessage('debug', `[vpn] Interface ${interfaceName} is up`));
    }

    const externalIP = getExternalIP(interfaceName);
    return { success: true, interface: interfaceName, externalIP };
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
    execSync(`wg-quick down "${info.configPath}"`, {
      encoding: 'utf8',
      timeout: 10000
    });

    activeInterfaces.delete(interfaceName);

    // Clean up temp config if it was inline
    const tempPath = path.join(TEMP_CONFIG_DIR, `${interfaceName}.conf`);
    if (fs.existsSync(tempPath)) {
      try { fs.unlinkSync(tempPath); } catch {}
    }

    if (forceDebug) {
      console.log(formatLogMessage('debug', `[vpn] Interface ${interfaceName} is down`));
    }

    return { success: true };
  } catch (error) {
    // Force remove from tracking even if wg-quick fails
    activeInterfaces.delete(interfaceName);
    return { success: false, error: error.message.trim() };
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
    // Check interface exists
    execSync(`ip link show ${interfaceName}`, { encoding: 'utf8', timeout: 3000 });

    // Ping through the specific interface
    const result = execSync(
      `ping -c 1 -W 5 -I ${interfaceName} ${testHost} 2>&1`,
      { encoding: 'utf8', timeout: 8000 }
    );

    const latencyMatch = result.match(/time=([0-9.]+)\s*ms/);
    const latencyMs = latencyMatch ? parseFloat(latencyMatch[1]) : null;

    if (forceDebug) {
      console.log(formatLogMessage('debug',
        `[vpn] ${interfaceName} connected (${latencyMs ? latencyMs + 'ms' : 'ok'})`
      ));
    }

    return { connected: true, latencyMs };
  } catch (error) {
    if (forceDebug) {
      console.log(formatLogMessage('debug',
        `[vpn] ${interfaceName} health check failed: ${error.message.split('\n')[0]}`
      ));
    }
    return { connected: false, error: error.message.split('\n')[0] };
  }
}

/**
 * Get WireGuard status for an interface
 * @param {string} interfaceName - Interface name
 * @returns {Object} Parsed wg show output
 */
function getInterfaceStatus(interfaceName) {
  try {
    const output = execSync(`wg show ${interfaceName}`, {
      encoding: 'utf8',
      timeout: 5000
    });

    const status = { interface: interfaceName, raw: output };

    // Parse key fields
    const endpointMatch = output.match(/endpoint:\s*(.+)/);
    const transferMatch = output.match(/transfer:\s*(.+)/);
    const handshakeMatch = output.match(/latest handshake:\s*(.+)/);
    const allowedMatch = output.match(/allowed ips:\s*(.+)/);

    if (endpointMatch) status.endpoint = endpointMatch[1].trim();
    if (transferMatch) status.transfer = transferMatch[1].trim();
    if (handshakeMatch) status.latestHandshake = handshakeMatch[1].trim();
    if (allowedMatch) status.allowedIps = allowedMatch[1].trim();

    return status;
  } catch (error) {
    return { interface: interfaceName, error: error.message.split('\n')[0] };
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

  return {
    config: vpnConfig.config || null,
    config_inline: vpnConfig.config_inline || null,
    interface: vpnConfig.interface || null,
    health_check: vpnConfig.health_check !== false,
    test_host: vpnConfig.test_host || '1.1.1.1',
    retry: vpnConfig.retry !== false,
    max_retries: vpnConfig.max_retries || 2
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
        `[vpn] Retry ${attempt - 1}/${vpnConfig.max_retries} for ${interfaceName}`
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
      `[vpn] ${interfaceName} still used by ${info.sites.size} site(s), keeping up`
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
      `[vpn] Disconnected ${results.tornDown} interface(s)`
    ));
  }

  return results;
}

/**
 * Get summary of all active VPN interfaces
 * @returns {Array} Array of interface status objects
 */
function getActiveInterfaces() {
  const interfaces = [];

  for (const [name, info] of activeInterfaces) {
    const status = getInterfaceStatus(name);
    interfaces.push({
      name,
      configPath: info.configPath,
      uptime: Math.round((Date.now() - info.startedAt) / 1000),
      sites: Array.from(info.sites),
      ...status
    });
  }

  return interfaces;
}

module.exports = {
  validateWireGuardAvailability,
  validateVpnConfig,
  normalizeVpnConfig,
  connectForSite,
  disconnectForSite,
  disconnectAll,
  checkConnection,
  getInterfaceStatus,
  getActiveInterfaces,
  // Low-level (for testing or advanced use)
  interfaceUp,
  interfaceDown,
  resolveInterfaceName,
  hasRootPrivileges
};