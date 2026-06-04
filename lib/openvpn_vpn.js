// === OpenVPN Module ===
// Per-site VPN configuration for network scanner
// Manages OpenVPN connections, process lifecycle, and cleanup
// Supports WSL2 and native Linux
//
// NOTE: Like wireguard_vpn.js, OpenVPN modifies system-level routing.
// When running concurrent scans, all traffic routes through the active
// VPN tunnel � not just the site that requested it. For isolated
// per-site VPN with concurrency, a SOCKS proxy approach is needed.

const { execSync, spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { formatLogMessage, messageColors } = require('./colorize');
const OPENVPN_TAG = messageColors.processing('[openvpn]');

/**
 * Fetch external IP address through the active tunnel
 * @param {string} tunDevice - TUN device name (optional)
 * @returns {string|null} External IP or null
 */
function getExternalIP(tunDevice) {
  const services = ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com'];
  for (const service of services) {
    // spawnSync with arg array (no shell) — tunDevice flows from
    // findTunDevice (kernel-assigned /sys/class/net names, practically
    // safe) but the pattern with execSync + interpolation was bad style.
    // Match wireguard_vpn.js's spawn-array approach for consistency.
    const args = ['-s', '-m', '5'];
    if (tunDevice) args.push('--interface', tunDevice);
    args.push(service);
    const result = spawnSync('curl', args, { encoding: 'utf8', timeout: 8000 });
    if (result.status === 0 && result.stdout) {
      return result.stdout.trim();
    }
  }
  return null;
}

// Track active connections: name ? { process, configPath, pid, tunDevice, startedAt, sites }
const activeConnections = new Map();

// Temp directory for auth files and inline configs
const TEMP_DIR = '/tmp/nwss-openvpn';

// Connection timeout (OpenVPN is slower to establish than WireGuard)
const DEFAULT_CONNECT_TIMEOUT = 30000;

// Poll interval when waiting for tunnel
const POLL_INTERVAL = 500;

/**
 * Validate OpenVPN availability on the system
 * @returns {Object} { isAvailable, version, error }
 */
function validateOpenVPNAvailability() {
  try {
    const output = execSync('openvpn --version 2>&1', { encoding: 'utf8', timeout: 5000 });
    // First line contains version, e.g. "OpenVPN 2.5.5 x86_64..."
    const versionLine = output.split('\n')[0].trim();
    const versionMatch = versionLine.match(/OpenVPN\s+(\S+)/);
    const version = versionMatch ? versionMatch[1] : versionLine;
    return { isAvailable: true, version };
  } catch (error) {
    return {
      isAvailable: false,
      error: 'OpenVPN not found. Install with: sudo apt install openvpn'
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
 * Detect if running inside WSL
 * @returns {boolean}
 */
const _isWSL = (() => {
  try {
    const release = fs.readFileSync('/proc/version', 'utf8').toLowerCase();
    return release.includes('microsoft') || release.includes('wsl');
  } catch {
    return false;
  }
})();

function isWSL() {
  return _isWSL;
}

/**
 * Check if TUN device is available (WSL2 may lack it)
 * @returns {Object} { available, error }
 */
function checkTunDevice() {
  // Check /dev/net/tun
  if (fs.existsSync('/dev/net/tun')) {
    return { available: true };
  }

  // Try to create it (requires root)
  if (hasRootPrivileges()) {
    try {
      execSync('mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 600 /dev/net/tun', {
        encoding: 'utf8',
        timeout: 5000
      });
      return { available: true, created: true };
    } catch (err) {
      return {
        available: false,
        error: `Cannot create /dev/net/tun: ${err.message.split('\n')[0]}`
      };
    }
  }

  return {
    available: false,
    error: '/dev/net/tun not found. On WSL2: enable systemd or load tun module with "sudo modprobe tun"'
  };
}

/**
 * Ensure temp directory exists with secure permissions
 */
function ensureTempDir() {
  // 0o700 matches wireguard_vpn.js — other users on the box can't list
  // the dir to discover which connection names exist. Individual files
  // inside are already 0o600 so contents were safe before, but directory
  // listing leaked the connection-name list. Note: mode is only applied
  // on creation; an existing dir from a prior run with mode 0o755 keeps
  // its mode until disconnectAll's rm -rf + next session creates fresh.
  fs.mkdirSync(TEMP_DIR, { recursive: true, mode: 0o700 });
}

/**
 * Write auth credentials to a temp file for --auth-user-pass
 * @param {string} connectionName - Connection identifier
 * @param {string} username - VPN username
 * @param {string} password - VPN password
 * @returns {string} Path to auth file
 */
function writeAuthFile(connectionName, username, password) {
  ensureTempDir();
  const authPath = path.join(TEMP_DIR, `${connectionName}-auth.txt`);
  fs.writeFileSync(authPath, `${username}\n${password}\n`, { mode: 0o600 });
  return authPath;
}

/**
 * Write inline config to temp file
 * @param {string} connectionName - Connection identifier
 * @param {string} configContent - OpenVPN config content
 * @returns {string} Path to temp config file
 */
function writeInlineConfig(connectionName, configContent) {
  ensureTempDir();
  const configPath = path.join(TEMP_DIR, `${connectionName}.ovpn`);
  fs.writeFileSync(configPath, configContent, { mode: 0o600 });
  return configPath;
}

/**
 * Resolve a connection name from config
 * @param {Object} vpnConfig - Normalized VPN config
 * @returns {string} Connection name
 */
function resolveConnectionName(vpnConfig) {
  if (vpnConfig.name) {
    return vpnConfig.name;
  }
  if (vpnConfig.config) {
    return path.basename(vpnConfig.config, '.ovpn');
  }
  // Inline-only config without explicit name: derive a stable name from a
  // hash of the content so connect and disconnect resolve to the same name
  // across calls. The old `nwss-ovpn${activeConnections.size}` used the
  // live Map size, so disconnect computed a DIFFERENT name than connect
  // did (size had grown in between) and silently failed to find the
  // entry — the connection would leak until disconnectAll. Same fix as
  // wireguard_vpn.js commit 478a3ad.
  if (vpnConfig.config_inline) {
    const hash = crypto.createHash('sha1').update(vpnConfig.config_inline).digest('hex').slice(0, 8);
    return `nwss-ovpn${hash}`;
  }
  // Last resort — should be unreachable if validation ran first.
  return 'nwss-ovpn-unknown';
}

/**
 * Find the TUN device created by an OpenVPN process
 * @param {number} pid - OpenVPN process PID
 * @returns {string|null} TUN device name or null
 */
function findTunDevice(pid) {
  try {
    // Check /sys/class/net for tun/tap devices
    const devices = fs.readdirSync('/sys/class/net');
    for (const dev of devices) {
      if (dev.startsWith('tun') || dev.startsWith('tap')) {
        // Verify it's recently created (within last 60s)
        try {
          const flags = fs.readFileSync(`/sys/class/net/${dev}/flags`, 'utf8').trim();
          const flagNum = parseInt(flags, 16);
          // IFF_UP = 0x1, IFF_RUNNING = 0x40
          if (flagNum & 0x1) {
            return dev;
          }
        } catch {
          return dev; // If we can't read flags, still return the device
        }
      }
    }
  } catch {}

  // Fallback: parse ip link
  try {
    const output = execSync('ip -o link show type tun 2>/dev/null || ip link show 2>/dev/null', {
      encoding: 'utf8',
      timeout: 3000
    });
    const match = output.match(/(tun\d+|tap\d+)/);
    if (match) return match[1];
  } catch {}

  return null;
}

/**
 * Wait for OpenVPN to establish connection
 * Monitors log output and TUN device creation
 * @param {Object} child - Spawned child process
 * @param {string} logPath - Path to log file
 * @param {number} timeout - Timeout in milliseconds
 * @param {boolean} forceDebug - Debug logging
 * @returns {Promise<Object>} { connected, tunDevice, error }
 */
function waitForConnection(child, logPath, timeout, forceDebug) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    let resolved = false;

    function done(result) {
      if (resolved) return;
      resolved = true;
      clearInterval(pollTimer);
      resolve(result);
    }

    const pollTimer = setInterval(() => {
      // Timeout check
      if (Date.now() - startTime > timeout) {
        done({ connected: false, error: `Connection timed out after ${timeout / 1000}s` });
        return;
      }

      // Process died
      if (child.exitCode !== null) {
        let lastLines = '';
        try {
          const log = fs.readFileSync(logPath, 'utf8');
          lastLines = log.split('\n').slice(-5).join(' ').trim();
        } catch {}
        done({
          connected: false,
          error: `OpenVPN exited with code ${child.exitCode}${lastLines ? ': ' + lastLines : ''}`
        });
        return;
      }

      // Check log for success indicators
      try {
        if (!fs.existsSync(logPath)) return;
        const log = fs.readFileSync(logPath, 'utf8');

        // Success: "Initialization Sequence Completed"
        if (log.includes('Initialization Sequence Completed')) {
          const tunDevice = findTunDevice(child.pid);
          if (forceDebug) {
            console.log(formatLogMessage('debug',
              `${OPENVPN_TAG} Connected (tun: ${tunDevice || 'unknown'}, ${Date.now() - startTime}ms)`
            ));
          }
          done({ connected: true, tunDevice });
          return;
        }

        // Auth failure
        if (log.includes('AUTH_FAILED') || log.includes('auth-failure')) {
          done({ connected: false, error: 'Authentication failed' });
          return;
        }

        // TLS error
        if (log.includes('TLS Error') || log.includes('TLS handshake failed')) {
          done({ connected: false, error: 'TLS handshake failed' });
          return;
        }

        // Connection refused
        if (log.includes('Connection refused') || log.includes('ECONNREFUSED')) {
          done({ connected: false, error: 'Connection refused by server' });
          return;
        }

        // TUN/TAP failure (common on WSL2)
        if (log.includes('Cannot open TUN/TAP') || log.includes('ERROR: Cannot open TUN')) {
          done({
            connected: false,
            error: 'Cannot open TUN/TAP device. On WSL2: run "sudo modprobe tun" first'
          });
          return;
        }

      } catch {}
    }, POLL_INTERVAL);
  });
}

/**
 * Build OpenVPN command arguments
 * @param {string} configPath - Path to .ovpn file
 * @param {Object} vpnConfig - Normalized config
 * @param {string} connectionName - Connection name
 * @param {string} logPath - Log file path
 * @returns {string[]} Array of command arguments
 */
function buildArgs(configPath, vpnConfig, connectionName, logPath) {
  const args = [
    '--config', configPath,
    '--daemon', connectionName,
    '--log', logPath,
    '--writepid', path.join(TEMP_DIR, `${connectionName}.pid`),
    '--connect-retry-max', '3',
    '--connect-timeout', String(Math.round((vpnConfig.connect_timeout || DEFAULT_CONNECT_TIMEOUT) / 1000)),
    '--resolv-retry', '3',
    '--verb', vpnConfig.verbosity || '3'
  ];

  // Auth file
  if (vpnConfig._authFilePath) {
    args.push('--auth-user-pass', vpnConfig._authFilePath);
  }

  // Extra args from config
  if (vpnConfig.extra_args && Array.isArray(vpnConfig.extra_args)) {
    args.push(...vpnConfig.extra_args);
  }

  // WSL2-specific: force tun device type if needed
  if (isWSL() && !vpnConfig.extra_args?.some(a => a.includes('dev-type'))) {
    args.push('--dev-type', 'tun');
  }

  return args;
}

/**
 * Start an OpenVPN connection
 * @param {string} configPath - Path to .ovpn file
 * @param {Object} vpnConfig - Normalized config
 * @param {boolean} forceDebug - Debug logging
 * @returns {Promise<Object>} { success, connection, tunDevice, error }
 */
async function startConnection(configPath, vpnConfig, forceDebug = false) {
  const connectionName = resolveConnectionName(vpnConfig);

  if (activeConnections.has(connectionName)) {
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${OPENVPN_TAG} ${connectionName} already active`));
    }
    const existing = activeConnections.get(connectionName);
    return { success: true, connection: connectionName, tunDevice: existing.tunDevice, alreadyActive: true };
  }

  // Kill any stale processes from a previous run using this config.
  // spawnSync with arg array (no shell) — connectionName flows from
  // user config (vpnConfig.name). Naive shell interpolation here was
  // vulnerable to '`; rm -rf ~; #' style injection.
  const pkillRes = spawnSync('sudo', ['pkill', '-TERM', '-f', `openvpn.*${connectionName}`], {
    encoding: 'utf8', timeout: 3000
  });
  // Only sleep if pkill actually matched + killed something (status 0).
  // pkill exits 1 when no processes match — pre-execSync code threw on
  // non-zero and the surrounding try/catch swallowed it, so the sleep
  // never ran in the no-stale-process case. With spawnSync (no throw
  // on non-zero), we have to gate this explicitly to preserve the same
  // behavior — otherwise every fresh connect would waste 1s of
  // blocking event loop.
  if (pkillRes.status === 0) {
    spawnSync('sleep', ['1'], { timeout: 3000 });
  }

  ensureTempDir();
  const logPath = path.join(TEMP_DIR, `${connectionName}.log`);

  // Clean stale log
  try { fs.unlinkSync(logPath); } catch {}

  // Pre-create log file writable by all so sudo openvpn can write and user can read
  try { fs.writeFileSync(logPath, '', { mode: 0o666 }); } catch {}

  const args = buildArgs(configPath, vpnConfig, connectionName, logPath);

  if (forceDebug) {
    console.log(formatLogMessage('debug', `${OPENVPN_TAG} Starting: openvpn ${args.join(' ')}`));
  }

  // Spawn OpenVPN — it daemonizes itself via --daemon, but we spawn
  // without --daemon so we can track the process directly
  // Remove --daemon and its argument from args, run in foreground
  const fgArgs = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--daemon') {
      i++; // Skip the daemon name argument
      continue;
    }
    fgArgs.push(args[i]);
  }

  const child = spawn('sudo', ['openvpn', ...fgArgs], {
    stdio: ['ignore', 'ignore', 'ignore'],
    detached: false
  });

  // Handle spawn error
  if (!child.pid) {
    return { success: false, connection: connectionName, error: 'Failed to spawn openvpn process' };
  }

  const timeout = vpnConfig.connect_timeout || DEFAULT_CONNECT_TIMEOUT;
  const result = await waitForConnection(child, logPath, timeout, forceDebug);

  if (!result.connected) {
    // Kill the process if still running
    try { child.kill('SIGTERM'); } catch {}
    // C2: check exitCode/signalCode before SIGKILL — child.kill uses the
    // captured PID, and Linux PIDs can be reused. If the process already
    // exited in the 3s window, a reused PID could belong to an unrelated
    // process that we'd then SIGKILL. unref() lets the event loop exit
    // naturally instead of waiting on this background cleanup timer.
    const sigkillTimer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) {
        try { child.kill('SIGKILL'); } catch {}
      }
    }, 3000);
    if (typeof sigkillTimer.unref === 'function') sigkillTimer.unref();
    return { success: false, connection: connectionName, error: result.error };
  }

  activeConnections.set(connectionName, {
    process: child,
    pid: child.pid,
    configPath,
    logPath,
    tunDevice: result.tunDevice,
    startedAt: Date.now(),
    sites: new Set()
  });

  return { success: true, connection: connectionName, tunDevice: result.tunDevice };
}

/**
 * Stop an OpenVPN connection
 * @param {string} connectionName - Connection identifier
 * @param {boolean} forceDebug - Debug logging
 * @returns {Object} { success, error }
 */
function stopConnection(connectionName, forceDebug = false) {
  const info = activeConnections.get(connectionName);
  if (!info) {
    return { success: true, alreadyDown: true };
  }

  try {
    // Find the actual openvpn PID (child of sudo) and kill it.
    // spawnSync with arg array — connectionName from user config, naive
    // shell interpolation was vulnerable to ';rm -rf ~' style injection.
    spawnSync('sudo', ['pkill', '-TERM', '-f', `openvpn.*${connectionName}`], {
      encoding: 'utf8', timeout: 3000
    });

    const killed = waitForProcessExit(info.pid, 5000);
    if (!killed) {
      spawnSync('sudo', ['pkill', '-9', '-f', `openvpn.*${connectionName}`], {
        encoding: 'utf8', timeout: 3000
      });
    }
  } catch (killErr) {
    // Process may already be dead
    if (forceDebug) {
      console.log(formatLogMessage('debug', `${OPENVPN_TAG} Kill error (may be already dead): ${killErr.message}`));
    }
  }

  activeConnections.delete(connectionName);

  // Clean up temp files for this connection
  cleanupConnectionFiles(connectionName);

  if (forceDebug) {
    console.log(formatLogMessage('debug', `${OPENVPN_TAG} ${connectionName} stopped`));
  }

  return { success: true };
}

/**
 * Synchronously wait for process to exit
 * @param {number} pid - Process ID
 * @param {number} timeout - Max wait time in ms
 * @returns {boolean} True if process exited
 */
function waitForProcessExit(pid, timeout) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      // Signal 0 tests if process exists
      process.kill(pid, 0);
      // Still alive, wait
      execSync('sleep 0.2', { timeout: 1000 });
    } catch {
      // Process gone
      return true;
    }
  }
  return false;
}

/**
 * Clean up temp files for a connection
 * @param {string} connectionName - Connection identifier
 */
function cleanupConnectionFiles(connectionName) {
  const filesToClean = [
    path.join(TEMP_DIR, `${connectionName}.ovpn`),
    path.join(TEMP_DIR, `${connectionName}.log`),
    path.join(TEMP_DIR, `${connectionName}.pid`),
    path.join(TEMP_DIR, `${connectionName}-auth.txt`)
  ];

  for (const file of filesToClean) {
    try { fs.unlinkSync(file); } catch {}
  }
}

/**
 * Check if an OpenVPN connection is alive and passing traffic
 * @param {string} connectionName - Connection identifier
 * @param {string} testHost - Host to ping
 * @param {boolean} forceDebug - Debug logging
 * @returns {Object} { connected, latencyMs, error }
 */
function checkConnection(connectionName, testHost = '1.1.1.1', forceDebug = false) {
  const info = activeConnections.get(connectionName);
  if (!info) {
    return { connected: false, error: 'Connection not found' };
  }

  // Check process is alive
  if (info.process && info.process.exitCode !== null) {
    return { connected: false, error: `OpenVPN process exited with code ${info.process.exitCode}` };
  }

  // Ping through the tunnel interface. spawnSync with arg array —
  // testHost flows from user config (vpnConfig.test_host), naive shell
  // interpolation was vulnerable to '1.1.1.1; rm -rf ~' style injection.
  try {
    const iface = info.tunDevice || 'tun0';
    const pingRes = spawnSync('ping', ['-c', '1', '-W', '5', '-I', iface, testHost], {
      encoding: 'utf8', timeout: 8000
    });
    if (pingRes.status !== 0) {
      throw new Error((pingRes.stderr || pingRes.stdout || '').split('\n')[0] || `ping failed for ${testHost}`);
    }
    const result = pingRes.stdout;

    const latencyMatch = result.match(/time=([0-9.]+)\s*ms/);
    const latencyMs = latencyMatch ? parseFloat(latencyMatch[1]) : null;

    if (forceDebug) {
      console.log(formatLogMessage('debug',
        `${OPENVPN_TAG} ${connectionName} connected (${latencyMs ? latencyMs + 'ms' : 'ok'})`
      ));
    }

    return { connected: true, latencyMs };
  } catch (error) {
    if (forceDebug) {
      console.log(formatLogMessage('debug',
        `${OPENVPN_TAG} ${connectionName} health check failed: ${error.message.split('\n')[0]}`
      ));
    }
    return { connected: false, error: error.message.split('\n')[0] };
  }
}

/**
 * Get status of an OpenVPN connection
 * @param {string} connectionName - Connection identifier
 * @returns {Object} Status information
 */
function getConnectionStatus(connectionName) {
  const info = activeConnections.get(connectionName);
  if (!info) {
    return { connection: connectionName, active: false };
  }

  const status = {
    connection: connectionName,
    active: info.process ? info.process.exitCode === null : false,
    pid: info.pid,
    tunDevice: info.tunDevice,
    uptime: Math.round((Date.now() - info.startedAt) / 1000),
    sites: Array.from(info.sites)
  };

  // Read last few lines of log
  try {
    const log = fs.readFileSync(info.logPath, 'utf8');
    const lines = log.trim().split('\n');
    status.lastLog = lines.slice(-3).join('\n');
  } catch {}

  return status;
}

/**
 * Normalize VPN config from site JSON
 * @param {Object|string} ovpnConfig - OpenVPN config from site JSON
 * @returns {Object|null} Normalized config
 */
function normalizeOvpnConfig(ovpnConfig) {
  // String shorthand: path to .ovpn file
  if (typeof ovpnConfig === 'string') {
    return {
      config: ovpnConfig,
      config_inline: null,
      name: null,
      username: null,
      password: null,
      auth_file: null,
      health_check: true,
      test_host: '1.1.1.1',
      retry: true,
      max_retries: 2,
      connect_timeout: DEFAULT_CONNECT_TIMEOUT,
      extra_args: null,
      verbosity: '3'
    };
  }

  if (typeof ovpnConfig !== 'object' || ovpnConfig === null) {
    return null;
  }

  return {
    config: ovpnConfig.config || null,
    config_inline: ovpnConfig.config_inline || null,
    name: ovpnConfig.name || null,
    username: ovpnConfig.username || null,
    password: ovpnConfig.password || null,
    auth_file: ovpnConfig.auth_file || null,
    health_check: ovpnConfig.health_check !== false,
    test_host: ovpnConfig.test_host || '1.1.1.1',
    retry: ovpnConfig.retry !== false,
    max_retries: ovpnConfig.max_retries || 2,
    connect_timeout: ovpnConfig.connect_timeout || DEFAULT_CONNECT_TIMEOUT,
    extra_args: ovpnConfig.extra_args || null,
    verbosity: ovpnConfig.verbosity || '3'
  };
}

/**
 * Validate an OpenVPN configuration
 * @param {Object} ovpnConfig - Normalized config
 * @returns {Object} { isValid, errors, warnings }
 */
function validateOvpnConfig(ovpnConfig) {
  const result = { isValid: true, errors: [], warnings: [] };

  if (!ovpnConfig) {
    result.isValid = false;
    result.errors.push('OpenVPN configuration is null or invalid');
    return result;
  }

  if (!ovpnConfig.config && !ovpnConfig.config_inline) {
    result.isValid = false;
    result.errors.push('Requires either "config" (.ovpn path) or "config_inline" (content)');
    return result;
  }

  if (ovpnConfig.config && ovpnConfig.config_inline) {
    result.warnings.push('Both "config" and "config_inline" provided; "config" takes precedence');
  }

  // D1: Validate user-provided connection 'name' to prevent path traversal
  // via writeAuthFile/writeInlineConfig's path.join, AND to limit the blast
  // radius of any future shell-interpolation that re-introduces ${name}.
  // The current shell calls all use spawnSync with arg arrays (S1 fix), but
  // the regex still blocks values that would confuse pkill's -f pattern
  // match. Length 32 = generous for connection names but bounded.
  // Mirror of wireguard_vpn.js F1 validation.
  if (ovpnConfig.name !== undefined && ovpnConfig.name !== null) {
    if (typeof ovpnConfig.name !== 'string' || !/^[a-zA-Z0-9_-]{1,32}$/.test(ovpnConfig.name)) {
      result.isValid = false;
      result.errors.push(
        `Invalid 'name' value ${JSON.stringify(ovpnConfig.name)}: ` +
        `must match /^[a-zA-Z0-9_-]{1,32}$/ (path-safe chars, max 32)`
      );
    }
  }

  // Validate config file exists
  if (ovpnConfig.config) {
    const configPath = ovpnConfig.config;
    if (!fs.existsSync(configPath)) {
      // Try with .ovpn extension
      if (!fs.existsSync(`${configPath}.ovpn`)) {
        result.isValid = false;
        result.errors.push(`Config file not found: ${configPath}`);
      }
    }
  }

  // Validate inline config
  if (ovpnConfig.config_inline && !ovpnConfig.config) {
    const content = ovpnConfig.config_inline;
    if (!content.includes('remote ') && !content.includes('<connection>')) {
      result.isValid = false;
      result.errors.push('Inline config missing "remote" directive');
    }
  }

  // Auth validation
  if (ovpnConfig.username && !ovpnConfig.password) {
    result.warnings.push('Username provided without password');
  }
  if (ovpnConfig.auth_file && !fs.existsSync(ovpnConfig.auth_file)) {
    result.isValid = false;
    result.errors.push(`Auth file not found: ${ovpnConfig.auth_file}`);
  }

  // Privilege check
  if (!hasRootPrivileges()) {
    result.warnings.push('OpenVPN requires root privileges � run with sudo');
  }

  // WSL checks
  if (isWSL()) {
    result.warnings.push('Running on WSL2 � ensure TUN module is loaded: sudo modprobe tun');
    const tunCheck = checkTunDevice();
    if (!tunCheck.available) {
      result.warnings.push(tunCheck.error);
    }
  }

  return result;
}

/**
 * Connect VPN for a site, with health check and retry
 * @param {Object} siteConfig - Site configuration from JSON
 * @param {boolean} forceDebug - Debug logging
 * @returns {Promise<Object>} { success, connection, tunDevice, error }
 */
async function connectForSite(siteConfig, forceDebug = false) {
  // Platform guard: OpenVPN routing here reads /proc and uses the iproute2 `ip`
  // command, both Linux-only. Fail clearly instead of a cryptic /proc or `ip`
  // error on macOS/Windows. WSL2 reports 'linux' and passes (TUN is checked
  // separately below via isWSL/checkTunDevice).
  if (process.platform !== 'linux') {
    return { success: false, error: `OpenVPN routing is currently Linux-only (needs /proc + the iproute2 'ip' command; not available on ${process.platform}). Run on Linux/WSL2, or remove the 'openvpn' option from the site config.` };
  }

  const ovpnConfig = normalizeOvpnConfig(siteConfig.openvpn);
  if (!ovpnConfig) {
    return { success: false, error: 'Invalid OpenVPN configuration' };
  }

  const validation = validateOvpnConfig(ovpnConfig);
  if (!validation.isValid) {
    return { success: false, error: validation.errors.join('; ') };
  }

  // WSL TUN check
  if (isWSL()) {
    const tunCheck = checkTunDevice();
    if (!tunCheck.available) {
      return { success: false, error: tunCheck.error };
    }
  }

  const connectionName = resolveConnectionName(ovpnConfig);

  // Resolve config path
  let configPath;
  if (ovpnConfig.config) {
    configPath = ovpnConfig.config;
    if (!fs.existsSync(configPath) && fs.existsSync(`${configPath}.ovpn`)) {
      configPath = `${configPath}.ovpn`;
    }
  } else {
    configPath = writeInlineConfig(connectionName, ovpnConfig.config_inline);
  }

  // Handle authentication
  if (ovpnConfig.auth_file) {
    ovpnConfig._authFilePath = ovpnConfig.auth_file;
  } else if (ovpnConfig.username && ovpnConfig.password) {
    ovpnConfig._authFilePath = writeAuthFile(connectionName, ovpnConfig.username, ovpnConfig.password);
  }

  const maxAttempts = ovpnConfig.retry ? ovpnConfig.max_retries + 1 : 1;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (forceDebug && attempt > 1) {
      console.log(formatLogMessage('debug',
        `${OPENVPN_TAG} Retry ${attempt - 1}/${ovpnConfig.max_retries} for ${connectionName}`
      ));
    }

    // Stop previous attempt if retrying
    if (attempt > 1) {
      stopConnection(connectionName, forceDebug);
      await new Promise(resolve => setTimeout(resolve, 3000));
    }

    const startResult = await startConnection(configPath, ovpnConfig, forceDebug);
    if (!startResult.success) {
      if (attempt === maxAttempts) return startResult;
      continue;
    }

    // Track which site uses this connection
    const info = activeConnections.get(connectionName);
    if (info && siteConfig.url) {
      info.sites.add(siteConfig.url);
    }

    // Health check
    if (ovpnConfig.health_check) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      const health = checkConnection(connectionName, ovpnConfig.test_host, forceDebug);
      if (!health.connected) {
        if (attempt === maxAttempts) {
          stopConnection(connectionName, forceDebug);
          return {
            success: false,
            connection: connectionName,
            error: `Health check failed: ${health.error}`
          };
        }
        continue;
      }
    }

    // C3: Only fetch external IP when debug-logging would actually use it.
    // getExternalIP runs up to 3 sequential 8s-timeout curls (~24s worst
    // case of blocking event loop) per VPN connect. Without this gate,
    // every successful OpenVPN connect burned 1-24s on a value that's
    // only displayed in the nwss info log when present — and only
    // genuinely useful for debugging. Matches wireguard_vpn.js's
    // forceDebug-gated approach (commit b97dedb).
    //
    // UX trade-off: the nwss info log (nwss.js:2273) only shows the IP
    // when forceDebug is on. Users wanting the IP in non-debug runs need
    // --debug; same behavior as WireGuard.
    let externalIP = null;
    if (forceDebug) {
      externalIP = getExternalIP(startResult.tunDevice);
      if (externalIP) {
        console.log(formatLogMessage('debug', `${OPENVPN_TAG} ${connectionName} external IP: ${externalIP}`));
      }
    }
    return { success: true, connection: connectionName, tunDevice: startResult.tunDevice, externalIP };
  }

  return { success: false, connection: connectionName, error: 'All attempts failed' };
}

/**
 * Disconnect VPN for a site
 * Only tears down if no other sites are sharing the connection
 * @param {Object} siteConfig - Site configuration from JSON
 * @param {boolean} forceDebug - Debug logging
 * @returns {Object} { success, tornDown, error }
 */
function disconnectForSite(siteConfig, forceDebug = false) {
  const ovpnConfig = normalizeOvpnConfig(siteConfig.openvpn);
  if (!ovpnConfig) return { success: true, tornDown: false };

  const connectionName = resolveConnectionName(ovpnConfig);
  const info = activeConnections.get(connectionName);

  if (!info) {
    return { success: true, tornDown: false };
  }

  // Remove this site from the connection's site set
  if (siteConfig.url) {
    info.sites.delete(siteConfig.url);
  }

  // Only tear down if no other sites are using it
  if (info.sites.size === 0) {
    const result = stopConnection(connectionName, forceDebug);
    return { success: result.success, tornDown: true, error: result.error };
  }

  if (forceDebug) {
    console.log(formatLogMessage('debug',
      `${OPENVPN_TAG} ${connectionName} still used by ${info.sites.size} site(s), keeping up`
    ));
  }

  return { success: true, tornDown: false };
}

/**
 * Tear down all active OpenVPN connections
 * Call on process exit or cleanup
 * @param {boolean} forceDebug - Debug logging
 * @returns {Object} { tornDown, errors }
 */
function disconnectAll(forceDebug = false) {
  const results = { tornDown: 0, errors: [] };

  for (const [connectionName] of activeConnections) {
    const result = stopConnection(connectionName, forceDebug);
    if (result.success) {
      results.tornDown++;
    } else {
      results.errors.push({ connection: connectionName, error: result.error });
    }
  }

  // Clean up entire temp directory
  try { fs.rmSync(TEMP_DIR, { recursive: true, force: true }); } catch {}

  if (forceDebug && results.tornDown > 0) {
    console.log(formatLogMessage('debug',
      `${OPENVPN_TAG} Disconnected ${results.tornDown} connection(s)`
    ));
  }

  return results;
}

/**
 * Get summary of all active connections
 * @returns {Array} Array of connection status objects
 */
function getActiveConnections() {
  const connections = [];
  for (const [name] of activeConnections) {
    connections.push(getConnectionStatus(name));
  }
  return connections;
}

module.exports = {
  validateOpenVPNAvailability,
  validateOvpnConfig,
  normalizeOvpnConfig,
  connectForSite,
  disconnectForSite,
  disconnectAll,
  checkConnection,
  getConnectionStatus,
  getActiveConnections,
  // System checks
  isWSL,
  checkTunDevice,
  hasRootPrivileges,
  // Low-level
  startConnection,
  stopConnection,
  resolveConnectionName
};