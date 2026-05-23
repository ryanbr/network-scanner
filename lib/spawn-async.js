// === Shared async-spawn helper ===
// Single canonical implementation of "spawn an external command, collect
// stdout/stderr with hard caps, enforce a kill timeout" — extracted from
// what used to be ~400 lines of near-identical Promise wrappers across
// lib/curl.js, lib/searchstring.js, and lib/grep.js (two sites in the
// latter). Each caller previously had its own copy of the same pattern:
// truncate-on-cap, SIGKILL belt-and-braces timer, stdout buffer concat,
// error/close handlers.
//
// Design notes:
// - Resolves (never rejects). Callers inspect the result object to
//   distinguish failure modes instead of needing try/catch. Pre-existing
//   call sites all converted failure into a result-object anyway —
//   this just standardizes the shape.
// - stdout/stderr returned as Buffer so the caller decides decoding
//   (curl's `--write-out` metadata is line-oriented and tolerant of
//   UTF-8 decoding mid-multibyte; binary HTTP responses are not).
// - lib/wireguard_vpn.js intentionally stays on spawnSync — its calls
//   are startup-only (validation, health check) and the synchronous
//   semantics are simpler. Not all spawn calls benefit from async.

const { spawn } = require('child_process');

const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_MAX_STDOUT = 50 * 1024 * 1024; // 50MB
const KILL_GRACE_MS = 5000; // belt-and-braces SIGKILL after timeout+grace

/**
 * Spawn a process asynchronously, collect stdout/stderr with hard caps,
 * enforce a kill timeout. Resolves with a result object describing what
 * happened — never rejects.
 *
 * @param {string} cmd - Executable name (no shell — args are not parsed)
 * @param {string[]} args - Argument array
 * @param {object} [opts]
 * @param {number} [opts.timeout=30000] - Soft timeout in ms; primary
 *   limit is whatever the executable itself enforces (e.g. curl
 *   --max-time). This is the belt-and-braces SIGKILL deadline fired at
 *   `timeout + 5000` ms.
 * @param {number} [opts.maxStdout=52428800] - Cap on stdout collection.
 *   When the cap is exceeded the child is killed with SIGTERM and the
 *   result has `truncated: true`.
 * @param {string|Buffer} [opts.input] - Data to write to the child's
 *   stdin then close. EPIPE on stdin is swallowed (child may exit early).
 * @param {boolean} [opts.collectStderr=true] - When false, stderr is
 *   drained but not retained (saves memory when caller doesn't need it).
 * @returns {Promise<{
 *   code: number|null,
 *   signal: string|null,
 *   stdout: Buffer,
 *   stderr: Buffer,
 *   truncated: boolean,
 *   error: string|null
 * }>}
 */
function runProcess(cmd, args, opts = {}) {
  const {
    timeout = DEFAULT_TIMEOUT_MS,
    maxStdout = DEFAULT_MAX_STDOUT,
    input,
    collectStderr = true
  } = opts;

  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args);
    } catch (spawnErr) {
      resolve({
        code: null, signal: null,
        stdout: Buffer.alloc(0), stderr: Buffer.alloc(0),
        truncated: false, error: spawnErr.message
      });
      return;
    }

    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let truncated = false;

    child.stdout.on('data', (chunk) => {
      if (truncated) return;
      if (stdoutBytes + chunk.length > maxStdout) {
        truncated = true;
        try { child.kill('SIGTERM'); } catch (_) {}
        return;
      }
      stdoutBytes += chunk.length;
      stdoutChunks.push(chunk);
    });

    if (collectStderr) {
      child.stderr.on('data', (chunk) => { stderrChunks.push(chunk); });
    } else {
      child.stderr.on('data', () => {}); // drain but discard
    }

    // SIGKILL belt-and-braces after timeout+grace. unref'd so the timer
    // doesn't keep the event loop alive on its own; if the process exits
    // earlier, the timer is cleared in the close handler.
    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, timeout + KILL_GRACE_MS);
    if (typeof killTimer.unref === 'function') killTimer.unref();

    child.on('error', (err) => {
      clearTimeout(killTimer);
      resolve({
        code: null, signal: null,
        stdout: Buffer.concat(stdoutChunks),
        stderr: Buffer.concat(stderrChunks),
        truncated, error: err.message
      });
    });

    child.on('close', (code, signal) => {
      clearTimeout(killTimer);
      resolve({
        code, signal,
        stdout: Buffer.concat(stdoutChunks),
        stderr: Buffer.concat(stderrChunks),
        truncated, error: null
      });
    });

    if (input !== undefined) {
      // EPIPE if the child exited before we finished writing (e.g. grep
      // matched and bailed early, or our truncation kill fired). Swallow
      // so it doesn't surface as an unhandled stream error.
      child.stdin.on('error', () => {});
      child.stdin.end(input);
    }
  });
}

module.exports = { runProcess };
