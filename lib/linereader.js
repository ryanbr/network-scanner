/**
 * linereader.js — read a very large file line by line, synchronously, without
 * loading it whole and without choking on a truncated final line.
 *
 * Both capture parsers need exactly this and nothing more: a Chrome net-log
 * runs to tens of MB and is left unterminated when the browser is killed, and a
 * Firefox MOZ_LOG of one page load measured 424MB. Streaming is not an
 * optimisation here, it is the difference between parsing and not.
 */

const fs = require('fs');

const READ_CHUNK = 1 << 22;   // 4MB

/**
 * Call onLine for each complete line in the file. A trailing fragment with no
 * newline after it is delivered as a final line, so a cut-off capture yields
 * everything up to the cut rather than nothing.
 *
 * A trailing \r is stripped, which is not cosmetic: captures are produced by
 * Windows browsers and are CRLF, and in a JavaScript regex \r is a LINE
 * TERMINATOR, so "." does not match it. A pattern as ordinary as /foo (.*)$/
 * silently matches nothing on every line of such a file -- measured, as 0 hits
 * across 200,000 lines of a real MOZ_LOG that plainly contained the text.
 */
function eachLine(filePath, onLine) {
  const fd = fs.openSync(filePath, 'r');
  const buf = Buffer.allocUnsafe(READ_CHUNK);
  let carry = '';
  try {
    for (;;) {
      const n = fs.readSync(fd, buf, 0, READ_CHUNK, null);
      if (n <= 0) break;
      const text = carry + buf.toString('utf8', 0, n);
      const lines = text.split('\n');
      carry = lines.pop();        // partial line, or the truncated tail
      for (const line of lines) onLine(line.endsWith('\r') ? line.slice(0, -1) : line);
    }
    if (carry) onLine(carry.endsWith('\r') ? carry.slice(0, -1) : carry);
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { eachLine };
