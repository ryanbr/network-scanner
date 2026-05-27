// === Log Compression Utility ===
// This module provides gzip compression functionality for log files

const fs = require('fs');
const { formatLogMessage } = require('./colorize');
const zlib = require('zlib');
const { pipeline } = require('node:stream/promises');

/**
 * Compresses a file using gzip and optionally removes the original.
 * Uses stream.pipeline for automatic cleanup of all streams on any error
 * (previously the manual readStream/gzipStream/writeStream wiring left the
 * other two streams alive when one errored, holding their fds until GC).
 * @param {string} filePath - Path to the file to compress
 * @param {boolean} removeOriginal - Whether to remove the original file after compression
 * @returns {Promise<string>} - Path to the compressed file
 */
async function compressFile(filePath, removeOriginal = true) {
  const compressedPath = `${filePath}.gz`;
  try {
    await pipeline(
      fs.createReadStream(filePath),
      zlib.createGzip(),
      fs.createWriteStream(compressedPath)
    );
  } catch (err) {
    // Clean up partial compressed file on error
    try { fs.unlinkSync(compressedPath); } catch { /* ignore */ }
    throw err;
  }
  if (removeOriginal) {
    try {
      fs.unlinkSync(filePath);
    } catch (removeErr) {
      // If we can't remove the original, compression is still successful
      console.warn(formatLogMessage('warn', `Failed to remove original file ${filePath}: ${removeErr.message}`));
    }
  }
  return compressedPath;
}

/**
 * Compresses multiple files and returns results
 * @param {string[]} filePaths - Array of file paths to compress
 * @param {boolean} removeOriginals - Whether to remove original files
 * @returns {Promise<Object>} - Object with successful and failed compressions
 */
async function compressMultipleFiles(filePaths, removeOriginals = true) {
  const results = {
    successful: [],
    failed: []
  };
  
  for (const filePath of filePaths) {
    try {
      const compressedPath = await compressFile(filePath, removeOriginals);
      results.successful.push({
        original: filePath,
        compressed: compressedPath
      });
    } catch (error) {
      results.failed.push({
        path: filePath,
        error: error.message
      });
    }
  }
  
  return results;
}

/**
 * Formats file size in human readable format
 * @param {number} bytes - Size in bytes
 * @returns {string} - Formatted size string
 */
function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

module.exports = {
  compressFile,
  compressMultipleFiles,
  formatFileSize
};
