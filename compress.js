// === Log Compression Utility ===
// This module provides gzip compression functionality for log files

const fs = require('fs');
const zlib = require('zlib');
const path = require('path');

/**
 * Compresses a file using gzip and optionally removes the original
 * @param {string} filePath - Path to the file to compress
 * @param {boolean} removeOriginal - Whether to remove the original file after compression
 * @returns {Promise<string>} - Path to the compressed file
 */
async function compressFile(filePath, removeOriginal = true) {
  return new Promise((resolve, reject) => {
    const compressedPath = `${filePath}.gz`;
    
    // Create read and write streams
    const readStream = fs.createReadStream(filePath);
    const writeStream = fs.createWriteStream(compressedPath);
    const gzipStream = zlib.createGzip();
    
    // Handle errors
    const handleError = (error) => {
      // Clean up partial compressed file on error
      try {
        if (fs.existsSync(compressedPath)) {
          fs.unlinkSync(compressedPath);
        }
      } catch (cleanupErr) {
        // Ignore cleanup errors
      }
      reject(error);
    };
    
    readStream.on('error', handleError);
    writeStream.on('error', handleError);
    gzipStream.on('error', handleError);
    
    // Handle successful completion
    writeStream.on('finish', () => {
      if (removeOriginal) {
        try {
          fs.unlinkSync(filePath);
        } catch (removeErr) {
          // If we can't remove original, still consider compression successful
          console.warn(`[warn] Failed to remove original file ${filePath}: ${removeErr.message}`);
        }
      }
      resolve(compressedPath);
    });
    
    // Pipe the streams
    readStream.pipe(gzipStream).pipe(writeStream);
  });
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
      if (fs.existsSync(filePath)) {
        const compressedPath = await compressFile(filePath, removeOriginals);
        results.successful.push({
          original: filePath,
          compressed: compressedPath
        });
      } else {
        results.failed.push({
          path: filePath,
          error: 'File does not exist'
        });
      }
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
 * Gets the compression ratio of a file
 * @param {string} originalPath - Path to original file
 * @param {string} compressedPath - Path to compressed file
 * @returns {number} - Compression ratio (0-1, where 0.5 means 50% of original size)
 */
function getCompressionRatio(originalPath, compressedPath) {
  try {
    const originalSize = fs.statSync(originalPath).size;
    const compressedSize = fs.statSync(compressedPath).size;
    return compressedSize / originalSize;
  } catch (error) {
    return null;
  }
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
  getCompressionRatio,
  formatFileSize
};
