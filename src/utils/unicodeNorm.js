const formatBuffer = require('./formatBuffer.js')

/**
 * Normalize a buffer with NFD.
 * @param {Buffer} buffer
 * @returns {Buffer} Normalized buffer
 */
function normalize (buffer) {
  return formatBuffer.fromString(formatBuffer.toString(buffer).normalize('NFKD'))
}

exports.normalize = normalize
