const formatBuffer = require('./formatBuffer.js')

/**
 * Normalize a buffer with the Normalization Form Compatibility Decomposition (NFKD) algorithm.
 *
 * @private
 * @param {Buffer} buf Buffer to-be normalized.
 * @example
 * normalize(Buffer.from('\u00e9')) // é
 * // returns <Buffer 65 cc 81>
 * @example
 * normalize(Buffer.from('\u0065\u0301')) // é (e with ́ on above)
 * // returns <Buffer 65 cc 81>
 * @returns {Buffer} The normalized buffer by the NFKD algorithm.
 */
function normalize (buf) {
  return formatBuffer.fromString(formatBuffer.toString(buf).normalize('NFKD'))
}

exports.normalize = normalize
