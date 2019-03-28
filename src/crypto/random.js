const crypto = require('crypto')
const base32Encode = require('base32-encode')

const formatBuffer = require('../utils/formatBuffer.js')

/**
 * Generate a random TOTP secret (32 base-32 characters)
 * @returns {Buffer} A random TOTP secret
 */
function randomTOTPSecret () {
  const randomBuffer = crypto.randomBytes(32)
  const hash = crypto.createHash('sha1').update(randomBuffer).digest()
  return formatBuffer.fromString(base32Encode(hash, 'RFC4648'))
}

exports.randomTOTPSecret = randomTOTPSecret
