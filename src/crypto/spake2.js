const crypto = require('crypto')
const spake2js = require('spake2')

const formatBuffer = require('../utils/formatBuffer.js')
const unicodeNorm = require('../utils/unicodeNorm.js')

const spake2 = spake2js.spake2Plus({
  suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT',
  mhf: { n: 16384, r: 8, p: 1 },
  kdf: { AAD: '' }
})

/**
 * Creates a password verifier of a given password-salt pair for the server to authenticate
 * via the [SPAKE2+ protocol](https://tools.ietf.org/html/draft-irtf-cfrg-spake2-08).
 *
 * @private
 * @param {string} password The username of a user.
 * @returns {Promise<object>} A password verifier for the username-password pair.
 * @property {string} w0 Part of the verifier, encoded in base64.
 * @property {string} L Part of the verifier, encoded in base64.
 */
async function createVerifier (password) {
  const normalizedPassword = unicodeNorm.normalize(password)
  const salt = crypto.randomBytes(32)
  const verifier = await spake2.computeVerifier(normalizedPassword, salt, 'authcoreuser', 'authcore')
  return {
    salt: formatBuffer.toBase64(salt),
    verifier: {
      w0: formatBuffer.toBase64(verifier.w0),
      L: formatBuffer.toBase64(verifier.L)
    }
  }
}

exports.spake2 = spake2
exports.createVerifier = createVerifier
