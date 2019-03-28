const scryptLib = require('scrypt-js')

const formatBuffer = require('../utils/formatBuffer.js')

/**
 * Use scrypt to hash the passphrase along with a given salt and control parameters.
 * @param {Buffer} salt
 * @param {Buffer} passphrase
 * @param {Number} n
 * @param {Number} r
 * @param {Number} p
 * @returns {Buffer} Hash value
 */
async function scrypt (passphrase, salt, n, r, p) {
  return new Promise(function (resolve, reject) {
    scryptLib(passphrase, salt, n, r, p, 64, function (error, _, key) {
      /* istanbul ignore next */
      if (error) return reject(error)
      else if (key) resolve(formatBuffer.fromUint8Array(key))
    })
  })
}

exports.scrypt = scrypt
