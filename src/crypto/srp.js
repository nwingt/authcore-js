const jsrp = require('jsrp')
// Disable as this is from the library.
// eslint-disable-next-line
const jsrpClient = new jsrp.client()

const formatBuffer = require('../utils/formatBuffer.js')

/**
 * Creates a password verifier of a given username-password pair for the server to authenticate
 * the user via the [secure remote password (SRP) protocol](https://tools.ietf.org/html/rfc5054).
 *
 * @private
 * @param {string} username The username of a user.
 * @param {string} password The password of a user.
 * @returns {object} A SRP verifier for the username-password pair.
 * @property {string} salt The salt used as a hash for the password.
 * @property {string} verifier The password verifier defined by the SRP protocol.
 */
function createVerifier (username, password) {
  return new Promise(function (resolve, reject) {
    jsrpClient.init({
      username: '',
      password
    }, function () {
      jsrpClient.createVerifier(function (err, result) {
        /* istanbul ignore if */
        if (err) {
          return reject(err)
        }
        return resolve({
          salt: formatBuffer.fromHex(result.salt),
          verifier: formatBuffer.fromHex(result.verifier)
        })
      })
    })
  })
}

/**
 * Computes an one-time ephemeral key and the corresponding proof given the username-password pair,
 * the salt and the server's one-time ephemeral key.
 *
 * @private
 * @param {string} username The username of a user.
 * @param {string} password The password of a user.
 * @param {Buffer} salt The salt used as a hash for the password.
 * @param {Buffer} B The one-time ephemeral key of the server.
 * @returns {object} The SRP response for the username-password pair, under the corresponding
 *          challenge.
 * @property {string} A The one-time ephemeral key of the client.
 * @property {string} M1 The proof defined by the SRP protocol.
 */
async function getAandM1 (username, password, salt, B) {
  return new Promise(function (resolve, reject) {
    jsrpClient.init({
      username: '',
      password
    }, function () {
      try {
        jsrpClient.setSalt(formatBuffer.toHex(salt))
        jsrpClient.setServerPublicKey(formatBuffer.toHex(B))
        return resolve({
          A: formatBuffer.fromHex(jsrpClient.getPublicKey()),
          M1: formatBuffer.fromHex(jsrpClient.getProof())
        })
      } catch (err) {
        /* istanbul ignore next */
        reject(err)
      }
    })
  })
}

exports.createVerifier = createVerifier
exports.getAandM1 = getAandM1
