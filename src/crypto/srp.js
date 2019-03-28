const jsrp = require('jsrp')
// Disable as this is from the library.
// eslint-disable-next-line
const jsrpClient = new jsrp.client()

const formatBuffer = require('../utils/formatBuffer.js')

/**
 * Creates the verifier
 * @param {string} username
 * @param {string} password
 * @returns {Object} Salt (buffer) and verifier (buffer)
 */
function createVerifier (_, password) {
  return new Promise(function (resolve, reject) {
    jsrpClient.init({
      username: '',
      password
    }, function () {
      jsrpClient.createVerifier(function (err, result) {
        /* istanbul ignore if */
        if (err) {
          reject(err)
          return
        }
        resolve({
          salt: formatBuffer.fromHex(result.salt),
          verifier: formatBuffer.fromHex(result.verifier)
        })
      })
    })
  })
}

/**
 * Get A and M1 for SRP.
 * @param {string} username
 * @param {string} password
 * @param {Buffer} salt
 * @param {Buffer} B
 * @returns {Object} A (Buffer) and M1 (Buffer) for verification
 */
async function getAandM1 (_, password, salt, B) {
  return new Promise(function (resolve, reject) {
    jsrpClient.init({
      username: '',
      password
    }, function () {
      try {
        jsrpClient.setSalt(formatBuffer.toHex(salt))
        jsrpClient.setServerPublicKey(formatBuffer.toHex(B))
        resolve({
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
