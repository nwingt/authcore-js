/* global suite, test */
const { assert } = require('chai')

const formatBuffer = require('../../src/utils/formatBuffer.js')
const random = require('../../src/crypto/random.js')

suite('crypto/random.js', function () {
  suite('randomTOTPSecret', function () {
    const fn = random.randomTOTPSecret
    test('should create random TOTP secret successfully', async function () {
      const outputOne = fn()
      const outputTwo = fn()
      assert.match(formatBuffer.toString(outputOne), /^[2-7A-Z]{32}$/)
      assert.match(formatBuffer.toString(outputTwo), /^[2-7A-Z]{32}$/)
      assert.notEqual(outputOne, outputTwo)
    })
  })
})
