/* global suite, test */
const { assert } = require('chai')

const unicodeNorm = require('../../src/utils/unicodeNorm.js')

const testCases = [{
  bufferOne: Buffer.from('\u00e9'), // é
  bufferTwo: Buffer.from('\u0065\u0301') // é (e with ́ on above)
}]

suite('utils/unicodeNorm.js', function () {
  suite('normailize', function () {
    const fn = unicodeNorm.normalize
    test('should be able to normalize inputs correctly', function () {
      testCases.forEach(function (testCase) {
        const outputOne = fn(testCase.bufferOne)
        const outputTwo = fn(testCase.bufferTwo)
        assert.equal(outputOne.toString('hex'), outputTwo.toString('hex'))
      })
    })
  })
})
