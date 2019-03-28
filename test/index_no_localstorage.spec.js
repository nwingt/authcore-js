/* global suite, test */
const { assert } = require('chai')

const { AuthCoreClient } = require('../src/index.js')

suite('index.js', function () {
  suite('AuthCoreClient (server client)', function () {
    test('should be able to get the refreshToken if it is set', async function () {
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      const authcoreClient = new AuthCoreClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        useLocalStorage: false
      })
      authcoreClient.setRefreshToken(refreshToken)

      assert.equal(authcoreClient.getRefreshToken(), refreshToken)
    })
  })
})
