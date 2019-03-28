/* global suite, test, localStorage, teardown */
const { assert } = require('chai')

const { mockAPI } = require('./api_helpers/mock.js')
const { AuthCoreClient } = require('../src/index.js')

suite('index.js', function () {
  suite('AuthCoreClient (HTTPS)', function () {
    teardown(function () {
      localStorage.clear()
    })
    test('should be able to get an access token', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClientForHTTPS', count: 3 },
        { type: 'CreateUserForHTTPS' },
        { type: 'CreateAccessTokenForHTTPS' },
        { type: 'ChangePasswordForHTTPS' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'https://0.0.0.0:13338' })
      await authcoreClient.createUser(
        'samuel', 'password', 'samuel@blocksq.com', '+85298765432', 'Samuel'
      )
      const { expiresAt, token } = authcoreClient.getAccessToken()
      assert.isTrue(expiresAt > new Date())
      assert.equal(token, 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxODIxMzcsImlhdCI6MTU0NDE4MDMzNywiaXNzIjoiYXBpLmF1dGhjb3JlLmlvIiwic2lkIjoiMSIsInN1YiI6IjEifQ.UsEahH_9G1BrAooP-MQP8s7BKfXowq2LwjUeiVXH7coMdMbDV8VAQ_ygOz3I2zQyZ5PFzdlwHCzahncawU9Mpw')
    })
  })
})
