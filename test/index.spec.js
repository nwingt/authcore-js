/* global suite, test, localStorage, beforeEach, teardown */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const { assert } = chai
const { JSDOM } = require('jsdom')

const { mockAPI } = require('./api_helpers/mock.js')
const { AuthCoreClient, AuthCoreWidgets } = require('../src/index.js')

const REFRESH_TOKEN_KEY = 'io.authcore.refreshToken'

suite('index.js', function () {
  suite('AuthCoreAPI', function () {
    teardown(function () {
      localStorage.clear()
    })

    test('ServiceProxy should return error with response object for AuthService fail case', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 3 },
        { type: 'GeneralAuthFail' }
      ])
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      try {
        await authcoreClient.createUser()
      } catch (err) {
        assert.isDefined(err.response)
      }
    })

    test('ServiceProxy should return error with response object for MgmtService fail case', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'GeneralMgmtFail' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      try {
        await authcoreClient.createUserByAdmin()
      } catch (err) {
        assert.isDefined(err.response)
      }
    })
  })
  suite('AuthCoreClient', function () {
    teardown(function () {
      localStorage.clear()
    })

    test('should be able to set the localStorage when refreshToken is set upon initialization', async function () {
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      assert.equal(authcoreClient.getRefreshToken(), refreshToken)
      assert.equal(localStorage.getItem(REFRESH_TOKEN_KEY), refreshToken)
    })

    test('should be able to set the localStorage when refreshToken is set upon request', async function () {
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      authcoreClient.setRefreshToken(refreshToken)

      assert.equal(authcoreClient.getRefreshToken(), refreshToken)
      assert.equal(localStorage.getItem(REFRESH_TOKEN_KEY), refreshToken)
    })

    test('should be able to unset the localStorage when refreshToken is set', async function () {
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      authcoreClient.setRefreshToken()
      assert.isNull(localStorage.getItem(REFRESH_TOKEN_KEY))
    })

    test('should be able to get an access token', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 3 },
        { type: 'CreateUser' },
        { type: 'CreateAccessToken' },
        { type: 'ChangePassword' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      await authcoreClient.createUser(
        'samuel', 'password', 'samuel@blocksq.com', '+85298765432', 'Samuel'
      )
      const { expiresAt, token } = authcoreClient.getAccessToken()
      assert.isTrue(expiresAt > new Date())
      assert.equal(token, 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxODIxMzcsImlhdCI6MTU0NDE4MDMzNywiaXNzIjoiYXBpLmF1dGhjb3JlLmlvIiwic2lkIjoiMSIsInN1YiI6IjEifQ.UsEahH_9G1BrAooP-MQP8s7BKfXowq2LwjUeiVXH7coMdMbDV8VAQ_ygOz3I2zQyZ5PFzdlwHCzahncawU9Mpw')
    })

    test('should be able to set an access token', async function () {
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      authcoreClient.setAccessToken({
        token: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxODIxMzcsImlhdCI6MTU0NDE4MDMzNywiaXNzIjoiYXBpLmF1dGhjb3JlLmlvIiwic2lkIjoiMSIsInN1YiI6IjEifQ.UsEahH_9G1BrAooP-MQP8s7BKfXowq2LwjUeiVXH7coMdMbDV8VAQ_ygOz3I2zQyZ5PFzdlwHCzahncawU9Mpw',
        expires_in: '1800'
      })
      const accessToken = authcoreClient.getAccessToken()
      assert.isTrue(accessToken.expiresAt > new Date())
      assert.equal(accessToken.token, 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxODIxMzcsImlhdCI6MTU0NDE4MDMzNywiaXNzIjoiYXBpLmF1dGhjb3JlLmlvIiwic2lkIjoiMSIsInN1YiI6IjEifQ.UsEahH_9G1BrAooP-MQP8s7BKfXowq2LwjUeiVXH7coMdMbDV8VAQ_ygOz3I2zQyZ5PFzdlwHCzahncawU9Mpw')

      authcoreClient.setAccessToken(accessToken)
      const accessToken2 = authcoreClient.getAccessToken()
      assert.isTrue(accessToken2.expiresAt > new Date())
      assert.equal(accessToken2.token, 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxODIxMzcsImlhdCI6MTU0NDE4MDMzNywiaXNzIjoiYXBpLmF1dGhjb3JlLmlvIiwic2lkIjoiMSIsInN1YiI6IjEifQ.UsEahH_9G1BrAooP-MQP8s7BKfXowq2LwjUeiVXH7coMdMbDV8VAQ_ygOz3I2zQyZ5PFzdlwHCzahncawU9Mpw')
    })

    test('should be able to create an account', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 3 },
        { type: 'CreateUser' },
        { type: 'CreateAccessToken' },
        { type: 'ChangePassword' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      await authcoreClient.createUser(
        'samuel', 'password', 'samuel@blocksq.com', '+85298765432', 'Samuel'
      )
    })

    test('should be able to sign in to an account with username', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartAuthentication' },
        { type: 'Authenticate' },
        { type: 'CreateAccessToken' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      const startAuthenticationResponse = await authcoreClient.startAuthentication('samuel')
      assert.include(startAuthenticationResponse['challenges'], 'SECURE_REMOTE_PASSWORD')
      assert.exists(startAuthenticationResponse['temporary_token'])
      assert.exists(startAuthenticationResponse['password_challenge']['token'])
      assert.exists(startAuthenticationResponse['password_challenge']['salt'])
      assert.exists(startAuthenticationResponse['password_challenge']['B'])

      const authenticateResponse = await authcoreClient.authenticateWithSRP('password')
      assert.isTrue(authenticateResponse['authenticated'])
    })

    test('should be able to sign in to an account with email', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartAuthentication' },
        { type: 'Authenticate' },
        { type: 'CreateAccessToken' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      const startAuthenticationResponse = await authcoreClient.startAuthentication('samuel@blocksq.com')
      assert.include(startAuthenticationResponse['challenges'], 'SECURE_REMOTE_PASSWORD')
      assert.exists(startAuthenticationResponse['temporary_token'])
      assert.exists(startAuthenticationResponse['password_challenge']['token'])
      assert.exists(startAuthenticationResponse['password_challenge']['salt'])
      assert.exists(startAuthenticationResponse['password_challenge']['B'])

      const authenticateResponse = await authcoreClient.authenticateWithSRP('password')
      assert.isTrue(authenticateResponse['authenticated'])
    })

    test('should not be able to sign in to an account with a wrong password', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartAuthentication' },
        { type: 'AuthenticateWrong' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      const startAuthenticationResponse = await authcoreClient.startAuthentication('samuel')
      assert.include(startAuthenticationResponse['challenges'], 'SECURE_REMOTE_PASSWORD')
      assert.exists(startAuthenticationResponse['temporary_token'])
      assert.exists(startAuthenticationResponse['password_challenge']['token'])
      assert.exists(startAuthenticationResponse['password_challenge']['salt'])
      assert.exists(startAuthenticationResponse['password_challenge']['B'])

      let error
      try {
        await authcoreClient.authenticateWithSRP('password?')
      } catch (err) {
        error = err
      }
      assert.exists(error)
    })

    test('should be able to sign in to an account with username, with TOTP enabled', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartAuthentication' },
        { type: 'AuthenticateTOTP' },
        { type: 'AuthenticateSecondFactor' },
        { type: 'CreateAccessToken' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      const startAuthenticationResponse = await authcoreClient.startAuthentication('samuel')
      assert.include(startAuthenticationResponse['challenges'], 'SECURE_REMOTE_PASSWORD')
      assert.exists(startAuthenticationResponse['temporary_token'])
      assert.exists(startAuthenticationResponse['password_challenge']['token'])
      assert.exists(startAuthenticationResponse['password_challenge']['salt'])
      assert.exists(startAuthenticationResponse['password_challenge']['B'])

      const authenticateResponse = await authcoreClient.authenticateWithSRP('password')
      assert.include(authenticateResponse['challenges'], 'TIME_BASED_ONE_TIME_PASSWORD')
      assert.exists(authenticateResponse['temporary_token'])

      const authenticateSecondFactorResponse = await authcoreClient.authenticateWithTOTP('131072')
      assert.isTrue(authenticateSecondFactorResponse['authenticated'])
    })

    test('should be able to sign in to an account with username, with SMS authentication enabled', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartAuthentication' },
        { type: 'AuthenticateSMS' },
        { type: 'StartAuthenticateSMS' },
        { type: 'AuthenticateSecondFactor' },
        { type: 'CreateAccessToken' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      const startAuthenticationResponse = await authcoreClient.startAuthentication('samuel')
      assert.include(startAuthenticationResponse['challenges'], 'SECURE_REMOTE_PASSWORD')
      assert.exists(startAuthenticationResponse['temporary_token'])
      assert.exists(startAuthenticationResponse['password_challenge']['token'])
      assert.exists(startAuthenticationResponse['password_challenge']['salt'])
      assert.exists(startAuthenticationResponse['password_challenge']['B'])

      const authenticateResponse = await authcoreClient.authenticateWithSRP('password')
      assert.include(authenticateResponse['challenges'], 'SMS_CODE')
      assert.exists(authenticateResponse['temporary_token'])

      await authcoreClient.startAuthenticateSMS()

      const authenticateSecondFactorResponse = await authcoreClient.authenticateWithSMS('2147483647')
      assert.isTrue(authenticateSecondFactorResponse['authenticated'])
    })

    test('should be able to obtain the current user', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'GetCurrentUser' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.getCurrentUser()
    })

    test('should be able to list the users (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'ListUsers' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const usersObject = await authcoreClient.listUsers(10, '', false)
      assert.isArray(usersObject.users)
      assert.equal(usersObject.next_page_token, '2')
      assert.equal(usersObject.total_size, 1)
    })

    test('should be able to get the user (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'GetUser' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const userObject = await authcoreClient.getUser('1')
      assert.equal(userObject.id, '1')
      assert.equal(userObject.username, 'samuel')
      assert.equal(userObject.email, 'samuel@blocksq.com')
      assert.equal(userObject.phone, '+85299965536')
      assert.equal(userObject.display_name, 'Samuel')
    })

    test('should be able to update user profile (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'GetUser' },
        { type: 'UpdateUser' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const user = await authcoreClient.getUser('1')
      user['display_name'] = 'Samuel_updated'

      const updatedUserProfileObject = await authcoreClient.updateUserProfile('1', user)
      assert.equal(updatedUserProfileObject.id, '1')
      assert.equal(updatedUserProfileObject.username, 'samuel')
      assert.equal(updatedUserProfileObject.email, 'samuel@blocksq.com')
      assert.equal(updatedUserProfileObject.phone, '+85299965536')
      assert.equal(updatedUserProfileObject.display_name, 'Samuel_updated')
    })

    test('should be able to update user lock (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'GetUser' },
        { type: 'UpdateUser', count: 3 }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const userObject = await authcoreClient.getUser('1')
      userObject.display_name = 'Samuel_updated'

      // Lock for 7 days
      await authcoreClient.updateUserLock('1', true, 7, 'Misbehaviour')
      // Lock permanently
      await authcoreClient.updateUserLock('1', true, Infinity, 'Misbehaviour')
      // Unlock
      await authcoreClient.updateUserLock('1', false, 'Banned the wrong guy ')
      // Lock for 0 days (Should fail)
      let error
      try {
        await authcoreClient.updateUserLock('1', true, 0, 'Troll')
      } catch (err) {
        error = err
      }
      assert.exists(error)
    })

    test('should be able to list TOTP authenticators', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'ListTOTPAuthenticators' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const listTOTPAuthenticatorsResponse = await authcoreClient.listTOTPAuthenticators()
      assert.exists(listTOTPAuthenticatorsResponse['totp_authenticators'])
      assert.typeOf(listTOTPAuthenticatorsResponse['totp_authenticators'], 'array')
    })

    test('should be able to create an TOTP authenticator', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'CreateTOTPAuthenticator' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const totpSecret = await authcoreClient.generateTOTPSecret()
      assert.match(totpSecret, /^[2-7A-Z]{32}$/)

      await authcoreClient.createTOTPAuthenticator(
        'S', totpSecret, '000000' // '000000' represents a valid PIN
      )
    })

    test('should be able to delete an TOTP authenticator', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'DeleteTOTPAuthenticator' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.deleteTOTPAuthenticator(1)
    })

    test('should be able to list contacts', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'ListOwnContacts' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const listOwnContactsResponse = await authcoreClient.listOwnContacts()
      assert.exists(listOwnContactsResponse['contacts'])
      assert.typeOf(listOwnContactsResponse['contacts'], 'array')
    })

    test('should be able to create an email contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'CreateContact_Email' },
        { type: 'StartVerifyContact' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.createEmailContact('example@example.com')
    })

    test('should be able to create an phone contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'CreateContact_Phone' },
        { type: 'StartVerifyContact' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.createPhoneContact('+85299965536')
    })

    test('should be able to delete a contact', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'DeleteOwnContact' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.deleteOwnContact(1)
    })

    test('should be able to verify a contact by token', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'StartVerifyContact' },
        { type: 'CompleteVerifyContact' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.startVerifyContact(1)
      await authcoreClient.verifyContactByToken('MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA')
    })

    test('should be able to verify a contact by code', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'StartVerifyContact' },
        { type: 'CompleteVerifyContact' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.startVerifyContact(1)
      await authcoreClient.verifyContactByCode('0133765536')
    })

    test('should be able to list the contacts (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'ListContacts' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.listContacts(1)
    })

    test('should be able to update contact authentication', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'UpdateContactAuthentication', count: 2 }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.updatePhoneAuthentication(true)
      await authcoreClient.updatePhoneAuthentication(false)
    })

    test('should list all audit logs (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'ListAuditLogs' }
      ])

        // Test
        const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
        localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
        const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
  
        const auditLogs = await authcoreClient.listAuditLogs(10, '', false)
        assert.isArray(auditLogs['auditLogs'])
        assert.equal(auditLogs['next_page_token'], '4')
        assert.equal(auditLogs['total_size'], 3)
      })

    test('should list all audit logs of a certain user (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'ListUserAuditLogs' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const auditLogsObject = await authcoreClient.listUserAuditLogs(1, 10, '', false)
      assert.isArray(auditLogsObject.auditLogs)
      assert.equal(auditLogsObject.next_page_token, '4')
      assert.equal(auditLogsObject.total_size, 3)
    })

    test('should be able to list roles (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'ListRoles' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const roles = await authcoreClient.listRoles()
      assert.isArray(roles)
      assert.deepEqual(roles[0], {
        'id': '1',
        'name': 'authcore.admin',
        'system_role': true
      })
    })

    test('should be able to create role (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'CreateRole' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.createRole('testing_application.admin')
    })

    test('should be able to delete role (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'DeleteRole' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.deleteRole(5)
    })

    test('should be able to assign role (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'AssignRole' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.assignRole(5, 3)
    })

    test('should be able to unassign role (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'StartAuthentication' },
        { type: 'Authenticate' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'UnassignRole' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.unassignRole(5, 3)
    })

    test('should be able to list role assignments (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'ListRoleAssignments' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const roles = await authcoreClient.listRoleAssignments(5)
      assert.isArray(roles)
      assert.deepEqual(roles[0], {
        'id': '2',
        'name': 'authcore.admin',
        'system_role': true
      })
    })

    test('should be able to list permission assignments (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'ListPermissionAssignments' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })
      const permissions = await authcoreClient.listPermissionAssignments(1)
      assert.isArray(permissions)
      assert.deepEqual(permissions[0], {
        'name': 'authcore.users.create'
      })
    })

    test('should be able to list the permissions of the current user (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient' },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'ListCurrentUserPermissions' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      const permissions = await authcoreClient.listCurrentUserPermissions()
      assert.isArray(permissions)
      assert.deepEqual(permissions[0], {
        'name': 'authcore.users.create'
      })
    })

    test('should be able to create an account (management API)', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient', count: 2 },
        { type: 'CreateAccessToken' },
        { type: 'SwaggerMgmtClient' },
        { type: 'CreateUserByAdmin' },
        { type: 'ChangePasswordByAdmin' }
      ])
      // Test
      const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
      localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await authcoreClient.createUserByAdmin(
        'samuel', 'password', 'samuel@blocksq.com', '+85298765432', 'Samuel'
      )
    })

    test('should be able to trigger the 401 callback successfully', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListUsers401' }
      ])
      // Test
      let callbackCounts = 0
      const authcoreClient = new AuthCoreClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        callbacks: {
          unauthorized: function () {
            callbackCounts += 1
          }
        }
      })
      await assert.isRejected(authcoreClient.listUsers(10, '', false))
      assert.equal(callbackCounts, 1)
    })

    test('should not throw another error if there are no 401 callbacks', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListUsers401' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({
        apiBaseURL: 'http://0.0.0.0:13337'
      })
      await assert.isRejected(authcoreClient.listUsers(10, '', false))
    })

    test('should be able to trigger the 403 callback successfully', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListUsers403' }
      ])
      // Test
      let callbackCounts = 0
      const authcoreClient = new AuthCoreClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        callbacks: {
          unauthenticated: function () {
            callbackCounts += 1
          }
        }
      })
      await assert.isRejected(authcoreClient.listUsers(10, '', false))
      assert.equal(callbackCounts, 1)
    })

    test('should not throw another error if there are no 403 callbacks', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerMgmtClient' },
        { type: 'ListUsers403' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({
        apiBaseURL: 'http://0.0.0.0:13337'
      })
      await assert.isRejected(authcoreClient.listUsers(10, '', false))
    })

    test('should be able to catch the errors from Swagger clients', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerClient404' },
        { type: 'SwaggerMgmtClient404' }
      ])
      // Test
      const authcoreClient = new AuthCoreClient({ apiBaseURL: 'http://0.0.0.0:13337' })

      await assert.isRejected(authcoreClient.startAuthentication('samuel'))
      await assert.isRejected(authcoreClient.listUsers(10, '', false))
    })
  })

  suite('AuthCoreWidget', function () {
    beforeEach(function () {
      const { window } = new JSDOM(`
        <html>
          <body>
            <div id="authcore-sign-in-widget"></div>
            <div id="authcore-contacts-widget"></div>
          </body>
        </html>
      `)
      const { document } = window
      global.window = window
      global.document = document
    })
    teardown(function () {
      localStorage.clear()
    })

    test('should be able to mount an iframe with basic attributes', async function () {
      // Preparing
      new AuthCoreWidgets.Login({
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337'
      })

      // Testing
      const iframes = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')
      assert.equal(iframes.length, 1)

      const iframe = iframes[0]
      assert.equal(iframe.style.width, '100%')
      assert.equal(iframe.style.overflow, 'hidden')
    })

    test('should be able to update height when `AuthCore__updateHeight` message is posted', function (done) {
      // Preparing
      new AuthCoreWidgets.Login({
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337'
      })
      window.addEventListener('message', e => {
        const { type } = e.data
        if (type === 'AuthCore__updateHeight') {
          assert.equal(iframe.style.height, '256px')
          done()
        }
      })

      // Testing
      const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
      assert.exists(iframe)

      window.postMessage({
        type: 'AuthCore__updateHeight',
        data: 256
      }, '*')
    })

    test('should be able to perform registered callbacks', function (done) {
      // Preparing
      let callbackToken

      new AuthCoreWidgets.Login({
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337',
        callbacks: {
          testCallback: ({ token }) => { callbackToken = token }
        }
      })
      window.addEventListener('message', e => {
        const { type } = e.data
        if (type === 'AuthCore_testCallback') {
          assert.equal(callbackToken, 42)
          done()
        }
      })

      // Testing
      const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
      assert.exists(iframe)

      window.postMessage({
        type: 'AuthCore_testCallback',
        data: {
          token: 42
        }
      }, '*')
    })

    test('should not be able to postMessage if the event data is malformed', async function () {
      // Preparing
      new AuthCoreWidgets.Login({
        container: 'authcore-sign-in-widget',
        root: 'http://0.0.0.0:1337'
      })

      // Testing
      const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
      assert.exists(iframe)

      // 1. Data is not an object
      window.postMessage('Hello world!', '*')
      // 2. Callback is not from AuthCore
      window.postMessage({
        type: 'MetaMask_testCallback'
      }, '*')
      // 3. Callback is not defined
      window.postMessage({
        type: 'AuthCore_testCallback'
      }, '*')
    })

    suite('Login widget', function () {
      test('should be able to mount an iframe with additional attributes', async function () {
        // Preparing
        new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.equal(iframe.src, 'http://0.0.0.0:1337/')
      })

      test('should be able to set refreshToken in localStorage when `AuthCore__onSuccess` is message is posted', function (done) {
        // Preparing
        const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
        new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          root: 'http://0.0.0.0:1337'
        })
        window.addEventListener('message', e => {
          const { type } = e.data
          if (type === 'AuthCore__onSuccess') {
            assert.equal(localStorage.getItem(REFRESH_TOKEN_KEY), refreshToken)
            done()
          }
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        window.postMessage({
          type: 'AuthCore__onSuccess',
          data: {
            'current_user': {
              'id': '1',
              'username': 'samuel',
              'email': 'samuel@blocksq.com',
              'phone': '+85299965536',
              'display_name': 'Samuel',
              'updated_at': '2018-12-07T10:58:58Z',
              'created_at': '2018-12-07T10:58:57Z'
            },
            'refresh_token': refreshToken
          }
        }, '*')
      })

      test('should be able to clear the refreshToken in localStorage when `AuthCore__onSuccess` is message is posted without data', function (done) {
        // Preparing
        const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
        new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          root: 'http://0.0.0.0:1337'
        })
        window.addEventListener('message', e => {
          const { type } = e.data
          if (type === 'AuthCore__onSuccess') {
            assert.isNull(localStorage.getItem(REFRESH_TOKEN_KEY))
            done()
          }
        })

        // Testing
        localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken)
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        window.postMessage({
          type: 'AuthCore__onSuccess'
        }, '*')
      })

      test('should be able to call customised callback when `AuthCore_onSuccess` is message is posted', function (done) {
        // Preparing
        let callbackToken

        const refreshToken = 'VFj09tlhF5PwzqXCqpUsxjW-cyDmSKSZhVtPmG3qQwU'
        new AuthCoreWidgets.Login({
          container: 'authcore-sign-in-widget',
          root: 'http://0.0.0.0:1337',
          callbacks: {
            onSuccess: () => { callbackToken = 42 }
          }
        })
        window.addEventListener('message', e => {
          const { type, data } = e.data
          if (type === 'AuthCore_onSuccess') {
            assert.deepEqual(data['current_user'], {
              'id': '1',
              'username': 'samuel',
              'email': 'samuel@blocksq.com',
              'phone': '+85299965536',
              'display_name': 'Samuel',
              'updated_at': '2018-12-07T10:58:58Z',
              'created_at': '2018-12-07T10:58:57Z'
            })
            assert.equal(data['refresh_token'], refreshToken)
            assert.equal(callbackToken, 42) // Customized callback is performed
            done()
          }
        })

        // Testing
        const iframe = document.getElementById('authcore-sign-in-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        window.postMessage({
          type: 'AuthCore_onSuccess',
          data: {
            'current_user': {
              'id': '1',
              'username': 'samuel',
              'email': 'samuel@blocksq.com',
              'phone': '+85299965536',
              'display_name': 'Samuel',
              'updated_at': '2018-12-07T10:58:58Z',
              'created_at': '2018-12-07T10:58:57Z'
            },
            'refresh_token': refreshToken
          }
        }, '*')
      })
    })

    suite('Contacts widget', function () {
      test('should be able to mount an iframe with additional attributes', async function () {
        // Preparing
        new AuthCoreWidgets.Contacts({
          container: 'authcore-contacts-widget',
          root: 'http://0.0.0.0:1337'
        })

        // Testing
        const iframe = document.getElementById('authcore-contacts-widget').getElementsByTagName('iframe')[0]
        assert.exists(iframe)

        assert.equal(iframe.src, 'http://0.0.0.0:1337/contacts')
      })
    })
  })
})
