// swagger wrapper
const Swagger = require('swagger-client')

const srp = require('../crypto/srp.js')
const { scrypt } = require('../crypto/scrypt.js')
const { randomTOTPSecret } = require('../crypto/random.js')
const formatBuffer = require('../utils/formatBuffer.js')
const unicodeNorm = require('../utils/unicodeNorm.js')

/**
 * Class interacting between AuthCore Web (and corresponding web clients) and auth backend.
 * Wrap interactive steps into functions.
 *
 * `config` is an object that contains:
 * 1. `apiBaseURL`: the base URL for the API endpoint.
 * 2. `callbacks`: the callback functions, listed below:
 *  - `unauthenticated`: callback when an user calls an API while not authenticated.
 * 3. `accessToken`: the access token of the user for the authenticated APIs.
 */
class AuthCoreAuthClient {
  constructor (config) {
    return new Promise(async (resolve, reject) => {
      this.config = config

      this.temporaryToken = undefined // the temporary token.
      this.deviceToken = undefined // the device token.

      this.handle = undefined // the user handle

      // Challenge for SECURE_REMOTE_PASSWORD
      this.passwordChallenge = undefined
      // Set accessToken into API
      await this.setAccessToken(config.accessToken)

      return resolve(this)
    })
  }

  /**
   * Constructs Swagger auth client
   * Including interceptor for unauthorized and unauthenticated cases to run
   * callbacks from client implementation.
   */
  async getSwaggerAuthClientAsync () {
    let authorizations
    if (this.config.accessToken) {
      authorizations = {
        'BearerAuth': {
          'value': `Bearer ${this.config.accessToken}`
        }
      }
    }

    if (this.config !== undefined) {
      await new Promise((resolve, reject) => {
        const swaggerJsonURL = `${this.config.apiBaseURL}/api/authapi/authcore.swagger.json`
        Swagger({
          url: swaggerJsonURL,
          authorizations,
          requestInterceptor: (req) => {
            // Hijack the scheme to match the origin request
            const schemePos = req.url.indexOf(':')
            const urlWithoutScheme = req.url.slice(schemePos)
            req.url = this.config.apiBaseURL.split(':')[0] + urlWithoutScheme
            return req
          },
          responseInterceptor: (res) => {
            if (res.status === 401) {
              this.config.callbacks['unauthorized']()
            }
            if (res.status === 403) {
              this.config.callbacks['unauthenticated']()
            }
            return res
          }
        })
          .then(client => {
            this.AuthService = client.apis.AuthService
            resolve(client.apis)
          })
          .catch(err => {
            return reject(err)
          })
      })
    }
  }

  /**
   * Sets the access token and renew the Swagger client
   * @param {string} accessToken
   */
  async setAccessToken (accessToken) {
    this.config.accessToken = accessToken
    await this.getSwaggerAuthClientAsync()
  }

  /**
   * Gets the access token
   * @returns {string} The access token
   */
  getAccessToken () {
    return this.config.accessToken
  }

  // Authentication APIs

  /**
   * Starts the authentication flow by getting the password challenge
   * @param {string} handle
   * @returns {object} The response body for 'StartAuthentication' API call
   */
  async startAuthentication (handle) {
    const { AuthService } = this

    const startAuthenticationResponse = await AuthService.StartAuthentication({
      'body': {
        'user_handle': handle
      }
    })
    const startAuthenticationResBody = startAuthenticationResponse.body

    this.handle = handle
    this.temporaryToken = startAuthenticationResBody['temporary_token']
    this._updateChallenges(startAuthenticationResBody)

    return startAuthenticationResBody
  }

  /**
   * Starts SMS authentication by sending a SMS
   * @returns {object} The response body for 'StartAuthenticateSecondFactor' API call
   */
  async startAuthenticateSMS () {
    const { AuthService, temporaryToken } = this

    const startAuthenticateSecondFactorResponse = await AuthService.StartAuthenticateSecondFactor({
      'body': {
        'temporary_token': temporaryToken,
        'challenge': 'SMS_CODE'
      }
    })
    const startAuthenticateSecondFactorResBody = startAuthenticateSecondFactorResponse.body
    return startAuthenticateSecondFactorResBody
  }

  /**
   * Continue the authentication flow with SRP as a factor
   * @param {string} password
   * @returns {object} The response body for 'Authenticate' API call
   */
  async authenticateWithSRP (password) {
    const { AuthService, handle, passwordChallenge, temporaryToken } = this

    const passwordSalt = formatBuffer.fromBase64(passwordChallenge['salt'])
    const challengeToken = passwordChallenge['token']
    const B = formatBuffer.fromBase64(passwordChallenge['B'])

    const hashedPassword = await scrypt(
      formatBuffer.fromString(unicodeNorm.normalize(password)),
      // TODO: Remove hardcoded parameters - https://gitlab.com/blocksq/kitty/issues/110
      formatBuffer.fromString('salt?'),
      16384, 8, 1
    )
    const { A, M1 } = await srp.getAandM1(handle, hashedPassword, passwordSalt, B)
    const authenticateResponse = await AuthService.Authenticate({
      'body': {
        'temporary_token': temporaryToken,
        'password_response': {
          'challenge_token': challengeToken,
          'M1': formatBuffer.toBase64(M1),
          'A': formatBuffer.toBase64(A)
        }
      }
    })
    const authenticateResBody = authenticateResponse.body

    this._updateChallenges(authenticateResBody)
    return authenticateResBody
  }

  /**
   * Continue the authentication flow with TOTP as a factor
   * @param {string} pin
   * @returns {object} The response body for 'AuthenticateSecondFactor' API call
   */
  async authenticateWithTOTP (pin) {
    const { AuthService, temporaryToken } = this

    const authenticateSecondFactorResponse = await AuthService.AuthenticateSecondFactor({
      'body': {
        'temporary_token': temporaryToken,
        'challenge': 'TIME_BASED_ONE_TIME_PASSWORD',
        'answer': pin
      }
    })
    const authenticateSecondFactorResBody = authenticateSecondFactorResponse.body

    this._updateChallenges(authenticateSecondFactorResBody)
    return authenticateSecondFactorResBody
  }

  /**
   * Continue the authentication flow with SMS as a factor
   * @param {string} code
   * @returns {object} The response body for 'AuthenticateSecondFactor' API call
   */
  async authenticateWithSMS (code) {
    const { AuthService, temporaryToken } = this

    const authenticateSecondFactorResponse = await AuthService.AuthenticateSecondFactor({
      'body': {
        'temporary_token': temporaryToken,
        'challenge': 'SMS_CODE',
        'answer': code
      }
    })
    const authenticateSecondFactorResBody = authenticateSecondFactorResponse.body

    this._updateChallenges(authenticateSecondFactorResBody)
    return authenticateSecondFactorResBody
  }

  /**
   * Continue the authentication flow with backup code as a factor
   * @param {string} code
   * @returns {object} The response body for 'AuthenticateSecondFactor' API call
   */
  async authenticateWithBackupCode (code) {
    const { AuthService, temporaryToken } = this

    const authenticateSecondFactorResponse = await AuthService.AuthenticateSecondFactor({
      'body': {
        'temporary_token': temporaryToken,
        'challenge': 'BACKUP_CODE',
        'answer': code
      }
    })
    const authenticateSecondFactorResBody = authenticateSecondFactorResponse.body

    this._updateChallenges(authenticateSecondFactorResBody)
    return authenticateSecondFactorResBody
  }  

  /**
   * Creates an access token from authorization token
   * @param {string} authorizationToken
   * @returns {object} The response body for 'CreateAccessToken' API call
   */
  async createAccessToken (authorizationToken) {
    const { AuthService } = this

    const createAccessTokenResponse = await AuthService.CreateAccessToken({
      'body': {
        'grant_type': 'AUTHORIZATION_TOKEN',
        'token': authorizationToken
      }
    })
    const createAccessTokenResBody = createAccessTokenResponse.body

    await this.setAccessToken(createAccessTokenResBody['access_token'])
    return createAccessTokenResBody
  }

  /**
   * Creates an access token from refresh token
   * @param {string} refreshToken
   * @returns {object} The response body for 'CreateAccessToken' API call
   */
  async createAccessTokenByRefreshToken (refreshToken) {
    const { AuthService } = this

    const createAccessTokenResponse = await AuthService.CreateAccessToken({
      'body': {
        'grant_type': 'REFRESH_TOKEN',
        'token': refreshToken
      }
    })
    const createAccessTokenResBody = createAccessTokenResponse.body

    await this.setAccessToken(createAccessTokenResBody['access_token'])
    return createAccessTokenResBody
  }

  /**
   * Get the current user
   * @returns {object} The current user
   */
  async getCurrentUser () {
    const { AuthService } = this

    const getCurrentUserResponse = await AuthService.GetCurrentUser()
    const getCurrentUserResBody = getCurrentUserResponse.body

    return getCurrentUserResBody
  }

  async updateCurrentUser (user) {
    const { authcoreAPI } = this

    const currentUser = await authcoreAPI.AuthService.UpdateCurrentUser({
      'body': {
        'user': user
      }
    })

    return currentUser
  }

  /**
   * Creates an user
   * @param {object} data Object includes user information to be registered. It should include handle information(username/email/phone) and password, displayName can also be provided.
   */
  async createUser (data) {
    const { username = '', phone = '', email = '', password } = data
    let { displayName } = data
    if (displayName === undefined) {
      if (username !== '') {
        displayName = username
      } else if (email !== '') {
        displayName = email
      } else if (phone !== '') {
        displayName = phone
      } else {
        throw new Error('displayName cannot be undefined')
      }
    }
    if (password === undefined) {
      throw new Error('no password')
    }
    let { AuthService } = this

    // Step 1: Create a user
    const createUserResponse = await AuthService.CreateUser({
      'body': {
        'username': username,
        'email': email,
        'phone': phone,
        'display_name': displayName
      }
    })
    const createUserResBody = createUserResponse.body
    await this.createAccessTokenByRefreshToken(createUserResBody['refresh_token'])
    // We need to replace the old AuthService to use the new instance with access token.
    AuthService = this.AuthService

    // Step 2: Change the password of the created user
    const hashedPassword = await scrypt(
      formatBuffer.fromString(unicodeNorm.normalize(password)),
      // TODO: Remove hardcoded parameters - https://gitlab.com/blocksq/kitty/issues/110
      formatBuffer.fromString('salt?'),
      16384, 8, 1
    )
    const { salt, verifier } = await srp.createVerifier(username, hashedPassword)
    const changePasswordResponse = await AuthService.ChangePassword({
      'body': {
        'password_verifier': {
          'salt': formatBuffer.toBase64(salt),
          'verifier': formatBuffer.toBase64(verifier)
        }
      }
    })
    const changePasswordResBody = changePasswordResponse.body
    return changePasswordResBody
  }

  async changePassword (oldPassword, newPassword) {
    const { AuthService } = this

    const { username } = await this.getCurrentUser()
    const createPasswordChallengeResponse = await AuthService.CreatePasswordChallenge()
    const passwordChallenge = createPasswordChallengeResponse.body
    const oldPasswordSalt = formatBuffer.fromBase64(passwordChallenge['salt'])
    const oldChallengeToken = passwordChallenge['token']
    const oldB = formatBuffer.fromBase64(passwordChallenge['B'])

    const oldHashedPassword = await scrypt(
      formatBuffer.fromString(unicodeNorm.normalize(oldPassword)),
      // TODO: Remove hardcoded parameters - https://gitlab.com/blocksq/kitty/issues/110
      formatBuffer.fromString('salt?'),
      16384, 8, 1
    )
    const { A, M1 } = await srp.getAandM1(username, oldHashedPassword, oldPasswordSalt, oldB)

    const newHashedPassword = await scrypt(
      formatBuffer.fromString(unicodeNorm.normalize(newPassword)),
      // TODO: Remove hardcoded parameters - https://gitlab.com/blocksq/kitty/issues/110
      formatBuffer.fromString('salt?'),
      16384, 8, 1
    )
    const { salt, verifier } = await srp.createVerifier(username, newHashedPassword)
    const changePasswordResponse = await AuthService.ChangePassword({
      'body': {
        'old_password_response': {
          'challenge_token': oldChallengeToken,
          'M1': formatBuffer.toBase64(M1),
          'A': formatBuffer.toBase64(A),
        },
        'password_verifier': {
          'salt': formatBuffer.toBase64(salt),
          'verifier': formatBuffer.toBase64(verifier)
        }
      }
    })
    const changePasswordResBody = changePasswordResponse.body

    return changePasswordResBody
  }

  /**
   * Gets the list of second factors for the current user
   * @returns {object[]} The list of second factors
   */
  async listSecondFactors () {
    const { AuthService } = this

    const listSecondFactorsResponse = await AuthService.ListSecondFactors()
    const listSecondFactorsResBody = listSecondFactorsResponse.body
    return listSecondFactorsResBody['second_factors']
  }

  /**
   * Generates a TOTP secret
   * @returns {string} a TOTP secret
   */
  generateTOTPSecret () {
    return formatBuffer.toString(randomTOTPSecret())
  }

  /**
   * Creates a TOTP authenticator for the current user
   * @param {*} identifier
   * @param {*} totpSecret
   * @param {*} totpPin
   */
  async createTOTPAuthenticator (identifier, totpSecret, totpPin) {
    const { AuthService } = this

    const createSecondFactorResponse = await AuthService.CreateSecondFactor({
      'body': {
        'totp_info': {
          'identifier': identifier,
          'secret': totpSecret,
        },
        'answer': totpPin
      }
    })
    const createSecondFactorResBody = createSecondFactorResponse.body
    return createSecondFactorResBody
  }

  /**
   * Creates a SMS second factor for the current user
   * @param {*} phoneNumber
   */
  async createSMSSecondFactor (phoneNumber) {
    const { AuthService } = this

    const createSecondFactorResponse = await AuthService.CreateSecondFactor({
      'body': {
        'sms_info': {
          'phone_number': phoneNumber
        }
      }
    })
    const createSecondFactorResBody = createSecondFactorResponse.body
    return createSecondFactorResBody
  }

  /**
   * Creates a backup code second factor for the current user
   */
  async createBackupCode () {
    const { AuthService } = this

    const createSecondFactorResponse = await AuthService.CreateSecondFactor({
      'body': {
        'backup_code_info': {},
        'answer': ''
      }
    })
    const createSecondFactorResBody = createSecondFactorResponse.body
    return createSecondFactorResBody
  }

  /**
   * Deletes a second factor for the current user
   * @param {number} id The second factor to be deleted
   */
  async deleteSecondFactor (id) {
    const { AuthService } = this

    const deleteSecondFactorResponse = await AuthService.DeleteSecondFactor({
      'id': id
    })
    const deleteSecondFactorResBody = deleteSecondFactorResponse.body
    return deleteSecondFactorResBody
  }

  /**
   * Creates an email contact
   * @param {string} email The e-mail address to be added
   */
  async createEmailContact (email) {
    const { AuthService } = this

    const createContactResponse = await AuthService.CreateContact({
      'body': {
        'contact': {
          'type': 'EMAIL',
          'value': email
        }
      }
    })
    const createContactResBody = createContactResponse.body

    const startVerifyContactResponse = await AuthService.StartVerifyContact({
      'body': {
        'contact_id': createContactResBody['id']
      }
    })
    const startVerifyContactResBody = startVerifyContactResponse.body
    return startVerifyContactResBody
  }

  /**
   * Creates a phone contact
   * @param {string} phone The phone number to be added
   */
  async createPhoneContact (phone) {
    const { AuthService } = this

    const createContactResponse = await AuthService.CreateContact({
      'body': {
        'contact': {
          'type': 'PHONE',
          'value': phone
        }
      }
    })
    const createContactResBody = createContactResponse.body

    const startVerifyContactResponse = await AuthService.StartVerifyContact({
      'body': {
        'contact_id': createContactResBody['id']
      }
    })
    const startVerifyContactResBody = startVerifyContactResponse.body
    return startVerifyContactResBody
  }

  /**
   * Gets the list of contacts for the current user
   */
  async listContacts (type) {
    const { AuthService } = this

    const listContactsResponse = await AuthService.ListContacts({
      type: type
    })
    const listContactsResBody = listContactsResponse.body
    return listContactsResBody
  }

  /**
   * Deletes a contact for the current user
   * @param {number} contactId The contact to be deleted
   */
  async deleteContact (contactId) {
    const { AuthService } = this

    const deleteContactResponse = await AuthService.DeleteContact({
      'contact_id': contactId
    })
    const deleteContactResBody = deleteContactResponse.body
    return deleteContactResBody
  }

  async startVerifyContact (contactId) {
    const { AuthService } = this

    const startVerifyContactResponse = await AuthService.StartVerifyContact({
      'body': {
        'contact_id': (contactId).toString()
      }
    })
    const startVerifyContactResBody = startVerifyContactResponse.body
    return startVerifyContactResBody
  }

  async updatePrimaryContact (contactId) {
    const { AuthService } = this

    const updatePrimaryContactResponse = await AuthService.UpdatePrimaryContact({
      'contact_id': (contactId).toString()
    })
    const updatePrimaryContactResBody = updatePrimaryContactResponse.body
    return updatePrimaryContactResBody
  }

  /**
   * Verifies a contact by a verification token.
   * The user need not to be authenticated to use this API.
   * @param {string} token The verification token that could verify the contact
   */
  async verifyContactByToken (token) {
    const { AuthService } = this

    const completeVerifyContactResponse = await AuthService.CompleteVerifyContact({
      'body': {
        'token': token
      }
    })
    const completeVerifyContactResBody = completeVerifyContactResponse.body
    return completeVerifyContactResBody
  }

  /**
   * Verifies a contact by a verification code.
   * The user needs to be authenticated to use this API.
   * @param {number} contactId The contact to be verified
   * @param {string} code The verification code that could verify the contact
   */
  async verifyContactByCode (contactId, code) {
    const { AuthService } = this

    const completeVerifyContactResponse = await AuthService.CompleteVerifyContact({
      'body': {
        'code': {
          'contact_id': (contactId).toString(),
          'code': code
        }
      }
    })
    const completeVerifyContactResBody = completeVerifyContactResponse.body
    return completeVerifyContactResBody
  }

  /**
   * Gets the list of sessions for a given user
   * @returns {object[]} The list of sessions
   */
  async listSessions (pageSize, pageToken, ascending) {
    const { AuthService } = this

    const listSessionsResponse = await AuthService.ListSessions({
      'page_size': pageSize,
      'page_token': pageToken,
      'ascending': ascending
    })
    const listSessionsResBody = listSessionsResponse.body
    return listSessionsResBody
  }

  /**
   * Delete session for a given session
   * @param {number} sessionId The session to be deleted
   */
  async deleteSession (sessionId) {
    const { AuthService } = this

    const deleteSessionResponse = await AuthService.DeleteSession({
      'session_id': sessionId
    })
    const deleteSessionResBody = deleteSessionResponse.body
    return deleteSessionResBody
  }

  /**
   * Gets the metadata for the current user.
   * @returns {string} The user metadata
   */
  async getMetadata () {
    const { AuthService } = this

    const getMetadataResponse = await AuthService.GetMetadata()
    const getMetadataResBody = getMetadataResponse.body
    return {
      userMetadata: getMetadataResBody['user_metadata']
    }
  }

  /**
   * Updates the metadata for the current user.
   * @param {string} metadata
   * @returns {string} The updated metadata
   */
  async updateMetadata (userMetadata) {
    const { AuthService } = this
    const updateMetadataResponse = await AuthService.UpdateMetadata({
      'body': {
        'user_metadata': userMetadata
      }
    })
    const updateMetadataResBody = updateMetadataResponse.body
    return {
      userMetadata: updateMetadataResBody['user_metadata']
    }
  }

  /**
   * Validates the OAuth parameters on the client.  Throws error if the parameters are not valid.
   * @param {string} responseType
   * @param {string} clientId
   * @param {string} redirectUri
   * @param {string} scope
   * @param {string} state
   */
  async validateOAuthParameters (responseType, clientId, redirectUri, scope, state) {
    const { AuthService } = this
    await AuthService.ValidateOAuthParameters({
      'response_type': responseType,
      'client_id': clientId,
      'redirect_uri': redirectUri,
      'scope': scope,
      'state': state
    })
  }

  async startResetPasswordAuthentication (handle) {
    const { AuthService } = this

    const startResetPasswordAuthenticationResponse = await AuthService.StartResetPasswordAuthentication({
      'body': {
        'user_handle': handle
      }
    })
    const startResetPasswordAuthenticationResBody = startResetPasswordAuthenticationResponse.body

    this.handle = handle
    this.temporaryToken = startResetPasswordAuthenticationResBody['temporary_token']
    this._updateChallenges(startResetPasswordAuthenticationResBody)

    return startResetPasswordAuthenticationResBody
  }

  async authenticateResetPasswordWithContact (token) {
    const { AuthService, temporaryToken } = this

    const authenticateResetPasswordResponse = await AuthService.AuthenticateResetPassword({
      'body': {
        'temporary_token': temporaryToken,
        'contact_token': {
          'token': token
        }
      }
    })
    const authenticateResetPasswordResBody = authenticateResetPasswordResponse.body

    this._updateChallenges(authenticateResetPasswordResBody)
    return authenticateResetPasswordResBody
  }

  async resetPassword (resetPasswordToken, newPassword) {
    const { AuthService } = this

    // In the current implementation, the username would not affect the password.
    const username = ''

    const newHashedPassword = await scrypt(
      formatBuffer.fromString(unicodeNorm.normalize(newPassword)),
      // TODO: Remove hardcoded parameters - https://gitlab.com/blocksq/kitty/issues/110
      formatBuffer.fromString('salt?'),
      16384, 8, 1
    )
    const { salt, verifier } = await srp.createVerifier(username, newHashedPassword)
    const resetPasswordResponse = await AuthService.ResetPassword({
      'body': {
        'token': resetPasswordToken,
        'password_verifier': {
          'salt': formatBuffer.toBase64(salt),
          'verifier': formatBuffer.toBase64(verifier)
        }
      }
    })
    const resetPasswordResBody = resetPasswordResponse.body

    return resetPasswordResBody
  }

  async startAuthenticateOAuth (service) {
    const { AuthService } = this

    const startAuthenticateOAuthResponse = await AuthService.StartAuthenticateOAuth({
      'service': service.toUpperCase()
    })
    const startAuthenticateOAuthResBody = startAuthenticateOAuthResponse.body
    
    return startAuthenticateOAuthResBody['oauth_endpoint_uri']
  }

  async authenticateOAuth (service, state, code) {
    const { AuthService } = this

    const authenticateOAuthResponse = await AuthService.Authenticate({
      'body': {
        'temporary_token': state, // = temporaryToken
        'oauth_response': {
          'service': service.toUpperCase(),
          'code': code
        }
      }
    })
    const authenticateOAuthResBody = authenticateOAuthResponse.body
    return authenticateOAuthResBody
  }

  async listOAuthFactors () {
    const { AuthService } = this

    const listOAuthFactorsResponse = await AuthService.ListOAuthFactors()
    const listOAuthFactorsResBody = listOAuthFactorsResponse.body
    return listOAuthFactorsResBody['oauth_factors']
  }

  async startCreateOAuthFactor (service) {
    const { AuthService } = this

    const startCreateOAuthFactorResponse = await AuthService.StartCreateOAuthFactor({
      'service': service.toUpperCase()
    })
    const startCreateOAuthFactorResBody = startCreateOAuthFactorResponse.body
    
    return startCreateOAuthFactorResBody['oauth_endpoint_uri']
  }

  async createOAuthFactor (service, state, code) {
    const { AuthService } = this

    const createOAuthFactorResponse = await AuthService.CreateOAuthFactor({
      'body': {
        'service': service.toUpperCase(),
        'state': state,
        'code': code
      }
    })
    const createOAuthFactorResBody = createOAuthFactorResponse.body
    return createOAuthFactorResBody
  }

  async deleteOAuthFactor (id) {
    const { AuthService } = this

    const deleteOAuthFactorResponse = await AuthService.DeleteOAuthFactor({
      'id': id
    })
    const deleteOAuthFactorResBody = deleteOAuthFactorResponse.body
    return deleteOAuthFactorResBody
  }

  // Private functions
  /**
   * Updates the challenge to the class instance, given the response body for StartAuthentication
   * or Authenticate.
   * @param {object} resBody
   */
  _updateChallenges (resBody) {
    // Reset challenges
    this.passwordChallenge = undefined
    // Load challenges
    if (resBody['challenges'] === undefined) return

    resBody['challenges'].forEach(challenge => {
      switch (challenge) {
        case 'SECURE_REMOTE_PASSWORD':
          this.passwordChallenge = resBody['password_challenge']
        break
        case 'TIME_BASED_ONE_TIME_PASSWORD': break
        case 'SMS_CODE': break
        case 'CONTACT_TOKEN': break
        case 'BACKUP_CODE': break
        /* istanbul ignore next */
        default: throw new Error(`Authentication method ${challenge} is not implemented`)
      }
    })
  }
}

exports.AuthCoreAuthClient = AuthCoreAuthClient
