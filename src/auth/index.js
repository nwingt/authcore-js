// swagger wrapper
const Swagger = require('swagger-client')

const spake2 = require('../crypto/spake2.js')
const { randomTOTPSecret } = require('../crypto/random.js')
const formatBuffer = require('../utils/formatBuffer.js')

/**
 * The class interacting between web client and AuthCore AuthAPI server.
 *
 * @public
 * @param {object} config
 * @param {string} config.apiBaseURL The base URL for the Authcore instance.
 * @param {object} config.callbacks The set of callback functions to-be called.
 * @param {Function} config.callbacks.unauthenticated The callback function when a user is
 *        unauthenticated.
 * @param {string} config.accessToken The access token of the user.
 * @returns {Promise<AuthCoreAuthClient>} The AuthClient.
 * @example
 * const authClient = await new AuthCoreAuthClient({
 *   apiBaseURL: 'https://auth.example.com',
 *   callbacks: {
 *     unauthenticated: function () {
 *       alert('unauthenticated!')
 *     }
 *   },
 *   accessToken: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJle...'
 * })
 */
class AuthCoreAuthClient {
  constructor (config) {
    return new Promise(async (resolve, reject) => { // eslint-disable-line no-async-promise-executor
      this.config = config

      this.temporaryToken = undefined
      this.deviceToken = undefined
      this.handle = undefined
      this.passwordChallenge = undefined

      // Set accessToken into API
      await this.setAccessToken(config.accessToken)

      return resolve(this)
    })
  }

  /**
   * Sets the access token and refreshes the Swagger client.
   *
   * @public
   * @param {string} accessToken The access token of the user.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async setAccessToken (accessToken) {
    this.config.accessToken = accessToken
    await this._getSwaggerClient()
  }

  /**
   * Gets the access token.
   *
   * @public
   * @returns {string} The access token of the user.
   */
  getAccessToken () {
    return this.config.accessToken
  }

  /**
   * Creates a new authentication flow by requesting a password challenge from the server.
   *
   * @public
   * @param {string} handle A handle of a user. Could be username, email address or phone number.
   * @returns {Promise<AuthenticationState>} The authentication state.
   */
  async startAuthentication (handle) {
    const { AuthService } = this

    const startPasswordAuthnResponse = await AuthService.StartPasswordAuthn({
      'body': {
        'user_handle': handle
      }
    })
    const startPasswordAuthnResBody = startPasswordAuthnResponse.body

    this.handle = handle
    this.temporaryToken = startPasswordAuthnResBody['temporary_token']
    this._updateChallenges(startPasswordAuthnResBody)

    return startPasswordAuthnResBody
  }

  /**
   * Authenticates a user by password, under the SPAKE2+ protocol.
   *
   * @public
   * @param {string} password The password of the user.
   * @returns {Promise<AuthenticationState>} The authentication state.
   */
  async authenticateWithPassword (password) {
    const { AuthService, salt, temporaryToken } = this

    const state = await spake2.spake2.startClient('authcoreuser', 'authcore', password, salt)
    const message = state.getMessage()
    const startAuthenticatePasswordResponse = await AuthService.PasswordAuthnKeyExchange({
      'body': {
        'temporary_token': temporaryToken,
        'message': formatBuffer.toBase64(message)
      }
    })
    const startAuthenticatePasswordResBody = startAuthenticatePasswordResponse.body
    const incomingMessage = formatBuffer.fromBase64(startAuthenticatePasswordResBody['password_challenge']['message'])
    const challengeToken = startAuthenticatePasswordResBody['password_challenge']['token']

    const sharedSecret = state.finish(incomingMessage)
    const confirmation = sharedSecret.getConfirmation()

    const authenticateResponse = await AuthService.FinishPasswordAuthn({
      'body': {
        'temporary_token': temporaryToken,
        'password_response': {
          'token': challengeToken,
          'confirmation': formatBuffer.toBase64(confirmation)
        }
      }
    })
    const authenticateResBody = authenticateResponse.body

    this._updateChallenges(authenticateResBody)
    return authenticateResBody
  }

  /**
   * Authenticates a user by time-based one time password (TOTP).
   *
   * @public
   * @param {string} pin The PIN received in the authenticator device of the user.
   * @returns {Promise<AuthenticationState>} The authentication state.
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
   * Requests a SMS for the second-factor authentication using SMS.
   *
   * @public
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async startAuthenticateSMS () {
    const { AuthService, temporaryToken } = this
    await AuthService.StartAuthenticateSecondFactor({
      'body': {
        'temporary_token': temporaryToken,
        'challenge': 'SMS_CODE'
      }
    })
  }

  /**
   * Authenticates a user by verifying the authentication code from SMS.
   *
   * @public
   * @param {string} code The SMS code received by the authenticating phone number of the user.
   * @returns {Promise<AuthenticationState>} The authentication state.
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
   * Authenticates a user by the backup code.
   *
   * @public
   * @param {string} code The backup code of the user.
   * @returns {Promise<AuthenticationState>} The authentication state.
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
   * Creates an access token from the authorization token.
   *
   * @public
   * @param {string} authorizationToken A one-use token that is used to generate refresh token and
   *        access token.
   * @returns {Promise<AccessToken>} The access token.
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
   * Creates an access token from refresh token.
   *
   * @public
   * @param {string} refreshToken A token that can be repeatedly generate access tokens.
   * @returns {Promise<AccessToken>} The access token.
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
   * Get the current user.
   *
   * @public
   * @returns {Promise<object>} The current user.
   */
  async getCurrentUser () {
    const { AuthService } = this

    const getCurrentUserResponse = await AuthService.GetCurrentUser()
    const getCurrentUserResBody = getCurrentUserResponse.body

    return getCurrentUserResBody
  }

  /**
   * Updates the current user.
   *
   * @public
   * @param {object} user The purposed update for the current user.
   * @returns {Promise<object>} The updated current user.
   */
  async updateCurrentUser (user) {
    const { AuthService } = this

    const updateCurrentUserResponse = await AuthService.UpdateCurrentUser({
      'body': {
        'user': user
      }
    })
    const updateCurrentUserResBody = updateCurrentUserResponse.body

    return updateCurrentUserResBody
  }

  /**
   * Creates an user.
   *
   * @public
   * @param {object} user The user object.
   * @param {string} user.username The purposed username of the user.
   * @param {string} user.phone The purposed phone number of the user.
   * @param {string} user.email The purposed email address of the user.
   * @param {string} user.password The purposed password of the user.
   * @param {string} user.displayName The purposed display name of the user.
   * @returns {Promise<AccessToken>} The access token.
   */
  async createUser (user) {
    const { username = '', phone = '', email = '', password } = user
    let { displayName } = user
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
        'display_name': displayName,
        'send_verification': true
      }
    })
    const createUserResBody = createUserResponse.body
    const accessToken = await this.createAccessTokenByRefreshToken(createUserResBody['refresh_token'])
    // We need to replace the old AuthService to use the new instance with access token.
    AuthService = this.AuthService

    // Step 2: Change the password of the created user
    const { salt, verifier } = await spake2.createVerifier(password)
    await AuthService.FinishChangePassword({
      'body': {
        'password_verifier': {
          'salt': salt,
          'verifierW0': verifier.w0,
          'verifierL': verifier.L
        }
      }
    })
    return accessToken
  }

  /**
   * Creates an user using OAuth.
   *
   * @public
   * @param {object} user The user object.
   * @param {string} user.username The purposed username of the user.
   * @param {string} user.phone The purposed phone number of the user.
   * @param {string} user.email The purposed email address of the user.
   * @param {string} user.displayName The purposed display name of the user.
   * @param {object} oauth The OAuth object.
   * @param {string} oauth.accessToken The access token for OAuth.
   * @param {string} oauth.service The service for OAuth.
   * @returns {Promise<AccessToken>} The access token.
   */
  async createUserByOAuth (user, oauth) {
    const { username = '', phone = '', email = '' } = user
    let { displayName } = user
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
    let { AuthService } = this

    // Step 1: Create a user
    const createUserResponse = await AuthService.CreateUser({
      'body': {
        'username': username,
        'email': email,
        'phone': phone,
        'display_name': displayName,
        'send_verification': false
      }
    })
    const createUserResBody = createUserResponse.body
    const accessToken = await this.createAccessTokenByRefreshToken(createUserResBody['refresh_token'])
    // We need to replace the old AuthService to use the new instance with access token.
    AuthService = this.AuthService

    // Step 2: Verify the contact by OAuth access token
    await AuthService.CompleteVerifyContact({
      'body': {
        'oauth_access_token': {
          'access_token': oauth.accessToken,
          'id_token': oauth.idToken,
          'service': oauth.service
        }
      }
    })

    // Step 3: Create a OAuth factor by OAuth access token
    await AuthService.CreateOAuthFactorByAccessToken({
      'body': {
        'access_token': oauth.accessToken,
        'id_token': oauth.idToken,
        'service': oauth.service
      }
    })
    return accessToken
  }

  /**
   * Changes the password of the current user.
   *
   * @public
   * @param {string} oldPassword The old password of the user.
   * @param {string} newPassword The purposed new password of the user.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async changePassword (oldPassword, newPassword) {
    const { AuthService } = this

    const startChangePasswordResponse = await AuthService.StartChangePassword()
    const startChangePasswordResBody = startChangePasswordResponse.body
    const oldSalt = formatBuffer.fromBase64(startChangePasswordResBody['salt'])

    const oldState = await spake2.spake2.startClient('authcoreuser', 'authcore', oldPassword, oldSalt)
    const oldMessage = oldState.getMessage()
    const changePasswordKeyExchangeResponse = await AuthService.ChangePasswordKeyExchange({
      'body': {
        'message': formatBuffer.toBase64(oldMessage)
      }
    })
    const changePasswordKeyExchangeResBody = changePasswordKeyExchangeResponse.body
    const incomingMessage = formatBuffer.fromBase64(changePasswordKeyExchangeResBody['message'])
    const oldChallengeToken = changePasswordKeyExchangeResBody['token']

    const sharedSecret = oldState.finish(incomingMessage)
    const confirmation = sharedSecret.getConfirmation()
    const { salt, verifier } = await spake2.createVerifier(newPassword)
    await AuthService.FinishChangePassword({
      'body': {
        'old_password_response': {
          'token': oldChallengeToken,
          'confirmation': formatBuffer.toBase64(confirmation)
        },
        'password_verifier': {
          'salt': salt,
          'verifierW0': verifier.w0,
          'verifierL': verifier.L
        }
      }
    })
  }

  /**
   * Lists the owned second factors.
   *
   * @public
   * @returns {Promise<object[]>} The list of second factors.
   */
  async listSecondFactors () {
    const { AuthService } = this

    const listSecondFactorsResponse = await AuthService.ListSecondFactors()
    const listSecondFactorsResBody = listSecondFactorsResponse.body
    return listSecondFactorsResBody['second_factors']
  }

  /**
   * Generates a secret for time-based one-time password (TOTP).
   *
   * @returns {string} A secret for time-based one-time password.
   */
  generateTOTPSecret () {
    return formatBuffer.toString(randomTOTPSecret())
  }

  /**
   * Creates a time-based one-time password (TOTP) as a second factor for the current user.
   *
   * @public
   * @param {string} identifier The identifier of the TOTP authenticator.
   * @param {string} totpSecret The secret for the TOTP authenticator.
   * @param {string} totpPin The PIN received in the authenticator device of the user.
   * @returns {Promise<object>} The second factor object.
   */
  async createTOTPAuthenticator (identifier, totpSecret, totpPin) {
    const { AuthService } = this

    const createSecondFactorResponse = await AuthService.CreateSecondFactor({
      'body': {
        'totp_info': {
          'identifier': identifier,
          'secret': totpSecret
        },
        'answer': totpPin
      }
    })
    const createSecondFactorResBody = createSecondFactorResponse.body
    return createSecondFactorResBody
  }

  /**
   * Start creating SMS as a second factor for the current user.
   *
   * @public
   * @param {string} phoneNumber The phone number for the SMS authentication.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async startCreateSMSSecondFactor (phoneNumber) {
    const { AuthService } = this

    await AuthService.StartCreateSecondFactor({
      'body': {
        'sms_info': {
          'phone_number': phoneNumber
        }
      }
    })
  }

  /**
   * Creates a SMS authentication as a second factor for the current user.
   *
   * @public
   * @param {string} phoneNumber The phone number for the SMS authentication.
   * @param {string} smsCode The sms code for verifying the authentication setting.
   * @returns {Promise<object>} The second factor object.
   */
  async createSMSSecondFactor (phoneNumber, smsCode) {
    const { AuthService } = this

    const createSecondFactorResponse = await AuthService.CreateSecondFactor({
      'body': {
        'sms_info': {
          'phone_number': phoneNumber
        },
        'answer': smsCode
      }
    })
    const createSecondFactorResBody = createSecondFactorResponse.body
    return createSecondFactorResBody
  }

  /**
   * Creates a backup code as a second factor for the current user.
   *
   * @public
   * @returns {Promise<object>} The second factor object.
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
   * Deletes an owned second factor.
   *
   * @public
   * @param {number} id The ID of the second factor to-be deleted.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async deleteSecondFactor (id) {
    const { AuthService } = this
    await AuthService.DeleteSecondFactor({
      'id': id
    })
  }

  /**
   * Creates an email contact.
   *
   * @public
   * @param {string} email The e-mail address to be created as a contact.
   * @returns {Promise<object>} The newly created email id and value.
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
    await AuthService.StartVerifyContact({
      'body': {
        'contact_id': createContactResBody['id']
      }
    })
    return createContactResBody
  }

  /**
   * Creates a phone contact.
   *
   * @public
   * @param {string} phone The phone number to be created as a contact.
   * @returns {Promise<object>} The newly created phone id and value.
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
    await AuthService.StartVerifyContact({
      'body': {
        'contact_id': createContactResBody['id']
      }
    })
    return createContactResBody
  }

  /**
   * Lists the owned contacts.
   *
   * @public
   * @param {string} [type] The type of contacts, either `phone` or `email`.
   * @returns {Promise<object[]>} The list of contacts.
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
   * Deletes a owned contact.
   *
   * @public
   * @param {number} contactId The ID of the contact to-be deleted.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async deleteContact (contactId) {
    const { AuthService } = this
    await AuthService.DeleteContact({
      'contact_id': contactId
    })
  }

  /**
   * Starts to verify an owned contact by requesting a verification email / SMS.
   *
   * @public
   * @param {string} contactId The ID of the contact to-be verified.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async startVerifyContact (contactId) {
    const { AuthService } = this
    await AuthService.StartVerifyContact({
      'body': {
        'contact_id': contactId.toString()
      }
    })
  }

  /**
   * Changes the primary contact.
   *
   * @public
   * @param {string} contactId The ID of the new primary contact.
   * @returns {Promise<object>} The primary contact object.
   */
  async updatePrimaryContact (contactId) {
    const { AuthService } = this

    const updatePrimaryContactResponse = await AuthService.UpdatePrimaryContact({
      'contact_id': (contactId).toString()
    })
    const updatePrimaryContactResBody = updatePrimaryContactResponse.body
    return updatePrimaryContactResBody
  }

  /**
   * Verifies a contact by verification token (the user need not to be authenticated to use this).
   *
   * @public
   * @param {string} token The verification token.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async verifyContactByToken (token) {
    const { AuthService } = this
    await AuthService.CompleteVerifyContact({
      'body': {
        'token': token
      }
    })
  }

  /**
   * Verifies a contact by verification code.
   *
   * @public
   * @param {number} contactId The ID of the contact to-be verified.
   * @param {string} code The verification code.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async verifyContactByCode (contactId, code) {
    const { AuthService } = this
    await AuthService.CompleteVerifyContact({
      'body': {
        'code': {
          'contact_id': (contactId).toString(),
          'code': code
        }
      }
    })
  }

  /**
   * Lists the owned sessions.
   *
   * @public
   * @param {number} pageSize The number of sessions per page.
   * @param {string} pageToken The page token.
   * @param {boolean} ascending Boolean flag indicating the order of the sessions.
   * @returns {Promise<object>} The list of sessions.
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
   * Deletes an owned session.
   *
   * @public
   * @param {number} sessionId The ID of the session to-be deleted.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async deleteSession (sessionId) {
    const { AuthService } = this
    await AuthService.DeleteSession({
      'session_id': sessionId
    })
  }

  /**
   * Gets the metadata for the current user.
   *
   * @public
   * @returns {Promise<Metadata>} The metadata object.
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
   *
   * @public
   * @param {string} userMetadata The user metadata to-be.
   * @returns {Promise<Metadata>} The metadata object.
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
   * Validates the OAuth parameters on the client for the authorization request stated in
   * [Section 4.1.1 of RFC6749](https://tools.ietf.org/html/rfc6749#section-4). Throws error if the
   * parameters are not valid. As of now, only authorization code grant is implemented.
   *
   * @public
   * @param {string} responseType Should either be "code" ~~or "token" (implicit grant is not
   *        implemented)~~.
   * @param {string} clientId The client identifier issued to the client by the Authcore OAuth
   *        endpoint.
   * @param {string} redirectUri The URI to be redirected after authenticated.
   * @param {string} scope The scope of the access request.
   * @param {string} state An opaque value used by the client to maintain the state between the
   *        request and callback.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
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

  /**
   * Creates a new reset password flow by sending an email to the email address or a SMS to the
   * phone number, depending the type of handle user has input.
   *
   * @public
   * @param {string} handle A handle of the user. Should either be a email address or a phone
   *        number.
   * @returns {Promise<object>} The authentication state for reset password.
   */
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

  /**
   * Authenticates a user by contact token for resetting password.
   *
   * @public
   * @param {string} token The contact token for reset password.
   * @returns {Promise<object>} The authentication state for reset password.
   */
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

  /**
   * Resets a user password given the reset password token and the new password.
   *
   * @public
   * @param {string} resetPasswordToken An one-use token that is used to reset password.
   * @param {string} newPassword The new password of the user.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async resetPassword (resetPasswordToken, newPassword) {
    const { AuthService } = this

    const { salt, verifier } = await spake2.createVerifier(newPassword)
    await AuthService.ResetPassword({
      'body': {
        'token': resetPasswordToken,
        'password_verifier': {
          'salt': salt,
          'verifierW0': verifier.w0,
          'verifierL': verifier.L
        }
      }
    })
  }

  /**
   * Initiates the OAuth authentication flow.
   *
   * @public
   * @param {string} service The external OAuth service used.
   * @returns {Promise<string>} The URI of the OAuth endpoint.
   */
  async startAuthenticateOAuth (service) {
    const { AuthService } = this

    const startAuthenticateOAuthResponse = await AuthService.StartAuthenticateOAuth({
      'service': service.toUpperCase()
    })
    const startAuthenticateOAuthResBody = startAuthenticateOAuthResponse.body

    return startAuthenticateOAuthResBody['oauth_endpoint_uri']
  }

  /**
   * Validates the OAuth parameters on the client for the authorization request stated in
   * [Section 4.1.2 of RFC6749](https://tools.ietf.org/html/rfc6749#section-4). Throws error if the.
   *
   * @public
   * @param {string} service The external OAuth service used.
   * @param {string} state An opaque value used by the client to maintain the state between the
   *        request and callback.
   * @param {string} code The authorization code returned by the external OAuth service.
   * @returns {Promise<object>} An object consisting of `authentication_state`, `create_account` and
   *          `preferred_email`.
   */
  async authenticateOAuth (service, state, code) {
    const { AuthService } = this

    const authenticateOAuthResponse = await AuthService.AuthenticateOAuth({
      'body': {
        'temporary_token': state, // = temporaryToken
        'oauth_response': {
          'service': service.toUpperCase(),
          'code': code
        }
      }
    })
    const authenticateOAuthResBody = authenticateOAuthResponse.body
    if (authenticateOAuthResBody['authentication_state']) {
      this._updateChallenges(authenticateOAuthResBody['authentication_state'])
    }
    return authenticateOAuthResBody
  }

  /**
   * Lists the owned OAuth factors.
   *
   * @public
   * @returns {Promise<object[]>} The list of OAuth factors.
   */
  async listOAuthFactors () {
    const { AuthService } = this

    const listOAuthFactorsResponse = await AuthService.ListOAuthFactors()
    const listOAuthFactorsResBody = listOAuthFactorsResponse.body
    return listOAuthFactorsResBody['oauth_factors']
  }

  /**
   * Initiates the create OAuth factor flow.
   *
   * @public
   * @param {string} service The external OAuth service used.
   * @returns {Promise<string>} The URI of the OAuth endpoint.
   */
  async startCreateOAuthFactor (service) {
    const { AuthService } = this

    const startCreateOAuthFactorResponse = await AuthService.StartCreateOAuthFactor({
      'service': service.toUpperCase()
    })
    const startCreateOAuthFactorResBody = startCreateOAuthFactorResponse.body

    return startCreateOAuthFactorResBody['oauth_endpoint_uri']
  }

  /**
   * Creates a OAuth factor by the response of the OAuth response.
   *
   * @public
   * @param {string} service The external OAuth service used.
   * @param {string} state An opaque value used by the client to maintain the state between the
   *        request and callback.
   * @param {string} code The authorization code returned by the external OAuth service.
   * @returns {Promise<AuthenticationState>} The authentication state.
   */
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

  /**
   * Deletes an owned OAuth factor.
   *
   * @public
   * @param {number} id The ID of the OAuth factor to-be deleted.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async deleteOAuthFactor (id) {
    const { AuthService } = this
    await AuthService.DeleteOAuthFactor({
      'id': id
    })
  }

  /**
   * Signs out from the current session.
   *
   * @public
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async signOut () {
    const { AuthService } = this
    await AuthService.DeleteCurrentSession()
  }

  /**
   * Constructs auth client including interceptor for unauthorized and unauthenticated cases to run
   * callbacks from client implementation.
   *
   * @private
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async _getSwaggerClient () {
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
   * Updates the challenge to the class instance, given the `AuthenticationState` entity defined by
   * the protocol buffers.
   *
   * @private
   * @param {object} res A response body from the authentication flow. Equivalently the
   *        `AuthenticationState` entity defined by the protocol buffers.
   */
  _updateChallenges (res) {
    // Reset challenges
    this.passwordChallenge = undefined
    // Load challenges
    if (res['challenges'] === undefined) return

    res['challenges'].forEach(challenge => {
      switch (challenge) {
        case 'PASSWORD':
          this.salt = formatBuffer.fromBase64(res['password_salt'])
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

/**
 * @typedef {object} AuthenticationState The `AuthenticationState` entity defined by the protocol
 *          buffers.
 * @property {string} temporary_token The temporary token during authentication.
 * @property {boolean} authenticated Boolean flag indicating if the authentication flow is
 *           completed.
 * @property {string} authenticated_user_id The authenticated user ID if the authentication flow is
 *           completed.
 * @property {string[]} challenges The list of challenges that can be completed to continue the
 *           authentication flow.
 * @property {object} password_challenge The challenge for the password under the SPAKE protocol.
 * @property {string} authorization_token The authorization token if the authentication flow is
 *           completed.
 */

/**
 * @typedef {object} AccessToken The `AccessToken` entity defined by the protocol buffers.
 * @property {string} access_token The access token.
 * @property {string} refresh_token The refresh token.
 * @property {string} id_token The ID token.
 * @property {string} token_type The token type.
 * @property {string} expires_in The lifetime (in seconds) of the access token.
 */

/**
 * @typedef {object} Metadata
 * @property {string} userMetadata The user metadata.
 */

exports.AuthCoreAuthClient = AuthCoreAuthClient
