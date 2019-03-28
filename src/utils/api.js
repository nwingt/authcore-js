// swagger wrapper
const Swagger = require('swagger-client')

class AuthCoreAPI {
  /**
   * Creates an AuthCoreAPI instance.
   * @param {string} apiBaseURL The base URL for the API endpoint
   * @param {object} callbacks The list of callback functions:
   *        - unauthenticated: callback when an user calls an API while not authenticated.
   */
  constructor (apiBaseURL, callbacks) {
    this.apiBaseURL = apiBaseURL
    this.accessToken = {
      expiresAt: new Date(0),
      token: undefined
    }
    this.authClient = undefined
    this.mgmtClient = undefined
    this.keyVaultClient = undefined

    this.AuthService = ServiceProxy(this, 'AuthCore', callbacks)
    this.ManagementService = ServiceProxy(this, 'Management', callbacks)
    this.KeyVaultService = ServiceProxy(this, 'KeyVault', callbacks)
  }

  /**
   * Gets the client.  If a refresh token is given, a valid access token will be injected.
   * @returns {Object} The client, with valid access token injected, containing the list of APIs.
   */
  async getAuthClient () {
    const { refreshToken } = this
    if (this._isRefreshAccessToken()) {
      await this._getSwaggerAuthClient()
      const createAccessTokenResponse = await this.authClient.AuthService.CreateAccessToken({
        'body': {
          'grant_type': 'REFRESH_TOKEN',
          'token': refreshToken
        }
      }, {
        // `scheme` parameter is added to avoid calling the swagger service from picking
        // the first scheme given in authcore.swagger.json (that is, HTTP).
        // This fixes from using HTTP swagger service from a HTTPS client.
        scheme: this.apiBaseURL.split(':')[0]
      })
      const createAccessTokenResBody = createAccessTokenResponse.body
      this.setAccessToken(
        createAccessTokenResBody['access_token'], createAccessTokenResBody['expires_in']
      )
      this.authClient = undefined
    }

    // Ensure the access token is valid (if signed in)
    if (this.authClient === undefined) {
      await this._getSwaggerAuthClient()
    }
    return this.authClient
  }

  /**
   * Gets the client.  If a refresh token is given, a valid access token will be injected.
   * @returns {Object} The client, with valid access token injected, containing the list of APIs.
   */
  async getMgmtClient () {
    const { refreshToken } = this
    if (this._isRefreshAccessToken()) {
      await this._getSwaggerAuthClient()
      const createAccessTokenResponse = await this.authClient.AuthService.CreateAccessToken({
        'body': {
          'grant_type': 'REFRESH_TOKEN',
          'token': refreshToken
        }
      }, {
        // `scheme` parameter is added to avoid calling the swagger service from picking
        // the first scheme given in authcore.swagger.json (that is, HTTP).
        // This fixes from using HTTP swagger service from a HTTPS client.
        scheme: this.apiBaseURL.split(':')[0]
      })
      const createAccessTokenResBody = createAccessTokenResponse.body
      this.setAccessToken(
        createAccessTokenResBody['access_token'], createAccessTokenResBody['expires_in']
      )
    }

    // Ensure the access token is valid (if signed in)
    if (this.mgmtClient === undefined) {
      await this._getSwaggerMgmtClient()
    }
    return this.mgmtClient
  }

  /**
   * Gets the client.  If a refresh token is given, a valid access token will be injected.
   * @returns {Object} The client, with valid access token injected, containing the list of APIs.
   */
  async getKeyVaultClient () {
    const { refreshToken } = this
    if (this._isRefreshAccessToken()) {
      await this._getSwaggerAuthClient()
      const createAccessTokenResponse = await this.authClient.AuthService.CreateAccessToken({
        'body': {
          'grant_type': 'REFRESH_TOKEN',
          'token': refreshToken
        }
      }, {
        // `scheme` parameter is added to avoid calling the swagger service from picking
        // the first scheme given in authcore.swagger.json (that is, HTTP).
        // This fixes from using HTTP swagger service from a HTTPS client.
        scheme: this.apiBaseURL.split(':')[0]
      })
      const createAccessTokenResBody = createAccessTokenResponse.body
      this.setAccessToken(
        createAccessTokenResBody['access_token'], createAccessTokenResBody['expires_in']
      )
    }

    // Ensure the access token is valid (if signed in)
    if (this.keyVaultClient === undefined) {
      await this._getSwaggerKeyVaultClient()
    }
    return this.keyVaultClient
  }

  /**
   * Sets the refresh token.
   * @param {String} refreshToken
   */
  setRefreshToken (refreshToken) {
    this.refreshToken = refreshToken
    this.accessToken = {
      expiresAt: new Date(0),
      token: undefined
    }
    this.authClient = undefined
    this.mgmtClient = undefined
  }

  /**
   * Sets the access token.
   * @param {String} accessToken
   * @param {Number} expiresIn Expiry in seconds
   */
  setAccessToken (accessToken, expiresIn) {
    this.accessToken.token = accessToken
    this.accessToken.expiresAt = new Date(
      new Date().getTime() + expiresIn * 1000
    )
  }


  // private functions

  /**
   * Gets the Swagger authentication client and puts it in `this.authClient`.
   */
  async _getSwaggerAuthClient () {
    const { apiBaseURL, accessToken } = this
    let authorizations
    if (accessToken.token !== undefined) {
      authorizations = {
        'BearerAuth': {
          'value': `Bearer ${accessToken.token}`
        }
      }
    }
    this.authClient = await new Promise(function (resolve, reject) {
      const swaggerJsonURL = `${apiBaseURL}/api/authapi/authcore.swagger.json`
      Swagger({
        url: swaggerJsonURL,
        authorizations
      })
        .then(client => resolve(client.apis))
        .catch(err => reject(err))
    })
  }

  /**
   * Gets the Swagger management client and puts it in `this.mgmtClient`.
   */
  async _getSwaggerMgmtClient () {
    const { apiBaseURL, accessToken } = this
    let authorizations
    if (accessToken.token !== undefined) {
      authorizations = {
        'BearerAuth': {
          'value': `Bearer ${accessToken.token}`
        }
      }
    }
    this.mgmtClient = await new Promise(function (resolve, reject) {
      const swaggerJsonURL = `${apiBaseURL}/api/managementapi/management.swagger.json`
      Swagger({
        url: swaggerJsonURL,
        authorizations
      })
        .then(client => resolve(client.apis))
        .catch(err => reject(err))
    })
  }

  /**
   * Gets the Swagger key vault client and puts it in `this.keyVaultClient`.
   */
  async _getSwaggerKeyVaultClient () {
    const { apiBaseURL, accessToken } = this
    let authorizations
    if (accessToken.token !== undefined) {
      authorizations = {
        'BearerAuth': {
          'value': `Bearer ${accessToken.token}`
        }
      }
    }
    this.keyVaultClient = await new Promise(function (resolve, reject) {
      const swaggerJsonURL = `${apiBaseURL}/api/keyvaultapi/keyvault.swagger.json`
      Swagger({
        url: swaggerJsonURL,
        authorizations
      })
        .then(client => resolve(client.apis))
        .catch(err => reject(err))
    })
  }

  /**
   * Checks whether the access token needs to be refreshed.
   */
  _isRefreshAccessToken () {
    if (this.refreshToken === undefined) {
      return false
    }
    return this.accessToken.expiresAt < new Date()
  }
}

/**
 * Wraps AuthCoreAPI / ManagementAPI by intercepting the API calls beforehand / afterwards.
 * Before calling the APIs,
 *  1. A valid access token will be requested, and
 *  2. The scheme will be changed to https (or http) according to the current scheme.
 * After calling the APIs,
 *  1. callbacks would be triggered when an user is unauthenticated, it would trigger callbacks after calling the authenticated APIs.
 * @param {*} authcoreAPI
 * @param {string} type The type of service.  Either `AuthCore` or `Management`.
 * @param {object} callbacks The list of callback functions
 *        - unauthenticated: callback when an user calls an API while not authenticated.
 */
function ServiceProxy (authcoreAPI, type, callbacks) {
  return new Proxy(authcoreAPI, {
    get: function (target, prop) {
      return async function (params, opts) {
        let client
        /* istanbul ignore else */
        if (type === 'AuthCore') {
          client = await target.getAuthClient()
          /* istanbul ignore else */
          if (prop in client.AuthService) {
            try {
              // `scheme` parameter is added to avoid calling the swagger service from picking
              // the first scheme given in authcore.swagger.json (that is, HTTP).
              // This fixes from using HTTP swagger service from a HTTPS client.
              // ~ https://gitlab.com/blocksq/kitty/issues/214

              // The code was once: `const res = await client.AuthService[prop](...arguments, { scheme: ... })`
              // However, when there are no arguments, `...arguments` would be nothing and `{ scheme: ... }`
              // would instead be the first argument (i.e. for "parameters") - which is not the correct place.
              // Adding an `params` variable would keep the `{ scheme: ... }` being the second argument to the call.
              // ~ https://gitlab.com/blocksq/kitty/issues/299
              const mergedOpts = Object.assign({
                scheme: authcoreAPI.apiBaseURL.split(':')[0]
              }, opts)

              const res = await client.AuthService[prop](params, mergedOpts)
              return res
            } catch (err) {
              statusCodeHandler(err.statusCode, callbacks)
              throw err
            }
          } else {
            throw new Error(`${prop} is not implemented in AuthService`)
          }
        } else if (type === 'Management') {
          client = await target.getMgmtClient()
          /* istanbul ignore else */
          if (prop in client.ManagementService) {
            try {
              // `scheme` parameter is added to avoid calling the swagger service from picking
              // the first scheme given in authcore.swagger.json (that is, HTTP).
              // This fixes from using HTTP swagger service from a HTTPS client.
              // ~ https://gitlab.com/blocksq/kitty/issues/214

              // The code was once: `const res = await client.AuthService[prop](...arguments, { scheme: ... })`
              // However, when there are no arguments, `...arguments` would be nothing and `{ scheme: ... }`
              // would instead be the first argument (i.e. for "parameters") - which is not the correct place.
              // Adding an `params` variable would keep the `{ scheme: ... }` being the second argument to the call.
              // ~ https://gitlab.com/blocksq/kitty/issues/299
              const mergedOpts = Object.assign({
                scheme: authcoreAPI.apiBaseURL.split(':')[0]
              }, opts)

              const res = await client.ManagementService[prop](params, mergedOpts)
              return res
            } catch (err) {
              statusCodeHandler(err.statusCode, callbacks)
              throw err
            }
          } else {
            throw new Error(`${prop} is not implemented in ManagementService`)
          }
        } else if (type === 'KeyVault') {
          client = await target.getKeyVaultClient()
          /* istanbul ignore else */
          if (prop in client.KeyVaultService) {
            try {
              // `scheme` parameter is added to avoid calling the swagger service from picking
              // the first scheme given in authcore.swagger.json (that is, HTTP).
              // This fixes from using HTTP swagger service from a HTTPS client.
              // ~ https://gitlab.com/blocksq/kitty/issues/214

              // The code was once: `const res = await client.AuthService[prop](...arguments, { scheme: ... })`
              // However, when there are no arguments, `...arguments` would be nothing and `{ scheme: ... }`
              // would instead be the first argument (i.e. for "parameters") - which is not the correct place.
              // Adding an `params` variable would keep the `{ scheme: ... }` being the second argument to the call.
              // ~ https://gitlab.com/blocksq/kitty/issues/299
              const mergedOpts = Object.assign({
                scheme: authcoreAPI.apiBaseURL.split(':')[0]
              }, opts)

              const res = await client.KeyVaultService[prop](params, mergedOpts)
              return res
            } catch (err) {
              statusCodeHandler(err.statusCode, callbacks)
              throw err
            }
          } else {
            throw new Error(`${prop} is not implemented in KeyVaultService`)
          }
        } else {
          throw new Error(`${type} is not a valid type for service proxy`)
        }
      }
    }
  })
}

/**
 * Handles status code
 * @param {number} statusCode The status code received when calling an API
 * @param {object} callbacks The list of callback functions
 *        - unauthenticated: callback when an user calls an API while not authenticated.
 */
function statusCodeHandler (statusCode, callbacks) {
  switch (statusCode) {
    case 401:
      if (typeof callbacks['unauthorized'] === 'function') {
        callbacks['unauthorized']()
      }
      break
    case 403:
      if (typeof callbacks['unauthenticated'] === 'function') {
        callbacks['unauthenticated']()
      }
      break
  }
}

exports.AuthCoreAPI = AuthCoreAPI
