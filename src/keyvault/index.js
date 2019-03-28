// swagger wrapper
const Swagger = require('swagger-client')

const formatBuffer = require('../utils/formatBuffer.js')

/**
 * Class interacting between AuthCore Web (and corresponding web clients) and the key vault.
 * Wrap interactive steps into functions.
 *
 * `config` is an object that contains:
 * 1. `apiBaseURL`: the base URL for the API endpoint.
 * 2. `callbacks`: the callback functions, listed below:
 *  - `unauthenticated`: callback when an user calls an API while not authenticated.
 * 3. `accessToken`: the access token of the user for the authenticated APIs.
 */
class AuthCoreKeyVaultClient {
  constructor (config) {
    return new Promise(async (resolve, reject) => {
      this.config = config

      // Set accessToken into API
      await this.setAccessToken(config.accessToken)

      resolve(this)
    })
  }

    /**
   * Constructs Swagger key vault client
   */
  async getSwaggerKeyVaultClientAsync () {
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
        const swaggerJsonURL = `${this.config.apiBaseURL}/api/keyvaultapi/keyvault.swagger.json`
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
            this.KeyVaultService = client.apis.KeyVaultService
            resolve(client.apis)
          })
          .catch(err => {
            return reject(err)
          })
      })
    }
  }

  /**
   * Sets the access token
   * @param {string} accessToken
   */
  async setAccessToken (accessToken) {
    if (accessToken !== undefined) {
      this.config.accessToken = accessToken
      await this.getSwaggerKeyVaultClientAsync()
    }
  }

  /**
   * Gets the access token
   * @returns {string} The access token
   */
  getAccessToken () {
    return this.config.accessToken
  }

  // Key Vault APIs
  /**
   * Create a secret.
   * @param {string} type The type of the secret
   * @param {number} size The size (in bytes) of the secret
   */
  async createSecret (type, size) {
    const { KeyVaultService } = this
    const performOperationResponse = await KeyVaultService.PerformOperation({
      'body': {
        'create_secret': {
          'type': type,
          'size': size
        }
      }
    })
    const performOperationResBody = performOperationResponse.body
    return performOperationResBody
  }

  /**
   * List the HD child public keys the current user has.
   */
  async listHDChildPublicKeys (pathPrefix) {
    const { KeyVaultService } = this
    const performOperationResponse = await KeyVaultService.PerformOperation({
      'body': {
        'list_hd_child_public_keys': {
          'path': `${pathPrefix}`
        }
      }
    })
    const performOperationResBody = performOperationResponse.body
    return performOperationResBody['hd_child_public_keys'] || []
  }

  /**
   * Signs an Ethereum payload (transaction / message).
   *
   * @param {string} objectId
   * @param {string} walletPath
   * @param {buffer} data The payload to be signed.
   */
  async ethereumSign (objectId, walletPath, data, type) {
    const { KeyVaultService } = this
    const performOperationResponse = await KeyVaultService.PerformOperation({
      'body': {
        'ethereum_sign': {
          'type': type,
          'object_id': objectId,
          'wallet_path': walletPath,
          'data': formatBuffer.toHex(data)
        }
      }
    })
    const performOperationResBody = performOperationResponse.body
    return performOperationResBody['signature']
  }
}

exports.AuthCoreKeyVaultClient = AuthCoreKeyVaultClient
