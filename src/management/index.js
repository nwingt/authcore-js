// swagger wrapper
const Swagger = require('swagger-client')

const srp = require('../crypto/srp.js')
const { scrypt } = require('../crypto/scrypt.js')
const formatBuffer = require('../utils/formatBuffer.js')
const unicodeNorm = require('../utils/unicodeNorm.js')

/**
 * Class interacting between AuthCore Web (and corresponding web clients) and the management.
 * Wrap interactive steps into functions.
 *
 * `config` is an object that contains:
 * 1. `apiBaseURL`: the base URL for the API endpoint.
 * 2. `callbacks`: the callback functions, listed below:
 *  - `unauthenticated`: callback when an user calls an API while not authenticated.
 * 3. `accessToken`: the access token of the user for the authenticated APIs.
 */
class AuthCoreManagementClient {
  constructor (config) {
    return new Promise(async (resolve, reject) => {
      this.config = config

      // Set accessToken into API
      await this.setAccessToken(config.accessToken)

      resolve(this)
    })
  }

  /**
   * Constructs Swagger management client
   */
  async getSwaggerMgmtClientAsync () {
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
        const swaggerJsonURL = `${this.config.apiBaseURL}/api/managementapi/management.swagger.json`
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
            this.ManagementService = client.apis.ManagementService
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
      await this.getSwaggerMgmtClientAsync()
    }
  }

  /**
   * Gets the access token
   * @returns {string} The access token
   */
  getAccessToken () {
    return this.config.accessToken
  }

  // Management APIs

  /**
   * Gets the list of users
   * @param {number} pageSize The number of items return for the page
   * @param {string} pageToken The token required for the specific page result
   * @param {boolean} ascending The order for the result
   * @returns {object} Object include the list of users, next page token and total size of all audit logs return.
   */
  async listUsers (pageSize, pageToken, ascending) {
    const { ManagementService } = this

    const listUsersResponse = await ManagementService.ListUsers({
      'page_size': pageSize,
      'page_token': pageToken,
      'ascending': ascending
    })
    const listUsersResBody = listUsersResponse.body
    return listUsersResBody
  }

  /**
   * Gets the user with given user ID
   * @param {string} userId The string representation for the user ID
   * @returns {object} The user with given ID
   */
  async getUser (userId) {
    const { ManagementService } = this

    const getUserResponse = await ManagementService.GetUser({
      'user_id': userId.toString()
    })
    const getUserResBody = getUserResponse.body
    return getUserResBody
  }

  /**
   * Updates the user profile with given user ID
   * @returns {object} The updated user information
   */
  async updateUserProfile (userId, userObject) {
    const { ManagementService } = this

    const updateUserResponse = await ManagementService.UpdateUser({
      'user_id': userId,
      'body': {
        'user': userObject
      }
    })
    const updateUserResBody = updateUserResponse.body
    return updateUserResBody
  }

  /**
   * Updates the user lock status with given user ID
   * @returns {object} The updated user information
   */
  async updateUserLock (userId, locked, lockInDays, description) {
    const { ManagementService } = this

    let lockExpiredAt
    if (locked) {
      if (lockInDays === Infinity) {
        lockExpiredAt = '2038-01-19T00:00:00Z'
      } else if (parseFloat(lockInDays) > 0) {
        lockExpiredAt = new Date(new Date().getTime() + 86400000 * parseFloat(lockInDays)).toISOString()
      } else {
        throw new Error('lock in days should be positive')
      }
    }

    const updateUserResponse = await ManagementService.UpdateUser({
      'user_id': userId,
      'body': {
        'user': {
          'locked': locked,
          'lock_expired_at': lockExpiredAt,
          'lock_description': description
        },
        'type': 'LOCK'
      }
    })
    const updateUserResBody = updateUserResponse.body
    return updateUserResBody
  }

  /**
   * Creates an email contact by admin
   * @param {string} userId The id of the user
   * @param {string} email The e-mail address to be added
   */
  async createEmailContact (userId, email) {
    const { ManagementService } = this

    const createContactResponse = await ManagementService.CreateContact({
      'user_id': userId,
      'body': {
        'contact': {
          'type': 'EMAIL',
          'value': email
        }
      }
    })
    const createContactResBody = createContactResponse.body

    const startVerifyContactResponse = await ManagementService.StartVerifyContact({
      body: {
        'contact_id': createContactResBody['id']
      }
    })
    const startVerifyContactResBody = startVerifyContactResponse.body
    return startVerifyContactResBody
  }

  /**
   * Creates an phone contact by admin
   * @param {string} userId The id of the user
   * @param {string} phone The phone to be added
   */
  async createPhoneContact (userId, phone) {
    const { ManagementService } = this

    const createContactResponse = await ManagementService.CreateContact({
      'user_id': userId,
      'body': {
        'contact': {
          'type': 'PHONE',
          'value': phone
        }
      }
    })
    const createContactResBody = createContactResponse.body

    const startVerifyContactResponse = await ManagementService.StartVerifyContact({
      body: {
        'contact_id': createContactResBody['id']
      }
    })
    const startVerifyContactResBody = startVerifyContactResponse.body
    return startVerifyContactResBody
  }

  /**
   * Gets the list of contacts for the given user ID
   * @returns {array} The list of contacts
   */
  async listContacts (userId, type) {
    const { ManagementService } = this

    const listContactsResponse = await ManagementService.ListContacts({
      'user_id': userId,
      type: type
    })
    const listContactsResBody = listContactsResponse.body
    return listContactsResBody
  }

  /**
   * Updates a primary contact
   * @param {number} contactId The contact to be updated as a primary contact
   */
  async updatePrimaryContact (contactId) {
    const { ManagementService } = this

    const updatePrimaryContactResponse = await ManagementService.UpdatePrimaryContact({
      'contact_id': contactId
    })
    const updatePrimaryContactResBody = updatePrimaryContactResponse.body
    return updatePrimaryContactResBody
  }

  /**
   * Deletes a contact
   * @param {number} contactId The contact to be deleted
   */
  async deleteContact (contactId) {
    const { ManagementService } = this

    const deleteContactResponse = await ManagementService.DeleteContact({
      'contact_id': contactId
    })
    const deleteContactResBody = deleteContactResponse.body
    return deleteContactResBody
  }

  /**
   * Initiate the process of contact verification
   * @param {number} contactId The contact to be verified
   */
  async startVerifyContact (contactId) {
    const { ManagementService } = this

    const startVerifyContactResponse = await ManagementService.StartVerifyContact({
      'contact_id': (contactId).toString()
    })
    const startVerifyContactResBody = startVerifyContactResponse.body
    return startVerifyContactResBody
  }

  /**
   * Gets the list of second factors for the current user
   * @returns {object[]} The list of second factors
   */
  async listSecondFactors (id) {
    const { ManagementService } = this

    const listSecondFactorsResponse = await ManagementService.ListSecondFactors({
      'user_id': id.toString()
    })
    const listSecondFactorsResBody = listSecondFactorsResponse.body
    return listSecondFactorsResBody['second_factors']
  }

  /**
   * Gets the list of audit logs
   * @param {number} pageSize The number of items return for the page
   * @param {string} pageToken The token required for the specific page result
   * @param {boolean} ascending The order for the result
   * @returns {object} Object include the list of audit logs, next page token and total size of all audit logs return.
   */
  async listAuditLogs (pageSize, pageToken, ascending) {
    const { ManagementService } = this

    const listAuditLogsResponse = await ManagementService.ListAuditLogs({
      'page_size': pageSize,
      'page_token': pageToken,
      'ascending': ascending
    })
    const listAuditLogsResBody = listAuditLogsResponse.body
    return listAuditLogsResBody
  }

  /**
   * Gets the list of audit logs for the given user ID
   * @param {string} userId The id string respresents a user
   * @param {number} pageSize The number of items return for the page
   * @param {string} pageToken The token required for the specific page result
   * @param {boolean} ascending The order for the result
   * @returns {object} Object include the list of audit logs, next page token and total size of all audit logs return.
   */
  async listUserAuditLogs (userId, pageSize, pageToken, ascending) {
    const { ManagementService } = this

    const listUserAuditLogsResponse = await ManagementService.ListAuditLogs({
      'user_id': userId,
      'page_size': pageSize,
      'page_token': pageToken,
      'ascending': ascending
    })
    const listUserAuditLogsResBody = listUserAuditLogsResponse.body
    return listUserAuditLogsResBody
  }

  /**
   * Gets the list of roles
   * @returns {array} The list of roles
   */
  async listRoles () {
    const { ManagementService } = this

    const listRolesResponse = await ManagementService.ListRoles()
    const listRolesResBody = listRolesResponse.body
    return listRolesResBody['roles']
  }

  async createRole (name) {
    const { ManagementService } = this

    const createRoleResponse = await ManagementService.CreateRole({
      'body': {
        'name': name
      }
    })
    const createRoleResBody = createRoleResponse.body
    return createRoleResBody
  }

  async deleteRole (roleId) {
    const { ManagementService } = this

    const deleteRoleResponse = await ManagementService.DeleteRole({
      'role_id': roleId
    })
    const deleteRoleResBody = deleteRoleResponse.body
    return deleteRoleResBody
  }

  /**
   * Assigns the specified role to the given user
   */
  async assignRole (userId, roleId) {
    const { ManagementService } = this

    const assignRoleResponse = await ManagementService.AssignRole({
      'user_id': userId,
      'body': {
        'role_id': roleId.toString()
      }
    })
    const assignRoleResBody = assignRoleResponse.body
    return assignRoleResBody
  }

  /**
   * Unassigns the specified role from the given user
   */
  async unassignRole (userId, roleId) {
    const { ManagementService } = this

    const unassignRoleResponse = await ManagementService.UnassignRole({
      'user_id': userId,
      'role_id': roleId
    })
    const unassignRoleResBody = unassignRoleResponse.body
    return unassignRoleResBody
  }

  /**
   * Gets the list of roles for the given user ID
   * @returns {array} The list of roles
   */
  async listRoleAssignments (userId) {
    const { ManagementService } = this

    const listRoleAssignmentsResponse = await ManagementService.ListRoleAssignments({
      'user_id': userId
    })
    const listRoleAssignmentsResBody = listRoleAssignmentsResponse.body
    return listRoleAssignmentsResBody['roles']
  }

  /**
   * Gets the list of permissions for the given role ID
   * @returns {array} The list of permissions
   */
  async listPermissionAssignments (roleId) {
    const { ManagementService } = this

    const listPermissionAssignmentsResponse = await ManagementService.ListPermissionAssignments({
      'role_id': roleId
    })
    const listPermissionAssignmentsResBody = listPermissionAssignmentsResponse.body
    return listPermissionAssignmentsResBody['permissions']
  }

  /**
   * Gets the list of permissions for the current user
   * @returns {array} The list of permissions
   */
  async listCurrentUserPermissions () {
    const { ManagementService } = this

    const listCurrentUserPermissionsResponse = await ManagementService.ListCurrentUserPermissions()
    const listCurrentUserPermissionsResBody = listCurrentUserPermissionsResponse.body
    return listCurrentUserPermissionsResBody['permissions']
  }

  /**
   * Creates an user under an admin role
   * @param {string} username
   * @param {string} password
   * @param {string} email
   * @param {string} phone
   * @param {string} displayName
   */
  async createUser (username, password, email, phone, displayName) {
    const { ManagementService } = this

    // Step 1: Create a user
    const createUserResponse = await ManagementService.CreateUser({
      'body': {
        'username': username,
        'email': email,
        'phone': phone,
        'display_name': displayName
      }
    })
    const createUserResBody = createUserResponse.body
    const userId = createUserResBody['user']['id']

    // Step 2: Change the password of the created user
    const hashedPassword = await scrypt(
      formatBuffer.fromString(unicodeNorm.normalize(password)),
      // TODO: Remove hardcoded parameters - https://gitlab.com/blocksq/kitty/issues/110
      formatBuffer.fromString('salt?'),
      16384, 8, 1
    )
    const { salt, verifier } = await srp.createVerifier(username, hashedPassword)
    await ManagementService.ChangePassword({
      'body': {
        'user_id': userId.toString(),
        'password_verifier': {
          'salt': formatBuffer.toBase64(salt),
          'verifier': formatBuffer.toBase64(verifier)
        }
      }
    })
  }

  /**
   * Changes a password of an user
   * @param {string} userId
   * @param {string} newPassword
   */
  async changePassword (userId, newPassword) {
    const { ManagementService } = this

    const { username } = await this.getUser(userId)
    const newHashedPassword = await scrypt(
      formatBuffer.fromString(unicodeNorm.normalize(newPassword)),
      // TODO: Remove hardcoded parameters - https://gitlab.com/blocksq/kitty/issues/110
      formatBuffer.fromString('salt?'),
      16384, 8, 1
    )
    const { salt, verifier } = await srp.createVerifier(username, newHashedPassword)
    const changePasswordResponse = await ManagementService.ChangePassword({
      'body': {
        'user_id': userId.toString(),
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
   * Gets the list of sessions for a given user
   * @returns {object[]} The list of sessions
   */
  async listSessions (userId, pageSize, pageToken, ascending) {
    const { ManagementService } = this

    const listSessionsResponse = await ManagementService.ListSessions({
      'user_id': userId,
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
    const { ManagementService } = this

    const deleteSessionResponse = await ManagementService.DeleteSession({
      'session_id': sessionId
    })
    const deleteSessionResBody = deleteSessionResponse.body
    return deleteSessionResBody
  }

  /**
   * Gets the metadata for a given user.
   * @param {number} userId
   * @returns {string} The user metadata
   */
  async getMetadata (userId) {
    const { ManagementService } = this

    const getMetadataResponse = await ManagementService.GetMetadata({
      'user_id': userId
    })
    const getMetadataResBody = getMetadataResponse.body
    return {
      userMetadata: getMetadataResBody['user_metadata'],
      appMetadata: getMetadataResBody['app_metadata']
    }
  }

  /**
   * Updates the metadata for a given user.
   * @param {number} userId
   * @param {string} userMetadata
   * @param {string} appMetadata
   * @returns {string} The updated metadata
   */
  async updateMetadata (userId, userMetadata, appMetadata) {
    const { ManagementService } = this
    const updateMetadataResponse = await ManagementService.UpdateMetadata({
      'user_id': userId,
      'body': {
        'user_metadata': userMetadata,
        'app_metadata': appMetadata
      }
    })
    const updateMetadataResBody = updateMetadataResponse.body
    return {
      userMetadata: updateMetadataResBody['user_metadata'],
      appMetadata: updateMetadataResBody['app_metadata']
    }
  }
}

exports.AuthCoreManagementClient = AuthCoreManagementClient
