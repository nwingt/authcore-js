const EthereumTx = require('ethereumjs-tx')
const BigNumber = require('bignumber.js')
const HookedWalletSubprovider = require('web3-provider-engine/subproviders/hooked-wallet.js')
const { publicToAddress, toChecksumAddress } = require('ethereumjs-util')
const hdKey = require('hdkey')

const { AuthCoreKeyVaultClient } = require('./keyvault/index.js')
const { AuthCoreWidgets } = require('./widgets')
const formatBuffer = require('./utils/formatBuffer')

/**
 * The Authcore-integrated web3 wallet subprovider.
 *
 * @public
 * @param {object} config The config object.
 * @param {AuthCoreKeyVaultClient} config.authcoreClient The KeyVaultClient instance for the API
 *        calls.
 * @param {string} config.authcoreWidgetsUrl The base URL for the Authcore widgets.
 * @param {string} [config.pathPrefix=m/44'/60'/0'/0] The prefix of the derivation path.
 * @param {number} [config.accountCount=1] The number of accounts.
 * @param {number} [config.chainId=1] The chain ID.
 * @param {string} config.container The ID of the DOM element that injects the widget.
 * @returns {HookedWalletSubprovider} Hooked wallet subprovider defined by the
 *          [MetaMask/web3-provider-engine](https://github.com/MetaMask/web3-provider-engine/)
 *          repository.
 */
function AuthCoreWalletSubprovider (config) {
  const authcoreClient = config.authcoreClient
  const authcoreWidgetsUrl = config.authcoreWidgetsUrl
  const pathPrefix = config.pathPrefix || `m/44'/60'/0'/0`
  const accountCount = config.accountCount || 1
  const chainId = config.chainId || 1
  const container = config.container
  let addresses = []

  /**
   * Lists the owned accounts.
   *
   * @memberof AuthCoreWalletSubprovider
   * @param {Function} cb Callback function defined by the HookedWalletSubprovider.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async function getAccounts (cb) {
    let error = null
    let res = null
    try {
      const publicKeys = await authcoreClient.listHDChildPublicKeys(pathPrefix)
      addresses = []
      for (let keyId = 0; keyId < publicKeys.length; keyId++) {
        const publicKey = publicKeys[keyId]
        const hdkey = hdKey.fromExtendedKey(publicKey['extended_public_key'])

        for (let childId = 0; childId < accountCount; childId++) {
          const childKey = hdkey.derive(`m/${childId}`)
          const address = toChecksumAddress(
            formatBuffer.toHex(
              publicToAddress(formatBuffer.fromHex(childKey.publicKey), true)
            )
          )
          addresses.push({
            id: publicKey['id'],
            path: `${pathPrefix}/${childId}`,
            address
          })
        }
      }
      res = addresses.map(addressObj => addressObj['address'])
    } catch (err) {
      console.error(err)
      error = err
    }
    cb(error, res)
  }

  /**
   * Creates an Authcore widget for the user to approve signing an Ethereum transaction (or
   * message).
   *
   * @memberof AuthCoreWalletSubprovider
   * @param {string} type The type of the payload.
   * @returns {Function} Wrapper function for approve.
   */
  function approve (type) {
    return function (txObject, cb) {
      new AuthCoreWidgets.EthereumSignApproval({ // eslint-disable-line no-new
        container,
        root: authcoreWidgetsUrl,
        accessToken: authcoreClient.getAccessToken(),
        approve: () => cb(null, true),
        reject: () => cb(null, false)
      })
    }
  }

  /**
   * Signs a transaction.
   *
   * @memberof AuthCoreWalletSubprovider
   * @param {object} txObject The transaction object.
   * @param {Function} cb Callback function defined by the HookedWalletSubprovider.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async function signTransaction (txObject, cb) {
    let error = null
    let res = null
    try {
      const { nonce, gasPrice, gas: gasLimit, from, to, value } = txObject
      const data = '0x'

      const tx = new EthereumTx({
        nonce,
        gasPrice,
        gasLimit,
        to,
        value,
        data,
        v: chainId,
        r: '',
        s: ''
      })
      const txData = tx.serialize()
      const { id: objectId, path } = addresses.find(addressObj => addressObj['address'].toLowerCase() === from.toLowerCase())
      const sign = await authcoreClient.ethereumSign(objectId, path, txData, 'TRANSACTION')

      const r = `0x${sign.substr(0, 64)}`
      const s = `0x${sign.substr(64, 64)}`
      // The correct v should be 'v (parity) + 35 + 2 * chain_id' according to EIP-155.
      // Reference: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
      const v = '0x' + BigNumber(sign.substr(128, 2), 16).plus(35 + 2 * chainId).toString(16)

      const signedTx = new EthereumTx({
        nonce, gasPrice, gasLimit, to, value, data, v, r, s
      })
      const signedTxData = formatBuffer.toHex(signedTx.serialize())
      res = `0x${signedTxData}`
    } catch (err) {
      console.error(err)
      error = err
    }
    cb(error, res)
  }

  /**
   * Signs a message.
   *
   * @memberof AuthCoreWalletSubprovider
   * @param {object} msgObject The message object.
   * @param {Function} cb Callback function defined by the HookedWalletSubprovider.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async function signMessage (msgObject, cb) {
    let error = null
    let res = null
    try {
      const { from, data } = msgObject
      const { id: objectId, path } = addresses.find(addressObj => addressObj['address'].toLowerCase() === from.toLowerCase())
      const sign = await authcoreClient.ethereumSign(objectId, path, formatBuffer.fromHex(data.substr(2)), 'MESSAGE')
      const v = BigNumber(sign.substr(128, 2), 16).plus(27).toString(16)
      const updatedSign = `${sign.substr(0, 128)}${v}`
      res = `0x${updatedSign}`
    } catch (err) {
      console.error(err)
      error = err
    }
    cb(error, res)
  }

  /**
   * Signs a personal message.
   *
   * @memberof AuthCoreWalletSubprovider
   * @param {object} msgObject The message object.
   * @param {Function} cb Callback function defined by the HookedWalletSubprovider.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async function signPersonalMessage (msgObject, cb) {
    let error = null
    let res = null
    try {
      const { from, data } = msgObject
      const { id: objectId, path } = addresses.find(addressObj => addressObj['address'].toLowerCase() === from.toLowerCase())
      const sign = await authcoreClient.ethereumSign(objectId, path, formatBuffer.fromHex(data.substr(2)), 'PERSONAL_MESSAGE')
      const v = BigNumber(sign.substr(128, 2), 16).plus(27).toString(16)
      const updatedSign = `${sign.substr(0, 128)}${v}`
      res = `0x${updatedSign}`
    } catch (err) {
      console.error(err)
      error = err
    }
    cb(error, res)
  }

  /**
   * Signs a typed message (version 1 for `eth_signTypedData`).
   *
   * @memberof AuthCoreWalletSubprovider
   * @param {object} msgObject The message object.
   * @param {Function} cb Callback function defined by the HookedWalletSubprovider.
   * @returns {Promise<undefined>} Undefined when succeed, throws an error when failed.
   */
  async function signTypedMessage (msgObject, cb) {
    let error = null
    let res = null
    try {
      const { from, data } = msgObject
      const { id: objectId, path } = addresses.find(addressObj => addressObj['address'].toLowerCase() === from.toLowerCase())
      const sign = await authcoreClient.ethereumSign(objectId, path, formatBuffer.fromString(JSON.stringify(data)), 'TYPED_MESSAGE')
      const v = BigNumber(sign.substr(128, 2), 16).plus(27).toString(16)
      const updatedSign = `${sign.substr(0, 128)}${v}`
      res = `0x${updatedSign}`
    } catch (err) {
      console.error(err)
      error = err
    }
    cb(error, res)
  }

  return new HookedWalletSubprovider({
    getAccounts,
    approveTransaction: approve('transaction'),
    approveMessage: approve('message'),
    approvePersonalMessage: approve('personal message'),
    approveTypedMessage: approve('typed message'),
    signTransaction,
    signMessage,
    signPersonalMessage,
    signTypedMessage
  })
}

exports.AuthCoreWalletSubprovider = AuthCoreWalletSubprovider
