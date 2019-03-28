const EthereumTx = require('ethereumjs-tx')
const BigNumber = require('bignumber.js')
const HookedWalletSubprovider = require('web3-provider-engine/subproviders/hooked-wallet.js')
const { publicToAddress, toChecksumAddress } = require('ethereumjs-util')
const hdKey = require('hdkey')

const { AuthCoreWidgets } = require('./widgets')
const formatBuffer = require('./utils/formatBuffer')

function AuthCoreWalletSubprovider (config) {
  const authcoreClient = config.authcoreClient
  const pathPrefix = config.pathPrefix || `m/44'/60'/0'/0`
  const accountCount = config.accountCount || 1
  const chainId = config.chainId || 1
  const container = config.container
  let addresses = []

  async function getAccounts (cb) {
    let error = null, res
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
      res = null
    }
    cb(error, res)
  }

  function approve (type) {
    return function (txObject, cb) {
      new AuthCoreWidgets.EthereumSignApproval({
        container,
        root: config.authcoreWidgetsUrl,
        accessToken: authcoreClient.getAccessToken(),
        approve: () => cb(null, true),
        reject: () => cb(null, false)
      })
    }
  }

  async function signTransaction (txObject, cb) {
    let error = null, res
    try {
      const { nonce, gasPrice, gas: gasLimit, from, to, value } = txObject
      const data = '0x'

      const tx = new EthereumTx({
        nonce, gasPrice, gasLimit, to, value, data,
        v: chainId, r: '', s: ''
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
      res = null
    }
    cb(error, res)
  }

  async function signMessage (msgObject, cb) {
    let error = null, res
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
      res = null
    }
    cb(error, res)
  }

  async function signPersonalMessage (msgObject, cb) {
    let error = null, res
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
      res = null
    }
    cb(error, res)
  }

  async function signTypedMessage (msgObject, cb) {
    let error = null, res
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
      res = null
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
