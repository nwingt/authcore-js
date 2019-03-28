/* global suite, test */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const { assert } = chai

const { mockAPI } = require('./api_helpers/mock.js')
const { AuthCoreKeyVaultClient } = require('../src/index.js')
const { AuthCoreWalletSubprovider } = require('../src/web3_provider.js')

suite('web3_provider.js', function () {
  suite('AuthCoreWalletSubprovider', function () {
    test('getAccounts', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerKeyVaultClient' },
        { type: 'OperationListHDChildPublicKeys' }
      ])
      // Test
      const authcoreClient = await new AuthCoreKeyVaultClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const walletSubprovider = AuthCoreWalletSubprovider({ authcoreClient })
      function callback (err, accounts) {
        assert.isNull(err)
        assert.deepEqual(accounts, [
          '0xe255D058f0473db9a54a6a25401B0AAe99c0567b'
        ])
      }
      await walletSubprovider.getAccounts(callback)
    })
    test('signTransaction', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerKeyVaultClient' },
        { type: 'OperationListHDChildPublicKeys' },
        { type: 'OperationEthereumSignTx' }
      ])
      // Test
      const authcoreClient = await new AuthCoreKeyVaultClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const walletSubprovider = AuthCoreWalletSubprovider({ authcoreClient })
      function callback (err, signedTx) {
        assert.isNull(err)
        assert.equal(
          signedTx,
          '0xf87e84313333378a313030303030303030308094bce00fd336be3be338458e93efc80da14f8a3e0593313030303030303030303030303030303030308025a0068cfd3c9760ca8ec2fa9c62b3c384aadbea79c87d93e401175e7c3f2351212da03fe388fd0628ab07c59d5cffa15f2fc99db7e5729ad29928852beff3ee0a43f0'
        )
      }
      // Test
      new Promise(function (resolve, reject) {
        walletSubprovider.getAccounts(resolve)
      }).then(function () {
        walletSubprovider.signTransaction({
          nonce: '1337',
          gasPrice: '1000000000', // 1gwei
          gasLimit: '21000',
          from: '0xe255D058f0473db9a54a6a25401B0AAe99c0567b',
          to: '0xBCe00FD336be3be338458e93EfC80Da14f8a3e05',
          value: '1000000000000000000' // 1ETH
        }, callback)
      })
    })
    test('signMessage', async function () {
      // Mock
      mockAPI([
        { type: 'SwaggerKeyVaultClient' },
        { type: 'OperationListHDChildPublicKeys' },
        { type: 'OperationEthereumSignMessage' }
      ])
      const authcoreClient = await new AuthCoreKeyVaultClient({
        apiBaseURL: 'http://0.0.0.0:13337',
        accessToken: 'AN_ACCESS_TOKEN'
      })
      const walletSubprovider = AuthCoreWalletSubprovider({ authcoreClient })
      function callback (err, signature) {
        assert.isNull(err)
        assert.equal(
          signature,
          '0xc204e2055af32c4aff80efd74cdb741b4c738abf366d5b2d4d253bc3b2f34f2116a6e4f721836d780b6d4f9986704d503c774d06ef08da66734673131441b5d41b'
        )
      }
      // Test
      new Promise(function (resolve, reject) {
        walletSubprovider.getAccounts(resolve)
      }).then(function () {
        walletSubprovider.signMessage({
          data: 'hello',
          from: '0xe255D058f0473db9a54a6a25401B0AAe99c0567b'
        }, callback)
      })
    })
  })
})