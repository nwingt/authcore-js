const { AuthCoreAuthClient } = require('./auth/index.js')
const { AuthCoreKeyVaultClient } = require('./keyvault/index.js')
const { AuthCoreManagementClient } = require('./management/index.js')
const { AuthCoreWalletSubprovider } = require('./web3_provider.js')
const { AuthCoreCosmosProvider } = require('./cosmos_provider.js')
const { AuthCoreWidgets } = require('./widgets.js')

// Provide AuthCoreWidgets in browser to provide simplest example for AuthCoreWidgets
if (global.window !== undefined && typeof global.window.define === 'function' && global.window.define.amd) {
  global.window.define('AuthCoreWidgets', function () {
    return AuthCoreWidgets
  })
} else if (global.window) {
  global.window.AuthCoreWidgets = AuthCoreWidgets
}

exports.AuthCoreAuthClient = AuthCoreAuthClient
exports.AuthCoreKeyVaultClient = AuthCoreKeyVaultClient
exports.AuthCoreManagementClient = AuthCoreManagementClient
exports.AuthCoreWalletSubprovider = AuthCoreWalletSubprovider
exports.AuthCoreCosmosProvider = AuthCoreCosmosProvider
exports.AuthCoreWidgets = AuthCoreWidgets
