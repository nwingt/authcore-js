const { AuthCoreAuthClient } = require('./auth/index.js')
const { AuthCoreKeyVaultClient } = require('./keyvault/index.js')
const { AuthCoreManagementClient } = require('./management/index.js')
const { AuthCoreWalletSubprovider } = require('./web3_provider.js')
const { AuthCoreCosmosProvider } = require('./cosmos_provider.js')
const { AuthCoreWidgets } = require('./widgets.js')

exports.AuthCoreAuthClient = AuthCoreAuthClient
exports.AuthCoreKeyVaultClient = AuthCoreKeyVaultClient
exports.AuthCoreManagementClient = AuthCoreManagementClient
exports.AuthCoreWalletSubprovider = AuthCoreWalletSubprovider
exports.AuthCoreCosmosProvider = AuthCoreCosmosProvider
exports.AuthCoreWidgets = AuthCoreWidgets
