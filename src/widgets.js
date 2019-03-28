const crypto = require('crypto')
const formatBuffer = require('./utils/formatBuffer')

function clearChildren (id) {
  const elm = document.getElementById(id)
  while (elm.firstChild) {
    elm.removeChild(elm.firstChild)
  }
}

class AuthCoreWidget {
  constructor (options) {
    if (!options.root) {
      options.root = window.location.origin + '/widgets'
    }

    const { container, callbacks, root, display = true } = options

    this.root = root
    this.containerId = formatBuffer.toHex(crypto.randomBytes(8))

    const widget = document.createElement('iframe')
    widget.style.height = '0px'
    widget.style.width = '100%'
    widget.style.overflow = 'hidden'
    widget.style.border = '0'
    widget.scrolling = 'no'

    if (!display) {
      widget.id = this.containerId
      widget.style.width = '0px'
      widget.style.display = 'none'
      document.body.appendChild(widget)
    } else {
      // For Safari, Webkit creates scrollbar with `overflow: auto` and if the content
      // scroll size is larger than the padding box size.
      const containerElement = document.getElementById(container)
      // Provide `overflow: auto` to ensure scroll behaviour, parent in client side should
      // also be set if necessary(Mainly case for modal dialog)
      containerElement.style['overflow'] = 'auto'
      containerElement.appendChild(widget)
    }

    this.container = container

    this.widget = widget
    this.callbacks = callbacks || {}

    this.callbacks['_updateHeight'] = data => {
      this.widget.style.height = `${data.height}px`
    }
    this.callbacks['_onSuccess'] = (data) => {
    }
    // Callback to be called from widget component to notify the widget is loaded
    this.callbacks['_onLoaded'] = () => {
      // Sends the access token to the widget
      this.widget.contentWindow.postMessage({
        type: 'AuthCore_accessToken',
        data: options.accessToken
      }, options.root)
    }
    this.callbacks['_unauthenticated_widget'] = () => {
    }

    // We are writing arrow functions as we want a specific scope for `this`.
    // This handles the messages sent from the widget to the parent.
    window.addEventListener('message', e => {
      // Upon receiving a message of type 'AuthCore_*', callback functions will be called.
      // For example, if AuthCore_getCurrentUser is received, `getCurrentUser` and `_getCurrentUser` will be called.
      if (typeof e.data !== 'object') return
      const { type, data } = e.data
      if (typeof type !== 'string' || !(type.startsWith('AuthCore_'))) return
      if (typeof data !== 'object' || data.containerId !== this.containerId) return
      const cbName = type.substr(9)
      const privCbName = `_${cbName}`
      if (typeof this.callbacks[cbName] === 'function') {
        this.callbacks[cbName](data)
      }
      if (typeof this.callbacks[privCbName] === 'function') {
        this.callbacks[privCbName](data)
      }
    })
  }

  destroy () {
    const { container } = this
    clearChildren(container)
    this.widget = undefined
    this.callbacks = {}
  }

  /**
   * Update the access token to the widget component
   **/
  updateAccessToken (accessToken) {
    this.widget.contentWindow.postMessage({
      type: 'AuthCore_accessToken',
      data: accessToken
    }, this.root)
  }

  /**
   * Build widget src with extra parameters
   **/
  buildWidgetSrc (options, name) {
    let { internal = false } = options
    if (typeof internal !== 'boolean') {
      throw new Error('internal must be boolean')
    }
    this.widget.src = `${options.root}/${name}?cid=${this.containerId}&internal=${internal}`
  }
}

const AuthCoreWidgets = {
  Register: class extends AuthCoreWidget {
    constructor (options) {
      super(options)
      // Assume required verification in registration
      let { logo, verification = true, internal = false } = options
      if (logo === undefined) {
        logo = ''
      } else {
        logo = encodeURIComponent(logo)
      }
      if (typeof internal !== 'boolean') {
        throw new Error('internal must be boolean')
      }
      if (typeof verification !== 'boolean') {
        throw new Error('verification must be boolean')
      }
      this.callbacks['_successRegister'] = (data) => {
        if (verification) {
          localStorage.setItem('temporaryToken', data.accessToken)
        }
        this.widget.src = `${options.root}/verification?logo=${logo}&cid=${this.containerId}&internal=${internal}`
      }
      this.widget.src = `${options.root}/register?logo=${logo}&cid=${this.containerId}&internal=${internal}`
    }
  },
  Login: class extends AuthCoreWidget {
    constructor (options) {
      super(options)
      this.buildWidgetSrc(options, 'signin')
    }
  },
  Verification: class extends AuthCoreWidget {
    constructor (options) {
      super(options)
      this.buildWidgetSrc(options, 'verification')
    }
  },
  Contacts: class extends AuthCoreWidget {
    constructor (options) {
      super(options)
      this.buildWidgetSrc(options, 'contacts')
    }
  },
  Profile: class extends AuthCoreWidget {
    constructor (options) {
      super(options)
      this.buildWidgetSrc(options, 'profile')
    }
  },
  Security: class extends AuthCoreWidget {
    constructor (options) {
      super(options)
      this.buildWidgetSrc(options, 'security')
    }
  },
  Sessions: class extends AuthCoreWidget {
    constructor (options) {
      super(options)
      this.buildWidgetSrc(options, 'sessions')
    }
  },
  EthereumSignApproval: class extends AuthCoreWidget {
    constructor (options) {
      super(options)
      this.buildWidgetSrc(options, 'ethereum-sign-approval')
      this.callbacks['_onEthereumSignApproved'] = () => {
        options.approve()
        this.destroy()
      }
      this.callbacks['_onEthereumSignRejected'] = () => {
        options.reject()
        this.destroy()
      }
    }
  },
  RefreshToken: class extends AuthCoreWidget {
    constructor (options) {
      options.display = false
      super(options)
      let containerClass = 'refresh-token'
      this.widget.className = containerClass
      this.widget.src = `${options.root}/refresh-token?cid=${this.containerId}`
      this.callbacks['_unauthenticated_tokenUpdated'] = () => {
        // Remove all refresh token widgets
        const elms = document.getElementsByClassName(containerClass)
        while (elms.length > 0) {
          elms[0].remove()
        }
      }
      this.callbacks['_unauthenticated_tokenUpdatedFail'] = () => {
        const elms = document.getElementsByClassName(containerClass)
        while (elms.length > 0) {
          elms[0].remove()
        }
      }
    }
  }
}

exports.AuthCoreWidgets = AuthCoreWidgets
