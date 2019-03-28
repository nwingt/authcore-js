const BigNumber = require('bignumber.js')

/**
 * Converts a string to buffer.
 *
 * Example: `fromString('Hello world') === <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>`
 * @param {string} payload
 */
function fromString (payload) {
  return Buffer.from(payload)
}

/**
 * Converts an integer to buffer.
 *
 * Example: `fromInt('87521618088882671231069284') === <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>`
 * @param {string} payload
 */
function fromInt (payload) {
  const hexPayload = new BigNumber(payload).toString(16)
  const pad = hexPayload.length % 2
  return fromHex('0'.repeat(pad) + hexPayload)
}

/**
 * Converts a hexadecimal string to buffer.
 *
 * Example: `fromHex('48656c6c6f20776f726c64') === <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>`
 * @param {string} payload
 */
function fromHex (payload) {
  return Buffer.from(payload, 'hex')
}

/**
 * Converts a base64 string to buffer.
 *
 * Example: `fromBase64('SGVsbG8gd29ybGQ=') === <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>`
 * @param {string} payload
 */
function fromBase64 (payload) {
  return Buffer.from(payload, 'base64')
}

/**
 * Converts an URL-safe base64 string to buffer.
 *
 * Example: `fromBase64URLSafe('SGVsbG8gd29ybGQ') === <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>`
 * @param {string} payload
 */
function fromBase64URLSafe (payload) {
  const pad = (4 - payload.length % 4) % 4
  const base64Payload = payload.replace(/_/g, '/').replace(/-/g, '+') + '='.repeat(pad)
  return fromBase64(base64Payload)
}

/**
 * Converts an uint8 array to buffer.
 *
 * Example: `fromUint8Array([72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]) === <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>`
 * @param {Uint8Array} payload
 */
function fromUint8Array (payload) {
  return Buffer.from(payload)
}

/**
 * Converts a buffer to a string.
 *
 * Example: `toString(<Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>) === 'Hello world'`
 * @param {Buffer} buffer
 */
function toString (buffer) {
  return buffer.toString()
}

/**
 * Converts a buffer to an integer.
 *
 * Example: `toInt(<Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>) === '87521618088882671231069284'`
 * @param {Buffer} buffer
 */
function toInt (buffer) {
  return new BigNumber(toHex(buffer), 16).toString(10)
}

/**
 * Converts a buffer to a hexadecimal string.
 *
 * Example: `toHex(<Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>) === '48656c6c6f20776f726c64'`
 * @param {Buffer} buffer
 */
function toHex (buffer) {
  return buffer.toString('hex')
}

/**
 * Converts a buffer to a base64 string.
 *
 * Example: `toBase64(<Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>) === 'SGVsbG8gd29ybGQ='`
 * @param {Buffer} buffer
 */
function toBase64 (buffer) {
  return buffer.toString('base64')
}

/**
 * Converts a buffer to an URL-safe base64 string.
 *
 * Example: `toBase64URLSafe(<Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>) === 'SGVsbG8gd29ybGQ'`
 * @param {Buffer} buffer
 */
function toBase64URLSafe (buffer) {
  return toBase64(buffer).replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '')
}

/**
 * Converts a buffer to an uint8 array.
 *
 * Example: `toUint8Array(<Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>) === [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100])`
 * @param {Buffer} buffer
 */
function toUint8Array (buffer) {
  return buffer.toJSON().data
}

exports.fromString = fromString
exports.fromInt = fromInt
exports.fromHex = fromHex
exports.fromBase64 = fromBase64
exports.fromBase64URLSafe = fromBase64URLSafe
exports.fromUint8Array = fromUint8Array
exports.toString = toString
exports.toInt = toInt
exports.toHex = toHex
exports.toBase64 = toBase64
exports.toBase64URLSafe = toBase64URLSafe
exports.toUint8Array = toUint8Array
