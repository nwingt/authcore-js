const BigNumber = require('bignumber.js')

/**
 * Converts a string to buffer.
 *
 * @private
 * @param {string} str String to-be converted.
 * @example
 * fromString('Hello world')
 * // returns <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>
 * @returns {Buffer} The buffer that is converted from the string.
 */
function fromString (str) {
  return Buffer.from(str)
}

/**
 * Converts an integer to buffer.
 *
 * @private
 * @param {BigNumber} int Integer to-be converted.
 * @example
 * fromBigNumber('87521618088882671231069284')
 * // returns <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>
 * @returns {Buffer} The buffer that is converted from the integer.
 */
function fromBigNumber (int) {
  const hexPayload = int.toString(16)
  const pad = hexPayload.length % 2
  return fromHex('0'.repeat(pad) + hexPayload)
}

/**
 * Converts a hexadecimal string to buffer.
 *
 * @private
 * @param {string} hex Hexadecimal string to-be converted.
 * @example
 * fromHex('48656c6c6f20776f726c64')
 * // returns <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>
 * @returns {Buffer} The buffer that is converted from the hexadecimal string.
 */
function fromHex (hex) {
  return Buffer.from(hex, 'hex')
}

/**
 * Converts a base64-encoded string to buffer.
 *
 * @private
 * @param {string} str Base64-encoded string to-be converted.
 * @example
 * fromBase64('SGVsbG8gd29ybGQ=')
 * // returns <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>
 * @returns {Buffer} The buffer that is converted from the base64-encoded string.
 */
function fromBase64 (str) {
  return Buffer.from(str, 'base64')
}

/**
 * Converts an URL-safe base64-encoded string to buffer.
 *
 * @private
 * @param {string} str URL-safe base64-encoded string to-be converted.
 * @example
 * fromBase64URLSafe('SGVsbG8gd29ybGQ')
 * // returns <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>
 * @returns {Buffer} The buffer that is URL-safe base64-encoded from the string.
 */
function fromBase64URLSafe (str) {
  const pad = (4 - str.length % 4) % 4
  const base64Payload = str.replace(/_/g, '/').replace(/-/g, '+') + '='.repeat(pad)
  return fromBase64(base64Payload)
}

/**
 * Converts an uint8 array to buffer.
 *
 * @private
 * @param {Uint8Array} arr Uint8 array to-be converted.
 * @example
 * fromUint8Array([72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100])
 * // <Buffer 48 65 6c 6c 6f 20 77 6f 72 6c 64>
 * @returns {Buffer} The buffer that is converted from the uint8 array.
 */
function fromUint8Array (arr) {
  return Buffer.from(arr)
}

/**
 * Converts a buffer to a string.
 *
 * @private
 * @param {Buffer} buf Buffer to-be converted.
 * @example
 * toString(Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64]))
 * // returns 'Hello world'
 * @returns {string} The string that is converted from the buffer.
 */
function toString (buf) {
  return buf.toString()
}

/**
 * Converts a buffer to an big number.
 *
 * @private
 * @param {Buffer} buf Buffer to-be converted.
 * @example
 * toBigNumber(Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64]))
 * // returns '87521618088882671231069284'
 * @returns {BigNumber} The integer that is converted from the buffer.
 */
function toBigNumber (buf) {
  return new BigNumber(toHex(buf), 16)
}

/**
 * Converts a buffer to a hexadecimal string.
 *
 * @private
 * @param {Buffer} buf Buffer to-be converted.
 * @example
 * toHex(Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64]))
 * // returns '48656c6c6f20776f726c64'
 * @returns {string} The hexadecimal string that is converted from the buffer.
 */
function toHex (buf) {
  return buf.toString('hex')
}

/**
 * Converts a buffer to a base64-encoded string.
 *
 * @private
 * @param {Buffer} buf Buffer to-be converted.
 * @example
 * toBase64(Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64]))
 * // returns 'SGVsbG8gd29ybGQ='
 * @returns {string} The base64-encoded string that is converted from the buffer.
 */
function toBase64 (buf) {
  return buf.toString('base64')
}

/**
 * Converts a buffer to an URL-safe base64-encoded string.
 *
 * @private
 * @param {Buffer} buf Buffer to-be converted.
 * @example
 * toBase64URLSafe(Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64]))
 * // returns 'SGVsbG8gd29ybGQ'
 * @returns {string} The URL-safe base64-encoded string that is converted from the buffer.
 */
function toBase64URLSafe (buf) {
  return toBase64(buf).replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '')
}

/**
 * Converts a buffer to an uint8 array.
 *
 * @private
 * @param {Buffer} buf Buffer to-be converted.
 * @example
 * toUint8Array(Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64]))
 * // returns [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]
 * @returns {Uint8Array} The uint8 array that is converted from the buffer.
 */
function toUint8Array (buf) {
  return buf.toJSON().data
}

exports.fromString = fromString
exports.fromBigNumber = fromBigNumber
exports.fromHex = fromHex
exports.fromBase64 = fromBase64
exports.fromBase64URLSafe = fromBase64URLSafe
exports.fromUint8Array = fromUint8Array
exports.toString = toString
exports.toBigNumber = toBigNumber
exports.toHex = toHex
exports.toBase64 = toBase64
exports.toBase64URLSafe = toBase64URLSafe
exports.toUint8Array = toUint8Array
