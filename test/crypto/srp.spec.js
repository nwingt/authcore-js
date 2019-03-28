/* global suite, test */
const { assert } = require('chai')

const srp = require('../../src/crypto/srp.js')

suite('crypto/srp.js', function () {
  suite('createVerifier', function () {
    const fn = srp.createVerifier
    test('should create salt and verifier successfully', async function () {
      const username = 'carol'
      const password = 'password'
      const { salt, verifier } = await fn(username, password)
      assert.exists(salt)
      assert.exists(verifier)
    })
  })
  suite('getAandM1', function () {
    const fn = srp.getAandM1
    test('should obtain A and M1', async function () {
      const username = 'carol'
      const password = 'password'
      const salt = Buffer.from('zOjCPDbEDD/77vffkdHQFDcybQvgmeYXGXLaXlwVOXc=', 'base64')
      const B = Buffer.from(
        'XEd8aIZfb6sdOhy/ulFnpEQScDI0HgqCwbE8noQf4maJY2hIDpOSQwTr49rJh1SnYs3LHMkuWW7Az15gpRgv2ek' +
        'LTYXOCHTuAEcbnmOi3XmqmJN15lC2Sw1Or5yTedgde9vwLw8cdTaFmMBApfL9laK7TOqCiW59Wgyq2ImXxpPPRC' +
        '2TygCj0y1QsKx7HcyfmNvl8iGDqj0AStrZRyNM+EyOOIfos5FAFi5Sz5Y3sDraKZA+FA46s8fR85Vqc2C8/CKqa' +
        '6uad054naGUORTWgaIDI6jrVOSoc71tNRFROGrpeXClIWEqGes9p/fK0FqbFxcq7r3WHREFLLSUVyMX01zZmy+s' +
        'hCgQwA79mDBOE48KwL+y7D1zo6S2t5CHlT+/NXZliQBX6cCwuS6RkC9FjqjCcjWiZCDbURzpv1iSEqKBg7Pk+DV' +
        '4w9laO2MrVklywy72AEz2rhTSBM5pFlJhRVkOAwneKTftTx9WD6tZsoQs1doSl1WwNF3BajDbHP2vtj+MViLVa+' +
        'qCzN2uJgi/63JvjrYo8zTXCbyT88OIVed+rqk9j+N2qiWTciJxh4cYnRiRiLHnnRd3QtWnKxujlRvPKRnOKfLKj' +
        '4SYJgMmQEgikgfwkKSrriOGYDguz10lRiW6j4lzUJRFAM6/IQE5eULhWzhvKjHbrsgStbrG5NE=',
        'base64'
      )
      const { A, M1 } = await fn(username, password, salt, B)
      assert.exists(A)
      assert.exists(M1)
    })
  })
})
