// depending on your environment, include JsAscon as module, script tag or require from nodejs
//const JsAscon = require('js-ascon') // when using as installed npm module
const JsAscon = require('../dist/ascon')

// test convenient methods
let key = 'mypassword'
let message = ['this can be any data type 😎 文', 123]
let associatedData = 'Some data 😋 文 This data is not contained in the encrypt output. You must pass the same data to encrypt and decrypt in order to be able to decrypt the message.'
let encrypted = JsAscon.encryptToHex(key, message, associatedData)
let decrypted = JsAscon.decryptFromHex(key, encrypted, associatedData)
JsAscon.assertSame(JSON.stringify(message), JSON.stringify(decrypted), 'Encryption/Decryption to hex failed')

console.log('convienient-usage.js successfully done')