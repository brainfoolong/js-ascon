// depending on your environment, include JsAscon as module, script tag or require from nodejs
//const JsAscon = require('js-ascon') // when using as installed npm module
const JsAscon = require('../dist/ascon')

// key must be 16 bytes or 20 bytes, depending on variant
const key = [0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0xAA, 0x90, 0x90, 0x90, 0x90, 0xCC, 0xEF]
// nonce must be 16 bytes and should always be random bytes, you must use same nonce for encrypt and decrypt the same message
const nonce = JsAscon.getRandomUintArray(16)
// this is the text you want to encrypt
const plaintext = 'Hi, i am a secret message!'
// associated data is not being encrypted, but is taken into account in the ciphertext
// this means, you can only decrypt when you pass the exact same associated data to the decrypt function as well
// so you can make sure that associated data and plaintext is not manipulated for given encrypted message
// this is optional and can be an empty string
const associatedData = 'Some data to pass to encryption and decryption - This data is not contained in the ciphertext output.'
const ciphertextByteArray = JsAscon.encrypt(key, nonce, associatedData, plaintext)
const plaintextDecrypted = JsAscon.decrypt(key, nonce, associatedData, ciphertextByteArray)

console.log("Hash")
console.log(JsAscon.hash("Testmessage"))

console.log("Mac")
console.log(JsAscon.mac(key, "Testmessage"))

console.log('raw-usage.js successfully done')