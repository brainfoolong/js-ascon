(function () {
  // generate known answers and compare them to LWC expected results
  // https://lab.las3.de/gitlab/lwc/compare/blob/master/test_vectors

  const JsAscon = require('../dist/ascon')
  const fs = require('fs')
  JsAscon.debugEnabled = false
  JsAscon.debugPermutationEnabled = false

  function genBytes (len) {
    const arr = new Uint8Array(len)
    return arr.map((byte, i) => i % 256)
  }

  const MAX_MESSAGE_LENGTH = 32
  const MAX_ASSOCIATED_DATA_LENGTH = 32
  const variants = ['Ascon-128', 'Ascon-128a', 'Ascon-80pq']

  for (let i in variants) {
    const variant = variants[i]

    const klen = variant === 'Ascon-80pq' ? 20 : 16
    const nlen = 16
    const tlen = 16
    const filename = 'LWC_AEAD_KAT_' + (klen * 8) + '_' + (nlen * 8) + '_' + variant.substring(6).toUpperCase()

    const key = genBytes(klen)
    const nonce = genBytes(nlen)
    const msg = genBytes(MAX_MESSAGE_LENGTH)
    const ad = genBytes(MAX_ASSOCIATED_DATA_LENGTH)

    let fileData = ''
    let count = 1
    for (let mlen = 0; mlen < MAX_MESSAGE_LENGTH + 1; mlen++) {
      for (let adlen = 0; adlen < MAX_ASSOCIATED_DATA_LENGTH + 1; adlen++) {
        let fileMsg = 'Count = ' + count + '\n'
        count++
        const adSliced = ad.slice(0, adlen)
        const msgSliced = msg.slice(0, mlen)
        const encrypt = JsAscon.encrypt(key, nonce, adSliced, msgSliced, variant)
        JsAscon.assertSame(mlen + tlen, encrypt.length, 'Not match expected encrypt message length')
        const decrypt = JsAscon.decrypt(key, nonce, adSliced, encrypt, variant)
        JsAscon.assertSame(mlen, (decrypt ?? []).length, 'Not match expected decrypt message length')
        fileMsg += 'Key = ' + JsAscon.byteArrayToHex(key).substring(2).toUpperCase() + '\n'
        fileMsg += 'Nonce = ' + JsAscon.byteArrayToHex(nonce).substring(2).toUpperCase() + '\n'
        fileMsg += 'PT = ' + JsAscon.byteArrayToHex(msgSliced).substring(2).toUpperCase() + '\n'
        fileMsg += 'AD = ' + JsAscon.byteArrayToHex(adSliced).substring(2).toUpperCase() + '\n'
        fileMsg += 'CT = ' + JsAscon.byteArrayToHex(encrypt).substring(2).toUpperCase() + '\n\n'
        fileData += fileMsg
      }
    }
    fs.writeFileSync(__dirname + '/genkat_results/' + filename + '.txt', fileData)
    JsAscon.assertSame(fileData, fs.readFileSync(__dirname + '/genkat_expected/' + filename + '.txt').toString(),
      'Test results for variant ' + variant + ' not matching LWC known results')
  }

})()
console.log('test-genkat.js successfully done')