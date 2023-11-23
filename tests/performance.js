const JsAscon = require('../dist/ascon')

JsAscon.debugEnabled = false
JsAscon.debugPermutationEnabled = false

let cycles = [
  {
    'nr': 10,
    'messageSize': 32,
    'assocSize': 128,
  },
  {
    'nr': 10,
    'messageSize': 128,
    'assocSize': 512,
  },
  {
    'nr': 10,
    'messageSize': 128 * 8,
    'assocSize': 512 * 4,
  },
  {
    'nr': 10,
    'messageSize': 512 * 8,
    'assocSize': 0,
  }
]

for (let i in cycles) {
  const cycle = cycles[i]
  let totalTime = 0
  let runs = cycle['nr']
  let message, associatedData
  for (i = 1; i <= runs; i++) {
    const key = crypto.getRandomValues(new Uint8Array(16))
    message = crypto.getRandomValues(new Uint8Array(cycle['messageSize']))
    associatedData = cycle['assocSize'] ? crypto.getRandomValues(new Uint8Array(cycle['assocSize'])) : null

    const start = performance.now()
    const encrypted = JsAscon.encryptToHex(key, message, associatedData)
    const decrypted = JsAscon.decryptFromHex(key, encrypted, associatedData)
    totalTime += performance.now() - start
    JsAscon.assertSame(JSON.stringify(message), JSON.stringify(decrypted), 'Encryption/Decryption to hex failed')
  }

  console.log('### ' + runs + ' cycles with ' + (message ? message.length : 0) + ' byte message data and ' + (associatedData ? associatedData.length : 0) + ' byte associated data ###')
  console.log('Total Time: ' + (totalTime / 1000).toFixed(3) + ' seconds')
}
