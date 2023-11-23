if (typeof window === 'undefined') {
  global.JsAscon = require('../dist/ascon')
}

(function () {
  JsAscon.debugEnabled = false
  JsAscon.debugPermutationEnabled = false

  let word, expected, actual

  word = 'ascon'
  expected = '0x02c895cb92d79f195ed9e3e2af89ae307059104aaa819b9a987a76cf7cf51e6e'
  actual = JsAscon.byteArrayToHex(JsAscon.hash(word))
  JsAscon.assertSame(expected, actual, 'Hash of word "' + word + '" in variant "Ascon-Hash"')

  word = 'asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+asconASDFNASKIQAL-_;:;#+'
  expected = '0x9223f5c59a29c05a60121936c90968ecb3103c3c69a876f4d5de87cd4d3fec84'
  actual = JsAscon.byteArrayToHex(JsAscon.hash(word))
  JsAscon.assertSame(expected, actual, 'Hash of word "' + word + '" in variant "Ascon-Hash"')

  expected = '0x54a4c99e9a43141b4ade74044c74e6fa9bc7ddcb2334c0fc2308c8c834c7feec'
  actual = JsAscon.byteArrayToHex(JsAscon.hash(word, 'Ascon-Xof'))
  JsAscon.assertSame(expected, actual, 'Hash of word "' + word + '" in variant "Ascon-Xof"')

  expected = '0x1349fdcb638579236bfc8f56ac260b6359706276d7bed25b9dd751645a523b2f'
  actual = JsAscon.byteArrayToHex(JsAscon.hash(word, 'Ascon-Xofa'))
  JsAscon.assertSame(expected, actual, 'Hash of word "' + word + '" in variant "Ascon-Xofa"')

  expected = '0xb03447d661a92286a403507c0bb647c6c10dad98a4366b60a0631cd5cb7ed930'
  actual = JsAscon.byteArrayToHex(JsAscon.hash(word, 'Ascon-Hasha'))
  JsAscon.assertSame(expected, actual, 'Hash of word "' + word + '" in variant "Ascon-Hasha"')

  console.log('test-hash.js successfully done')
})()