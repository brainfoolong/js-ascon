// create all required dist files
const fs = require('fs')

const packageJson = require('../package.json')
const srcFile = __dirname + '/../dist/ascon.js'
const srcFileEs6 = __dirname + '/../dist/ascon.module.js'
let contents = fs.readFileSync(srcFile).toString().replace('export default JsAscon;', '')
contents = '// js-ascon v' + packageJson.version + ' @ ' + packageJson.homepage + '\n' + contents
contents += `
if (typeof module !== 'undefined' && module.exports) {
  module.exports = JsAscon
}

if(typeof crypto === 'undefined' && typeof global !== 'undefined'){
  global.crypto = require('crypto')
}
`
let contentsCommonJs = contents
contentsCommonJs = contentsCommonJs.replace(/\sexport {.*?};/s, '')
fs.writeFileSync(srcFile, contentsCommonJs)
let contentsEs6 = contents.replace(/^class JsAscon/m, 'export default class JsAscon')
fs.writeFileSync(srcFileEs6, contentsEs6)