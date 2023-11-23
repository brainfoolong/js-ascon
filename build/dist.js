// create all required dist files
const fs = require('fs')

const packageJson = require('../package.json')
const srcFile = __dirname + '/../dist/ascon.js'
let contents = fs.readFileSync(srcFile).toString()
contents = '// js-ascon v' + packageJson.version + ' @ ' + packageJson.homepage + '\n' + contents
contents = contents.replace(/export default class JsAscon/, 'class JsAscon')
contents += `
if (typeof module !== 'undefined' && module.exports) {
  module.exports = JsAscon
}
if(typeof crypto === 'undefined' && typeof global !== 'undefined'){
  global.crypto = require('crypto')
}
`
fs.writeFileSync(srcFile, contents)