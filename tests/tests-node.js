const fs = require("fs")

globalThis.JsAscon = require(__dirname + '/../dist/ascon.js')
globalThis.readFile = async (path) => {
    return fs.readFileSync(path).toString()
}
globalThis.writeFile = async (path, data) => {
    return fs.writeFileSync(path, data)
}
require(__dirname + '/tests.js')
