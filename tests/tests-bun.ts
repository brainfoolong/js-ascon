import JsAscon from '../src/ascon.ts'
// @ts-ignore
globalThis.JsAscon = JsAscon
globalThis.readFile = async (path) => {
    return Bun.file(path).text()
}
globalThis.writeFile = async (path, data) => {
    return Bun.file(path).write(data)
}
require(__dirname + '/tests.js')
