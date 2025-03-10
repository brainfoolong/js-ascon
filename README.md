# JavaScript/TypeScript Implementation of Ascon

[![Tests](https://github.com/brainfoolong/js-ascon/actions/workflows/tests.yml/badge.svg)](https://github.com/brainfoolong/js-ascon/actions/workflows/tests.yml)

This is a JavaScript/TypeScript (JS compiled from TypeScript) implementation of Ascon v1.2, an authenticated cipher and hash function.
It allows to encrypt and decrypt any kind of message. At kind be somewhat seen as the successor to AES encryption.
Heavily inspired by the python implementation of Ascon by https://github.com/meichlseder/pyascon

> Notice: This library does contain the version 1.2 of Ascon. v1.2 was a draft version and there are already newer versions of ascon. See https://github.com/ascon/ascon-c - I don't have time to upgrade this library to the new version.

## About Ascon

Ascon is a family of [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) (AEAD)
and [hashing](https://en.wikipedia.org/wiki/Cryptographic_hash_function) algorithms designed to be lightweight and easy
to implement, even with added countermeasures against side-channel attacks.
It was designed by a team of cryptographers from Graz University of Technology, Infineon Technologies, and Radboud
University: Christoph Dobraunig, Maria Eichlseder, Florian Mendel, and Martin Schläffer.

Ascon has been selected as the standard for lightweight cryptography in
the [NIST Lightweight Cryptography competition (2019–2023)](https://csrc.nist.gov/projects/lightweight-cryptography) and
as the primary choice for lightweight authenticated encryption in the final portfolio of
the [CAESAR competition (2014–2019)](https://competitions.cr.yp.to/caesar-submissions.html).

Find more information, including the specification and more implementations here:

https://ascon.iaik.tugraz.at/

## About me

I have made library for AES PHP/JS encryption already in the past. Bit juggling is somewhat cool, in a really nerdy way.
I like the Ascon implementation and it at the time of writing, a JS implementation was missing. So i made one. Would be
cool if you leave a follow or spend some virtual coffee.

## PHP Implementation
Chances are high that you probably need a PHP implementation too. I've made one here -> https://github.com/brainfoolong/php-ascon

## Installation

    # for npm
    npm install js-ascon
    const JsAscon = require('js-ascon')
    # in browser
    <script src="ascon.js"></script>

## Usage

For more demos see in folder `demo`.

```js
// test convenient methods
let key = 'mypassword'
let message = ['this can be any data type 😎 文', 123]
let associatedData = 'Some data 😋 文 This data is not contained in the encrypt output. You must pass the same data to encrypt and decrypt in order to be able to decrypt the message.'
let encrypted = JsAscon.encryptToHex(key, message, associatedData)
let decrypted = JsAscon.decryptFromHex(key, encrypted, associatedData)
JsAscon.assertSame(JSON.stringify(message), JSON.stringify(decrypted), 'Encryption/Decryption to hex failed')

// raw usage of basic methods
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

```

See `tests/performance.html` for some tests with various message data size.

```
# no scientific tests, just executed on my local machine, results depend on your machine
# a "cycle" is one encryption and one decryption 

### 10 cycles with 32 byte message data and 128 byte associated data ###
Total Time: 0.080 seconds

### 10 cycles with 128 byte message data and 512 byte associated data ###
Total Time: 0.260 seconds

### 10 cycles with 1024 byte message data and 2048 byte associated data ###
Total Time: 1.370 seconds

### 10 cycles with 4096 byte message data and 0 byte associated data ###
Total Time: 2.869 seconds
```

## Implemented Algorithms

This is a simple reference implementation of Ascon v1.2 as submitted to the NIST LWC competition that includes

* Authenticated encryption/decryption with the following 3 variants:

    - `Ascon-128`
    - `Ascon-128a`
    - `Ascon-80pq`

* Hashing algorithms including 4 hash function variants with fixed 256-bit (`Hash`) or variable (`Xof`) output lengths:

    - `Ascon-Hash`
    - `Ascon-Hasha`
    - `Ascon-Xof`
    - `Ascon-Xofa`

* Message authentication codes including 5 MAC variants (from https://eprint.iacr.org/2021/1574, not part of the LWC
  proposal) with fixed 128-bit (`Mac`) or variable (`Prf`) output lengths, including a variant for short messages of up
  to 128 bits (`PrfShort`).

    - `Ascon-Mac`
    - `Ascon-Maca`
    - `Ascon-Prf`
    - `Ascon-Prfa`
    - `Ascon-PrfShort`