/**
 * Implementation of Ascon, an authenticated cipher and hash function
 * NIST SP 800-232
 * https://ascon.iaik.tugraz.at/
 * Heavily inspired by the python implementation of https://github.com/meichlseder/pyascon
 * @link https://github.com/brainfoolong/js-ascon
 * @author BrainFooLong (Roland Eigelsreiter)
 * @version 1.0.0
 */
export default class JsAscon {
  public static debugEnabled: boolean = false
  public static debugPermutationEnabled: boolean = false

  /**
   * Encrypt any message to a hex string
   * @param {string|Uint8Array} secretKey Your "password", so to say
   * @param {any} messageToEncrypt Any type of message
   * @param {any} associatedData Any type of associated data
   * @param {string} cipherVariant See JsAscon.encrypt()
   * @return {string}
   */
  public static encryptToHex (
    secretKey: string | Uint8Array,
    messageToEncrypt: any,
    associatedData: any = null,
    cipherVariant: string = 'Ascon-AEAD128'
  ): string {
    const key = JsAscon.hash(secretKey, 'Ascon-XOF128', 16)
    const nonce = JsAscon.getRandomUintArray(16)
    const ciphertext = JsAscon.encrypt(
      key,
      nonce,
      associatedData !== null ? JSON.stringify(associatedData) : '',
      JSON.stringify(messageToEncrypt),
      cipherVariant
    )
    return JsAscon.byteArrayToHex(ciphertext).substring(2) + JsAscon.byteArrayToHex(nonce).substring(2)
  }

  /**
   * Decrypt any message from a hex string previously generated with encryptToHex
   * @param {string|Uint8Array} secretKey Your "password", so to say
   * @param {string} hexStr Any type of message
   * @param {any} associatedData Any type of associated data
   * @param {string} cipherVariant See JsAscon.encrypt()
   * @return {any} Null indicate unsuccessfull decrypt
   */
  public static decryptFromHex (
    secretKey: string | Uint8Array,
    hexStr: string,
    associatedData: any = null,
    cipherVariant: string = 'Ascon-AEAD128'
  ): any {
    const key = JsAscon.hash(secretKey, 'Ascon-XOF128', 16)
    const hexData = JsAscon.hexToByteArray(hexStr)
    const plaintextMessage = JsAscon.decrypt(
      key,
      hexData.slice(-16),
      associatedData !== null ? JSON.stringify(associatedData) : '',
      hexData.slice(0, -16),
      cipherVariant
    )
    return plaintextMessage !== null ? JSON.parse(JsAscon.byteArrayToStr(plaintextMessage)) : null
  }

  /**
   * Ascon encryption
   * @param {string|Uint8Array|number[]} key A string or byte array of a length 16
   * @param  {string|Uint8Array|number[]} nonce A string or byte array of a length of 16 bytes (must not repeat for the same key!)
   * @param  {string|Uint8Array|number[]} associatedData A string or byte array of any length
   * @param  {string|Uint8Array|number[]} plaintext A string or byte array of any length
   * @param {string} variant "Ascon-AEAD128"
   * @return {Uint8Array}
   */
  public static encrypt (
    key: string | Uint8Array,
    nonce: string | Uint8Array,
    associatedData: string | Uint8Array,
    plaintext: string | Uint8Array,
    variant: string = 'Ascon-AEAD128'
  ): Uint8Array {
    const versions = { 'Ascon-AEAD128': 1 }
    if (typeof versions[variant] === 'undefined') {
      throw new Error('Unsupported variant')
    }
    key = JsAscon.anyToByteArray(key)
    const keyLength = key.length
    nonce = JsAscon.anyToByteArray(nonce)
    const nonceLength = nonce.length
    JsAscon.assert(keyLength === 16 && nonceLength === 16, 'Incorrect key (' + keyLength + ') or nonce(' + nonceLength + ') length')
    const data = []
    const permutationRoundsA = 12
    const permutationRoundsB = 8
    const rate = 16
    JsAscon.initialize(data, rate, permutationRoundsA, permutationRoundsB, versions[variant], key, nonce)
    associatedData = JsAscon.anyToByteArray(associatedData)
    JsAscon.processAssociatedData(data, permutationRoundsB, rate, associatedData)
    plaintext = JsAscon.anyToByteArray(plaintext)
    const ciphertext = JsAscon.processPlaintext(data, permutationRoundsB, rate, plaintext)
    const tag = JsAscon.finalize(data, permutationRoundsA, rate, key)
    return JsAscon.concatByteArrays(ciphertext, tag)
  }

  /**
   * Ascon decryption
   * @param {string|Uint8Array|number[]} key A string or byte array of a length 16
   * @param  {string|Uint8Array|number[]} nonce A string or byte array of a length of 16 bytes (must not repeat for the same key!)
   * @param  {string|Uint8Array|number[]} associatedData A string or byte array of any length
   * @param  {string|Uint8Array|number[]} ciphertextAndTag A string or byte array of any length
   * @param {string} variant "Ascon-AEAD128"
   * @return {Uint8Array|null} Returns plaintext as byte array or NULL when cannot decrypt
   */
  public static decrypt (
    key: string | Uint8Array,
    nonce: string | Uint8Array,
    associatedData: string | Uint8Array,
    ciphertextAndTag: string | Uint8Array,
    variant: string = 'Ascon-AEAD128'
  ): Uint8Array | null {
    const versions = { 'Ascon-AEAD128': 1 }
    if (typeof versions[variant] === 'undefined') {
      throw new Error('Unsupported variant')
    }
    key = JsAscon.anyToByteArray(key)
    const keyLength = key.length
    nonce = JsAscon.anyToByteArray(nonce)
    const nonceLength = nonce.length
    JsAscon.assert(keyLength === 16 && nonceLength === 16, 'Incorrect key (' + keyLength + ') or nonce(' + nonceLength + ') length')
    const data = []
    const permutationRoundsA = 12
    const permutationRoundsB = 8
    const rate = 16
    JsAscon.initialize(data, rate, permutationRoundsA, permutationRoundsB, versions[variant], key, nonce)
    associatedData = JsAscon.anyToByteArray(associatedData)
    JsAscon.processAssociatedData(data, permutationRoundsB, rate, associatedData)
    ciphertextAndTag = JsAscon.anyToByteArray(ciphertextAndTag)
    const ciphertext = ciphertextAndTag.slice(0, -16)
    const ciphertextTag = ciphertextAndTag.slice(-16)
    const plaintext = JsAscon.processCiphertext(data, permutationRoundsB, rate, ciphertext)
    const tag = JsAscon.finalize(data, permutationRoundsA, rate, key)
    if (JsAscon.byteArrayToHex(tag) === JsAscon.byteArrayToHex(ciphertextTag)) {
      return plaintext
    }
    return null
  }

  /**
   * Ascon hash function and extendable-output function
   * @param {string|Uint8Array} message  A string or byte array
   * @param {string} variant "Ascon-Hash256" (with 256-bit output for 128-bit security), "Ascon-XOF128", or "Ascon-CXOF128" (both with arbitrary output length, security=min(128, bitlen/2))
   *     hashlength: the requested output bytelength (must be 32 for variant "Ascon-Hash256"; can be arbitrary for Ascon-XOF128, but should be >= 32 for 128-bit security)
   *     customization: a bytes object of at most 256 bytes specifying the customization string (only for Ascon-CXOF128)
   * @param {number} hashLength The requested output bytelength (must be 32 for variant "Ascon-Hash"; can be arbitrary
   *   for Ascon-Xof, but should be >= 32 for 128-bit security)
   * @param {string|Uint8Array} customization A bytes object of at most 256 bytes specifying the customization string (only for Ascon-CXOF128)
   * @return {Uint8Array} The byte array representing the hash tag
   */
  public static hash (
    message: string | number[] | Uint8Array,
    variant: string = 'Ascon-Hash256',
    hashLength: number = 32,
    customization: string | number[] | Uint8Array = '',
  ): Uint8Array {
    const versions = {
      'Ascon-Hash256': 2,
      'Ascon-XOF128': 3,
      'Ascon-CXOF128': 4
    }
    if (typeof versions[variant] === 'undefined') {
      throw new Error('Unsupported hash variant')
    }
    let tagLength = 0n
    let customize = false
    if (['Ascon-Hash256'].indexOf(variant) > -1) {
      JsAscon.assert(hashLength === 32, 'Incorrect hash length')
      tagLength = 256n
    }
    if (['Ascon-CXOF128'].indexOf(variant) > -1) {
      JsAscon.assert(customization.length <= 256, 'Incorrect customization length')
      customize = true
    }
    const permutationRoundsA = 12
    const permutationRoundsB = 12
    const rate = 8
    const iv = JsAscon.concatByteArrays(
      [versions[variant], 0, (permutationRoundsB << 4) + permutationRoundsA],
      JsAscon.intToByteArray(tagLength, 2),
      [rate, 0, 0]
    )
    message = JsAscon.anyToByteArray(message)
    const messageLength = message.length
    const data = JsAscon.byteArrayToState(JsAscon.concatByteArrays(
      iv,
      new Uint8Array(32)
    ))
    JsAscon.debug('initial value', data)
    JsAscon.permutation(data, permutationRoundsA)
    JsAscon.debug('initialization', data)

    // Customization
    if (customize) {
      const zPadding = JsAscon.concatByteArrays(
        [0x01],
        new Uint8Array(rate - (customization.length % rate) - 1)
      )
      const zLength = JsAscon.intToByteArray(BigInt(customization.length * 8))
      const zPadded = JsAscon.concatByteArrays(zLength, customization, zPadding)

      // customization blocks 0,...,m
      for (let block = 0; block < zPadded.length; block += rate) {
        data[0] ^= JsAscon.byteArrayToBigInt(zPadded, block)
        JsAscon.permutation(data, permutationRoundsB)

      }
    }
    // message processing (absorbing)
    const messagePadded = JsAscon.concatByteArrays(
      message,
      [0x01],
      new Uint8Array(rate - (messageLength % rate) - 1)
    )
    const messagePaddedLength = messagePadded.length
    // message blocks 0,...,n
    for (let block = 0; block < messagePaddedLength; block += rate) {
      data[0] ^= JsAscon.byteArrayToBigInt(messagePadded, block)
      JsAscon.permutation(data, permutationRoundsB)
    }
    JsAscon.debug('process message', data)
    // finalization (squeezing)
    let hash = []
    while (hash.length < hashLength) {
      // @ts-ignore
      hash = hash.concat(...JsAscon.intToByteArray(data[0]))
      JsAscon.permutation(data, permutationRoundsB)
    }
    JsAscon.debug('finalization', data)
    return new Uint8Array(hash)
  }

  /**
   * Ascon message authentication code (MAC) and pseudorandom function (PRF)
   * @param {string|number[]|Uint8Array} key A string or byte array of a length of 16 bytes
   * @param {string|number[]|Uint8Array} message A string or byte array (<= 16 for "Ascon-PrfShort")
   * @param {string} variant "Ascon-Mac" (128-bit output, arbitrarily long input), "Ascon-Prf" (arbitrarily long input and output), or "Ascon-PrfShort" (t-bit output for t<=128, m-bit input for m<=128)
   * @param {number} tagLength the requested output bytelength l/8 (must be <=16 for variants "Ascon-Mac" and "Ascon-PrfShort", arbitrary for "Ascon-Prf"; should be >= 16 for 128-bit security)
   * @return {Uint8Array} The byte array representing the authentication tag
   */
  public static mac (
    key: string | number[] | Uint8Array,
    message: string | number[] | Uint8Array,
    variant: string = 'Ascon-Mac',
    tagLength: number = 16
  ): Uint8Array {
    JsAscon.assertInArray(
      variant,
      ['Ascon-Mac', 'Ascon-Prf', 'Ascon-PrfShort'],
      'Mac variant'
    )
    key = JsAscon.anyToByteArray(key)
    const keyLength = key.length
    message = JsAscon.anyToByteArray(message)
    const messageLength = message.length
    if (variant === 'Ascon-Mac') {
      JsAscon.assert(keyLength === 16 && tagLength <= 16, 'Incorrect key length')
    } else if (variant === 'Ascon-Prf') {
      JsAscon.assert(keyLength === 16, 'Incorrect key length')
    } else if (variant === 'Ascon-PrfShort') {
      JsAscon.assert(messageLength <= 16, 'Message to long for variant ' + variant)
      JsAscon.assert(keyLength === 16 && tagLength <= 16 && messageLength <= 16, 'Incorrect key length')
    }
    const permutationRoundsA = 12
    const permutationRoundsB = 12
    const messageBlockSize = 32
    const rate = 16
    // TODO update IVs to be consistent with NIST format
    if (variant === 'Ascon-PrfShort') {
      const data = JsAscon.byteArrayToState(JsAscon.concatByteArrays(
        [keyLength * 8, messageLength * 8, permutationRoundsA + 64, tagLength * 8, 0, 0, 0, 0],
        key,
        message,
        new Uint8Array(16 - messageLength)
      ))
      JsAscon.debug('initial value', data)
      JsAscon.permutation(data, permutationRoundsA)
      JsAscon.debug('process message', data)
      data[3] ^= JsAscon.byteArrayToBigInt(key, 0)
      data[4] ^= JsAscon.byteArrayToBigInt(key, 8)
      return new Uint8Array([...JsAscon.intToByteArray(data[3]), ...JsAscon.intToByteArray(data[4])])
    }
    const data = JsAscon.byteArrayToState(JsAscon.concatByteArrays(
      [keyLength * 8, rate * 8, permutationRoundsA + 128, permutationRoundsA - permutationRoundsB],
      JsAscon.intToByteArray(variant === 'Ascon-Mac' ? 128n : 0n, 4), // tagspec
      key,
      new Uint8Array(16)
    ))
    JsAscon.debug('initial value', data)
    JsAscon.permutation(data, permutationRoundsA)
    JsAscon.debug('initialization', data)
    // message processing (absorbing)
    const messagePadded = JsAscon.concatByteArrays(
      message,
      [0x01],
      new Uint8Array(messageBlockSize - (messageLength % messageBlockSize) - 1)
    )
    const messagePaddedLength = messagePadded.length
    // first s-1 blocks
    for (let block = 0; block < messagePaddedLength - messageBlockSize; block += messageBlockSize) {
      for (let i = 0; i < 4; i++) {
        data[i] ^= JsAscon.byteArrayToBigInt(messagePadded, block + (i * 8))
      }
      JsAscon.permutation(data, permutationRoundsB)
    }
    // last block
    const block = messagePaddedLength - messageBlockSize
    for (let i = 0; i < 4; i++) {
      data[i] ^= JsAscon.byteArrayToBigInt(messagePadded, block + (i * 8))
    }
    data[4] ^= 1n
    JsAscon.debug('process message', data)
    // finalization (squeezing)
    let tag = []
    JsAscon.permutation(data, permutationRoundsA)
    while (tag.length < tagLength) {
      // @ts-ignore
      tag = tag.concat(...JsAscon.intToByteArray(data[0]), ...JsAscon.intToByteArray(data[1]))
      JsAscon.permutation(data, permutationRoundsB)
    }
    JsAscon.debug('finalization', data)
    return new Uint8Array(tag)
  }

  /**
   * Ascon initialization phase - internal helper function
   * @param {BigInt[]} data Ascon state, a list of 5 64-bit integers
   * @param {number} rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
   * @param {number} permutationRoundsA Number of initialization/finalization rounds for permutation
   * @param {number} permutationRoundsB Number of intermediate rounds for permutation
   * @param {number} version 1 (for Ascon-AEAD128)
   * @param {Uint8Array} key a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
   * @param {Uint8Array} nonce A bytes object of size 16
   */
  public static initialize (
    data: bigint[],
    rate: number,
    permutationRoundsA: number,
    permutationRoundsB: number,
    version: number,
    key: Uint8Array,
    nonce: Uint8Array
  ): void {
    const tagLength = 128n
    const iv = JsAscon.concatByteArrays(
      [version, 0, (permutationRoundsB << 4) + permutationRoundsA],
      JsAscon.intToByteArray(tagLength, 2),
      [rate, 0, 0]
    )
    JsAscon.byteArrayToState(JsAscon.concatByteArrays(iv, key, nonce), data)
    JsAscon.debug('initial value', data)
    JsAscon.permutation(data, permutationRoundsA)
    const zeroKey = JsAscon.byteArrayToState(JsAscon.concatByteArrays(
      new Uint8Array(40 - key.length),
      key
    ))
    for (let i = 0; i <= 4; i++) {
      data[i] ^= zeroKey[i]
    }
    JsAscon.debug('initialization', data)
  }

  /**
   * Ascon associated data processing phase - internal helper function
   * @param {BigInt[]} data data Ascon state, a list of 5 64-bit integers
   * @param {number} permutationRoundsB Number of intermediate rounds for permutation
   * @param {number} rate Block size in bytes (16 for Ascon-AEAD128)
   * @param {Uint8Array} associatedData A byte array of any length
   */
  public static processAssociatedData (
    data: bigint[],
    permutationRoundsB: number,
    rate: number,
    associatedData: Uint8Array
  ): void {
    if (associatedData.length) {
      // message processing (absorbing)
      const message = JsAscon.concatByteArrays(associatedData, [0x01], new Uint8Array(rate - (associatedData.length % rate) - 1))
      const messageLength = message.length
      for (let block = 0; block < messageLength; block += rate) {
        data[0] ^= JsAscon.byteArrayToBigInt(message, block)
        data[1] ^= JsAscon.byteArrayToBigInt(message, block + 8)
        JsAscon.permutation(data, permutationRoundsB)
      }
    }
    data[4] ^= 1n << 63n
    JsAscon.debug('process associated data', data)
  }

  /**
   * Ascon plaintext processing phase (during encryption) - internal helper function
   * @param {BigInt[]} data data Ascon state, a list of 5 64-bit integers
   * @param {number} permutationRoundsB Number of intermediate rounds for permutation
   * @param {number} rate block size in bytes (16 for Ascon-AEAD128)
   * @param {Uint8Array} plaintext A byte array of any length
   * @return {Uint8Array} Returns the ciphertext as byte array
   */
  public static processPlaintext (
    data: bigint[],
    permutationRoundsB: number,
    rate: number,
    plaintext: Uint8Array
  ): Uint8Array {
    const lastLen = plaintext.length % rate
    const message = JsAscon.concatByteArrays(plaintext, [0x01], new Uint8Array(rate - lastLen - 1))
    const messageLength = message.length
    const ciphertextArr: number[] = []
    // first t-1 blocks
    for (let block = 0; block < messageLength - rate; block += rate) {
      data[0] ^= JsAscon.byteArrayToBigInt(message, block)
      ciphertextArr.push(...JsAscon.intToByteArray(data[0]))
      data[1] ^= JsAscon.byteArrayToBigInt(message, block + 8)
      ciphertextArr.push(...JsAscon.intToByteArray(data[1]))
      JsAscon.permutation(data, permutationRoundsB)
    }
    // last block
    const block = messageLength - rate
    data[0] ^= JsAscon.byteArrayToBigInt(message, block)
    data[1] ^= JsAscon.byteArrayToBigInt(message, block + 8)
    ciphertextArr.push(...JsAscon.intToByteArray(data[0]).slice(0, Math.min(8, lastLen)))
    ciphertextArr.push(...JsAscon.intToByteArray(data[1]).slice(0, Math.max(0, lastLen - 8)))
    JsAscon.debug('process plaintext', data)
    return new Uint8Array(ciphertextArr)
  }

  /**
   * Ascon plaintext processing phase (during encryption) - internal helper function
   * @param {BigInt[]} data data Ascon state, a list of 5 64-bit integers
   * @param {number} permutationRoundsB Number of intermediate rounds for permutation
   * @param {number} rate block size in bytes (16 for Ascon-AEAD128)
   * @param {Uint8Array} ciphertext A byte array of any length
   * @return {Uint8Array} Returns the ciphertext as byte array
   */
  public static processCiphertext (
    data: bigint[],
    permutationRoundsB: number,
    rate: number,
    ciphertext: Uint8Array
  ): Uint8Array {

    const lastLen = ciphertext.length % rate
    const message = JsAscon.concatByteArrays(ciphertext, new Uint8Array(rate - lastLen))
    const messageLength = message.length
    let ci: bigint
    const plaintextArr: number[] = []
    // first t-1 blocks
    for (let block = 0; block < messageLength - rate; block += rate) {
      ci = JsAscon.byteArrayToBigInt(message, block)
      plaintextArr.push(...JsAscon.intToByteArray(data[0] ^ ci))
      data[0] = ci
      ci = JsAscon.byteArrayToBigInt(message, block + 8)
      plaintextArr.push(...JsAscon.intToByteArray(data[1] ^ ci))
      data[1] = ci
      JsAscon.permutation(data, permutationRoundsB)
    }
    // last block
    const block = messageLength - rate
    const padding = JsAscon.concatByteArrays(new Uint8Array(lastLen), [0x01], new Uint8Array(rate - lastLen - 1))
    const mask = JsAscon.concatByteArrays(new Uint8Array(lastLen), (new Uint8Array(rate - lastLen)).fill(0xFF))

    ci = JsAscon.byteArrayToBigInt(message, block)
    const lastPart: number[] = []
    lastPart.push(...JsAscon.intToByteArray(data[0] ^ ci))
    data[0] = data[0] & JsAscon.byteArrayToBigInt(mask, 0) ^ ci ^ JsAscon.byteArrayToBigInt(padding, 0)

    ci = JsAscon.byteArrayToBigInt(message, block + 8)
    lastPart.push(...JsAscon.intToByteArray(data[1] ^ ci).slice(0, lastLen))
    data[1] = data[1] & JsAscon.byteArrayToBigInt(mask, 8) ^ ci ^ JsAscon.byteArrayToBigInt(padding, 8)

    plaintextArr.push(...lastPart.slice(0, lastLen))
    JsAscon.debug('process ciphertext', data)
    return new Uint8Array(plaintextArr)
  }

  /**
   * Ascon finalization phase - internal helper function
   *
   * @param {BigInt[]} data data Ascon state, a list of 5 64-bit integers
   * @param {number} permutationRoundsA Number of initialization/finalization rounds for permutation
   * @param {number} rate block size in bytes (16 for Ascon-AEAD128)
   * @param {Uint8Array} key a bytes object of size 16 (for Ascon-AEAD128; 128-bit security)
   * @return {Uint8Array} The tag as a byte array
   */
  public static finalize (
    data: bigint[],
    permutationRoundsA: number,
    rate: number,
    key: Uint8Array
  ): Uint8Array {
    JsAscon.assert(key.length === 16, 'Incorrect key length')

    let index = (rate / 8)
    data[index++] ^= JsAscon.byteArrayToBigInt(key, 0)
    data[index++] ^= JsAscon.byteArrayToBigInt(key, 8)

    JsAscon.permutation(data, permutationRoundsA)

    data[3] ^= JsAscon.byteArrayToBigInt(key, -16)
    data[4] ^= JsAscon.byteArrayToBigInt(key, -8)
    JsAscon.debug('finalization', data)
    return JsAscon.concatByteArrays(
      JsAscon.intToByteArray(data[3]),
      JsAscon.intToByteArray(data[4])
    )
  }

  /**
   * Ascon core permutation for the sponge construction - internal helper function
   * @param {BigInt[]} data Ascon state, a list of 5 64-bit integers
   * @param {number} rounds
   */
  public static permutation (data: bigint[], rounds: number = 1): void {
    JsAscon.assert(rounds <= 12, 'Permutation rounds must be <= 12')
    JsAscon.debug('permutation input', data, true)
    for (let round = 12 - rounds; round < 12; round++) {
      // add round constants
      data[2] ^= BigInt(0xf0 - round * 0x10 + round)
      JsAscon.debug('round constant addition', data, true)
      // substitution layer
      data[0] ^= data[4]
      data[4] ^= data[3]
      data[2] ^= data[1]
      let t = new Array<bigint>()
      for (let i = 0; i <= 4; i++) {
        t[i] = (data[i] ^ BigInt('0xffffffffffffffff')) & data[(i + 1) % 5]
      }
      for (let i = 0; i <= 4; i++) {
        data[i] ^= t[(i + 1) % 5]
      }
      data[1] ^= data[0]
      data[0] ^= data[4]
      data[3] ^= data[2]
      data[2] ^= BigInt('0xffffffffffffffff')
      JsAscon.debug('substitution layer', data, true)
      // linear diffusion layer
      data[0] ^= JsAscon.bitRotateRight(data[0], 19) ^ JsAscon.bitRotateRight(data[0], 28)
      data[1] ^= JsAscon.bitRotateRight(data[1], 61) ^ JsAscon.bitRotateRight(data[1], 39)
      data[2] ^= JsAscon.bitRotateRight(data[2], 1) ^ JsAscon.bitRotateRight(data[2], 6)
      data[3] ^= JsAscon.bitRotateRight(data[3], 10) ^ JsAscon.bitRotateRight(data[3], 17)
      data[4] ^= JsAscon.bitRotateRight(data[4], 7) ^ JsAscon.bitRotateRight(data[4], 41)
      JsAscon.debug('linear diffusion layer', data, true)
    }
  }

  /**
   * Concat any amount of byte array to single byte array
   * @param {ArrayLike[]} arrays
   * @return {Uint8Array}
   */
  public static concatByteArrays (...arrays: ArrayLike<any>[]): Uint8Array {
    let len = 0
    for (let i = 0; i < arrays.length; i++) {
      len += arrays[i].length
    }
    const arr = new Uint8Array(len)
    let offset = 0
    for (let i = 0; i < arrays.length; i++) {
      arr.set(arrays[i], offset)
      offset += arrays[i].length
    }
    return arr
  }

  /**
   * Convert a byte array to a binary string
   * @param {Uint8Array} byteArray
   * @return {string}
   */
  public static byteArrayToStr (byteArray: Uint8Array): string {
    return new TextDecoder().decode(byteArray)
  }

  /**
   * Convert a any value to a byte array
   * @param {string|number[]|Uint8Array} val
   * @return {Uint8Array}
   */
  public static anyToByteArray (val: any): Uint8Array {
    if (val instanceof Uint8Array) {
      return val
    }
    if (Array.isArray(val)) {
      return new Uint8Array(val)
    }
    return new TextEncoder().encode(val)
  }

  /**
   * Convert given bigint into byte array
   * @param  {BigInt|number} nr
   * @param  {number} bytesCount
   * @return {Uint8Array}
   */
  public static intToByteArray (nr: bigint, bytesCount: number = 8): Uint8Array {
    let arr = new Uint8Array(bytesCount)
    let i = 0
    while (bytesCount > 0) {
      arr[i++] = Number(nr & 255n)
      nr >>= 8n
      bytesCount--
    }
    return arr
  }

  /**
   * Convert given byte array into internal state array of 5 bigints
   * @param  {Uint8Array} byteArray
   * @param {BigInt[]|null} arr If set, use this reference array
   * @return {BigInt[]}
   */
  public static byteArrayToState (byteArray: Uint8Array, arr: bigint[] | null = null): bigint[] {
    arr = arr || []
    arr[0] = JsAscon.byteArrayToBigInt(byteArray, 0)
    arr[1] = JsAscon.byteArrayToBigInt(byteArray, 8)
    arr[2] = JsAscon.byteArrayToBigInt(byteArray, 16)
    arr[3] = JsAscon.byteArrayToBigInt(byteArray, 24)
    arr[4] = JsAscon.byteArrayToBigInt(byteArray, 32)
    return arr
  }

  /**
   * Convert given byte array to bigint
   * @param {Uint8Array} byteArray
   * @param {number} offset
   * @return {BigInt}
   */
  public static byteArrayToBigInt (byteArray: Uint8Array, offset: number): bigint {
    if (offset < 0) {
      offset = byteArray.length + offset
    }
    if (byteArray.length - 1 < offset) {
      return 0n
    }
    return new DataView(byteArray.buffer).getBigUint64(offset, true)
  }

  /**
   * Convert given byte array to visual hex representation with leading 0x
   * @param {Uint8Array} byteArray
   * @return {string}
   */
  public static byteArrayToHex (byteArray: Uint8Array): string {

    return '0x' + Array.from(byteArray).map(x => x.toString(16).padStart(2, '0')).join('')
  }

  /**
   * Convert a hex string into given byte array to visual hex representation with leading 0x
   * @param {str} str
   * @return {string}
   */
  public static hexToByteArray (str: string): Uint8Array {
    if (str.startsWith('0x')) {
      str = str.substring(2)
    }
    return Uint8Array.from((str.match(/.{1,2}/g) || []).map((byte: string) => parseInt(byte, 16)))
  }

  /**
   * Bit shift rotate right integer or given number of places
   * @param {BigInt} nr
   * @param {number} places
   */
  public static bitRotateRight (nr: bigint, places: number): bigint {
    const placesBig = BigInt(places)
    const shift1 = BigInt(1)
    const shiftRev = BigInt(64 - places)
    return (nr >> placesBig) | ((nr & (shift1 << placesBig) - shift1) << (shiftRev))
  }

  /**
   * Assert that this is true
   * If false, it throw and exception
   * @param {string} value
   * @param {string[]} values
   * @param {string} errorMessage
   */
  public static assertInArray (value: string, values: string[], errorMessage: string): void {
    JsAscon.assert(
      values.indexOf(value) > -1,
      errorMessage + ': Value \'' + value + '\' is not in available choices of\n' + JSON.stringify(values)
    )
  }

  /**
   * Assert that this is true
   * If false, it throw and exception
   * @param {any} expected
   * @param {any} actual
   * @param {string} errorMessage
   */
  public static assertSame (expected: any, actual: any, errorMessage: string): void {
    JsAscon.assert(
      expected === actual,
      errorMessage + ': Value is expected to be\n' + JSON.stringify(expected) + '\nbut actual value is\n' + JSON.stringify(actual)
    )

  }

  /**
   * Assert that this is true
   * If false, it throw and exception
   * @param {boolean} result
   * @param {string} errorMessage
   */
  public static assert (result: boolean, errorMessage: string): void {
    if (!result) {
      throw new Error(errorMessage)
    }
  }

  /**
   * Generate a uint array with random bytes with given length
   * @param {number} length
   * @return {Uint8Array}
   */
  public static getRandomUintArray (length: number): Uint8Array {
    if (typeof crypto === 'undefined') {
      new Error('JsAscon requires the "crypto" library to be installed')
    }
    if (typeof crypto.getRandomValues === 'function') {
      return crypto.getRandomValues(new Uint8Array(length))
    }
    // @ts-ignore
    if (typeof crypto.randomBytes === 'function') {
      // @ts-ignore
      return JsAscon.anyToByteArray(crypto.randomBytes(length))
    }
    return new Uint8Array(0)
  }

  /**
   * Debug output
   * @param {any} msg
   * @param {BigInt[]|null} stateData
   * @param {boolean} permutation Is a permutation debug
   */
  public static debug (
    msg: any,
    stateData: Array<bigint> | null = null,
    permutation: boolean = false
  ): void {
    if (!permutation && !JsAscon.debugEnabled) {
      return
    }
    if (permutation && !JsAscon.debugPermutationEnabled) {
      return
    }
    if (stateData) {
      let outMsg = msg + ':\n '
      for (let i = 0; i < stateData.length; i++) {
        outMsg += stateData[i].toString(16).padStart(16, '0') + ' '
      }
      console.log(outMsg)
    } else {
      console.log('[Ascon Debug] ' + msg)
    }
  }
}

if (typeof BigInt === 'undefined') {
  throw new Error('Cannot use JsAscon library, BigInt datatype is missing')
}