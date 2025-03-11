// js-ascon v1.3.0 @ https://github.com/brainfoolong/js-ascon
// src/ascon.ts
class JsAscon {
  static debugEnabled = false;
  static debugPermutationEnabled = false;
  static encryptToHex(secretKey, messageToEncrypt, associatedData = null, cipherVariant = "Ascon-AEAD128") {
    const key = JsAscon.hash(secretKey, "Ascon-XOF128", 16);
    const nonce = JsAscon.getRandomUintArray(16);
    const ciphertext = JsAscon.encrypt(key, nonce, associatedData !== null ? JSON.stringify(associatedData) : "", JSON.stringify(messageToEncrypt), cipherVariant);
    return JsAscon.byteArrayToHex(ciphertext).substring(2) + JsAscon.byteArrayToHex(nonce).substring(2);
  }
  static decryptFromHex(secretKey, hexStr, associatedData = null, cipherVariant = "Ascon-AEAD128") {
    const key = JsAscon.hash(secretKey, "Ascon-XOF128", 16);
    const hexData = JsAscon.hexToByteArray(hexStr);
    const plaintextMessage = JsAscon.decrypt(key, hexData.slice(-16), associatedData !== null ? JSON.stringify(associatedData) : "", hexData.slice(0, -16), cipherVariant);
    return plaintextMessage !== null ? JSON.parse(JsAscon.byteArrayToStr(plaintextMessage)) : null;
  }
  static encrypt(key, nonce, associatedData, plaintext, variant = "Ascon-AEAD128") {
    const versions = { "Ascon-AEAD128": 1 };
    if (typeof versions[variant] === "undefined") {
      throw new Error("Unsupported variant");
    }
    key = JsAscon.anyToByteArray(key);
    const keyLength = key.length;
    nonce = JsAscon.anyToByteArray(nonce);
    const nonceLength = nonce.length;
    JsAscon.assert(keyLength === 16 && nonceLength === 16, "Incorrect key (" + keyLength + ") or nonce(" + nonceLength + ") length");
    const data = [];
    const keySizeBits = keyLength * 8;
    const permutationRoundsA = 12;
    const permutationRoundsB = 8;
    const rate = 16;
    JsAscon.initialize(data, keySizeBits, rate, permutationRoundsA, permutationRoundsB, versions[variant], key, nonce);
    associatedData = JsAscon.anyToByteArray(associatedData);
    JsAscon.processAssociatedData(data, permutationRoundsB, rate, associatedData);
    plaintext = JsAscon.anyToByteArray(plaintext);
    const ciphertext = JsAscon.processPlaintext(data, permutationRoundsB, rate, plaintext);
    const tag = JsAscon.finalize(data, permutationRoundsA, rate, key);
    return JsAscon.concatByteArrays(ciphertext, tag);
  }
  static decrypt(key, nonce, associatedData, ciphertextAndTag, variant = "Ascon-AEAD128") {
    const versions = { "Ascon-AEAD128": 1 };
    if (typeof versions[variant] === "undefined") {
      throw new Error("Unsupported variant");
    }
    key = JsAscon.anyToByteArray(key);
    const keyLength = key.length;
    nonce = JsAscon.anyToByteArray(nonce);
    const nonceLength = nonce.length;
    JsAscon.assert(keyLength === 16 && nonceLength === 16, "Incorrect key (" + keyLength + ") or nonce(" + nonceLength + ") length");
    const data = [];
    const keySizeBits = keyLength * 8;
    const permutationRoundsA = 12;
    const permutationRoundsB = 8;
    const rate = 16;
    JsAscon.initialize(data, keySizeBits, rate, permutationRoundsA, permutationRoundsB, versions[variant], key, nonce);
    associatedData = JsAscon.anyToByteArray(associatedData);
    JsAscon.processAssociatedData(data, permutationRoundsB, rate, associatedData);
    ciphertextAndTag = JsAscon.anyToByteArray(ciphertextAndTag);
    const ciphertext = ciphertextAndTag.slice(0, -16);
    const ciphertextTag = ciphertextAndTag.slice(-16);
    const plaintext = JsAscon.processCiphertext(data, permutationRoundsB, rate, ciphertext);
    const tag = JsAscon.finalize(data, permutationRoundsA, rate, key);
    if (JsAscon.byteArrayToHex(tag) === JsAscon.byteArrayToHex(ciphertextTag)) {
      return plaintext;
    }
    return null;
  }
  static hash(message, variant = "Ascon-Hash256", hashLength = 32, customization = "") {
    const versions = {
      "Ascon-Hash256": 2,
      "Ascon-XOF128": 3,
      "Ascon-CXOF128": 4
    };
    if (typeof versions[variant] === "undefined") {
      throw new Error("Unsupported hash variant");
    }
    let tagLength = 0n;
    let customize = false;
    if (["Ascon-Hash256"].indexOf(variant) > -1) {
      JsAscon.assert(hashLength === 32, "Incorrect hash length");
      tagLength = 256n;
    }
    if (["Ascon-CXOF128"].indexOf(variant) > -1) {
      JsAscon.assert(customization.length <= 256, "Incorrect customization length");
      customize = true;
    }
    const permutationRoundsA = 12;
    const permutationRoundsB = 12;
    const rate = 8;
    const iv = JsAscon.concatByteArrays([versions[variant], 0, (permutationRoundsB << 4) + permutationRoundsA], JsAscon.intToByteArray(tagLength, 2), [rate, 0, 0]);
    message = JsAscon.anyToByteArray(message);
    const messageLength = message.length;
    const data = JsAscon.byteArrayToState(JsAscon.concatByteArrays(iv, new Uint8Array(32)));
    JsAscon.debug("hash initial value", data, true);
    JsAscon.permutation(data, permutationRoundsA);
    JsAscon.debug("hash initialization", data, true);
    if (customize) {
      const zPadding = JsAscon.concatByteArrays([1], new Uint8Array(rate - customization.length % rate - 1));
      const zLength = JsAscon.intToByteArray(BigInt(customization.length * 8));
      const zPadded = JsAscon.concatByteArrays(zLength, customization, zPadding);
      for (let block = 0;block < zPadded.length; block += rate) {
        data[0] ^= JsAscon.byteArrayToBigInt(zPadded, block);
        JsAscon.permutation(data, permutationRoundsB);
      }
    }
    const messagePadded = JsAscon.concatByteArrays(message, [1], new Uint8Array(rate - messageLength % rate - 1));
    const messagePaddedLength = messagePadded.length;
    for (let block = 0;block < messagePaddedLength; block += rate) {
      data[0] ^= JsAscon.byteArrayToBigInt(messagePadded, block);
      JsAscon.permutation(data, permutationRoundsB);
    }
    JsAscon.debug("process message", data);
    let hash = [];
    while (hash.length < hashLength) {
      hash = hash.concat(...JsAscon.bigIntToByteArray(data[0]));
      JsAscon.permutation(data, permutationRoundsB);
    }
    JsAscon.debug("finalization", data);
    return new Uint8Array(hash);
  }
  static mac(key, message, variant = "Ascon-Mac", tagLength = 16) {
    JsAscon.assertInArray(variant, ["Ascon-Mac", "Ascon-Prf", "Ascon-PrfShort"], "Mac variant");
    key = JsAscon.anyToByteArray(key);
    const keyLength = key.length;
    message = JsAscon.anyToByteArray(message);
    const messageLength = message.length;
    if (["Ascon-Mac"].indexOf(variant) > -1) {
      JsAscon.assert(keyLength === 16 && tagLength <= 16, "Incorrect key length");
    } else if (["Ascon-Prf"].indexOf(variant) > -1) {
      JsAscon.assert(keyLength === 16, "Incorrect key length");
    } else if (variant === "Ascon-PrfShort") {
      JsAscon.assert(messageLength <= 16, "Message to long for variant " + variant);
      JsAscon.assert(keyLength === 16 && tagLength <= 16 && messageLength <= 16, "Incorrect key length");
    }
    const permutationRoundsA = 12;
    const permutationRoundsB = 12;
    const messageBlockSize = 32;
    const rate = 16;
    if (variant === "Ascon-PrfShort") {
      const data2 = JsAscon.byteArrayToState(JsAscon.concatByteArrays([keyLength * 8, messageLength * 8, permutationRoundsA + 64, tagLength * 8, 0, 0, 0, 0], key, message, new Uint8Array(16 - messageLength)));
      JsAscon.debug("mac initial value", data2);
      JsAscon.permutation(data2, permutationRoundsA);
      JsAscon.debug("mac process message", data2);
      data2[3] ^= JsAscon.byteArrayToBigInt(key, 0);
      data2[4] ^= JsAscon.byteArrayToBigInt(key, 8);
      return new Uint8Array([...JsAscon.bigIntToByteArray(data2[3]), ...JsAscon.bigIntToByteArray(data2[4])]);
    }
    const data = JsAscon.byteArrayToState(JsAscon.concatByteArrays([keyLength * 8, rate * 8, permutationRoundsA + 128, permutationRoundsA - permutationRoundsB], JsAscon.intToByteArray(variant === "Ascon-Mac" ? 128n : 0n, 4), key, new Uint8Array(16)));
    JsAscon.debug("mac initial value", data);
    JsAscon.permutation(data, permutationRoundsA);
    JsAscon.debug("mac initialization", data);
    const messagePadded = JsAscon.concatByteArrays(message, [1], new Uint8Array(messageBlockSize - messageLength % messageBlockSize - 1));
    const messagePaddedLength = messagePadded.length;
    for (let block2 = 0;block2 < messagePaddedLength - messageBlockSize; block2 += messageBlockSize) {
      for (let i = 0;i < 4; i++) {
        data[i] ^= JsAscon.byteArrayToBigInt(messagePadded, block2 + i * 8);
      }
      JsAscon.permutation(data, permutationRoundsB);
    }
    const block = messagePaddedLength - messageBlockSize;
    for (let i = 0;i < 4; i++) {
      data[i] ^= JsAscon.byteArrayToBigInt(messagePadded, block + i * 8);
    }
    data[4] ^= 1n;
    JsAscon.debug("mac process message", data);
    let tag = [];
    JsAscon.permutation(data, permutationRoundsA);
    while (tag.length < tagLength) {
      tag = tag.concat(...JsAscon.bigIntToByteArray(data[0]), ...JsAscon.bigIntToByteArray(data[1]));
      JsAscon.permutation(data, permutationRoundsB);
    }
    JsAscon.debug("mac finalization", data);
    return new Uint8Array(tag);
  }
  static initialize(data, keySize, rate, permutationRoundsA, permutationRoundsB, version, key, nonce) {
    const tagLength = 128n;
    const iv = JsAscon.concatByteArrays([version, 0, (permutationRoundsB << 4) + permutationRoundsA], JsAscon.intToByteArray(tagLength, 2), [rate, 0, 0]);
    JsAscon.byteArrayToState(JsAscon.concatByteArrays(iv, key, nonce), data);
    JsAscon.debug("initial value", data);
    JsAscon.permutation(data, permutationRoundsA);
    const zeroKey = JsAscon.byteArrayToState(JsAscon.concatByteArrays(new Uint8Array(40 - key.length), key));
    for (let i = 0;i <= 4; i++) {
      data[i] ^= zeroKey[i];
    }
    JsAscon.debug("initialization", data);
  }
  static processAssociatedData(data, permutationRoundsB, rate, associatedData) {
    if (associatedData.length) {
      const message = JsAscon.concatByteArrays(associatedData, [1], new Uint8Array(rate - associatedData.length % rate - 1));
      const messageLength = message.length;
      for (let block = 0;block < messageLength; block += rate) {
        data[0] ^= JsAscon.byteArrayToBigInt(message, block);
        data[1] ^= JsAscon.byteArrayToBigInt(message, block + 8);
        JsAscon.permutation(data, permutationRoundsB);
      }
    }
    data[4] ^= 1n << 63n;
    JsAscon.debug("process associated data", data);
  }
  static processPlaintext(data, permutationRoundsB, rate, plaintext) {
    const lastLen = plaintext.length % rate;
    const message = JsAscon.concatByteArrays(plaintext, [1], new Uint8Array(rate - lastLen - 1));
    const messageLength = message.length;
    const ciphertextArr = [];
    for (let block2 = 0;block2 < messageLength - rate; block2 += rate) {
      data[0] ^= JsAscon.byteArrayToBigInt(message, block2);
      ciphertextArr.push(...JsAscon.bigIntToByteArray(data[0], true));
      data[1] ^= JsAscon.byteArrayToBigInt(message, block2 + 8);
      ciphertextArr.push(...JsAscon.bigIntToByteArray(data[1], true));
      JsAscon.permutation(data, permutationRoundsB);
    }
    const block = messageLength - rate;
    data[0] ^= JsAscon.byteArrayToBigInt(message, block);
    data[1] ^= JsAscon.byteArrayToBigInt(message, block + 8);
    ciphertextArr.push(...JsAscon.bigIntToByteArray(data[0], true).slice(0, Math.min(8, lastLen)));
    ciphertextArr.push(...JsAscon.bigIntToByteArray(data[1], true).slice(0, Math.max(0, lastLen - 8)));
    JsAscon.debug("process plaintext", data);
    return new Uint8Array(ciphertextArr);
  }
  static processCiphertext(data, permutationRoundsB, rate, ciphertext) {
    const lastLen = ciphertext.length % rate;
    const message = JsAscon.concatByteArrays(ciphertext, new Uint8Array(rate - lastLen));
    const messageLength = message.length;
    let ci;
    const plaintextArr = [];
    for (let block2 = 0;block2 < messageLength - rate; block2 += rate) {
      ci = JsAscon.byteArrayToBigInt(message, block2);
      plaintextArr.push(...JsAscon.bigIntToByteArray(data[0] ^ ci, true));
      data[0] = ci;
      ci = JsAscon.byteArrayToBigInt(message, block2 + 8);
      plaintextArr.push(...JsAscon.bigIntToByteArray(data[1] ^ ci, true));
      data[1] = ci;
      JsAscon.permutation(data, permutationRoundsB);
    }
    const block = messageLength - rate;
    const padding = JsAscon.concatByteArrays(new Uint8Array(lastLen), [1], new Uint8Array(rate - lastLen - 1));
    const mask = JsAscon.concatByteArrays(new Uint8Array(lastLen), new Uint8Array(rate - lastLen).fill(255));
    ci = JsAscon.byteArrayToBigInt(message, block);
    const lastPart = [];
    lastPart.push(...JsAscon.bigIntToByteArray(data[0] ^ ci, true));
    data[0] = data[0] & JsAscon.byteArrayToBigInt(mask, 0) ^ ci ^ JsAscon.byteArrayToBigInt(padding, 0);
    ci = JsAscon.byteArrayToBigInt(message, block + 8);
    lastPart.push(...JsAscon.bigIntToByteArray(data[1] ^ ci, true).slice(0, lastLen));
    data[1] = data[1] & JsAscon.byteArrayToBigInt(mask, 8) ^ ci ^ JsAscon.byteArrayToBigInt(padding, 8);
    plaintextArr.push(...lastPart.slice(0, lastLen));
    JsAscon.debug("process ciphertext", data);
    return new Uint8Array(plaintextArr);
  }
  static finalize(data, permutationRoundsA, rate, key) {
    JsAscon.assert(key.length === 16, "Incorrect key length");
    let index = rate / 8;
    data[index++] ^= JsAscon.byteArrayToBigInt(key, 0);
    data[index++] ^= JsAscon.byteArrayToBigInt(key, 8);
    JsAscon.permutation(data, permutationRoundsA);
    data[3] ^= JsAscon.byteArrayToBigInt(key, -16);
    data[4] ^= JsAscon.byteArrayToBigInt(key, -8);
    JsAscon.debug("finalization", data);
    return JsAscon.concatByteArrays(JsAscon.bigIntToByteArray(data[3], true), JsAscon.bigIntToByteArray(data[4], true));
  }
  static permutation(data, rounds = 1) {
    JsAscon.assert(rounds <= 12, "Permutation rounds must be <= 12");
    JsAscon.debug("permutation input", data, true);
    for (let round = 12 - rounds;round < 12; round++) {
      data[2] ^= BigInt(240 - round * 16 + round);
      JsAscon.debug("round constant addition", data, true);
      data[0] ^= data[4];
      data[4] ^= data[3];
      data[2] ^= data[1];
      let t = new Array;
      for (let i = 0;i <= 4; i++) {
        t[i] = (data[i] ^ BigInt("0xffffffffffffffff")) & data[(i + 1) % 5];
      }
      for (let i = 0;i <= 4; i++) {
        data[i] ^= t[(i + 1) % 5];
      }
      data[1] ^= data[0];
      data[0] ^= data[4];
      data[3] ^= data[2];
      data[2] ^= BigInt("0xffffffffffffffff");
      JsAscon.debug("substitution layer", data, true);
      data[0] ^= JsAscon.bitRotateRight(data[0], 19) ^ JsAscon.bitRotateRight(data[0], 28);
      data[1] ^= JsAscon.bitRotateRight(data[1], 61) ^ JsAscon.bitRotateRight(data[1], 39);
      data[2] ^= JsAscon.bitRotateRight(data[2], 1) ^ JsAscon.bitRotateRight(data[2], 6);
      data[3] ^= JsAscon.bitRotateRight(data[3], 10) ^ JsAscon.bitRotateRight(data[3], 17);
      data[4] ^= JsAscon.bitRotateRight(data[4], 7) ^ JsAscon.bitRotateRight(data[4], 41);
      JsAscon.debug("linear diffusion layer", data, true);
    }
  }
  static concatByteArrays(...arrays) {
    let len = 0;
    for (let i = 0;i < arrays.length; i++) {
      len += arrays[i].length;
    }
    const arr = new Uint8Array(len);
    let offset = 0;
    for (let i = 0;i < arrays.length; i++) {
      arr.set(arrays[i], offset);
      offset += arrays[i].length;
    }
    return arr;
  }
  static byteArrayToStr(byteArray) {
    return new TextDecoder().decode(byteArray);
  }
  static anyToByteArray(val) {
    if (val instanceof Uint8Array) {
      return val;
    }
    if (Array.isArray(val)) {
      return new Uint8Array(val);
    }
    return new TextEncoder().encode(val);
  }
  static intToByteArray(nr, bytesCount = 8) {
    let arr = new Uint8Array(bytesCount);
    let c = 0;
    while (nr > 0) {
      arr[c++] = Number(nr & 255n);
      nr >>= 8n;
    }
    return arr;
  }
  static bigIntToByteArray(nr, reverse = true) {
    let bytes = 8;
    let arr = new Uint8Array(bytes);
    while (nr > 0) {
      arr[--bytes] = Number(nr & 255n);
      nr >>= 8n;
    }
    if (reverse) {
      arr.reverse();
    }
    return arr;
  }
  static byteArrayToState(byteArray, fillInto = null) {
    const arr = [
      JsAscon.byteArrayToBigInt(byteArray, 0),
      JsAscon.byteArrayToBigInt(byteArray, 8),
      JsAscon.byteArrayToBigInt(byteArray, 16),
      JsAscon.byteArrayToBigInt(byteArray, 24),
      JsAscon.byteArrayToBigInt(byteArray, 32)
    ];
    if (fillInto !== null) {
      for (let i = 0;i < arr.length; i++) {
        fillInto[i] = arr[i];
      }
    }
    return arr;
  }
  static byteArrayToBigInt(byteArray, offset) {
    if (offset < 0) {
      offset = byteArray.length + offset;
    }
    if (byteArray.length - 1 < offset) {
      return 0n;
    }
    return new DataView(byteArray.buffer).getBigUint64(offset, true);
  }
  static byteArrayToHex(byteArray, reverse = false) {
    if (reverse) {
      return "0x" + Array.from(byteArray).reverse().map((x) => x.toString(16).padStart(2, "0")).join("");
    }
    return "0x" + Array.from(byteArray).map((x) => x.toString(16).padStart(2, "0")).join("");
  }
  static bigIntToHex(nr) {
    return nr.toString(16).padStart(16, "0");
  }
  static hexToByteArray(str) {
    if (str.startsWith("0x")) {
      str = str.substring(2);
    }
    return Uint8Array.from((str.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16)));
  }
  static bitRotateRight(nr, places) {
    const placesBig = BigInt(places);
    const shift1 = BigInt(1);
    const shiftRev = BigInt(64 - places);
    return nr >> placesBig | (nr & (shift1 << placesBig) - shift1) << shiftRev;
  }
  static assertInArray(value, values, errorMessage) {
    JsAscon.assert(values.indexOf(value) > -1, errorMessage + ": Value '" + value + `' is not in available choices of
` + JSON.stringify(values));
  }
  static assertSame(expected, actual, errorMessage) {
    JsAscon.assert(expected === actual, errorMessage + `: Value is expected to be
` + JSON.stringify(expected) + `
but actual value is
` + JSON.stringify(actual));
  }
  static assert(result, errorMessage) {
    if (!result) {
      throw new Error(errorMessage);
    }
  }
  static getRandomUintArray(length) {
    if (typeof crypto === "undefined") {
      new Error('JsAscon requires the "crypto" library to be installed');
    }
    if (typeof crypto.getRandomValues === "function") {
      return crypto.getRandomValues(new Uint8Array(length));
    }
    if (typeof crypto.randomBytes === "function") {
      return JsAscon.anyToByteArray(crypto.randomBytes(length));
    }
    return new Uint8Array(0);
  }
  static debug(msg, stateData = null, permutation = false) {
    if (!permutation && !JsAscon.debugEnabled) {
      return;
    }
    if (permutation && !JsAscon.debugPermutationEnabled) {
      return;
    }
    if (stateData) {
      let outMsg = msg + `:
 `;
      for (let i = 0;i < stateData.length; i++) {
        outMsg += stateData[i].toString(16).padStart(16, "0") + " ";
      }
      console.log(outMsg);
    } else {
      console.log("[Ascon Debug] " + msg);
    }
  }
}
if (typeof BigInt === "undefined") {
  throw new Error("Cannot use JsAscon library, BigInt datatype is missing");
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = JsAscon
}

if(typeof crypto === 'undefined' && typeof global !== 'undefined'){
  global.crypto = require('crypto')
}
