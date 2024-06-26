// js-ascon v1.0.3 @ https://github.com/brainfoolong/js-ascon
/**
 * Javascript / Typescript implementation of Ascon v1.2
 * Heavily inspired by the python implementation of https://github.com/meichlseder/pyascon
 * @link https://github.com/brainfoolong/js-ascon
 * @author BrainFooLong (Roland Eigelsreiter)
 * @version 1.0.0
 */
export default class JsAscon {
    /**
     * Encrypt any message to a hex string
     * @param {string|Uint8Array} secretKey Your "password", so to say
     * @param {any} messageToEncrypt Any type of message
     * @param {any} associatedData Any type of associated data
     * @param {string} cipherVariant See JsAscon.encrypt()
     * @return {string}
     */
    static encryptToHex(secretKey, messageToEncrypt, associatedData = null, cipherVariant = 'Ascon-128') {
        const key = JsAscon.hash(secretKey, 'Ascon-Xof', cipherVariant === 'Ascon-80pq' ? 20 : 16);
        const nonce = JsAscon.getRandomUintArray(16);
        const ciphertext = JsAscon.encrypt(key, nonce, associatedData !== null ? JSON.stringify(associatedData) : '', JSON.stringify(messageToEncrypt), cipherVariant);
        return JsAscon.byteArrayToHex(ciphertext).substring(2) + JsAscon.byteArrayToHex(nonce).substring(2);
    }
    /**
     * Decrypt any message from a hex string previously generated with encryptToHex
     * @param {string|Uint8Array} secretKey Your "password", so to say
     * @param {string} hexStr Any type of message
     * @param {any} associatedData Any type of associated data
     * @param {string} cipherVariant See JsAscon.encrypt()
     * @return {any} Null indicate unsuccessfull decrypt
     */
    static decryptFromHex(secretKey, hexStr, associatedData = null, cipherVariant = 'Ascon-128') {
        const key = JsAscon.hash(secretKey, 'Ascon-Xof', cipherVariant === 'Ascon-80pq' ? 20 : 16);
        const hexData = JsAscon.hexToByteArray(hexStr);
        const plaintextMessage = JsAscon.decrypt(key, hexData.slice(-16), associatedData !== null ? JSON.stringify(associatedData) : '', hexData.slice(0, -16), cipherVariant);
        return plaintextMessage !== null ? JSON.parse(JsAscon.byteArrayToStr(plaintextMessage)) : null;
    }
    /**
     * Ascon encryption
     * @param {string|Uint8Array|number[]} key A string or byte array of a length 16 (for Ascon-128, Ascon-128a; 128-bit security) or
     *   20 (for Ascon-80pq; 128-bit security)
     * @param  {string|Uint8Array|number[]} nonce A string or byte array of a length of 16 bytes (must not repeat for the same key!)
     * @param  {string|Uint8Array|number[]} associatedData A string or byte array of any length
     * @param  {string|Uint8Array|number[]} plaintext A string or byte array of any length
     * @param {string} variant "Ascon-128", "Ascon-128a", or "Ascon-80pq" (specifies key size, rate and number of
     *   rounds)
     * @return {Uint8Array}
     */
    static encrypt(key, nonce, associatedData, plaintext, variant = 'Ascon-128') {
        key = JsAscon.anyToByteArray(key);
        const keyLength = key.length;
        nonce = JsAscon.anyToByteArray(nonce);
        const nonceLength = nonce.length;
        JsAscon.assertInArray(variant, ['Ascon-128', 'Ascon-128a', 'Ascon-80pq'], 'Encrypt variant');
        if (['Ascon-128', 'Ascon-128a'].indexOf(variant) > -1) {
            JsAscon.assert(keyLength === 16 && nonceLength === 16, 'Incorrect key (' + keyLength + ') or nonce(' + nonceLength + ') length');
        }
        else {
            JsAscon.assert(keyLength === 20 && nonceLength === 16, 'Incorrect key (' + keyLength + ') or nonce(' + nonceLength + ') length');
        }
        const data = [];
        const keySizeBits = keyLength * 8;
        const permutationRoundsA = 12;
        const permutationRoundsB = variant === 'Ascon-128a' ? 8 : 6;
        const rate = variant === 'Ascon-128a' ? 16 : 8;
        JsAscon.initialize(data, keySizeBits, rate, permutationRoundsA, permutationRoundsB, key, nonce);
        associatedData = JsAscon.anyToByteArray(associatedData);
        JsAscon.processAssociatedData(data, permutationRoundsB, rate, associatedData);
        plaintext = JsAscon.anyToByteArray(plaintext);
        const ciphertext = JsAscon.processPlaintext(data, permutationRoundsB, rate, plaintext);
        const tag = JsAscon.finalize(data, permutationRoundsA, rate, key);
        return JsAscon.concatByteArrays(ciphertext, tag);
    }
    /**
     * Ascon decryption
     * @param {string|Uint8Array|number[]} key A string or byte array of a length 16 (for Ascon-128, Ascon-128a; 128-bit security) or
     *   20 (for Ascon-80pq; 128-bit security)
     * @param  {string|Uint8Array|number[]} nonce A string or byte array of a length of 16 bytes (must not repeat for the same key!)
     * @param  {string|Uint8Array|number[]} associatedData A string or byte array of any length
     * @param  {string|Uint8Array|number[]} ciphertextAndTag A string or byte array of any length
     * @param {string} variant "Ascon-128", "Ascon-128a", or "Ascon-80pq" (specifies key size, rate and number of
     *   rounds)
     * @return {Uint8Array|null} Returns plaintext as byte array or NULL when cannot decrypt
     */
    static decrypt(key, nonce, associatedData, ciphertextAndTag, variant = 'Ascon-128') {
        key = JsAscon.anyToByteArray(key);
        const keyLength = key.length;
        nonce = JsAscon.anyToByteArray(nonce);
        const nonceLength = nonce.length;
        JsAscon.assertInArray(variant, ['Ascon-128', 'Ascon-128a', 'Ascon-80pq'], 'Encrypt variant');
        if (['Ascon-128', 'Ascon-128a'].indexOf(variant) > -1) {
            JsAscon.assert(keyLength === 16 && nonceLength === 16, 'Incorrect key (' + keyLength + ') or nonce(' + nonceLength + ') length');
        }
        else {
            JsAscon.assert(keyLength === 20 && nonceLength === 16, 'Incorrect key (' + keyLength + ') or nonce(' + nonceLength + ') length');
        }
        const data = [];
        const keySizeBits = keyLength * 8;
        const permutationRoundsA = 12;
        const permutationRoundsB = variant === 'Ascon-128a' ? 8 : 6;
        const rate = variant === 'Ascon-128a' ? 16 : 8;
        JsAscon.initialize(data, keySizeBits, rate, permutationRoundsA, permutationRoundsB, key, nonce);
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
    /**
     * Ascon hash function and extendable-output function
     * @param {string|Uint8Array} message  A string or byte array
     * @param {string} variant "Ascon-Hash", "Ascon-Hasha" (both with 256-bit output for 128-bit security), "Ascon-Xof",
     *   or "Ascon-Xofa" (both with arbitrary output length, security=min(128, bitlen/2))
     * @param {number} hashLength The requested output bytelength (must be 32 for variant "Ascon-Hash"; can be arbitrary
     *   for Ascon-Xof, but should be >= 32 for 128-bit security)
     * @return {Uint8Array} The byte array representing the hash tag
     */
    static hash(message, variant = 'Ascon-Hash', hashLength = 32) {
        JsAscon.assertInArray(variant, ['Ascon-Hash', 'Ascon-Hasha', 'Ascon-Xof', 'Ascon-Xofa'], 'Hash variant');
        if (['Ascon-Hash', 'Ascon-Hasha'].indexOf(variant) > -1) {
            JsAscon.assert(hashLength === 32, 'Incorrect hash length');
        }
        message = JsAscon.anyToByteArray(message);
        const messageLength = message.length;
        const permutationRoundsA = 12;
        const permutationRoundsB = ['Ascon-Hasha', 'Ascon-Xofa'].indexOf(variant) > -1 ? 8 : 12;
        const rate = 8;
        const data = JsAscon.byteArrayToState(JsAscon.concatByteArrays([0, rate * 8, permutationRoundsA, permutationRoundsA - permutationRoundsB], [0, 0, ['Ascon-Hash', 'Ascon-Hasha'].indexOf(variant) > -1 ? 1 : 0, 0], // tagspec,
        new Uint8Array(32)));
        JsAscon.debug('initial value', data, true);
        JsAscon.permutation(data, permutationRoundsA);
        JsAscon.debug('initialization', data, true);
        // message processing (absorbing)
        const messagePadded = JsAscon.concatByteArrays(message, [0x80], new Uint8Array(rate - (messageLength % rate) - 1));
        const messagePaddedLength = messagePadded.length;
        // first s-1 blocks
        for (let block = 0; block < messagePaddedLength - rate; block += rate) {
            data[0] ^= JsAscon.byteArrayToBigInt(messagePadded, block);
            JsAscon.permutation(data, permutationRoundsB);
        }
        // last block
        const block = messagePaddedLength - rate;
        data[0] ^= JsAscon.byteArrayToBigInt(messagePadded, block);
        JsAscon.debug('process message', data);
        // finalization (squeezing)
        let hash = [];
        JsAscon.permutation(data, permutationRoundsA);
        while (hash.length < hashLength) {
            // @ts-ignore
            hash = hash.concat(...JsAscon.bigIntToByteArray(data[0]));
            JsAscon.permutation(data, permutationRoundsB);
        }
        JsAscon.debug('finalization', data);
        return new Uint8Array(hash);
    }
    /**
     * Ascon message authentication code (MAC) and pseudorandom function (PRF)
     * @param {string|number[]|Uint8Array} key A string or byte array of a length of 16 bytes
     * @param {string|number[]|Uint8Array} message A string or byte array (<= 16 for "Ascon-PrfShort")
     * @param {string} variant "Ascon-Mac", "Ascon-Maca" (both 128-bit output, arbitrarily long input), "Ascon-Prf",
     *   "Ascon-Prfa" (both arbitrarily long input and output), or "Ascon-PrfShort" (t-bit output for t<=128, m-bit
     *   input for m<=128)
     * @param {number} tagLength The requested output bytelength l/8 (must be <=16 for variants "Ascon-Mac", "Ascon-Maca",
     *   and "Ascon-PrfShort", arbitrary for "Ascon-Prf", "Ascon-Prfa"; should be >= 16 for 128-bit security)
     * @return {Uint8Array} The byte array representing the authentication tag
     */
    static mac(key, message, variant = 'Ascon-Mac', tagLength = 16) {
        JsAscon.assertInArray(variant, ['Ascon-Mac', 'Ascon-Prf', 'Ascon-Maca', 'Ascon-Prfa', 'Ascon-PrfShort'], 'Mac variant');
        key = JsAscon.anyToByteArray(key);
        const keyLength = key.length;
        message = JsAscon.anyToByteArray(message);
        const messageLength = message.length;
        if (['Ascon-Mac', 'Ascon-Maca'].indexOf(variant) > -1) {
            JsAscon.assert(keyLength === 16 && tagLength <= 16, 'Incorrect key length');
        }
        else if (['Ascon-Prf', 'Ascon-Prfa'].indexOf(variant) > -1) {
            JsAscon.assert(keyLength === 16, 'Incorrect key length');
        }
        else if (variant === 'Ascon-PrfShort') {
            JsAscon.assert(messageLength <= 16, 'Message to long for variant ' + variant);
            JsAscon.assert(keyLength === 16 && tagLength <= 16 && messageLength <= 16, 'Incorrect key length');
        }
        const permutationRoundsA = 12;
        const permutationRoundsB = ['Ascon-Prfa', 'Ascon-Maca'].indexOf(variant) > -1 ? 8 : 12;
        const messageBlockSize = ['Ascon-Prfa', 'Ascon-Maca'].indexOf(variant) > -1 ? 40 : 32;
        const rate = 16;
        if (variant === 'Ascon-PrfShort') {
            const data = JsAscon.byteArrayToState(JsAscon.concatByteArrays([keyLength * 8, messageLength * 8, permutationRoundsA + 64, tagLength * 8, 0, 0, 0, 0], key, message, new Uint8Array(16 - messageLength)));
            JsAscon.debug('initial value', data);
            JsAscon.permutation(data, permutationRoundsA);
            JsAscon.debug('process message', data);
            data[3] ^= JsAscon.byteArrayToBigInt(key, 0);
            data[4] ^= JsAscon.byteArrayToBigInt(key, 8);
            return new Uint8Array([...JsAscon.bigIntToByteArray(data[3]), ...JsAscon.bigIntToByteArray(data[4])]);
        }
        const data = JsAscon.byteArrayToState(JsAscon.concatByteArrays([keyLength * 8, rate * 8, permutationRoundsA + 128, permutationRoundsA - permutationRoundsB], [0, 0, 0, ['Ascon-Mac', 'Ascon-Maca'].indexOf(variant) > -1 ? 128 : 0], // tagspec
        key, new Uint8Array(16)));
        JsAscon.debug('initial value', data);
        JsAscon.permutation(data, permutationRoundsA);
        JsAscon.debug('initialization', data);
        // message processing (absorbing)
        const messagePadded = JsAscon.concatByteArrays(message, [0x80], new Uint8Array(messageBlockSize - (messageLength % messageBlockSize) - 1));
        const messagePaddedLength = messagePadded.length;
        const iterations = ['Ascon-Prfa', 'Ascon-Maca'].indexOf(variant) > -1 ? 4 : 3;
        // first s-1 blocks
        for (let block = 0; block < messagePaddedLength - messageBlockSize; block += messageBlockSize) {
            for (let i = 0; i <= iterations; i++) {
                data[i] ^= JsAscon.byteArrayToBigInt(messagePadded, block + (i * 8));
            }
            JsAscon.permutation(data, permutationRoundsB);
        }
        // last block
        const block = messagePaddedLength - messageBlockSize;
        for (let i = 0; i <= iterations; i++) {
            data[i] ^= JsAscon.byteArrayToBigInt(messagePadded, block + (i * 8));
        }
        data[4] ^= 1n;
        JsAscon.debug('process message', data);
        // finalization (squeezing)
        let tag = [];
        JsAscon.permutation(data, permutationRoundsA);
        while (tag.length < tagLength) {
            // @ts-ignore
            tag = tag.concat(...JsAscon.bigIntToByteArray(data[0]), ...JsAscon.bigIntToByteArray(data[1]));
            JsAscon.permutation(data, permutationRoundsB);
        }
        JsAscon.debug('finalization', data);
        return new Uint8Array(tag);
    }
    /**
     * Ascon initialization phase - internal helper function
     * @param {BigInt[]} data Ascon state, a list of 5 64-bit integers
     * @param {number} keySize Key size in bits
     * @param {number} rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param {number} permutationRoundsA Number of initialization/finalization rounds for permutation
     * @param {number} permutationRoundsB Number of intermediate rounds for permutation
     * @param {Uint8Array} key A bytes object of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq;
     *   128-bit security)
     * @param {Uint8Array} nonce A bytes object of size 16
     */
    static initialize(data, keySize, rate, permutationRoundsA, permutationRoundsB, key, nonce) {
        JsAscon.byteArrayToState(JsAscon.concatByteArrays([keySize, rate * 8, permutationRoundsA, permutationRoundsB], new Uint8Array(20 - key.length), key, nonce), data);
        JsAscon.debug('initial value', data);
        JsAscon.permutation(data, permutationRoundsA);
        const zeroKey = JsAscon.byteArrayToState(JsAscon.concatByteArrays(new Uint8Array(40 - key.length), key));
        for (let i = 0; i <= 4; i++) {
            data[i] ^= zeroKey[i];
        }
        JsAscon.debug('initialization', data);
    }
    /**
     * Ascon associated data processing phase - internal helper function
     * @param {BigInt[]} data data Ascon state, a list of 5 64-bit integers
     * @param {number} permutationRoundsB Number of intermediate rounds for permutation
     * @param {number} rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param {Uint8Array} associatedData A byte array of any length
     */
    static processAssociatedData(data, permutationRoundsB, rate, associatedData) {
        if (associatedData.length) {
            // message processing (absorbing)
            const rateDouble = rate * 2;
            const messagePadded = JsAscon.byteArrayToHex(associatedData).substring(2) + '80' + ('00').repeat(rate - (associatedData.length % rate) - 1);
            const messagePaddedLength = messagePadded.length;
            for (let block = 0; block < messagePaddedLength; block += rateDouble) {
                data[0] ^= BigInt('0x' + messagePadded.substring(block, block + 16));
                if (rate === 16) {
                    data[1] ^= BigInt('0x' + messagePadded.substring(block + 16, block + 32));
                }
                JsAscon.permutation(data, permutationRoundsB);
            }
        }
        data[4] ^= 1n;
        JsAscon.debug('process associated data', data);
    }
    /**
     * Ascon plaintext processing phase (during encryption) - internal helper function
     * @param {BigInt[]} data data Ascon state, a list of 5 64-bit integers
     * @param {number} permutationRoundsB Number of intermediate rounds for permutation
     * @param {number} rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param {Uint8Array} plaintext A byte array of any length
     * @return {Uint8Array} Returns the ciphertext as byte array
     */
    static processPlaintext(data, permutationRoundsB, rate, plaintext) {
        const lastLen = plaintext.length % rate;
        const messagePadded = JsAscon.byteArrayToHex(plaintext).substring(2) + '80' + ('00').repeat(rate - lastLen - 1);
        const messagePaddedLength = messagePadded.length;
        let ciphertext = '';
        const rateDouble = rate * 2;
        // first t-1 blocks
        for (let block = 0; block < messagePaddedLength - rateDouble; block += rateDouble) {
            data[0] ^= BigInt('0x' + messagePadded.substring(block, block + 16));
            ciphertext += JsAscon.bigIntToHex(data[0]);
            if (rate === 16) {
                data[1] ^= BigInt('0x' + messagePadded.substring(block + 16, block + 32));
                ciphertext += JsAscon.bigIntToHex(data[1]);
            }
            JsAscon.permutation(data, permutationRoundsB);
        }
        // last block
        const block = messagePaddedLength - rateDouble;
        if (rate === 8) {
            data[0] ^= BigInt('0x' + messagePadded.substring(block, block + 16));
            ciphertext += JsAscon.bigIntToHex(data[0]).substring(0, lastLen * 2);
        }
        else if (rate === 16) {
            data[0] ^= BigInt('0x' + messagePadded.substring(block, block + 16));
            data[1] ^= BigInt('0x' + messagePadded.substring(block + 16, block + 32));
            ciphertext += JsAscon.bigIntToHex(data[0]).substring(0, (lastLen > 8 ? 8 : lastLen) * 2);
            ciphertext += JsAscon.bigIntToHex(data[1]).substring(0, (lastLen - 8 < 0 ? 0 : lastLen - 8) * 2);
        }
        JsAscon.debug('process plaintext', data);
        return JsAscon.hexToByteArray(ciphertext);
    }
    /**
     * Ascon plaintext processing phase (during encryption) - internal helper function
     * @param {BigInt[]} data data Ascon state, a list of 5 64-bit integers
     * @param {number} permutationRoundsB Number of intermediate rounds for permutation
     * @param {number} rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param {Uint8Array} ciphertext A byte array of any length
     * @return {Uint8Array} Returns the ciphertext as byte array
     */
    static processCiphertext(data, permutationRoundsB, rate, ciphertext) {
        const lastLen = ciphertext.length % rate;
        const messagePadded = JsAscon.byteArrayToHex(ciphertext).substring(2) + ('00').repeat(rate - lastLen);
        const messagePaddedLength = messagePadded.length;
        const rateDouble = rate * 2;
        let plaintext = '';
        // first t-1 blocks
        for (let block = 0; block < messagePaddedLength - rateDouble; block += rateDouble) {
            let ci = BigInt('0x' + messagePadded.substring(block, block + 16));
            plaintext += JsAscon.bigIntToHex(data[0] ^ ci);
            data[0] = ci;
            if (rate === 16) {
                ci = BigInt('0x' + messagePadded.substring(block + 16, block + 32));
                plaintext += JsAscon.bigIntToHex(data[1] ^ ci);
                data[1] = ci;
            }
            JsAscon.permutation(data, permutationRoundsB);
        }
        // last block
        const block = messagePaddedLength - rateDouble;
        if (rate === 8) {
            let ci = BigInt('0x' + messagePadded.substring(block, block + 16));
            plaintext += JsAscon.bigIntToHex(data[0] ^ ci).substring(0, lastLen * 2);
            const padding = 0x80n << BigInt((rate - lastLen - 1) * 8);
            const mask = BigInt('0xFFFFFFFFFFFFFFFF') >> BigInt(lastLen * 8);
            data[0] = ci ^ (data[0] & mask) ^ padding;
        }
        else if (rate === 16) {
            const lastLenWord = lastLen % 8;
            const padding = 0x80n << BigInt((8 - lastLenWord - 1) * 8);
            const mask = BigInt('0xFFFFFFFFFFFFFFFF') >> BigInt(lastLenWord * 8);
            let ciA = BigInt('0x' + messagePadded.substring(block, block + 16));
            let ciB = BigInt('0x' + messagePadded.substring(block + 16, block + 32));
            plaintext += (JsAscon.bigIntToHex(data[0] ^ ciA) + JsAscon.bigIntToHex(data[1] ^ ciB)).substring(0, lastLen * 2);
            if (lastLen < 8) {
                data[0] = ciA ^ (data[0] & mask) ^ padding;
            }
            else {
                data[0] = ciA;
                data[1] = ciB ^ (data[1] & mask) ^ padding;
            }
        }
        JsAscon.debug('process ciphertext', data);
        return JsAscon.hexToByteArray(plaintext);
    }
    /**
     * Ascon finalization phase - internal helper function
     *
     * @param {BigInt[]} data data Ascon state, a list of 5 64-bit integers
     * @param {number} permutationRoundsA Number of initialization/finalization rounds for permutation
     * @param {number} rate Block size in bytes (8 for Ascon-128, Ascon-80pq; 16 for Ascon-128a)
     * @param {Uint8Array} key A bytes array of size 16 (for Ascon-128, Ascon-128a; 128-bit security) or 20 (for Ascon-80pq;
     *   128-bit security)
     * @return {Uint8Array} The tag as a byte array
     */
    static finalize(data, permutationRoundsA, rate, key) {
        let zeroFilledKey = key;
        if (key.length > 16) {
            const newLen = key.length + 24 - key.length;
            zeroFilledKey = new Uint8Array(newLen);
            zeroFilledKey.set(key);
        }
        let index = (rate / 8) | 0;
        data[index++] ^= JsAscon.byteArrayToBigInt(key, 0);
        data[index++] ^= JsAscon.byteArrayToBigInt(key, 8);
        data[index++] ^= JsAscon.byteArrayToBigInt(zeroFilledKey, 16);
        JsAscon.permutation(data, permutationRoundsA);
        data[3] ^= JsAscon.byteArrayToBigInt(key, -16);
        data[4] ^= JsAscon.byteArrayToBigInt(key, -8);
        JsAscon.debug('finalization', data);
        return JsAscon.concatByteArrays(JsAscon.bigIntToByteArray(data[3]), JsAscon.bigIntToByteArray(data[4]));
    }
    /**
     * Ascon core permutation for the sponge construction - internal helper function
     * @param {BigInt[]} data Ascon state, a list of 5 64-bit integers
     * @param {number} rounds
     */
    static permutation(data, rounds = 1) {
        JsAscon.assert(rounds <= 12, 'Permutation rounds must be <= 12');
        JsAscon.debug('permutation input', data, true);
        for (let round = 12 - rounds; round < 12; round++) {
            // add round constants
            data[2] ^= BigInt(0xf0 - round * 0x10 + round);
            JsAscon.debug('round constant addition', data, true);
            // substitution layer
            data[0] ^= data[4];
            data[4] ^= data[3];
            data[2] ^= data[1];
            let t = new Array();
            for (let i = 0; i <= 4; i++) {
                t[i] = (data[i] ^ BigInt('0xffffffffffffffff')) & data[(i + 1) % 5];
            }
            for (let i = 0; i <= 4; i++) {
                data[i] ^= t[(i + 1) % 5];
            }
            data[1] ^= data[0];
            data[0] ^= data[4];
            data[3] ^= data[2];
            data[2] ^= BigInt('0xffffffffffffffff');
            JsAscon.debug('substitution layer', data, true);
            // linear diffusion layer
            data[0] ^= JsAscon.bitRotateRight(data[0], 19) ^ JsAscon.bitRotateRight(data[0], 28);
            data[1] ^= JsAscon.bitRotateRight(data[1], 61) ^ JsAscon.bitRotateRight(data[1], 39);
            data[2] ^= JsAscon.bitRotateRight(data[2], 1) ^ JsAscon.bitRotateRight(data[2], 6);
            data[3] ^= JsAscon.bitRotateRight(data[3], 10) ^ JsAscon.bitRotateRight(data[3], 17);
            data[4] ^= JsAscon.bitRotateRight(data[4], 7) ^ JsAscon.bitRotateRight(data[4], 41);
            JsAscon.debug('linear diffusion layer', data, true);
        }
    }
    /**
     * Concat any amount of byte array to single byte array
     * @param {ArrayLike[]} arrays
     * @return {Uint8Array}
     */
    static concatByteArrays(...arrays) {
        let len = 0;
        for (let i = 0; i < arrays.length; i++) {
            len += arrays[i].length;
        }
        const arr = new Uint8Array(len);
        let offset = 0;
        for (let i = 0; i < arrays.length; i++) {
            arr.set(arrays[i], offset);
            offset += arrays[i].length;
        }
        return arr;
    }
    /**
     * Convert a byte array to a binary string
     * @param {Uint8Array} byteArray
     * @return {string}
     */
    static byteArrayToStr(byteArray) {
        return new TextDecoder().decode(byteArray);
    }
    /**
     * Convert a any value to a byte array
     * @param {string|number[]|Uint8Array} val
     * @return {Uint8Array}
     */
    static anyToByteArray(val) {
        if (val instanceof Uint8Array) {
            return val;
        }
        if (Array.isArray(val)) {
            return new Uint8Array(val);
        }
        return new TextEncoder().encode(val);
    }
    /**
     * Convert given bigint into byte array
     * @param  {BigInt} nr
     * @return {Uint8Array}
     */
    static bigIntToByteArray(nr) {
        let bytes = 8;
        let arr = new Uint8Array(bytes);
        while (nr > 0) {
            arr[--bytes] = Number(nr & 255n);
            nr >>= 8n;
        }
        return arr;
    }
    /**
     * Convert given byte array into internal state array of 5 bigints
     * @param  {Uint8Array} byteArray
     * @param {BigInt[]|null} fillInto If set, fill this given reference as well
     * @return {BigInt[]}
     */
    static byteArrayToState(byteArray, fillInto = null) {
        const arr = [
            JsAscon.byteArrayToBigInt(byteArray, 0),
            JsAscon.byteArrayToBigInt(byteArray, 8),
            JsAscon.byteArrayToBigInt(byteArray, 16),
            JsAscon.byteArrayToBigInt(byteArray, 24),
            JsAscon.byteArrayToBigInt(byteArray, 32)
        ];
        if (fillInto !== null) {
            for (let i = 0; i < arr.length; i++) {
                fillInto[i] = arr[i];
            }
        }
        return arr;
    }
    /**
     * Convert given byte array to bigint
     * @param {Uint8Array} byteArray
     * @param {number} offset
     * @return {BigInt}
     */
    static byteArrayToBigInt(byteArray, offset) {
        if (offset < 0) {
            offset = byteArray.length + offset;
        }
        if (byteArray.length - 1 < offset) {
            return 0n;
        }
        return new DataView(byteArray.buffer).getBigUint64(offset);
    }
    /**
     * Convert given byte array to visual hex representation with leading 0x
     * @param {Uint8Array} byteArray
     * @return {string}
     */
    static byteArrayToHex(byteArray) {
        return '0x' + Array.from(byteArray).map(x => x.toString(16).padStart(2, '0')).join('');
    }
    /**
     * Convert given byte array to visual hex representation with leading 0x
     * @param {bigint} nr
     * @return {string}
     */
    static bigIntToHex(nr) {
        return nr.toString(16).padStart(16, '0');
    }
    /**
     * Convert a hex string into given byte array to visual hex representation with leading 0x
     * @param {str} str
     * @return {string}
     */
    static hexToByteArray(str) {
        if (str.startsWith('0x'))
            str = str.substring(2);
        return Uint8Array.from((str.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16)));
    }
    /**
     * Bit shift rotate right integer or given number of places
     * @param {BigInt} nr
     * @param {number} places
     */
    static bitRotateRight(nr, places) {
        const placesBig = BigInt(places);
        const shift1 = BigInt(1);
        const shiftRev = BigInt(64 - places);
        return (nr >> placesBig) | ((nr & (shift1 << placesBig) - shift1) << (shiftRev));
    }
    /**
     * Assert that this is true
     * If false, it throw and exception
     * @param {string} value
     * @param {string[]} values
     * @param {string} errorMessage
     */
    static assertInArray(value, values, errorMessage) {
        JsAscon.assert(values.indexOf(value) > -1, errorMessage + ': Value \'' + value + '\' is not in available choices of\n' + JSON.stringify(values));
    }
    /**
     * Assert that this is true
     * If false, it throw and exception
     * @param {any} expected
     * @param {any} actual
     * @param {string} errorMessage
     */
    static assertSame(expected, actual, errorMessage) {
        JsAscon.assert(expected === actual, errorMessage + ': Value is expected to be\n' + JSON.stringify(expected) + '\nbut actual value is\n' + JSON.stringify(actual));
    }
    /**
     * Assert that this is true
     * If false, it throw and exception
     * @param {boolean} result
     * @param {string} errorMessage
     */
    static assert(result, errorMessage) {
        if (!result) {
            throw new Error(errorMessage);
        }
    }
    /**
     * Generate a uint array with random bytes with given length
     * @param {number} length
     * @return {Uint8Array}
     */
    static getRandomUintArray(length) {
        if (typeof crypto === 'undefined') {
            new Error('JsAscon requires the "crypto" library to be installed');
        }
        if (typeof crypto.getRandomValues === 'function') {
            return crypto.getRandomValues(new Uint8Array(length));
        }
        // @ts-ignore
        if (typeof crypto.randomBytes === 'function') {
            // @ts-ignore
            return JsAscon.anyToByteArray(crypto.randomBytes(length));
        }
        return new Uint8Array(0);
    }
    /**
     * Debug output
     * @param {any} msg
     * @param {BigInt[]|null} stateData
     * @param {boolean} permutation Is a permutation debug
     */
    static debug(msg, stateData = null, permutation = false) {
        if (!permutation && !JsAscon.debugEnabled) {
            return;
        }
        if (permutation && !JsAscon.debugPermutationEnabled) {
            return;
        }
        if (stateData) {
            let outMsg = '[Ascon Debug] ' + msg + ': [';
            for (let i = 0; i < stateData.length; i++) {
                outMsg += '"0x' + stateData[i].toString(16).padStart(16, '0') + '", ';
            }
            console.log(outMsg.substring(0, outMsg.length - 2) + ']');
        }
        else {
            console.log('[Ascon Debug] ' + msg);
        }
    }
}
JsAscon.debugEnabled = false;
JsAscon.debugPermutationEnabled = false;

if (typeof BigInt === 'undefined') {
    throw new Error('Cannot use JsAscon library, BigInt datatype is missing');
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = JsAscon
}

if(typeof crypto === 'undefined' && typeof global !== 'undefined'){
  global.crypto = require('crypto')
}
