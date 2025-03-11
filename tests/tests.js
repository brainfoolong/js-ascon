const JsAscon = globalThis.JsAscon;

(async function () {
    JsAscon.debugEnabled = false;
    JsAscon.debugPermutationEnabled = false;
    function genBytes(len) {
        const arr = new Uint8Array(len);
        return arr.map((byte, i) => i % 256);
    }
    const tests = process.argv[2] ? process.argv[2].toLowerCase().split(",") : [];
    const aead_variants = !tests.length || tests.includes("aead") ? { "Ascon-AEAD128": { filename: "LWC_AEAD_KAT_128_128.txt" } } : {};
    const hash_variants = !tests.length || tests.includes("hash") ? { "Ascon-Hash256": { filename: "LWC_HASH_KAT_256.txt" }, "Ascon-XOF128": { filename: "LWC_HASHXOF_KAT_256.txt" }, "Ascon-CXOF128": { filename: "LWC_HASHCXOF_KAT_256.txt" } } : {};
    const cxof_variants = !tests.length || tests.includes("cxof") ? { "Ascon-CXOF128": { filename: "LWC_CXOF_KAT_256.txt" } } : {};
    const auth_variants = !tests.length || tests.includes("auth") ? { "Ascon-Mac": { filename: "LWC_AUTHMAC_KAT_128_128.txt", "Ascon-Prf": { filename: "LWC_AUTHPRF_KAT_128_128.txt" }, "Ascon-PrfShort": { filename: "LWC_AUTHPRFSHORT_KAT_128_128.txt" } } } : {};
    for (const variant in hash_variants) {
        const MAX_MESSAGE_LENGTH = 1024;
        const hlen = 32;
        const row = hash_variants[variant];
        const expected = (await globalThis.readFile(__dirname + "/genkat_expected/" + row.filename)).replace(/\r/g, "");
        let fileData = "";
        let count = 1;
        await globalThis.writeFile(__dirname + "/genkat_results/" + row.filename, fileData)
        for (let index = 0; index < MAX_MESSAGE_LENGTH + 1; index++) {
            const msg = genBytes(index);
            const hash = JsAscon.hash(msg, variant, hlen);
            let fileMsg = "Count = " + count + "\n";
            const fileDataStart = fileData.length;
            fileMsg += "Msg = " + JsAscon.byteArrayToHex(msg).substring(2).toUpperCase() + "\n";
            fileMsg += "MD = " + JsAscon.byteArrayToHex(hash).substring(2).toUpperCase() + "\n";
            fileData += fileMsg + "\n";
            await globalThis.writeFile(__dirname + "/genkat_results/" + row.filename, fileData)
            const expectedPart = expected.substring(fileDataStart, fileData.length);
            const actualPart = fileData.substring(fileDataStart);
            count++;
            if (expectedPart !== actualPart) {
                JsAscon.assertSame(expectedPart, actualPart, "Test results for cycle " + (count - 1) + " variant " + variant + " not matching LWC known results");
            }
        }
        JsAscon.assertSame(expected, fileData, "Test results for variant " + variant + " not matching LWC known results");
    }
    for (const variant in cxof_variants) {
        const MAX_MESSAGE_LENGTH = 32;
        const MAX_CUSTOMIZATION_LENGTH = 32;
        const hlen = 32;
        const row = cxof_variants[variant];
        const expected = (await globalThis.readFile(__dirname + "/genkat_expected/" + row.filename)).replace(/\r/g, "");
        let fileData = "";
        let count = 1;
        await globalThis.writeFile(__dirname + "/genkat_results/" + row.filename, fileData)
        for (let msgLen = 0; msgLen < MAX_MESSAGE_LENGTH + 1; msgLen++) {
            for (let customLen = 0; customLen < MAX_CUSTOMIZATION_LENGTH + 1; customLen++) {
                const msg = genBytes(msgLen);
                const custom = genBytes(customLen);
                const hash = JsAscon.hash(msg, variant, hlen, custom);
                let fileMsg = "Count = " + count + "\n";
                const fileDataStart = fileData.length;
                fileMsg += "Msg = " + JsAscon.byteArrayToHex(msg).substring(2).toUpperCase() + "\n";
                fileMsg += "Z = " + JsAscon.byteArrayToHex(custom).substring(2).toUpperCase() + "\n";
                fileMsg += "MD = " + JsAscon.byteArrayToHex(hash).substring(2).toUpperCase() + "\n";
                fileData += fileMsg + "\n";
                await globalThis.writeFile(__dirname + "/genkat_results/" + row.filename, fileData)
                const expectedPart = expected.substring(fileDataStart, fileData.length);
                const actualPart = fileData.substring(fileDataStart);
                count++;
                if (expectedPart !== actualPart) {
                    JsAscon.assertSame(expectedPart, actualPart, "Test results for cycle " + (count - 1) + " variant " + variant + " not matching LWC known results");
                }
            }
        }
        JsAscon.assertSame(expected, fileData, "Test results for variant " + variant + " not matching LWC known results");
    }
    for (const variant in auth_variants) {
        const MAX_MESSAGE_LENGTH = 1024;
        const klen = 16;
        const tlen = 16;
        const row = auth_variants[variant];
        const expected = (await globalThis.readFile(__dirname + "/genkat_expected/" + row.filename)).replace(/\r/g, "");
        let fileData = "";
        let count = 1;
        await globalThis.writeFile(__dirname + "/genkat_results/" + row.filename, fileData)
        for (let index = 0; index < MAX_MESSAGE_LENGTH + 1; index++) {
            const key = genBytes(klen);
            const msg = genBytes(index);
            const hash = JsAscon.mac(key, msg, variant, tlen);
            let fileMsg = "Count = " + count + "\n";
            const fileDataStart = fileData.length;
            fileMsg += "Key = " + JsAscon.byteArrayToHex(key).substring(2).toUpperCase() + "\n";
            fileMsg += "Msg = " + JsAscon.byteArrayToHex(msg).substring(2).toUpperCase() + "\n";
            fileMsg += "Tag = " + JsAscon.byteArrayToHex(hash).substring(2).toUpperCase() + "\n";
            fileData += fileMsg + "\n";
            await globalThis.writeFile(__dirname + "/genkat_results/" + row.filename, fileData)
            const expectedPart = expected.substring(fileDataStart, fileData.length);
            const actualPart = fileData.substring(fileDataStart);
            count++;
            if (expectedPart !== actualPart) {
                JsAscon.assertSame(expectedPart, actualPart, "Test results for cycle " + (count - 1) + " variant " + variant + " not matching LWC known results");
            }
        }
        JsAscon.assertSame(expected, fileData, "Test results for variant " + variant + " not matching LWC known results");
    }
    for (let variant in aead_variants) {
        const MAX_MESSAGE_LENGTH = 32;
        const MAX_ASSOCIATED_DATA_LENGTH = 32;
        const tlen = 16;
        const row = aead_variants[variant];
        const expected = (await globalThis.readFile(__dirname + "/genkat_expected/" + row.filename)).replace(/\r/g, "");
        let fileData = "";
        let count = 1;
        await globalThis.writeFile(__dirname + "/genkat_results/" + row.filename, fileData)
        for (let mlen = 0; mlen < MAX_MESSAGE_LENGTH + 1; mlen++) {
            for (let adlen = 0; adlen < MAX_ASSOCIATED_DATA_LENGTH + 1; adlen++) {
                let fileMsg = "Count = " + count + `
`;
                const fileDataStart = fileData.length;
                const key = genBytes(16);
                const nonce = genBytes(16);
                const msg = genBytes(mlen);
                const ad = genBytes(adlen);
                const encrypt = JsAscon.encrypt(key, nonce, ad, msg, variant);
                JsAscon.assertSame(mlen + tlen, encrypt.length, "Not match expected encrypt message length  in cycle " + count);
                const decrypt = JsAscon.decrypt(key, nonce, ad, encrypt, variant);
                JsAscon.assertSame(mlen, (decrypt ?? []).length, "Not match expected decrypt message length in cycle " + count);
                fileMsg += "Key = " + JsAscon.byteArrayToHex(key).substring(2).toUpperCase() + "\n";
                fileMsg += "Nonce = " + JsAscon.byteArrayToHex(nonce).substring(2).toUpperCase() + "\n";
                fileMsg += "PT = " + JsAscon.byteArrayToHex(msg).substring(2).toUpperCase() + "\n";
                fileMsg += "AD = " + JsAscon.byteArrayToHex(ad).substring(2).toUpperCase() + "\n";
                fileMsg += "CT = " + JsAscon.byteArrayToHex(encrypt).substring(2).toUpperCase() + "\n";
                fileData += fileMsg + "\n";
                await globalThis.writeFile(__dirname + "/genkat_results/" + row.filename, fileData)
                const expectedPart = expected.substring(fileDataStart, fileData.length);
                const actualPart = fileData.substring(fileDataStart);
                count++;
                if (expectedPart !== actualPart) {
                    JsAscon.assertSame(expectedPart, actualPart, "Test results for cycle " + (count - 1) + " variant " + variant + " not matching LWC known results");
                }
            }
        }
        JsAscon.assertSame(expected, fileData, "Test results for variant " + variant + " not matching LWC known results");
    }

    const secret = "👌SecretSauce"
    const msg = "SecretMsg🥐"
    const encrypted = JsAscon.encryptToHex(secret, msg)
    const decrypted = JsAscon.decryptFromHex(secret, encrypted)
    JsAscon.assertSame(msg, decrypted, "Encryption/Decryption failed");


    console.log("Tests successfully done");
})();