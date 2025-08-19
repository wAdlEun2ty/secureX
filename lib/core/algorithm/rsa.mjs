const isNode = typeof process !== 'undefined' && process.versions?.node;
let webcrypto;
if (isNode) {
    const nodeCrypto = await import('node:crypto');
    webcrypto = nodeCrypto.webcrypto;
} else if (typeof globalThis.crypto !== 'undefined') {
    webcrypto = globalThis.crypto;
}

class RSAError extends Error {
    constructor(code) {
        super(`RSAError: ${code}`);
        this.code = code;
    }
}

class RSA {
    constructor(opts = {}) {
        this.modulusLength = opts.modulusLength || 2048;
        this.publicExponent = opts.publicExponent || new Uint8Array([0x01, 0x00, 0x01]);
        this.hybridAES = opts.hybridAES ?? true;
        this.padding = opts.padding || 'OAEP';
        this.hash = opts.hash || 'SHA-256';
        this.chunkSize = opts.chunkSize || this._calculateMaxChunkSize();
        this.pbkdf2Iterations = opts.pbkdf2Iterations || 100000;
        this._validateOptions();
    }

    _validateOptions() {
        if (![2048, 3072, 4096].includes(this.modulusLength)) {
            throw new RSAError('INVALID_MODULUS');
        }
        if (this.publicExponent.byteLength !== 3 || !this.publicExponent.every((b, i) => 
            i === 0 ? b === 0x01 : i === 1 ? b === 0x00 : b === 0x01)) {
            throw new RSAError('INVALID_EXPONENT');
        }
        if (!['OAEP', 'PKCS1'].includes(this.padding)) {
            throw new RSAError('INVALID_PADDING');
        }
        if (!['SHA-256', 'SHA-384', 'SHA-512'].includes(this.hash)) {
            throw new RSAError('INVALID_HASH');
        }
        if (this.chunkSize < 1 || this.chunkSize > 1024 * 1024 * 1024) {
            throw new RSAError('INVALID_CHUNK');
        }
    }

    _calculateMaxChunkSize() {
        const overhead = this.padding === 'OAEP' ? 42 : 11;
        return Math.floor(this.modulusLength / 8) - overhead;
    }

    async _getSubtle() {
        if (!webcrypto || !webcrypto.subtle) throw new RSAError('CRYPTO_UNAVAILABLE');
        return webcrypto.subtle;
    }

    async generateKeyPair() {
        const subtle = await this._getSubtle();
        const algorithm = {
            name: 'RSA-OAEP',
            modulusLength: this.modulusLength,
            publicExponent: this.publicExponent,
            hash: { name: this.hash }
        };
        const keyPair = await subtle.generateKey(algorithm, true, ['encrypt', 'decrypt']);
        const publicKey = new Uint8Array(await subtle.exportKey('spki', keyPair.publicKey));
        const privateKey = new Uint8Array(await subtle.exportKey('pkcs8', keyPair.privateKey));
        return { publicKey, privateKey };
    }

    async _importPublicKey(rawKey) {
        const subtle = await this._getSubtle();
        return subtle.importKey('spki', rawKey, { name: 'RSA-OAEP', hash: { name: this.hash } }, false, ['encrypt']);
    }

    async _importPrivateKey(rawKey) {
        const subtle = await this._getSubtle();
        return subtle.importKey('pkcs8', rawKey, { name: 'RSA-OAEP', hash: { name: this.hash } }, false, ['decrypt']);
    }

    async encrypt(publicKey, data) {
        if (!(publicKey instanceof Uint8Array)) throw new RSAError('INVALID_PUBLIC_KEY');
        if (!(data instanceof Uint8Array)) throw new RSAError('INVALID_DATA');
        if (this.hybridAES && data.length > this.chunkSize) {
            return this._encryptHybrid(publicKey, data);
        }
        return this._encryptRSA(publicKey, data);
    }

    async _encryptRSA(publicKey, data) {
        const subtle = await this._getSubtle();
        const key = await this._importPublicKey(publicKey);
        const maxChunk = this._calculateMaxChunkSize();
        if (data.length > maxChunk && !this.hybridAES) {
            return this._encryptChunked(key, data, maxChunk);
        }
        const encrypted = await subtle.encrypt({ name: this.padding === 'OAEP' ? 'RSA-OAEP' : 'RSA-PKCS1-v1_5' }, key, data);
        return new Uint8Array(encrypted);
    }

    async _encryptChunked(key, data, chunkSize) {
        const result = [];
        for (let offset = 0; offset < data.length; offset += chunkSize) {
            const chunk = data.slice(offset, offset + chunkSize);
            const encryptedChunk = await webcrypto.subtle.encrypt(
                { name: this.padding === 'OAEP' ? 'RSA-OAEP' : 'RSA-PKCS1-v1_5' },
                key,
                chunk
            );
            result.push(new Uint8Array(encryptedChunk));
        }
        return concatUint8(...result);
    }

    async _encryptHybrid(publicKey, data) {
        const aesKey = randomBytes(32);
        const iv = randomBytes(12);
        const subtle = await this._getSubtle();
        const importedAesKey = await subtle.importKey('raw', aesKey, 'AES-GCM', false, ['encrypt']);
        const encryptedData = await subtle.encrypt({ name: 'AES-GCM', iv }, importedAesKey, data);
        const encryptedDataArr = new Uint8Array(encryptedData);
        const tag = encryptedDataArr.slice(-16);
        const ciphertext = encryptedDataArr.slice(0, -16);
        const encryptedKey = await this._encryptRSA(publicKey, aesKey);
        return concatUint8(
            new Uint8Array([0x01]),
            iv,
            tag,
            new Uint8Array(encryptedKey),
            ciphertext
        );
    }

    async decrypt(privateKey, encryptedData) {
        if (!(privateKey instanceof Uint8Array)) throw new RSAError('INVALID_PRIVATE_KEY');
        if (!(encryptedData instanceof Uint8Array)) throw new RSAError('INVALID_ENCRYPTED');
        if (encryptedData[0] === 0x01) {
            return this._decryptHybrid(privateKey, encryptedData);
        }
        return this._decryptRSA(privateKey, encryptedData);
    }

    async _decryptRSA(privateKey, encryptedData) {
        const subtle = await this._getSubtle();
        const key = await this._importPrivateKey(privateKey);
        const chunkSize = this.modulusLength / 8;
        if (encryptedData.length > chunkSize) {
            return this._decryptChunked(key, encryptedData, chunkSize);
        }
        const decrypted = await subtle.decrypt({ name: this.padding === 'OAEP' ? 'RSA-OAEP' : 'RSA-PKCS1-v1_5' }, key, encryptedData);
        return new Uint8Array(decrypted);
    }

    async _decryptChunked(key, encryptedData, chunkSize) {
        const result = [];
        for (let offset = 0; offset < encryptedData.length; offset += chunkSize) {
            const chunk = encryptedData.slice(offset, offset + chunkSize);
            const decryptedChunk = await webcrypto.subtle.decrypt(
                { name: this.padding === 'OAEP' ? 'RSA-OAEP' : 'RSA-PKCS1-v1_5' },
                key,
                chunk
            );
            result.push(new Uint8Array(decryptedChunk));
        }
        return concatUint8(...result);
    }

    async _decryptHybrid(privateKey, encryptedData) {
        let offset = 1;
        const iv = encryptedData.slice(offset, offset + 12);
        offset += 12;
        const tag = encryptedData.slice(offset, offset + 16);
        offset += 16;
        const keyLen = this.modulusLength / 8;
        const encryptedKey = encryptedData.slice(offset, offset + keyLen);
        offset += keyLen;
        const ciphertext = encryptedData.slice(offset);
        const aesKey = await this._decryptRSA(privateKey, encryptedKey);
        const subtle = await this._getSubtle();
        const importedAesKey = await subtle.importKey('raw', aesKey, 'AES-GCM', false, ['decrypt']);
        const combined = concatUint8(ciphertext, tag);
        const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, importedAesKey, combined);
        return new Uint8Array(decrypted);
    }

    async sign(privateKey, data) {
        if (!(privateKey instanceof Uint8Array)) throw new RSAError('INVALID_PRIVATE_KEY');
        if (!(data instanceof Uint8Array)) throw new RSAError('INVALID_DATA');
        const subtle = await this._getSubtle();
        const key = await subtle.importKey('pkcs8', privateKey, { name: this.padding === 'OAEP' ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5', hash: { name: this.hash } }, false, ['sign']);
        const signature = await subtle.sign({ name: this.padding === 'OAEP' ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5', saltLength: 32 }, key, data);
        return new Uint8Array(signature);
    }

    async verify(publicKey, signature, data) {
        if (!(publicKey instanceof Uint8Array)) throw new RSAError('INVALID_PUBLIC_KEY');
        if (!(signature instanceof Uint8Array)) throw new RSAError('INVALID_SIGNATURE');
        if (!(data instanceof Uint8Array)) throw new RSAError('INVALID_DATA');
        const subtle = await this._getSubtle();
        const key = await subtle.importKey('spki', publicKey, { name: this.padding === 'OAEP' ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5', hash: { name: this.hash } }, false, ['verify']);
        return subtle.verify({ name: this.padding === 'OAEP' ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5', saltLength: 32 }, key, signature, data);
    }
}

function randomBytes(length) {
    const bytes = new Uint8Array(length);
    if (webcrypto && webcrypto.getRandomValues) {
        webcrypto.getRandomValues(bytes);
    } else {
        throw new RSAError('RANDOM_UNAVAILABLE');
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(Math.ceil(hex.length / 2));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

function concatUint8(...arrays) {
    let totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
    let result = new Uint8Array(totalLength);
    let offset = 0;
    for (let arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

function constantTimeEq(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}

function zeroBuffer(buffer) {
    buffer.fill(0);
}

async function deriveKeyFromPassword(password, salt = randomBytes(16), iterations = 100000) {
    if (!webcrypto.subtle) throw new RSAError('CRYPTO_UNAVAILABLE');
    const importedKey = await webcrypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
    const key = await webcrypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, importedKey, 256);
    return new Uint8Array(key);
}

async function selfTest() {
    const failures = [];
    const testData = new TextEncoder().encode('RSA Self-Test');
    const rsa = new RSA({ modulusLength: 2048, hybridAES: false, chunkSize: 190 });
    try {
        const { publicKey, privateKey } = await rsa.generateKeyPair();
        const encrypted = await rsa.encrypt(publicKey, testData);
        const decrypted = await rsa.decrypt(privateKey, encrypted);
        if (!constantTimeEq(testData, decrypted)) {
            failures.push('RSA_ENC_DEC_FAIL');
        }
        const signature = await rsa.sign(privateKey, testData);
        const valid = await rsa.verify(publicKey, signature, testData);
        if (!valid) {
            failures.push('SIGN_VERIFY_FAIL');
        }
        const largeData = randomBytes(1024 * 1024);
        const encryptedLarge = await rsa.encrypt(publicKey, largeData);
        const decryptedLarge = await rsa.decrypt(privateKey, encryptedLarge);
        if (!constantTimeEq(largeData, decryptedLarge)) {
            failures.push('CHUNKED_FAIL');
        }
        const rsaHybrid = new RSA({ modulusLength: 2048, hybridAES: true });
        const encryptedHybrid = await rsaHybrid.encrypt(publicKey, largeData);
        const decryptedHybrid = await rsaHybrid.decrypt(privateKey, encryptedHybrid);
        if (!constantTimeEq(largeData, decryptedHybrid)) {
            failures.push('HYBRID_FAIL');
        }
        const corrupted = new Uint8Array(encrypted);
        corrupted[10] ^= 0xFF;
        try {
            await rsa.decrypt(privateKey, corrupted);
            failures.push('TAMPER_DETECT_FAIL');
        } catch (e) {}
    } catch (e) {
        failures.push(`RUNTIME_ERROR: ${e.code || e.message}`);
    }
    return failures.length === 0 ? { ok: true } : { ok: false, failures };
}

async function Benchmark() {
    const results = {};
    const rsa = new RSA({ modulusLength: 2048 });
    const testData = randomBytes(1024);
    const { publicKey, privateKey } = await rsa.generateKeyPair();
    const startKeyGen = performance.now();
    for (let i = 0; i < 10; i++) {
        await rsa.generateKeyPair();
    }
    results.keyGen = 10000 / (performance.now() - startKeyGen);
    const startEnc = performance.now();
    for (let i = 0; i < 100; i++) {
        await rsa.encrypt(publicKey, testData);
    }
    results.encrypt = 100000 / (performance.now() - startEnc);
    const encResult = await rsa.encrypt(publicKey, testData);
    const startDec = performance.now();
    for (let i = 0; i < 100; i++) {
        await rsa.decrypt(privateKey, encResult);
    }
    results.decrypt = 100000 / (performance.now() - startDec);
    const startSign = performance.now();
    for (let i = 0; i < 100; i++) {
        await rsa.sign(privateKey, testData);
    }
    results.sign = 100000 / (performance.now() - startSign);
    const sigResult = await rsa.sign(privateKey, testData);
    const startVerify = performance.now();
    for (let i = 0; i < 100; i++) {
        await rsa.verify(publicKey, sigResult, testData);
    }
    results.verify = 100000 / (performance.now() - startVerify);
    const largeData = randomBytes(1024 * 1024);
    const startHybridEnc = performance.now();
    const hybridEnc = await rsa.encrypt(publicKey, largeData);
    results.hybridEncrypt = 1000 / (performance.now() - startHybridEnc);
    const startHybridDec = performance.now();
    await rsa.decrypt(privateKey, hybridEnc);
    results.hybridDecrypt = 1000 / (performance.now() - startHybridDec);
    return { ops: results };
}

export {
    generateKeyPair,
    encrypt,
    decrypt,
    sign,
    verify,
    randomBytes,
    bytesToHex,
    hexToBytes,
    concatUint8,
    constantTimeEq,
    zeroBuffer,
    deriveKeyFromPassword,
    selfTest,
    Benchmark
};

export default RSA;

async function generateKeyPair(opts = {}) {
    const rsa = new RSA(opts);
    return rsa.generateKeyPair();
}

async function encrypt(publicKey, data, opts = {}) {
    const rsa = new RSA(opts);
    return rsa.encrypt(publicKey, data);
}

async function decrypt(privateKey, encryptedData, opts = {}) {
    const rsa = new RSA(opts);
    return rsa.decrypt(privateKey, encryptedData);
}

async function sign(privateKey, data, opts = {}) {
    const rsa = new RSA(opts);
    return rsa.sign(privateKey, data);
}

async function verify(publicKey, signature, data, opts = {}) {
    const rsa = new RSA(opts);
    return rsa.verify(publicKey, signature, data);
}

if (isNode && import.meta.url.endsWith(process.argv[1])) {
    const testResult = await selfTest();
    console.log('Self-Test:', testResult.ok ? 'PASSED' : 'FAILED', testResult.failures || '');
    const benchResult = await Benchmark();
    console.log('Benchmark:', benchResult.ops);
}