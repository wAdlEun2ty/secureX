class ECCError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const curves = {
  "P-256": {
    hash: "SHA-256",
    publicKeyLength: 65,
    privateKeyLength: 32,
    id: 1,
  },
  "P-384": {
    hash: "SHA-384",
    publicKeyLength: 97,
    privateKeyLength: 48,
    id: 2,
  },
  "P-521": {
    hash: "SHA-512",
    publicKeyLength: 133,
    privateKeyLength: 66,
    id: 3,
  },
  secp256k1: {
    hash: "SHA-256",
    publicKeyLength: 65,
    privateKeyLength: 32,
    id: 4,
  },
};
const idToCurve = Object.fromEntries(
  Object.entries(curves).map(([k, v]) => [v.id, k])
);

let webcrypto, nodecrypto;
const getWebCrypto = () => {
  if (!webcrypto) {
    if (typeof crypto !== "undefined" && crypto.subtle)
      webcrypto = crypto.subtle;
    else if (globalThis.crypto?.subtle) webcrypto = globalThis.crypto.subtle;
  }
  return webcrypto;
};
const getNodeCrypto = async () => {
  if (!nodecrypto && process?.versions?.node) {
    nodecrypto = (await import("crypto")).webcrypto.subtle;
  }
  return nodecrypto;
};
const getCrypto = async () => getWebCrypto() || (await getNodeCrypto());

const fallback = {
  hmac: async (key, data, hash) => {
    const crypto = await getCrypto();
    const cryptoKey = await crypto.importKey(
      "raw",
      key,
      { name: "HMAC", hash },
      false,
      ["sign"]
    );
    return new Uint8Array(await crypto.sign("HMAC", cryptoKey, data));
  },
  hkdf: async (ikm, salt, info, hash, length) => {
    const hashLen = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 }[hash];
    const prk = await fallback.hmac(salt || new Uint8Array(hashLen), ikm, hash);
    let t = new Uint8Array(0);
    const okm = new Uint8Array(length);
    for (let i = 0, offset = 0; offset < length; i++) {
      const chunk = new Uint8Array(t.length + info.length + 1);
      chunk.set(t);
      chunk.set(info, t.length);
      chunk.set([i + 1], chunk.length - 1);
      t = await fallback.hmac(prk, chunk, hash);
      const copyLen = Math.min(t.length, length - offset);
      okm.set(t.subarray(0, copyLen), offset);
      offset += copyLen;
    }
    return okm;
  },
  pbkdf2: async (password, salt, iterations, hash, length) => {
    const hashLen = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 }[hash];
    const block = new Uint8Array(salt.length + 4);
    block.set(salt);
    const dk = new Uint8Array(length);
    for (let i = 1, offset = 0; offset < length; i++) {
      block.set([i >>> 24, i >>> 16, i >>> 8, i & 0xff], salt.length);
      let u = await fallback.hmac(password, block, hash);
      let t = u;
      for (let j = 1; j < iterations; j++) {
        u = await fallback.hmac(password, u, hash);
        for (let k = 0; k < t.length; k++) t[k] ^= u[k];
      }
      const copyLen = Math.min(t.length, length - offset);
      dk.set(t.subarray(0, copyLen), offset);
      offset += copyLen;
    }
    return dk;
  },
};

export class ECC {
  constructor(opts = {}) {
    this.curve = opts.curve || "P-256";
    this.hybridAES = opts.hybridAES !== false;
    this.kdfIterations = opts.kdfIterations || 1;
    this.pbkdf2Iterations = opts.pbkdf2Iterations || 200000;
  }

  async generateKeyPair(curve = this.curve) {
    const curveInfo = curves[curve];
    if (!curveInfo) throw new ECCError("ERR_INVALID_CURVE");
    const crypto = await getCrypto();
    const keyPair = await crypto.generateKey(
      { name: "ECDH", namedCurve: curve },
      true,
      ["deriveKey", "deriveBits"]
    );
    const publicKey = new Uint8Array(
      await crypto.exportKey("raw", keyPair.publicKey)
    );
    const privateKey = new Uint8Array(
      await crypto.exportKey("raw", keyPair.privateKey)
    );
    return { publicKey, privateKey };
  }

  async sign(privateKey, message, opts = {}) {
    const curveInfo = curves[this.curve];
    if (!curveInfo) throw new ECCError("ERR_INVALID_CURVE");
    const crypto = await getCrypto();
    const key = await crypto.importKey(
      "raw",
      privateKey,
      { name: "ECDSA", namedCurve: this.curve },
      false,
      ["sign"]
    );
    const signature = await crypto.sign(
      { name: "ECDSA", hash: curveInfo.hash },
      key,
      message
    );
    return new Uint8Array(signature);
  }

  async verify(publicKey, message, signature) {
    const curveInfo = curves[this.curve];
    if (!curveInfo) throw new ECCError("ERR_INVALID_CURVE");
    const crypto = await getCrypto();
    const key = await crypto.importKey(
      "raw",
      publicKey,
      { name: "ECDSA", namedCurve: this.curve },
      false,
      ["verify"]
    );
    return await crypto.verify(
      { name: "ECDSA", hash: curveInfo.hash },
      key,
      signature,
      message
    );
  }

  async encrypt(publicKey, plaintext, opts = {}) {
    const curveInfo = curves[this.curve];
    if (!curveInfo) throw new ECCError("ERR_INVALID_CURVE");
    const chunkSize = opts.chunkSize || 65536;
    const isChunked = plaintext.length > chunkSize;
    const ephemeral = await this.generateKeyPair();
    const shared = await this.deriveSharedSecret(
      ephemeral.privateKey,
      publicKey
    );
    const salt = opts.salt || new Uint8Array(32);
    const info = opts.associatedData || new Uint8Array(0);
    const derived = await fallback.hkdf(shared, salt, info, curveInfo.hash, 44);
    const key = derived.subarray(0, 32);
    const ivBase = derived.subarray(32, 44);
    const crypto = await getCrypto();
    const cryptoKey = await crypto.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    let ciphertext, authTag;
    if (!isChunked) {
      const encrypted = await crypto.encrypt(
        { name: "AES-GCM", iv: ivBase },
        cryptoKey,
        plaintext
      );
      ciphertext = new Uint8Array(encrypted);
      authTag = ciphertext.subarray(-16);
      ciphertext = ciphertext.subarray(0, -16);
    } else {
      const chunks = [];
      const tags = [];
      const chunkCount = Math.ceil(plaintext.length / chunkSize);
      for (let i = 0; i < chunkCount; i++) {
        const start = i * chunkSize;
        const end = Math.min(start + chunkSize, plaintext.length);
        const chunk = plaintext.subarray(start, end);
        const counter = new Uint8Array(8);
        new DataView(counter.buffer).setBigUint64(0, BigInt(i), true);
        const iv = new Uint8Array(12);
        for (let j = 0; j < 8; j++) iv[j] = ivBase[j] ^ counter[j];
        iv.set(ivBase.subarray(8), 8);
        const encrypted = await crypto.encrypt(
          { name: "AES-GCM", iv },
          cryptoKey,
          chunk
        );
        const encChunk = new Uint8Array(encrypted);
        chunks.push(encChunk.subarray(0, -16));
        tags.push(encChunk.subarray(-16));
      }
      ciphertext = ECC.concatUint8(...chunks);
      authTag = ECC.concatUint8(...tags);
    }
    const header = new Uint8Array([
      0x01,
      curveInfo.id,
      isChunked ? 0x01 : 0x00,
      ephemeral.publicKey.length >>> 8,
      ephemeral.publicKey.length & 0xff,
    ]);
    const saltHeader = new Uint8Array([salt.length]);
    const chunkCount = new Uint8Array(4);
    if (isChunked)
      new DataView(chunkCount.buffer).setUint32(
        0,
        Math.ceil(plaintext.length / chunkSize)
      );
    return ECC.concatUint8(
      header,
      ephemeral.publicKey,
      saltHeader,
      salt,
      ivBase,
      isChunked ? chunkCount : new Uint8Array(0),
      ciphertext,
      authTag
    );
  }

  async decrypt(privateKey, ciphertext, opts = {}) {
    if (ciphertext[0] !== 0x01) throw new ECCError("ERR_INVALID_CIPHERTEXT");
    const curve = idToCurve[ciphertext[1]];
    if (!curve) throw new ECCError("ERR_INVALID_CURVE");
    const curveInfo = curves[curve];
    const flags = ciphertext[2];
    const isChunked = (flags & 0x01) === 0x01;
    let offset = 3;
    const ephemeralPubLen = (ciphertext[offset] << 8) | ciphertext[offset + 1];
    offset += 2;
    const ephemeralPub = ciphertext.subarray(offset, offset + ephemeralPubLen);
    offset += ephemeralPubLen;
    const saltLen = ciphertext[offset++];
    const salt = ciphertext.subarray(offset, offset + saltLen);
    offset += saltLen;
    const ivBase = ciphertext.subarray(offset, offset + 12);
    offset += 12;
    let chunkCount = 1;
    if (isChunked) {
      chunkCount = new DataView(ciphertext.buffer, offset, 4).getUint32(0);
      offset += 4;
    }
    const authTagOffset =
      ciphertext.length - (isChunked ? chunkCount * 16 : 16);
    const encryptedData = ciphertext.subarray(offset, authTagOffset);
    const authTags = ciphertext.subarray(authTagOffset);
    const shared = await this.deriveSharedSecret(privateKey, ephemeralPub);
    const info = opts.associatedData || new Uint8Array(0);
    const derived = await fallback.hkdf(shared, salt, info, curveInfo.hash, 44);
    const key = derived.subarray(0, 32);
    const crypto = await getCrypto();
    const cryptoKey = await crypto.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    let plaintext;
    if (!isChunked) {
      const fullCiphertext = ECC.concatUint8(encryptedData, authTags);
      try {
        plaintext = await crypto.decrypt(
          { name: "AES-GCM", iv: ivBase },
          cryptoKey,
          fullCiphertext
        );
      } catch {
        throw new ECCError("ERR_DECRYPT_FAILED");
      }
    } else {
      const chunkSize = Math.ceil(encryptedData.length / chunkCount);
      const chunks = [];
      for (let i = 0; i < chunkCount; i++) {
        const start = i * chunkSize;
        const end = Math.min(start + chunkSize, encryptedData.length);
        const chunkCiphertext = encryptedData.subarray(start, end);
        const counter = new Uint8Array(8);
        new DataView(counter.buffer).setBigUint64(0, BigInt(i), true);
        const iv = new Uint8Array(12);
        for (let j = 0; j < 8; j++) iv[j] = ivBase[j] ^ counter[j];
        iv.set(ivBase.subarray(8), 8);
        const tag = authTags.subarray(i * 16, (i + 1) * 16);
        const fullChunk = ECC.concatUint8(chunkCiphertext, tag);
        try {
          const decrypted = await crypto.decrypt(
            { name: "AES-GCM", iv },
            cryptoKey,
            fullChunk
          );
          chunks.push(new Uint8Array(decrypted));
        } catch {
          throw new ECCError("ERR_DECRYPT_FAILED");
        }
      }
      plaintext = ECC.concatUint8(...chunks);
    }
    return new Uint8Array(plaintext);
  }

  async deriveSharedSecret(privateKey, publicKey, opts = {}) {
    const curveInfo = curves[this.curve];
    if (!curveInfo) throw new ECCError("ERR_INVALID_CURVE");
    const crypto = await getCrypto();
    const privateKeyObj = await crypto.importKey(
      "raw",
      privateKey,
      { name: "ECDH", namedCurve: this.curve },
      false,
      ["deriveBits"]
    );
    const publicKeyObj = await crypto.importKey(
      "raw",
      publicKey,
      { name: "ECDH", namedCurve: this.curve },
      false,
      []
    );
    const bits = await crypto.deriveBits(
      { name: "ECDH", public: publicKeyObj },
      privateKeyObj,
      curveInfo.publicKeyLength * 8
    );
    return new Uint8Array(bits);
  }

  async deriveKeyFromPassword(
    password,
    salt,
    iterations = this.pbkdf2Iterations
  ) {
    return await fallback.pbkdf2(password, salt, iterations, "SHA-256", 32);
  }

  async importKey(raw, type, curve = this.curve) {
    const curveInfo = curves[curve];
    if (!curveInfo) throw new ECCError("ERR_INVALID_CURVE");
    const crypto = await getCrypto();
    return await crypto.importKey(
      "raw",
      raw,
      { name: type === "private" ? "ECDH" : "ECDSA", namedCurve: curve },
      false,
      type === "private" ? ["deriveBits"] : ["verify"]
    );
  }

  async exportKey(key, format) {
    const crypto = await getCrypto();
    const exported = await crypto.exportKey(format, key);
    return format === "jwk" ? exported : new Uint8Array(exported);
  }

  static randomBytes(n) {
    const arr = new Uint8Array(n);
    if (crypto.getRandomValues) crypto.getRandomValues(arr);
    else if (globalThis.crypto?.getRandomValues)
      globalThis.crypto.getRandomValues(arr);
    else throw new ECCError("ERR_CRYPTO_UNAVAILABLE");
    return arr;
  }

  static bytesToHex(u8) {
    return Array.from(u8)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  static hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new ECCError("ERR_INVALID_HEX");
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++)
      arr[i] = parseInt(hex.substr(i * 2, 2), 16);
    return arr;
  }

  static concatUint8(...parts) {
    const length = parts.reduce((sum, part) => sum + part.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }

  static constantTimeEq(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
    return result === 0;
  }

  static zeroBuffer(buf) {
    if (buf) buf.fill(0);
  }

  static async selfTest(seed) {
    const test = new ECC({ curve: "P-256" });
    const failures = [];
    try {
      const testKey = await test.generateKeyPair();
      const testMsg = ECC.randomBytes(4096);
      const sig = await test.sign(testKey.privateKey, testMsg);
      if (!(await test.verify(testKey.publicKey, testMsg, sig)))
        failures.push("ERR_SIGN_VERIFY");
      const ciphertext = await test.encrypt(testKey.publicKey, testMsg);
      const plaintext = await test.decrypt(testKey.privateKey, ciphertext);
      if (!ECC.constantTimeEq(testMsg, plaintext))
        failures.push("ERR_ENCRYPT_DECRYPT");
      const ciphertextChunked = await test.encrypt(
        testKey.publicKey,
        ECC.randomBytes(300000),
        { chunkSize: 100000 }
      );
      const plaintextChunked = await test.decrypt(
        testKey.privateKey,
        ciphertextChunked
      );
      if (plaintextChunked.length !== 300000) failures.push("ERR_CHUNKED_SIZE");
      const shared1 = await test.deriveSharedSecret(
        testKey.privateKey,
        testKey.publicKey
      );
      const shared2 = await test.deriveSharedSecret(
        testKey.privateKey,
        testKey.publicKey
      );
      if (!ECC.constantTimeEq(shared1, shared2)) failures.push("ERR_DERIVE");
      const password = new TextEncoder().encode("password");
      const salt = ECC.randomBytes(16);
      const key1 = await test.deriveKeyFromPassword(password, salt, 100000);
      const key2 = await test.deriveKeyFromPassword(password, salt, 100000);
      if (!ECC.constantTimeEq(key1, key2)) failures.push("ERR_PBKDF2");
      const badSig = new Uint8Array(sig);
      badSig[0] ^= 0x01;
      if (await test.verify(testKey.publicKey, testMsg, badSig))
        failures.push("ERR_FUZZ");
    } catch (e) {
      failures.push(e.code || "ERR_SELFTEST");
    }
    return { ok: failures.length === 0, failures };
  }

  static async Benchmark(opts = {}) {
    const test = new ECC();
    const iterations = opts.iterations || 1000;
    const rounds = opts.rounds || 100;
    const results = {};
    const start = performance.now();
    for (let i = 0; i < rounds; i++) {
      await test.generateKeyPair();
    }
    results.keyGen = rounds / ((performance.now() - start) / 1000);
    const testKey = await test.generateKeyPair();
    const testMsg = ECC.randomBytes(1024);
    const signStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      await test.sign(testKey.privateKey, testMsg);
    }
    results.sign = iterations / ((performance.now() - signStart) / 1000);
    const sig = await test.sign(testKey.privateKey, testMsg);
    const verifyStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      await test.verify(testKey.publicKey, testMsg, sig);
    }
    results.verify = iterations / ((performance.now() - verifyStart) / 1000);
    const deriveStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      await test.deriveSharedSecret(testKey.privateKey, testKey.publicKey);
    }
    results.derive = iterations / ((performance.now() - deriveStart) / 1000);
    const encryptStart = performance.now();
    for (let i = 0; i < Math.min(iterations, 50); i++) {
      await test.encrypt(testKey.publicKey, testMsg);
    }
    results.encrypt =
      Math.min(iterations, 50) / ((performance.now() - encryptStart) / 1000);
    const ciphertext = await test.encrypt(testKey.publicKey, testMsg);
    const decryptStart = performance.now();
    for (let i = 0; i < Math.min(iterations, 50); i++) {
      await test.decrypt(testKey.privateKey, ciphertext);
    }
    results.decrypt =
      Math.min(iterations, 50) / ((performance.now() - decryptStart) / 1000);
    const summary = Object.entries(results)
      .map(([k, v]) => `${k}:${v.toFixed(1)}`)
      .join(", ");
    return { summary, ops: results };
  }
}

export default ECC;
export async function generateKeyPair(curve) {
  return await new ECC().generateKeyPair(curve);
}
export async function sign(privateKey, message, opts) {
  return await new ECC().sign(privateKey, message, opts);
}
export async function verify(publicKey, message, signature) {
  return await new ECC().verify(publicKey, message, signature);
}
export async function encrypt(publicKey, plaintext, opts) {
  return await new ECC().encrypt(publicKey, plaintext, opts);
}
export async function decrypt(privateKey, ciphertext, opts) {
  return await new ECC().decrypt(privateKey, ciphertext, opts);
}
export async function deriveSharedSecret(privateKey, publicKey, opts) {
  return await new ECC().deriveSharedSecret(privateKey, publicKey, opts);
}
export async function importKey(raw, type, curve) {
  return await new ECC().importKey(raw, type, curve);
}
export async function exportKey(key, format) {
  return await new ECC().exportKey(key, format);
}
export async function deriveKeyFromPassword(password, salt, iterations) {
  return await new ECC().deriveKeyFromPassword(password, salt, iterations);
}
export function randomBytes(n) {
  return ECC.randomBytes(n);
}
export function bytesToHex(u8) {
  return ECC.bytesToHex(u8);
}
export function hexToBytes(hex) {
  return ECC.hexToBytes(hex);
}
export function concatUint8(...parts) {
  return ECC.concatUint8(...parts);
}
export function constantTimeEq(a, b) {
  return ECC.constantTimeEq(a, b);
}
export function zeroBuffer(buf) {
  ECC.zeroBuffer(buf);
}
export async function selfTest(seed) {
  return await ECC.selfTest(seed);
}
export async function Benchmark(opts) {
  return await ECC.Benchmark(opts);
}

if (
  typeof process !== "undefined" &&
  (import.meta.url === new URL(process.argv[1], "file:").href ||
    process.env.NODE_ECC_SELFTEST)
) {
  (async () => {
    const test = await selfTest();
    console.log(
      `selfTest: ${test.ok ? "OK" : "FAIL " + test.failures.join(",")}`
    );
    const bench = await Benchmark();
    console.log(`benchmark: ${bench.summary}`);
  })();
}
