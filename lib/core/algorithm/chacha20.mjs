class ChaChaError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
    this.name = "ChaChaError";
  }
}
const crypto = (() => {
  if (
    typeof globalThis !== "undefined" &&
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.getRandomValues === "function"
  )
    return globalThis.crypto;
  try {
    if (typeof require === "function") return require("node:crypto");
  } catch (e) {}
  return null;
})();
const nodeCrypto = (() => {
  try {
    if (typeof require === "function") return require("node:crypto");
  } catch (e) {}
  return null;
})();
const BufferImpl = (() => {
  if (
    typeof globalThis !== "undefined" &&
    typeof globalThis.Buffer !== "undefined"
  )
    return globalThis.Buffer;
  try {
    if (typeof require === "function") return require("node:buffer").Buffer;
  } catch (e) {}
  return null;
})();
const Transform = (() => {
  try {
    if (typeof require === "function") return require("node:stream").Transform;
  } catch (e) {}
  return null;
})();
const WebCryptoSubtle = (() => {
  try {
    if (crypto && crypto.subtle) return crypto.subtle;
    if (nodeCrypto && nodeCrypto.webcrypto && nodeCrypto.webcrypto.subtle)
      return nodeCrypto.webcrypto.subtle;
  } catch (e) {}
  return null;
})();
const USE_WASM = (() => {
  try {
    return (
      (typeof process !== "undefined" && process?.env?.USE_WASM === "1") ||
      globalThis?.USE_WASM === "1"
    );
  } catch (e) {
    return false;
  }
})();
let __CH20_WASM_MODULE = null;
if (USE_WASM) {
  if (
    typeof globalThis !== "undefined" &&
    typeof globalThis.__CH20_WASM_MODULE__ !== "undefined"
  )
    __CH20_WASM_MODULE = globalThis.__CH20_WASM_MODULE__;
  else if (
    typeof process !== "undefined" &&
    process.env.CH20_WASM_PATH &&
    nodeCrypto
  ) {
    try {
      __CH20_WASM_MODULE = require("node:fs").readFileSync(
        process.env.CH20_WASM_PATH
      );
    } catch (e) {
      __CH20_WASM_MODULE = null;
    }
  }
}
function bytesToHex(bytes) {
  const arr = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++)
    arr[i] = bytes[i].toString(16).padStart(2, "0");
  return arr.join("");
}
function hexToBytes(hex) {
  if ((hex.length & 1) !== 0) throw new ChaChaError("BAD_FORMAT", "BAD_FORMAT");
  const out = new Uint8Array(hex.length >>> 1);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToBase64(bytes) {
  if (BufferImpl) return BufferImpl.from(bytes).toString("base64");
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function base64ToBytes(b64) {
  if (BufferImpl) return new Uint8Array(BufferImpl.from(b64, "base64"));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function concatUint8(arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const res = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    res.set(a, off);
    off += a.length;
  }
  return res;
}
function constantTimeEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}
function zeroBuffer(buf) {
  if (!buf) return;
  if (typeof buf.fill === "function") {
    try {
      buf.fill(0);
      return;
    } catch (e) {}
  }
  for (let i = 0; i < buf.length; i++) buf[i] = 0;
}
function randomBytes(len) {
  if (len <= 0) throw new ChaChaError("BAD_INPUT", "BAD_INPUT");
  if (
    typeof process !== "undefined" &&
    nodeCrypto &&
    typeof nodeCrypto.randomBytes === "function"
  ) {
    const b = nodeCrypto.randomBytes(len);
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  }
  if (crypto && typeof crypto.getRandomValues === "function") {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return arr;
  }
  if (
    nodeCrypto &&
    nodeCrypto.webcrypto &&
    typeof nodeCrypto.webcrypto.getRandomValues === "function"
  ) {
    const arr = new Uint8Array(len);
    nodeCrypto.webcrypto.getRandomValues(arr);
    return arr;
  }
  throw new ChaChaError("RNG_UNAVAILABLE", "RNG_UNAVAILABLE");
}
function generateKey(len = 32) {
  return randomBytes(len);
}
async function deriveKeyHKDF(
  ikm,
  salt = null,
  info = null,
  length = 32,
  hash = "SHA-256"
) {
  salt = salt || new Uint8Array(0);
  info = info || new Uint8Array(0);
  if (WebCryptoSubtle) {
    const keyMaterial = await WebCryptoSubtle.importKey(
      "raw",
      ikm,
      { name: "HKDF" },
      false,
      ["deriveBits"]
    );
    const derived = await WebCryptoSubtle.deriveBits(
      { name: "HKDF", hash, salt, info },
      keyMaterial,
      length * 8
    );
    return new Uint8Array(derived);
  }
  if (nodeCrypto && typeof nodeCrypto.hkdf === "function") {
    return await new Promise((resolve, reject) => {
      nodeCrypto.hkdf(
        hash.toLowerCase(),
        ikm,
        salt,
        info,
        length,
        (err, derived) => {
          if (err)
            reject(new ChaChaError("HKDF_FAILED", "PLATFORM_UNSUPPORTED"));
          else resolve(new Uint8Array(derived));
        }
      );
    });
  }
  if (nodeCrypto && typeof nodeCrypto.hkdfSync === "function") {
    try {
      const d = nodeCrypto.hkdfSync(
        hash.toLowerCase(),
        ikm,
        salt,
        info,
        length
      );
      return new Uint8Array(d);
    } catch (e) {
      throw new ChaChaError("HKDF_FAILED", "PLATFORM_UNSUPPORTED");
    }
  }
  throw new ChaChaError("HKDF unavailable", "PLATFORM_UNSUPPORTED");
}
function rotl32(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}
function quarterRound(state, a, b, c, d) {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotl32(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotl32(state[b] ^ state[c], 7);
}
function chacha20Block(key, counter, nonce) {
  if (!(key instanceof Uint8Array) || key.length !== 32)
    throw new ChaChaError("INVALID_KEY", "INVALID_KEY");
  if (!(nonce instanceof Uint8Array) || nonce.length !== 12)
    throw new ChaChaError("INVALID_NONCE", "INVALID_NONCE");
  const state = new Uint32Array(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) {
    state[4 + i] =
      (key[i * 4] |
        (key[i * 4 + 1] << 8) |
        (key[i * 4 + 2] << 16) |
        (key[i * 4 + 3] << 24)) >>>
      0;
  }
  state[12] = counter >>> 0;
  state[13] =
    (nonce[0] | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24)) >>> 0;
  state[14] =
    (nonce[4] | (nonce[5] << 8) | (nonce[6] << 16) | (nonce[7] << 24)) >>> 0;
  state[15] =
    (nonce[8] | (nonce[9] << 8) | (nonce[10] << 16) | (nonce[11] << 24)) >>> 0;
  const working = new Uint32Array(16);
  working.set(state);
  for (let i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const v = (working[i] + state[i]) >>> 0;
    out[i * 4] = v & 0xff;
    out[i * 4 + 1] = (v >>> 8) & 0xff;
    out[i * 4 + 2] = (v >>> 16) & 0xff;
    out[i * 4 + 3] = (v >>> 24) & 0xff;
  }
  return out;
}
function chacha20XorIETF(key, nonce, data, counterStart = 1) {
  if (!(key instanceof Uint8Array) || key.length !== 32)
    throw new ChaChaError("INVALID_KEY", "INVALID_KEY");
  if (!(nonce instanceof Uint8Array) || nonce.length !== 12)
    throw new ChaChaError("INVALID_NONCE", "INVALID_NONCE");
  if (!Number.isSafeInteger(counterStart) || counterStart < 0)
    throw new ChaChaError("BAD_INPUT", "BAD_INPUT");
  const out = new Uint8Array(data.length);
  let counter = counterStart >>> 0;
  for (let i = 0; i < data.length; i += 64) {
    if (counter === 0)
      throw new ChaChaError("COUNTER_OVERFLOW", "COUNTER_OVERFLOW");
    const ks = chacha20Block(key, counter, nonce);
    const chunkLen = Math.min(64, data.length - i);
    for (let j = 0; j < chunkLen; j++) out[i + j] = data[i + j] ^ ks[j];
    counter = (counter + 1) >>> 0;
  }
  return out;
}
function hChaCha20(key, nonce16) {
  if (!(key instanceof Uint8Array) || key.length !== 32)
    throw new ChaChaError("INVALID_KEY", "INVALID_KEY");
  if (!(nonce16 instanceof Uint8Array) || nonce16.length !== 16)
    throw new ChaChaError("INVALID_NONCE", "INVALID_NONCE");
  const state = new Uint32Array(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let i = 0; i < 8; i++)
    state[4 + i] =
      (key[i * 4] |
        (key[i * 4 + 1] << 8) |
        (key[i * 4 + 2] << 16) |
        (key[i * 4 + 3] << 24)) >>>
      0;
  state[12] =
    (nonce16[0] |
      (nonce16[1] << 8) |
      (nonce16[2] << 16) |
      (nonce16[3] << 24)) >>>
    0;
  state[13] =
    (nonce16[4] |
      (nonce16[5] << 8) |
      (nonce16[6] << 16) |
      (nonce16[7] << 24)) >>>
    0;
  state[14] =
    (nonce16[8] |
      (nonce16[9] << 8) |
      (nonce16[10] << 16) |
      (nonce16[11] << 24)) >>>
    0;
  state[15] =
    (nonce16[12] |
      (nonce16[13] << 8) |
      (nonce16[14] << 16) |
      (nonce16[15] << 24)) >>>
    0;
  const working = new Uint32Array(16);
  working.set(state);
  for (let i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const v = working[i];
    out[i * 4] = v & 0xff;
    out[i * 4 + 1] = (v >>> 8) & 0xff;
    out[i * 4 + 2] = (v >>> 16) & 0xff;
    out[i * 4 + 3] = (v >>> 24) & 0xff;
  }
  for (let i = 12; i < 16; i++) {
    const v = working[i];
    const idx = (i - 8) * 4;
    out[idx] = v & 0xff;
    out[idx + 1] = (v >>> 8) & 0xff;
    out[idx + 2] = (v >>> 16) & 0xff;
    out[idx + 3] = (v >>> 24) & 0xff;
  }
  return out;
}
function xchacha20Xor(key, nonce24, data, counterStart = 1) {
  if (!(key instanceof Uint8Array) || key.length !== 32)
    throw new ChaChaError("INVALID_KEY", "INVALID_KEY");
  if (!(nonce24 instanceof Uint8Array) || nonce24.length !== 24)
    throw new ChaChaError("INVALID_NONCE", "INVALID_NONCE");
  const subkey = hChaCha20(key, nonce24.subarray(0, 16));
  const subnonce = new Uint8Array(12);
  subnonce.set(nonce24.subarray(16, 24), 4);
  return chacha20XorIETF(subkey, subnonce, data, counterStart);
}
function le64(n) {
  const b = new Uint8Array(8);
  let x = BigInt(n);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}
function aadPad(aad) {
  const pad = (16 - (aad.length % 16)) % 16;
  return new Uint8Array(pad);
}
function ciphertextPad(ct) {
  const pad = (16 - (ct.length % 16)) % 16;
  return new Uint8Array(pad);
}
function poly1305Tag(key, msg) {
  if (!(key instanceof Uint8Array) || key.length !== 32)
    throw new ChaChaError("INVALID_KEY", "INVALID_KEY");
  const rBytes = key.subarray(0, 16);
  const sBytes = key.subarray(16, 32);
  const r0 =
    BigInt(rBytes[0]) |
    (BigInt(rBytes[1]) << 8n) |
    (BigInt(rBytes[2]) << 16n) |
    (BigInt(rBytes[3]) << 24n);
  const r1 =
    BigInt(rBytes[4]) |
    (BigInt(rBytes[5]) << 8n) |
    (BigInt(rBytes[6]) << 16n) |
    (BigInt(rBytes[7]) << 24n);
  const r2 =
    BigInt(rBytes[8]) |
    (BigInt(rBytes[9]) << 8n) |
    (BigInt(rBytes[10]) << 16n) |
    (BigInt(rBytes[11]) << 24n);
  const r3 =
    BigInt(rBytes[12]) |
    (BigInt(rBytes[13]) << 8n) |
    (BigInt(rBytes[14]) << 16n) |
    (BigInt(rBytes[15]) << 24n);
  const R0 = r0 & 0x0fffffffn;
  const R1 = r1 & 0x0ffffffcn;
  const R2 = r2 & 0x0ffffffcn;
  const R3 = r3 & 0x0ffffffcn;
  const s0 =
    BigInt(sBytes[0]) |
    (BigInt(sBytes[1]) << 8n) |
    (BigInt(sBytes[2]) << 16n) |
    (BigInt(sBytes[3]) << 24n);
  const s1 =
    BigInt(sBytes[4]) |
    (BigInt(sBytes[5]) << 8n) |
    (BigInt(sBytes[6]) << 16n) |
    (BigInt(sBytes[7]) << 24n);
  const s2 =
    BigInt(sBytes[8]) |
    (BigInt(sBytes[9]) << 8n) |
    (BigInt(sBytes[10]) << 16n) |
    (BigInt(sBytes[11]) << 24n);
  const s3 =
    BigInt(sBytes[12]) |
    (BigInt(sBytes[13]) << 8n) |
    (BigInt(sBytes[14]) << 16n) |
    (BigInt(sBytes[15]) << 24n);
  let h0 = 0n,
    h1 = 0n,
    h2 = 0n,
    h3 = 0n,
    h4 = 0n;
  const len = msg.length;
  for (let i = 0; i < len; i += 16) {
    const block = msg.subarray(i, Math.min(i + 16, len));
    let d0 = 0n,
      d1 = 0n,
      d2 = 0n,
      d3 = 0n;
    for (let j = 0; j < block.length; j++) {
      const shift = BigInt((j % 4) * 8);
      const idx = Math.floor(j / 4);
      if (idx === 0) d0 |= BigInt(block[j]) << shift;
      else if (idx === 1) d1 |= BigInt(block[j]) << shift;
      else if (idx === 2) d2 |= BigInt(block[j]) << shift;
      else d3 |= BigInt(block[j]) << shift;
    }
    if (block.length < 16) {
      const pad = 1n << BigInt((block.length % 4) * 8);
      if (block.length < 4) d0 |= pad;
      else if (block.length < 8) d1 |= pad;
      else if (block.length < 12) d2 |= pad;
      else d3 |= pad;
    } else {
      // full 16-bytes -> append 1 at 2^128 position implicitly handled below
    }
    h0 += d0;
    h1 += d1;
    h2 += d2;
    h3 += d3;
    // multiply by r modulo (2^130 - 5) - limb method (simplified)
    const t0 = h0 * R0 + h1 * R3 * 5n + h2 * R2 * 5n + h3 * R1 * 5n;
    const t1 = h0 * R1 + h1 * R0 + h2 * R3 * 5n + h3 * R2 * 5n;
    const t2 = h0 * R2 + h1 * R1 + h2 * R0 + h3 * R3 * 5n;
    const t3 = h0 * R3 + h1 * R2 + h2 * R1 + h3 * R0;
    h0 = t0 & ((1n << 32n) - 1n);
    let carry = t0 >> 32n;
    h1 = (t1 + carry) & ((1n << 32n) - 1n);
    carry = (t1 + carry) >> 32n;
    h2 = (t2 + carry) & ((1n << 32n) - 1n);
    carry = (t2 + carry) >> 32n;
    h3 = (t3 + carry) & ((1n << 32n) - 1n);
    carry = (t3 + carry) >> 32n;
    h0 = (h0 + carry * 5n) & ((1n << 32n) - 1n);
  }
  // final addition of s
  let f = h0 + (h1 << 32n) + (h2 << 64n) + (h3 << 96n);
  f += s0 + (s1 << 32n) + (s2 << 64n) + (s3 << 96n);
  const tag = new Uint8Array(16);
  for (let i = 0; i < 16; i++) tag[i] = Number((f >> BigInt(i * 8)) & 0xffn);
  return tag;
}
function poly1305KeyGen(key, nonce) {
  try {
    const block = chacha20Block(
      key,
      0,
      nonce.length === 12
        ? nonce
        : (() => {
            const n = new Uint8Array(12);
            n.set(nonce.subarray(0, 12));
            return n;
          })()
    );
    return block.subarray(0, 32);
  } catch (e) {
    throw new ChaChaError("OTK_GEN_FAILED", "OTK_GEN_FAILED");
  }
}
async function aeadEncrypt(
  key,
  nonce,
  plaintext,
  aad = new Uint8Array(0),
  opts = {}
) {
  if (!(key instanceof Uint8Array) || key.length !== 32)
    throw new ChaChaError("INVALID_KEY", "INVALID_KEY");
  if (!(nonce instanceof Uint8Array))
    throw new ChaChaError("INVALID_NONCE", "INVALID_NONCE");
  let ciphertext, tag;
  if (
    nodeCrypto &&
    typeof nodeCrypto.createCipheriv === "function" &&
    nodeCrypto.getCiphers &&
    nodeCrypto.getCiphers().includes("chacha20-poly1305")
  ) {
    const cipher = nodeCrypto.createCipheriv(
      "chacha20-poly1305",
      BufferImpl.from(key),
      BufferImpl.from(nonce),
      { authTagLength: 16 }
    );
    if (aad && aad.length) cipher.setAAD(BufferImpl.from(aad));
    const ct1 = cipher.update(BufferImpl.from(plaintext));
    const ct2 = cipher.final();
    const ctBuf = BufferImpl.concat([ct1, ct2]);
    const t = cipher.getAuthTag();
    ciphertext = new Uint8Array(
      ctBuf.buffer,
      ctBuf.byteOffset,
      ctBuf.byteLength
    );
    tag = new Uint8Array(t.buffer, t.byteOffset, t.byteLength);
    return { ciphertext, tag };
  }
  if (USE_WASM && __CH20_WASM_MODULE && __CH20_WASM_MODULE.aead_encrypt) {
    const res = __CH20_WASM_MODULE.aead_encrypt(key, nonce, plaintext, aad);
    return {
      ciphertext: new Uint8Array(res.ciphertext),
      tag: new Uint8Array(res.tag),
    };
  }
  const otk = poly1305KeyGen(key, nonce);
  try {
    const ct =
      nonce.length === 12
        ? chacha20XorIETF(key, nonce, plaintext, 1)
        : xchacha20Xor(key, nonce, plaintext, 1);
    const macData = concatUint8([
      aad,
      aadPad(aad),
      ct,
      ciphertextPad(ct),
      le64(aad.length),
      le64(ct.length),
    ]);
    const t = poly1305Tag(otk, macData);
    ciphertext = ct;
    tag = t;
    return { ciphertext, tag };
  } finally {
    zeroBuffer(otk);
  }
}
async function aeadDecrypt(
  key,
  nonce,
  ciphertext,
  tag,
  aad = new Uint8Array(0),
  opts = {}
) {
  if (!(key instanceof Uint8Array) || key.length !== 32)
    throw new ChaChaError("INVALID_KEY", "INVALID_KEY");
  if (!(nonce instanceof Uint8Array))
    throw new ChaChaError("INVALID_NONCE", "INVALID_NONCE");
  if (!(tag instanceof Uint8Array) || tag.length !== 16)
    throw new ChaChaError("INVALID_TAG", "INVALID_TAG");
  if (
    nodeCrypto &&
    typeof nodeCrypto.createDecipheriv === "function" &&
    nodeCrypto.getCiphers &&
    nodeCrypto.getCiphers().includes("chacha20-poly1305")
  ) {
    const decipher = nodeCrypto.createDecipheriv(
      "chacha20-poly1305",
      BufferImpl.from(key),
      BufferImpl.from(nonce),
      { authTagLength: 16 }
    );
    if (aad && aad.length) decipher.setAAD(BufferImpl.from(aad));
    decipher.setAuthTag(BufferImpl.from(tag));
    try {
      const p1 = decipher.update(BufferImpl.from(ciphertext));
      const p2 = decipher.final();
      const pb = BufferImpl.concat([p1, p2]);
      return new Uint8Array(pb.buffer, pb.byteOffset, pb.byteLength);
    } catch (e) {
      throw new ChaChaError("AUTH_FAILURE", "AUTH_FAILURE");
    }
  }
  if (USE_WASM && __CH20_WASM_MODULE && __CH20_WASM_MODULE.aead_decrypt) {
    const out = __CH20_WASM_MODULE.aead_decrypt(
      key,
      nonce,
      ciphertext,
      tag,
      aad
    );
    return new Uint8Array(out);
  }
  const otk = poly1305KeyGen(key, nonce);
  try {
    const macData = concatUint8([
      aad,
      aadPad(aad),
      ciphertext,
      ciphertextPad(ciphertext),
      le64(aad.length),
      le64(ciphertext.length),
    ]);
    const calc = poly1305Tag(otk, macData);
    if (!constantTimeEq(calc, tag))
      throw new ChaChaError("AUTH_FAILURE", "AUTH_FAILURE");
    return nonce.length === 12
      ? chacha20XorIETF(key, nonce, ciphertext, 1)
      : xchacha20Xor(key, nonce, ciphertext, 1);
  } finally {
    zeroBuffer(otk);
  }
}
async function encrypt(key, plaintext, opts = {}) {
  const mode = opts.mode || "ietf";
  const nonceLen = mode === "xchacha" ? 24 : 12;
  const nonce = opts.nonce || randomBytes(nonceLen);
  const aad = opts.aad || new Uint8Array(0);
  const { ciphertext, tag } = await aeadEncrypt(
    key,
    nonce,
    plaintext,
    aad,
    opts
  );
  const out = concatUint8([nonce, ciphertext, tag]);
  if (opts.output === "hex") return bytesToHex(out);
  if (opts.output === "base64") return bytesToBase64(out);
  return out;
}
async function decrypt(key, input, opts = {}) {
  let data;
  if (typeof input === "string") {
    if (opts.input === "hex") data = hexToBytes(input);
    else if (opts.input === "base64") data = base64ToBytes(input);
    else throw new ChaChaError("BAD_FORMAT", "BAD_FORMAT");
  } else data = input;
  if (!(data instanceof Uint8Array) || data.length < 12 + 16)
    throw new ChaChaError("BAD_FORMAT", "BAD_FORMAT");
  const nonce = data.subarray(0, 12);
  const ciphertext = data.subarray(12, data.length - 16);
  const tag = data.subarray(data.length - 16);
  const aad = opts.aad || new Uint8Array(0);
  return await aeadDecrypt(key, nonce, ciphertext, tag, aad, opts);
}
async function encryptEnvelope(key, plaintext, opts = {}) {
  const mode = opts.mode || "ietf";
  const nonceLen = mode === "xchacha" ? 24 : 12;
  const nonce = opts.nonce || randomBytes(nonceLen);
  const aad = opts.aad || new Uint8Array(0);
  const { ciphertext, tag } = await aeadEncrypt(
    key,
    nonce,
    plaintext,
    aad,
    opts
  );
  const header = new Uint8Array(4 + 1 + 1 + 1 + 1); // 'CH20' + ver + mode + flags + nonceLen (we will place nonce after)
  header.set([67, 72, 50, 48, 1, mode === "ietf" ? 1 : 2, 0, nonceLen]);
  const payloadLen = new Uint8Array(8);
  new DataView(payloadLen.buffer).setBigUint64(
    0,
    BigInt(ciphertext.length),
    false
  );
  const result = concatUint8([header, nonce, payloadLen, ciphertext, tag]);
  if (opts.output === "hex") return bytesToHex(result);
  if (opts.output === "base64") return bytesToBase64(result);
  return result;
}
async function decryptEnvelope(key, input, opts = {}) {
  let data = input;
  if (typeof input === "string") {
    if (opts.encoding === "hex") data = hexToBytes(input);
    else if (opts.encoding === "base64") data = base64ToBytes(input);
    else throw new ChaChaError("BAD_FORMAT", "BAD_FORMAT");
  }
  if (!(data instanceof Uint8Array) || data.length < 4 + 1 + 1 + 1 + 8 + 16)
    throw new ChaChaError("BAD_FORMAT", "BAD_FORMAT");
  if (String.fromCharCode(...data.subarray(0, 4)) !== "CH20")
    throw new ChaChaError("BAD_FORMAT", "BAD_FORMAT");
  const version = data[4];
  if (version !== 1) throw new ChaChaError("BAD_FORMAT", "BAD_FORMAT");
  const mode = data[5] === 1 ? "ietf" : "xchacha";
  const nonceLen = data[7];
  const nonce = data.subarray(8, 8 + nonceLen);
  const payloadLen = Number(
    new DataView(data.buffer, data.byteOffset + 8 + nonceLen, 8).getBigUint64(
      0,
      false
    )
  );
  const cStart = 8 + nonceLen + 8;
  const cEnd = cStart + payloadLen;
  if (cEnd + 16 > data.length)
    throw new ChaChaError("BAD_FORMAT", "BAD_FORMAT");
  const ciphertext = data.subarray(cStart, cEnd);
  const tag = data.subarray(cEnd, cEnd + 16);
  const aad = opts.aad || new Uint8Array(0);
  return await aeadDecrypt(
    key,
    nonce,
    ciphertext,
    tag,
    concatUint8([data.subarray(0, 8), aad]),
    opts
  );
}
function encryptStream(key, opts = {}) {
  if (!Transform)
    throw new ChaChaError("PLATFORM_UNSUPPORTED", "PLATFORM_UNSUPPORTED");
  const chunkSize = opts.chunkSize || 65536;
  const mode = opts.mode || "ietf";
  const baseNonce = opts.nonce || randomBytes(mode === "xchacha" ? 24 : 12);
  let seq = 0n;
  return new Transform({
    transform(chunk, encoding, callback) {
      (async () => {
        try {
          const chunkBuf =
            chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
          const chunkNonce = new Uint8Array(baseNonce.length);
          chunkNonce.set(baseNonce);
          if (mode === "ietf") {
            for (let i = 0; i < 8; i++) {
              const v = Number((seq >> BigInt(i * 8)) & 0xffn);
              chunkNonce[4 + i] = chunkNonce[4 + i] ^ v;
            }
          } else {
            const ctr = new Uint8Array(8);
            const dv = new DataView(ctr.buffer);
            dv.setBigUint64(0, seq, false);
            chunkNonce.set(ctr, 16);
          }
          const aad = new Uint8Array(8);
          new DataView(aad.buffer).setBigUint64(0, seq, false);
          const { ciphertext, tag } = await aeadEncrypt(
            key,
            chunkNonce,
            chunkBuf,
            aad,
            opts
          );
          const recordLen = ciphertext.length + 16;
          const header = new Uint8Array(4 + 1 + 8);
          new DataView(header.buffer).setUint32(0, recordLen, false);
          header[4] = 0;
          const seqBuf = new Uint8Array(8);
          new DataView(seqBuf.buffer).setBigUint64(0, seq, false);
          header.set(seqBuf, 5);
          const out = concatUint8([header, ciphertext, tag]);
          this.push(out);
          seq = seq + 1n;
          callback();
        } catch (err) {
          callback(err);
        }
      })();
    },
    flush(cb) {
      cb();
    },
  });
}
function decryptStream(key, opts = {}) {
  if (!Transform)
    throw new ChaChaError("PLATFORM_UNSUPPORTED", "PLATFORM_UNSUPPORTED");
  const mode = opts.mode || "ietf";
  let buffer = new Uint8Array(0);
  return new Transform({
    transform(chunk, encoding, callback) {
      (async () => {
        try {
          buffer = concatUint8([
            buffer,
            chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk),
          ]);
          while (buffer.length >= 13) {
            const header = buffer.subarray(0, 13);
            const dvHeader = new DataView(
              header.buffer,
              header.byteOffset,
              header.byteLength
            );
            const len = dvHeader.getUint32(0, false);
            if (buffer.length < 13 + len) break;
            const record = buffer.subarray(13, 13 + len);
            const flags = header[4];
            const counterBuf = header.subarray(5, 13);
            const seq = new DataView(
              counterBuf.buffer,
              counterBuf.byteOffset,
              counterBuf.byteLength
            ).getBigUint64(0, false);
            const chunkNonce = new Uint8Array(mode === "xchacha" ? 24 : 12);
            if (opts.nonce) chunkNonce.set(opts.nonce);
            if (mode === "ietf") {
              for (let i = 0; i < 8; i++) {
                const v = Number((seq >> BigInt(i * 8)) & 0xffn);
                chunkNonce[4 + i] = chunkNonce[4 + i] ^ v;
              }
            } else {
              const seqBuf = new Uint8Array(8);
              new DataView(seqBuf.buffer).setBigUint64(0, seq, false);
              chunkNonce.set(seqBuf, 16);
            }
            const ciphertext = record.subarray(0, record.length - 16);
            const tag = record.subarray(record.length - 16);
            const aad = new Uint8Array(8);
            new DataView(aad.buffer).setBigUint64(0, seq, false);
            const plain = await aeadDecrypt(
              key,
              chunkNonce,
              ciphertext,
              tag,
              aad,
              opts
            );
            this.push(plain);
            buffer = buffer.subarray(13 + len);
          }
          callback();
        } catch (err) {
          callback(err);
        }
      })();
    },
    flush(cb) {
      if (buffer.length > 0) cb(new ChaChaError("BAD_FORMAT", "BAD_FORMAT"));
      else cb();
    },
  });
}
let __TEST_HOOK__ = undefined;
if (
  (typeof process !== "undefined" && process?.env?.CH20_TEST === "1") ||
  globalThis?.CH20_TEST === "1"
) {
  __TEST_HOOK__ = {
    mutateState: (obj, prop, val) => {
      if (obj && prop in obj) obj[prop] = val;
    },
  };
}
async function selfTest() {
  const vectors = [
    {
      key: hexToBytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ),
      nonce: hexToBytes("000000090000004a00000000"),
      counter: 1,
      block: hexToBytes(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
      ),
    },
    {
      key: hexToBytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ),
      nonce: hexToBytes("000000000000004a00000000"),
      plaintext: hexToBytes(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
      ),
      counterStart: 1,
      ciphertext: hexToBytes(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
      ),
    },
    {
      key: hexToBytes(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
      ),
      nonce: hexToBytes("070000004041424344454647"),
      aad: hexToBytes("50515253c0c1c2c3c4c5c6c7"),
      plaintext: hexToBytes(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
      ),
      tag: hexToBytes("1ae10b594f09e26a7e902ecbd0600691"),
    },
  ];
  const b = chacha20Block(vectors[0].key, vectors[0].counter, vectors[0].nonce);
  if (!constantTimeEq(b, vectors[0].block))
    throw new ChaChaError("SELFTEST_FAIL", "SELFTEST_FAIL");
  const s = chacha20XorIETF(
    vectors[1].key,
    vectors[1].nonce,
    vectors[1].plaintext,
    vectors[1].counterStart
  );
  if (!constantTimeEq(s, vectors[1].ciphertext))
    throw new ChaChaError("SELFTEST_FAIL", "SELFTEST_FAIL");
  const { tag } = await aeadEncrypt(
    vectors[2].key,
    vectors[2].nonce,
    vectors[2].plaintext,
    vectors[2].aad
  );
  if (!constantTimeEq(tag, vectors[2].tag))
    throw new ChaChaError("SELFTEST_FAIL", "SELFTEST_FAIL");
  const dec = await aeadDecrypt(
    vectors[2].key,
    vectors[2].nonce,
    vectors[1].ciphertext,
    vectors[2].tag,
    vectors[2].aad
  );
  if (!constantTimeEq(dec, vectors[2].plaintext))
    throw new ChaChaError("SELFTEST_FAIL", "SELFTEST_FAIL");
  return true;
}
async function Benchmark(sizeMB = 4, iterations = 3) {
  const key = randomBytes(32);
  const nonce12 = randomBytes(12);
  const nonce24 = randomBytes(24);
  const data = randomBytes(sizeMB * 1024 * 1024);
  const results = { ietf: [], xchacha: [], stream: [] };
  for (let i = 0; i < iterations; i++) {
    let t0 = process.hrtime.bigint();
    chacha20XorIETF(key, nonce12, data);
    let t1 = process.hrtime.bigint();
    results.ietf.push(Number(sizeMB * 1e9) / Number(t1 - t0));
    t0 = process.hrtime.bigint();
    xchacha20Xor(key, nonce24, data);
    t1 = process.hrtime.bigint();
    results.xchacha.push(Number(sizeMB * 1e9) / Number(t1 - t0));
    t0 = process.hrtime.bigint();
    const s = encryptStream(key);
    s.write(data);
    s.end();
    while (s.read());
    t1 = process.hrtime.bigint();
    results.stream.push(Number(sizeMB * 1e9) / Number(t1 - t0));
  }
  const median = (arr) => {
    arr.sort((a, b) => a - b);
    const m = Math.floor(arr.length / 2);
    return arr.length % 2 ? arr[m] : (arr[m - 1] + arr[m]) / 2;
  };
  return {
    ietf: median(results.ietf),
    xchacha: median(results.xchacha),
    stream: median(results.stream),
  };
}
function dts() {
  return (
    `declare class ChaChaError extends Error { code: string; constructor(message: string, code: string); }` +
    `declare function generateKey(len?: number): Uint8Array;` +
    `declare function deriveKeyHKDF(ikm: Uint8Array, salt: Uint8Array | null, info: Uint8Array | null, length?: number, hash?: string): Promise<Uint8Array>;` +
    `declare function chacha20Block(key: Uint8Array, counter: number, nonce12: Uint8Array): Uint8Array;` +
    `declare function chacha20XorIETF(key: Uint8Array, nonce12: Uint8Array, data: Uint8Array, counterStart?: number): Uint8Array;` +
    `declare function hChaCha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array;` +
    `declare function xchacha20Xor(key: Uint8Array, nonce24: Uint8Array, data: Uint8Array, counterStart?: number): Uint8Array;` +
    `declare function poly1305Tag(key: Uint8Array, msg: Uint8Array): Uint8Array;` +
    `declare function aeadEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array, opts?: any): Promise<{ ciphertext: Uint8Array, tag: Uint8Array }>;` +
    `declare function aeadDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad?: Uint8Array, opts?: any): Promise<Uint8Array>;` +
    `declare function encrypt(key: Uint8Array, plaintext: Uint8Array, opts?: any): Promise<Uint8Array | string>;` +
    `declare function decrypt(key: Uint8Array, input: Uint8Array | string, opts?: any): Promise<Uint8Array>;` +
    `declare function encryptEnvelope(key: Uint8Array, plaintext: Uint8Array, opts?: any): Promise<Uint8Array | string>;` +
    `declare function decryptEnvelope(key: Uint8Array, input: Uint8Array | string, opts?: any): Promise<Uint8Array>;` +
    `declare function encryptStream(key: Uint8Array, opts?: any): any;` +
    `declare function decryptStream(key: Uint8Array, opts?: any): any;` +
    `declare function randomBytes(len: number): Uint8Array;` +
    `declare function bytesToHex(bytes: Uint8Array): string;` +
    `declare function hexToBytes(hex: string): Uint8Array;` +
    `declare function concatUint8(arrays: Uint8Array[]): Uint8Array;` +
    `declare function constantTimeEq(a: Uint8Array, b: Uint8Array): boolean;` +
    `declare function zeroBuffer(buf: Uint8Array | Buffer): void;` +
    `declare function selfTest(): Promise<boolean>;` +
    `declare function Benchmark(sizeMB?: number, iterations?: number): Promise<{ ietf: number, xchacha: number, stream: number }>;` +
    `declare const __TEST_HOOK__: any;` +
    `declare class ChaCha20Poly1305 { constructor(opts?: any); }` +
    `export { ChaCha20Poly1305, chacha20Block, chacha20XorIETF, hChaCha20, xchacha20Xor, poly1305Tag, aeadEncrypt, aeadDecrypt, encrypt, decrypt, encryptEnvelope, decryptEnvelope, encryptStream, decryptStream, generateKey, deriveKeyHKDF, randomBytes, bytesToHex, hexToBytes, concatUint8, constantTimeEq, zeroBuffer, selfTest, Benchmark, __TEST_HOOK__, ChaChaError }; export default ChaCha20Poly1305;`
  );
}
class ChaCha20Poly1305 {
  constructor(opts = {}) {
    this.opts = opts;
  }
}
export {
  ChaCha20Poly1305,
  chacha20Block,
  chacha20XorIETF,
  hChaCha20,
  xchacha20Xor,
  poly1305Tag,
  aeadEncrypt,
  aeadDecrypt,
  encrypt,
  decrypt,
  encryptEnvelope,
  decryptEnvelope,
  encryptStream,
  decryptStream,
  generateKey,
  deriveKeyHKDF,
  randomBytes,
  bytesToHex,
  hexToBytes,
  concatUint8,
  constantTimeEq,
  zeroBuffer,
  selfTest,
  Benchmark,
  __TEST_HOOK__,
  ChaChaError,
};
export default ChaCha20Poly1305;
if (
  typeof process !== "undefined" &&
  typeof process.argv !== "undefined" &&
  process.argv[1] === import.meta.url
) {
  (async () => {
    try {
      await selfTest();
      console.log("selfTest: OK");
      const bench = await Benchmark();
      console.log(JSON.stringify(bench));
      process.exit(0);
    } catch (e) {
      console.error("selfTest: FAIL", e);
      process.exit(1);
    }
  })();
}
