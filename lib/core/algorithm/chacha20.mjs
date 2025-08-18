// chacha20.mjs - RFC 8439 ChaCha20-Poly1305 implementation
// Production-ready, zero-dependency ES Module for Node and browsers

/**
 * Rotate 32-bit integer left (bitwise)
 * @param {number} x - Input value
 * @param {number} n - Rotation amount (0-31)
 * @returns {number} Rotated value
 */
const rotl32 = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

/**
 * Convert Uint8Array to Uint32Array (little-endian)
 * @param {Uint8Array} bytes - Input bytes
 * @returns {Uint32Array} Words array
 */
function u8ToU32LE(bytes) {
  if (bytes.length % 4 !== 0) throw new Error('Byte length must be multiple of 4');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const result = new Uint32Array(bytes.length >>> 2);
  for (let i = 0; i < result.length; i++) {
    result[i] = view.getUint32(i << 2, true);
  }
  return result;
}

/**
 * Convert Uint32Array to Uint8Array (little-endian)
 * @param {Uint32Array} words - Input words
 * @returns {Uint8Array} Bytes array
 */
function u32ToU8LE(words) {
  const buffer = new ArrayBuffer(words.length << 2);
  const view = new DataView(buffer);
  for (let i = 0; i < words.length; i++) {
    view.setUint32(i << 2, words[i], true);
  }
  return new Uint8Array(buffer);
}

/**
 * XOR two Uint8Arrays (equal length)
 * @param {Uint8Array} a - First array
 * @param {Uint8Array} b - Second array
 * @returns {Uint8Array} Result array
 */
function xorBytes(a, b) {
  if (a.length !== b.length) throw new Error('Arrays must be same length');
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

// ChaCha20 constants
const CHACHA_CONSTANTS = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

/**
 * ChaCha20 quarter round operation (modifies state in-place)
 * @param {Uint32Array} state - ChaCha state
 * @param {number} a - First index
 * @param {number} b - Second index
 * @param {number} c - Third index
 * @param {number} d - Fourth index
 */
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

/**
 * Generate 64-byte ChaCha20 keystream block
 * @param {Uint8Array} key - 32-byte key
 * @param {number} counter - 32-bit block counter
 * @param {Uint8Array} nonce - 12-byte nonce
 * @returns {Uint8Array} 64-byte keystream
 */
export function chacha20Block(key, counter, nonce) {
  if (key.length !== 32) throw new Error('Key must be 32 bytes');
  if (nonce.length !== 12) throw new Error('Nonce must be 12 bytes');

  const state = new Uint32Array(16);
  state.set(CHACHA_CONSTANTS);
  state.set(u8ToU32LE(key), 4);
  state[12] = counter;
  state.set(u8ToU32LE(nonce), 13);

  const workingState = new Uint32Array(state);
  for (let i = 0; i < 10; i++) {
    // Column rounds
    quarterRound(workingState, 0, 4, 8, 12);
    quarterRound(workingState, 1, 5, 9, 13);
    quarterRound(workingState, 2, 6, 10, 14);
    quarterRound(workingState, 3, 7, 11, 15);
    // Diagonal rounds
    quarterRound(workingState, 0, 5, 10, 15);
    quarterRound(workingState, 1, 6, 11, 12);
    quarterRound(workingState, 2, 7, 8, 13);
    quarterRound(workingState, 3, 4, 9, 14);
  }

  for (let i = 0; i < 16; i++) {
    workingState[i] = (workingState[i] + state[i]) >>> 0;
  }

  return u32ToU8LE(workingState);
}

/**
 * Encrypt/decrypt data with IETF ChaCha20 (12-byte nonce)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} nonce12 - 12-byte nonce
 * @param {Uint8Array} data - Data to process
 * @param {number} [counterStart=1] - Starting counter value
 * @returns {Uint8Array} Processed data
 */
export function chacha20XorIETF(key, nonce12, data, counterStart = 1) {
  if (key.length !== 32) throw new Error('Key must be 32 bytes');
  if (nonce12.length !== 12) throw new Error('Nonce must be 12 bytes');
  if (!Number.isSafeInteger(counterStart)) throw new Error('Invalid counter');

  const result = new Uint8Array(data.length);
  const fullBlocks = Math.floor(data.length / 64);
  const remainder = data.length % 64;
  
  let blockCounter = counterStart;
  let position = 0;
  
  for (let i = 0; i < fullBlocks; i++) {
    if (blockCounter >= 0x100000000) throw new Error('Counter overflow');
    const keystream = chacha20Block(key, blockCounter, nonce12);
    const block = data.subarray(position, position + 64);
    result.set(xorBytes(block, keystream), position);
    position += 64;
    blockCounter++;
  }

  if (remainder > 0) {
    if (blockCounter >= 0x100000000) throw new Error('Counter overflow');
    const keystream = chacha20Block(key, blockCounter, nonce12);
    const block = data.subarray(position, position + remainder);
    result.set(xorBytes(block, keystream.subarray(0, remainder)), position);
  }

  return result;
}

// Poly1305 implementation (RFC 8439 §2.5)
const POLY1305_MASK = new Uint32Array([
  0x0fffffff, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc
]);

/**
 * Generate Poly1305 authentication tag
 * @param {Uint8Array} key - 32-byte one-time key
 * @param {Uint8Array} msg - Message to authenticate
 * @returns {Uint8Array} 16-byte tag
 */
export function poly1305Tag(key, msg) {
  if (key.length !== 32) throw new Error('Key must be 32 bytes');
  
  // Clamp r portion (first 16 bytes)
  const r = new Uint32Array(4);
  const rView = new DataView(key.buffer, key.byteOffset, 16);
  for (let i = 0; i < 4; i++) {
    r[i] = rView.getUint32(i << 2, true) & POLY1305_MASK[i];
  }
  
  const s = new Uint32Array([
    rView.getUint32(16, true), rView.getUint32(20, true),
    rView.getUint32(24, true), rView.getUint32(28, true)
  ]);
  
  // 130-bit accumulator (5x26-bit limbs)
  let h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
  
  // Process message in 16-byte blocks
  for (let i = 0; i <= msg.length; i += 16) {
    // Read block with 0x01 padding
    let c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 1;
    if (i < msg.length) {
      const block = msg.subarray(i, Math.min(i + 16, msg.length));
      const view = new DataView(block.buffer, block.byteOffset, block.length);
      for (let j = 0; j < Math.ceil(block.length / 4); j++) {
        const val = view.getUint32(j << 2, true);
        if (j === 0) c0 = val;
        else if (j === 1) c1 = val;
        else if (j === 2) c2 = val;
        else if (j === 3) c3 = val;
      }
      if (block.length % 4 !== 0) {
        const last = view.getUint32(block.length - (block.length % 4), true);
        c4 = (last | (1 << (8 * (block.length % 4)))) >>> 0;
      }
    }
    
    // Add current block to accumulator
    h0 = (h0 + (c0 & 0x3ffffff)) >>> 0;
    h1 = (h1 + (c1 & 0x3ffffff) + ((c0 >>> 26) & 0x3f)) >>> 0;
    h2 = (h2 + (c2 & 0x3ffffff) + ((c1 >>> 26) & 0x3f)) >>> 0;
    h3 = (h3 + (c3 & 0x3ffffff) + ((c2 >>> 26) & 0x3f)) >>> 0;
    h4 = (h4 + (c4 & 0x3ffffff) + ((c3 >>> 26) & 0x3f)) >>> 0;
    
    // Multiply by r (mod 2^130-5)
    const d0 = (
      BigInt(h0) * BigInt(r[0]) +
      BigInt(h1) * BigInt(r[3]) +
      BigInt(h2) * BigInt(r[2]) +
      BigInt(h3) * BigInt(r[1]) +
      BigInt(h4) * BigInt(r[0])
    );
    
    const d1 = (
      BigInt(h0) * BigInt(r[1]) +
      BigInt(h1) * BigInt(r[0]) +
      BigInt(h2) * BigInt(r[3]) +
      BigInt(h3) * BigInt(r[2]) +
      BigInt(h4) * BigInt(r[1])
    );
    
    const d2 = (
      BigInt(h0) * BigInt(r[2]) +
      BigInt(h1) * BigInt(r[1]) +
      BigInt(h2) * BigInt(r[0]) +
      BigInt(h3) * BigInt(r[3]) +
      BigInt(h4) * BigInt(r[2])
    );
    
    const d3 = (
      BigInt(h0) * BigInt(r[3]) +
      BigInt(h1) * BigInt(r[2]) +
      BigInt(h2) * BigInt(r[1]) +
      BigInt(h3) * BigInt(r[0]) +
      BigInt(h4) * BigInt(r[3])
    );
    
    const d4 = BigInt(h4) * BigInt(r[0]);
    
    // Partial reduction
    let carry = Number(d0 >> 26n);
    h0 = Number(d0 & 0x3ffffffn);
    h1 = (Number(d1) + carry) >>> 0;
    carry = h1 >>> 26;
    h1 &= 0x3ffffff;
    h2 = (Number(d2) + carry) >>> 0;
    carry = h2 >>> 26;
    h2 &= 0x3ffffff;
    h3 = (Number(d3) + carry) >>> 0;
    carry = h3 >>> 26;
    h3 &= 0x3ffffff;
    h4 = (Number(d4) + carry) >>> 0;
    carry = h4 >>> 26;
    h4 &= 0x3ffffff;
    h0 = (h0 + carry * 5) >>> 0;
    carry = h0 >>> 26;
    h0 &= 0x3ffffff;
    h1 = (h1 + carry) >>> 0;
  }
  
  // Final reduction
  const g0 = (h0 + 5) >>> 0;
  const g1 = (h1 + (g0 >>> 26)) >>> 0;
  const g2 = (h2 + (g1 >>> 26)) >>> 0;
  const g3 = (h3 + (g2 >>> 26)) >>> 0;
  const g4 = (h4 + (g3 >>> 26) - (1 << 26)) >>> 0;
  
  // Select reduced or original
  const mask = (g4 >>> 31) - 1;
  const h0r = (h0 & mask) | (g0 & ~mask);
  const h1r = (h1 & mask) | (g1 & ~mask);
  const h2r = (h2 & mask) | (g2 & ~mask);
  const h3r = (h3 & mask) | (g3 & ~mask);
  
  // Add s mod 2^128
  const t0 = (h0r | (h1r << 26)) + s[0];
  const t1 = ((h1r >>> 6) | (h2r << 20)) + s[1];
  const t2 = ((h2r >>> 12) | (h3r << 14)) + s[2];
  const t3 = (h3r >>> 18) + s[3];
  
  // Construct tag
  const tag = new Uint8Array(16);
  const view = new DataView(tag.buffer);
  view.setUint32(0, t0, true);
  view.setUint32(4, t1, true);
  view.setUint32(8, t2, true);
  view.setUint32(12, t3, true);
  
  return tag;
}

/**
 * Concatenate multiple Uint8Arrays
 * @param {Uint8Array[]} arrays - Arrays to concatenate
 * @returns {Uint8Array} Concatenated array
 */
function concatUint8Arrays(arrays) {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Pad data to multiple of 16 bytes (RFC 8439 §2.8.1)
 * @param {Uint8Array} data - Input data
 * @returns {Uint8Array} Padded data
 */
function pad16(data) {
  if (data.length % 16 === 0) return data;
  const padded = new Uint8Array(data.length + (16 - (data.length % 16)));
  padded.set(data);
  return padded;
}

/**
 * Encrypt data with AEAD ChaCha20-Poly1305
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} nonce12 - 12-byte nonce
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {Uint8Array} [aad] - Additional authenticated data
 * @returns {{ciphertext: Uint8Array, tag: Uint8Array}} Encrypted data and tag
 */
export function aeadChaCha20Poly1305Encrypt(key, nonce12, plaintext, aad) {
  if (key.length !== 32) throw new Error('Key must be 32 bytes');
  if (nonce12.length !== 12) throw new Error('Nonce must be 12 bytes');
  
  // Generate one-time key
  const otk = chacha20Block(key, 0, nonce12).subarray(0, 32);
  
  // Encrypt data
  const ciphertext = chacha20XorIETF(key, nonce12, plaintext, 1);
  
  // Construct authentication data
  const authData = concatUint8Arrays([
    aad || new Uint8Array(),
    pad16(aad || new Uint8Array()).subarray(aad ? aad.length : 0),
    ciphertext,
    pad16(ciphertext).subarray(ciphertext.length),
    new Uint8Array(new Uint8Array([
      ...new Uint8Array(new BigUint64Array([aad ? BigInt(aad.length) : 0n]).buffer).reverse(),
      ...new Uint8Array(new BigUint64Array([BigInt(ciphertext.length)]).buffer).reverse()
    ]))
  ]);
  
  // Generate tag
  const tag = poly1305Tag(otk, authData);
  
  return { ciphertext, tag };
}

/**
 * Decrypt data with AEAD ChaCha20-Poly1305
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} nonce12 - 12-byte nonce
 * @param {Uint8Array} ciphertext - Data to decrypt
 * @param {Uint8Array} tag - 16-byte authentication tag
 * @param {Uint8Array} [aad] - Additional authenticated data
 * @returns {Uint8Array} Decrypted data
 */
export function aeadChaCha20Poly1305Decrypt(key, nonce12, ciphertext, tag, aad) {
  if (key.length !== 32) throw new Error('Key must be 32 bytes');
  if (nonce12.length !== 12) throw new Error('Nonce must be 12 bytes');
  if (tag.length !== 16) throw new Error('Tag must be 16 bytes');
  
  // Generate one-time key
  const otk = chacha20Block(key, 0, nonce12).subarray(0, 32);
  
  // Reconstruct authentication data
  const authData = concatUint8Arrays([
    aad || new Uint8Array(),
    pad16(aad || new Uint8Array()).subarray(aad ? aad.length : 0),
    ciphertext,
    pad16(ciphertext).subarray(ciphertext.length),
    new Uint8Array(new Uint8Array([
      ...new Uint8Array(new BigUint64Array([aad ? BigInt(aad.length) : 0n]).buffer).reverse(),
      ...new Uint8Array(new BigUint64Array([BigInt(ciphertext.length)]).buffer).reverse()
    ]))
  ]);
  
  // Verify tag (constant-time)
  const calcTag = poly1305Tag(otk, authData);
  let diff = 0;
  for (let i = 0; i < 16; i++) {
    diff |= tag[i] ^ calcTag[i];
  }
  if (diff !== 0) throw new Error('Tag verification failed');
  
  // Decrypt data
  return chacha20XorIETF(key, nonce12, ciphertext, 1);
}

/**
 * Convert hex string to Uint8Array
 * @param {string} hex - Hex string
 * @returns {Uint8Array} Byte array
 */
export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 * @param {Uint8Array} u8 - Byte array
 * @returns {string} Hex string
 */
export function bytesToHex(u8) {
  return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate cryptographically secure random bytes
 * @param {number} len - Number of bytes
 * @returns {Uint8Array} Random bytes
 */
export async function randomBytes(len) {
  if (typeof globalThis?.crypto?.getRandomValues === 'function') {
    return globalThis.crypto.getRandomValues(new Uint8Array(len));
  }
  try {
    const { webcrypto } = await import('node:crypto');
    return webcrypto.getRandomValues(new Uint8Array(len));
  } catch (e) {
    throw new Error('No secure RNG available');
  }
}