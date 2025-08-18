const sBox = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
  0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4,
  0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7,
  0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3,
  0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09,
  0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3,
  0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe,
  0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
  0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c,
  0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
  0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
  0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2,
  0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
  0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
  0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
  0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
  0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const invSBox = new Uint8Array([
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81,
  0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e,
  0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23,
  0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66,
  0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72,
  0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65,
  0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46,
  0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
  0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca,
  0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91,
  0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
  0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
  0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f,
  0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
  0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8,
  0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93,
  0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
  0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
  0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]);

// Round constants
const rcon = new Uint8Array([
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]);

// Precompute multiplication tables
const mul2 = new Uint8Array(256);
const mul3 = new Uint8Array(256);
const mul9 = new Uint8Array(256);
const mul11 = new Uint8Array(256);
const mul13 = new Uint8Array(256);
const mul14 = new Uint8Array(256);

for (let i = 0; i < 256; i++) {
  if (i < 128) {
    mul2[i] = i << 1;
  } else {
    mul2[i] = (i << 1) ^ 0x11b;
  }

  mul3[i] = mul2[i] ^ i;
  mul9[i] = mul2[mul2[mul2[i]]] ^ i; // 9 = 2^3 + 1
  mul11[i] = mul2[mul2[mul2[i]] ^ i] ^ i; // 11 = 2^3 + 2 + 1
  mul13[i] = mul2[mul2[mul2[i] ^ i]] ^ i; // 13 = 2^3 + 2^2 + 1
  mul14[i] = mul2[mul2[mul2[i] ^ i] ^ i]; // 14 = 2^3 + 2^2 + 2
}

/**
 * Expand 256-bit key into 240-byte round keys
 * @param {Uint8Array} key - 32-byte AES key
 * @returns {Uint8Array} - 240-byte round keys
 */
export function keyExpansion(key) {
  if (key.length !== 32) throw new Error("Key must be 32 bytes");

  const roundKeys = new Uint8Array(240); // 60 words × 4 bytes
  roundKeys.set(key.subarray(0, 32), 0);

  for (let i = 8; i < 60; i++) {
    let temp = roundKeys.slice((i - 1) * 4, i * 4);

    if (i % 8 === 0) {
      // RotWord
      temp = new Uint8Array([temp[1], temp[2], temp[3], temp[0]]);
      // SubWord
      temp = new Uint8Array([
        sBox[temp[0]],
        sBox[temp[1]],
        sBox[temp[2]],
        sBox[temp[3]],
      ]);
      // Rcon
      temp[0] ^= rcon[Math.floor(i / 8) - 1];
    } else if (i % 8 === 4) {
      // SubWord only
      temp = new Uint8Array([
        sBox[temp[0]],
        sBox[temp[1]],
        sBox[temp[2]],
        sBox[temp[3]],
      ]);
    }

    const prevOffset = (i - 8) * 4;
    const dest = i * 4;
    for (let j = 0; j < 4; j++) {
      roundKeys[dest + j] = temp[j] ^ roundKeys[prevOffset + j];
    }
  }

  return roundKeys;
}

/**
 * AES-256 block encryption
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} block - 16-byte plaintext block
 * @returns {Uint8Array} - 16-byte ciphertext block
 */
export function encryptBlock(key, block) {
  if (key.length !== 32) throw new Error("Key must be 32 bytes");
  if (block.length !== 16) throw new Error("Block must be 16 bytes");

  const roundKeys = keyExpansion(key);
  let state = new Uint8Array(block);

  // Initial round
  state = addRoundKey(state, roundKeys.subarray(0, 16));

  // 13 main rounds
  for (let round = 1; round <= 13; round++) {
    state = subBytes(state);
    state = shiftRows(state);
    state = mixColumns(state);
    state = addRoundKey(state, roundKeys.subarray(round * 16, round * 16 + 16));
  }

  // Final round
  state = subBytes(state);
  state = shiftRows(state);
  state = addRoundKey(state, roundKeys.subarray(224, 240));

  return state;
}

/**
 * AES-256 block decryption
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} block - 16-byte ciphertext block
 * @returns {Uint8Array} - 16-byte plaintext block
 */
export function decryptBlock(key, block) {
  if (key.length !== 32) throw new Error("Key must be 32 bytes");
  if (block.length !== 16) throw new Error("Block must be 16 bytes");

  const roundKeys = keyExpansion(key);
  let state = new Uint8Array(block);

  // Initial round
  state = addRoundKey(state, roundKeys.subarray(224, 240));
  state = invShiftRows(state);
  state = invSubBytes(state);

  // 13 main rounds
  for (let round = 13; round >= 1; round--) {
    state = invSubBytes(state);
    state = invShiftRows(state);
    state = invMixColumns(state);
    state = addRoundKey(state, roundKeys.subarray(round * 16, round * 16 + 16));
  }

  state = addRoundKey(state, roundKeys.subarray(0, 16));

  return state;
}

// Core AES operations
function subBytes(state) {
  return new Uint8Array(state.map((b) => sBox[b]));
}

function invSubBytes(state) {
  return new Uint8Array(state.map((b) => invSBox[b]));
}

function shiftRows(state) {
  return new Uint8Array([
    state[0],
    state[5],
    state[10],
    state[15],
    state[4],
    state[9],
    state[14],
    state[3],
    state[8],
    state[13],
    state[2],
    state[7],
    state[12],
    state[1],
    state[6],
    state[11],
  ]);
}

export function invShiftRows(state) {
  return new Uint8Array([
    state[0],
    state[13],
    state[10],
    state[7],
    state[4],
    state[1],
    state[14],
    state[11],
    state[8],
    state[5],
    state[2],
    state[15],
    state[12],
    state[9],
    state[6],
    state[3],
  ]);
}

export function mixColumns(state) {
  const result = new Uint8Array(16);

  for (let col = 0; col < 4; col++) {
    const offset = col * 4;
    const s0 = state[offset];
    const s1 = state[offset + 1];
    const s2 = state[offset + 2];
    const s3 = state[offset + 3];

    result[offset] = mul2[s0] ^ mul3[s1] ^ s2 ^ s3;
    result[offset + 1] = s0 ^ mul2[s1] ^ mul3[s2] ^ s3;
    result[offset + 2] = s0 ^ s1 ^ mul2[s2] ^ mul3[s3];
    result[offset + 3] = mul3[s0] ^ s1 ^ s2 ^ mul2[s3];
  }

  return result;
}

export function invMixColumns(state) {
  const result = new Uint8Array(16);

  for (let col = 0; col < 4; col++) {
    const offset = col * 4;
    const s0 = state[offset];
    const s1 = state[offset + 1];
    const s2 = state[offset + 2];
    const s3 = state[offset + 3];

    result[offset] = mul14[s0] ^ mul11[s1] ^ mul13[s2] ^ mul9[s3];
    result[offset + 1] = mul9[s0] ^ mul14[s1] ^ mul11[s2] ^ mul13[s3];
    result[offset + 2] = mul13[s0] ^ mul9[s1] ^ mul14[s2] ^ mul11[s3];
    result[offset + 3] = mul11[s0] ^ mul13[s1] ^ mul9[s2] ^ mul14[s3];
  }

  return result;
}

export function addRoundKey(state, roundKey) {
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    result[i] = state[i] ^ roundKey[i];
  }
  return result;
}

// Padding utilities
/**
 * PKCS#7 padding
 * @param {Uint8Array} data - Input data
 * @param {number} [blockSize=16] - Block size
 * @returns {Uint8Array} - Padded data
 */
export function pkcs7Pad(data, blockSize = 16) {
  if (blockSize > 255) throw new Error("Block size too large");
  const padding = blockSize - (data.length % blockSize);
  const result = new Uint8Array(data.length + padding);
  result.set(data);
  result.fill(padding, data.length);
  return result;
}

/**
 * Remove PKCS#7 padding
 * @param {Uint8Array} data - Padded data
 * @param {number} [blockSize=16] - Block size
 * @returns {Uint8Array} - Unpadded data
 */
export function pkcs7Unpad(data, blockSize = 16) {
  if (data.length === 0 || data.length % blockSize !== 0) {
    throw new Error("Invalid padded data");
  }

  const padding = data[data.length - 1];
  if (padding === 0 || padding > blockSize) {
    throw new Error("Invalid padding");
  }

  for (let i = data.length - padding; i < data.length; i++) {
    if (data[i] !== padding) {
      throw new Error("Invalid padding");
    }
  }

  return data.subarray(0, data.length - padding);
}

// Mode operations
/**
 * ECB encryption (INSECURE - for testing only)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} plaintext - Input data
 * @returns {Uint8Array} - Encrypted data
 */
export function ecbEncrypt(key, plaintext) {
  const padded = pkcs7Pad(plaintext);
  const result = new Uint8Array(padded.length);

  for (let i = 0; i < padded.length; i += 16) {
    const block = encryptBlock(key, padded.subarray(i, i + 16));
    result.set(block, i);
  }

  return result;
}

/**
 * ECB decryption (INSECURE - for testing only)
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} ciphertext - Encrypted data
 * @returns {Uint8Array} - Decrypted data
 */
export function ecbDecrypt(key, ciphertext) {
  if (ciphertext.length % 16 !== 0) {
    throw new Error("Ciphertext must be multiple of block size");
  }

  const result = new Uint8Array(ciphertext.length);

  for (let i = 0; i < ciphertext.length; i += 16) {
    const block = decryptBlock(key, ciphertext.subarray(i, i + 16));
    result.set(block, i);
  }

  return pkcs7Unpad(result);
}

/**
 * CBC encryption
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte initialization vector
 * @param {Uint8Array} plaintext - Input data
 * @returns {Uint8Array} - Encrypted data
 */
export function cbcEncrypt(key, iv, plaintext) {
  if (iv.length !== 16) throw new Error("IV must be 16 bytes");

  const padded = pkcs7Pad(plaintext);
  const result = new Uint8Array(padded.length);
  let prev = new Uint8Array(iv);

  for (let i = 0; i < padded.length; i += 16) {
    const block = padded.subarray(i, i + 16);
    const xored = new Uint8Array(16);
    for (let j = 0; j < 16; j++) xored[j] = block[j] ^ prev[j];

    const encrypted = encryptBlock(key, xored);
    result.set(encrypted, i);
    prev = encrypted;
  }

  return result;
}

/**
 * CBC decryption
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte initialization vector
 * @param {Uint8Array} ciphertext - Encrypted data
 * @returns {Uint8Array} - Decrypted data
 */
export function cbcDecrypt(key, iv, ciphertext) {
  if (iv.length !== 16) throw new Error("IV must be 16 bytes");
  if (ciphertext.length % 16 !== 0) {
    throw new Error("Ciphertext must be multiple of block size");
  }

  const result = new Uint8Array(ciphertext.length);
  let prev = new Uint8Array(iv);

  for (let i = 0; i < ciphertext.length; i += 16) {
    const block = ciphertext.subarray(i, i + 16);
    const decrypted = decryptBlock(key, block);

    const xored = new Uint8Array(16);
    for (let j = 0; j < 16; j++) xored[j] = decrypted[j] ^ prev[j];

    result.set(xored, i);
    prev = block;
  }

  return pkcs7Unpad(result);
}

/**
 * CTR encryption/decryption
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} nonce - 12-16 byte nonce
 * @param {Uint8Array} data - Input data
 * @param {number} [counterStart=0] - Initial counter value
 * @returns {Uint8Array} - Processed data
 */
export function ctrEncrypt(key, nonce, data, counterStart = 0) {
  if (nonce.length < 12 || nonce.length > 16) {
    throw new Error("Nonce must be 12-16 bytes");
  }

  const result = new Uint8Array(data.length);
  const counterBlock = new Uint8Array(16);
  counterBlock.set(nonce, 0);

  const counter = new DataView(counterBlock.buffer);
  counter.setUint32(12, counterStart, false); // Big-endian counter

  for (let i = 0; i < data.length; i += 16) {
    // Update counter block
    counter.setUint32(12, counterStart + Math.floor(i / 16), false);

    // Generate keystream block
    const keystream = encryptBlock(key, counterBlock);

    // XOR with data
    const length = Math.min(16, data.length - i);
    for (let j = 0; j < length; j++) {
      result[i + j] = data[i + j] ^ keystream[j];
    }
  }

  return result;
}

// Utility functions
/**
 * Convert hex string to bytes
 * @param {string} hex - Hex string
 * @returns {Uint8Array} - Byte array
 */
export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have even length");
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to hex string
 * @param {Uint8Array} u8 - Byte array
 * @returns {string} - Hex string
 */
export function bytesToHex(u8) {
  return Array.from(u8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Generate random bytes
 * @param {number} len - Number of bytes
 * @returns {Uint8Array} - Random bytes
 */
export function randomBytes(len) {
  if (len <= 0) throw new Error("Length must be positive");

  if (globalThis.crypto && globalThis.crypto.getRandomValues) {
    const arr = new Uint8Array(len);
    globalThis.crypto.getRandomValues(arr);
    return arr;
  }

  throw new Error("No CSPRNG available");
}

// Known Answer Tests (KAT)
/**
 * Run self-test with known vectors
 * @returns {true} - Returns true if all tests pass
 * @throws {Error} - If any test fails
 */
export function selfTest() {
  // AES-256 ECB Test (NIST SP 800-38A F.1.5)
  const key1 = hexToBytes(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
  );
  const pt1 = hexToBytes("6bc1bee22e409f96e93d7e117393172a");
  const ct1 = hexToBytes("f3eed1bdb5d2a03c064b5a7e3db181f8");

  const encrypted1 = encryptBlock(key1, pt1);
  if (bytesToHex(encrypted1) !== bytesToHex(ct1)) {
    throw new Error("ECB encryption test failed");
  }

  const decrypted1 = decryptBlock(key1, ct1);
  if (bytesToHex(decrypted1) !== bytesToHex(pt1)) {
    throw new Error("ECB decryption test failed");
  }

  // AES-256 CBC Test (NIST SP 800-38A F.2.5)
  const iv2 = hexToBytes("000102030405060708090a0b0c0d0e0f");
  const key2 = key1; // Same key as above
  const pt2 = pt1; // Same plaintext
  const ct2 = hexToBytes("f58c4c04d6e5f1ba779eabfb5f7bfbd6");

  const encrypted2 = cbcEncrypt(key2, iv2, pt2);
  if (bytesToHex(encrypted2.subarray(0, 16)) !== bytesToHex(ct2)) {
    throw new Error("CBC encryption test failed");
  }

  const decrypted2 = cbcDecrypt(key2, iv2, encrypted2);
  if (bytesToHex(decrypted2) !== bytesToHex(pt2)) {
    throw new Error("CBC decryption test failed");
  }

  // CTR mode smoke test
  const nonce3 = randomBytes(12);
  const key3 = randomBytes(32);
  const pt3 = new TextEncoder().encode("AES-256 CTR mode test");

  const ct3 = ctrEncrypt(key3, nonce3, pt3);
  const decrypted3 = ctrEncrypt(key3, nonce3, ct3);

  if (bytesToHex(decrypted3) !== bytesToHex(pt3)) {
    throw new Error("CTR mode test failed");
  }

  return true;
}

// Example usage:
//   import { hexToBytes, cbcEncrypt, cbcDecrypt, randomBytes, selfTest } from './aes256.mjs';
//   selfTest(); // throws if any test fails
//
//   const key = hexToBytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
//   const iv = randomBytes(16);
//   const msg = new TextEncoder().encode('hello secret');
//
//   const ct = cbcEncrypt(key, iv, msg);
//   const pt = cbcDecrypt(key, iv, ct);
//   console.log(new TextDecoder().decode(pt)); // 'hello secret'
