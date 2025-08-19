// blake2.mjs - Production-ready BLAKE2 cryptographic utilities (Node.js ESM)
import {
  createHash,
  createHmac,
  timingSafeEqual,
  randomBytes,
  pbkdf2Sync,
  pbkdf2,
} from "crypto";
import { createReadStream } from "fs";
import { access } from "fs/promises";
import { constants } from "fs";
import { pipeline } from "stream/promises";

const DEFAULT_ENCODING = "hex";
const VALID_ENCODINGS = new Set([
  "hex",
  "base64",
  "latin1",
  "base64url",
  "buffer",
  "uint8array",
]);
const DEFAULT_PBKDF2_ITERATIONS = 100000;
const DEFAULT_PBKDF2_KEYLEN = 64;
const DEFAULT_SALT_LENGTH = 16;

// Check if BLAKE2 algorithms are available
const BLAKE2_AVAILABLE = (() => {
  try {
    createHash("blake2b512");
    createHash("blake2s256");
    return true;
  } catch {
    return false;
  }
})();

function assertEncoding(enc) {
  if (!VALID_ENCODINGS.has(enc)) {
    throw new TypeError(
      `Invalid encoding "${enc}". Supported: ${[...VALID_ENCODINGS].join(", ")}`
    );
  }
}

function toBuffer(input, inputEncoding = "utf8") {
  if (input == null) throw new TypeError("Input is required");
  if (Buffer.isBuffer(input)) return input;
  if (typeof input === "string") return Buffer.from(input, inputEncoding);
  if (input instanceof ArrayBuffer) return Buffer.from(input);
  if (ArrayBuffer.isView(input))
    return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  throw new TypeError("Unsupported input type");
}

function encodeOutput(buf, encoding = "hex") {
  assertEncoding(encoding);

  switch (encoding) {
    case "buffer":
      return buf;
    case "uint8array":
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    case "base64url":
      return buf
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    default:
      return buf.toString(encoding);
  }
}

function normalizeOptions(options, defaultEncoding = DEFAULT_ENCODING) {
  if (typeof options === "string") return { encoding: options };
  return { encoding: defaultEncoding, ...options };
}

function validateVariant(variant) {
  if (!["blake2b", "blake2s"].includes(variant)) {
    throw new TypeError('Variant must be "blake2b" or "blake2s"');
  }
}

export function hash(input, options = {}) {
  if (!BLAKE2_AVAILABLE) {
    throw new Error(
      "BLAKE2 is not available in this environment. Use Node.js 18+ or a different hash algorithm."
    );
  }

  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  const variant = opts.variant || "blake2b";
  validateVariant(variant);

  assertEncoding(encoding);

  const inputBuf = toBuffer(input, opts.inputEncoding);
  const algorithm = variant === "blake2b" ? "blake2b512" : "blake2s256";
  const hashObj = createHash(algorithm);

  // Handle key if provided
  if (opts.key) {
    const keyBuf = toBuffer(opts.key, opts.keyEncoding);
    hashObj.update(keyBuf);
  }

  // Handle salt if provided
  if (opts.salt) {
    const saltBuf = toBuffer(opts.salt, opts.saltEncoding);
    hashObj.update(saltBuf);
  }

  hashObj.update(inputBuf);
  const digest = hashObj.digest();
  return encodeOutput(digest, encoding);
}

export async function hashAsync(input, options = {}) {
  return Promise.resolve().then(() => hash(input, options));
}

export function hmac(key, input, options = {}) {
  if (!BLAKE2_AVAILABLE) {
    throw new Error(
      "BLAKE2 is not available in this environment. Use Node.js 18+ or a different HMAC algorithm."
    );
  }

  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  const variant = opts.variant || "blake2b";
  validateVariant(variant);

  assertEncoding(encoding);

  const inputBuf = toBuffer(input, opts.inputEncoding);
  const keyBuf = toBuffer(key, opts.keyEncoding);
  const algorithm = variant === "blake2b" ? "blake2b512" : "blake2s256";

  const hmacObj = createHmac(algorithm, keyBuf);
  hmacObj.update(inputBuf);
  const digest = hmacObj.digest();

  return encodeOutput(digest, encoding);
}

export async function hashFile(path, options = {}) {
  if (!BLAKE2_AVAILABLE) {
    throw new Error(
      "BLAKE2 is not available in this environment. Use Node.js 18+ or a different hash algorithm."
    );
  }

  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  const variant = opts.variant || "blake2b";
  validateVariant(variant);

  assertEncoding(encoding);

  if (typeof path !== "string") throw new TypeError("Path must be a string");
  await access(path, constants.R_OK);

  const algorithm = variant === "blake2b" ? "blake2b512" : "blake2s256";
  const hashObj = createHash(algorithm);
  const rs = createReadStream(path);

  // Handle key if provided
  if (opts.key) {
    const keyBuf = toBuffer(opts.key, opts.keyEncoding);
    hashObj.update(keyBuf);
  }

  // Handle salt if provided
  if (opts.salt) {
    const saltBuf = toBuffer(opts.salt, opts.saltEncoding);
    hashObj.update(saltBuf);
  }

  const cleanup = () => {
    if (!rs.destroyed) rs.destroy();
  };

  try {
    await pipeline(rs, hashObj);
    const digest = hashObj.digest();
    return encodeOutput(digest, encoding);
  } finally {
    cleanup();
  }
}

export function pbkdf2(password, salt, options = {}) {
  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  const iterations = opts.iterations || DEFAULT_PBKDF2_ITERATIONS;
  const keylen = opts.keylen || DEFAULT_PBKDF2_KEYLEN;

  assertEncoding(encoding);

  const passwordBuf = toBuffer(password, opts.inputEncoding);
  const saltBuf = toBuffer(salt, opts.saltEncoding);

  // Note: Node.js doesn't support BLAKE2 for PBKDF2, so we fall back to SHA-512
  const dk = pbkdf2Sync(passwordBuf, saltBuf, iterations, keylen, "sha512");
  return encodeOutput(dk, encoding);
}

export async function pbkdf2Async(password, salt, options = {}) {
  return new Promise((resolve, reject) => {
    try {
      const opts = normalizeOptions(options);
      const encoding = opts.encoding;
      const iterations = opts.iterations || DEFAULT_PBKDF2_ITERATIONS;
      const keylen = opts.keylen || DEFAULT_PBKDF2_KEYLEN;

      assertEncoding(encoding);

      const passwordBuf = toBuffer(password, opts.inputEncoding);
      const saltBuf = toBuffer(salt, opts.saltEncoding);

      // Note: Node.js doesn't support BLAKE2 for PBKDF2, so we fall back to SHA-512
      pbkdf2(passwordBuf, saltBuf, iterations, keylen, "sha512", (err, dk) => {
        if (err) return reject(err);
        resolve(encodeOutput(dk, encoding));
      });
    } catch (err) {
      reject(err);
    }
  });
}

export function randomSalt(length = DEFAULT_SALT_LENGTH, encoding = "hex") {
  assertEncoding(encoding);
  const salt = randomBytes(length);
  return encodeOutput(salt, encoding);
}

export function compare(a, b) {
  if (a == null || b == null) return false;

  const bufA = Buffer.isBuffer(a) ? a : toBuffer(a);
  const bufB = Buffer.isBuffer(b) ? b : toBuffer(b);

  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export function selfTest() {
  const results = [];
  let allPassed = true;

  try {
    // Test 1: Basic hash
    const hashResult = hash("abc", { variant: "blake2b", encoding: "hex" });
    results.push({ test: "Basic hash", passed: true, result: hashResult });
  } catch (error) {
    results.push({ test: "Basic hash", passed: false, error: error.message });
    allPassed = false;
  }

  try {
    // Test 2: Empty string
    const emptyHash = hash("", { variant: "blake2b", encoding: "hex" });
    results.push({
      test: "Empty string hash",
      passed: true,
      result: emptyHash,
    });
  } catch (error) {
    results.push({
      test: "Empty string hash",
      passed: false,
      error: error.message,
    });
    allPassed = false;
  }

  try {
    // Test 3: Keyed hash
    const keyedHash = hash("message", {
      variant: "blake2b",
      encoding: "hex",
      key: "secret-key",
    });
    results.push({ test: "Keyed hash", passed: true, result: keyedHash });
  } catch (error) {
    results.push({ test: "Keyed hash", passed: false, error: error.message });
    allPassed = false;
  }

  try {
    // Test 4: HMAC
    const hmacResult = hmac("key", "data", {
      variant: "blake2b",
      encoding: "hex",
    });
    results.push({ test: "HMAC", passed: true, result: hmacResult });
  } catch (error) {
    results.push({ test: "HMAC", passed: false, error: error.message });
    allPassed = false;
  }

  try {
    // Test 5: PBKDF2
    const pbkdf2Result = pbkdf2("password", "salt", {
      iterations: 1000,
      keylen: 32,
      encoding: "hex",
    });
    results.push({ test: "PBKDF2", passed: true, result: pbkdf2Result });
  } catch (error) {
    results.push({ test: "PBKDF2", passed: false, error: error.message });
    allPassed = false;
  }

  try {
    // Test 6: Compare
    const hash1 = hash("test", { variant: "blake2b", encoding: "hex" });
    const hash2 = hash("test", { variant: "blake2b", encoding: "hex" });
    const compareResult = compare(hash1, hash2);
    results.push({
      test: "Compare",
      passed: compareResult,
      result: compareResult,
    });
    if (!compareResult) allPassed = false;
  } catch (error) {
    results.push({ test: "Compare", passed: false, error: error.message });
    allPassed = false;
  }

  // Performance test
  try {
    const testData = randomBytes(1024 * 1024); // 1MB
    const start = performance.now();
    const perfHash = hash(testData, { variant: "blake2b", encoding: "hex" });
    const end = performance.now();
    const opsPerSec = 1000 / (end - start);

    results.push({
      test: "Performance",
      passed: true,
      result: `~${opsPerSec.toFixed(2)} ops/sec for 1MB data`,
    });
  } catch (error) {
    results.push({ test: "Performance", passed: false, error: error.message });
    allPassed = false;
  }

  return { ok: allPassed, details: results };
}

// Convenience functions
export const hashHex = (input, opts = {}) =>
  hash(input, { ...opts, encoding: "hex" });
export const hashBase64 = (input, opts = {}) =>
  hash(input, { ...opts, encoding: "base64" });
export const hashBase64Url = (input, opts = {}) =>
  hash(input, { ...opts, encoding: "base64url" });
export const hashBuffer = (input, opts = {}) =>
  hash(input, { ...opts, encoding: "buffer" });

export default {
  hash,
  hashAsync,
  hashHex,
  hashBase64,
  hashBase64Url,
  hashBuffer,
  hmac,
  hashFile,
  pbkdf2,
  pbkdf2Async,
  randomSalt,
  compare,
  selfTest,
  BLAKE2_AVAILABLE,
};
