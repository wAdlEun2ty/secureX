// sha512.mjs - Production-ready SHA-512 cryptographic utilities (Node.js ESM)
import {
  createHash,
  createHmac,
  timingSafeEqual,
  randomBytes,
  pbkdf2Sync,
  pbkdf2,
  scryptSync,
  scrypt,
} from "crypto";
import { createReadStream, readFileSync } from "fs";
import { access } from "fs/promises";
import { constants } from "fs";
import { pipeline } from "stream/promises";

const DEFAULT_ENCODING = "hex";
const VALID_ENCODINGS = new Set([
  "hex",
  "base64",
  "latin1",
  "base64url",
  "raw",
  "buffer",
  "uint8array",
]);
const DEFAULT_PBKDF2_ITERATIONS = 100000;
const DEFAULT_PBKDF2_KEYLEN = 64;
const DEFAULT_SCRYPT_KEYLEN = 64;

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
    case "raw":
      return buf.toString("latin1");
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

export function sha512(data, options = DEFAULT_ENCODING) {
  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  assertEncoding(encoding);

  const buf = toBuffer(data, opts.inputEncoding);
  const hash = createHash("sha512").update(buf).digest();
  return encodeOutput(hash, encoding);
}

export async function sha512Async(data, options = DEFAULT_ENCODING) {
  return Promise.resolve().then(() => sha512(data, options));
}

export function sha512Hmac(data, key, options = DEFAULT_ENCODING) {
  if (key == null) throw new TypeError("Key is required for HMAC");

  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  assertEncoding(encoding);

  const dataBuf = toBuffer(data, opts.inputEncoding);
  const keyBuf = toBuffer(key, opts.keyEncoding);
  const hmac = createHmac("sha512", keyBuf).update(dataBuf).digest();
  return encodeOutput(hmac, encoding);
}

export async function sha512HmacAsync(data, key, options = DEFAULT_ENCODING) {
  return Promise.resolve().then(() => sha512Hmac(data, key, options));
}

export async function sha512Stream(stream, options = {}) {
  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  assertEncoding(encoding);

  if (!stream || typeof stream[Symbol.asyncIterator] !== "function") {
    throw new TypeError("Stream must be a readable async iterable");
  }

  const signal = opts.signal;
  if (signal?.aborted) throw new Error("Operation aborted");

  const hash = createHash("sha512");
  let bytes = 0;

  try {
    for await (const chunk of stream) {
      if (signal?.aborted) throw new Error("Operation aborted");
      hash.update(chunk);
      bytes += chunk.length;
      opts.onProgress?.(bytes);
    }
  } catch (error) {
    if (error.message !== "Operation aborted") throw error;
  }

  const dig = hash.digest();
  return encodeOutput(dig, encoding);
}

export async function sha512File(path, options = {}) {
  if (typeof path !== "string") throw new TypeError("Path must be a string");
  await access(path, constants.R_OK);

  const rs = createReadStream(path);
  const cleanup = () => {
    if (!rs.destroyed) rs.destroy();
  };

  try {
    return await sha512Stream(rs, options);
  } finally {
    cleanup();
  }
}

export function sha512FileSync(path, options = DEFAULT_ENCODING) {
  if (typeof path !== "string") throw new TypeError("Path must be a string");
  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  assertEncoding(encoding);

  const buf = readFileSync(path);
  const hash = createHash("sha512").update(buf).digest();
  return encodeOutput(hash, encoding);
}

export function sha512Salted(data, salt, options = DEFAULT_ENCODING) {
  const opts = normalizeOptions(options);
  const dataBuf = toBuffer(data, opts.inputEncoding);
  const saltBuf = toBuffer(salt, opts.saltEncoding);
  const combined = Buffer.concat([saltBuf, dataBuf]);
  return sha512(combined, opts.encoding);
}

export function sha512Peppered(data, pepper, options = DEFAULT_ENCODING) {
  const opts = normalizeOptions(options);
  const dataBuf = toBuffer(data, opts.inputEncoding);
  const pepperBuf = toBuffer(pepper, opts.pepperEncoding);
  const combined = Buffer.concat([dataBuf, pepperBuf]);
  return sha512(combined, opts.encoding);
}

export function sha512WithSaltPepper(
  data,
  salt,
  pepper,
  options = DEFAULT_ENCODING
) {
  const opts = normalizeOptions(options);
  const dataBuf = toBuffer(data, opts.inputEncoding);
  const saltBuf = toBuffer(salt, opts.saltEncoding);
  const pepperBuf = toBuffer(pepper, opts.pepperEncoding);
  const combined = Buffer.concat([saltBuf, dataBuf, pepperBuf]);
  return sha512(combined, opts.encoding);
}

export function hashPasswordPBKDF2(
  password,
  salt = randomBytes(16),
  iterations = DEFAULT_PBKDF2_ITERATIONS,
  keylen = DEFAULT_PBKDF2_KEYLEN,
  options = DEFAULT_ENCODING
) {
  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  assertEncoding(encoding);

  const passwordBuf = toBuffer(password, opts.inputEncoding);
  const saltBuf = toBuffer(salt, opts.saltEncoding);
  const dk = pbkdf2Sync(passwordBuf, saltBuf, iterations, keylen, "sha512");

  return {
    salt: encodeOutput(saltBuf, encoding),
    hash: encodeOutput(dk, encoding),
    iterations,
    keylen,
  };
}

export function hashPasswordPBKDF2Async(
  password,
  salt = randomBytes(16),
  iterations = DEFAULT_PBKDF2_ITERATIONS,
  keylen = DEFAULT_PBKDF2_KEYLEN,
  options = DEFAULT_ENCODING
) {
  return new Promise((resolve, reject) => {
    try {
      const opts = normalizeOptions(options);
      const encoding = opts.encoding;
      assertEncoding(encoding);

      const passwordBuf = toBuffer(password, opts.inputEncoding);
      const saltBuf = toBuffer(salt, opts.saltEncoding);

      pbkdf2(passwordBuf, saltBuf, iterations, keylen, "sha512", (err, dk) => {
        if (err) return reject(err);

        resolve({
          salt: encodeOutput(saltBuf, encoding),
          hash: encodeOutput(dk, encoding),
          iterations,
          keylen,
        });
      });
    } catch (err) {
      reject(err);
    }
  });
}

export function hashPasswordScrypt(
  password,
  salt = randomBytes(16),
  keylen = DEFAULT_SCRYPT_KEYLEN,
  options = {}
) {
  const opts = normalizeOptions(options);
  const encoding = opts.encoding;
  assertEncoding(encoding);

  const passwordBuf = toBuffer(password, opts.inputEncoding);
  const saltBuf = toBuffer(salt, opts.saltEncoding);
  const dk = scryptSync(passwordBuf, saltBuf, keylen, opts.scryptOptions);

  return {
    salt: encodeOutput(saltBuf, encoding),
    hash: encodeOutput(dk, encoding),
    keylen,
  };
}

export function hashPasswordScryptAsync(
  password,
  salt = randomBytes(16),
  keylen = DEFAULT_SCRYPT_KEYLEN,
  options = {}
) {
  return new Promise((resolve, reject) => {
    try {
      const opts = normalizeOptions(options);
      const encoding = opts.encoding;
      assertEncoding(encoding);

      const passwordBuf = toBuffer(password, opts.inputEncoding);
      const saltBuf = toBuffer(salt, opts.saltEncoding);

      scrypt(passwordBuf, saltBuf, keylen, opts.scryptOptions, (err, dk) => {
        if (err) return reject(err);

        resolve({
          salt: encodeOutput(saltBuf, encoding),
          hash: encodeOutput(dk, encoding),
          keylen,
        });
      });
    } catch (err) {
      reject(err);
    }
  });
}

export function constantTimeCompare(a, b) {
  if (a == null || b == null) return false;

  const bufA = Buffer.isBuffer(a) ? a : toBuffer(a);
  const bufB = Buffer.isBuffer(b) ? b : toBuffer(b);

  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export function verifyPasswordPBKDF2(
  password,
  hash,
  salt,
  iterations = DEFAULT_PBKDF2_ITERATIONS,
  keylen = DEFAULT_PBKDF2_KEYLEN,
  options = {}
) {
  const opts = normalizeOptions(options);
  const newHash = hashPasswordPBKDF2(password, salt, iterations, keylen, {
    ...opts,
    encoding: "raw",
  });
  const compareHash =
    opts.encoding === "raw" ? toBuffer(hash) : toBuffer(hash, opts.encoding);
  return constantTimeCompare(newHash.hash, compareHash);
}

export function verifyPasswordScrypt(
  password,
  hash,
  salt,
  keylen = DEFAULT_SCRYPT_KEYLEN,
  options = {}
) {
  const opts = normalizeOptions(options);
  const newHash = hashPasswordScrypt(password, salt, keylen, {
    ...opts,
    encoding: "raw",
  });
  const compareHash =
    opts.encoding === "raw" ? toBuffer(hash) : toBuffer(hash, opts.encoding);
  return constantTimeCompare(newHash.hash, compareHash);
}

export const sha512Hex = (data) => sha512(data, "hex");
export const sha512Base64 = (data) => sha512(data, "base64");
export const sha512Base64Url = (data) => sha512(data, "base64url");
export const sha512Raw = (data) => sha512(data, "raw");
export const sha512Buffer = (data) => sha512(data, "buffer");

export const sha512HmacHex = (data, key) => sha512Hmac(data, key, "hex");
export const sha512HmacBase64 = (data, key) => sha512Hmac(data, key, "base64");
export const sha512HmacBase64Url = (data, key) =>
  sha512Hmac(data, key, "base64url");
export const sha512HmacRaw = (data, key) => sha512Hmac(data, key, "raw");

export default {
  sha512,
  sha512Async,
  sha512Hex,
  sha512Base64,
  sha512Base64Url,
  sha512Raw,
  sha512Buffer,
  sha512Hmac,
  sha512HmacAsync,
  sha512HmacHex,
  sha512HmacBase64,
  sha512HmacBase64Url,
  sha512HmacRaw,
  sha512Stream,
  sha512File,
  sha512FileSync,
  sha512Salted,
  sha512Peppered,
  sha512WithSaltPepper,
  hashPasswordPBKDF2,
  hashPasswordPBKDF2Async,
  hashPasswordScrypt,
  hashPasswordScryptAsync,
  verifyPasswordPBKDF2,
  verifyPasswordScrypt,
  constantTimeCompare,
  DEFAULT_PBKDF2_ITERATIONS,
  DEFAULT_PBKDF2_KEYLEN,
  DEFAULT_SCRYPT_KEYLEN,
};
