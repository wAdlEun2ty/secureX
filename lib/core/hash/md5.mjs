// md5.mjs
import { createHash, createHmac, timingSafeEqual } from "crypto";
import { pipeline as pipelineProm } from "stream/promises";
import { createReadStream, readFileSync } from "fs";
import { access } from "fs/promises";
import { constants } from "fs";

const DEFAULT_ENCODING = "hex";
const VALID_ENCODINGS = new Set(["hex", "base64", "latin1", "base64url", "raw"]);
const MD5_HEX_LENGTH = 32;

function assertEncoding(enc) {
  if (!VALID_ENCODINGS.has(enc)) {
    throw new TypeError(`Invalid encoding "${enc}". Supported: ${[...VALID_ENCODINGS].join(", ")}`);
  }
}

function toBuffer(input, inputEncoding = "utf8") {
  if (input == null) throw new TypeError("Input is required");
  if (Buffer.isBuffer(input)) return input;
  if (typeof input === "string") return Buffer.from(input, inputEncoding);
  if (input instanceof ArrayBuffer) return Buffer.from(input);
  if (ArrayBuffer.isView(input)) return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  throw new TypeError("Unsupported input type");
}

function toStringFromBuffer(buf, encoding) {
  if (encoding === "raw") return buf;
  if (encoding === "base64url") {
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  return buf.toString(encoding);
}

function normalizeEncoding(enc = DEFAULT_ENCODING) {
  const e = String(enc || "").toLowerCase();
  if (e === "base64url") return "base64url";
  if (e === "raw" || e === "buffer") return "raw";
  if (VALID_ENCODINGS.has(e)) return e;
  throw new TypeError(`Unsupported encoding: ${enc}`);
}

function normalizeOptions(options, defaultEncoding = DEFAULT_ENCODING) {
  if (typeof options === "string") return { encoding: options };
  return { encoding: defaultEncoding, ...options };
}

export function md5(data, options = DEFAULT_ENCODING) {
  const opts = normalizeOptions(options);
  const encoding = normalizeEncoding(opts.encoding);
  assertEncoding(encoding);
  const buf = toBuffer(data, opts.inputEncoding);
  const dig = createHash("md5").update(buf).digest();
  return encoding === "raw" ? dig : toStringFromBuffer(dig, encoding);
}

export function md5Buffer(data) {
  const buf = toBuffer(data);
  return createHash("md5").update(buf).digest();
}

export function md5Hmac(data, key, options = DEFAULT_ENCODING) {
  if (key == null) throw new TypeError("Key is required for HMAC");
  const opts = normalizeOptions(options);
  const encoding = normalizeEncoding(opts.encoding);
  assertEncoding(encoding);
  const dataBuf = toBuffer(data, opts.inputEncoding);
  const keyBuf = toBuffer(key, opts.keyEncoding);
  const dig = createHmac("md5", keyBuf).update(dataBuf).digest();
  return encoding === "raw" ? dig : toStringFromBuffer(dig, encoding);
}

export async function md5Stream(stream, options = {}) {
  const opts = normalizeOptions(options);
  const encoding = normalizeEncoding(opts.encoding);
  assertEncoding(encoding);
  
  if (!stream || typeof stream[Symbol.asyncIterator] !== "function") {
    throw new TypeError("Stream must be a readable async iterable");
  }

  const signal = opts.signal;
  if (signal?.aborted) throw new Error("Operation aborted");

  const hash = createHash("md5");
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
  return encoding === "raw" ? dig : toStringFromBuffer(dig, encoding);
}

export async function md5StreamBuffer(stream, options = {}) {
  return md5Stream(stream, { ...options, encoding: "raw" });
}

export async function md5File(path, options = {}) {
  if (typeof path !== "string") throw new TypeError("Path must be a string");
  await access(path, constants.R_OK);
  
  const rs = createReadStream(path);
  const cleanup = () => {
    if (!rs.destroyed) rs.destroy();
  };
  
  try {
    return await md5Stream(rs, options);
  } finally {
    cleanup();
  }
}

export async function md5FileBuffer(path, options = {}) {
  return md5File(path, { ...options, encoding: "raw" });
}

export function md5FileSync(path, options = DEFAULT_ENCODING) {
  if (typeof path !== "string") throw new TypeError("Path must be a string");
  const opts = normalizeOptions(options);
  const encoding = normalizeEncoding(opts.encoding);
  assertEncoding(encoding);
  const buf = readFileSync(path);
  const dig = createHash("md5").update(buf).digest();
  return encoding === "raw" ? dig : toStringFromBuffer(dig, encoding);
}

export function isValidMd5(digest) {
  return typeof digest === "string" && /^[a-f0-9]{32}$/i.test(digest);
}

export function compareMd5Hex(a, b) {
  if (!isValidMd5(a) || !isValidMd5(b)) return false;
  const bufA = Buffer.from(a, "hex");
  const bufB = Buffer.from(b, "hex");
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

export function constantTimeCompare(a, b) {
  if (a == null || b == null) return false;
  
  if (typeof a === "string" && typeof b === "string") {
    if (isValidMd5(a) && isValidMd5(b)) return compareMd5Hex(a, b);
    const bufA = Buffer.from(a, "utf8");
    const bufB = Buffer.from(b, "utf8");
    return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
  }
  
  const bufA = Buffer.isBuffer(a) ? a : Buffer.from(a);
  const bufB = Buffer.isBuffer(b) ? b : Buffer.from(b);
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

export const md5Hex = (data) => md5(data, "hex");
export const md5Base64 = (data) => md5(data, "base64");
export const md5Base64Url = (data) => md5(data, "base64url");
export const md5Raw = (data) => md5(data, "raw");

export const md5HmacHex = (data, key) => md5Hmac(data, key, "hex");
export const md5HmacBase64 = (data, key) => md5Hmac(data, key, "base64");
export const md5HmacRaw = (data, key) => md5Hmac(data, key, "raw");

export default {
  md5,
  md5Buffer,
  md5Hex,
  md5Base64,
  md5Base64Url,
  md5Raw,
  md5Hmac,
  md5HmacHex,
  md5HmacBase64,
  md5HmacRaw,
  md5Stream,
  md5StreamBuffer,
  md5File,
  md5FileBuffer,
  md5FileSync,
  isValidMd5,
  compareMd5Hex,
  constantTimeCompare
};