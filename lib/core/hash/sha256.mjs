// sha256.mjs
// Robust, cross-runtime SHA-256 utility (Node.js + Browser fallback)
// Exports async-first APIs; sync APIs available when running under Node.

const isNode = typeof process !== "undefined" && !!process.versions?.node;
const hasWebCrypto = typeof globalThis?.crypto?.subtle !== "undefined";

let nodeCrypto = null;
let fs = null;
let fsPromises = null;
let streamPromises = null;

if (isNode) {
  // top-level await is used intentionally so imports only happen in Node environment
  nodeCrypto = await import("node:crypto");
  fs = await import("node:fs");
  fsPromises = await import("node:fs/promises");
  streamPromises = await import("node:stream/promises");
}

const TEXT_ENCODER =
  typeof TextEncoder !== "undefined" ? new TextEncoder() : null;
const TEXT_DECODER =
  typeof TextDecoder !== "undefined" ? new TextDecoder() : null;

const DEFAULT_PBKDF2_ITER = 100000;
const DEFAULT_PBKDF2_KEYLEN = 32;

function assertNode(feature) {
  if (!isNode)
    throw new Error(`${feature} is only available in Node.js environment`);
}

function normalizeEncoding(enc = "hex") {
  const e = String(enc || "").toLowerCase();
  if (e === "base64url") return "base64url";
  if (e === "base64") return "base64";
  if (e === "hex") return "hex";
  if (e === "latin1" || e === "binary") return "latin1";
  if (e === "raw" || e === "buffer" || e === "uint8array") return "raw";
  throw new TypeError(`Unsupported encoding: ${enc}`);
}

function toUint8Array(input, inputEncoding = "utf8") {
  if (input == null) return new Uint8Array();
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input))
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(input))
    return new Uint8Array(input);
  if (typeof input === "string") {
    if (inputEncoding === "utf8") {
      if (!TEXT_ENCODER) throw new Error("TextEncoder not available");
      return TEXT_ENCODER.encode(input);
    }
    // support hex/base64 input strings
    const enc = inputEncoding.toLowerCase();
    if (enc === "hex") return Uint8Array.from(Buffer.from(input, "hex"));
    if (enc === "base64") return Uint8Array.from(Buffer.from(input, "base64"));
    if (enc === "latin1" || enc === "binary")
      return Uint8Array.from(Buffer.from(input, "latin1"));
    // fallback to utf8
    if (!TEXT_ENCODER) throw new Error("TextEncoder not available");
    return TEXT_ENCODER.encode(input);
  }
  throw new TypeError(
    "Unsupported input type (expected string/Buffer/ArrayBuffer/TypedArray)"
  );
}

function uint8ToBuffer(u8) {
  return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength);
}

function bufferToUint8(buf) {
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

function toOutput(bufU8, encoding = "hex", returnType = "string") {
  const enc = normalizeEncoding(encoding);
  const ret = (returnType || "string").toLowerCase();
  if (enc === "raw") {
    if (ret === "buffer") return uint8ToBuffer(bufU8);
    return bufferToUint8(uint8ToBuffer(bufU8));
  }
  // string encodings
  if (ret === "buffer") {
    if (typeof Buffer === "undefined") throw new Error("Buffer not available");
    if (enc === "base64url") {
      const b = Buffer.from(bufU8);
      return Buffer.from(
        b
          .toString("base64")
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, ""),
        "utf8"
      );
    }
    return Buffer.from(bufU8).toString(enc);
  }
  // default string
  if (enc === "base64url") {
    const b = Buffer.from(bufU8);
    return b
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }
  return Buffer.from(bufU8).toString(enc);
}

function constantTimeCompare(a, b) {
  // accepts Uint8Array | Buffer | string (string will be utf8 encoded)
  const ua =
    typeof a === "string"
      ? toUint8Array(a)
      : a instanceof Uint8Array
      ? a
      : toUint8Array(a);
  const ub =
    typeof b === "string"
      ? toUint8Array(b)
      : b instanceof Uint8Array
      ? b
      : toUint8Array(b);
  if (ua.length !== ub.length) return false;
  if (isNode && nodeCrypto?.timingSafeEqual) {
    return nodeCrypto.timingSafeEqual(uint8ToBuffer(ua), uint8ToBuffer(ub));
  }
  // manual constant-time comparison
  let diff = 0;
  for (let i = 0; i < ua.length; i++) diff |= ua[i] ^ ub[i];
  return diff === 0;
}

// ---------- Core hashing ----------

export async function sha256Async(
  data,
  { encoding = "hex", inputEncoding = "utf8", returnType = "string" } = {}
) {
  const enc = normalizeEncoding(encoding);
  const u8 = toUint8Array(data, inputEncoding);
  // prefer Node fast path
  if (isNode) {
    const hash = nodeCrypto
      .createHash("sha256")
      .update(uint8ToBuffer(u8))
      .digest();
    return toOutput(
      new Uint8Array(hash.buffer, hash.byteOffset, hash.byteLength),
      enc,
      returnType
    );
  }
  if (!hasWebCrypto) throw new Error("No crypto available in this environment");
  const digest = await crypto.subtle.digest("SHA-256", u8);
  return toOutput(new Uint8Array(digest), enc, returnType);
}

export function sha256(
  data,
  { encoding = "hex", inputEncoding = "utf8", returnType = "string" } = {}
) {
  // synchronous version — only available in Node
  assertNode("sha256 (sync)");
  const enc = normalizeEncoding(encoding);
  const u8 = toUint8Array(data, inputEncoding);
  const hashBuf = nodeCrypto
    .createHash("sha256")
    .update(uint8ToBuffer(u8))
    .digest();
  return toOutput(
    new Uint8Array(hashBuf.buffer, hashBuf.byteOffset, hashBuf.byteLength),
    enc,
    returnType
  );
}

// ---------- HMAC ----------

export async function hmacSha256Async(
  data,
  key,
  {
    encoding = "hex",
    inputEncoding = "utf8",
    keyEncoding = "utf8",
    returnType = "string",
  } = {}
) {
  const enc = normalizeEncoding(encoding);
  const u8data = toUint8Array(data, inputEncoding);
  const u8key = toUint8Array(key, keyEncoding);

  if (isNode) {
    const h = nodeCrypto
      .createHmac("sha256", uint8ToBuffer(u8key))
      .update(uint8ToBuffer(u8data))
      .digest();
    return toOutput(
      new Uint8Array(h.buffer, h.byteOffset, h.byteLength),
      enc,
      returnType
    );
  }
  if (!hasWebCrypto) throw new Error("No crypto available in this environment");
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    u8key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, u8data);
  return toOutput(new Uint8Array(sig), enc, returnType);
}

export function hmacSha256(
  data,
  key,
  {
    encoding = "hex",
    inputEncoding = "utf8",
    keyEncoding = "utf8",
    returnType = "string",
  } = {}
) {
  assertNode("hmacSha256 (sync)");
  const enc = normalizeEncoding(encoding);
  const u8data = toUint8Array(data, inputEncoding);
  const u8key = toUint8Array(key, keyEncoding);
  const hm = nodeCrypto
    .createHmac("sha256", uint8ToBuffer(u8key))
    .update(uint8ToBuffer(u8data))
    .digest();
  return toOutput(
    new Uint8Array(hm.buffer, hm.byteOffset, hm.byteLength),
    enc,
    returnType
  );
}

// ---------- Streams & files (Node only) ----------

export async function sha256File(
  path,
  { encoding = "hex", returnType = "string" } = {}
) {
  assertNode("sha256File");
  const enc = normalizeEncoding(encoding);
  await fsPromises.access(path).catch(() => {
    throw new Error(`File not found: ${path}`);
  });
  const hash = nodeCrypto.createHash("sha256");
  const rs = fs.createReadStream(path);
  await streamPromises.pipeline(rs, hash);
  const dig = hash.digest();
  return toOutput(
    new Uint8Array(dig.buffer, dig.byteOffset, dig.byteLength),
    enc,
    returnType
  );
}

export async function sha256Stream(
  readable,
  { encoding = "hex", returnType = "string" } = {}
) {
  assertNode("sha256Stream");
  const enc = normalizeEncoding(encoding);
  const hash = nodeCrypto.createHash("sha256");
  await streamPromises.pipeline(readable, hash);
  const dig = hash.digest();
  return toOutput(
    new Uint8Array(dig.buffer, dig.byteOffset, dig.byteLength),
    enc,
    returnType
  );
}

// ---------- PBKDF2 (async + sync) ----------

export function pbkdf2Sync(
  password,
  salt,
  iterations = DEFAULT_PBKDF2_ITER,
  keylen = DEFAULT_PBKDF2_KEYLEN,
  digest = "sha256",
  {
    inputEncoding = "utf8",
    saltEncoding = "utf8",
    encoding = "hex",
    returnType = "string",
  } = {}
) {
  assertNode("pbkdf2Sync");
  const enc = normalizeEncoding(encoding);
  const passU8 = toUint8Array(password, inputEncoding);
  const saltU8 = toUint8Array(salt, saltEncoding);
  const key = nodeCrypto.pbkdf2Sync(
    uint8ToBuffer(passU8),
    uint8ToBuffer(saltU8),
    iterations,
    keylen,
    digest
  );
  return toOutput(
    new Uint8Array(key.buffer, key.byteOffset, key.byteLength),
    enc,
    returnType
  );
}

export function pbkdf2(
  password,
  salt,
  iterations = DEFAULT_PBKDF2_ITER,
  keylen = DEFAULT_PBKDF2_KEYLEN,
  digest = "sha256",
  {
    inputEncoding = "utf8",
    saltEncoding = "utf8",
    encoding = "hex",
    returnType = "string",
  } = {}
) {
  // async pbkdf2: use Node native or WebCrypto PBKDF2
  const enc = normalizeEncoding(encoding);
  const passU8 = toUint8Array(password, inputEncoding);
  const saltU8 = toUint8Array(salt, saltEncoding);
  if (isNode) {
    return new Promise((resolve, reject) => {
      nodeCrypto.pbkdf2(
        uint8ToBuffer(passU8),
        uint8ToBuffer(saltU8),
        iterations,
        keylen,
        digest,
        (err, derivedKey) => {
          if (err) return reject(err);
          resolve(
            toOutput(
              new Uint8Array(
                derivedKey.buffer,
                derivedKey.byteOffset,
                derivedKey.byteLength
              ),
              enc,
              returnType
            )
          );
        }
      );
    });
  }
  if (!hasWebCrypto) return Promise.reject(new Error("No crypto available"));
  // WebCrypto PBKDF2
  return (async () => {
    const alg = { name: "PBKDF2" };
    const baseKey = await crypto.subtle.importKey("raw", passU8, alg, false, [
      "deriveBits",
    ]);
    const derived = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltU8, iterations, hash: { name: "SHA-256" } },
      baseKey,
      keylen * 8
    );
    return toOutput(new Uint8Array(derived), enc, returnType);
  })();
}

// ---------- scrypt (Node only) ----------

export function scryptSync(
  password,
  salt,
  keylen = 64,
  options = {},
  {
    inputEncoding = "utf8",
    saltEncoding = "utf8",
    encoding = "hex",
    returnType = "string",
  } = {}
) {
  assertNode("scryptSync");
  if (!nodeCrypto.scryptSync)
    throw new Error("scryptSync not available in this Node version");
  const enc = normalizeEncoding(encoding);
  const passU8 = toUint8Array(password, inputEncoding);
  const saltU8 = toUint8Array(salt, saltEncoding);
  const key = nodeCrypto.scryptSync(
    uint8ToBuffer(passU8),
    uint8ToBuffer(saltU8),
    keylen,
    options
  );
  return toOutput(
    new Uint8Array(key.buffer, key.byteOffset, key.byteLength),
    enc,
    returnType
  );
}

export function scrypt(
  password,
  salt,
  keylen = 64,
  options = {},
  {
    inputEncoding = "utf8",
    saltEncoding = "utf8",
    encoding = "hex",
    returnType = "string",
  } = {}
) {
  assertNode("scrypt (async)");
  if (!nodeCrypto.scrypt)
    return Promise.reject(
      new Error("scrypt not available in this Node version")
    );
  const enc = normalizeEncoding(encoding);
  const passU8 = toUint8Array(password, inputEncoding);
  const saltU8 = toUint8Array(salt, saltEncoding);
  return new Promise((resolve, reject) => {
    nodeCrypto.scrypt(
      uint8ToBuffer(passU8),
      uint8ToBuffer(saltU8),
      keylen,
      options,
      (err, derived) => {
        if (err) return reject(err);
        resolve(
          toOutput(
            new Uint8Array(
              derived.buffer,
              derived.byteOffset,
              derived.byteLength
            ),
            enc,
            returnType
          )
        );
      }
    );
  });
}

// ---------- Password helpers (PBKDF2 default, optional scrypt) ----------

export async function passwordHash(
  password,
  {
    salt,
    pepper = "",
    algorithm = "pbkdf2",
    iterations = DEFAULT_PBKDF2_ITER,
    keylen = DEFAULT_PBKDF2_KEYLEN,
    digest = "sha256",
    scryptOptions = {},
    encoding = "hex",
    inputEncoding = "utf8",
    saltEncoding = "utf8",
    returnType = "string",
  } = {}
) {
  if (!salt) throw new TypeError("Salt is required");
  const enc = normalizeEncoding(encoding);
  const pwd = toUint8Array(password, inputEncoding);
  const combined = pepper
    ? new Uint8Array([...pwd, ...toUint8Array(pepper, "utf8")])
    : pwd;
  if (algorithm === "scrypt") {
    // scrypt only in Node
    assertNode("scrypt passwordHash");
    const res = await scrypt(combined, salt, keylen, scryptOptions, {
      inputEncoding: "utf8",
      saltEncoding,
      encoding,
      returnType,
    });
    return res;
  }
  // default pbkdf2
  return await pbkdf2(combined, salt, iterations, keylen, digest, {
    inputEncoding: "raw",
    saltEncoding,
    encoding,
    returnType,
  });
}

export async function passwordVerify(
  password,
  expectedHash,
  {
    salt,
    pepper = "",
    algorithm = "pbkdf2",
    iterations = DEFAULT_PBKDF2_ITER,
    keylen = DEFAULT_PBKDF2_KEYLEN,
    digest = "sha256",
    scryptOptions = {},
    encoding = "hex",
    inputEncoding = "utf8",
    saltEncoding = "utf8",
  } = {}
) {
  if (!salt) throw new TypeError("Salt is required");
  const enc = normalizeEncoding(encoding);
  const pwd = toUint8Array(password, inputEncoding);
  const combined = pepper
    ? new Uint8Array([...pwd, ...toUint8Array(pepper, "utf8")])
    : pwd;
  let derived;
  if (algorithm === "scrypt") {
    assertNode("scrypt passwordVerify");
    derived = await scrypt(combined, salt, keylen, scryptOptions, {
      inputEncoding: "raw",
      saltEncoding,
      encoding: "raw",
      returnType: "raw",
    });
  } else {
    derived = await pbkdf2(combined, salt, iterations, keylen, digest, {
      inputEncoding: "raw",
      saltEncoding,
      encoding: "raw",
      returnType: "raw",
    });
  }
  const expectU8 =
    normalizeEncoding(encoding) === "raw"
      ? toUint8Array(expectedHash)
      : toUint8Array(expectedHash, encoding);
  const derivedU8 =
    derived instanceof Uint8Array ? derived : toUint8Array(derived, "raw");
  return constantTimeCompare(derivedU8, expectU8);
}

// ---------- Utility wrappers / sugar ----------

export const sha256HexAsync = (data, opts = {}) =>
  sha256Async(data, { ...opts, encoding: "hex" });
export const sha256Base64Async = (data, opts = {}) =>
  sha256Async(data, { ...opts, encoding: "base64" });
export const sha256RawAsync = (data, opts = {}) =>
  sha256Async(data, { ...opts, encoding: "raw", returnType: "buffer" });

export const sha256Hex = (data, opts = {}) =>
  sha256(data, { ...opts, encoding: "hex" });
export const sha256Base64 = (data, opts = {}) =>
  sha256(data, { ...opts, encoding: "base64" });
export const sha256Raw = (data, opts = {}) =>
  sha256(data, { ...opts, encoding: "raw", returnType: "buffer" });

export const hmacSha256HexAsync = (data, key, opts = {}) =>
  hmacSha256Async(data, key, { ...opts, encoding: "hex" });
export const hmacSha256Base64Async = (data, key, opts = {}) =>
  hmacSha256Async(data, key, { ...opts, encoding: "base64" });
export const hmacSha256Hex = (data, key, opts = {}) =>
  hmacSha256(data, key, { ...opts, encoding: "hex" });
export const hmacSha256Base64 = (data, key, opts = {}) =>
  hmacSha256(data, key, { ...opts, encoding: "base64" });

export function salted(
  data,
  salt,
  {
    encoding = "hex",
    inputEncoding = "utf8",
    saltEncoding = "utf8",
    returnType = "string",
  } = {}
) {
  const u8 = toUint8Array(data, inputEncoding);
  const s8 = toUint8Array(salt, saltEncoding);
  const comb = new Uint8Array(s8.length + u8.length);
  comb.set(s8, 0);
  comb.set(u8, s8.length);
  // prefer sync
  if (isNode) {
    const h = nodeCrypto
      .createHash("sha256")
      .update(uint8ToBuffer(comb))
      .digest();
    return toOutput(
      new Uint8Array(h.buffer, h.byteOffset, h.byteLength),
      normalizeEncoding(encoding),
      returnType
    );
  }
  // fallback: use subtle (sync not available) — provide async alternative
  throw new Error(
    "salted (sync) is only available in Node; use saltedAsync for browser"
  );
}

export async function saltedAsync(
  data,
  salt,
  {
    encoding = "hex",
    inputEncoding = "utf8",
    saltEncoding = "utf8",
    returnType = "string",
  } = {}
) {
  const u8 = toUint8Array(data, inputEncoding);
  const s8 = toUint8Array(salt, saltEncoding);
  const comb = new Uint8Array(s8.length + u8.length);
  comb.set(s8, 0);
  comb.set(u8, s8.length);
  return sha256Async(comb, { encoding, inputEncoding: "raw", returnType });
}

export function peppered(
  data,
  pepper,
  {
    encoding = "hex",
    inputEncoding = "utf8",
    pepperEncoding = "utf8",
    returnType = "string",
  } = {}
) {
  const u8 = toUint8Array(data, inputEncoding);
  const p8 = toUint8Array(pepper, pepperEncoding);
  const comb = new Uint8Array(u8.length + p8.length);
  comb.set(u8, 0);
  comb.set(p8, u8.length);
  if (isNode) {
    const h = nodeCrypto
      .createHash("sha256")
      .update(uint8ToBuffer(comb))
      .digest();
    return toOutput(
      new Uint8Array(h.buffer, h.byteOffset, h.byteLength),
      normalizeEncoding(encoding),
      returnType
    );
  }
  throw new Error(
    "peppered (sync) is only available in Node; use pepperedAsync for browser"
  );
}

export async function pepperedAsync(
  data,
  pepper,
  {
    encoding = "hex",
    inputEncoding = "utf8",
    pepperEncoding = "utf8",
    returnType = "string",
  } = {}
) {
  const u8 = toUint8Array(data, inputEncoding);
  const p8 = toUint8Array(pepper, pepperEncoding);
  const comb = new Uint8Array(u8.length + p8.length);
  comb.set(u8, 0);
  comb.set(p8, u8.length);
  return sha256Async(comb, { encoding, inputEncoding: "raw", returnType });
}

export function verifyHmac(
  data,
  key,
  signature,
  {
    signatureEncoding = "hex",
    inputEncoding = "utf8",
    keyEncoding = "utf8",
  } = {}
) {
  // sync verify only in Node
  assertNode("verifyHmac (sync)");
  const got = hmacSha256(data, key, {
    encoding: signatureEncoding,
    inputEncoding,
    keyEncoding,
    returnType: "buffer",
  });
  const expect =
    signatureEncoding === "raw"
      ? toUint8Array(signature)
      : toUint8Array(signature, signatureEncoding);
  return constantTimeCompare(got, expect);
}

export async function verifyHmacAsync(
  data,
  key,
  signature,
  {
    signatureEncoding = "hex",
    inputEncoding = "utf8",
    keyEncoding = "utf8",
  } = {}
) {
  const got = await hmacSha256Async(data, key, {
    encoding: signatureEncoding,
    inputEncoding,
    keyEncoding,
    returnType: "raw",
  });
  const expect =
    signatureEncoding === "raw"
      ? toUint8Array(signature)
      : toUint8Array(signature, signatureEncoding);
  return constantTimeCompare(got, expect);
}

// ---------- Exports default object ----------

const api = {
  // core
  sha256,
  sha256Async,
  sha256Hex,
  sha256HexAsync,
  sha256Base64,
  sha256Base64Async,
  sha256Raw,
  sha256RawAsync,

  // hmac
  hmacSha256,
  hmacSha256Async,
  hmacSha256Hex: hmacSha256,
  hmacSha256HexAsync: hmacSha256Async,
  hmacSha256Base64: (d, k, o) => hmacSha256(d, k, { ...o, encoding: "base64" }),
  hmacSha256Base64Async: (d, k, o) =>
    hmacSha256Async(d, k, { ...o, encoding: "base64" }),

  // files & streams
  sha256File,
  sha256Stream,

  // pbkdf2 & scrypt
  pbkdf2,
  pbkdf2Sync,
  scrypt,
  scryptSync,

  // password helpers
  passwordHash,
  passwordVerify,

  // salted/peppered
  salted,
  saltedAsync,
  peppered,
  pepperedAsync,

  // verify
  verifyHmac,
  verifyHmacAsync,

  // utils
  constantTimeCompare,
  normalizeEncoding,
  toUint8Array,
  toOutput,
};

export default api;
