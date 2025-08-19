import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createSecretKey,
  getCiphers,
  hkdfSync,
  pbkdf2Sync,
  randomBytes,
  randomFillSync,
  timingSafeEqual,
} from "crypto";
import { Transform } from "stream";

const VERSION = 0x01;
const MAGIC = new TextEncoder().encode("AS256");
const MODES = { gcm: 0x01, cbc: 0x02, ctr: 0x03 };
const MODE_NAMES = { 0x01: "gcm", 0x02: "cbc", 0x03: "ctr" };
const TAG_LENGTHS = { gcm: 16, cbc: 32, ctr: 32 };

class AES256Error extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
    this.name = "AES256Error";
  }
}

const bytesToHex = (buf) =>
  buf.reduce((s, b) => s + b.toString(16).padStart(2, "0"), "");
const hexToBytes = (hex) => {
  if (hex.length % 2) throw new AES256Error("Invalid hex length", "BAD_FORMAT");
  const buf = new Uint8Array(hex.length / 2);
  for (let i = 0; i < buf.length; i++) {
    const j = i * 2;
    const byte = parseInt(hex.slice(j, j + 2), 16);
    if (isNaN(byte))
      throw new AES256Error("Invalid hex character", "BAD_FORMAT");
    buf[i] = byte;
  }
  return buf;
};

const concatUint8 = (arrays) => {
  const len = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(len);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
};

const constantTimeEq = (a, b) => {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
};

const zeroBuffer = (buf) => {
  if (buf && buf.fill) buf.fill(0);
};

const safeRandomBytes = (len) => {
  try {
    return new Uint8Array(randomBytes(len));
  } catch (e) {
    throw new AES256Error("Secure RNG unavailable", "RNG_UNAVAILABLE");
  }
};

const generateKey = (len = 32) => safeRandomBytes(len);

const deriveKeyPBKDF2 = (
  password,
  salt,
  iterations = 200000,
  hash = "sha512"
) => {
  if (iterations < 50000)
    throw new AES256Error("Iterations too low", "INVALID_ITERATIONS");
  const pwdBuf =
    typeof password === "string"
      ? new TextEncoder().encode(password)
      : password;
  return new Uint8Array(pbkdf2Sync(pwdBuf, salt, iterations, 32, hash));
};

const deriveKeyHKDF = async (ikm, salt, info, length = 32, hash = "sha256") => {
  const hkdf = hkdfSync(
    hash,
    ikm,
    salt || new Uint8Array(),
    info || new Uint8Array(),
    length
  );
  return new Uint8Array(hkdf);
};

const encrypt = async (key, plaintext, opts = {}) => {
  if (key.length !== 32)
    throw new AES256Error("Invalid key length", "INVALID_KEY");
  const mode = opts.mode || "gcm";
  const iv = opts.iv || safeRandomBytes(mode === "gcm" ? 12 : 16);
  const aad = opts.aad || new Uint8Array();
  const tagLength = opts.tagLength || TAG_LENGTHS[mode];
  let ciphertext, tag;

  if (mode === "gcm") {
    const cipher = createCipheriv("aes-256-gcm", key, iv, {
      authTagLength: tagLength,
    });
    if (aad.length) cipher.setAAD(aad);
    ciphertext = cipher.update(plaintext);
    ciphertext = concatUint8([ciphertext, cipher.final()]);
    tag = cipher.getAuthTag();
  } else {
    const encKey = await deriveKeyHKDF(
      key,
      null,
      new TextEncoder().encode(`aes256:enc`),
      32
    );
    const macKey = await deriveKeyHKDF(
      key,
      null,
      new TextEncoder().encode(`aes256:mac`),
      32
    );
    try {
      const cipher = createCipheriv(`aes-256-${mode}`, encKey, iv);
      ciphertext = cipher.update(plaintext);
      ciphertext = concatUint8([ciphertext, cipher.final()]);
      const hmac = createHmac("sha256", macKey);
      hmac.update(concatUint8([iv, ciphertext]));
      tag = hmac.digest().subarray(0, tagLength);
    } finally {
      zeroBuffer(encKey);
      zeroBuffer(macKey);
    }
  }

  const result = concatUint8([iv, ciphertext, tag]);
  if (opts.output === "hex") return bytesToHex(result);
  if (opts.output === "base64") return Buffer.from(result).toString("base64");
  return result;
};

const decrypt = async (key, ciphertext, opts = {}) => {
  if (key.length !== 32)
    throw new AES256Error("Invalid key length", "INVALID_KEY");
  const mode = opts.mode || "gcm";
  let input = ciphertext;
  if (typeof ciphertext === "string") {
    if (opts.input === "hex") input = hexToBytes(ciphertext);
    else if (opts.input === "base64")
      input = new Uint8Array(Buffer.from(ciphertext, "base64"));
    else throw new AES256Error("Invalid input encoding", "BAD_FORMAT");
  }
  const iv = opts.iv || input.subarray(0, mode === "gcm" ? 12 : 16);
  const tagLength = opts.tagLength || TAG_LENGTHS[mode];
  const ciphertextStart = iv.length;
  const ciphertextEnd = input.length - tagLength;
  if (ciphertextEnd <= ciphertextStart)
    throw new AES256Error("Invalid ciphertext length", "BAD_FORMAT");
  const encData = input.subarray(ciphertextStart, ciphertextEnd);
  const tag = input.subarray(ciphertextEnd);
  const aad = opts.aad || new Uint8Array();
  let plaintext;

  if (mode === "gcm") {
    const decipher = createDecipheriv("aes-256-gcm", key, iv, {
      authTagLength: tagLength,
    });
    if (aad.length) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    plaintext = decipher.update(encData);
    try {
      plaintext = concatUint8([plaintext, decipher.final()]);
    } catch (e) {
      throw new AES256Error("Authentication failed", "AUTH_FAILURE");
    }
  } else {
    const encKey = await deriveKeyHKDF(
      key,
      null,
      new TextEncoder().encode(`aes256:enc`),
      32
    );
    const macKey = await deriveKeyHKDF(
      key,
      null,
      new TextEncoder().encode(`aes256:mac`),
      32
    );
    try {
      const hmac = createHmac("sha256", macKey);
      hmac.update(concatUint8([iv, encData]));
      const mac = hmac.digest().subarray(0, tagLength);
      if (!constantTimeEq(mac, tag))
        throw new AES256Error("Authentication failed", "AUTH_FAILURE");
      const decipher = createDecipheriv(`aes-256-${mode}`, encKey, iv);
      plaintext = decipher.update(encData);
      plaintext = concatUint8([plaintext, decipher.final()]);
    } finally {
      zeroBuffer(encKey);
      zeroBuffer(macKey);
    }
  }
  return plaintext;
};

const encryptEnvelope = async (key, plaintext, opts = {}) => {
  const mode = opts.mode || "gcm";
  const modeByte = MODES[mode];
  const iv = opts.iv || safeRandomBytes(mode === "gcm" ? 12 : 16);
  const aad = opts.aad || new Uint8Array();
  const tagLength = opts.tagLength || TAG_LENGTHS[mode];
  let ciphertext, tag;

  if (mode === "gcm") {
    const cipher = createCipheriv("aes-256-gcm", key, iv, {
      authTagLength: tagLength,
    });
    if (aad.length) cipher.setAAD(aad);
    ciphertext = cipher.update(plaintext);
    ciphertext = concatUint8([ciphertext, cipher.final()]);
    tag = cipher.getAuthTag();
  } else {
    const encKey = await deriveKeyHKDF(
      key,
      null,
      new TextEncoder().encode(`aes256:enc`),
      32
    );
    const macKey = await deriveKeyHKDF(
      key,
      null,
      new TextEncoder().encode(`aes256:mac`),
      32
    );
    try {
      const cipher = createCipheriv(`aes-256-${mode}`, encKey, iv);
      ciphertext = cipher.update(plaintext);
      ciphertext = concatUint8([ciphertext, cipher.final()]);
      const hmac = createHmac("sha256", macKey);
      hmac.update(concatUint8([iv, ciphertext]));
      tag = hmac.digest().subarray(0, tagLength);
    } finally {
      zeroBuffer(encKey);
      zeroBuffer(macKey);
    }
  }

  const payloadLen = new Uint8Array(4);
  payloadLen[0] = (ciphertext.length >>> 24) & 0xff;
  payloadLen[1] = (ciphertext.length >>> 16) & 0xff;
  payloadLen[2] = (ciphertext.length >>> 8) & 0xff;
  payloadLen[3] = ciphertext.length & 0xff;

  const envelope = concatUint8([
    MAGIC,
    new Uint8Array([VERSION, modeByte, 0x00, iv.length]),
    iv,
    payloadLen,
    ciphertext,
    tag,
  ]);

  if (opts.output === "hex") return bytesToHex(envelope);
  if (opts.output === "base64") return Buffer.from(envelope).toString("base64");
  return envelope;
};

const decryptEnvelope = async (key, envelope, opts = {}) => {
  let input = envelope;
  if (typeof envelope === "string") {
    if (opts.input === "hex") input = hexToBytes(envelope);
    else if (opts.input === "base64")
      input = new Uint8Array(Buffer.from(envelope, "base64"));
    else throw new AES256Error("Invalid input encoding", "BAD_FORMAT");
  }

  if (input.length < 15 || !constantTimeEq(input.subarray(0, 5), MAGIC))
    throw new AES256Error("Invalid envelope", "BAD_FORMAT");
  if (input[5] !== VERSION)
    throw new AES256Error("Unsupported version", "BAD_FORMAT");
  const modeByte = input[6];
  const flags = input[7];
  const ivLen = input[8];
  let pos = 9;
  const iv = input.subarray(pos, pos + ivLen);
  pos += ivLen;
  if (pos + 4 > input.length)
    throw new AES256Error("Invalid envelope", "BAD_FORMAT");
  const payloadLen =
    (input[pos] << 24) |
    (input[pos + 1] << 16) |
    (input[pos + 2] << 8) |
    input[pos + 3];
  pos += 4;
  if (pos + payloadLen + TAG_LENGTHS[MODE_NAMES[modeByte]] > input.length)
    throw new AES256Error("Invalid payload length", "BAD_FORMAT");
  const ciphertext = input.subarray(pos, pos + payloadLen);
  pos += payloadLen;
  const tag = input.subarray(pos);

  const mode = MODE_NAMES[modeByte];
  const aad = opts.aad || new Uint8Array();
  let plaintext;

  if (mode === "gcm") {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    if (aad.length) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    plaintext = decipher.update(ciphertext);
    try {
      plaintext = concatUint8([plaintext, decipher.final()]);
    } catch (e) {
      throw new AES256Error("Authentication failed", "AUTH_FAILURE");
    }
  } else {
    const encKey = await deriveKeyHKDF(
      key,
      null,
      new TextEncoder().encode(`aes256:enc`),
      32
    );
    const macKey = await deriveKeyHKDF(
      key,
      null,
      new TextEncoder().encode(`aes256:mac`),
      32
    );
    try {
      const hmac = createHmac("sha256", macKey);
      hmac.update(concatUint8([iv, ciphertext]));
      const mac = hmac.digest().subarray(0, tag.length);
      if (!constantTimeEq(mac, tag))
        throw new AES256Error("Authentication failed", "AUTH_FAILURE");
      const decipher = createDecipheriv(`aes-256-${mode}`, encKey, iv);
      plaintext = decipher.update(ciphertext);
      plaintext = concatUint8([plaintext, decipher.final()]);
    } finally {
      zeroBuffer(encKey);
      zeroBuffer(macKey);
    }
  }
  return plaintext;
};

class EncryptStream extends Transform {
  constructor(key, opts = {}) {
    super();
    this.key = key;
    this.mode = opts.mode || "gcm";
    this.chunkSize = opts.chunkSize || 65536;
    this.iv = opts.iv || safeRandomBytes(16);
    this.chunkIndex = 0;
    this.writeHeader();
  }

  writeHeader() {
    const header = concatUint8([
      MAGIC,
      new Uint8Array([VERSION, MODES[this.mode], 0x80, this.iv.length]),
      this.iv,
      new Uint8Array(4),
    ]);
    this.push(header);
  }

  _transform(chunk, _, callback) {
    this.processChunk(chunk)
      .then((encrypted) => {
        this.push(encrypted);
        callback();
      })
      .catch(callback);
  }

  async processChunk(chunk) {
    const ivChunk = new Uint8Array(16);
    randomFillSync(ivChunk);
    const encKey = await deriveKeyHKDF(
      this.key,
      null,
      new TextEncoder().encode(`aes256:chunk`),
      32
    );
    try {
      const cipher = createCipheriv(`aes-256-${this.mode}`, encKey, ivChunk);
      const ciphertext = concatUint8([cipher.update(chunk), cipher.final()]);
      const lenBuf = new Uint8Array(4);
      lenBuf[0] = (ciphertext.length >>> 24) & 0xff;
      lenBuf[1] = (ciphertext.length >>> 16) & 0xff;
      lenBuf[2] = (ciphertext.length >>> 8) & 0xff;
      lenBuf[3] = ciphertext.length & 0xff;
      return concatUint8([lenBuf, ivChunk, ciphertext]);
    } finally {
      zeroBuffer(encKey);
    }
  }

  _flush(callback) {
    callback();
  }
}

class DecryptStream extends Transform {
  constructor(key, opts = {}) {
    super();
    this.key = key;
    this.mode = opts.mode || "gcm";
    this.buffer = new Uint8Array();
    this.headerProcessed = false;
  }

  _transform(chunk, _, callback) {
    this.buffer = concatUint8([this.buffer, chunk]);
    this.processBuffer()
      .then(() => callback())
      .catch(callback);
  }

  async processBuffer() {
    if (!this.headerProcessed && this.buffer.length >= 13) {
      if (!constantTimeEq(this.buffer.subarray(0, 5), MAGIC))
        throw new AES256Error("Invalid stream header", "BAD_FORMAT");
      if (this.buffer[5] !== VERSION)
        throw new AES256Error("Unsupported version", "BAD_FORMAT");
      const ivLen = this.buffer[8];
      if (this.buffer.length < 9 + ivLen) return;
      this.iv = this.buffer.subarray(9, 9 + ivLen);
      this.buffer = this.buffer.subarray(9 + ivLen);
      this.headerProcessed = true;
    }

    while (this.headerProcessed && this.buffer.length >= 4) {
      const len =
        (this.buffer[0] << 24) |
        (this.buffer[1] << 16) |
        (this.buffer[2] << 8) |
        this.buffer[3];
      if (this.buffer.length < 4 + 16 + len) break;
      const ivChunk = this.buffer.subarray(4, 20);
      const ciphertext = this.buffer.subarray(20, 20 + len);
      this.buffer = this.buffer.subarray(20 + len);
      const encKey = await deriveKeyHKDF(
        this.key,
        null,
        new TextEncoder().encode(`aes256:chunk`),
        32
      );
      try {
        const decipher = createDecipheriv(
          `aes-256-${this.mode}`,
          encKey,
          ivChunk
        );
        const plaintext = concatUint8([
          decipher.update(ciphertext),
          decipher.final(),
        ]);
        this.push(plaintext);
      } finally {
        zeroBuffer(encKey);
      }
    }
  }

  _flush(callback) {
    if (this.buffer.length)
      callback(new AES256Error("Incomplete stream data", "BAD_FORMAT"));
    else callback();
  }
}

const encryptStream = (key, opts) => new EncryptStream(key, opts);
const decryptStream = (key, opts) => new DecryptStream(key, opts);

const wrapKeyRFC3394 = (kwKey, keyToWrap) => {
  if (kwKey.length !== 32)
    throw new AES256Error("Invalid key length", "INVALID_KEY");
  if (keyToWrap.length % 8 !== 0)
    throw new AES256Error("Key length not multiple of 8", "BAD_FORMAT");
  const cipher = createCipheriv("id-aes256-wrap", kwKey, Buffer.alloc(8, 0xa6));
  return concatUint8([cipher.update(keyToWrap), cipher.final()]);
};

const unwrapKeyRFC3394 = (kwKey, wrapped) => {
  if (kwKey.length !== 32)
    throw new AES256Error("Invalid key length", "INVALID_KEY");
  if (wrapped.length % 8 !== 0)
    throw new AES256Error("Wrapped key length not multiple of 8", "BAD_FORMAT");
  const decipher = createDecipheriv(
    "id-aes256-wrap",
    kwKey,
    Buffer.alloc(8, 0xa6)
  );
  const key = concatUint8([decipher.update(wrapped), decipher.final()]);
  return key;
};

const exportRawKey = (key, format = "hex") => {
  if (key.length !== 32)
    throw new AES256Error("Invalid key length", "INVALID_KEY");
  if (format === "hex") return bytesToHex(key);
  if (format === "base64") return Buffer.from(key).toString("base64");
  throw new AES256Error("Invalid format", "BAD_FORMAT");
};

const importRawKey = (keyData, format = "hex") => {
  let key;
  if (format === "hex") key = hexToBytes(keyData);
  else if (format === "base64")
    key = new Uint8Array(Buffer.from(keyData, "base64"));
  else throw new AES256Error("Invalid format", "BAD_FORMAT");
  if (key.length !== 32)
    throw new AES256Error("Invalid key length", "INVALID_KEY");
  return key;
};

const Benchmark = async (sizeMB = 4) => {
  const key = generateKey();
  const data = safeRandomBytes(sizeMB * 1024 * 1024);
  const results = {};

  const run = async (mode) => {
    const start = process.hrtime.bigint();
    await encrypt(key, data, { mode });
    const end = process.hrtime.bigint();
    return Number(end - start) / 1e9;
  };

  results.gcm = sizeMB / (await run("gcm"));
  results.cbc = sizeMB / (await run("cbc"));
  results.ctr = sizeMB / (await run("ctr"));
  return results;
};

const selfTest = async () => {
  const key = hexToBytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  );
  const plaintext = hexToBytes("00112233445566778899aabbccddeeff");
  const ciphertext = await encrypt(key, plaintext, {
    mode: "gcm",
    iv: new Uint8Array(12),
  });
  const decrypted = await decrypt(key, ciphertext, { mode: "gcm" });
  if (!constantTimeEq(plaintext, decrypted))
    throw new AES256Error("GCM self-test failed", "SELF_TEST_FAIL");

  const pbkdf2Key = deriveKeyPBKDF2(
    "password",
    new Uint8Array(16),
    1,
    "sha256"
  );
  if (
    bytesToHex(pbkdf2Key) !==
    "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
  )
    throw new AES256Error("PBKDF2 self-test failed", "SELF_TEST_FAIL");

  const kwKey = hexToBytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  );
  const keyToWrap = hexToBytes("00112233445566778899aabbccddeeff");
  const wrapped = wrapKeyRFC3394(kwKey, keyToWrap);
  const unwrapped = unwrapKeyRFC3394(kwKey, wrapped);
  if (!constantTimeEq(keyToWrap, unwrapped))
    throw new AES256Error("Key wrap self-test failed", "SELF_TEST_FAIL");
};

if (process.argv[1] === import.meta.url) {
  (async () => {
    try {
      await selfTest();
      console.log("selfTest: OK");
      const bench = await Benchmark();
      console.log(JSON.stringify(bench));
      process.exit(0);
    } catch (e) {
      console.error("selfTest: FAIL", e.message);
      process.exit(1);
    }
  })();
}

export {
  AES256Error,
  encrypt,
  decrypt,
  encryptEnvelope,
  decryptEnvelope,
  encryptStream,
  decryptStream,
  generateKey,
  deriveKeyPBKDF2,
  deriveKeyHKDF,
  wrapKeyRFC3394,
  unwrapKeyRFC3394,
  exportRawKey,
  importRawKey,
  bytesToHex,
  hexToBytes,
  concatUint8,
  constantTimeEq,
  zeroBuffer,
  selfTest,
  Benchmark,
};

export default {
  encrypt,
  decrypt,
  encryptEnvelope,
  decryptEnvelope,
  encryptStream,
  decryptStream,
  generateKey,
  deriveKeyPBKDF2,
  deriveKeyHKDF,
  wrapKeyRFC3394,
  unwrapKeyRFC3394,
  exportRawKey,
  importRawKey,
  bytesToHex,
  hexToBytes,
  concatUint8,
  constantTimeEq,
  zeroBuffer,
  selfTest,
  Benchmark,
};
