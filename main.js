"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => PrivateSyncPlugin
});
module.exports = __toCommonJS(main_exports);
var import_obsidian18 = require("obsidian");

// src/api/client.ts
var import_obsidian = require("obsidian");

// src/utils/validate.ts
var ProtocolValueError = class extends Error {
  constructor(field, got, where) {
    super(
      `Invalid protocol field: ${field}=${describe(got)}${where ? `\uFF08${where}\uFF09` : ""} — this operation was stopped; truncated or forged values are never used`
    );
    this.field = field;
    this.got = got;
    this.where = where;
    this.name = "ProtocolValueError";
  }
};
function describe(v) {
  if (typeof v === "string") return v.length > 48 ? `"${v.slice(0, 48)}\u2026"` : `"${v}"`;
  if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint") return String(v);
  if (v === void 0) return "undefined";
  if (v === null) return "null";
  return `<${typeof v}>`;
}
var FILE_ID_RE = /^[0-9a-f]{32}$/;
var KEY_EPOCH_MIN = 1;
var KEY_EPOCH_MAX_EXCLUSIVE = 4294967296;
var GENERATION_MAX = Number.MAX_SAFE_INTEGER;
function isFileId(v) {
  return typeof v === "string" && FILE_ID_RE.test(v);
}
function isKeyEpoch(v) {
  return typeof v === "number" && Number.isInteger(v) && v >= KEY_EPOCH_MIN && v < KEY_EPOCH_MAX_EXCLUSIVE;
}
function isGeneration(v) {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= GENERATION_MAX;
}
function requireFileId(v, where) {
  if (!isFileId(v)) throw new ProtocolValueError("fileId", v, where);
  return v;
}
function requireKeyEpoch(v, where) {
  if (!isKeyEpoch(v)) throw new ProtocolValueError("keyEpoch", v, where);
  return v;
}
function requireGeneration(v, where) {
  if (!isGeneration(v)) throw new ProtocolValueError("generation", v, where);
  return v;
}
function optionalFileId(v, where) {
  if (v === void 0 || v === null || v === "") return void 0;
  return requireFileId(v, where);
}
function optionalGeneration(v, where) {
  if (v === void 0 || v === null) return void 0;
  return requireGeneration(v, where);
}

// src/crypto/padding.ts
var MIN_BUCKET = 4096;
var STEPS_PER_OCTAVE = 8;
var MAX_PADDED_LENGTH = 2 ** 40;
function bucketSize(n) {
  if (!Number.isFinite(n) || n < 0) throw new RangeError(`bucketSize: invalid length ${n}`);
  if (n > MAX_PADDED_LENGTH) throw new RangeError(`bucketSize: over the padding limit ${n}`);
  if (n <= MIN_BUCKET) return MIN_BUCKET;
  const octave = Math.floor(Math.log2(n));
  const step = 2 ** octave / STEPS_PER_OCTAVE;
  const bucket = Math.ceil(n / step) * step;
  return bucket < n ? bucket + step : bucket;
}
var FRAME_HEADER_LEN = 8;
function frame(content, padded) {
  const len = content.byteLength;
  if (len > MAX_PADDED_LENGTH) throw new RangeError(`frame: content too large ${len}`);
  const total = padded ? bucketSize(len + FRAME_HEADER_LEN) : len + FRAME_HEADER_LEN;
  const out = new Uint8Array(total);
  new DataView(out.buffer).setBigUint64(0, BigInt(len), false);
  out.set(new Uint8Array(content), FRAME_HEADER_LEN);
  return out.buffer;
}
function unframe(framed) {
  if (framed.byteLength < FRAME_HEADER_LEN) return null;
  const len = new DataView(framed).getBigUint64(0, false);
  if (len > BigInt(MAX_PADDED_LENGTH)) return null;
  const n = Number(len);
  if (FRAME_HEADER_LEN + n > framed.byteLength) return null;
  return framed.slice(FRAME_HEADER_LEN, FRAME_HEADER_LEN + n);
}

// src/crypto/crypto.ts
var KDF_ITERATIONS = 6e5;
var MAGIC = new Uint8Array([76, 83, 69, 49]);
var MAGIC2 = new Uint8Array([76, 83, 69, 50]);
var MAGIC3 = new Uint8Array([76, 83, 69, 51]);
var MAGIC4 = new Uint8Array([76, 83, 69, 52]);
var FLAGS_LEN = 1;
var LSE4_FLAG_PADDED = 1;
var IV_LEN = 12;
var EPOCH_LEN = 4;
var GEN_LEN = 8;
function fileAadV3(b) {
  return new TextEncoder().encode(`litesync/v3/file:${b.vaultId}:${b.keyEpoch}:${b.fileId}:${b.generation}`);
}
function fileAadV4(b, flags) {
  return new TextEncoder().encode(
    `litesync/v4/file:${b.vaultId}:${b.keyEpoch}:${b.fileId}:${b.generation}:${flags}`
  );
}
function newFileId() {
  const raw = randomBytes(16);
  let out = "";
  for (const b of raw) out += b.toString(16).padStart(2, "0");
  return out;
}
var META_MAGIC = new Uint8Array([76, 83, 77, 49]);
async function deriveResetAuth(vmkRaw) {
  const master = await crypto.subtle.importKey("raw", vmkRaw, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode("litesync/v1/token-reset-auth")
    },
    master,
    256
  );
  return Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function deriveMetaKeys(vmkRaw) {
  const master = await crypto.subtle.importKey("raw", vmkRaw, "HKDF", false, ["deriveKey"]);
  const hkdf = (info, algo, usages) => crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(info)
    },
    master,
    algo,
    false,
    usages
  );
  const [enc, mac] = await Promise.all([
    hkdf("litesync/v5/meta-enc", { name: "AES-GCM", length: 256 }, ["encrypt", "decrypt"]),
    hkdf("litesync/v5/meta-mac", { name: "HMAC", hash: "SHA-256", length: 256 }, ["sign"])
  ]);
  return { enc, mac };
}
function metaAad(vaultId, keyEpoch, fileId, metaGeneration) {
  return new TextEncoder().encode(`litesync/v5/meta:${vaultId}:${keyEpoch}:${fileId}:${metaGeneration}`);
}
async function encryptMeta(keys, binding, meta) {
  requireKeyEpoch(binding.keyEpoch, "encryptMeta");
  requireFileId(binding.fileId, "encryptMeta");
  requireGeneration(binding.metaGeneration, "encryptMeta.metaGeneration");
  const iv = randomBytes(IV_LEN);
  const plain = new TextEncoder().encode(JSON.stringify(meta));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: metaAad(binding.vaultId, binding.keyEpoch, binding.fileId, binding.metaGeneration)
      },
      keys.enc,
      plain
    )
  );
  const head = META_MAGIC.length + EPOCH_LEN + GEN_LEN;
  const out = new Uint8Array(head + IV_LEN + ct.length);
  out.set(META_MAGIC, 0);
  const view = new DataView(out.buffer);
  view.setUint32(META_MAGIC.length, binding.keyEpoch, false);
  view.setBigUint64(META_MAGIC.length + EPOCH_LEN, BigInt(binding.metaGeneration), false);
  out.set(iv, head);
  out.set(ct, head + IV_LEN);
  return b64encode(out);
}
async function decryptMeta(keys, payloadB64, vaultId, fileId) {
  let raw;
  try {
    raw = b64decode(payloadB64);
  } catch {
    return null;
  }
  const head = META_MAGIC.length + EPOCH_LEN + GEN_LEN;
  if (raw.byteLength < head + IV_LEN + 16) return null;
  for (let i = 0; i < META_MAGIC.length; i++) {
    if (raw[i] !== META_MAGIC[i]) return null;
  }
  const view = new DataView(raw.buffer, raw.byteOffset);
  const keyEpoch = view.getUint32(META_MAGIC.length, false);
  const genRaw = view.getBigUint64(META_MAGIC.length + EPOCH_LEN, false);
  if (!isKeyEpoch(keyEpoch) || genRaw > BigInt(GENERATION_MAX)) return null;
  const metaGeneration = Number(genRaw);
  if (!isFileId(fileId)) return null;
  try {
    const iv = raw.subarray(head, head + IV_LEN);
    const ct = raw.subarray(head + IV_LEN);
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: metaAad(vaultId, keyEpoch, fileId, metaGeneration)
      },
      keys.enc,
      ct
    );
    const meta = JSON.parse(new TextDecoder().decode(plain));
    if (typeof meta.path !== "string" || meta.path === "") return null;
    return { meta, metaGeneration, keyEpoch };
  } catch {
    return null;
  }
}
async function canonicalPathHmac(keys, path) {
  const canonical = path.normalize("NFC").toLowerCase();
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", keys.mac, new TextEncoder().encode(canonical))
  );
  let out = "";
  for (const b of sig) out += b.toString(16).padStart(2, "0");
  return out;
}
var VMK_AAD = new TextEncoder().encode("litesync/v1/vault-key");
function fileAad(path) {
  return new TextEncoder().encode(`litesync/v1/file:${path}`);
}
function fileAadV2(binding, path) {
  return new TextEncoder().encode(`litesync/v2/file:${binding.vaultId}:${binding.keyEpoch}:${path}`);
}
function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
function b64encode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function b64decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function deriveKek(password, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function importVmk(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt"
  ]);
}
async function exportVmkRaw(key) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}
async function createVaultKeyDoc(password) {
  const salt = randomBytes(16);
  const iv = randomBytes(IV_LEN);
  const vmkRaw = randomBytes(32);
  const kek = await deriveKek(password, salt, KDF_ITERATIONS);
  const wrapped = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: VMK_AAD },
      kek,
      vmkRaw
    )
  );
  const vmk = await importVmk(vmkRaw);
  vmkRaw.fill(0);
  return {
    doc: {
      version: 1,
      kdf: "pbkdf2-sha256",
      iterations: KDF_ITERATIONS,
      salt: b64encode(salt),
      iv: b64encode(iv),
      wrappedKey: b64encode(wrapped),
      enabled: false,
      createdAt: Date.now()
    },
    vmk
  };
}
async function unlockVaultKey(doc, password) {
  try {
    const kek = await deriveKek(password, b64decode(doc.salt), doc.iterations);
    const vmkRaw = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: b64decode(doc.iv),
          additionalData: VMK_AAD
        },
        kek,
        b64decode(doc.wrappedKey)
      )
    );
    const key = await importVmk(vmkRaw);
    vmkRaw.fill(0);
    return key;
  } catch {
    return null;
  }
}
var SHARE_MAGIC = new Uint8Array([76, 83, 83, 49]);
var SHARE_AAD = new TextEncoder().encode("litesync/v1/share");
var SHARE_NAME_MAGIC = new Uint8Array([76, 83, 78, 49]);
function frameShareContent(name, content) {
  const nameBytes = new TextEncoder().encode(name);
  if (nameBytes.length > 65535) throw new Error("Share display name too long");
  const out = new Uint8Array(SHARE_NAME_MAGIC.length + 2 + nameBytes.length + content.byteLength);
  out.set(SHARE_NAME_MAGIC, 0);
  out[4] = nameBytes.length >> 8 & 255;
  out[5] = nameBytes.length & 255;
  out.set(nameBytes, 6);
  out.set(new Uint8Array(content), 6 + nameBytes.length);
  return out.buffer;
}
var SHARE_BUNDLE_MAGIC = new Uint8Array([76, 83, 78, 50]);
function frameShareBundle(name, content, attachments) {
  if (attachments.length === 0) return frameShareContent(name, content);
  if (attachments.length > 65535) throw new Error("Too many share attachments");
  const enc = new TextEncoder();
  const nameBytes = enc.encode(name);
  if (nameBytes.length > 65535) throw new Error("Share display name too long");
  const entries = attachments.map((a) => {
    const pathBytes = enc.encode(a.path);
    if (pathBytes.length > 65535) throw new Error(`Attachment path too long: ${a.path}`);
    return { pathBytes, data: new Uint8Array(a.data) };
  });
  let size = 4 + 2 + nameBytes.length + 2 + content.byteLength;
  for (const e of entries) size += 2 + e.pathBytes.length + 4 + e.data.length;
  const out = new Uint8Array(size);
  const dv = new DataView(out.buffer);
  let off = 0;
  out.set(SHARE_BUNDLE_MAGIC, off);
  off += 4;
  dv.setUint16(off, nameBytes.length, false);
  off += 2;
  out.set(nameBytes, off);
  off += nameBytes.length;
  dv.setUint16(off, entries.length, false);
  off += 2;
  for (const e of entries) {
    dv.setUint16(off, e.pathBytes.length, false);
    off += 2;
    out.set(e.pathBytes, off);
    off += e.pathBytes.length;
    dv.setUint32(off, e.data.length, false);
    off += 4;
    out.set(e.data, off);
    off += e.data.length;
  }
  out.set(new Uint8Array(content), off);
  return out.buffer;
}
async function encryptShare(keyRaw, plaintext) {
  const key = await crypto.subtle.importKey("raw", keyRaw, { name: "AES-GCM" }, false, [
    "encrypt"
  ]);
  const iv = randomBytes(IV_LEN);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: SHARE_AAD },
      key,
      plaintext
    )
  );
  const out = new Uint8Array(SHARE_MAGIC.length + IV_LEN + ct.length);
  out.set(SHARE_MAGIC, 0);
  out.set(iv, SHARE_MAGIC.length);
  out.set(ct, SHARE_MAGIC.length + IV_LEN);
  return out.buffer;
}
function b64urlEncode(bytes) {
  return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function hasMagic(data, magic, minTail) {
  if (data.byteLength < magic.length + minTail) return false;
  const head = new Uint8Array(data, 0, magic.length);
  for (let i = 0; i < magic.length; i++) {
    if (head[i] !== magic[i]) return false;
  }
  return true;
}
function isEncryptedPayload(data) {
  return hasMagic(data, MAGIC, IV_LEN + 16) || hasMagic(data, MAGIC2, EPOCH_LEN + IV_LEN + 16) || hasMagic(data, MAGIC3, EPOCH_LEN + GEN_LEN + IV_LEN + 16);
}
function isLegacyEnvelope(data) {
  return hasMagic(data, MAGIC, IV_LEN + 16) || hasMagic(data, MAGIC2, EPOCH_LEN + IV_LEN + 16);
}
function isLse3Envelope(data) {
  return hasMagic(data, MAGIC3, EPOCH_LEN + GEN_LEN + IV_LEN + 16);
}
function parseLse3Header(data) {
  if (!isLse3Envelope(data)) return null;
  const view = new DataView(data);
  const keyEpoch = view.getUint32(MAGIC3.length, false);
  const genRaw = view.getBigUint64(MAGIC3.length + EPOCH_LEN, false);
  if (!isKeyEpoch(keyEpoch) || genRaw > BigInt(GENERATION_MAX)) return null;
  return { keyEpoch, generation: Number(genRaw) };
}
async function encryptFileV3(vmk, binding, plaintext) {
  requireKeyEpoch(binding.keyEpoch, "encryptFileV3");
  requireFileId(binding.fileId, "encryptFileV3");
  requireGeneration(binding.generation, "encryptFileV3.generation");
  const iv = randomBytes(IV_LEN);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: fileAadV3(binding) },
      vmk,
      plaintext
    )
  );
  const head = MAGIC3.length + EPOCH_LEN + GEN_LEN;
  const out = new Uint8Array(head + IV_LEN + ct.length);
  out.set(MAGIC3, 0);
  const view = new DataView(out.buffer);
  view.setUint32(MAGIC3.length, binding.keyEpoch, false);
  view.setBigUint64(MAGIC3.length + EPOCH_LEN, BigInt(binding.generation), false);
  out.set(iv, head);
  out.set(ct, head + IV_LEN);
  return out.buffer;
}
async function decryptFileV3(vmk, payload, vaultId, fileId, expectedKeyEpoch) {
  const header2 = parseLse3Header(payload);
  if (header2 === null || !vaultId || !isFileId(fileId)) return null;
  if (expectedKeyEpoch > 0 && header2.keyEpoch !== expectedKeyEpoch) return null;
  try {
    const head = MAGIC3.length + EPOCH_LEN + GEN_LEN;
    const iv = new Uint8Array(payload, head, IV_LEN);
    const ct = new Uint8Array(payload, head + IV_LEN);
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: fileAadV3({
          vaultId,
          keyEpoch: header2.keyEpoch,
          fileId,
          generation: header2.generation
        })
      },
      vmk,
      ct
    );
    return { plain, generation: header2.generation };
  } catch {
    return null;
  }
}
async function encryptFile(vmk, path, plaintext, binding) {
  const iv = randomBytes(IV_LEN);
  if (!binding) {
    const ct2 = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: fileAad(path) },
        vmk,
        plaintext
      )
    );
    const out2 = new Uint8Array(MAGIC.length + IV_LEN + ct2.length);
    out2.set(MAGIC, 0);
    out2.set(iv, MAGIC.length);
    out2.set(ct2, MAGIC.length + IV_LEN);
    return out2.buffer;
  }
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: fileAadV2(binding, path) },
      vmk,
      plaintext
    )
  );
  const out = new Uint8Array(MAGIC2.length + EPOCH_LEN + IV_LEN + ct.length);
  out.set(MAGIC2, 0);
  new DataView(out.buffer).setUint32(MAGIC2.length, requireKeyEpoch(binding.keyEpoch, "encryptFile/LSE2"), false);
  out.set(iv, MAGIC2.length + EPOCH_LEN);
  out.set(ct, MAGIC2.length + EPOCH_LEN + IV_LEN);
  return out.buffer;
}
async function decryptFile(vmk, path, payload, binding) {
  if (hasMagic(payload, MAGIC2, EPOCH_LEN + IV_LEN + 16)) {
    if (!binding?.vaultId) return null;
    const envelopeEpoch = new DataView(payload).getUint32(MAGIC2.length, false);
    if (!isKeyEpoch(envelopeEpoch)) return null;
    if (binding.keyEpoch > 0 && envelopeEpoch !== binding.keyEpoch) return null;
    try {
      const iv = new Uint8Array(payload, MAGIC2.length + EPOCH_LEN, IV_LEN);
      const ct = new Uint8Array(payload, MAGIC2.length + EPOCH_LEN + IV_LEN);
      return await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: fileAadV2({ vaultId: binding.vaultId, keyEpoch: envelopeEpoch }, path)
        },
        vmk,
        ct
      );
    } catch {
      return null;
    }
  }
  if (!hasMagic(payload, MAGIC, IV_LEN + 16)) return null;
  try {
    const iv = new Uint8Array(payload, MAGIC.length, IV_LEN);
    const ct = new Uint8Array(payload, MAGIC.length + IV_LEN);
    return await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: fileAad(path) },
      vmk,
      ct
    );
  } catch {
    return null;
  }
}
async function encryptFileV4(vmk, binding, plaintext, padded) {
  requireKeyEpoch(binding.keyEpoch, "encryptFileV4");
  requireFileId(binding.fileId, "encryptFileV4");
  requireGeneration(binding.generation, "encryptFileV4.generation");
  const flags = padded ? LSE4_FLAG_PADDED : 0;
  const framed = frame(plaintext, padded);
  const iv = randomBytes(IV_LEN);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: fileAadV4(binding, flags) },
      vmk,
      framed
    )
  );
  const head = MAGIC4.length + FLAGS_LEN + EPOCH_LEN + GEN_LEN;
  const out = new Uint8Array(head + IV_LEN + ct.length);
  out.set(MAGIC4, 0);
  out[MAGIC4.length] = flags;
  const view = new DataView(out.buffer);
  view.setUint32(MAGIC4.length + FLAGS_LEN, binding.keyEpoch, false);
  view.setBigUint64(MAGIC4.length + FLAGS_LEN + EPOCH_LEN, BigInt(binding.generation), false);
  out.set(iv, head);
  out.set(ct, head + IV_LEN);
  return out.buffer;
}
function isLse4Envelope(data) {
  return hasMagic(data, MAGIC4, FLAGS_LEN + EPOCH_LEN + GEN_LEN + IV_LEN + 16);
}
function parseLse4Header(data) {
  if (!isLse4Envelope(data)) return null;
  const view = new DataView(data);
  const flags = view.getUint8(MAGIC4.length);
  const keyEpoch = view.getUint32(MAGIC4.length + FLAGS_LEN, false);
  const genRaw = view.getBigUint64(MAGIC4.length + FLAGS_LEN + EPOCH_LEN, false);
  if (!isKeyEpoch(keyEpoch) || genRaw > BigInt(GENERATION_MAX)) return null;
  return { flags, keyEpoch, generation: Number(genRaw) };
}
async function decryptFileV4(vmk, payload, vaultId, fileId, expectedKeyEpoch) {
  const header2 = parseLse4Header(payload);
  if (header2 === null || !vaultId || !isFileId(fileId)) return null;
  if (expectedKeyEpoch > 0 && header2.keyEpoch !== expectedKeyEpoch) return null;
  try {
    const head = MAGIC4.length + FLAGS_LEN + EPOCH_LEN + GEN_LEN;
    const iv = new Uint8Array(payload, head, IV_LEN);
    const ct = new Uint8Array(payload, head + IV_LEN);
    const framed = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: fileAadV4(
          { vaultId, keyEpoch: header2.keyEpoch, fileId, generation: header2.generation },
          header2.flags
        )
      },
      vmk,
      ct
    );
    const plain = unframe(framed);
    if (plain === null) return null;
    return { plain, generation: header2.generation };
  } catch {
    return null;
  }
}

// src/utils/hash.ts
async function sha256Hex(data) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

// src/utils/text.ts
function decodeUtf8Strict(data) {
  const bytes = new Uint8Array(data);
  const probe = Math.min(bytes.length, 8192);
  for (let i = 0; i < probe; i++) {
    if (bytes[i] === 0) return null;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(data);
  } catch {
    return null;
  }
}
function encodeUtf8(text) {
  const bytes = new TextEncoder().encode(text);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

// src/crypto/checkpoint.ts
async function objectsRoot(objects) {
  const lines = objects.map(
    (o) => `${o.fileId}:${o.contentGeneration}:${o.metaGeneration}:${o.contentHash}:${o.metadataHash}:${o.state}`
  ).sort();
  return sha256Hex(encodeUtf8(lines.join("\n")));
}
function canonicalCheckpoint(b) {
  return [
    `v=${b.version}`,
    `vault=${b.vaultId}`,
    `repoEpoch=${b.repoEpoch}`,
    `formatEpoch=${b.formatEpoch}`,
    `keyEpoch=${b.keyEpoch}`,
    `head=${b.headSequence}`,
    `root=${b.objectsRoot}`,
    `count=${b.objectCount}`,
    `prev=${b.previousCheckpointHash}`,
    `device=${b.signingDeviceId}`,
    `ts=${b.timestamp}`
  ].join("\n");
}
async function checkpointHash(b) {
  return sha256Hex(encodeUtf8(canonicalCheckpoint(b)));
}
var SIGN_ALG = { name: "ECDSA", namedCurve: "P-256" };
var SIGN_PARAMS = { name: "ECDSA", hash: "SHA-256" };
async function generateSigningKey() {
  const pair = await crypto.subtle.generateKey(SIGN_ALG, true, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  return {
    privateKey: pair.privateKey,
    publicKeyB64: b64encode(spki),
    privateKeyPkcs8B64: b64encode(pkcs8)
  };
}
async function importSigningPrivateKey(pkcs8B64) {
  return crypto.subtle.importKey("pkcs8", b64decode(pkcs8B64), SIGN_ALG, false, ["sign"]);
}
async function importSigningPublicKey(spkiB64) {
  return crypto.subtle.importKey("spki", b64decode(spkiB64), SIGN_ALG, false, ["verify"]);
}
async function signCheckpoint(privateKey, body) {
  const canonical = encodeUtf8(canonicalCheckpoint(body));
  const sig = new Uint8Array(await crypto.subtle.sign(SIGN_PARAMS, privateKey, canonical));
  return { body, hash: await checkpointHash(body), signature: b64encode(sig) };
}
async function verifyCheckpoint(publicKeySpkiB64, cp) {
  if (await checkpointHash(cp.body) !== cp.hash) return false;
  try {
    const key = await importSigningPublicKey(publicKeySpkiB64);
    return await crypto.subtle.verify(
      SIGN_PARAMS,
      key,
      b64decode(cp.signature),
      encodeUtf8(canonicalCheckpoint(cp.body))
    );
  } catch {
    return false;
  }
}

// src/api/client.ts
var PLUGIN_PROTOCOL_VERSION = 6;
var PLUGIN_VERSION = "0.19.0";
function detectClientPlatform() {
  const p = import_obsidian.Platform;
  if (p.isIosApp) return "ios";
  if (p.isAndroidApp) return "android";
  if (p.isMacOS) return "macos";
  if (p.isWin) return "windows";
  if (p.isLinux) return "linux";
  return "unknown";
}
var CLIENT_PLATFORM = detectClientPlatform();
function protocolError(info) {
  const server = info.protocolVersion ?? 1;
  const minClient = info.minProtocolVersion ?? 1;
  if (minClient > PLUGIN_PROTOCOL_VERSION) {
    return `LiteSync plugin needs updating: the server (${info.version}) requires protocol ≥ ${minClient}, current plugin is ${PLUGIN_PROTOCOL_VERSION}`;
  }
  if (server < PLUGIN_PROTOCOL_VERSION) {
    return `LiteSync Server needs updating: the plugin requires protocol ${PLUGIN_PROTOCOL_VERSION}, server (${info.version}) is ${server}`;
  }
  return null;
}
var ApiError = class extends Error {
  constructor(status, message, code, retryable, existing) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryable = retryable;
    this.existing = existing;
    this.name = "ApiError";
  }
  is(code) {
    return this.code === code;
  }
};
var MigrationValidationError = class extends Error {
  constructor(failures) {
    super(
      `Migration verification failed (${failures.length} items):` + failures.map((f) => `${f.check}\uFF08${f.code} \xD7${f.count}\uFF09`).join("\uFF1B")
    );
    this.failures = failures;
    this.name = "MigrationValidationError";
  }
};
var ConflictError = class extends Error {
  constructor(server) {
    super(`revision conflict on ${server.path} (server revision ${server.revision})`);
    this.server = server;
    this.name = "ConflictError";
  }
};
var NotFoundError = class extends Error {
  constructor(deleted = false, revision = 0) {
    super("not found");
    this.deleted = deleted;
    this.revision = revision;
    this.name = "NotFoundError";
  }
};
var ApiClient = class {
  constructor(getConfig) {
    this.getConfig = getConfig;
  }
  base() {
    const url = this.getConfig().serverUrl.trim().replace(/\/+$/, "");
    if (!url) throw new ApiError(0, "server URL is not configured");
    if (/^http:\/\//i.test(url) && !isLoopbackUrl(url)) {
      throw new ApiError(0, "Non-local addresses must use https:// (the current Server URL is http://, which would expose the token in plaintext)");
    }
    return url;
  }
  headers(extra) {
    const { apiToken, deviceId, formatEpoch, repoEpoch, keyEpoch, vaultChoice } = this.getConfig();
    return {
      Authorization: `Bearer ${apiToken}`,
      // 目标仓库（v0.19）：用户级凭据据此选择仓库（服务端按成员关系硬校验，
      // 非成员 404）；设备凭据已绑定仓库，服务端对它忽略此头
      ...vaultChoice ? { "X-Vault-ID": vaultChoice } : {},
      "X-Device-ID": deviceId,
      // 逐请求协议与世代校验（协议 v6 / ADR-006 §2.2、计划书 §5.3）：
      // 服务器逐请求比对，不匹配即拒绝写入——绝不让本设备用过时的判断改数据
      "X-LiteSync-Protocol": String(PLUGIN_PROTOCOL_VERSION),
      // 客户端版本（§15 第 3 步）：让「所有设备都升级了吗」成为一个可查的事实，
      // 而不是一句只能靠人挨个问的口头确认
      "X-Client-Version": PLUGIN_VERSION,
      // 客户端平台（运维页 Devices 列表）：让「哪台是丢失的那台手机」
      // 在事故当天一眼可辨，而不是对着一排设备名猜
      "X-Client-Platform": CLIENT_PLATFORM,
      ...formatEpoch > 0 ? { "X-Format-Epoch": String(formatEpoch) } : {},
      ...repoEpoch ? { "X-Repo-Epoch": repoEpoch } : {},
      ...keyEpoch > 0 ? { "X-Key-Epoch": String(keyEpoch) } : {},
      ...extra
    };
  }
  /** 幂等键：响应丢失后用同一个 id 重试，服务器返回首次结果而不是产生第二个 revision。 */
  opHeader(operationId) {
    return operationId ? { "X-Operation-Id": operationId } : {};
  }
  async info() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/info`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "info failed", res.text);
    return res.json;
  }
  async changes(since, limit = 500) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/changes?since=${since}&limit=${limit}`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `changes failed: HTTP ${res.status}`);
    return res.json;
  }
  /** 当前所有未删除文件的元数据（changes 被裁剪后的全量对账）。 */
  async snapshot() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/snapshot`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `snapshot failed: HTTP ${res.status}`);
    return res.json;
  }
  async download(path) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/file?path=${encodeURIComponent(path)}`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status === 404) {
      const body = tryJson(res.text);
      throw new NotFoundError(body?.deleted === true, num(body?.revision));
    }
    if (res.status !== 200) throw new ApiError(res.status, `download ${path} failed: HTTP ${res.status}`);
    return {
      data: res.arrayBuffer,
      revision: num(header(res.headers, "x-revision")),
      hash: header(res.headers, "x-content-hash") ?? "",
      size: num(header(res.headers, "x-file-size")),
      mtime: num(header(res.headers, "x-file-mtime")),
      fileId: header(res.headers, "x-file-id") || void 0,
      metaEnc: header(res.headers, "x-meta-enc") || void 0,
      metaGeneration: num(header(res.headers, "x-meta-generation")) || void 0
    };
  }
  async upload(path, baseRevision, hash, data, mtime, action = "upsert", fileId, meta, operationId) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/file`,
      method: "PUT",
      headers: this.headers({
        "Content-Type": "application/octet-stream",
        "X-File-Path": encodeURIComponent(path),
        "X-Base-Revision": String(baseRevision),
        "X-Content-Hash": hash,
        "X-File-Mtime": String(Math.round(mtime)),
        "X-Action": action,
        ...fileId ? { "X-File-Id": fileId } : {},
        ...meta ? { "X-Meta-Enc": meta.metaEnc, "X-Canonical-Hash": meta.canonicalHash } : {},
        ...this.opHeader(operationId)
      }),
      body: data,
      throw: false
    });
    if (res.status === 409) {
      const body = tryJson(res.text);
      if (typeof body?.code === "string" && body.code !== "CONFLICT") {
        throw apiError(409, `upload ${path} failed`, res.text);
      }
      throw new ConflictError(parseConflict(res.text, path));
    }
    if (res.status !== 200) {
      throw apiError(res.status, `upload ${path} failed`, res.text);
    }
    return res.json;
  }
  /** 获取文件的历史版本列表（revision 降序）。 */
  async history(path) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/history?path=${encodeURIComponent(path)}`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `history ${path} failed: HTTP ${res.status}`);
    const body = res.json;
    return body.versions ?? [];
  }
  /** 下载某历史版本的内容。版本不存在或已被 GC 时抛 NotFoundError。 */
  async version(path, revision) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/version?path=${encodeURIComponent(path)}&revision=${revision}`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status === 404) throw new NotFoundError();
    if (res.status !== 200)
      throw new ApiError(res.status, `version ${path}@${revision} failed: HTTP ${res.status}`);
    return {
      data: res.arrayBuffer,
      revision: num(header(res.headers, "x-revision")),
      hash: header(res.headers, "x-content-hash") ?? "",
      size: num(header(res.headers, "x-file-size")),
      mtime: num(header(res.headers, "x-file-mtime")),
      fileId: header(res.headers, "x-file-id") || void 0
    };
  }
  /**
   * 创建分享（body 是独立 Share Key 加密后的密文；服务器拿不到 key）。
   *
   * v0.13.3 §7.4：**不再发送 `X-Share-Name`**。显示名已经打进密文帧里，
   * 由查看页解密后展示；服务器侧只保留一个随机标签。以前把真实路径放进
   * Header，等于让「用户分享了哪个文件」出现在服务端日志与数据库里。
   */
  async createShare(expiresAt, payload) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/share`,
      method: "POST",
      headers: this.headers({
        "Content-Type": "application/octet-stream",
        "X-Share-Expires": String(expiresAt)
      }),
      body: payload,
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `share create failed: HTTP ${res.status}`);
    return res.json;
  }
  /**
   * 拉取 checkpoint 链（v0.15 / §9）。
   *
   * 服务器只是转发者：它给出的 signingKeys 与 revokedDevices 仅用于**识别**，
   * 绝不用于授信——信任集合由配对流程建立（§9.3）。
   */
  async checkpoints(since) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/checkpoints?since=${since}`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "checkpoints failed", res.text);
    const body = res.json;
    return {
      repoEpoch: body.repoEpoch,
      checkpoints: (body.checkpoints ?? []).map(parseCheckpoint),
      conflicting: (body.conflicting ?? []).map(parseCheckpoint),
      signingKeys: body.signingKeys ?? {},
      revokedDevices: body.revokedDevices ?? []
    };
  }
  /** 发布本设备签名的 checkpoint。 */
  async publishCheckpoint(cp) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/checkpoint`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        hash: cp.hash,
        repoEpoch: cp.body.repoEpoch,
        headSequence: cp.body.headSequence,
        previousHash: cp.body.previousCheckpointHash,
        body: canonicalCheckpoint(cp.body),
        signature: cp.signature
      }),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "publish checkpoint failed", res.text);
  }
  /** 名下仓库列表（v0.19 多仓库；设备凭据也可调——只列自己主人的）。 */
  async listVaults() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/vaults`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "list vaults failed", res.text);
    return res.json.vaults ?? [];
  }
  /** 新建仓库（v0.19；用户级 Token 专属，设备凭据会被拒）。 */
  async createVault(name) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/vaults`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ name }),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "create vault failed", res.text);
    return res.json.id;
  }
  /** 重命名仓库（v0.19.x；用户级 Token 专属，只动展示名——身份/密钥/账本不受影响）。 */
  async renameVault(id, name) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/vaults/${encodeURIComponent(id)}`,
      method: "PATCH",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ name }),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "rename vault failed", res.text);
  }
  /**
   * 登记重置凭证（v0.18 / v11 设计 §3.1）：resetKey = HKDF(VMK, "litesync/v1/token-reset-auth")。
   * 服务端存 SHA-256——之后「重置 API Token」必须提交这个值，只拿到 Token 的
   * 攻击者派生不出它。幂等；服务端已登记不同值时返回 409（RESET_AUTH_MISMATCH），
   * 调用方按 code 分支决定是否提示。
   */
  async registerResetAuth(resetAuth) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/vault/reset-auth`,
      method: "PUT",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ resetAuth }),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "register reset auth failed", res.text);
  }
  /** 登记本设备的 checkpoint 签名公钥（首次接入时一次）。 */
  async registerSigningKey(publicKeyB64) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/device/signing-key`,
      method: "PUT",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ publicKey: publicKeyB64 }),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "register signing key failed", res.text);
  }
  async listShares() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/shares`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `share list failed: HTTP ${res.status}`);
    return res.json.shares ?? [];
  }
  async revokeShare(id) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/share?id=${encodeURIComponent(id)}`,
      method: "DELETE",
      headers: this.headers(),
      throw: false
    });
    if (res.status === 404) throw new NotFoundError();
    if (res.status !== 200) throw new ApiError(res.status, `share revoke failed: HTTP ${res.status}`);
  }
  // ---------- 设备级凭据（v9.2，协议 v3） ----------
  /** 当前凭据身份：root（.env 根 Token）或 device（设备凭据）。 */
  async whoami() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/whoami`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `whoami failed: HTTP ${res.status}`);
    return res.json;
  }
  /** 根 Token 直接创建设备凭据（首台设备自注册；token 明文只返回一次）。 */
  async createDevice(name) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/devices`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ name }),
      throw: false
    });
    if (res.status !== 200)
      throw new ApiError(res.status, `device create failed: HTTP ${res.status}${serverErrText(res.text)}`);
    return res.json;
  }
  /** 生成一次性注册凭据（配对包 v2 携带；secret 只返回一次）。 */
  async createEnrollment(ttlSeconds = 900) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/enrollments`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ ttlSeconds }),
      throw: false
    });
    if (res.status !== 200)
      throw new ApiError(res.status, `enrollment create failed: HTTP ${res.status}${serverErrText(res.text)}`);
    return res.json;
  }
  /** 设备列表（不含凭据材料）。 */
  async listDevices() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/devices`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `device list failed: HTTP ${res.status}`);
    return res.json.devices ?? [];
  }
  /** 创建一次性加密配对包（v8「添加新设备」；服务器只存密文）。 */
  async createPairing(ciphertextB64, ttlSeconds = 300) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/pairing`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ ciphertext: ciphertextB64, ttlSeconds }),
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `pairing create failed: HTTP ${res.status}`);
    return res.json;
  }
  /** 撤销配对包（配对窗口关闭时调用；已消费/不存在也视为成功）。 */
  async deletePairing(id) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/pairing/${encodeURIComponent(id)}`,
      method: "DELETE",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `pairing delete failed: HTTP ${res.status}`);
  }
  /** 获取服务器上的加密 vault key 文档；未启用 E2EE 时返回 null。 */
  async getVaultKey() {
    return (await this.getVaultKeyWithFingerprint())?.doc ?? null;
  }
  /** 获取 vault key 文档及其 CAS 指纹（replace 时必须原样传回，0.9.0+）。 */
  async getVaultKeyWithFingerprint() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/vault-key`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status === 404) return null;
    if (res.status !== 200) throw new ApiError(res.status, `vault-key get failed: HTTP ${res.status}`);
    return {
      doc: res.json,
      fingerprint: header(res.headers, "x-vault-key-fingerprint") ?? ""
    };
  }
  /**
   * 上传加密 vault key 文档。已存在且未 replace 时服务器返回 409；
   * replace 必须携带当前文档指纹（CAS），指纹不符服务器返回 412——
   * 防止并发迁移把别的设备刚写入的 key 文档无条件覆盖掉。
   */
  async putVaultKey(doc, replace, expectedFingerprint = "") {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/vault-key${replace ? "?replace=true" : ""}`,
      method: "PUT",
      headers: this.headers({
        "Content-Type": "application/json",
        ...expectedFingerprint ? { "X-Expected-Fingerprint": expectedFingerprint } : {}
      }),
      body: JSON.stringify(doc),
      throw: false
    });
    if (res.status !== 200)
      throw new ApiError(res.status, `vault-key put failed: HTTP ${res.status}${serverErrText(res.text)}`);
  }
  /** E2EE 状态机（0.9.0+）：begin 冻结明文写 / complete 全量验证后启用 / abort 回退。 */
  async e2eeTransition(action) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/e2ee/${action}`,
      method: "POST",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200)
      throw new ApiError(res.status, `e2ee ${action} failed: HTTP ${res.status}${serverErrText(res.text)}`);
    return res.json;
  }
  /** 清理某路径 beforeRevision 之前的历史版本（E2EE 迁移：密文验证后清明文）。 */
  async purgeHistory(path, beforeRevision) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/history?path=${encodeURIComponent(path)}&beforeRevision=${beforeRevision}`,
      method: "DELETE",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw new ApiError(res.status, `history purge failed: HTTP ${res.status}`);
    return num(res.json?.removed);
  }
  /**
   * 改名（协议 v6 / ADR-001 §3.4）：一次元数据更新。
   *
   * 服务器只改 pseudonym / canonical HMAC / metaGeneration——内容 blob、
   * revision、contentGeneration 全部不动，**不产生任何 tombstone**。
   * 412 = metaGeneration CAS 失败（并发改名，重取后重试）；
   * 409 = 目标被 live 对象占用。目标名上只有 tombstone 时改名**放行**
   *（0.17 实测修正）：那不是复活，删除事实按 fileId 保留——以前的 409
   * 会把客户端逼进 delete+upsert 退化，历史嫁接到死对象身上。
   */
  async rename(fromPath, toPath, baseMetaGeneration, meta, operationId) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/file/rename`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json", ...this.opHeader(operationId) }),
      body: JSON.stringify({
        fromPath,
        toPath,
        baseMetaGeneration,
        metaEnc: meta?.metaEnc ?? "",
        canonicalHash: meta?.canonicalHash ?? ""
      }),
      throw: false
    });
    if (res.status === 409) throw new ConflictError(parseConflict(res.text, toPath));
    if (res.status !== 200) throw apiError(res.status, `rename ${fromPath} -> ${toPath} failed`, res.text);
    return res.json;
  }
  /**
   * 显式恢复已删除对象（协议 v6 / ADR-002 §3.6）。
   *
   * v5 里「删除后重建」是拿 tombstone revision 做普通 upsert 穿透墓碑，
   * 服务器分不清「用户真想恢复」与「陈旧设备把三个月前的副本传了回来」。
   * v6 把它变成显式操作：恢复后 revision 连续、fileId 不变、历史全部仍可达。
   * 随后再用返回的 revision 作为 baseRevision 上传新内容。
   */
  async restore(fileId, params, operationId) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/files/${encodeURIComponent(fileId)}/restore`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json", ...this.opHeader(operationId) }),
      body: JSON.stringify({
        expectedTombstoneRevision: params.expectedTombstoneRevision,
        contentGeneration: params.contentGeneration,
        pseudonym: params.pseudonym,
        metaEnc: params.metaEnc ?? "",
        canonicalHash: params.canonicalHash ?? ""
      }),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, `restore ${fileId} failed`, res.text);
    return res.json;
  }
  /** 信封升级完成：服务器验证全部 HEAD 为 LSE3 后把仓库下限提升到 3（ADR-006）。 */
  async completeEnvelopeUpgrade() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/envelope/complete`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: "{}",
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "envelope upgrade complete failed", res.text);
    return res.json;
  }
  // ---------- 元数据加密（协议 v6，ADR-003） ----------
  /** 轻量获取文件元数据（改名变更无需下载内容）。 */
  async getFileMeta(path) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/file/meta?path=${encodeURIComponent(path)}`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status === 404) throw new NotFoundError();
    if (res.status !== 200) throw new ApiError(res.status, `meta get failed: HTTP ${res.status}`);
    return res.json;
  }
  /** 续租迁移（计划书 §5.4）：owner 在长迁移中周期调用。 */
  async renewMigrationLease() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/meta/renew`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: "{}",
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "meta renew failed", res.text);
    return res.json;
  }
  /** 显式接管租约已过期的迁移（绝不自动发生，计划书 §5.4）。 */
  async takeoverMigration(migrationId) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/meta/takeover`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ migrationId }),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "meta takeover failed", res.text);
    return res.json;
  }
  /** 迁移进度与状态（journal 汇总）。 */
  async metaStatus() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/meta/status`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "meta status failed", res.text);
    return res.json;
  }
  /** 单对象伪名化（幂等，断点续传安全）。 */
  async migrateObjectMeta(fromPath, metaEnc, canonicalHash) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/meta/migrate`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ fromPath, metaEnc, canonicalHash }),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "meta migrate failed", res.text);
    return res.json;
  }
  /** 列出仍带明文寻址名的删除记录（迁移 owner 专用）。 */
  async listPlaintextTombstones() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/meta/tombstones`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "meta tombstones failed", res.text);
    return res.json.tombstones ?? [];
  }
  /**
   * 把一条 tombstone 转成隐私格式（ADR-002 §3.2）。
   * 明文寻址名换成 fileId、归一化路径换成客户端 HMAC——**删除屏障完整保留**，
   * 这正是 v0.12.0「删掉 tombstone 抹明文」造成静默复活的正解。
   */
  async migrateTombstone(fileId, canonicalHash) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/meta/migrate-tombstone`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ fileId, canonicalHash }),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "tombstone migrate failed", res.text);
  }
  /** 预检：只跑服务端验证器，不改状态。 */
  async validateMetaMigration() {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/meta/validate`,
      method: "GET",
      headers: this.headers(),
      throw: false
    });
    if (res.status !== 200) throw apiError(res.status, "meta validate failed", res.text);
    const body = res.json;
    return { ok: body.ok, failures: body.failures ?? [] };
  }
  async metaTransition(action, confirmErase, migrationId) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/meta/${action}`,
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: action === "complete" ? JSON.stringify({ confirmErase: confirmErase === true, migrationId: migrationId ?? "" }) : "{}",
      throw: false
    });
    if (res.status !== 200) throw metaTransitionError(res.status, action, res.text);
    return res.json;
  }
  async remove(path, baseRevision) {
    const res = await (0, import_obsidian.requestUrl)({
      url: `${this.base()}/api/v1/file`,
      method: "DELETE",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ path, baseRevision }),
      throw: false
    });
    if (res.status === 409) throw new ConflictError(parseConflict(res.text, path));
    if (res.status === 404) throw new NotFoundError();
    if (res.status !== 200) throw new ApiError(res.status, `delete ${path} failed: HTTP ${res.status}`);
  }
};
function parseConflict(text, path) {
  const body = tryJson(text);
  return {
    path: typeof body?.path === "string" ? body.path : path,
    revision: num(body?.revision),
    hash: typeof body?.hash === "string" ? body.hash : "",
    deleted: body?.deleted === true,
    priorHash: typeof body?.priorHash === "string" ? body.priorHash : void 0,
    fileId: typeof body?.fileId === "string" ? body.fileId : void 0,
    contentGeneration: typeof body?.contentGeneration === "number" ? body.contentGeneration : void 0
  };
}
function serverErrText(text) {
  const body = tryJson(text);
  const msg = typeof body?.message === "string" ? body.message : typeof body?.error === "string" ? body.error : "";
  const extra = typeof body?.existing === "string" ? ` (conflicts with an existing file: ${body.existing}\uFF09` : "";
  return msg ? ` \u2014 ${msg}${extra}` : "";
}
function metaTransitionError(status, action, text) {
  const body = tryJson(text);
  if (body?.code === "MIGRATION_VALIDATION_FAILED" && Array.isArray(body.failures)) {
    return new MigrationValidationError(body.failures);
  }
  return apiError(status, `meta ${action} failed`, text);
}
function apiError(status, prefix, text) {
  const body = tryJson(text);
  return new ApiError(
    status,
    `${prefix}: HTTP ${status}${serverErrText(text)}`,
    typeof body?.code === "string" ? body.code : void 0,
    typeof body?.retryable === "boolean" ? body.retryable : void 0,
    typeof body?.existing === "string" ? body.existing : void 0
  );
}
async function enrollDevice(serverUrl, secret, name) {
  const res = await (0, import_obsidian.requestUrl)({
    url: `${serverUrl.replace(/\/+$/, "")}/enroll`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ secret, name }),
    throw: false
  });
  if (res.status === 404) throw new ApiError(404, "The registration credential is invalid or expired — regenerate the pairing QR code on the old device");
  if (res.status !== 200) throw new ApiError(res.status, `device enroll failed: HTTP ${res.status}`);
  return res.json;
}
function isLoopbackUrl(url) {
  const m = /^https?:\/\/(\[[^\]]+\]|[^/:?#]+)/i.exec(url.trim());
  if (!m) return false;
  const host = m[1].toLowerCase();
  return host === "localhost" || host === "[::1]" || host === "127.0.0.1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}
function tryJson(text) {
  try {
    const v = JSON.parse(text);
    return typeof v === "object" && v !== null ? v : null;
  } catch {
    return null;
  }
}
function header(headers, name) {
  if (name in headers) return headers[name];
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === name) return headers[key];
  }
  return void 0;
}
function num(v) {
  const n = typeof v === "string" ? parseInt(v, 10) : typeof v === "number" ? v : NaN;
  return Number.isFinite(n) ? n : 0;
}
function parseCheckpoint(raw) {
  const kv = /* @__PURE__ */ new Map();
  for (const line of raw.body.split(/\r?\n/)) {
    const i = line.indexOf("=");
    if (i > 0) kv.set(line.slice(0, i), line.slice(i + 1));
  }
  const num2 = (k) => Number(kv.get(k) ?? 0);
  return {
    hash: raw.hash,
    signature: raw.signature,
    body: {
      version: 1,
      vaultId: kv.get("vault") ?? "",
      repoEpoch: kv.get("repoEpoch") ?? "",
      formatEpoch: num2("formatEpoch"),
      keyEpoch: num2("keyEpoch"),
      headSequence: num2("head"),
      objectsRoot: kv.get("root") ?? "",
      objectCount: num2("count"),
      previousCheckpointHash: kv.get("prev") ?? "",
      signingDeviceId: kv.get("device") ?? "",
      timestamp: num2("ts")
    }
  };
}

// src/utils/conflict-name.ts
function conflictPathFor(path, deviceName, when, salt) {
  const slash = path.lastIndexOf("/");
  const dot = path.lastIndexOf(".");
  const hasExt = dot > slash + 1;
  const stem = hasExt ? path.slice(0, dot) : path;
  const ext = hasExt ? path.slice(dot) : "";
  const pad = (n) => String(n).padStart(2, "0");
  const stamp = `${when.getFullYear()}${pad(when.getMonth() + 1)}${pad(when.getDate())}-${pad(when.getHours())}${pad(when.getMinutes())}${pad(when.getSeconds())}`;
  const device = deviceName.replace(/[\\/:*?"<>|#^[\]]/g, "-") || "device";
  const rand = salt ?? randomSuffix();
  return `${stem}.conflict-${device}-${stamp}-${rand}${ext}`;
}
function randomSuffix() {
  return Math.random().toString(36).slice(2, 6).padEnd(4, "0");
}

// src/utils/path.ts
function parentOf(path) {
  const idx = path.lastIndexOf("/");
  return idx === -1 ? "" : path.slice(0, idx);
}
async function ensureParentFolder(adapter, path) {
  const parent = parentOf(path);
  if (!parent) return;
  const parts = parent.split("/");
  let cur = "";
  for (const part of parts) {
    cur = cur ? `${cur}/${part}` : part;
    if (!await adapter.exists(cur)) {
      try {
        await adapter.mkdir(cur);
      } catch (e) {
        if (!await adapter.exists(cur)) throw e;
      }
    }
  }
}

// src/utils/failpoint.ts
var registry = /* @__PURE__ */ new Map();
var InjectedFailure = class extends Error {
  constructor(name) {
    super(`failpoint: injected failure at ${name}`);
    this.name = "InjectedFailure";
  }
};
async function evalFailpoint(name) {
  const e = registry.get(name);
  if (e === void 0) return;
  e.hits++;
  if (e.remaining > 0) {
    e.remaining--;
    if (e.remaining === 0) registry.delete(name);
  }
  if (e.action === null) throw new InjectedFailure(name);
  await e.action();
}
var FP = {
  /** pending op 已进内存、尚未落盘 */
  queueBeforeDurable: "queue.before-durable-add",
  /** pending op 已落盘 */
  queueAfterDurable: "queue.after-durable-add",
  /** StateStore 写完某个副本槽、尚未提升 generation */
  stateAfterSlotWrite: "state.after-slot-write",
  /** StateStore 即将切换活动槽 */
  stateBeforePointerSwitch: "state.before-pointer-switch",
  /** 远端内容已下载、尚未提交到本地 */
  pullAfterDownload: "pull.after-download",
  /** 旧内容已移入 recovery、新内容尚未安装 */
  commitAfterRecovery: "local-commit.after-recovery",
  /** staging 即将安装到目标路径 */
  commitBeforeInstall: "local-commit.before-install",
  /** 名字互换：第一步已完成、第二步尚未开始 */
  swapAfterFirstStep: "rename.after-first-step",
  /** 即将推进 lastSequence */
  cursorBeforeAck: "cursor.before-ack",
  /** bootstrap 即将标记完成 */
  bootstrapBeforeComplete: "bootstrap.before-complete",
  /** 迁移即将 complete */
  migrationBeforeComplete: "migration.before-complete"
};

// src/utils/vault-path.ts
var MAX_COMPONENT_BYTES = 255;
var MAX_PATH_LENGTH = 400;
var WINDOWS_RESERVED = /* @__PURE__ */ new Set([
  "con",
  "prn",
  "aux",
  "nul",
  "com1",
  "com2",
  "com3",
  "com4",
  "com5",
  "com6",
  "com7",
  "com8",
  "com9",
  "lpt1",
  "lpt2",
  "lpt3",
  "lpt4",
  "lpt5",
  "lpt6",
  "lpt7",
  "lpt8",
  "lpt9"
]);
var InvalidVaultPathError = class extends Error {
  constructor(reason, shape) {
    super(`The path provided by the remote is unsafe (${reason}\uFF0C${shape}), refusing to write it locally`);
    this.reason = reason;
    this.shape = shape;
    this.name = "InvalidVaultPathError";
  }
};
function shapeOf(path) {
  return `${path.split("/").length} hunks / ${path.length} chars`;
}
var utf8 = new TextEncoder();
function validateAndCanonicalizeVaultPath(path) {
  if (typeof path !== "string" || path.length === 0) {
    throw new InvalidVaultPathError("empty", "0 chars");
  }
  if (path.length > MAX_PATH_LENGTH) {
    throw new InvalidVaultPathError("too-long", shapeOf(path));
  }
  if (path.includes("\\")) {
    throw new InvalidVaultPathError("backslash", shapeOf(path));
  }
  if (path.startsWith("//")) {
    throw new InvalidVaultPathError("unc", shapeOf(path));
  }
  if (path.startsWith("/")) {
    throw new InvalidVaultPathError("absolute", shapeOf(path));
  }
  if (/^[a-zA-Z]:/.test(path)) {
    throw new InvalidVaultPathError("drive-letter", shapeOf(path));
  }
  const normalized = path.normalize("NFC");
  const parts = normalized.split("/");
  for (const part of parts) {
    if (part.length === 0) {
      throw new InvalidVaultPathError("empty-component", shapeOf(normalized));
    }
    if (part === "." || part === "..") {
      throw new InvalidVaultPathError("traversal", shapeOf(normalized));
    }
    if (utf8.encode(part).length > MAX_COMPONENT_BYTES) {
      throw new InvalidVaultPathError("component-too-long", shapeOf(normalized));
    }
    for (const ch of part) {
      const code = ch.codePointAt(0);
      if (code === 0) throw new InvalidVaultPathError("nul", shapeOf(normalized));
      if (code < 32 || code === 127) {
        throw new InvalidVaultPathError("control-char", shapeOf(normalized));
      }
    }
    if (part.endsWith(" ") || part.endsWith(".")) {
      throw new InvalidVaultPathError("trailing-space-or-dot", shapeOf(normalized));
    }
    const stem = part.split(".")[0].toLowerCase();
    if (WINDOWS_RESERVED.has(stem)) {
      throw new InvalidVaultPathError("windows-reserved", shapeOf(normalized));
    }
  }
  return normalized;
}
function tryCanonicalizeVaultPath(path) {
  try {
    return validateAndCanonicalizeVaultPath(path);
  } catch {
    return null;
  }
}
function platformCollisionKey(path) {
  return path.normalize("NFC").toLowerCase().split("/").map((part) => {
    const trimmed = part.replace(/[. ]+$/, "");
    const stem = trimmed.split(".")[0];
    return WINDOWS_RESERVED.has(stem) ? `\0reserved:${trimmed}` : trimmed;
  }).join("/");
}
function pathsCollide(a, b) {
  return a !== b && platformCollisionKey(a) === platformCollisionKey(b);
}

// src/sync/local-commit.ts
var CommitIntegrityError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "CommitIntegrityError";
  }
};
var RECOVERY_RETENTION_MS = 7 * 24 * 3600 * 1e3;
var NON_ATOMIC_REASON = "PLATFORM_NO_ATOMIC_REPLACE";
var LocalCommitter = class {
  constructor(app, pluginDir, log = () => {
  }) {
    this.app = app;
    this.pluginDir = pluginDir;
    this.log = log;
    this.locks = /* @__PURE__ */ new Map();
    /** 平台是否支持「rename 到不存在的目标」——移动端探测失败则退化 */
    this.renameSupported = null;
  }
  get stagingDir() {
    return `${this.pluginDir}/staging`;
  }
  get recoveryDir() {
    return `${this.pluginDir}/recovery`;
  }
  /**
   * 取某个路径的互斥锁并执行。
   *
   * 同一路径的提交严格串行；不同路径并发。锁按碰撞键取——在 Windows/macOS 上
   * `A.md` 与 `a.md` 是同一个文件，必须共享同一把锁。
   */
  async withPathLock(path, fn) {
    const key = path.normalize("NFC").toLowerCase();
    const prev = this.locks.get(key) ?? Promise.resolve();
    let release;
    const gate = new Promise((r) => release = r);
    this.locks.set(key, prev.then(() => gate));
    await prev.catch(() => {
    });
    try {
      return await fn();
    } finally {
      release();
      if (this.locks.get(key) === gate) this.locks.delete(key);
    }
  }
  /**
   * 提交一次远端内容到本地 Vault。
   *
   * **不**更新 FileState——身份字段的写入由调用方通过 store 的强类型转换完成
   * （§6.11），提交器只负责「安全地把字节放到正确的位置」。
   */
  async commitRemoteChange(req) {
    const actual = await sha256Hex(req.incoming);
    if (actual !== req.incomingHash) {
      throw new CommitIntegrityError(
        `The hash of the content to write does not match the declared value (expected ${req.incomingHash.slice(0, 12)}, actual ${actual.slice(0, 12)}…), refusing to write it locally`
      );
    }
    let path;
    try {
      path = validateAndCanonicalizeVaultPath(req.realPath);
    } catch (e) {
      if (!(e instanceof InvalidVaultPathError)) throw e;
      return { status: "rejected", reason: `Unsafe path: ${e.reason}` };
    }
    return this.withPathLock(path, () => this.commitLocked(req, path));
  }
  async commitLocked(req, path) {
    const adapter = this.app.vault.adapter;
    const stat = await adapter.stat(path);
    if (stat?.type === "folder") {
      return { status: "rejected", reason: "The target path is occupied by a local folder" };
    }
    const currentHash = stat ? await sha256Hex(await adapter.readBinary(path)) : null;
    if (currentHash !== req.expectedLocalHash) {
      this.log(`commit: precondition failed for ${path} (policy=${req.conflictPolicy})`);
      return {
        status: "precondition-failed",
        reason: currentHash === null ? "The local file was deleted" : "The local file was modified while this was being processed"
      };
    }
    if (!await this.canInstallAtomically() && currentHash !== null) {
      return {
        status: "rejected",
        reason: `${NON_ATOMIC_REASON}: this platform does not provide a reliable rename, so atomic install is impossible`
      };
    }
    const staging = `${this.stagingDir}/${req.operationId}`;
    await ensureParentFolder(adapter, staging);
    await adapter.writeBinary(staging, req.incoming);
    let recoveryPath;
    if (currentHash !== null) {
      recoveryPath = `${this.recoveryDir}/${req.operationId}`;
      await ensureParentFolder(adapter, recoveryPath);
      try {
        await adapter.rename(path, recoveryPath);
      } catch (e) {
        await this.discard(staging);
        throw new CommitIntegrityError(`Could not move the old content into the recovery area, this write was abandoned: ${String(e)}`);
      }
    }
    await evalFailpoint(FP.commitAfterRecovery);
    try {
      await ensureParentFolder(adapter, path);
      await evalFailpoint(FP.commitBeforeInstall);
      if (currentHash === null && !await this.canInstallAtomically()) {
        await adapter.writeBinary(path, req.incoming);
        await this.discard(staging);
      } else {
        await adapter.rename(staging, path);
      }
    } catch (e) {
      if (recoveryPath !== void 0) {
        try {
          await adapter.rename(recoveryPath, path);
        } catch {
          this.log(`commit: FAILED to restore ${path} from recovery — the old content is still at ${recoveryPath}`);
          throw new CommitIntegrityError(
            `The write failed and could not be rolled back; the old content is kept in the plugin's recovery directory (${req.operationId}\uFF09`
          );
        }
      }
      await this.discard(staging);
      throw e;
    }
    const after = await adapter.readBinary(path);
    const writtenHash = await sha256Hex(after);
    if (writtenHash !== req.incomingHash) {
      throw new CommitIntegrityError(`Read-back verification after writing failed (${path}), please check your disk space`);
    }
    if (req.incomingMtime !== void 0 && req.incomingMtime > 0) {
      try {
        await adapter.writeBinary(path, after, { mtime: req.incomingMtime });
      } catch {
      }
    }
    return { status: "committed", writtenHash, ...recoveryPath !== void 0 ? { recoveryPath } : {} };
  }
  /**
   * 探测本平台能否用 rename 安装（只探测一次）。
   *
   * # 探测的是「改名到一个空位」，因为安装做的就是这件事
   *
   * 安装流程是「先把旧内容挪进 recovery，再把 staging 改名过来」——
   * 目标路径在改名那一刻已经是空的。所以这里要探测的是
   * `rename(A → 不存在的 B)`，而**不是**「改名覆盖已存在的文件」。
   *
   * 这个区别很要紧：Windows 的 rename 不能覆盖已存在的文件，
   * 但先挪走再改名完全正常。按「能否覆盖」来探测会把所有 Windows 用户
   * 误判成不支持原子替换，于是每一次远端更新都退化成冲突副本——
   * 一个为了安全而加的检查，反过来把正常平台的同步毁掉。
   *
   * 探测同时校验改名后的**内容**，而不只是「目标存在」：一个把 rename
   * 实现成「创建空文件」的适配器，只查存在性是查不出来的。
   *
   * 桌面端不再跳过探测（v0.17 改）：以前直接假定桌面可用，于是这条路径
   * 在桌面上从来没被真正跑过——而网络盘、同步盘挂载的 Vault 就在桌面上。
   * 一次探测的代价是三个小文件操作，只在每个会话里发生一次。
   */
  async canInstallAtomically() {
    if (this.renameSupported !== null) return this.renameSupported;
    const adapter = this.app.vault.adapter;
    const probeA = `${this.stagingDir}/.probe-a`;
    const probeB = `${this.stagingDir}/.probe-b`;
    const marker = new Uint8Array([165]).buffer;
    try {
      await ensureParentFolder(adapter, probeA);
      await this.discard(probeB);
      await adapter.writeBinary(probeA, marker);
      await adapter.rename(probeA, probeB);
      const after = await adapter.readBinary(probeB);
      this.renameSupported = after.byteLength === 1 && new Uint8Array(after)[0] === 165;
    } catch {
      this.renameSupported = false;
    }
    await this.discard(probeA);
    await this.discard(probeB);
    if (!this.renameSupported) {
      this.log(
        "commit: this platform does not support a reliable rename. Overwriting writes degrade to keeping both versions — never a non-atomic overwrite: a power cut mid-write leaves half a file, and that half file is the user's only copy of the content"
      );
    }
    return this.renameSupported;
  }
  /**
   * 本平台是否支持原子替换（供 UI 与诊断使用；会触发一次探测）。
   *
   * 计划书 §8.8 门槛 11 要求「所有不可原子替换的平台都安全退化为 keep-both」。
   * 把这个判断暴露出来，是为了让「退化有没有发生」是可观测的，
   * 而不是只能从一堆冲突副本里反推。
   */
  async supportsAtomicReplace() {
    return this.canInstallAtomically();
  }
  async discard(path) {
    try {
      if (await this.app.vault.adapter.stat(path)) await this.app.vault.adapter.remove(path);
    } catch {
    }
  }
  /**
   * 清理过期的 staging 与 recovery（启动时调用一次）。
   *
   * staging 里的东西一律可丢（那是还没安装成功的副本）；
   * recovery 里是**被换下来的用户旧内容**，必须按保留期留够时间。
   */
  async sweep(now) {
    const adapter = this.app.vault.adapter;
    for (const [dir, retention] of [
      [this.stagingDir, 0],
      [this.recoveryDir, RECOVERY_RETENTION_MS]
    ]) {
      let listing;
      try {
        listing = await adapter.list(dir);
      } catch {
        continue;
      }
      for (const f of listing.files) {
        const st = await adapter.stat(f);
        if (st && now - st.mtime < retention) continue;
        await this.discard(f);
      }
    }
  }
};

// src/crypto/keyring.ts
var E2eeLockedError = class extends Error {
  constructor() {
    super("End-to-end encryption is enabled — please unlock first (Unlock E2EE)");
    this.name = "E2eeLockedError";
  }
};
var Keyring = class {
  constructor() {
    this.vmk = null;
    this.currentDoc = null;
    this.cachedMetaKeys = null;
  }
  get doc() {
    return this.currentDoc;
  }
  get enabled() {
    return this.currentDoc?.enabled === true;
  }
  get unlocked() {
    return this.vmk !== null;
  }
  get needsUnlock() {
    return this.enabled && !this.unlocked;
  }
  /** 更新文档；密钥材料变化时使已解锁的 VMK 失效。 */
  setDoc(doc) {
    const sameKeyMaterial = doc !== null && this.currentDoc !== null && doc.wrappedKey === this.currentDoc.wrappedKey && doc.salt === this.currentDoc.salt;
    this.currentDoc = doc;
    if (!sameKeyMaterial) {
      this.vmk = null;
      this.cachedMetaKeys = null;
    }
  }
  /** 迁移流程中直接采用已解锁的密钥。 */
  adopt(doc, vmk) {
    this.currentDoc = doc;
    this.vmk = vmk;
    this.cachedMetaKeys = null;
  }
  async unlock(password) {
    if (!this.currentDoc) return false;
    const key = await unlockVaultKey(this.currentDoc, password);
    if (!key) return false;
    this.vmk = key;
    this.cachedMetaKeys = null;
    return true;
  }
  /** 用 Trusted Device 恢复的原始 VMK 解锁（raw 由调用方负责清零）。 */
  async unlockWithRaw(raw) {
    this.vmk = await importVmk(raw);
    this.cachedMetaKeys = null;
  }
  lock() {
    this.vmk = null;
    this.cachedMetaKeys = null;
  }
  requireKey() {
    if (!this.vmk) throw new E2eeLockedError();
    return this.vmk;
  }
  /**
   * 元数据密钥（v9.3 三期）：HKDF 从 VMK 派生，懒加载缓存。
   * VMK 原始字节仅在派生瞬间存在，用完立即清零。
   */
  /** 重置凭证（v0.18）：未解锁返回 null（不该为了登记去打扰用户解锁）。 */
  async resetAuth() {
    if (!this.vmk) return null;
    const raw = await exportVmkRaw(this.vmk);
    try {
      return await deriveResetAuth(raw);
    } finally {
      raw.fill(0);
    }
  }
  async metaKeys() {
    if (!this.vmk) throw new E2eeLockedError();
    if (this.cachedMetaKeys) return this.cachedMetaKeys;
    const raw = await exportVmkRaw(this.vmk);
    try {
      this.cachedMetaKeys = await deriveMetaKeys(raw);
    } finally {
      raw.fill(0);
    }
    return this.cachedMetaKeys;
  }
};

// src/sync/queue.ts
function newOperationId() {
  const raw = new Uint8Array(12);
  crypto.getRandomValues(raw);
  let out = "";
  for (const b of raw) out += b.toString(16).padStart(2, "0");
  return out;
}
var PendingQueue = class {
  constructor() {
    this.map = /* @__PURE__ */ new Map();
    this.genCounter = 0;
    /** 持久化挂钩（main.ts 接到 store.state.pendingOps）。 */
    this.onChange = null;
    /**
     * 落盘挂钩（v0.13.2 / §6.3）：由 main.ts 接到 `store.save()`。
     * `add`/`addMove` 会等待它完成——只有落盘成功，这条操作才算被接受。
     */
    this.persist = null;
  }
  fireChange() {
    if (this.onChange) this.onChange(this.toRecord());
  }
  /**
   * 入队并**等待落盘**。
   *
   * 调用方 await 它之后，这条操作即使立刻断电也不会丢失。
   * 落盘失败时抛错并把条目回滚出队——绝不留下「内存里有、盘上没有」的假象，
   * 那会让用户以为改动已被接受。
   */
  async add(path, action, extra = {}) {
    this.stage(path, { action, ...extra });
    await this.flush(path);
  }
  /** 入队原子改名（key 为新路径）并等待落盘。 */
  async addMove(toPath, fromPath, extra = {}) {
    this.stage(toPath, { action: "move", from: fromPath, ...extra });
    await this.flush(toPath);
  }
  /**
   * 只入内存不等落盘（扫描等批量场景；调用方负责随后统一 `persist()`）。
   * 用于「本来就要在同一轮同步里立刻处理」的路径——它们不经过退出窗口。
   */
  stage(path, op) {
    {
      const entry = this.map.get(path);
      if (op.action === "upsert" && entry?.op.action === "move") {
        entry.gen = ++this.genCounter;
        this.fireChange();
        return;
      }
    }
    const prev = this.map.get(path)?.op;
    const sameOp = prev !== void 0 && prev.action === op.action && prev.from === op.from;
    this.map.set(path, {
      op: {
        operationId: (sameOp ? prev.operationId : void 0) ?? newOperationId(),
        createdAt: prev?.createdAt ?? Date.now(),
        attemptCount: sameOp ? prev.attemptCount ?? 0 : 0,
        status: "queued",
        // 对象身份与动作无关：同一路径仍指向同一个远端对象，必须保留
        ...prev?.fileId !== void 0 ? { fileId: prev.fileId } : {},
        ...prev?.serverPseudonym !== void 0 ? { serverPseudonym: prev.serverPseudonym } : {},
        ...op
      },
      gen: ++this.genCounter
    });
    this.fireChange();
  }
  async flush(path) {
    if (!this.persist) return;
    try {
      await evalFailpoint(FP.queueBeforeDurable);
      await this.persist();
      await evalFailpoint(FP.queueAfterDurable);
    } catch (e) {
      this.map.delete(path);
      this.fireChange();
      throw e;
    }
  }
  /** 记录一次尝试（重试计数与状态进入日志，便于诊断卡住的操作）。 */
  markAttempt(path, status, lastError) {
    const entry = this.map.get(path);
    if (!entry) return;
    entry.op.status = status;
    entry.op.attemptCount = (entry.op.attemptCount ?? 0) + 1;
    if (lastError !== void 0) entry.op.lastError = lastError;
    this.fireChange();
  }
  /** 补记该操作的身份信息（首次上传拿到 fileId 后调用，重试即可复用）。 */
  rememberIdentity(path, identity) {
    const entry = this.map.get(path);
    if (!entry) return;
    if (identity.fileId !== void 0) entry.op.fileId = identity.fileId;
    if (identity.serverPseudonym !== void 0) entry.op.serverPseudonym = identity.serverPseudonym;
    this.fireChange();
  }
  /**
   * 远端改名落地后，把同一对象上 pending 的本地改名意图跟着换基（验收 T3.4）。
   *
   * 场景：本机离线把 race.md 改成 race-d2.md（move op 的 from=race.md），
   * 上线后 pull 先应用了对端的改名 race.md → race-d1.md（tracked 已重键）。
   * 不换基的话，pushMove 按旧 from 找不到 tracked，只能退化为「新建对象」——
   * 服务器上凭空多出一份内容。换基后它变成 race-d1.md → race-d2.md 的正常
   * 改名：同一身份、无 tombstone、两台设备收敛到同一个名字。
   */
  rebaseMoveFrom(oldFrom, newFrom) {
    let rebased = 0;
    for (const entry of this.map.values()) {
      if (entry.op.action === "move" && entry.op.from === oldFrom) {
        entry.op.from = newFrom;
        rebased++;
        this.fireChange();
      }
    }
    return rebased;
  }
  /** 查看某路径当前排队的操作（不存在返回 undefined）。 */
  getOp(path) {
    return this.map.get(path)?.op;
  }
  /**
   * 移除条目。传入 gen 时只有 generation 未变才移除（处理完成路径必须用这个形式）；
   * 不传 gen 为无条件移除（仅用于「该路径已不再需要同步」的语义，如忽略规则命中）。
   */
  remove(path, gen) {
    if (gen !== void 0 && this.map.get(path)?.gen !== gen) return;
    this.map.delete(path);
    this.fireChange();
  }
  /** 返回当前快照（含 generation，不清空）。 */
  entries() {
    return [...this.map.entries()].map(([p, e]) => [p, e.op, e.gen]);
  }
  toRecord() {
    const out = {};
    for (const [p, e] of this.map.entries()) out[p] = e.op;
    return out;
  }
  /** 从持久化镜像恢复（插件启动时）；兼容 v9.2 之前的字符串形式。 */
  restore(entries) {
    for (const [path, raw] of Object.entries(entries)) {
      if (this.map.has(path)) continue;
      const op = typeof raw === "string" ? { action: raw } : raw;
      if (op.action !== "upsert" && op.action !== "delete" && op.action !== "move") continue;
      this.map.set(path, { op: { operationId: newOperationId(), ...op }, gen: ++this.genCounter });
    }
    this.fireChange();
  }
  get size() {
    return this.map.size;
  }
};

// src/sync/transfer.ts
function metaEncrypted(ctx) {
  return ctx.store.state.bootstrap.metaState === "encrypted";
}
var EnvelopeBindingMissingError = class extends Error {
  constructor(realPath) {
    super("Missing vaultId/keyEpoch binding material, so the upload was blocked (it never falls back to a weaker encryption envelope); the next sync will fill it in and retry");
    this.realPath = realPath;
    this.name = "EnvelopeBindingMissingError";
  }
};
var MetaPathUnresolvedError = class extends Error {
  constructor(realPath) {
    super(
      "This file has no known server pseudonym in the metadata-encrypted vault, so the request was blocked (the real path is never sent to the server); the next sync will reconcile first and retry"
    );
    this.realPath = realPath;
    this.name = "MetaPathUnresolvedError";
  }
};
var FileIdMismatchError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "FileIdMismatchError";
  }
};
var MetaGenerationRollbackError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "MetaGenerationRollbackError";
  }
};
var MetaForkError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "MetaForkError";
  }
};
function assertMetaGeneration(ctx, path, decMetaGeneration, fingerprint) {
  const tracked = ctx.store.get(path);
  const known = tracked?.metaGeneration;
  if (known === void 0) return "apply";
  if (decMetaGeneration < known) {
    const msg = `Metadata rollback detected (${path}): authenticated metaGeneration ${decMetaGeneration} < locally seen ${known}), sync stopped`;
    ctx.gate.markIntegrityError(msg);
    throw new MetaGenerationRollbackError(msg);
  }
  if (decMetaGeneration === known) {
    if (tracked?.metaFingerprint === void 0 || tracked.metaFingerprint === fingerprint) {
      return "idempotent";
    }
    const msg = `Two different contents at the same metadata generation (${path}\uFF1AmetaGeneration ${decMetaGeneration}), the server may be returning different results to different devices — sync stopped`;
    ctx.gate.markIntegrityError(msg);
    throw new MetaForkError(msg);
  }
  return "apply";
}
async function metaFingerprintOf(metaEnc) {
  return sha256Hex(encodeUtf8(metaEnc));
}
function serverPathOf(ctx, realPath) {
  if (!metaEncrypted(ctx)) return realPath;
  const tracked = ctx.store.get(realPath);
  const pseudonym = tracked?.serverPseudonym ?? tracked?.fileId;
  if (pseudonym === void 0) throw new MetaPathUnresolvedError(realPath);
  return pseudonym;
}
async function historyOf(ctx, realPath, serverPath) {
  return ctx.client.history(serverPath ?? serverPathOf(ctx, realPath));
}
async function purgeHistoryOf(ctx, realPath, beforeRevision) {
  return ctx.client.purgeHistory(serverPathOf(ctx, realPath), beforeRevision);
}
function e2eeBinding(ctx) {
  const b = ctx.store.state.bootstrap;
  if (!b.remoteVaultId || b.keyEpoch === void 0 || b.keyEpoch === 0) return void 0;
  return { vaultId: b.remoteVaultId, keyEpoch: requireKeyEpoch(b.keyEpoch, "bootstrap.keyEpoch") };
}
async function decode(ctx, path, dl, opts) {
  const cipherHash = await sha256Hex(dl.data);
  if (dl.hash && cipherHash !== dl.hash) {
    throw new Error(`downloaded content hash mismatch for ${path}`);
  }
  const fileId = optionalFileId(dl.fileId, `download(${path}).X-File-Id`);
  const metaGeneration = optionalGeneration(dl.metaGeneration, `download(${path}).X-Meta-Generation`);
  const trackedBefore = ctx.store.get(path);
  if (trackedBefore?.fileId !== void 0 && fileId !== void 0 && trackedBefore.fileId !== fileId) {
    const msg = `The server returned ${path} returned a different file identity (expected ${trackedBefore.fileId.slice(0, 8)}, actual ${fileId.slice(0, 8)}…), auto-sync for this vault has been stopped`;
    ctx.gate.markIntegrityError(msg);
    throw new FileIdMismatchError(msg);
  }
  if (opts.enforceGeneration && trackedBefore?.metaGeneration !== void 0 && metaGeneration !== void 0 && metaGeneration < trackedBefore.metaGeneration) {
    const msg = `Metadata rollback detected (${path}: server metaGeneration ${metaGeneration} < locally seen ${trackedBefore.metaGeneration}), sync stopped`;
    ctx.gate.markIntegrityError(msg);
    throw new MetaGenerationRollbackError(msg);
  }
  if (isLse3Envelope(dl.data) || isLse4Envelope(dl.data)) {
    if (!ctx.e2ee.unlocked) throw new E2eeLockedError();
    const bind = e2eeBinding(ctx);
    if (!bind?.vaultId || fileId === void 0) {
      throw new Error(`Cannot decrypt ${path} (missing vaultId/fileId binding material)`);
    }
    const dec = isLse4Envelope(dl.data) ? await decryptFileV4(ctx.e2ee.requireKey(), dl.data, bind.vaultId, fileId, bind.keyEpoch) : await decryptFileV3(ctx.e2ee.requireKey(), dl.data, bind.vaultId, fileId, bind.keyEpoch);
    if (dec === null) throw new Error(`Cannot decrypt ${path} (key mismatch, tampered data, or mismatched key epoch)`);
    if (opts.enforceGeneration) {
      const tracked = ctx.store.get(path);
      if (tracked?.fileId === fileId && tracked.generation !== void 0 && dec.generation < tracked.generation) {
        throw new Error(
          `Content rollback detected (${path}: server generation ${dec.generation} < locally seen ${tracked.generation}), sync stopped — the server may have been tampered with, or restored from a backup without rotating the epoch`
        );
      }
    }
    return {
      plain: dec.plain,
      plainHash: await sha256Hex(dec.plain),
      cipherHash,
      revision: dl.revision,
      mtime: dl.mtime,
      fileId,
      generation: dec.generation,
      metaEnc: dl.metaEnc,
      metaGeneration
    };
  }
  let plain = dl.data;
  if (isEncryptedPayload(dl.data)) {
    if (!ctx.e2ee.unlocked) throw new E2eeLockedError();
    const dec = await decryptFile(ctx.e2ee.requireKey(), path, dl.data, e2eeBinding(ctx));
    if (dec === null) throw new Error(`Cannot decrypt ${path} (key mismatch, tampered data, or mismatched key epoch)`);
    plain = dec;
  } else if (ctx.e2ee.enabled) {
    throw new Error(`E2EE is enabled but the server returned plaintext: ${path} (a plaintext write from an un-upgraded device may exist — sync stopped)`);
  }
  return {
    plain,
    plainHash: await sha256Hex(plain),
    cipherHash,
    revision: dl.revision,
    mtime: dl.mtime,
    fileId,
    metaEnc: dl.metaEnc,
    metaGeneration
  };
}
async function downloadPlain(ctx, path, serverPath) {
  const sp = serverPath ?? serverPathOf(ctx, path);
  return decode(ctx, path, await ctx.client.download(sp), { enforceGeneration: true });
}
async function versionPlain(ctx, path, revision, serverPath) {
  const sp = serverPath ?? serverPathOf(ctx, path);
  return decode(ctx, path, await ctx.client.version(sp, revision), { enforceGeneration: false });
}
async function removeRemote(ctx, path, baseRevision) {
  await ctx.client.remove(serverPathOf(ctx, path), baseRevision);
}
async function writeIfLocalUnchanged(ctx, path, data, expectedLocalHash, mtime, operationId) {
  const res = await ctx.committer.commitRemoteChange({
    operationId: operationId ?? newOperationId(),
    realPath: path,
    expectedLocalHash,
    incoming: data,
    incomingHash: await sha256Hex(data),
    conflictPolicy: "fail",
    ...mtime !== void 0 && mtime > 0 ? { incomingMtime: mtime } : {}
  });
  if (res.status === "rejected") {
    ctx.log(`commit rejected: ${res.reason}`);
    return false;
  }
  return res.status === "committed";
}
async function writeOrReportNonAtomic(ctx, path, data, expectedLocalHash, mtime, operationId) {
  const res = await ctx.committer.commitRemoteChange({
    operationId: operationId ?? newOperationId(),
    realPath: path,
    expectedLocalHash,
    incoming: data,
    incomingHash: await sha256Hex(data),
    conflictPolicy: "fail",
    ...mtime !== void 0 && mtime > 0 ? { incomingMtime: mtime } : {}
  });
  if (res.status === "committed") return "written";
  if (res.status === "rejected" && (res.reason ?? "").startsWith(NON_ATOMIC_REASON)) {
    ctx.log(`commit: ${path} degrades to keeping both versions (no atomic replace on this platform)`);
    return "non-atomic";
  }
  ctx.log(`commit not applied: ${path} (${res.status === "rejected" ? res.reason ?? "" : res.status})`);
  return "local-changed";
}
async function reserveFileId(ctx, path) {
  const reserved = ctx.queue.getOp(path)?.fileId;
  if (reserved !== void 0) return requireFileId(reserved, `reserved(${path}).fileId`);
  const fileId = newFileId();
  ctx.queue.rememberIdentity(path, { fileId });
  await ctx.store.save();
  return fileId;
}
async function uploadFromPlain(ctx, path, plain, baseRevision, mtime, action = "upsert", opts) {
  let payload = plain;
  let sendFileId;
  let generation;
  let serverPath = path;
  let meta;
  let metaGeneration;
  if (ctx.e2ee.enabled) {
    const bind = e2eeBinding(ctx);
    if (!bind) {
      throw new EnvelopeBindingMissingError(path);
    }
    {
      const tracked = ctx.store.get(path);
      const fileId = tracked?.fileId === void 0 ? await reserveFileId(ctx, path) : requireFileId(tracked.fileId, `upload(${path}).fileId`);
      const knownGen = tracked?.fileId === fileId ? tracked?.generation ?? 0 : 0;
      generation = Math.max(knownGen, opts?.generationFloor ?? 0) + 1;
      const binding3 = { vaultId: bind.vaultId, keyEpoch: bind.keyEpoch, fileId, generation };
      payload = ctx.padsSize(path) ? await encryptFileV4(ctx.e2ee.requireKey(), binding3, plain, true) : await encryptFileV3(ctx.e2ee.requireKey(), binding3, plain);
      sendFileId = fileId;
      if (metaEncrypted(ctx)) {
        serverPath = fileId;
        if (!tracked) {
          const keys = await ctx.e2ee.metaKeys();
          metaGeneration = 1;
          meta = {
            metaEnc: await encryptMeta(
              keys,
              { vaultId: bind.vaultId, keyEpoch: bind.keyEpoch, fileId, metaGeneration },
              { path }
            ),
            canonicalHash: await canonicalPathHmac(keys, path)
          };
        } else {
          metaGeneration = tracked.metaGeneration;
        }
      }
    }
  }
  const cipherHash = await sha256Hex(payload);
  const res = await ctx.client.upload(
    serverPath,
    baseRevision,
    cipherHash,
    payload,
    ctx.reportedMtime(mtime),
    action,
    sendFileId,
    meta
  );
  const confirmed = optionalFileId(res.fileId, `upload(${path}).fileId`) ?? sendFileId;
  if (sendFileId !== void 0 && confirmed !== sendFileId) {
    throw new Error(
      `The fileId returned by the server does not match the identity used for this encryption (${path}), sync stopped so that undecryptable content is not written`
    );
  }
  return {
    revision: res.revision,
    cipherHash,
    sequence: res.sequence,
    fileId: confirmed,
    generation,
    metaGeneration,
    serverPseudonym: metaEncrypted(ctx) ? serverPath : void 0
  };
}

// src/sync/conflict.ts
async function keepBothVersions(ctx, path, localData) {
  const adapter = ctx.app.vault.adapter;
  let conflictPath = conflictPathFor(path, ctx.deviceName(), /* @__PURE__ */ new Date());
  for (let i = 0; i < 5 && await adapter.stat(conflictPath); i++) {
    conflictPath = conflictPathFor(path, ctx.deviceName(), /* @__PURE__ */ new Date());
  }
  if (!await writeIfLocalUnchanged(ctx, conflictPath, localData, null)) {
    throw new Error(`Cannot create a conflict copy (the target already exists): ${conflictPath}`);
  }
  let dl;
  try {
    dl = await downloadPlain(ctx, path);
  } catch (e) {
    if (e instanceof NotFoundError) {
      await adapter.remove(conflictPath);
      return null;
    }
    if (e instanceof MetaPathUnresolvedError) {
      await adapter.remove(conflictPath);
      const tracked = ctx.store.get(path);
      ctx.store.setBlockedChange({
        sequence: ctx.store.state.lastSequence,
        action: "upsert",
        fileId: tracked?.fileId,
        revision: tracked?.revision,
        contentHash: tracked?.serverHash,
        contentGeneration: tracked?.generation,
        metaGeneration: tracked?.metaGeneration,
        realPath: path,
        reason: "The server pseudonym for this file has not been resolved in the metadata-encrypted vault"
      });
      ctx.notify(`Conflict deferred (the server pseudonym is not resolved yet): ${path}
Local content was not modified; the next sync will retry automatically`);
      return null;
    }
    throw e;
  }
  const localHash = await sha256Hex(localData);
  if (await writeIfLocalUnchanged(ctx, path, dl.plain, localHash, dl.mtime)) {
    const stat = await adapter.stat(path);
    ctx.store.update(path, {
      hash: dl.plainHash,
      serverHash: dl.cipherHash,
      revision: dl.revision,
      mtime: stat?.mtime ?? Date.now(),
      size: dl.plain.byteLength,
      fileId: dl.fileId,
      generation: dl.generation,
      metaGeneration: dl.metaGeneration
    });
  } else {
    ctx.log(`keepBoth: local changed during download of ${path}, keeping current content`);
  }
  ctx.queue.stage(conflictPath, { action: "upsert" });
  ctx.notify(`Sync conflict: ${path}
The local version was saved as ${conflictPath}`);
  return conflictPath;
}
async function keepIncomingAside(ctx, path, incoming) {
  const adapter = ctx.app.vault.adapter;
  let asidePath = conflictPathFor(path, "remote", /* @__PURE__ */ new Date());
  for (let i = 0; i < 5 && await adapter.stat(asidePath); i++) {
    asidePath = conflictPathFor(path, "remote", /* @__PURE__ */ new Date());
  }
  if (!await writeIfLocalUnchanged(ctx, asidePath, incoming, null)) {
    ctx.log(`keepIncomingAside: could not create a copy ${asidePath}`);
    return null;
  }
  ctx.queue.stage(asidePath, { action: "upsert" });
  return asidePath;
}

// src/sync/pull.ts
var import_obsidian2 = require("obsidian");

// src/merge/diff.ts
var DiffTooLargeError = class extends Error {
  constructor() {
    super("diff too large");
    this.name = "DiffTooLargeError";
  }
};
var MAX_LINES = 2e5;
var MAX_EDIT_DISTANCE = 2e3;
function splitLines(text) {
  return text.split("\n");
}
function diffHunks(a, b) {
  if (a.length + b.length > MAX_LINES) throw new DiffTooLargeError();
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }
  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);
  if (midA.length === 0 && midB.length === 0) return [];
  if (midA.length === 0) return [{ aStart: start, aEnd: start, bStart: start, bEnd: start + midB.length }];
  if (midB.length === 0) return [{ aStart: start, aEnd: start + midA.length, bStart: start, bEnd: start }];
  const ops = myers(midA, midB);
  const hunks = [];
  let ca = start;
  let cb = start;
  let cur = null;
  for (const op of ops) {
    if (op === "same") {
      if (cur) {
        hunks.push(cur);
        cur = null;
      }
      ca++;
      cb++;
    } else if (op === "del") {
      cur ?? (cur = { aStart: ca, aEnd: ca, bStart: cb, bEnd: cb });
      cur.aEnd = ++ca;
    } else {
      cur ?? (cur = { aStart: ca, aEnd: ca, bStart: cb, bEnd: cb });
      cur.bEnd = ++cb;
    }
  }
  if (cur) hunks.push(cur);
  return hunks;
}
function myers(a, b) {
  const n = a.length;
  const m = b.length;
  const maxD = Math.min(n + m, MAX_EDIT_DISTANCE);
  const offset = maxD;
  const width = 2 * maxD + 1;
  let v = new Int32Array(width);
  const trace = [];
  let found = false;
  for (let d = 0; d <= maxD; d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x2;
      if (k === -d || k !== d && v[offset + k - 1] < v[offset + k + 1]) {
        x2 = v[offset + k + 1];
      } else {
        x2 = v[offset + k - 1] + 1;
      }
      let y2 = x2 - k;
      while (x2 < n && y2 < m && a[x2] === b[y2]) {
        x2++;
        y2++;
      }
      v[offset + k] = x2;
      if (x2 >= n && y2 >= m) {
        found = true;
        break;
      }
    }
    if (found) break;
  }
  if (!found) throw new DiffTooLargeError();
  const ops = [];
  let x = n;
  let y = m;
  for (let d = trace.length - 1; d >= 0; d--) {
    const vd = trace[d];
    const k = x - y;
    let prevK;
    if (k === -d || k !== d && vd[offset + k - 1] < vd[offset + k + 1]) {
      prevK = k + 1;
    } else {
      prevK = k - 1;
    }
    const prevX = vd[offset + prevK];
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      ops.push("same");
      x--;
      y--;
    }
    if (d > 0) {
      if (x === prevX) {
        ops.push("ins");
        y--;
      } else {
        ops.push("del");
        x--;
      }
    }
    x = prevX;
    y = prevY;
  }
  return ops.reverse();
}
function diffLinesView(aText, bText) {
  const a = splitLines(aText);
  const b = splitLines(bText);
  const hunks = diffHunks(a, b);
  const out = [];
  let ca = 0;
  let cb = 0;
  for (const h of hunks) {
    while (ca < h.aStart) {
      out.push({ type: "same", text: a[ca] });
      ca++;
      cb++;
    }
    for (; ca < h.aEnd; ca++) out.push({ type: "del", text: a[ca] });
    for (; cb < h.bEnd; cb++) out.push({ type: "add", text: b[cb] });
  }
  while (ca < a.length) {
    out.push({ type: "same", text: a[ca] });
    ca++;
    cb++;
  }
  return out;
}

// src/merge/markdown/frontmatter.ts
var KEY_LINE = /^([A-Za-z0-9_][A-Za-z0-9_ ./-]*):(?:\s|$)/;
var LIST_ITEM = /^\s+-\s+(.*)$/;
function splitFrontmatter(text) {
  if (!text.startsWith("---\n") && text !== "---") return { fm: null, body: text };
  const end = text.indexOf("\n---", 3);
  if (end < 0) return { fm: null, body: text };
  const after = end + 4;
  if (after < text.length && text[after] !== "\n") return { fm: null, body: text };
  return {
    fm: text.slice(4, end + 1),
    // 含结尾换行，不含围栏
    body: text.slice(after < text.length ? after + 1 : after)
  };
}
function parseFmBlocks(fm) {
  const blocks = [];
  const seen = /* @__PURE__ */ new Set();
  let current = null;
  const lines = fm.split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  for (const line of lines) {
    const m = KEY_LINE.exec(line);
    if (m) {
      const key = m[1].trim();
      if (seen.has(key)) return null;
      seen.add(key);
      current = { key, lines: [line] };
      blocks.push(current);
    } else if (line.trim() === "" || /^\s/.test(line)) {
      if (!current) {
        if (line.trim() === "") continue;
        return null;
      }
      current.lines.push(line);
    } else {
      return null;
    }
  }
  return blocks;
}
function blockText(b) {
  return b.lines.join("\n");
}
function listItems(b) {
  if (b.lines.length < 2) return null;
  if (b.lines[0].trim() !== `${b.key}:`) return null;
  const items = [];
  for (const line of b.lines.slice(1)) {
    const m = LIST_ITEM.exec(line);
    if (!m) return null;
    items.push(m[1].trim());
  }
  return items;
}
function mergeListBlocks(key, base, local, remote) {
  const baseItems = base ? listItems(base) : [];
  const localItems = listItems(local);
  const remoteItems = listItems(remote);
  if (baseItems === null || localItems === null || remoteItems === null) return null;
  for (const arr of [baseItems, localItems, remoteItems]) {
    if (new Set(arr).size !== arr.length) return null;
  }
  const localSet = new Set(localItems);
  const remoteSet = new Set(remoteItems);
  const baseSet = new Set(baseItems);
  const out = [];
  for (const item of baseItems) {
    if (localSet.has(item) && remoteSet.has(item)) out.push(item);
  }
  for (const item of localItems) {
    if (!baseSet.has(item) && !out.includes(item)) out.push(item);
  }
  for (const item of remoteItems) {
    if (!baseSet.has(item) && !out.includes(item)) out.push(item);
  }
  return { key, lines: [`${key}:`, ...out.map((it) => `  - ${it}`)] };
}
function mergeFrontmatter(baseFm, localFm, remoteFm) {
  const baseBlocks = parseFmBlocks(baseFm);
  const localBlocks = parseFmBlocks(localFm);
  const remoteBlocks = parseFmBlocks(remoteFm);
  if (baseBlocks === null || localBlocks === null || remoteBlocks === null) return null;
  const baseMap = new Map(baseBlocks.map((b) => [b.key, b]));
  const localMap = new Map(localBlocks.map((b) => [b.key, b]));
  const remoteMap = new Map(remoteBlocks.map((b) => [b.key, b]));
  const merged = [];
  const emitted = /* @__PURE__ */ new Set();
  const mergeKey = (key) => {
    const b = baseMap.get(key) ?? null;
    const l = localMap.get(key) ?? null;
    const r = remoteMap.get(key) ?? null;
    const bt = b ? blockText(b) : null;
    const lt = l ? blockText(l) : null;
    const rt = r ? blockText(r) : null;
    if (lt === rt) return l;
    if (lt === bt) return r;
    if (rt === bt) return l;
    if (l && r) {
      const lm = mergeListBlocks(key, b, l, r);
      if (lm) return lm;
    }
    return "conflict";
  };
  const orderedKeys = [];
  for (const b of baseBlocks) orderedKeys.push(b.key);
  for (const b of localBlocks) if (!baseMap.has(b.key)) orderedKeys.push(b.key);
  for (const b of remoteBlocks) if (!baseMap.has(b.key) && !localMap.has(b.key)) orderedKeys.push(b.key);
  for (const key of orderedKeys) {
    if (emitted.has(key)) continue;
    emitted.add(key);
    const result = mergeKey(key);
    if (result === "conflict") return null;
    if (result !== null) merged.push(result);
  }
  if (merged.length === 0) return "";
  return merged.map(blockText).join("\n") + "\n";
}

// src/merge/markdown/sections.ts
var HEADING = /^(#{1,6})\s+(.*)$/;
var FENCE = /^(```|~~~)/;
function splitSections(lines) {
  const sections = [];
  const ancestry = [];
  let inFence = false;
  let fenceMarker = "";
  let start = 0;
  let currentPath = "";
  const flush = (end) => {
    if (end > start) sections.push({ path: currentPath, start, end });
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (inFence) {
      if (line.startsWith(fenceMarker)) inFence = false;
      continue;
    }
    const fence = FENCE.exec(line);
    if (fence) {
      inFence = true;
      fenceMarker = fence[1];
      continue;
    }
    const h = HEADING.exec(line);
    if (h) {
      flush(i);
      const level = h[1].length;
      while (ancestry.length > 0 && ancestry[ancestry.length - 1].level >= level) ancestry.pop();
      ancestry.push({ level, title: h[2].trim() });
      currentPath = ancestry.map((a) => a.title).join(" / ");
      start = i;
    }
  }
  flush(lines.length);
  return sections;
}
function alignSections(base, local, remote) {
  const sb = splitSections(base);
  const sl = splitSections(local);
  const sr = splitSections(remote);
  if (sb.length < 2) return null;
  if (sb.length !== sl.length || sb.length !== sr.length) return null;
  for (let i = 0; i < sb.length; i++) {
    if (sb[i].path !== sl[i].path || sb[i].path !== sr[i].path) return null;
  }
  return sb.map((b, i) => ({ base: b, local: sl[i], remote: sr[i] }));
}

// src/merge/markdown/lists.ts
var ITEM = /^([-*+]|\d+[.)])\s+(\[[ xX]\]\s+)?(.*)$/;
function parseItems(lines) {
  const items = [];
  const seen = /* @__PURE__ */ new Set();
  for (const line of lines) {
    if (/^\s/.test(line)) return null;
    const m = ITEM.exec(line);
    if (!m) return null;
    const isTask = m[2] !== void 0;
    const checked = isTask && /x/i.test(m[2]);
    const id = `${m[1]} ${m[3]}`;
    if (seen.has(id)) return null;
    seen.add(id);
    items.push({ id, line, isTask, checked });
  }
  return items;
}
function renderItem(it, checked) {
  if (!it.isTask) return it.line;
  return it.line.replace(/\[[ xX]\]/, checked ? "[x]" : "[ ]");
}
function tryMergeListBlock(baseLines, localLines, remoteLines) {
  const base = parseItems(baseLines);
  const local = parseItems(localLines);
  const remote = parseItems(remoteLines);
  if (base === null || local === null || remote === null) return null;
  const baseMap = new Map(base.map((it) => [it.id, it]));
  const remoteMap = new Map(remote.map((it) => [it.id, it]));
  const out = [];
  const emitted = /* @__PURE__ */ new Set();
  for (const it of local) {
    const b = baseMap.get(it.id);
    const r = remoteMap.get(it.id);
    if (b && !r) {
      if (it.line === b.line) continue;
      return null;
    }
    emitted.add(it.id);
    if (!b) {
      out.push(it.line);
      continue;
    }
    const localChanged = it.line !== b.line;
    const remoteChanged = r.line !== b.line;
    if (localChanged && remoteChanged && it.line !== r.line) return null;
    out.push(localChanged ? renderItem(it, it.checked) : renderItem(r, r.checked));
  }
  for (const it of remote) {
    if (emitted.has(it.id)) continue;
    const b = baseMap.get(it.id);
    if (!b) {
      out.push(it.line);
      continue;
    }
    if (it.line !== b.line) return null;
  }
  return out;
}

// src/merge/three-way.ts
function mergePieces(base, local, remote) {
  const hunks = [
    ...diffHunks(base, local).map((h) => ({ ...h, side: "local" })),
    ...diffHunks(base, remote).map((h) => ({ ...h, side: "remote" }))
  ].sort((a, b) => a.aStart - b.aStart || a.aEnd - b.aEnd);
  const pieces = [];
  let cursor = 0;
  let i = 0;
  while (i < hunks.length) {
    let regionStart = hunks[i].aStart;
    let regionEnd = hunks[i].aEnd;
    const group = [hunks[i]];
    let j = i + 1;
    while (j < hunks.length) {
      const h = hunks[j];
      const strictOverlap = h.aStart < regionEnd;
      const boundaryInsert = h.aStart === regionEnd && (h.aStart === h.aEnd || regionStart === regionEnd);
      if (strictOverlap || boundaryInsert) {
        group.push(h);
        regionEnd = Math.max(regionEnd, h.aEnd);
        j++;
      } else {
        break;
      }
    }
    i = j;
    if (cursor < regionStart) {
      pieces.push({ kind: "lines", lines: base.slice(cursor, regionStart) });
    }
    const localHunks = group.filter((h) => h.side === "local");
    const remoteHunks = group.filter((h) => h.side === "remote");
    const localLines = applySide(base, regionStart, regionEnd, localHunks, local);
    const remoteLines = applySide(base, regionStart, regionEnd, remoteHunks, remote);
    if (localHunks.length === 0) {
      pieces.push({ kind: "lines", lines: remoteLines });
    } else if (remoteHunks.length === 0) {
      pieces.push({ kind: "lines", lines: localLines });
    } else if (sameLines(localLines, remoteLines)) {
      pieces.push({ kind: "lines", lines: localLines });
    } else {
      pieces.push({
        kind: "conflict",
        baseStart: regionStart,
        baseEnd: regionEnd,
        baseLines: base.slice(regionStart, regionEnd),
        localLines,
        remoteLines
      });
    }
    cursor = regionEnd;
  }
  if (cursor < base.length) {
    pieces.push({ kind: "lines", lines: base.slice(cursor) });
  }
  return pieces;
}
function assembleResolution(segments, choices) {
  const out = [];
  for (const s of segments) {
    if (s.type === "text") {
      out.push(...s.text.split("\n"));
    } else {
      const chosen = choices[s.conflict.id];
      if (chosen === void 0) throw new Error(`conflict ${s.conflict.id} unresolved`);
      if (chosen !== "") out.push(...chosen.split("\n"));
    }
  }
  return out.join("\n");
}
function applySide(base, regionStart, regionEnd, sideHunks, sideLines) {
  const out = [];
  let pos = regionStart;
  for (const h of sideHunks) {
    for (; pos < h.aStart; pos++) out.push(base[pos]);
    for (let bi = h.bStart; bi < h.bEnd; bi++) out.push(sideLines[bi]);
    pos = h.aEnd;
  }
  for (; pos < regionEnd; pos++) out.push(base[pos]);
  return out;
}
function sameLines(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// src/merge/token/tokenize.ts
var LATIN = /[A-Za-z0-9_]/;
function tokenize(text) {
  const tokens = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === "\n") {
      tokens.push("\n");
      i++;
      continue;
    }
    if (c === " " || c === "	" || c === "\r") {
      let j = i + 1;
      while (j < n && (text[j] === " " || text[j] === "	" || text[j] === "\r")) j++;
      tokens.push(text.slice(i, j));
      i = j;
      continue;
    }
    if (LATIN.test(c)) {
      let j = i + 1;
      while (j < n && LATIN.test(text[j])) j++;
      tokens.push(text.slice(i, j));
      i = j;
      continue;
    }
    const ch = String.fromCodePoint(text.codePointAt(i));
    tokens.push(ch);
    i += ch.length;
  }
  return tokens;
}

// src/merge/token/three-way-token.ts
var MAX_TOKEN_TEXT = 2e4;
function tokenThreeWayMerge(base, local, remote) {
  if (base.length > MAX_TOKEN_TEXT || local.length > MAX_TOKEN_TEXT || remote.length > MAX_TOKEN_TEXT) {
    return null;
  }
  try {
    const pieces = mergePieces(tokenize(base), tokenize(local), tokenize(remote));
    const out = [];
    for (const p of pieces) {
      if (p.kind === "conflict") return null;
      out.push(...p.lines);
    }
    return out.join("");
  } catch (e) {
    if (e instanceof DiffTooLargeError) return null;
    throw e;
  }
}

// src/merge/smart-merge.ts
function smartThreeWayMerge(input) {
  let { base, local, remote } = input;
  const fb = splitFrontmatter(base);
  const fl = splitFrontmatter(local);
  const fr = splitFrontmatter(remote);
  if (fb.fm !== null || fl.fm !== null || fr.fm !== null) {
    const mergedFm = mergeFrontmatter(fb.fm ?? "", fl.fm ?? "", fr.fm ?? "");
    if (mergedFm !== null) {
      const prefix = mergedFm === "" ? "" : `---
${mergedFm}---
`;
      base = prefix + fb.body;
      local = prefix + fl.body;
      remote = prefix + fr.body;
    }
  }
  const baseLines = splitLines(base);
  const localLines = splitLines(local);
  const remoteLines = splitLines(remote);
  const aligned = alignSections(baseLines, localLines, remoteLines);
  const pieces = [];
  if (aligned) {
    for (const seg of aligned) {
      const segPieces = mergePieces(
        baseLines.slice(seg.base.start, seg.base.end),
        localLines.slice(seg.local.start, seg.local.end),
        remoteLines.slice(seg.remote.start, seg.remote.end)
      );
      for (const p of segPieces) {
        if (p.kind === "conflict") {
          pieces.push({ ...p, baseStart: p.baseStart + seg.base.start, baseEnd: p.baseEnd + seg.base.start });
        } else {
          pieces.push(p);
        }
      }
    }
  } else {
    pieces.push(...mergePieces(baseLines, localLines, remoteLines));
  }
  let autoResolved = 0;
  const processed = [];
  for (const p of pieces) {
    if (p.kind !== "conflict") {
      processed.push(p);
      continue;
    }
    const resolved = resolveConflictPiece(p);
    if (resolved.lines !== null) {
      autoResolved++;
      processed.push({ kind: "lines", lines: resolved.lines });
    } else {
      processed.push({ kind: "smart-conflict", conflict: resolved.conflict });
    }
  }
  const segments = [];
  const conflicts = [];
  const mergedLines = [];
  let seq = 0;
  for (const p of processed) {
    if (p.kind === "lines") {
      if (p.lines.length > 0) {
        appendText(segments, mergedLines, p.lines);
      }
    } else if (p.kind === "smart-conflict") {
      const conflict = { id: `c${++seq}`, ...p.conflict };
      conflicts.push(conflict);
      segments.push({ type: "conflict", conflict });
      if (conflict.localText !== "") mergedLines.push(...conflict.localText.split("\n"));
    }
  }
  return {
    clean: conflicts.length === 0,
    mergedText: mergedLines.join("\n"),
    conflicts,
    segments,
    stats: { autoResolved }
  };
}
function appendText(segments, mergedLines, lines) {
  mergedLines.push(...lines);
  const last = segments[segments.length - 1];
  if (last && last.type === "text") {
    last.text = last.text === "" ? lines.join("\n") : `${last.text}
${lines.join("\n")}`;
  } else {
    segments.push({ type: "text", text: lines.join("\n") });
  }
}
function resolveConflictPiece(p) {
  const listMerged = tryMergeListBlock(p.baseLines, p.localLines, p.remoteLines);
  if (listMerged !== null) return { lines: listMerged };
  const tokenMerged = tokenThreeWayMerge(
    p.baseLines.join("\n"),
    p.localLines.join("\n"),
    p.remoteLines.join("\n")
  );
  if (tokenMerged !== null) return { lines: tokenMerged === "" ? [] : tokenMerged.split("\n") };
  const conflict = {
    baseStart: p.baseStart,
    baseEnd: p.baseEnd,
    baseText: p.baseLines.join("\n"),
    localText: p.localLines.join("\n"),
    remoteText: p.remoteLines.join("\n"),
    kind: "text"
  };
  if (p.localLines.length === 0 && p.remoteLines.length > 0 && p.baseLines.length > 0) {
    conflict.kind = "delete-edit";
    conflict.suggestedText = conflict.remoteText;
    conflict.confidence = "medium";
    conflict.reason = "The local side deleted this hunk and the remote side changed it — keeping the remote change is suggested (no information is lost)";
  } else if (p.remoteLines.length === 0 && p.localLines.length > 0 && p.baseLines.length > 0) {
    conflict.kind = "delete-edit";
    conflict.suggestedText = conflict.localText;
    conflict.confidence = "medium";
    conflict.reason = "The remote side deleted this hunk and the local side changed it — keeping the local change is suggested (no information is lost)";
  }
  return { lines: null, conflict };
}

// src/sync/auto-merge.ts
var MAX_MERGE_ATTEMPTS = 3;
function eligibleForTextMerge(path) {
  return path.toLowerCase().endsWith(".md");
}
async function attemptAutoMerge(ctx, path, localData, tracked) {
  try {
    if (!eligibleForTextMerge(path)) return "fallback";
    if (!tracked) return "fallback";
    const localText = decodeUtf8Strict(localData);
    if (localText === null) return "fallback";
    const localHash = await sha256Hex(localData);
    let baseText;
    try {
      const base = await versionPlain(ctx, path, tracked.revision);
      const t = decodeUtf8Strict(base.plain);
      if (t === null) return "fallback";
      baseText = t;
    } catch (e) {
      if (e instanceof E2eeLockedError) throw e;
      return "fallback";
    }
    for (let attempt = 0; attempt < MAX_MERGE_ATTEMPTS; attempt++) {
      const remote = await downloadPlain(ctx, path);
      const remoteText = decodeUtf8Strict(remote.plain);
      if (remoteText === null) return "fallback";
      if (remote.plainHash === localHash) {
        const stat = await ctx.app.vault.adapter.stat(path);
        ctx.store.update(path, {
          hash: localHash,
          serverHash: remote.cipherHash,
          revision: remote.revision,
          mtime: stat?.mtime ?? Date.now(),
          size: localData.byteLength,
          fileId: remote.fileId,
          generation: remote.generation,
          metaGeneration: remote.metaGeneration
        });
        return "merged";
      }
      const result = smartThreeWayMerge({ base: baseText, local: localText, remote: remoteText });
      if (!result.clean) {
        ctx.store.recordConflict(path, {
          baseRevision: tracked.revision,
          remoteRevision: remote.revision,
          createdAt: Date.now()
        });
        ctx.log(
          `auto-merge: structured conflicts on ${path} (${result.conflicts.length} hunks, ${result.stats?.autoResolved ?? 0} auto-resolved)`
        );
        return "pending";
      }
      const mergedData = encodeUtf8(result.mergedText);
      const mergedHash = await sha256Hex(mergedData);
      try {
        const out = await uploadFromPlain(ctx, path, mergedData, remote.revision, Date.now(), "merge", {
          generationFloor: remote.generation
        });
        const wrote = await writeIfLocalUnchanged(ctx, path, mergedData, localHash);
        if (!wrote) {
          ctx.log(`auto-merge: local changed during merge of ${path}, keeping newer local content`);
          return "merged";
        }
        const stat = await ctx.app.vault.adapter.stat(path);
        ctx.store.update(path, {
          hash: mergedHash,
          serverHash: out.cipherHash,
          revision: out.revision,
          mtime: stat?.mtime ?? Date.now(),
          size: mergedData.byteLength,
          fileId: out.fileId,
          generation: out.generation,
          metaGeneration: out.metaGeneration,
          serverPseudonym: out.serverPseudonym
        });
        ctx.notify(`Auto-merged: ${path}`);
        ctx.log(`auto-merge: ${path} \u2192 rev ${out.revision} (attempt ${attempt + 1})`);
        return "merged";
      } catch (e) {
        if (e instanceof ConflictError) continue;
        throw e;
      }
    }
    ctx.log(`auto-merge: gave up after ${MAX_MERGE_ATTEMPTS} attempts on ${path}`);
    return "fallback";
  } catch (e) {
    if (e instanceof E2eeLockedError) throw e;
    ctx.log(`auto-merge error on ${path}: ${e instanceof Error ? e.message : String(e)}`);
    return "fallback";
  }
}

// src/sync/pull.ts
var HEX32 = /^[0-9a-f]{32}$/;
async function resolveMetaChange(ctx, change) {
  const pseudonym = requireFileId(change.path, `change@${change.sequence}.path`);
  const known = ctx.store.pathByFileId(pseudonym);
  if (known !== void 0) return { realPath: known, serverPath: pseudonym };
  if (change.action === "delete") return "skip";
  let meta;
  try {
    meta = await ctx.client.getFileMeta(pseudonym);
  } catch (e) {
    if (e instanceof NotFoundError) return "skip";
    throw e;
  }
  if (!meta.metaEnc) throw new Error(`In meta mode the server returned no encrypted metadata: ${pseudonym}`);
  const bind = ctx.store.state.bootstrap;
  const keys = await ctx.e2ee.metaKeys();
  const dec = await decryptMeta(keys, meta.metaEnc, bind.remoteVaultId ?? "", pseudonym);
  if (dec === null) throw new Error(`Cannot decrypt file metadata (${pseudonym}): key mismatch or tampered data — sync stopped`);
  const safe = requireSafeRemotePath(ctx, dec.meta.path, {
    sequence: change.sequence,
    action: "upsert",
    // delete 已在上面提前返回
    fileId: pseudonym,
    serverPseudonym: pseudonym,
    revision: change.revision,
    contentHash: change.hash,
    metaGeneration: change.metaGeneration ?? dec.metaGeneration
  });
  if (safe === null) return "blocked";
  return { realPath: safe, serverPath: pseudonym };
}
function requireSafeRemotePath(ctx, path, rec) {
  try {
    return validateAndCanonicalizeVaultPath(path);
  } catch (e) {
    if (!(e instanceof InvalidVaultPathError)) throw e;
    ctx.store.setBlockedChange({ ...rec, realPath: "", reason: `Unsafe remote path: ${e.reason}` });
    ctx.log(`pull: rejected unsafe remote path (${e.reason}, ${e.shape})`);
    ctx.notify(`Refused an unsafe remote path (${e.reason}), sync continues; check the versions on other devices`);
    return null;
  }
}
async function tryResolveNameSwap(ctx, realPath, newPath, pseudonym, metaGeneration, fingerprint) {
  const occupant = ctx.store.get(newPath);
  const occupantPseudonym = occupant?.serverPseudonym ?? occupant?.fileId;
  if (!occupant || occupantPseudonym === void 0 || occupantPseudonym === pseudonym) return null;
  let occupantTarget;
  let occupantMetaGeneration;
  let occupantFingerprint;
  try {
    const meta = await ctx.client.getFileMeta(occupantPseudonym);
    const keys = await ctx.e2ee.metaKeys();
    const vaultId = ctx.store.state.bootstrap.remoteVaultId ?? "";
    const dec = await decryptMeta(keys, meta.metaEnc, vaultId, occupantPseudonym);
    if (dec === null) return null;
    occupantTarget = dec.meta.path;
    occupantMetaGeneration = dec.metaGeneration;
    occupantFingerprint = await metaFingerprintOf(meta.metaEnc);
  } catch {
    return null;
  }
  if (occupantTarget !== realPath) return null;
  const adapter = ctx.app.vault.adapter;
  const temp = `${ctx.pluginDir()}/swap/${pseudonym}`;
  ctx.store.setPendingSwap({ tempPath: temp, fileId: pseudonym, targetPath: newPath, sourcePath: realPath });
  await ctx.store.save();
  try {
    await ensureParentFolder(adapter, temp);
    await adapter.rename(realPath, temp);
    await evalFailpoint(FP.swapAfterFirstStep);
    await ensureParentFolder(adapter, realPath);
    await adapter.rename(newPath, realPath);
    await ensureParentFolder(adapter, newPath);
    await adapter.rename(temp, newPath);
  } catch (e) {
    ctx.log(`swap: swapping ${realPath} \u2194 ${newPath} failed: ${String(e)} (the temp copy is kept in the plugin directory and resumed next round)`);
    return "blocked";
  }
  ctx.store.clearPendingSwap(temp);
  const mine = ctx.store.get(realPath);
  const theirs = ctx.store.get(newPath);
  ctx.store.markDeleted(realPath);
  ctx.store.markDeleted(newPath);
  ctx.store.replaceWithNewObject(newPath, {
    ...mine,
    metaGeneration,
    metaFingerprint: fingerprint,
    serverPseudonym: pseudonym
  });
  ctx.store.replaceWithNewObject(realPath, {
    ...theirs,
    metaGeneration: occupantMetaGeneration,
    metaFingerprint: occupantFingerprint,
    serverPseudonym: occupantPseudonym
  });
  await ctx.store.save();
  ctx.log(`pull: swapped ${realPath} <-> ${newPath} via ${temp}`);
  return "applied";
}
async function recoverInterruptedSwaps(ctx) {
  const adapter = ctx.app.vault.adapter;
  for (const swap of ctx.store.pendingSwaps()) {
    if (!await adapter.stat(swap.tempPath)) {
      ctx.store.clearPendingSwap(swap.tempPath);
      continue;
    }
    const target = await adapter.stat(swap.targetPath) ? null : swap.targetPath;
    if (target === null) {
      if (swap.sourcePath !== void 0 && !await adapter.stat(swap.sourcePath)) {
        await ensureParentFolder(adapter, swap.sourcePath);
        await adapter.rename(swap.tempPath, swap.sourcePath);
        ctx.store.clearPendingSwap(swap.tempPath);
        ctx.log(`swap: ${swap.targetPath} is occupied, the temp copy was put back at ${swap.sourcePath}`);
        continue;
      }
      ctx.log(`swap: ${swap.targetPath} is still occupied, the temp copy is kept (retry next round)`);
      continue;
    }
    await ensureParentFolder(adapter, target);
    await adapter.rename(swap.tempPath, target);
    ctx.store.clearPendingSwap(swap.tempPath);
    ctx.log(`swap: resumed the interrupted swap → ${target}`);
  }
  await ctx.store.save();
}
async function renameLocalFile(ctx, fromPath, toPath, fileId) {
  const adapter = ctx.app.vault.adapter;
  const occupied = await adapter.stat(toPath);
  if (!occupied) {
    await ensureParentFolder(adapter, toPath);
    await adapter.rename(fromPath, toPath);
    return "renamed";
  }
  if (ctx.store.get(toPath) !== void 0 || !pathsCollide(fromPath, toPath)) {
    return "occupied";
  }
  const temp = `${ctx.pluginDir()}/swap/${fileId ?? newOperationId()}`;
  ctx.store.setPendingSwap({ tempPath: temp, fileId: fileId ?? "", targetPath: toPath, sourcePath: fromPath });
  await ctx.store.save();
  await ensureParentFolder(adapter, temp);
  await adapter.rename(fromPath, temp);
  if (await adapter.stat(toPath)) {
    await adapter.rename(temp, fromPath);
    ctx.store.clearPendingSwap(temp);
    await ctx.store.save();
    return "occupied";
  }
  await ensureParentFolder(adapter, toPath);
  await adapter.rename(temp, toPath);
  ctx.store.clearPendingSwap(temp);
  await ctx.store.save();
  return "renamed";
}
async function applyPlainRename(ctx, fromPath, toPath, change, occupantTargets) {
  const tracked = ctx.store.get(fromPath);
  if (!tracked) return "skipped";
  if (tracked.metaGeneration !== void 0 && change.metaGeneration !== void 0 && change.metaGeneration < tracked.metaGeneration) {
    return "skipped";
  }
  const adapter = ctx.app.vault.adapter;
  if (!await adapter.stat(fromPath)) {
    ctx.store.applyMetaRenameState(fromPath, toPath, { metaGeneration: change.metaGeneration });
    if (ctx.queue.rebaseMoveFrom(fromPath, toPath) > 0) {
      ctx.notify(`Another device renamed ${fromPath} renamed to ${toPath}; the local rename continues from that, and the local name wins in the end`);
    }
    return "applied";
  }
  const occupant = ctx.store.get(toPath);
  if (occupant !== void 0 && await adapter.stat(toPath)) {
    const occupantTarget = occupant.fileId !== void 0 ? occupantTargets?.get(occupant.fileId) : void 0;
    if (occupantTarget === fromPath) {
      return applyPlainSwap(ctx, fromPath, toPath, change);
    }
  }
  if (await renameLocalFile(ctx, fromPath, toPath, change.fileId ?? tracked.fileId) === "occupied") {
    ctx.store.setBlockedChange({
      sequence: change.sequence,
      action: "rename",
      fileId: change.fileId ?? tracked.fileId,
      revision: change.revision ?? tracked.revision,
      contentHash: change.hash ?? tracked.serverHash,
      contentGeneration: tracked.generation,
      metaGeneration: change.metaGeneration,
      realPath: toPath,
      renameFrom: fromPath,
      renameTo: toPath,
      reason: "The remote rename target is occupied by a local file"
    });
    ctx.notify(`Remote renamed ${fromPath} renamed to ${toPath}, but the target already exists locally — deferred`);
    return "blocked";
  }
  ctx.store.applyMetaRenameState(fromPath, toPath, { metaGeneration: change.metaGeneration });
  ctx.queue.rebaseMoveFrom(fromPath, toPath);
  ctx.log(`pull: renamed ${fromPath} -> ${toPath}`);
  return "applied";
}
async function applyPlainSwap(ctx, realPath, newPath, change) {
  const adapter = ctx.app.vault.adapter;
  const temp = `${ctx.pluginDir()}/swap/${change.fileId ?? newOperationId()}`;
  ctx.store.setPendingSwap({ tempPath: temp, fileId: change.fileId ?? "", targetPath: newPath, sourcePath: realPath });
  await ctx.store.save();
  try {
    await ensureParentFolder(adapter, temp);
    await adapter.rename(realPath, temp);
    await evalFailpoint(FP.swapAfterFirstStep);
    await ensureParentFolder(adapter, realPath);
    await adapter.rename(newPath, realPath);
    await ensureParentFolder(adapter, newPath);
    await adapter.rename(temp, newPath);
  } catch (e) {
    ctx.log(`swap: swapping ${realPath} \u2194 ${newPath} failed: ${String(e)} (the temp copy is kept in the plugin directory and resumed next round)`);
    return "blocked";
  }
  ctx.store.clearPendingSwap(temp);
  const mine = ctx.store.get(realPath);
  const theirs = ctx.store.get(newPath);
  ctx.store.markDeleted(realPath);
  ctx.store.markDeleted(newPath);
  ctx.store.replaceWithNewObject(newPath, { ...mine, metaGeneration: change.metaGeneration });
  ctx.store.replaceWithNewObject(realPath, { ...theirs });
  await ctx.store.save();
  ctx.log(`pull: swapped ${realPath} <-> ${newPath} via ${temp}`);
  return "applied";
}
async function applyMetaRename(ctx, realPath, pseudonym, sequence) {
  const tracked = ctx.store.get(realPath);
  if (!tracked) return "skipped";
  const meta = await ctx.client.getFileMeta(pseudonym);
  const bind = ctx.store.state.bootstrap;
  const keys = await ctx.e2ee.metaKeys();
  const dec = await decryptMeta(keys, meta.metaEnc, bind.remoteVaultId ?? "", pseudonym);
  if (dec === null) throw new Error(`Cannot decrypt file metadata (${pseudonym}\uFF09`);
  const fingerprint = await metaFingerprintOf(meta.metaEnc);
  if (assertMetaGeneration(ctx, realPath, dec.metaGeneration, fingerprint) === "idempotent") {
    return "skipped";
  }
  const newPath = requireSafeRemotePath(ctx, dec.meta.path, {
    sequence,
    action: "rename",
    fileId: tracked.fileId,
    serverPseudonym: pseudonym,
    metaGeneration: dec.metaGeneration,
    renameFrom: realPath
  });
  if (newPath === null) return "blocked";
  if (newPath === realPath) {
    ctx.store.applyRemoteIdentity(realPath, {
      metaGeneration: dec.metaGeneration,
      metaFingerprint: fingerprint,
      serverPseudonym: pseudonym
    });
    return "skipped";
  }
  const adapter = ctx.app.vault.adapter;
  const registerBlocked = () => {
    ctx.store.setBlockedChange({
      sequence,
      action: "rename",
      fileId: tracked.fileId,
      serverPseudonym: pseudonym,
      revision: tracked.revision,
      contentHash: tracked.serverHash,
      contentGeneration: tracked.generation,
      metaGeneration: dec.metaGeneration,
      realPath,
      renameFrom: realPath,
      renameTo: newPath,
      reason: "The remote rename target is occupied by a local file"
    });
    ctx.notify(`Remote renamed ${realPath} renamed to ${newPath}, but the target already exists locally — deferred`);
    return "blocked";
  };
  const occupiedByOther = await adapter.stat(newPath) !== null && (ctx.store.get(newPath) !== void 0 || !pathsCollide(realPath, newPath));
  if (occupiedByOther) {
    const swapped = await tryResolveNameSwap(ctx, realPath, newPath, pseudonym, dec.metaGeneration, fingerprint);
    if (swapped !== null) return swapped;
    return registerBlocked();
  }
  if (!await adapter.stat(realPath)) {
    ctx.store.applyMetaRenameState(realPath, newPath, {
      metaGeneration: dec.metaGeneration,
      metaFingerprint: fingerprint,
      serverPseudonym: pseudonym
    });
    if (ctx.queue.rebaseMoveFrom(realPath, newPath) > 0) {
      ctx.notify(`Another device renamed ${realPath} renamed to ${newPath}; the local rename continues from that, and the local name wins in the end`);
    }
    return "applied";
  }
  if (await renameLocalFile(ctx, realPath, newPath, tracked.fileId) === "occupied") {
    return registerBlocked();
  }
  ctx.store.applyMetaRenameState(realPath, newPath, {
    metaGeneration: dec.metaGeneration,
    metaFingerprint: fingerprint,
    serverPseudonym: pseudonym
  });
  ctx.queue.rebaseMoveFrom(realPath, newPath);
  ctx.log(`pull: renamed ${realPath} -> ${newPath} (metaGen ${dec.metaGeneration})`);
  return "applied";
}
var RepoEpochChangedError = class extends Error {
  constructor() {
    super("The server's sequence epoch (repoEpoch) has changed — this device needs to rejoin");
    this.name = "RepoEpochChangedError";
  }
};
async function guardRepoEpoch(ctx, serverEpoch) {
  if (!serverEpoch) return;
  const saved = ctx.store.state.bootstrap.repoEpoch;
  if (!saved) {
    ctx.store.state.bootstrap.repoEpoch = serverEpoch;
    return;
  }
  if (saved !== serverEpoch) {
    ctx.store.enterRecovery({
      reason: "repo-epoch-changed",
      previousEpoch: saved,
      serverEpoch,
      localSequence: ctx.store.state.lastSequence,
      localFileCount: ctx.store.paths().length,
      at: Date.now()
    });
    ctx.store.resetBootstrap();
    ctx.store.clearBinding();
    ctx.store.state.lastSequence = 0;
    await ctx.store.save();
    ctx.notify(
      "The server's data was restored from a backup (repoEpoch changed) and auto-sync is paused.\nPlease re-run the setup wizard and choose \"safe merge\" — newer local content will not be lost"
    );
    throw new RepoEpochChangedError();
  }
}
async function pullRemoteChanges(ctx) {
  const result = { applied: 0, conflicts: 0 };
  try {
    await retryBlockedChanges(ctx, result);
    for (; ; ) {
      const resp = await ctx.client.changes(ctx.store.state.lastSequence, 500);
      await guardRepoEpoch(ctx, resp.repoEpoch);
      if (resp.resyncRequired) {
        ctx.log(
          `resync required (cursor ${ctx.store.state.lastSequence} < min ${resp.minSequence ?? 0})`
        );
        const r = await resyncFromSnapshot(ctx);
        result.applied += r.applied;
        result.conflicts += r.conflicts;
        break;
      }
      if (resp.changes.length === 0 && resp.latestSequence < ctx.store.state.lastSequence) {
        ctx.log(
          `server head ${resp.latestSequence} < cursor ${ctx.store.state.lastSequence}, forcing snapshot reconcile`
        );
        const r = await resyncFromSnapshot(ctx);
        result.applied += r.applied;
        result.conflicts += r.conflicts;
        break;
      }
      if (resp.changes.length === 0) {
        if (resp.latestSequence > ctx.store.state.lastSequence) {
          ctx.store.state.lastSequence = resp.latestSequence;
        }
        break;
      }
      for (const change of resp.changes) {
        const note = {};
        const outcome = await applyRemoteChange(ctx, change, note);
        await evalFailpoint(FP.cursorBeforeAck);
        if (outcome === "applied") result.applied++;
        if (outcome === "conflict") result.conflicts++;
        ctx.store.recordSequenceEvidence({
          sequence: change.sequence,
          outcome,
          ...outcome === "skipped" ? { reason: note.reason ?? "unspecified" } : {},
          at: Date.now()
        });
        if (outcome === "blocked") {
          await ctx.store.save();
        }
        ctx.store.state.lastSequence = change.sequence;
      }
      if (!resp.hasMore) break;
    }
  } finally {
    await ctx.store.save();
  }
  return result;
}
async function retryBlockedChanges(ctx, result) {
  for (const [key, rec] of ctx.store.blockedChanges()) {
    if (rec.realPath !== "" && (await ctx.app.vault.adapter.stat(rec.realPath))?.type === "folder") continue;
    let outcome;
    if (rec.action === "rename" && rec.serverPseudonym && rec.renameFrom) {
      outcome = await applyMetaRename(ctx, rec.renameFrom, rec.serverPseudonym, rec.sequence);
    } else if (rec.action === "rename" && rec.renameFrom && rec.renameTo) {
      outcome = await applyPlainRename(ctx, rec.renameFrom, rec.renameTo, {
        sequence: rec.sequence,
        fileId: rec.fileId,
        revision: rec.revision,
        hash: rec.contentHash,
        metaGeneration: rec.metaGeneration
      });
    } else {
      const replayPath = rec.serverPseudonym ?? rec.realPath;
      if (replayPath === "") {
        continue;
      }
      outcome = await applyRemoteChange(ctx, {
        sequence: rec.sequence,
        path: replayPath,
        action: rec.action === "delete" ? "delete" : "upsert",
        revision: rec.revision ?? 0,
        ...rec.fileId !== void 0 ? { fileId: rec.fileId } : {},
        ...rec.contentHash !== void 0 ? { hash: rec.contentHash } : {},
        ...rec.metaGeneration !== void 0 ? { metaGeneration: rec.metaGeneration } : {}
      });
    }
    if (outcome !== "blocked") ctx.store.clearBlockedChange(key);
    if (outcome === "applied") result.applied++;
    if (outcome === "conflict") result.conflicts++;
  }
}
async function resyncFromSnapshot(ctx) {
  const result = { applied: 0, conflicts: 0 };
  const snap = await ctx.client.snapshot();
  await guardRepoEpoch(ctx, snap.repoEpoch);
  const files = await resolveSnapshotPaths(ctx, snap.files, snap.sequence);
  const snapPaths = new Set(files.map((f) => f.path));
  const snapTargets = /* @__PURE__ */ new Map();
  for (const f of files) {
    if (f.fileId) snapTargets.set(f.fileId, f.path);
  }
  for (const path of ctx.store.paths()) {
    if (ctx.ignores(path) || snapPaths.has(path)) continue;
    const tracked = ctx.store.get(path);
    if (tracked?.fileId !== void 0 && snapTargets.has(tracked.fileId)) continue;
    const outcome = await applyRemoteChange(ctx, {
      sequence: snap.sequence,
      path: metaEncrypted(ctx) && tracked?.fileId ? tracked.fileId : path,
      action: "delete",
      revision: 0
    });
    if (outcome === "applied") result.applied++;
    if (outcome === "conflict") result.conflicts++;
  }
  for (const f of files) {
    if (ctx.ignores(f.path)) continue;
    if (f.fileId) {
      const existing = ctx.store.pathByFileId(f.fileId);
      if (existing !== void 0 && existing !== f.path) {
        const outcome2 = f.serverPseudonym ? await applyMetaRename(ctx, existing, f.serverPseudonym, snap.sequence) : await applyPlainRename(
          ctx,
          existing,
          f.path,
          {
            sequence: snap.sequence,
            fileId: f.fileId,
            revision: f.revision,
            hash: f.hash,
            metaGeneration: f.metaGeneration
          },
          snapTargets
        );
        if (outcome2 === "applied") result.applied++;
        if (outcome2 === "blocked") continue;
      }
    }
    const tracked = ctx.store.get(f.path);
    if (tracked && tracked.serverHash === f.hash) {
      if (tracked.revision !== f.revision || tracked.metaGeneration !== f.metaGeneration) {
        ctx.store.applyRemoteIdentity(f.path, {
          metaGeneration: f.metaGeneration,
          metaFingerprint: f.metaFingerprint,
          fileId: f.fileId,
          serverPseudonym: f.serverPseudonym
        });
        ctx.store.patchContentState(f.path, { revision: f.revision });
      }
      continue;
    }
    const outcome = await applyRemoteChange(ctx, {
      sequence: snap.sequence,
      path: f.serverPseudonym ?? f.path,
      action: "upsert",
      revision: f.revision,
      hash: f.hash,
      metaGeneration: f.metaGeneration
    });
    if (outcome === "applied") result.applied++;
    if (outcome === "conflict") result.conflicts++;
  }
  ctx.store.state.lastSequence = snap.sequence;
  await ctx.store.save();
  ctx.notify("The server's change log has been rotated — a full reconciliation was completed via a snapshot");
  return result;
}
async function resolveSnapshotPaths(ctx, files, sequence = 0) {
  if (!files.some((f) => f.metaEnc)) return files;
  const vaultId = ctx.store.state.bootstrap.remoteVaultId ?? "";
  const keys = await ctx.e2ee.metaKeys();
  const out = [];
  for (const f of files) {
    if (!f.metaEnc || !f.fileId) {
      out.push(f);
      continue;
    }
    const dec = await decryptMeta(keys, f.metaEnc, vaultId, f.fileId);
    if (dec === null) {
      throw new Error(`Cannot decrypt file metadata (${f.fileId}): key mismatch or tampered data — sync stopped`);
    }
    const safe = requireSafeRemotePath(ctx, dec.meta.path, {
      sequence,
      action: "upsert",
      fileId: f.fileId,
      serverPseudonym: f.fileId,
      revision: f.revision,
      contentHash: f.hash,
      metaGeneration: dec.metaGeneration
    });
    if (safe === null) continue;
    out.push({
      ...f,
      path: safe,
      metaGeneration: dec.metaGeneration,
      metaFingerprint: await metaFingerprintOf(f.metaEnc),
      serverPseudonym: f.fileId
    });
  }
  return out;
}
function skip(note, reason) {
  if (note) note.reason = reason;
  return "skipped";
}
async function applyRemoteChange(ctx, change, note) {
  let path = change.path;
  let serverPath;
  if (metaEncrypted(ctx) && HEX32.test(change.path)) {
    const resolved = await resolveMetaChange(ctx, change);
    if (resolved === "blocked") return "blocked";
    if (resolved === "skip" || resolved === null) return skip(note, "meta-change-not-applicable");
    path = resolved.realPath;
    serverPath = resolved.serverPath;
    const tracked2 = ctx.store.get(path);
    if (change.action === "upsert" && tracked2 && (change.metaGeneration ?? 0) > (tracked2.metaGeneration ?? 0)) {
      const renameOnly = change.hash !== void 0 && change.hash === tracked2.serverHash;
      const ren = await applyMetaRename(ctx, path, resolved.serverPath, change.sequence);
      if (renameOnly || ren === "blocked") return ren;
      path = ctx.store.pathByFileId(resolved.serverPath) ?? path;
    }
  } else {
    const safe = requireSafeRemotePath(ctx, path, {
      sequence: change.sequence,
      action: change.action === "delete" ? "delete" : "upsert",
      fileId: change.fileId,
      revision: change.revision,
      contentHash: change.hash,
      metaGeneration: change.metaGeneration
    });
    if (safe === null) return "blocked";
    path = safe;
    if (change.action !== "delete" && change.fileId !== void 0) {
      const existing = ctx.store.pathByFileId(change.fileId);
      if (existing !== void 0 && existing !== path) {
        const existingState = ctx.store.get(existing);
        if (existingState?.serverPseudonym === change.path) {
          path = existing;
          serverPath = change.path;
        } else {
          const ren = await applyPlainRename(ctx, existing, path, change);
          if (ren === "blocked") return "blocked";
          if (ren === "skipped") return skip(note, "stale-rename-change");
          const moved = ctx.store.get(path);
          if (change.hash !== void 0 && change.hash === moved?.serverHash) {
            if (moved) ctx.store.update(path, { revision: change.revision });
            return ren;
          }
        }
      }
    }
  }
  if (ctx.ignores(path)) return skip(note, "ignored-by-rules");
  if (ctx.store.getConflict(path)) return skip(note, "frozen-by-pending-conflict");
  if (change.action !== "delete") {
    const collides = ctx.store.collidingPath(path, serverPath ?? change.fileId ?? ctx.store.get(path)?.fileId);
    if (collides !== void 0) {
      ctx.store.setBlockedChange({
        sequence: change.sequence,
        action: "upsert",
        fileId: serverPath,
        serverPseudonym: serverPath,
        revision: change.revision,
        contentHash: change.hash,
        metaGeneration: change.metaGeneration,
        realPath: path,
        reason: `Collides with an existing file on this platform (${collides}\uFF09`
      });
      ctx.notify(`Deferred: ${path} and the existing local ${collides} are the same file name on this platform\nRename it on any device and it will recover automatically`);
      return "blocked";
    }
  }
  const adapter = ctx.app.vault.adapter;
  const stat = await adapter.stat(path);
  if (stat?.type === "folder") {
    ctx.store.setBlockedChange({
      sequence: change.sequence,
      action: change.action === "delete" ? "delete" : "upsert",
      fileId: serverPath ?? ctx.store.get(path)?.fileId,
      serverPseudonym: serverPath,
      revision: change.revision,
      contentHash: change.hash,
      metaGeneration: change.metaGeneration,
      realPath: path,
      reason: "Remote file has the same name as a local folder"
    });
    ctx.notify(`Deferred: remote file has the same name as a local folder ${path}
Move the folder aside and it will be filled in automatically`);
    return "blocked";
  }
  const tracked = ctx.store.get(path);
  if (change.action === "delete") {
    if (!stat) {
      ctx.store.markDeleted(path);
      ctx.store.clearPendingDelete(path);
      return skip(note, "delete-of-untracked-file");
    }
    const localData2 = await adapter.readBinary(path);
    const localHash2 = await sha256Hex(localData2);
    if (tracked && localHash2 === tracked.hash) {
      if (await trashLocal(ctx.app, path)) {
        ctx.store.markDeleted(path);
        ctx.log(`pull: deleted ${path}`);
        return "applied";
      }
      ctx.store.markDeleted(path);
      ctx.store.setPendingDelete(path);
      ctx.notify(`Could not move to the trash, local file kept (it will not be re-uploaded): ${path}
Delete it manually`);
      return "applied";
    }
    ctx.store.markDeleted(path);
    ctx.queue.stage(path, { action: "upsert" });
    ctx.notify(`Deleted on the remote but modified locally — local file kept: ${path}`);
    return "conflict";
  }
  if (tracked && change.hash && change.hash === tracked.serverHash) {
    ctx.store.update(path, { revision: change.revision, serverPseudonym: serverPath });
    return skip(note, "content-already-known");
  }
  let localHash = null;
  let localData = null;
  if (stat) {
    const data = await adapter.readBinary(path);
    localData = data;
    localHash = await sha256Hex(data);
  }
  if (localHash !== null && change.hash && localHash === change.hash) {
    ctx.store.update(path, {
      hash: localHash,
      serverHash: change.hash,
      revision: change.revision,
      mtime: stat?.mtime ?? Date.now(),
      size: stat?.size ?? localData.byteLength,
      serverPseudonym: serverPath
    });
    return skip(note, "local-content-already-identical");
  }
  const localChanged = stat !== null && (!tracked || localHash !== tracked.hash);
  if (!stat || !localChanged) {
    let dl;
    try {
      dl = await downloadPlain(ctx, path, serverPath);
    } catch (e) {
      if (e instanceof NotFoundError) return skip(note, "deleted-by-later-change");
      throw e;
    }
    const wrote = await writeOrReportNonAtomic(ctx, path, dl.plain, localHash, dl.mtime);
    if (wrote === "non-atomic") {
      const kept2 = await keepIncomingAside(ctx, path, dl.plain);
      if (kept2 === null) return skip(note, "non-atomic-keep-both-failed");
      ctx.notify(
        `${path}: this device does not support atomic replace, so the remote version was saved as ${kept2}, the original file is unchanged. Please compare and merge them by hand.`
      );
      return "conflict";
    }
    if (wrote === "written") {
      const st = await adapter.stat(path);
      ctx.store.update(path, {
        hash: dl.plainHash,
        serverHash: dl.cipherHash,
        revision: dl.revision,
        mtime: st?.mtime ?? Date.now(),
        size: dl.plain.byteLength,
        fileId: dl.fileId,
        generation: dl.generation,
        metaGeneration: dl.metaGeneration ?? change.metaGeneration,
        serverPseudonym: serverPath
      });
      ctx.log(`pull: downloaded ${path} (rev ${dl.revision})`);
      return "applied";
    }
    ctx.log(`pull: local changed during download of ${path}, rerouting to merge`);
    const curStat = await adapter.stat(path);
    if (!curStat) return skip(note, "removed-locally-during-download");
    localData = await adapter.readBinary(path);
  }
  const merged = await attemptAutoMerge(ctx, path, localData, tracked);
  if (merged === "merged") return "applied";
  if (merged === "pending") {
    ctx.notify(`Sync conflict: ${path}
Run "Resolve conflicts" to handle it`);
    return "conflict";
  }
  const kept = await keepBothVersions(ctx, path, localData);
  return kept === null ? "skipped" : "conflict";
}
async function trashLocal(app, path) {
  const adapter = app.vault.adapter;
  try {
    const af = app.vault.getAbstractFileByPath(path);
    if (af) {
      await app.fileManager.trashFile(af);
      return true;
    }
    if (!import_obsidian2.Platform.isMobileApp && await adapter.trashSystem(path)) return true;
    await adapter.trashLocal(path);
    return true;
  } catch {
    return false;
  }
}

// src/sync/push.ts
var import_obsidian3 = require("obsidian");
async function scanLocalChanges(ctx) {
  const seen = /* @__PURE__ */ new Set();
  const moveFroms = /* @__PURE__ */ new Set();
  for (const [, op] of ctx.queue.entries()) {
    if (op.action === "move" && op.from) moveFroms.add(op.from);
  }
  for (const path of Object.keys(ctx.store.state.pendingDeletes)) {
    if (!await ctx.app.vault.adapter.stat(path)) ctx.store.clearPendingDelete(path);
  }
  for (const file of ctx.app.vault.getFiles()) {
    const path = file.path;
    if (ctx.ignores(path) || ctx.store.hasPendingDelete(path)) continue;
    seen.add(path);
    if (ctx.queue.getOp(path)?.action === "move") continue;
    const tracked = ctx.store.get(path);
    if (!tracked || tracked.mtime !== file.stat.mtime || tracked.size !== file.stat.size) {
      ctx.queue.stage(path, { action: "upsert" });
    }
  }
  if (ctx.syncObsidian()) {
    for (const path of await listHiddenFiles(ctx, ctx.app.vault.configDir)) {
      if (ctx.ignores(path) || ctx.store.hasPendingDelete(path)) continue;
      seen.add(path);
      if (ctx.queue.getOp(path)?.action === "move") continue;
      const stat = await ctx.app.vault.adapter.stat(path);
      if (!stat) continue;
      const tracked = ctx.store.get(path);
      if (!tracked || tracked.mtime !== stat.mtime || tracked.size !== stat.size) {
        ctx.queue.stage(path, { action: "upsert" });
      }
    }
  }
  for (const path of ctx.store.paths()) {
    if (ctx.ignores(path) || seen.has(path) || moveFroms.has(path)) continue;
    ctx.queue.stage(path, { action: "delete" });
  }
}
async function listHiddenFiles(ctx, dir) {
  const out = [];
  const walk = async (d) => {
    if (ctx.ignores(d)) return;
    let listing;
    try {
      listing = await ctx.app.vault.adapter.list(d);
    } catch {
      return;
    }
    out.push(...listing.files);
    for (const sub of listing.folders) await walk(sub);
  };
  await walk(dir);
  return out;
}
async function pushPendingChanges(ctx) {
  const result = { pushed: 0, conflicts: 0 };
  try {
    for (const [path, op, gen] of ctx.queue.entries()) {
      if (ctx.ignores(path)) {
        ctx.queue.remove(path);
        continue;
      }
      let outcome;
      switch (op.action) {
        case "upsert":
          outcome = await pushUpsert(ctx, path);
          break;
        case "delete":
          outcome = await pushDelete(ctx, path);
          break;
        case "move":
          outcome = await pushMove(ctx, path, op.from ?? "");
          break;
      }
      if (outcome === "pushed") result.pushed++;
      if (outcome === "conflict") result.conflicts++;
      ctx.queue.remove(path, gen);
    }
  } finally {
    await ctx.store.save();
  }
  return result;
}
async function pushMove(ctx, toPath, fromPath) {
  const adapter = ctx.app.vault.adapter;
  const tracked = fromPath ? ctx.store.get(fromPath) : void 0;
  const stat = await adapter.stat(toPath);
  const degrade = async () => {
    let outcome = "skipped";
    if (stat) {
      const u = await pushUpsert(ctx, toPath);
      if (u === "pushed") outcome = "pushed";
      if (u === "conflict") outcome = "conflict";
      const landed = (ctx.store.get(toPath)?.revision ?? 0) > 0;
      if (!landed) {
        ctx.log(`move degrade: ${toPath} did not land on the server, keeping the old object`);
        return outcome;
      }
    }
    if (tracked && !await adapter.stat(fromPath)) {
      const d = await pushDelete(ctx, fromPath);
      if (d === "conflict") outcome = "conflict";
    }
    return outcome;
  };
  if (!tracked || !stat || ctx.store.getConflict(fromPath) || ctx.store.getConflict(toPath)) {
    return degrade();
  }
  const data = await adapter.readBinary(toPath);
  const hash = await sha256Hex(data);
  const contentChanged = hash !== tracked.hash;
  const meta = await renameMetadata(ctx, tracked, toPath);
  if (meta === "unavailable") return degrade();
  const serverFrom = metaEncrypted(ctx) ? serverPathOf(ctx, fromPath) : fromPath;
  const serverTo = metaEncrypted(ctx) ? serverFrom : toPath;
  try {
    const out = await ctx.client.rename(serverFrom, serverTo, tracked.metaGeneration ?? 0, meta);
    ctx.store.applyMetaRenameState(fromPath, toPath, {
      mtime: stat.mtime,
      size: stat.size,
      revision: out.revision,
      metaGeneration: out.metaGeneration,
      fileId: out.fileId,
      serverPseudonym: metaEncrypted(ctx) ? out.toPath : void 0
    });
    ctx.log(`push: renamed ${fromPath} -> ${toPath} (metaGen ${out.metaGeneration})`);
    if (!contentChanged) return "pushed";
    const u = await pushUpsert(ctx, toPath);
    return u === "conflict" ? "conflict" : "pushed";
  } catch (e) {
    if (e instanceof ConflictError || e instanceof NotFoundError) {
      return reconcileFailedRename(ctx, fromPath, toPath, degrade);
    }
    if (e instanceof ApiError && (e.status === 400 || e.status === 404 || e.status === 412 || e.status === 422)) {
      return reconcileFailedRename(ctx, fromPath, toPath, degrade);
    }
    throw e;
  }
}
async function reconcileFailedRename(ctx, fromPath, toPath, degrade) {
  const tracked = ctx.store.get(fromPath);
  if (!tracked || !metaEncrypted(ctx) || !tracked.serverPseudonym) return degrade();
  let remotePath;
  let remoteMetaGeneration;
  let fingerprint;
  try {
    const meta = await ctx.client.getFileMeta(tracked.serverPseudonym);
    const bind = e2eeBinding(ctx);
    const keys = await ctx.e2ee.metaKeys();
    const dec = await decryptMeta(keys, meta.metaEnc, bind?.vaultId ?? "", tracked.serverPseudonym);
    if (dec === null) throw new Error("Metadata cannot be decrypted");
    remotePath = dec.meta.path;
    remoteMetaGeneration = dec.metaGeneration;
    fingerprint = await metaFingerprintOf(meta.metaEnc);
  } catch (e) {
    if (e instanceof E2eeLockedError) throw e;
    ctx.log(`rename reconcile: could not read the server state (${String(e)} → degrades to create-then-delete`);
    return degrade();
  }
  if (remotePath === toPath) {
    ctx.store.applyMetaRenameState(fromPath, toPath, {
      metaGeneration: remoteMetaGeneration,
      metaFingerprint: fingerprint
    });
    ctx.log(`rename reconcile: the remote was renamed to ${toPath}, accepted`);
    return "skipped";
  }
  if (remoteMetaGeneration > (tracked.metaGeneration ?? 0)) {
    ctx.store.applyRemoteIdentity(fromPath, {
      metaGeneration: remoteMetaGeneration,
      metaFingerprint: fingerprint
    });
    ctx.notify(`Another device renamed this file to ${remotePath}, this rename did not take effect — the next sync will align`);
    return "conflict";
  }
  return degrade();
}
async function renameMetadata(ctx, tracked, toPath) {
  if (!metaEncrypted(ctx)) return void 0;
  const bind = e2eeBinding(ctx);
  if (!bind || !tracked.fileId || tracked.metaGeneration === void 0) return "unavailable";
  const keys = await ctx.e2ee.metaKeys();
  const newGen = tracked.metaGeneration + 1;
  return {
    metaEnc: await encryptMeta(
      keys,
      { vaultId: bind.vaultId, keyEpoch: bind.keyEpoch, fileId: tracked.fileId, metaGeneration: newGen },
      { path: toPath }
    ),
    canonicalHash: await canonicalPathHmac(keys, toPath)
  };
}
async function restoreObject(ctx, path, server) {
  if (!server.fileId) return null;
  const tracked = ctx.store.get(path);
  const nextGen = Math.max(server.contentGeneration ?? 0, tracked?.generation ?? 0) + 1;
  let meta;
  let pseudonym = path;
  if (metaEncrypted(ctx)) {
    const bind = e2eeBinding(ctx);
    if (!bind) return null;
    const keys = await ctx.e2ee.metaKeys();
    pseudonym = server.fileId;
    meta = {
      metaEnc: await encryptMeta(
        keys,
        { vaultId: bind.vaultId, keyEpoch: bind.keyEpoch, fileId: server.fileId, metaGeneration: 1 },
        { path }
      ),
      canonicalHash: await canonicalPathHmac(keys, path)
    };
  }
  const out = await ctx.client.restore(server.fileId, {
    expectedTombstoneRevision: server.revision,
    contentGeneration: nextGen,
    pseudonym,
    metaEnc: meta?.metaEnc,
    canonicalHash: meta?.canonicalHash
  });
  ctx.store.update(path, {
    fileId: out.fileId,
    revision: out.revision,
    generation: nextGen,
    ...metaEncrypted(ctx) ? { metaGeneration: 1 } : { metaGeneration: out.metaGeneration },
    serverPseudonym: metaEncrypted(ctx) ? out.path : void 0
  });
  return { fileId: out.fileId, revision: out.revision };
}
var MOBILE_LARGE_FILE_WARNING_BYTES = 50 << 20;
var warnedLargeFiles = /* @__PURE__ */ new Set();
async function pushUpsert(ctx, path) {
  if (ctx.store.getConflict(path)) return "skipped";
  const adapter = ctx.app.vault.adapter;
  const stat = await adapter.stat(path);
  if (!stat || stat.type === "folder") return "skipped";
  const data = await adapter.readBinary(path);
  if (import_obsidian3.Platform.isMobileApp && data.byteLength > MOBILE_LARGE_FILE_WARNING_BYTES && !warnedLargeFiles.has(path)) {
    warnedLargeFiles.add(path);
    ctx.notify(`⚠ Large files may use a lot of memory when synced on mobile: ${path}\uFF08${Math.round(data.byteLength / (1 << 20))} MB\uFF09`);
  }
  const hash = await sha256Hex(data);
  const tracked = ctx.store.get(path);
  if (tracked && tracked.hash === hash) {
    ctx.store.update(path, { mtime: stat.mtime, size: stat.size });
    return "skipped";
  }
  const baseRevision = tracked?.revision ?? 0;
  try {
    const out = await uploadFromPlain(ctx, path, data, baseRevision, stat.mtime);
    ctx.store.update(path, {
      hash,
      serverHash: out.cipherHash,
      revision: out.revision,
      mtime: stat.mtime,
      size: stat.size,
      fileId: out.fileId,
      generation: out.generation,
      metaGeneration: out.metaGeneration,
      serverPseudonym: out.serverPseudonym
    });
    ctx.log(`push: uploaded ${path} (rev ${out.revision})`);
    return "pushed";
  } catch (e) {
    if (e instanceof ConflictError) {
      const server = e.server;
      if (server.deleted) {
        if (!tracked) {
          const stale = await isStaleResurrection(ctx, path, hash, server);
          if (stale) {
            ctx.store.setPendingDelete(path);
            ctx.notify(
              `A stale copy of a deleted file was detected and will not be re-uploaded: ${path}
(the content was deleted on another device; to restore it, edit and save it again, or delete the local file by hand)`
            );
            return "skipped";
          }
        }
        const restored = await restoreObject(ctx, path, server);
        if (restored === null) {
          ctx.notify(`Cannot restore the deleted file (the server did not provide its object identity): ${path}`);
          return "skipped";
        }
        const out = await uploadFromPlain(ctx, path, data, restored.revision, stat.mtime);
        ctx.store.update(path, {
          hash,
          serverHash: out.cipherHash,
          revision: out.revision,
          mtime: stat.mtime,
          size: stat.size,
          fileId: out.fileId ?? restored.fileId,
          generation: out.generation,
          metaGeneration: out.metaGeneration,
          serverPseudonym: out.serverPseudonym
        });
        ctx.log(`push: restored + uploaded ${path} (rev ${out.revision})`);
        return "pushed";
      }
      if (!ctx.e2ee.enabled && server.hash === hash) {
        ctx.store.update(path, {
          hash,
          serverHash: server.hash,
          revision: server.revision,
          mtime: stat.mtime,
          size: stat.size
        });
        return "skipped";
      }
      try {
        const dl = await downloadPlain(ctx, path);
        if (dl.plainHash === hash) {
          ctx.store.update(path, {
            hash,
            serverHash: dl.cipherHash,
            revision: dl.revision,
            mtime: stat.mtime,
            size: stat.size,
            fileId: dl.fileId,
            generation: dl.generation,
            metaGeneration: dl.metaGeneration
          });
          return "skipped";
        }
      } catch (dlErr) {
        if (dlErr instanceof E2eeLockedError) throw dlErr;
      }
      const merged = await attemptAutoMerge(ctx, path, data, tracked);
      if (merged === "merged") return "pushed";
      if (merged === "pending") {
        ctx.notify(`Sync conflict: ${path}
Run "Resolve conflicts" to handle it`);
        return "conflict";
      }
      const kept = await keepBothVersions(ctx, path, data);
      return kept === null ? "skipped" : "conflict";
    }
    if (e instanceof ApiError && e.status === 413) {
      ctx.notify(`Skipped large file (over the server size limit): ${path}`);
      return "skipped";
    }
    if (e instanceof ApiError && e.is("CANONICAL_COLLISION")) {
      return resolveCanonicalCollision(ctx, path, data, hash, e);
    }
    throw e;
  }
}
async function resolveCanonicalCollision(ctx, path, data, localHash, err) {
  const existing = err.existing;
  if (!existing) {
    ctx.notify(`A file with the same name already exists on the server — local version saved as: ${path}`);
    const kept = await keepBothVersions(ctx, path, data);
    return kept === null ? "skipped" : "conflict";
  }
  let existingPath = existing;
  if (metaEncrypted(ctx)) {
    try {
      const meta = await ctx.client.getFileMeta(existing);
      const bind = e2eeBinding(ctx);
      const keys = await ctx.e2ee.metaKeys();
      const dec = await decryptMeta(keys, meta.metaEnc, bind?.vaultId ?? "", existing);
      if (dec === null) throw new Error("Metadata cannot be decrypted");
      existingPath = dec.meta.path;
    } catch (metaErr) {
      if (metaErr instanceof E2eeLockedError) throw metaErr;
      ctx.log(`collision: could not resolve the real path of the existing object (${existing}\uFF09\uFF1A${String(metaErr)}`);
      const kept = await keepBothVersions(ctx, path, data);
      return kept === null ? "skipped" : "conflict";
    }
  }
  if (existingPath === path) {
    let remote;
    try {
      remote = await downloadPlain(ctx, path, existing);
    } catch (dlErr) {
      if (dlErr instanceof E2eeLockedError) throw dlErr;
      remote = null;
    }
    if (remote !== null && remote.plainHash === localHash) {
      ctx.store.applyRemoteIdentity(path, {
        fileId: remote.fileId,
        generation: remote.generation,
        metaGeneration: remote.metaGeneration,
        serverPseudonym: metaEncrypted(ctx) ? existing : void 0
      });
      ctx.store.patchContentState(path, {
        hash: localHash,
        serverHash: remote.cipherHash,
        revision: remote.revision
      });
      ctx.log(`collision: adopted existing object for ${path} (rev ${remote.revision})`);
      return "skipped";
    }
    const kept = await keepBothVersions(ctx, path, data);
    ctx.notify(`Another device created a file with the same name: ${path}
The local version was saved as a copy`);
    return kept === null ? "skipped" : "conflict";
  }
  const renamed = await renameLocalAsideForCollision(ctx, path, existingPath);
  ctx.notify(
    `File name ${path} collides with the synced ${existingPath} on some systems; on this one they are the same file;\n` + (renamed === null ? "Rename it manually before syncing" : `The local file was renamed to ${renamed} so both copies are kept`)
  );
  return "conflict";
}
async function renameLocalAsideForCollision(ctx, path, existingPath) {
  const adapter = ctx.app.vault.adapter;
  const dot = path.lastIndexOf(".");
  const slash = path.lastIndexOf("/");
  const hasExt = dot > slash + 1;
  const stem = hasExt ? path.slice(0, dot) : path;
  const ext = hasExt ? path.slice(dot) : "";
  for (let i = 1; i <= 20; i++) {
    const candidate = `${stem} (${ctx.deviceName()}${i === 1 ? "" : ` ${i}`})${ext}`;
    if (await adapter.stat(candidate)) continue;
    if (pathsCollide(candidate, existingPath)) continue;
    try {
      await adapter.rename(path, candidate);
    } catch {
      return null;
    }
    ctx.store.applyMetaRenameState(path, candidate, {});
    ctx.queue.stage(candidate, { action: "upsert" });
    return candidate;
  }
  return null;
}
async function isStaleResurrection(ctx, path, plainHash, server) {
  if (!ctx.e2ee.enabled) return server.priorHash !== void 0 && server.priorHash === plainHash;
  try {
    const prior = await versionPlain(ctx, path, server.revision - 1);
    return prior.plainHash === plainHash;
  } catch (e) {
    if (e instanceof E2eeLockedError) throw e;
    return false;
  }
}
async function pushDelete(ctx, path) {
  if (ctx.store.getConflict(path)) return "skipped";
  const tracked = ctx.store.get(path);
  if (!tracked) return "skipped";
  const adapter = ctx.app.vault.adapter;
  if (await adapter.stat(path)) return "skipped";
  try {
    await removeRemote(ctx, path, tracked.revision);
    ctx.store.markDeleted(path);
    ctx.log(`push: deleted ${path}`);
    return "pushed";
  } catch (e) {
    if (e instanceof NotFoundError) {
      ctx.store.markDeleted(path);
      return "skipped";
    }
    if (e instanceof ConflictError) {
      if (e.server.deleted) {
        ctx.store.markDeleted(path);
        return "skipped";
      }
      const dl = await downloadPlain(ctx, path);
      if (!await writeIfLocalUnchanged(ctx, path, dl.plain, null, dl.mtime)) {
        ctx.notify(`This file was updated on another device, but a file with the same name appeared locally — restore deferred: ${path}`);
        return "conflict";
      }
      const st = await adapter.stat(path);
      ctx.store.update(path, {
        hash: dl.plainHash,
        serverHash: dl.cipherHash,
        revision: dl.revision,
        mtime: st?.mtime ?? Date.now(),
        size: dl.plain.byteLength,
        fileId: dl.fileId,
        generation: dl.generation,
        metaGeneration: dl.metaGeneration
      });
      ctx.notify(`This file was updated on another device — restored: ${path}`);
      return "conflict";
    }
    throw e;
  }
}

// src/bootstrap/bootstrap-manager.ts
async function preflight(ctx) {
  const info = await ctx.client.info();
  if (info.vaultId && ctx.store.paths().length > 0) {
    const owner = ctx.store.state.ledgerVaultId ?? (ctx.store.state.bootstrap.status === "ready" ? ctx.store.state.bootstrap.remoteVaultId : void 0);
    if (owner !== info.vaultId) {
      ctx.log(
        `preflight: ledger belongs to ${owner ? owner.slice(0, 8) + "\u2026" : "an unknown repository"}, server is ${info.vaultId.slice(0, 8)}\u2026; discarding stale ledger`
      );
      ctx.store.resetForNewRepository();
    }
  }
  ctx.store.setPendingBinding({
    remoteVaultId: info.vaultId,
    repoEpoch: info.repoEpoch,
    keyEpoch: info.keyEpoch,
    metaState: info.metaState,
    formatEpoch: info.formatEpoch,
    minimumEnvelopeVersion: info.minimumEnvelopeVersion
  });
  await ctx.store.save();
  await ctx.refreshE2ee();
  const snap = await ctx.client.snapshot();
  let files = snap.files;
  if (files.some((f) => f.metaEnc) && ctx.e2ee.unlocked) {
    files = await resolveSnapshotPaths(ctx, files);
  }
  const remoteFiles = files.filter((f) => !ctx.ignores(f.path));
  const localPaths = [];
  for (const file of ctx.app.vault.getFiles()) {
    if (!ctx.ignores(file.path)) localPaths.push(file.path);
  }
  const remoteSet = new Set(remoteFiles.map((f) => f.path));
  const commonCount = localPaths.filter((p) => remoteSet.has(p)).length;
  return {
    info,
    snapshotSequence: snap.sequence,
    repoEpoch: snap.repoEpoch ?? info.repoEpoch,
    remoteFiles,
    localPaths,
    commonCount,
    e2eeEnabled: ctx.e2ee.enabled
  };
}
async function ensureResolvedPre(ctx, pre) {
  if (!pre.remoteFiles.some((f) => f.metaEnc && f.path === f.fileId)) return pre;
  const files = await resolveSnapshotPaths(ctx, pre.remoteFiles);
  const remoteFiles = files.filter((f) => !ctx.ignores(f.path));
  const remoteSet = new Set(remoteFiles.map((f) => f.path));
  return {
    ...pre,
    remoteFiles,
    commonCount: pre.localPaths.filter((p) => remoteSet.has(p)).length
  };
}
function completeBootstrap(ctx, pre, mode) {
  ctx.store.state.lastSequence = pre.snapshotSequence;
  ctx.store.completeBootstrap(mode, pre.info.vaultId, pre.snapshotSequence, pre.repoEpoch, pre.info.keyEpoch);
}
async function bootstrapLocalInit(ctx, pre) {
  if (pre.remoteFiles.length === 0 && ctx.store.paths().length > 0) {
    ctx.log(`bootstrap: local-init found stale ledger (${ctx.store.paths().length} entries) against an empty remote \u2014 clearing`);
    ctx.store.clearSyncLedger();
  }
  completeBootstrap(ctx, pre, "local-init");
  await ctx.store.save();
  ctx.log(`bootstrap: local-init (local=${pre.localPaths.length})`);
}
async function bootstrapRemoteWins(ctx, pre, onProgress) {
  pre = await ensureResolvedPre(ctx, pre);
  const adapter = ctx.app.vault.adapter;
  const remoteSet = new Set(pre.remoteFiles.map((f) => f.path));
  const total = pre.remoteFiles.length + pre.localPaths.filter((p) => !remoteSet.has(p)).length;
  let done = 0;
  let blocked = 0;
  for (const f of pre.remoteFiles) {
    onProgress({ done: ++done, total, current: f.path });
    const dl = await downloadPlain(ctx, f.path, serverPseudonymOf(f));
    const stat = await adapter.stat(f.path);
    if (stat) {
      const localData = await adapter.readBinary(f.path);
      const localHash = await sha256Hex(localData);
      if (localHash === dl.plainHash) {
        ctx.store.update(f.path, {
          hash: localHash,
          serverHash: dl.cipherHash,
          revision: dl.revision,
          mtime: stat.mtime,
          size: stat.size,
          fileId: dl.fileId,
          generation: dl.generation,
          metaGeneration: dl.metaGeneration,
          serverPseudonym: serverPseudonymOf(f)
        });
        continue;
      }
      if (!await trashLocal(ctx.app, f.path)) {
        blocked++;
        ctx.store.setBlockedChange({
          sequence: f.revision,
          action: "upsert",
          fileId: f.fileId,
          serverPseudonym: serverPseudonymOf(f),
          revision: f.revision,
          contentHash: f.hash,
          metaGeneration: f.metaGeneration,
          realPath: f.path,
          reason: "bootstrap remote-wins: the trash is unavailable, local content was not overwritten"
        });
        ctx.notify(`Could not move to the trash, local content kept (not overwritten by remote): ${f.path}`);
        continue;
      }
    }
    if (!await writeIfLocalUnchanged(ctx, f.path, dl.plain, null, dl.mtime)) {
      blocked++;
      ctx.store.setBlockedChange({
        sequence: f.revision,
        action: "upsert",
        fileId: f.fileId,
        serverPseudonym: serverPseudonymOf(f),
        revision: f.revision,
        contentHash: f.hash,
        metaGeneration: f.metaGeneration,
        realPath: f.path,
        reason: "bootstrap remote-wins: a file appeared locally before the write, so it was not overwritten"
      });
      ctx.notify(`Kept a newly-appearing local file (not overwritten by remote): ${f.path}`);
      continue;
    }
    const st = await adapter.stat(f.path);
    ctx.store.update(f.path, {
      hash: dl.plainHash,
      serverHash: dl.cipherHash,
      revision: dl.revision,
      mtime: st?.mtime ?? Date.now(),
      size: dl.plain.byteLength,
      fileId: dl.fileId,
      generation: dl.generation,
      metaGeneration: dl.metaGeneration,
      serverPseudonym: serverPseudonymOf(f)
    });
  }
  for (const path of pre.localPaths) {
    if (remoteSet.has(path)) continue;
    onProgress({ done: ++done, total, current: path });
    if (await trashLocal(ctx.app, path)) {
      ctx.store.markDeleted(path);
    } else {
      ctx.store.markDeleted(path);
      ctx.store.setPendingDelete(path);
      ctx.notify(`Could not move to the trash, local file kept (it will not be re-uploaded): ${path}
Delete it manually`);
    }
  }
  completeBootstrap(ctx, pre, "remote-wins");
  await ctx.store.save();
  ctx.log(`bootstrap: remote-wins (remote=${pre.remoteFiles.length}, blocked=${blocked})`);
}
async function bootstrapMerge(ctx, pre, onProgress) {
  pre = await ensureResolvedPre(ctx, pre);
  const adapter = ctx.app.vault.adapter;
  const remoteSet = new Set(pre.remoteFiles.map((f) => f.path));
  const localOnly = pre.localPaths.filter((p) => !remoteSet.has(p));
  const total = pre.remoteFiles.length + localOnly.length;
  const result = { downloaded: 0, uploaded: 0, conflicts: 0 };
  let done = 0;
  for (const f of pre.remoteFiles) {
    onProgress({ done: ++done, total, current: f.path });
    const stat = await adapter.stat(f.path);
    if (!stat) {
      const dl2 = await downloadPlain(ctx, f.path, serverPseudonymOf(f));
      if (!await writeIfLocalUnchanged(ctx, f.path, dl2.plain, null, dl2.mtime)) continue;
      const st = await adapter.stat(f.path);
      ctx.store.update(f.path, {
        hash: dl2.plainHash,
        serverHash: dl2.cipherHash,
        revision: dl2.revision,
        mtime: st?.mtime ?? Date.now(),
        size: dl2.plain.byteLength,
        fileId: dl2.fileId,
        generation: dl2.generation,
        metaGeneration: dl2.metaGeneration,
        serverPseudonym: serverPseudonymOf(f)
      });
      result.downloaded++;
      continue;
    }
    const localData = await adapter.readBinary(f.path);
    const localHash = await sha256Hex(localData);
    const dl = await downloadPlain(ctx, f.path, serverPseudonymOf(f));
    if (localHash === dl.plainHash) {
      ctx.store.update(f.path, {
        hash: localHash,
        serverHash: dl.cipherHash,
        revision: dl.revision,
        mtime: stat.mtime,
        size: stat.size,
        fileId: dl.fileId,
        generation: dl.generation,
        metaGeneration: dl.metaGeneration,
        serverPseudonym: serverPseudonymOf(f)
      });
      continue;
    }
    if (isMarkdownLike(f.path)) {
      ctx.store.recordConflict(f.path, { baseRevision: 0, remoteRevision: dl.revision, createdAt: Date.now() });
      ctx.onConflictsChanged();
      result.conflicts++;
    } else {
      await keepBothVersions(ctx, f.path, localData);
      result.conflicts++;
    }
  }
  for (const path of localOnly) {
    onProgress({ done: ++done, total, current: path });
    const stat = await adapter.stat(path);
    if (!stat) continue;
    const data = await adapter.readBinary(path);
    const hash = await sha256Hex(data);
    let out;
    try {
      out = await uploadFromPlain(ctx, path, data, 0, stat.mtime);
    } catch (e) {
      if (e instanceof ConflictError && e.server.deleted) {
        if (await isStaleResurrection(ctx, path, hash, e.server)) {
          ctx.store.setPendingDelete(path);
          ctx.notify(`A stale copy of a deleted file was detected and will not be re-uploaded: ${path}`);
          continue;
        }
        out = await uploadFromPlain(ctx, path, data, e.server.revision, stat.mtime);
      } else {
        throw e;
      }
    }
    ctx.store.update(path, {
      hash,
      serverHash: out.cipherHash,
      revision: out.revision,
      mtime: stat.mtime,
      size: stat.size,
      fileId: out.fileId,
      generation: out.generation,
      metaGeneration: out.metaGeneration,
      serverPseudonym: out.serverPseudonym
    });
    result.uploaded++;
  }
  completeBootstrap(ctx, pre, "merge");
  await ctx.store.save();
  ctx.log(
    `bootstrap: merge (down=${result.downloaded} up=${result.uploaded} conflicts=${result.conflicts})`
  );
  return result;
}
function serverPseudonymOf(f) {
  return f.metaEnc && f.fileId ? f.fileId : void 0;
}
function isMarkdownLike(path) {
  const p = path.toLowerCase();
  return p.endsWith(".md") || p.endsWith(".txt");
}

// src/bootstrap/bootstrap-modal.ts
var import_obsidian6 = require("obsidian");

// src/crypto/e2ee-modals.ts
var import_obsidian4 = require("obsidian");
var UnlockModal = class extends import_obsidian4.Modal {
  constructor(app, defaultTrust, onSubmit) {
    super(app);
    this.defaultTrust = defaultTrust;
    this.onSubmit = onSubmit;
    this.busy = false;
  }
  onOpen() {
    this.titleEl.setText("Unlock End-to-End Encryption");
    const { contentEl } = this;
    contentEl.createDiv({ text: "Enter the E2EE password to unlock sync (the password is used in memory only and is never saved)." });
    const input = contentEl.createEl("input", { type: "password", cls: "litesync-modal-input" });
    const trustLabel = contentEl.createEl("label", { cls: "litesync-trust-label" });
    const trustBox = trustLabel.createEl("input", { type: "checkbox" });
    trustBox.checked = this.defaultTrust;
    trustLabel.appendText("Trust this device (auto-unlock on later launches)");
    const errorEl = contentEl.createDiv({ cls: "litesync-history-meta" });
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    const btn = footer.createEl("button", { text: "Unlock", cls: "mod-cta" });
    const submit = async () => {
      if (this.busy) return;
      this.busy = true;
      btn.setText("Unlocking…");
      btn.disabled = true;
      try {
        const err = await this.onSubmit(input.value, trustBox.checked);
        if (err === null) {
          this.close();
          return;
        }
        errorEl.setText(err);
      } finally {
        this.busy = false;
        btn.setText("Unlock");
        btn.disabled = false;
      }
    };
    btn.onclick = () => void submit();
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void submit();
    });
    window.setTimeout(() => input.focus(), 50);
  }
};
var EnableE2eeModal = class extends import_obsidian4.Modal {
  constructor(app, defaultTrust, onEnable, copy) {
    super(app);
    this.defaultTrust = defaultTrust;
    this.onEnable = onEnable;
    this.copy = copy;
    this.busy = false;
  }
  onOpen() {
    this.titleEl.setText("Enable End-to-End Encryption (E2EE)");
    const { contentEl } = this;
    const warn = contentEl.createDiv();
    warn.createEl("p", {
      text: "Once enabled, every note is encrypted on this device before upload; the server only stores ciphertext."
    });
    const strong = warn.createEl("p");
    strong.createEl("strong", {
      text: "⚠️ Once the password is lost, the data on the server can never be recovered; this version cannot disable E2EE or change the password."
    });
    warn.createEl("p", {
      text: this.copy?.note ?? "The migration re-encrypts and re-uploads every current file, then clears the server's plaintext history after verifying the ciphertext. Make sure no other device is syncing right now."
    });
    contentEl.createDiv({ text: "Set E2EE password (at least 8 characters):" });
    const pw1 = contentEl.createEl("input", { type: "password", cls: "litesync-modal-input" });
    contentEl.createDiv({ text: "Enter it again to confirm:" });
    const pw2 = contentEl.createEl("input", { type: "password", cls: "litesync-modal-input" });
    const trustLabel = contentEl.createEl("label", { cls: "litesync-trust-label" });
    const trustBox = trustLabel.createEl("input", { type: "checkbox" });
    trustBox.checked = this.defaultTrust;
    trustLabel.appendText("Trust this device (auto-unlock on later launches)");
    const progressEl = contentEl.createDiv({ cls: "litesync-history-meta" });
    const errorEl = contentEl.createDiv({ cls: "litesync-history-meta" });
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    const btn = footer.createEl("button", { text: "Start Encryption Migration", cls: "mod-cta" });
    footer.createEl("button", { text: "Cancel" }).onclick = () => this.close();
    pw1.addEventListener("keydown", (e) => {
      if (e.key === "Enter") pw2.focus();
    });
    pw2.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        pw2.blur();
        btn.click();
      }
    });
    btn.onclick = async () => {
      if (this.busy) return;
      errorEl.setText("");
      if (pw1.value.length < 8) {
        errorEl.setText("The password needs at least 8 characters");
        return;
      }
      if (pw1.value !== pw2.value) {
        errorEl.setText("The two passwords do not match");
        return;
      }
      this.busy = true;
      btn.disabled = true;
      btn.setText("Migrating…");
      try {
        const migrated = await this.onEnable(pw1.value, trustBox.checked, (p) => {
          progressEl.setText(`Encrypting migration ${p.done}/${p.total}\uFF1A${p.current}`);
        });
        new import_obsidian4.Notice(this.copy?.success?.(migrated) ?? `E2EE enabled, migrated ${migrated} files from remote ✓`, 1e4);
        this.close();
      } catch (e) {
        errorEl.setText(
          `Migration failed: ${e instanceof Error ? e.message : String(e)} (re-runnable; already-encrypted files are skipped automatically)`
        );
        this.busy = false;
        btn.disabled = false;
        btn.setText("Restart Encryption Migration");
      }
    };
  }
};

// src/token-prompt-modal.ts
var import_obsidian5 = require("obsidian");
var TokenPromptModal = class extends import_obsidian5.Modal {
  constructor(app, message, onSubmit, onClosed) {
    super(app);
    this.message = message;
    this.onSubmit = onSubmit;
    this.onClosed = onClosed;
  }
  onOpen() {
    this.titleEl.setText("Enter your account API Token");
    const { contentEl } = this;
    contentEl.createEl("p", { cls: "litesync-history-meta", text: this.message });
    const input = contentEl.createEl("input", { type: "password", cls: "litesync-modal-input", placeholder: "lsk_\u2026" });
    input.setAttribute("enterkeyhint", "go");
    const errEl = contentEl.createDiv({ cls: "litesync-history-meta" });
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    const submit = () => {
      const t = input.value.trim();
      if (!t) {
        errEl.setText("Enter your API Token (starts with lsk_).");
        return;
      }
      input.blur();
      this.close();
      this.onSubmit(t);
    };
    footer.createEl("button", { text: "OK", cls: "mod-cta" }).onclick = submit;
    footer.createEl("button", { text: "Cancel" }).onclick = () => this.close();
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit();
    });
    if (!import_obsidian5.Platform.isMobileApp) input.focus();
  }
  onClose() {
    this.contentEl.empty();
    this.onClosed?.();
  }
};

// src/sync/gate.ts
var SyncGate = class {
  constructor() {
    /** 未绑定：server URL / Token / 设备身份 / vault key 文档变化后置位（LS-121-C02） */
    this.unbound = "Binding validation against the server is not complete";
    /** 协议不兼容（/info 判定） */
    this.protocol = null;
    /** repoEpoch 与本地记录不符（灾备恢复） */
    this.repoEpoch = null;
    /** 迁移进行中（元数据加密 / 信封升级 / E2EE 启用）：串行化并阻断其他写入 */
    this.migration = null;
    /** 不可自动恢复的完整性错误（如服务器换掉了 fileId）：需要人工处理 */
    this.integrity = null;
    /**
     * 服务器拒绝了本设备凭据（HTTP 401，验收 T5.2）：设备被撤销或 Token 失效。
     * 与 unbound 不同——那是「本地配置变了需要重新校验」，这是「服务器不认识
     * 我们了」，不会自己好起来，也不该用退避重试去撞；手动同步会重新校验，
     * /info 成功后自动清除。
     */
    this.credential = null;
  }
  get isUnbound() {
    return this.unbound !== null;
  }
  get isMigrationActive() {
    return this.migration !== null;
  }
  markUnbound(reason) {
    this.unbound = reason;
  }
  /** 只能由完成了 /info + 凭据 + vaultId/repoEpoch 校验的重新绑定流程调用。 */
  markBound() {
    this.unbound = null;
  }
  markProtocolMismatch(message) {
    this.protocol = message;
  }
  markRepoEpochMismatch(message) {
    this.repoEpoch = message;
  }
  markIntegrityError(message) {
    this.integrity = message;
  }
  markCredentialRejected(message) {
    this.credential = message;
  }
  clearIntegrityError() {
    this.integrity = null;
  }
  beginMigration(what) {
    this.migration = what;
  }
  endMigration() {
    this.migration = null;
  }
  /** 仅返回会话级阻断项；仓库/密钥状态由 {@link syncGateBlock} 合并判断。 */
  sessionBlock() {
    if (this.integrity !== null) return { reason: "integrity-error", message: this.integrity };
    if (this.protocol !== null) return { reason: "protocol-mismatch", message: this.protocol };
    if (this.credential !== null) return { reason: "credential-rejected", message: this.credential };
    if (this.repoEpoch !== null) return { reason: "repo-epoch-mismatch", message: this.repoEpoch };
    if (this.unbound !== null) {
      return {
        reason: "unbound",
        message: `This device has not completed binding validation against the current server (${this.unbound}); run "Sync Now" once to complete the validation`
      };
    }
    if (this.migration !== null) {
      return { reason: "migration-active", message: `Running ${this.migration}, please wait for it to finish before acting` };
    }
    return null;
  }
};
function syncGateBlock(ctx) {
  if (ctx.store.corrupted) {
    return {
      reason: "state-corrupted",
      message: "The local sync state file is corrupt (neither state-a/state-b.json can be read); all sync and manual operations have stopped. Restore the state files from a backup or rejoin — never keep writing in this state"
    };
  }
  if (!ctx.store.bootstrapReady) {
    return { reason: "bootstrap-pending", message: "This device has not finished the setup wizard — finish joining first" };
  }
  const session = ctx.gate.sessionBlock();
  if (session !== null) return session;
  if (ctx.e2ee.needsUnlock) {
    return { reason: "key-locked", message: "End-to-end encryption is locked — please unlock first (Unlock E2EE)" };
  }
  return null;
}
var SyncBlockedError = class extends Error {
  constructor(reason, message) {
    super(message);
    this.reason = reason;
    this.name = "SyncBlockedError";
  }
};
function requireSyncSafe(ctx, action) {
  const block = syncGateBlock(ctx);
  if (block === null) return;
  ctx.log(`blocked ${action}: ${block.reason}`);
  if (block.reason === "key-locked") throw new E2eeLockedError();
  throw new SyncBlockedError(block.reason, `Cannot ${action}\uFF1A${block.message}`);
}

// src/crypto/migration.ts
async function acquireVaultKey(ctx, password) {
  let doc = await ctx.client.getVaultKey();
  let vmk;
  if (doc) {
    if (doc.enabled) throw new Error("End-to-end encryption is already enabled");
    const key = await unlockVaultKey(doc, password);
    if (!key) throw new Error("This password does not match the key already on the server (an earlier migration may have been interrupted — use the password from back then)");
    vmk = key;
  } else {
    const created = await createVaultKeyDoc(password);
    doc = created.doc;
    vmk = created.vmk;
    await ctx.client.putVaultKey(doc, false);
  }
  ctx.e2ee.adopt(doc, vmk);
  ctx.store.state.e2ee = doc;
  await ctx.store.save();
  return vmk;
}
async function finalizeVaultKeyEnabled(ctx, vmk) {
  const cur = await ctx.client.getVaultKeyWithFingerprint();
  if (!cur) throw new Error("The vault key document is missing — please re-enable it");
  if (!cur.doc.enabled) {
    const finalDoc = { ...cur.doc, enabled: true };
    await ctx.client.putVaultKey(finalDoc, true, cur.fingerprint);
    ctx.e2ee.adopt(finalDoc, vmk);
    ctx.store.state.e2ee = finalDoc;
  } else {
    ctx.e2ee.adopt(cur.doc, vmk);
    ctx.store.state.e2ee = cur.doc;
  }
  await ctx.store.save();
}
async function enableE2ee(ctx, password, fullSync, onProgress) {
  requireSyncSafe(ctx, "Enable End-to-End Encryption");
  if (password.length < 8) throw new Error("The password needs at least 8 characters");
  const vmk = await acquireVaultKey(ctx, password);
  await fullSync();
  if (ctx.queue.size > 0 || ctx.store.conflictPaths().length > 0) {
    throw new Error("There is an unfinished sync or unresolved conflict — resolve it and re-enable");
  }
  ctx.gate.beginMigration("End-to-End Encryption Migration");
  try {
    return await runE2eeMigration(ctx, vmk, onProgress);
  } finally {
    ctx.gate.endMigration();
  }
}
async function runE2eeMigration(ctx, vmk, onProgress) {
  const info = await ctx.client.info();
  const serverState = info.encryptionState ?? "plaintext";
  let done = 0;
  if (serverState !== "encrypted") {
    const state = await ctx.client.e2eeTransition("begin");
    ctx.store.state.bootstrap.keyEpoch = requireKeyEpoch(state.keyEpoch, "e2ee/begin.keyEpoch");
    if (!ctx.store.state.bootstrap.remoteVaultId && info.vaultId) {
      ctx.store.state.bootstrap.remoteVaultId = info.vaultId;
    }
    await ctx.store.save();
    const binding = e2eeBinding(ctx);
    const snap = await ctx.client.snapshot();
    const paths = snap.files.map((f) => f.path).filter((p) => !ctx.ignores(p));
    for (const path of paths) {
      onProgress({ total: paths.length, done, current: path });
      await migratePath(ctx, vmk, path, binding);
      done++;
      if (done % 10 === 0) await ctx.store.save();
    }
    await ctx.store.save();
    await ctx.client.e2eeTransition("complete");
  }
  await finalizeVaultKeyEnabled(ctx, vmk);
  ctx.log(`e2ee: migration complete, ${done} files encrypted`);
  return done;
}
async function enableE2eeOnEmptyRemote(ctx, password) {
  if (ctx.store.corrupted) throw new Error("The local sync state is corrupt, cannot enable");
  if (password.length < 8) throw new Error("The password needs at least 8 characters");
  const info = await ctx.client.info();
  if ((info.latestSequence ?? 0) > 0 || (info.encryptionState ?? "plaintext") !== "plaintext") {
    throw new Error("The remote vault is no longer uninitialized — use the setup wizard instead");
  }
  const vmk = await acquireVaultKey(ctx, password);
  const state = await ctx.client.e2eeTransition("begin");
  ctx.store.state.bootstrap.keyEpoch = requireKeyEpoch(state.keyEpoch, "e2ee/begin.keyEpoch");
  if (!ctx.store.state.bootstrap.remoteVaultId && info.vaultId) {
    ctx.store.state.bootstrap.remoteVaultId = info.vaultId;
  }
  await ctx.store.save();
  await ctx.client.e2eeTransition("complete");
  await finalizeVaultKeyEnabled(ctx, vmk);
  ctx.log("e2ee: enabled on empty remote (no migration needed)");
}
async function migratePath(ctx, vmk, path, binding) {
  let raw;
  try {
    raw = await ctx.client.download(path);
  } catch (e) {
    if (e instanceof NotFoundError) {
      ctx.store.markDeleted(path);
      return;
    }
    throw e;
  }
  const serverHash = await sha256Hex(raw.data);
  if (raw.hash && serverHash !== raw.hash) {
    throw new Error(`Server content hash verification failed: ${path}`);
  }
  const tracked = ctx.store.get(path);
  if (isEncryptedPayload(raw.data)) {
    const dec2 = await decryptAny(vmk, path, raw.data, binding, raw.fileId);
    if (dec2 === null) throw new Error(`Encrypted but cannot be decrypted with the current key: ${path}`);
    ctx.store.update(path, {
      hash: await sha256Hex(dec2.plain),
      serverHash,
      revision: raw.revision,
      mtime: tracked?.mtime ?? Date.now(),
      size: dec2.plain.byteLength,
      fileId: raw.fileId,
      generation: dec2.generation
    });
    await purgeHistoryOf(ctx, path, raw.revision);
    return;
  }
  const plain = raw.data;
  const plainHash = await sha256Hex(plain);
  let payload;
  let generation;
  if (binding && raw.fileId) {
    generation = 1;
    payload = await encryptFileV3(vmk, { ...binding, fileId: raw.fileId, generation }, plain);
  } else {
    payload = await encryptFile(vmk, path, plain, binding);
  }
  const cipherHash = await sha256Hex(payload);
  const res = await ctx.client.upload(path, raw.revision, cipherHash, payload, raw.mtime, "upsert");
  const check = await ctx.client.download(path);
  if (await sha256Hex(check.data) !== cipherHash) {
    throw new Error(`Ciphertext read-back does not match the upload: ${path}`);
  }
  const dec = await decryptAny(vmk, path, check.data, binding, check.fileId ?? raw.fileId);
  if (dec === null || await sha256Hex(dec.plain) !== plainHash) {
    throw new Error(`Ciphertext decryption verification failed: ${path}`);
  }
  ctx.store.update(path, {
    hash: plainHash,
    serverHash: cipherHash,
    revision: res.revision,
    mtime: tracked?.mtime ?? Date.now(),
    size: plain.byteLength,
    fileId: res.fileId ?? raw.fileId,
    generation
  });
  await purgeHistoryOf(ctx, path, res.revision);
}
async function encryptMetadata(ctx, opts) {
  const { onProgress } = opts;
  requireSyncSafe(ctx, "Encrypt Paths & File Names");
  if (!ctx.e2ee.enabled) throw new Error("Please enable end-to-end encryption first");
  const bind = e2eeBinding(ctx);
  if (!bind) throw new Error("Missing vaultId/keyEpoch binding material — complete one normal sync and retry");
  await opts.fullSync();
  if (ctx.queue.size > 0 || ctx.store.conflictPaths().length > 0) {
    throw new Error("There is an unfinished sync or unresolved conflict — resolve it and retry");
  }
  ctx.gate.beginMigration("Path & File Name Encryption Migration");
  try {
    const keys = await ctx.e2ee.metaKeys();
    let status = await ctx.client.metaTransition("begin");
    adoptMetaState(ctx, status.metaState);
    await ctx.store.save();
    const snap = await ctx.client.snapshot();
    const pending = snap.files.filter((f) => f.fileId !== f.path);
    let migrated = 0;
    let done = 0;
    for (const f of pending) {
      onProgress({ total: pending.length + status.plaintextTombstones, done: done++, current: f.path });
      const fileId = requireFileId(f.fileId, `snapshot(${f.path}).fileId`);
      const metaEnc = await encryptMeta(
        keys,
        { vaultId: bind.vaultId, keyEpoch: bind.keyEpoch, fileId, metaGeneration: 1 },
        { path: f.path }
      );
      const canonicalHash = await canonicalPathHmac(keys, f.path);
      let res;
      try {
        res = await ctx.client.migrateObjectMeta(f.path, metaEnc, canonicalHash);
      } catch (e) {
        if (e instanceof ApiError && (e.is("PLAINTEXT_REJECTED") || e.is("ENVELOPE_TOO_OLD"))) {
          throw new Error(`Old-envelope ciphertext exists for (${f.path}), run "Upgrade Encryption Envelopes LSE1 → LSE3" first, then retry`);
        }
        throw e;
      }
      if (ctx.store.get(f.path)) {
        ctx.store.update(f.path, {
          fileId,
          revision: res.revision,
          metaGeneration: res.metaGeneration,
          serverPseudonym: res.toPath
        });
      }
      migrated++;
      if (migrated % 10 === 0) await ctx.store.save();
    }
    await ctx.store.save();
    const tombstones = await ctx.client.listPlaintextTombstones();
    let convertedTombstones = 0;
    for (const t of tombstones) {
      onProgress({
        total: pending.length + tombstones.length,
        done: done++,
        current: t.lastPseudonym
      });
      await ctx.client.migrateTombstone(t.fileId, await canonicalPathHmac(keys, t.lastPseudonym));
      convertedTombstones++;
    }
    status = await ctx.client.metaTransition("verify");
    adoptMetaState(ctx, status.metaState);
    await ctx.store.save();
    await verifyMigrationClientSide(ctx, keys, bind, status.cutoffSequence, onProgress);
    const check = await ctx.client.validateMetaMigration();
    if (!check.ok) {
      throw new MigrationValidationError(check.failures);
    }
    const result = {
      migrated,
      convertedTombstones,
      total: snap.files.length,
      metaState: status.metaState,
      erased: false
    };
    if (!opts.allowIrreversibleComplete) {
      ctx.log(
        `meta encryption: ${migrated} objects + ${convertedTombstones} tombstones migrated, erase skipped (experimental build gate)`
      );
      return result;
    }
    const final = await ctx.client.metaTransition("complete", true, status.migrationId);
    adoptMetaState(ctx, final.metaState);
    ctx.store.state.bootstrap.formatEpoch = final.formatEpoch;
    ctx.store.state.lastSequence = 0;
    await ctx.store.save();
    ctx.log(`meta encryption complete: formatEpoch=${final.formatEpoch}, plaintext paths erased`);
    return { ...result, metaState: final.metaState, erased: true };
  } finally {
    ctx.gate.endMigration();
  }
}
async function verifyMigrationClientSide(ctx, keys, bind, cutoffSequence, onProgress) {
  const snap = await ctx.client.snapshot();
  if (snap.sequence < cutoffSequence) {
    throw new Error(
      `Server snapshot (sequence ${snap.sequence}) predates the migration start (${cutoffSequence}), aborted — retry instead; do not erase plaintext paths in this state`
    );
  }
  const failures = [];
  let done = 0;
  for (const f of snap.files) {
    onProgress({ total: snap.files.length, done: done++, current: `verify ${f.fileId ?? "?"}` });
    if (!isFileId(f.fileId)) {
      failures.push(`Invalid fileId: ${String(f.fileId).slice(0, 12)}`);
      continue;
    }
    if (f.path !== f.fileId) {
      failures.push(`${f.fileId.slice(0, 8)}: the server still addresses it by a non-pseudonym name`);
      continue;
    }
    if (!f.metaEnc) {
      failures.push(`${f.fileId.slice(0, 8)}: missing encrypted metadata`);
      continue;
    }
    const dec = await decryptMeta(keys, f.metaEnc, bind.vaultId, f.fileId);
    if (dec === null) {
      failures.push(`${f.fileId.slice(0, 8)}: this device cannot decrypt its metadata`);
      continue;
    }
    if (dec.keyEpoch !== bind.keyEpoch) {
      failures.push(`${f.fileId.slice(0, 8)}: metadata key epoch is ${dec.keyEpoch}, current is ${bind.keyEpoch}`);
    }
    if (f.metaGeneration !== void 0 && dec.metaGeneration !== f.metaGeneration) {
      failures.push(
        `${f.fileId.slice(0, 8)}: metaGeneration mismatch (in ciphertext ${dec.metaGeneration} vs server ${f.metaGeneration}\uFF09`
      );
    }
    if (f.envelopeVersion !== void 0 && f.envelopeVersion < 3) {
      failures.push(`${f.fileId.slice(0, 8)}: content is still an old envelope (LSE${f.envelopeVersion || "?"}\uFF09`);
    }
    if (failures.length >= 20) break;
  }
  if (failures.length > 0) {
    throw new Error(
      `Migration re-verification failed (${failures.length} items), aborted without any erasure; the migration can continue or be abandoned. First few:${failures.slice(0, 10).join("\uFF1B")}`
    );
  }
  ctx.log(`client-side migration verification passed: ${snap.files.length} objects`);
}
function adoptMetaState(ctx, metaState) {
  ctx.store.state.bootstrap.metaState = metaState;
}
async function abortMetadataMigration(ctx) {
  requireSyncSafe(ctx, "Abort Path Encryption Migration");
  const st = await ctx.client.metaTransition("abort");
  adoptMetaState(ctx, st.metaState);
  await ctx.store.save();
  ctx.log(`meta migration aborted, metaState=${st.metaState}`);
  return st.metaState;
}
async function decryptAny(vmk, path, payload, binding, fileId) {
  if (isLse3Envelope(payload)) {
    if (!binding?.vaultId || !fileId) return null;
    return decryptFileV3(vmk, payload, binding.vaultId, fileId, binding.keyEpoch);
  }
  const plain = await decryptFile(vmk, path, payload, binding);
  return plain === null ? null : { plain };
}
async function upgradeEnvelopes(ctx, onProgress) {
  requireSyncSafe(ctx, "Upgrade Encryption Envelopes");
  if (!ctx.e2ee.enabled) throw new Error("End-to-end encryption is not enabled — no envelope upgrade needed");
  const vmk = ctx.e2ee.requireKey();
  const binding = e2eeBinding(ctx);
  if (!binding) throw new Error("Missing vaultId/keyEpoch binding material — complete one normal sync and retry");
  ctx.gate.beginMigration("Encryption Envelope Upgrade");
  try {
    return await runEnvelopeUpgrade(ctx, vmk, binding, onProgress);
  } finally {
    ctx.gate.endMigration();
  }
}
async function runEnvelopeUpgrade(ctx, vmk, binding, onProgress) {
  const snap = await ctx.client.snapshot();
  const files = snap.files.filter((f) => !ctx.ignores(f.path));
  let upgraded = 0;
  let skipped = 0;
  let done = 0;
  for (const f of files) {
    onProgress({ total: files.length, done: done++, current: f.path });
    let raw;
    try {
      raw = await ctx.client.download(f.path);
    } catch (e) {
      if (e instanceof NotFoundError) continue;
      throw e;
    }
    if (!isLegacyEnvelope(raw.data)) continue;
    const fileId = raw.fileId ?? f.fileId;
    if (!fileId) {
      skipped++;
      continue;
    }
    const plain = await decryptFile(vmk, f.path, raw.data, binding);
    if (plain === null) {
      skipped++;
      ctx.log(`envelope upgrade: cannot decrypt ${f.path}, skipped`);
      continue;
    }
    const tracked = ctx.store.get(f.path);
    const generation = (tracked?.fileId === fileId ? tracked?.generation ?? 0 : 0) + 1;
    const payload = await encryptFileV3(vmk, { ...binding, fileId, generation }, plain);
    const cipherHash = await sha256Hex(payload);
    try {
      const res = await ctx.client.upload(f.path, raw.revision, cipherHash, payload, raw.mtime, "upsert");
      if (tracked) {
        ctx.store.update(f.path, {
          serverHash: cipherHash,
          revision: res.revision,
          fileId,
          generation
        });
      }
      upgraded++;
    } catch (e) {
      if (e instanceof ConflictError) {
        skipped++;
        continue;
      }
      throw e;
    }
  }
  await ctx.store.save();
  if (skipped === 0) {
    try {
      const st = await ctx.client.completeEnvelopeUpgrade();
      ctx.store.state.bootstrap.minimumEnvelopeVersion = st.minimumEnvelopeVersion;
      await ctx.store.save();
      ctx.log(`envelope floor raised to ${st.minimumEnvelopeVersion}`);
    } catch (e) {
      ctx.log(`envelope floor not raised yet: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  ctx.log(`envelope upgrade: ${upgraded} upgraded, ${skipped} skipped, ${files.length} total`);
  return { upgraded, skipped, total: files.length };
}

// src/bootstrap/bootstrap-types.ts
var PENDING_BOOTSTRAP = { status: "pending" };
function classifyBootstrap(localCount, remoteCount) {
  if (localCount === 0 && remoteCount === 0) return "both-empty";
  if (remoteCount === 0) return "local-only";
  if (localCount === 0) return "remote-only";
  return "both";
}
function vaultPickerVisible(listSucceeded, hasSetter) {
  return listSucceeded && hasSetter;
}

// src/bootstrap/bootstrap-modal.ts
var BootstrapWizardModal = class extends import_obsidian6.Modal {
  constructor(app, ctx, hooks) {
    super(app);
    this.ctx = ctx;
    this.hooks = hooks;
    this.busy = false;
  }
  onOpen() {
    this.titleEl.setText("LiteSync New Device Setup");
    this.contentEl.createDiv({ text: "Detecting the remote vault…", cls: "litesync-history-meta" });
    void this.runVaultPicker();
  }
  /**
   * 选择仓库步（v0.19 单用户多仓库）。
   *
   * 服务器支持 vaults 端点时**始终显示**——哪怕名下只有一个仓库（预选它，
   * 一键继续）：「新建仓库」的唯一入口在这一步，见 vaultPickerVisible 的注释。
   * 列出名字/文件数/大小，可选任意一个或新建；选择非当前指向的仓库需要
   * **用户级 Token**（设备凭据绑定单仓库、X-Vault-ID 对它无效——这是刻意的
   * 最小权限设计），此时提示先在设置里重新填入 API Token。
   */
  async runVaultPicker() {
    let vaults = [];
    let listOk = true;
    try {
      vaults = await this.ctx.client.listVaults();
    } catch {
      listOk = false;
    }
    if (!vaultPickerVisible(listOk, !!this.hooks.setVaultChoice)) {
      void this.runPreflight();
      return;
    }
    let tokenType = "root";
    try {
      tokenType = (await this.ctx.client.whoami()).tokenType ?? "root";
    } catch {
    }
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("p", { text: "Choose which remote vault this Obsidian vault should sync to (or create a new one):" });
    let selected = "";
    const list = contentEl.createDiv();
    const fmtBytes = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
    const radios = [];
    for (const v of vaults) {
      const row = list.createDiv({ cls: "litesync-history-meta" });
      const label = row.createEl("label");
      const radio = label.createEl("input", { type: "radio" });
      radio.name = "litesync-vault-pick";
      radio.value = v.id;
      if (v.current) {
        radio.checked = true;
        selected = v.id;
      }
      radios.push(radio);
      radio.onchange = () => {
        if (radio.checked) selected = v.id;
      };
      label.appendText(
        ` ${v.name || v.id}\uFF08${v.fileCount} files · ${fmtBytes(v.bytesUsed)}\uFF09` + (v.current ? " · Current" : "")
      );
    }
    const createRow = contentEl.createDiv({ cls: "litesync-history-meta" });
    const createLabel = createRow.createEl("label");
    const createRadio = createLabel.createEl("input", { type: "radio" });
    createRadio.name = "litesync-vault-pick";
    createRadio.value = "__new__";
    radios.push(createRadio);
    createRadio.onchange = () => {
      if (createRadio.checked) selected = "__new__";
    };
    createLabel.appendText(" Create new vault:");
    const nameInput = createRow.createEl("input", { type: "text", placeholder: "Vault name (1–64 characters)" });
    nameInput.setAttribute("autocomplete", "off");
    nameInput.onfocus = () => {
      createRadio.checked = true;
      selected = "__new__";
    };
    const hint = contentEl.createDiv({ cls: "litesync-history-meta" });
    hint.setText("Switching vaults discards this device's sync records (local notes are kept), then restores/merges/initializes as you choose.");
    const errEl = contentEl.createDiv({ cls: "litesync-history-meta" });
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    const submitOnEnter = (input) => {
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          input.blur();
          proceed();
        }
      });
    };
    const proceed = () => {
      void (async () => {
        if (!selected) {
          errEl.setText("Choose a vault, or create one.");
          return;
        }
        const currentVault = vaults.find((v) => v.current);
        const changing = selected === "__new__" || currentVault && selected !== currentVault.id;
        if (changing && tokenType === "device") {
          if (!this.hooks.setApiToken) {
            errEl.setText("Switching or creating a vault requires your account API Token. Fill it in again in settings before opening the wizard.");
            return;
          }
          errEl.setText("Switching or creating a vault requires your account API Token (this device holds a device credential bound to a single vault).");
          const pendingName = nameInput.value;
          nameInput.readOnly = true;
          new TokenPromptModal(
            this.app,
            "Switching or creating a vault requires your account API Token (starts with lsk_; see the Account page on the web for instructions). It will be saved as this device's credential and continue.",
            (t) => {
              void (async () => {
                await this.hooks.setApiToken?.(t);
                try {
                  tokenType = (await this.ctx.client.whoami()).tokenType ?? "root";
                } catch (e) {
                  errEl.setText(`Token validation failed: ${e instanceof Error ? e.message : String(e)}`);
                  return;
                }
                if (tokenType === "device") {
                  errEl.setText("This token is still a device credential — click \"Continue\" and paste your account's API Token (starting with lsk_) again.");
                  return;
                }
                errEl.setText("");
                proceed();
              })();
            },
            () => {
              nameInput.readOnly = false;
              nameInput.value = pendingName;
            }
          ).open();
          return;
        }
        try {
          let target = selected;
          if (selected === "__new__") {
            const name = nameInput.value.trim();
            if (!name) {
              errEl.setText("Enter a name for the new vault.");
              return;
            }
            target = await this.ctx.client.createVault(name);
          }
          await this.hooks.setVaultChoice?.(target);
          contentEl.empty();
          contentEl.createDiv({ text: "Detecting the remote vault…", cls: "litesync-history-meta" });
          await this.runPreflight();
        } catch (e) {
          errEl.setText(`Failed: ${e instanceof Error ? e.message : String(e)}`);
        }
      })();
    };
    footer.createEl("button", { text: "Continue", cls: "mod-cta" }).onclick = proceed;
    submitOnEnter(nameInput);
    footer.createEl("button", { text: "Maybe later" }).onclick = () => this.close();
  }
  onClose() {
    this.hooks.onClosed();
  }
  renderE2eeNote(contentEl) {
    contentEl.createEl("p", {
      cls: "litesync-history-meta",
      text: "A new vault must enable end-to-end encryption: the first upload is ciphertext and the server never sees plaintext. The password may be the same as your other vaults (each vault derives its key independently with its own salt)."
    });
  }
  /**
   * 空远端的 E2EE 初始化（唯一路径）。0.19.x 起新仓库**强制 E2EE**：
   * 明文初始化按钮已移除——「先明文再事后迁移」意味着明文经过服务器
   * WAL/备份，与新仓库的隐私预期不符；既有明文仓库（远端非空）不受影响。
   */
  renderE2eeButton(footer) {
    footer.createEl("button", { text: "Set E2EE password and initialize", cls: "mod-cta" }).onclick = () => {
      new EnableE2eeModal(
        this.app,
        this.hooks.trustDevice?.() ?? false,
        async (password, trustDevice) => {
          await enableE2eeOnEmptyRemote(this.ctx, password);
          await this.hooks.setTrustDevice?.(trustDevice);
          const fresh = await preflight(this.ctx);
          await bootstrapLocalInit(this.ctx, fresh);
          this.close();
          this.hooks.onDone();
          return 0;
        },
        {
          note: "The remote vault is still empty: setting the password takes effect immediately, and the first upload after that is ciphertext — there is no migration step, and plaintext never passes through the server.",
          success: () => "End-to-end encryption enabled, running the first sync (all content uploaded as ciphertext) ✓"
        }
      ).open();
    };
  }
  async runPreflight() {
    try {
      const pre = await preflight(this.ctx);
      this.renderChoices(pre);
    } catch (e) {
      const { contentEl } = this;
      contentEl.empty();
      contentEl.createDiv({ text: `Cannot connect to the server: ${e instanceof Error ? e.message : String(e)}` });
      const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
      footer.createEl("button", { text: "Retry", cls: "mod-cta" }).onclick = () => {
        contentEl.empty();
        contentEl.createDiv({ text: "Detecting the remote vault…", cls: "litesync-history-meta" });
        void this.runPreflight();
      };
      footer.createEl("button", { text: "Maybe later" }).onclick = () => this.close();
    }
  }
  renderChoices(pre) {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createDiv({
      cls: "litesync-history-meta",
      text: `Remote ${pre.remoteFiles.length} files · local ${pre.localPaths.length} files · same path ${pre.commonCount} `
    });
    if (pre.e2eeEnabled && this.ctx.e2ee.needsUnlock) {
      contentEl.createEl("p", { text: "This sync vault has end-to-end encryption enabled — you must unlock before joining." });
      const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
      footer.createEl("button", { text: "Unlock E2EE…", cls: "mod-cta" }).onclick = () => {
        this.hooks.openUnlock(() => {
          contentEl.empty();
          contentEl.createDiv({ text: "Detecting the remote vault…", cls: "litesync-history-meta" });
          void this.runPreflight();
        });
      };
      footer.createEl("button", { text: "Maybe later" }).onclick = () => this.close();
      return;
    }
    const scenario = classifyBootstrap(pre.localPaths.length, pre.remoteFiles.length);
    const progressEl = contentEl.createDiv({ cls: "litesync-history-meta" });
    const run = async (btn, label, fn) => {
      if (this.busy) return;
      this.busy = true;
      for (const b of Array.from(contentEl.querySelectorAll("button"))) b.disabled = true;
      btn.setText(`${label}…`);
      try {
        await fn();
        this.close();
        this.hooks.onDone();
      } catch (e) {
        this.busy = false;
        for (const b of Array.from(contentEl.querySelectorAll("button"))) b.disabled = false;
        btn.setText(label);
        progressEl.setText(`Failed: ${e instanceof Error ? e.message : String(e)} (retryable, the completed part will not be reprocessed)`);
      }
    };
    const onProgress = (p) => {
      progressEl.setText(`Processing ${p.done}/${p.total}\uFF1A${p.current}`);
    };
    switch (scenario) {
      case "both-empty": {
        contentEl.createEl("p", { text: "Both the local and remote vaults are empty. Set an end-to-end encryption password to finish initializing." });
        this.renderE2eeNote(contentEl);
        const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
        this.renderE2eeButton(footer);
        break;
      }
      case "local-only": {
        contentEl.createEl("p", {
          text: `The remote vault is empty. After you set an E2EE password, this device's ${pre.localPaths.length} files will be uploaded as ciphertext as the remote's initial content.`
        });
        this.renderE2eeNote(contentEl);
        const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
        this.renderE2eeButton(footer);
        break;
      }
      case "remote-only": {
        contentEl.createEl("p", {
          text: `The local vault is empty. All ${pre.remoteFiles.length} files will be downloaded from the remote.`
        });
        const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
        const btn = footer.createEl("button", { text: "Restore This Device from Remote", cls: "mod-cta" });
        btn.onclick = () => void run(btn, "Restore", async () => {
          await bootstrapRemoteWins(this.ctx, pre, onProgress);
          new import_obsidian6.Notice(`Restored ${pre.remoteFiles.length} files from remote ✓`);
        });
        break;
      }
      case "both": {
        contentEl.createEl("p", {
          text: `The current vault already contains ${pre.localPaths.length} files, and the remote already has ${pre.remoteFiles.length} files. Choose how to join:`
        });
        const optA = contentEl.createDiv({ cls: "litesync-hunk" });
        optA.createDiv({ cls: "litesync-hunk-label", text: "Restore from remote, replacing local content (recommended for new devices)" });
        optA.createDiv({
          cls: "litesync-history-meta",
          text: "Files synced on this device take the remote version; differing local content is moved to the trash first, never permanently deleted."
        });
        const btnA = optA.createEl("button", { text: "Restore This Device from Remote", cls: "mod-cta" });
        btnA.onclick = () => void run(btnA, "Restore", async () => {
          await bootstrapRemoteWins(this.ctx, pre, onProgress);
          new import_obsidian6.Notice("Restored this device from remote ✓ (replaced local content is in the trash)");
        });
        const optB = contentEl.createDiv({ cls: "litesync-hunk" });
        optB.createDiv({ cls: "litesync-hunk-label", text: "Keep local content and merge with remote" });
        optB.createDiv({
          cls: "litesync-history-meta",
          text: "Neither side loses data: complementary files sync to each other; Markdown at the same path with different content goes to the conflict resolver, and other files keep both versions."
        });
        const btnB = optB.createEl("button", { text: "Merge with Remote" });
        btnB.onclick = () => void run(btnB, "Merge", async () => {
          const r = await bootstrapMerge(this.ctx, pre, onProgress);
          new import_obsidian6.Notice(
            `Merge complete ✓ downloaded ${r.downloaded}, uploaded ${r.uploaded}` + (r.conflicts > 0 ? `\u3001${r.conflicts} conflicts pending (see the status bar)` : ""),
            1e4
          );
        });
        break;
      }
    }
    contentEl.createDiv({
      cls: "litesync-history-meta",
      text: "Normal incremental sync starts automatically once you have joined."
    });
  }
};

// src/bootstrap/first-sync-modal.ts
var import_obsidian7 = require("obsidian");
var FirstSyncModal = class extends import_obsidian7.Modal {
  constructor(app, choices) {
    super(app);
    this.choices = choices;
  }
  onOpen() {
    this.titleEl.setText("Connected: the remote vault is not initialized yet");
    const { contentEl } = this;
    contentEl.createEl("p", { text: "The server is working fine but has no content yet. Initialize the local vault to the remote now?" });
    contentEl.createEl("p", {
      cls: "litesync-history-meta",
      text: "Initialization needs an end-to-end encryption (E2EE) password first — the first upload is ciphertext and the server never sees plaintext. If the password is lost the data cannot be recovered; keep it safe."
    });
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    footer.createEl("button", { text: "Close" }).onclick = () => this.close();
    footer.createEl("button", { text: "Set E2EE and sync now", cls: "mod-cta" }).onclick = () => {
      this.close();
      this.choices.withE2ee();
    };
  }
};

// src/conflict-ui/conflict-view.ts
var import_obsidian8 = require("obsidian");

// src/conflict-ui/conflict-actions.ts
async function loadConflict(ctx, path) {
  requireSyncSafe(ctx, "Resolve Sync Conflicts");
  const pending = ctx.store.getConflict(path);
  if (!pending) throw new Error("This file is no longer in conflict");
  let remote;
  try {
    remote = await downloadPlain(ctx, path);
  } catch (e) {
    if (e instanceof NotFoundError) {
      ctx.store.clearConflict(path);
      ctx.store.markDeleted(path);
      ctx.queue.stage(path, { action: "upsert" });
      await ctx.store.save();
      throw new Error("The remote file was deleted; the local content will be re-uploaded on the next sync");
    }
    throw e;
  }
  const remoteText = decodeUtf8Strict(remote.plain);
  if (remoteText === null) throw new Error("The remote content is not UTF-8 text");
  const adapter = ctx.app.vault.adapter;
  let localText = "";
  let localHash = "";
  if (await adapter.stat(path)) {
    const data = await adapter.readBinary(path);
    const t = decodeUtf8Strict(data);
    if (t === null) throw new Error("The local content is not UTF-8 text");
    localText = t;
    localHash = await sha256Hex(data);
  }
  let baseText = null;
  try {
    const baseDl = await versionPlain(ctx, path, pending.baseRevision);
    baseText = decodeUtf8Strict(baseDl.plain);
  } catch {
    baseText = null;
  }
  const merge = smartThreeWayMerge({ base: baseText ?? "", local: localText, remote: remoteText });
  pending.remoteRevision = remote.revision;
  ctx.store.recordConflict(path, pending);
  return {
    path,
    pending,
    remoteRevision: remote.revision,
    remoteGeneration: remote.generation,
    localText,
    localHash,
    remoteText,
    baseText,
    merge
  };
}
var LocalChangedError = class extends Error {
  constructor(path) {
    super(`The local file was modified while being processed: ${path}`);
    this.name = "LocalChangedError";
  }
};
async function saveResolution(ctx, path, finalText, remoteRevision, expectedLocalHash, remoteGeneration) {
  requireSyncSafe(ctx, "Save conflict resolution");
  const data = encodeUtf8(finalText);
  const hash = await sha256Hex(data);
  const out = await uploadFromPlain(ctx, path, data, remoteRevision, Date.now(), "merge", {
    generationFloor: remoteGeneration
  });
  const wrote = await writeIfLocalUnchanged(ctx, path, data, expectedLocalHash === "" ? null : expectedLocalHash);
  if (!wrote) throw new LocalChangedError(path);
  const stat = await ctx.app.vault.adapter.stat(path);
  ctx.store.update(path, {
    hash,
    serverHash: out.cipherHash,
    revision: out.revision,
    mtime: stat?.mtime ?? Date.now(),
    size: data.byteLength,
    fileId: out.fileId,
    generation: out.generation,
    metaGeneration: out.metaGeneration,
    serverPseudonym: out.serverPseudonym
  });
  ctx.store.clearConflict(path);
  await ctx.store.save();
  ctx.log(`resolver: merged ${path} \u2192 rev ${out.revision}`);
  return out.revision;
}
async function keepBothForConflict(ctx, path) {
  const adapter = ctx.app.vault.adapter;
  if (await adapter.stat(path)) {
    const localData = await adapter.readBinary(path);
    ctx.store.clearConflict(path);
    await keepBothVersions(ctx, path, localData);
  } else {
    ctx.store.clearConflict(path);
  }
  await ctx.store.save();
}

// src/conflict-ui/conflict-state.ts
function listPendingConflicts(ctx) {
  return ctx.store.conflictPaths().map((p) => [p, ctx.store.getConflict(p)]);
}

// src/conflict-ui/conflict-view.ts
var ConflictListModal = class extends import_obsidian8.Modal {
  constructor(ctx) {
    super(ctx.app);
    this.ctx = ctx;
  }
  onOpen() {
    this.titleEl.setText("Unresolved sync conflicts");
    this.render();
  }
  render() {
    const { contentEl } = this;
    contentEl.empty();
    const conflicts = listPendingConflicts(this.ctx);
    if (conflicts.length === 0) {
      contentEl.setText("No unresolved conflicts ✓");
      return;
    }
    const list = contentEl.createDiv({ cls: "litesync-conflict-list" });
    for (const [path, pending] of conflicts) {
      const item = list.createDiv({ cls: "litesync-conflict-item" });
      const info = item.createDiv();
      info.createDiv({ text: `\u25CF ${path}` });
      info.createDiv({
        cls: "litesync-history-meta",
        text: `Found at ${new Date(pending.createdAt).toLocaleString()}`
      });
      item.createEl("button", { text: "Process" });
      item.onclick = () => {
        this.close();
        new ResolverModal(this.ctx, path).open();
      };
    }
  }
};
var ResolverModal = class extends import_obsidian8.Modal {
  constructor(ctx, path) {
    super(ctx.app);
    this.ctx = ctx;
    this.path = path;
    this.loaded = null;
    /** 每个冲突段的当前选择文本（undefined = 未选择） */
    this.choices = {};
    this.manualEdit = false;
    this.mergedTextarea = null;
    this.hunkEls = [];
    this.currentHunk = 0;
  }
  async onOpen() {
    this.modalEl.addClass("mod-sync-resolver");
    this.titleEl.setText(`Resolve Conflict — ${this.path}`);
    this.contentEl.setText("Loading…");
    await this.reload();
  }
  async reload() {
    this.choices = {};
    this.manualEdit = false;
    this.hunkEls = [];
    this.currentHunk = 0;
    try {
      this.loaded = await loadConflict(this.ctx, this.path);
    } catch (e) {
      this.contentEl.setText(e instanceof Error ? e.message : String(e));
      this.ctx.onConflictsChanged();
      return;
    }
    if (this.loaded.merge.clean) {
      try {
        await saveResolution(
          this.ctx,
          this.path,
          this.loaded.merge.mergedText,
          this.loaded.remoteRevision,
          this.loaded.localHash,
          this.loaded.remoteGeneration
        );
        new import_obsidian8.Notice(`Conflict resolved automatically: ${this.path}`);
        this.ctx.onConflictsChanged();
        this.close();
        return;
      } catch {
      }
    }
    this.render();
  }
  render() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("litesync-resolver");
    const loaded = this.loaded;
    if (loaded.baseText === null) {
      contentEl.createDiv({
        cls: "litesync-history-meta",
        text: "The common ancestor version is no longer available, so the comparison is made whole between \"local\" and \"remote\"."
      });
    }
    const panes = contentEl.createDiv({ cls: "litesync-resolver-panes" });
    const localPane = panes.createDiv({ cls: "litesync-resolver-pane" });
    localPane.createEl("h4", { text: "Local (this device)" });
    localPane.createEl("pre", { cls: "litesync-resolver-pre", text: loaded.localText });
    const remotePane = panes.createDiv({ cls: "litesync-resolver-pane" });
    remotePane.createEl("h4", { text: `Remote (server rev ${loaded.remoteRevision}\uFF09` });
    remotePane.createEl("pre", { cls: "litesync-resolver-pre", text: loaded.remoteText });
    const hunksBox = contentEl.createDiv();
    const conflicts = loaded.merge.conflicts;
    const nav = contentEl.createDiv({ cls: "litesync-hunk-buttons" });
    nav.createEl("button", { text: "Previous conflict" }).onclick = () => this.gotoHunk(this.currentHunk - 1);
    nav.createEl("button", { text: "Next conflict" }).onclick = () => this.gotoHunk(this.currentHunk + 1);
    const autoResolved = loaded.merge.stats?.autoResolved ?? 0;
    nav.createSpan({
      cls: "litesync-history-meta",
      text: `Total ${conflicts.length} conflicts` + (autoResolved > 0 ? ` (plus ${autoResolved} auto-merged by suggestion)` : "")
    });
    const suggestionAppliers = [];
    const suggestedCount = conflicts.filter((c) => c.suggestedText !== void 0).length;
    if (suggestedCount > 0) {
      nav.createEl("button", { text: `Accept all suggestions (${suggestedCount})`, cls: "mod-cta" }).onclick = () => {
        for (const apply of suggestionAppliers) apply();
      };
    }
    conflicts.forEach((c, idx) => {
      const box = hunksBox.createDiv({ cls: "litesync-hunk" });
      this.hunkEls.push(box);
      box.createDiv({ cls: "litesync-hunk-label", text: `Conflict #${idx + 1}` });
      if (c.baseText !== "" || c.localText === "" || c.remoteText === "") {
        box.createDiv({ cls: "litesync-hunk-label", text: "BASE:" });
        box.createDiv({ cls: "litesync-hunk-text", text: c.baseText || "(empty)" });
      }
      box.createDiv({ cls: "litesync-hunk-label", text: "LOCAL:" });
      box.createDiv({ cls: "litesync-hunk-text litesync-hunk-local", text: c.localText || "(delete this hunk)" });
      box.createDiv({ cls: "litesync-hunk-label", text: "REMOTE:" });
      box.createDiv({ cls: "litesync-hunk-text litesync-hunk-remote", text: c.remoteText || "(delete this hunk)" });
      let bSuggest = null;
      if (c.suggestedText !== void 0) {
        const confidenceText = c.confidence === "high" ? "high" : c.confidence === "low" ? "low" : "…";
        const sug = box.createDiv({ cls: "litesync-hunk-suggest" });
        sug.createDiv({
          cls: "litesync-hunk-label",
          text: `LiteSync suggestion (confidence: ${confidenceText}\uFF09\uFF1A${c.reason ?? ""}`
        });
        sug.createDiv({ cls: "litesync-hunk-text", text: c.suggestedText || "(delete this hunk)" });
      }
      const btns = box.createDiv({ cls: "litesync-hunk-buttons" });
      if (c.suggestedText !== void 0) {
        bSuggest = btns.createEl("button", { text: "Accept suggestion", cls: "mod-cta" });
      }
      const bLocal = btns.createEl("button", { text: "Use local" });
      const bRemote = btns.createEl("button", { text: "Use remote" });
      const bBoth = btns.createEl("button", { text: "Use both" });
      const allBtns = [bLocal, bRemote, bBoth, ...bSuggest ? [bSuggest] : []];
      const pick = (text, chosen) => {
        this.choices[c.id] = text;
        box.addClass("litesync-hunk-resolved");
        for (const b of allBtns) b.removeClass("litesync-chosen");
        chosen.addClass("litesync-chosen");
        this.refreshMerged();
      };
      if (bSuggest) {
        const applySuggestion = () => pick(c.suggestedText, bSuggest);
        bSuggest.onclick = applySuggestion;
        suggestionAppliers.push(() => {
          if (this.choices[c.id] === void 0) applySuggestion();
        });
      }
      bLocal.onclick = () => pick(c.localText, bLocal);
      bRemote.onclick = () => pick(c.remoteText, bRemote);
      bBoth.onclick = () => pick(
        c.localText === "" ? c.remoteText : c.remoteText === "" ? c.localText : `${c.localText}
${c.remoteText}`,
        bBoth
      );
    });
    const mergedBox = contentEl.createDiv({ cls: "litesync-resolver-merged" });
    mergedBox.createEl("h4", { text: "Merged result (editable)" });
    this.mergedTextarea = mergedBox.createEl("textarea");
    this.mergedTextarea.placeholder = "Choose Use local / Use remote / Use both for each hunk, or edit the final content directly";
    this.mergedTextarea.addEventListener("input", () => {
      this.manualEdit = true;
    });
    this.refreshMerged();
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    const saveBtn = footer.createEl("button", { text: "Save merge", cls: "mod-cta" });
    saveBtn.onclick = () => void this.save();
    footer.createEl("button", { text: "Keep both (keep both versions)" }).onclick = () => void this.keepBoth();
    footer.createEl("button", { text: "Cancel" }).onclick = () => this.close();
  }
  gotoHunk(idx) {
    if (this.hunkEls.length === 0) return;
    this.currentHunk = Math.max(0, Math.min(idx, this.hunkEls.length - 1));
    this.hunkEls[this.currentHunk].scrollIntoView({ behavior: "smooth", block: "center" });
  }
  /** 根据当前选择重建合并预览（用户手动编辑后不再自动覆盖）。 */
  refreshMerged() {
    if (!this.mergedTextarea || this.manualEdit || !this.loaded) return;
    const allChosen = this.loaded.merge.conflicts.every((c) => this.choices[c.id] !== void 0);
    if (!allChosen) return;
    this.mergedTextarea.value = assembleResolution(this.loaded.merge.segments, this.choices);
  }
  finalText() {
    if (!this.loaded) return null;
    if (this.manualEdit) return this.mergedTextarea?.value ?? null;
    const allChosen = this.loaded.merge.conflicts.every((c) => this.choices[c.id] !== void 0);
    if (!allChosen) return null;
    return assembleResolution(this.loaded.merge.segments, this.choices);
  }
  async save() {
    const text = this.finalText();
    if (text === null) {
      new import_obsidian8.Notice("There are still unresolved hunks (or the merged result is empty)");
      return;
    }
    try {
      const rev = await saveResolution(
        this.ctx,
        this.path,
        text,
        this.loaded.remoteRevision,
        this.loaded.localHash,
        this.loaded.remoteGeneration
      );
      new import_obsidian8.Notice(`Merge complete: ${this.path} \u2192 Revision ${rev}`);
      this.ctx.onConflictsChanged();
      this.close();
    } catch (e) {
      if (e instanceof ConflictError) {
        new import_obsidian8.Notice("The remote changed again while being processed — the latest version was reloaded, please confirm the merge again");
        this.contentEl.setText("Reloading…");
        await this.reload();
      } else if (e instanceof LocalChangedError) {
        new import_obsidian8.Notice("The local file was modified while being processed — reloaded, please confirm the merge again");
        this.contentEl.setText("Reloading…");
        await this.reload();
      } else {
        new import_obsidian8.Notice(`Save failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }
  async keepBoth() {
    try {
      await keepBothForConflict(this.ctx, this.path);
      this.ctx.onConflictsChanged();
      this.close();
    } catch (e) {
      new import_obsidian8.Notice(`Operation failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
};

// src/crypto/device-trust.ts
var VAULT_KEY_SECRET_ID = "litesync-vault-key";
var API_TOKEN_SECRET_ID = "litesync-api-token";
function keyIdOf(doc) {
  return doc.wrappedKey.slice(0, 24);
}
function trustAad(keyId) {
  return new TextEncoder().encode(`litesync/v1/device-trust:${keyId}`);
}
async function wrapVmkForDevice(deviceKeyRaw, vmkRaw, keyId) {
  const key = await crypto.subtle.importKey("raw", deviceKeyRaw, { name: "AES-GCM" }, false, [
    "encrypt"
  ]);
  const iv = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: trustAad(keyId) },
      key,
      vmkRaw
    )
  );
  const blob = { v: 1, keyId, iv: b64encode(iv), data: b64encode(ct) };
  return JSON.stringify(blob);
}
async function unwrapVmkForDevice(deviceKeyRaw, blobJson, expectedKeyId) {
  try {
    const blob = JSON.parse(blobJson);
    if (blob.v !== 1 || blob.keyId !== expectedKeyId) return null;
    const key = await crypto.subtle.importKey(
      "raw",
      deviceKeyRaw,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    const raw = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64decode(blob.iv),
        additionalData: trustAad(blob.keyId)
      },
      key,
      b64decode(blob.data)
    );
    return new Uint8Array(raw);
  } catch {
    return null;
  }
}
async function persistTrustedDevice(app, existingDeviceKeyB64, keyring) {
  if (!keyring.doc || !keyring.unlocked) return null;
  const deviceKey = existingDeviceKeyB64 ? b64decode(existingDeviceKeyB64) : randomBytes(32);
  const vmkRaw = await exportVmkRaw(keyring.requireKey());
  try {
    const blob = await wrapVmkForDevice(deviceKey, vmkRaw, keyIdOf(keyring.doc));
    app.secretStorage.setSecret(VAULT_KEY_SECRET_ID, blob);
  } finally {
    vmkRaw.fill(0);
  }
  return b64encode(deviceKey);
}
async function loadTrustedVmk(app, deviceKeyB64, doc) {
  if (!deviceKeyB64) return null;
  const blob = app.secretStorage.getSecret(VAULT_KEY_SECRET_ID);
  if (!blob) return null;
  return unwrapVmkForDevice(b64decode(deviceKeyB64), blob, keyIdOf(doc));
}
function forgetTrustedDevice(app) {
  app.secretStorage.setSecret(VAULT_KEY_SECRET_ID, "");
}

// src/crypto/meta-modals.ts
var import_obsidian9 = require("obsidian");
var ConfirmMetaEncryptionModal = class extends import_obsidian9.Modal {
  constructor(app, allowIrreversibleErase, onConfirm) {
    super(app);
    this.allowIrreversibleErase = allowIrreversibleErase;
    this.onConfirm = onConfirm;
  }
  onOpen() {
    this.titleEl.setText("Encrypt Paths & File Names (Experimental)");
    const { contentEl } = this;
    contentEl.createEl("p", {
      text: "This operation replaces every file path and file name on the server with a random pseudonym; the real paths are stored end-to-end encrypted."
    });
    contentEl.createEl("p", {
      cls: "mod-warning",
      text: "v0.12.x is not suitable for your only real vault — use it only on a test vault or a fully backed-up copy."
    });
    const ul = contentEl.createEl("ul");
    ul.createEl("li", { text: "Server backups from before the migration may still contain plaintext paths; this operation neither will nor can clean them up" });
    ul.createEl("li", { text: "Prerequisites: E2EE enabled, \"Upgrade Encryption Envelopes LSE1 → LSE3\" run, no unresolved conflicts" });
    ul.createEl("li", { text: "All devices must be upgraded to 0.12+; older versions cannot read this vault" });
    ul.createEl("li", { text: "Re-run this command after the interruption to resume" });
    if (this.allowIrreversibleErase) {
      ul.createEl("li", {
        cls: "mod-warning",
        text: "You have turned on the developer switch \"allow irreversible plaintext path erasure\": once complete, the plaintext path records on the server are erased and the real paths can no longer be recovered by an ordinary rollback (the v0.12.1 server still refuses this step while plaintext tombstones exist)"
      });
    } else {
      ul.createEl("li", {
        text: "This run will not perform the irreversible plaintext erasure: the migration stops at the reversible \"pseudonymised but not erased\" state, and you can always \"Abort Path Encryption Migration\" in settings to return to plain. Wait for the v0.13.0 privacy tombstone ledger for the real erasure"
      });
    }
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    footer.createEl("button", { text: "I understand, start pseudonymising", cls: "mod-warning" }).onclick = () => {
      this.close();
      this.onConfirm();
    };
    footer.createEl("button", { text: "Cancel" }).onclick = () => this.close();
  }
};

// src/history/history-view.ts
var import_obsidian10 = require("obsidian");
var ACTION_LABEL = {
  upsert: "Modify",
  delete: "Delete",
  restore: "Restore",
  merge: "Merge"
};
function formatTime(unixSeconds) {
  return new Date(unixSeconds * 1e3).toLocaleString();
}
function formatSize(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}
var HistoryModal = class extends import_obsidian10.Modal {
  constructor(ctx, path) {
    super(ctx.app);
    this.ctx = ctx;
    this.path = path;
  }
  async onOpen() {
    this.titleEl.setText(`Version History — ${this.path}`);
    this.contentEl.addClass("litesync-history");
    this.contentEl.setText("Loading…");
    let versions;
    try {
      requireSyncSafe(this.ctx, "View Version History");
      versions = await historyOf(this.ctx, this.path);
    } catch (e) {
      this.contentEl.setText(`Failed to load history: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }
    this.contentEl.empty();
    if (versions.length === 0) {
      this.contentEl.setText("No history versions yet (the server has history disabled, or the file has not synced yet).");
      return;
    }
    const current = this.ctx.store.get(this.path);
    const list = this.contentEl.createDiv({ cls: "litesync-history-list" });
    for (const v of versions) {
      const row = list.createDiv({ cls: "litesync-history-row" });
      const info = row.createDiv({ cls: "litesync-history-info" });
      const title = info.createDiv();
      title.createSpan({ cls: "litesync-rev", text: `Revision ${v.revision}` });
      title.createSpan({
        cls: `litesync-badge litesync-badge-${v.action}`,
        text: ACTION_LABEL[v.action] ?? v.action
      });
      if (current && v.revision === current.revision) {
        title.createSpan({ cls: "litesync-badge litesync-badge-current", text: "Current" });
      }
      info.createDiv({
        cls: "litesync-history-meta",
        text: `${formatTime(v.createdAt)}` + (v.deviceId ? ` \xB7 ${v.deviceId.slice(0, 12)}` : "") + (v.action !== "delete" ? ` \xB7 ${formatSize(v.size)}` : "")
      });
      if (v.action !== "delete") {
        const btns = row.createDiv({ cls: "litesync-history-actions" });
        btns.createEl("button", { text: "Compare" }).onclick = () => void this.compare(v);
        btns.createEl("button", { text: "Restore" }).onclick = () => void this.restore(v);
        btns.createEl("button", { text: "Save a copy" }).onclick = () => void this.saveCopy(v);
      }
    }
  }
  async compare(v) {
    try {
      const dl = await versionPlain(this.ctx, this.path, v.revision);
      const old = decodeUtf8Strict(dl.plain);
      if (old === null) {
        new import_obsidian10.Notice("Binary files do not support text comparison");
        return;
      }
      const adapter = this.ctx.app.vault.adapter;
      let currentText = "";
      if (await adapter.stat(this.path)) {
        const cur = decodeUtf8Strict(await adapter.readBinary(this.path));
        if (cur === null) {
          new import_obsidian10.Notice("The current file is binary and cannot be compared as text");
          return;
        }
        currentText = cur;
      }
      new DiffModal(this.ctx, this.path, v.revision, old, currentText).open();
    } catch (e) {
      if (e instanceof NotFoundError) new import_obsidian10.Notice("That version's content has been cleaned up by the server");
      else if (e instanceof DiffTooLargeError) new import_obsidian10.Notice("The file differences are too large to compare");
      else new import_obsidian10.Notice(`Comparison failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  /**
   * 恢复历史版本：不回退 HEAD，而是把旧内容作为新 revision 上传（action=restore），
   * 保持历史线性可追踪（计划书 Phase 13）。
   */
  async restore(v) {
    try {
      requireSyncSafe(this.ctx, "Restore Version History");
      const dl = await versionPlain(this.ctx, this.path, v.revision);
      const tracked = this.ctx.store.get(this.path);
      if (tracked && tracked.hash === dl.plainHash) {
        new import_obsidian10.Notice("That version matches the current content — no restore needed");
        return;
      }
      const out = await uploadFromPlain(
        this.ctx,
        this.path,
        dl.plain,
        tracked?.revision ?? 0,
        dl.mtime || Date.now(),
        "restore"
      );
      const adapter = this.ctx.app.vault.adapter;
      const cur = await adapter.stat(this.path);
      const curHash = cur ? await sha256Hex(await adapter.readBinary(this.path)) : null;
      if (!await writeIfLocalUnchanged(this.ctx, this.path, dl.plain, curHash, dl.mtime)) {
        const copy = await this.writeSideCopy(dl.plain, v.revision);
        new import_obsidian10.Notice(`The local file was modified during the restore, so revision ${v.revision} saved as ${copy}`);
        this.close();
        return;
      }
      const stat = await adapter.stat(this.path);
      this.ctx.store.update(this.path, {
        hash: dl.plainHash,
        serverHash: out.cipherHash,
        revision: out.revision,
        mtime: stat?.mtime ?? Date.now(),
        size: dl.plain.byteLength,
        fileId: out.fileId,
        generation: out.generation,
        metaGeneration: out.metaGeneration,
        serverPseudonym: out.serverPseudonym
      });
      await this.ctx.store.save();
      new import_obsidian10.Notice(`Restored revision ${v.revision} → new revision ${out.revision}`);
      this.close();
    } catch (e) {
      if (e instanceof ConflictError) {
        new import_obsidian10.Notice("The local vault and the server are out of sync — run \"Sync Now\" before restoring");
      } else if (e instanceof NotFoundError) {
        new import_obsidian10.Notice("That version's content has been cleaned up by the server and cannot be restored");
      } else {
        new import_obsidian10.Notice(`Restore failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }
  async saveCopy(v) {
    try {
      requireSyncSafe(this.ctx, "Save a Copy of the History Version");
      const dl = await versionPlain(this.ctx, this.path, v.revision);
      const copyPath = await this.writeSideCopy(dl.plain, v.revision);
      new import_obsidian10.Notice(`Saved a copy as ${copyPath}`);
    } catch (e) {
      if (e instanceof NotFoundError) new import_obsidian10.Notice("That version's content has been cleaned up by the server");
      else new import_obsidian10.Notice(`Failed to save a copy: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  /**
   * 把某个历史版本写成一份**新文件**（§6.1）。
   *
   * 目标名被占用时换一个，绝不覆盖已有文件——历史副本的存在价值就是「多留一份」，
   * 为它覆盖掉别的内容是本末倒置。
   */
  async writeSideCopy(plain, revision) {
    const slash = this.path.lastIndexOf("/");
    const dot = this.path.lastIndexOf(".");
    const hasExt = dot > slash + 1;
    const stem = hasExt ? this.path.slice(0, dot) : this.path;
    const ext = hasExt ? this.path.slice(dot) : "";
    for (let i = 0; ; i++) {
      const candidate = i === 0 ? `${stem}.rev-${revision}${ext}` : `${stem}.rev-${revision}-${i}${ext}`;
      if (await writeIfLocalUnchanged(this.ctx, candidate, plain, null)) return candidate;
      if (i >= 20) throw new Error("Cannot create a history copy: all target file names are already taken");
    }
  }
};
var DiffModal = class extends import_obsidian10.Modal {
  constructor(ctx, path, revision, oldText, newText) {
    super(ctx.app);
    this.path = path;
    this.revision = revision;
    this.oldText = oldText;
    this.newText = newText;
  }
  onOpen() {
    this.titleEl.setText(`Revision ${this.revision} vs current — ${this.path}`);
    this.contentEl.addClass("litesync-diff");
    let lines;
    try {
      lines = diffLinesView(this.oldText, this.newText);
    } catch {
      this.contentEl.setText("The file differences are too large to compare");
      return;
    }
    const box = this.contentEl.createEl("pre", { cls: "litesync-diff-box" });
    let same = 0;
    for (const line of lines) {
      if (line.type === "same") same++;
      const el = box.createDiv({ cls: `litesync-diff-line litesync-diff-${line.type}` });
      el.setText((line.type === "add" ? "+ " : line.type === "del" ? "- " : "  ") + line.text);
    }
    if (same === lines.length) {
      this.contentEl.createDiv({ text: "Both versions have identical content." });
    }
  }
};

// src/pairing/device-list-modal.ts
var import_obsidian11 = require("obsidian");
var DeviceListModal = class extends import_obsidian11.Modal {
  constructor(app, client) {
    super(app);
    this.client = client;
  }
  onOpen() {
    this.titleEl.setText("Registered devices");
    this.contentEl.setText("Loading…");
    void this.render();
  }
  async render() {
    const { contentEl } = this;
    try {
      const devices = await this.client.listDevices();
      contentEl.empty();
      if (devices.length === 0) {
        contentEl.setText("No device credential yet (the first sync will issue one for this device)");
        return;
      }
      const list = contentEl.createDiv({ cls: "litesync-conflict-list" });
      for (const d of devices) {
        const item = list.createDiv({ cls: "litesync-conflict-item" });
        const info = item.createDiv();
        info.createDiv({
          text: `${d.revoked ? "\u26D4 " : "\u25CF "}${d.name || d.id}${d.current ? " (this device)" : ""}`
        });
        info.createDiv({
          cls: "litesync-history-meta",
          text: `ID ${d.id} · Scope ${d.scopes} · Registered ${new Date(d.createdAt * 1e3).toLocaleDateString()}` + (d.lastSeenAt > 0 ? ` · Last active ${new Date(d.lastSeenAt * 1e3).toLocaleString()}` : "") + (d.revoked ? " · Revoked" : "")
        });
      }
      contentEl.createDiv({
        cls: "litesync-history-meta",
        text: 'Revoking a device needs the server root Token (by design: a stolen device must not be able to revoke other devices).\nRun this on the server: curl -X DELETE -H "Authorization: Bearer ***" <ServerURL>/api/v1/devices/<DEVICE_ID>'
      });
    } catch (e) {
      contentEl.setText(`Failed to load: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
};

// src/pairing/import-handler.ts
var import_obsidian13 = require("obsidian");

// src/pairing/pairing.ts
var import_obsidian12 = require("obsidian");
var PAIRING_AAD = "litesync/v1/pairing";
function aadBytes() {
  return new TextEncoder().encode(PAIRING_AAD);
}
function newPairSecret() {
  return randomBytes(32);
}
async function encryptPairingConfig(secretRaw, config) {
  const key = await crypto.subtle.importKey("raw", secretRaw, { name: "AES-GCM" }, false, [
    "encrypt"
  ]);
  const iv = randomBytes(12);
  const plain = new TextEncoder().encode(JSON.stringify(config));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aadBytes() },
      key,
      plain
    )
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return b64encode(out);
}
async function decryptPairingConfig(secretRaw, ciphertextB64) {
  try {
    const raw = b64decode(ciphertextB64);
    if (raw.length < 13) return null;
    const key = await crypto.subtle.importKey("raw", secretRaw, { name: "AES-GCM" }, false, [
      "decrypt"
    ]);
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: raw.slice(0, 12),
        additionalData: aadBytes()
      },
      key,
      raw.slice(12)
    );
    const config = JSON.parse(new TextDecoder().decode(plain));
    if (typeof config.serverUrl !== "string") return null;
    if (config.v === 1 && typeof config.apiToken === "string") return config;
    if (config.v === 2 && typeof config.enrollmentSecret === "string") return config;
    return null;
  } catch {
    return null;
  }
}
function b64urlDecode(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4);
  return b64decode(b64);
}
function buildPairUrl(serverUrl, id, secretRaw) {
  return `${serverUrl.replace(/\/+$/, "")}/p/${id}#secret=${b64urlEncode(secretRaw)}`;
}
function parsePairUrl(url) {
  try {
    const u = new URL(url.trim());
    if (u.protocol === "http:" && !isLoopbackHost(u.hostname)) return null;
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    const m = /^\/p\/([0-9a-f]+)$/i.exec(u.pathname);
    if (!m) return null;
    const secret = new URLSearchParams(u.hash.slice(1)).get("secret");
    if (!secret) return null;
    return { serverUrl: u.origin, id: m[1], secretB64url: secret };
  } catch {
    return null;
  }
}
function isLoopbackHost(host) {
  const h = host.toLowerCase();
  return h === "localhost" || h === "::1" || h === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}
async function consumePairing(serverUrl, id) {
  const res = await (0, import_obsidian12.requestUrl)({
    url: `${serverUrl.replace(/\/+$/, "")}/pair/${encodeURIComponent(id)}/consume`,
    method: "POST",
    throw: false
  });
  if (res.status === 404) return null;
  if (res.status !== 200) throw new Error(`pairing consume failed: HTTP ${res.status}`);
  const body = res.json;
  return typeof body.ciphertext === "string" ? body.ciphertext : null;
}

// src/pairing/import-handler.ts
function registerImportHandler(plugin) {
  plugin.registerObsidianProtocolHandler("litesync-import", (params) => {
    void handleImportParams(plugin, params.server, params.id, params.secret);
  });
}
async function handleImportParams(plugin, server, id, secretB64url) {
  if (!server || !id || !secretB64url || !/^https?:\/\//i.test(server)) {
    new import_obsidian13.Notice("The pairing link is incomplete or corrupted — regenerate it on the original device");
    return;
  }
  const ok = await confirmImport(plugin.app, server);
  if (!ok) return;
  try {
    const ciphertext = await consumePairing(server, id);
    if (ciphertext === null) {
      new import_obsidian13.Notice("The pairing package does not exist, has expired, or has already been used — regenerate it on the original device");
      return;
    }
    const secret = b64urlDecode(secretB64url);
    const config = await decryptPairingConfig(secret, ciphertext);
    secret.fill(0);
    if (config === null) {
      new import_obsidian13.Notice("Failed to decrypt the pairing package (key mismatch or tampered data)");
      return;
    }
    await applyPairingConfig(plugin, config);
    new import_obsidian13.Notice("LiteSync config imported ✓ now finish joining this device");
    plugin.openBootstrapWizard();
  } catch (e) {
    new import_obsidian13.Notice(`Import failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}
async function applyPairingConfig(plugin, config) {
  const url = config.serverUrl.trim().replace(/\/+$/, "");
  if (/^http:\/\//i.test(url) && !isLoopbackHost(new URL(url).hostname)) {
    throw new Error("The Server URL in the pairing config uses a non-local http:// address — import refused (the token would be exposed in plaintext)");
  }
  plugin.settings.serverUrl = url;
  if (typeof config.syncIntervalSeconds === "number") {
    plugin.settings.syncIntervalSeconds = config.syncIntervalSeconds;
  }
  if (typeof config.syncObsidian === "boolean") plugin.settings.syncObsidian = config.syncObsidian;
  if (typeof config.ignorePatterns === "string") plugin.settings.ignorePatterns = config.ignorePatterns;
  if (config.v === 2 && config.enrollmentSecret) {
    const cred = await enrollDevice(url, config.enrollmentSecret, plugin.settings.deviceName || "New device");
    await plugin.setApiToken(cred.deviceToken);
  } else if (config.apiToken) {
    await plugin.setApiToken(config.apiToken);
  } else {
    throw new Error("The pairing package is missing its credential field");
  }
  await plugin.saveSettings();
  plugin.applySettings();
  plugin.resetBootstrapState();
}
var PasteLinkModal = class extends import_obsidian13.Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }
  onOpen() {
    this.titleEl.setText("Import Pairing Link");
    const { contentEl } = this;
    contentEl.createEl("p", { text: "Paste the pairing link generated on the original device under \"Add New Device\":" });
    const input = contentEl.createEl("input", {
      type: "text",
      cls: "litesync-modal-input",
      placeholder: "https://sync.example.com/p/\u2026#secret=\u2026"
    });
    const errEl = contentEl.createDiv({ cls: "litesync-history-meta" });
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    const submit = () => {
      const parsed = parsePairUrl(input.value);
      if (!parsed) {
        errEl.setText("The link format is wrong (it needs to be a complete link containing /p/{id}#secret=…)");
        return;
      }
      this.close();
      void handleImportParams(this.plugin, parsed.serverUrl, parsed.id, parsed.secretB64url);
    };
    footer.createEl("button", { text: "Import", cls: "mod-cta" }).onclick = submit;
    footer.createEl("button", { text: "Cancel" }).onclick = () => this.close();
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit();
    });
    window.setTimeout(() => input.focus(), 50);
  }
};
function confirmImport(app, server) {
  return new Promise((resolve) => {
    new ConfirmImportModal(app, server, resolve).open();
  });
}
var ConfirmImportModal = class extends import_obsidian13.Modal {
  constructor(app, server, resolve) {
    super(app);
    this.server = server;
    this.resolve = resolve;
    this.decided = false;
  }
  onOpen() {
    this.titleEl.setText("Import LiteSync Config");
    const { contentEl } = this;
    contentEl.createEl("p", { text: "The sync configuration (Server URL, API Token and sync settings) will be imported from this server:" });
    contentEl.createEl("p").createEl("strong", { text: this.server });
    contentEl.createEl("p", {
      cls: "litesync-history-meta",
      text: "Only continue if this is a pairing link you generated yourself on another device. The current device's server configuration will be replaced."
    });
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    footer.createEl("button", { text: "Import", cls: "mod-cta" }).onclick = () => {
      this.decided = true;
      this.close();
      this.resolve(true);
    };
    footer.createEl("button", { text: "Cancel" }).onclick = () => this.close();
  }
  onClose() {
    if (!this.decided) this.resolve(false);
  }
};

// src/pairing/pairing-modal.ts
var import_obsidian14 = require("obsidian");

// node_modules/qrcode-generator/dist/qrcode.mjs
var qrcode = function(typeNumber, errorCorrectionLevel) {
  const PAD0 = 236;
  const PAD1 = 17;
  let _typeNumber = typeNumber;
  const _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
  let _modules = null;
  let _moduleCount = 0;
  let _dataCache = null;
  const _dataList = [];
  const _this = {};
  const makeImpl = function(test, maskPattern) {
    _moduleCount = _typeNumber * 4 + 17;
    _modules = (function(moduleCount) {
      const modules = new Array(moduleCount);
      for (let row = 0; row < moduleCount; row += 1) {
        modules[row] = new Array(moduleCount);
        for (let col = 0; col < moduleCount; col += 1) {
          modules[row][col] = null;
        }
      }
      return modules;
    })(_moduleCount);
    setupPositionProbePattern(0, 0);
    setupPositionProbePattern(_moduleCount - 7, 0);
    setupPositionProbePattern(0, _moduleCount - 7);
    setupPositionAdjustPattern();
    setupTimingPattern();
    setupTypeInfo(test, maskPattern);
    if (_typeNumber >= 7) {
      setupTypeNumber(test);
    }
    if (_dataCache == null) {
      _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
    }
    mapData(_dataCache, maskPattern);
  };
  const setupPositionProbePattern = function(row, col) {
    for (let r = -1; r <= 7; r += 1) {
      if (row + r <= -1 || _moduleCount <= row + r) continue;
      for (let c = -1; c <= 7; c += 1) {
        if (col + c <= -1 || _moduleCount <= col + c) continue;
        if (0 <= r && r <= 6 && (c == 0 || c == 6) || 0 <= c && c <= 6 && (r == 0 || r == 6) || 2 <= r && r <= 4 && 2 <= c && c <= 4) {
          _modules[row + r][col + c] = true;
        } else {
          _modules[row + r][col + c] = false;
        }
      }
    }
  };
  const getBestMaskPattern = function() {
    let minLostPoint = 0;
    let pattern = 0;
    for (let i = 0; i < 8; i += 1) {
      makeImpl(true, i);
      const lostPoint = QRUtil.getLostPoint(_this);
      if (i == 0 || minLostPoint > lostPoint) {
        minLostPoint = lostPoint;
        pattern = i;
      }
    }
    return pattern;
  };
  const setupTimingPattern = function() {
    for (let r = 8; r < _moduleCount - 8; r += 1) {
      if (_modules[r][6] != null) {
        continue;
      }
      _modules[r][6] = r % 2 == 0;
    }
    for (let c = 8; c < _moduleCount - 8; c += 1) {
      if (_modules[6][c] != null) {
        continue;
      }
      _modules[6][c] = c % 2 == 0;
    }
  };
  const setupPositionAdjustPattern = function() {
    const pos = QRUtil.getPatternPosition(_typeNumber);
    for (let i = 0; i < pos.length; i += 1) {
      for (let j = 0; j < pos.length; j += 1) {
        const row = pos[i];
        const col = pos[j];
        if (_modules[row][col] != null) {
          continue;
        }
        for (let r = -2; r <= 2; r += 1) {
          for (let c = -2; c <= 2; c += 1) {
            if (r == -2 || r == 2 || c == -2 || c == 2 || r == 0 && c == 0) {
              _modules[row + r][col + c] = true;
            } else {
              _modules[row + r][col + c] = false;
            }
          }
        }
      }
    }
  };
  const setupTypeNumber = function(test) {
    const bits = QRUtil.getBCHTypeNumber(_typeNumber);
    for (let i = 0; i < 18; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
    }
    for (let i = 0; i < 18; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
    }
  };
  const setupTypeInfo = function(test, maskPattern) {
    const data = _errorCorrectionLevel << 3 | maskPattern;
    const bits = QRUtil.getBCHTypeInfo(data);
    for (let i = 0; i < 15; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      if (i < 6) {
        _modules[i][8] = mod;
      } else if (i < 8) {
        _modules[i + 1][8] = mod;
      } else {
        _modules[_moduleCount - 15 + i][8] = mod;
      }
    }
    for (let i = 0; i < 15; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      if (i < 8) {
        _modules[8][_moduleCount - i - 1] = mod;
      } else if (i < 9) {
        _modules[8][15 - i - 1 + 1] = mod;
      } else {
        _modules[8][15 - i - 1] = mod;
      }
    }
    _modules[_moduleCount - 8][8] = !test;
  };
  const mapData = function(data, maskPattern) {
    let inc = -1;
    let row = _moduleCount - 1;
    let bitIndex = 7;
    let byteIndex = 0;
    const maskFunc = QRUtil.getMaskFunction(maskPattern);
    for (let col = _moduleCount - 1; col > 0; col -= 2) {
      if (col == 6) col -= 1;
      while (true) {
        for (let c = 0; c < 2; c += 1) {
          if (_modules[row][col - c] == null) {
            let dark = false;
            if (byteIndex < data.length) {
              dark = (data[byteIndex] >>> bitIndex & 1) == 1;
            }
            const mask = maskFunc(row, col - c);
            if (mask) {
              dark = !dark;
            }
            _modules[row][col - c] = dark;
            bitIndex -= 1;
            if (bitIndex == -1) {
              byteIndex += 1;
              bitIndex = 7;
            }
          }
        }
        row += inc;
        if (row < 0 || _moduleCount <= row) {
          row -= inc;
          inc = -inc;
          break;
        }
      }
    }
  };
  const createBytes = function(buffer, rsBlocks) {
    let offset = 0;
    let maxDcCount = 0;
    let maxEcCount = 0;
    const dcdata = new Array(rsBlocks.length);
    const ecdata = new Array(rsBlocks.length);
    for (let r = 0; r < rsBlocks.length; r += 1) {
      const dcCount = rsBlocks[r].dataCount;
      const ecCount = rsBlocks[r].totalCount - dcCount;
      maxDcCount = Math.max(maxDcCount, dcCount);
      maxEcCount = Math.max(maxEcCount, ecCount);
      dcdata[r] = new Array(dcCount);
      for (let i = 0; i < dcdata[r].length; i += 1) {
        dcdata[r][i] = 255 & buffer.getBuffer()[i + offset];
      }
      offset += dcCount;
      const rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
      const rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);
      const modPoly = rawPoly.mod(rsPoly);
      ecdata[r] = new Array(rsPoly.getLength() - 1);
      for (let i = 0; i < ecdata[r].length; i += 1) {
        const modIndex = i + modPoly.getLength() - ecdata[r].length;
        ecdata[r][i] = modIndex >= 0 ? modPoly.getAt(modIndex) : 0;
      }
    }
    let totalCodeCount = 0;
    for (let i = 0; i < rsBlocks.length; i += 1) {
      totalCodeCount += rsBlocks[i].totalCount;
    }
    const data = new Array(totalCodeCount);
    let index = 0;
    for (let i = 0; i < maxDcCount; i += 1) {
      for (let r = 0; r < rsBlocks.length; r += 1) {
        if (i < dcdata[r].length) {
          data[index] = dcdata[r][i];
          index += 1;
        }
      }
    }
    for (let i = 0; i < maxEcCount; i += 1) {
      for (let r = 0; r < rsBlocks.length; r += 1) {
        if (i < ecdata[r].length) {
          data[index] = ecdata[r][i];
          index += 1;
        }
      }
    }
    return data;
  };
  const createData = function(typeNumber2, errorCorrectionLevel2, dataList) {
    const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, errorCorrectionLevel2);
    const buffer = qrBitBuffer();
    for (let i = 0; i < dataList.length; i += 1) {
      const data = dataList[i];
      buffer.put(data.getMode(), 4);
      buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
      data.write(buffer);
    }
    let totalDataCount = 0;
    for (let i = 0; i < rsBlocks.length; i += 1) {
      totalDataCount += rsBlocks[i].dataCount;
    }
    if (buffer.getLengthInBits() > totalDataCount * 8) {
      throw "code length overflow. (" + buffer.getLengthInBits() + ">" + totalDataCount * 8 + ")";
    }
    if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
      buffer.put(0, 4);
    }
    while (buffer.getLengthInBits() % 8 != 0) {
      buffer.putBit(false);
    }
    while (true) {
      if (buffer.getLengthInBits() >= totalDataCount * 8) {
        break;
      }
      buffer.put(PAD0, 8);
      if (buffer.getLengthInBits() >= totalDataCount * 8) {
        break;
      }
      buffer.put(PAD1, 8);
    }
    return createBytes(buffer, rsBlocks);
  };
  _this.addData = function(data, mode) {
    mode = mode || "Byte";
    let newData = null;
    switch (mode) {
      case "Numeric":
        newData = qrNumber(data);
        break;
      case "Alphanumeric":
        newData = qrAlphaNum(data);
        break;
      case "Byte":
        newData = qr8BitByte(data);
        break;
      case "Kanji":
        newData = qrKanji(data);
        break;
      default:
        throw "mode:" + mode;
    }
    _dataList.push(newData);
    _dataCache = null;
  };
  _this.isDark = function(row, col) {
    if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
      throw row + "," + col;
    }
    return _modules[row][col];
  };
  _this.getModuleCount = function() {
    return _moduleCount;
  };
  _this.make = function() {
    if (_typeNumber < 1) {
      let typeNumber2 = 1;
      for (; typeNumber2 < 40; typeNumber2++) {
        const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, _errorCorrectionLevel);
        const buffer = qrBitBuffer();
        for (let i = 0; i < _dataList.length; i++) {
          const data = _dataList[i];
          buffer.put(data.getMode(), 4);
          buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
          data.write(buffer);
        }
        let totalDataCount = 0;
        for (let i = 0; i < rsBlocks.length; i++) {
          totalDataCount += rsBlocks[i].dataCount;
        }
        if (buffer.getLengthInBits() <= totalDataCount * 8) {
          break;
        }
      }
      _typeNumber = typeNumber2;
    }
    makeImpl(false, getBestMaskPattern());
  };
  _this.createTableTag = function(cellSize, margin) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    let qrHtml = "";
    qrHtml += '<table style="';
    qrHtml += " border-width: 0px; border-style: none;";
    qrHtml += " border-collapse: collapse;";
    qrHtml += " padding: 0px; margin: " + margin + "px;";
    qrHtml += '">';
    qrHtml += "<tbody>";
    for (let r = 0; r < _this.getModuleCount(); r += 1) {
      qrHtml += "<tr>";
      for (let c = 0; c < _this.getModuleCount(); c += 1) {
        qrHtml += '<td style="';
        qrHtml += " border-width: 0px; border-style: none;";
        qrHtml += " border-collapse: collapse;";
        qrHtml += " padding: 0px; margin: 0px;";
        qrHtml += " width: " + cellSize + "px;";
        qrHtml += " height: " + cellSize + "px;";
        qrHtml += " background-color: ";
        qrHtml += _this.isDark(r, c) ? "#000000" : "#ffffff";
        qrHtml += ";";
        qrHtml += '"/>';
      }
      qrHtml += "</tr>";
    }
    qrHtml += "</tbody>";
    qrHtml += "</table>";
    return qrHtml;
  };
  _this.createSvgTag = function(cellSize, margin, alt, title) {
    let opts = {};
    if (typeof arguments[0] == "object") {
      opts = arguments[0];
      cellSize = opts.cellSize;
      margin = opts.margin;
      alt = opts.alt;
      title = opts.title;
    }
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    alt = typeof alt === "string" ? { text: alt } : alt || {};
    alt.text = alt.text || null;
    alt.id = alt.text ? alt.id || "qrcode-description" : null;
    title = typeof title === "string" ? { text: title } : title || {};
    title.text = title.text || null;
    title.id = title.text ? title.id || "qrcode-title" : null;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    let c, mc, r, mr, qrSvg = "", rect;
    rect = "l" + cellSize + ",0 0," + cellSize + " -" + cellSize + ",0 0,-" + cellSize + "z ";
    qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
    qrSvg += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : "";
    qrSvg += ' viewBox="0 0 ' + size + " " + size + '" ';
    qrSvg += ' preserveAspectRatio="xMinYMin meet"';
    qrSvg += title.text || alt.text ? ' role="img" aria-labelledby="' + escapeXml([title.id, alt.id].join(" ").trim()) + '"' : "";
    qrSvg += ">";
    qrSvg += title.text ? '<title id="' + escapeXml(title.id) + '">' + escapeXml(title.text) + "</title>" : "";
    qrSvg += alt.text ? '<description id="' + escapeXml(alt.id) + '">' + escapeXml(alt.text) + "</description>" : "";
    qrSvg += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
    qrSvg += '<path d="';
    for (r = 0; r < _this.getModuleCount(); r += 1) {
      mr = r * cellSize + margin;
      for (c = 0; c < _this.getModuleCount(); c += 1) {
        if (_this.isDark(r, c)) {
          mc = c * cellSize + margin;
          qrSvg += "M" + mc + "," + mr + rect;
        }
      }
    }
    qrSvg += '" stroke="transparent" fill="black"/>';
    qrSvg += "</svg>";
    return qrSvg;
  };
  _this.createDataURL = function(cellSize, margin) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    return createDataURL(size, size, function(x, y) {
      if (min <= x && x < max && min <= y && y < max) {
        const c = Math.floor((x - min) / cellSize);
        const r = Math.floor((y - min) / cellSize);
        return _this.isDark(r, c) ? 0 : 1;
      } else {
        return 1;
      }
    });
  };
  _this.createImgTag = function(cellSize, margin, alt) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    let img = "";
    img += "<img";
    img += ' src="';
    img += _this.createDataURL(cellSize, margin);
    img += '"';
    img += ' width="';
    img += size;
    img += '"';
    img += ' height="';
    img += size;
    img += '"';
    if (alt) {
      img += ' alt="';
      img += escapeXml(alt);
      img += '"';
    }
    img += "/>";
    return img;
  };
  const escapeXml = function(s) {
    let escaped = "";
    for (let i = 0; i < s.length; i += 1) {
      const c = s.charAt(i);
      switch (c) {
        case "<":
          escaped += "&lt;";
          break;
        case ">":
          escaped += "&gt;";
          break;
        case "&":
          escaped += "&amp;";
          break;
        case '"':
          escaped += "&quot;";
          break;
        default:
          escaped += c;
          break;
      }
    }
    return escaped;
  };
  const _createHalfASCII = function(margin) {
    const cellSize = 1;
    margin = typeof margin == "undefined" ? cellSize * 2 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    let y, x, r1, r2, p;
    const blocks = {
      "\u2588\u2588": "\u2588",
      "\u2588 ": "\u2580",
      " \u2588": "\u2584",
      "  ": " "
    };
    const blocksLastLineNoMargin = {
      "\u2588\u2588": "\u2580",
      "\u2588 ": "\u2580",
      " \u2588": " ",
      "  ": " "
    };
    let ascii = "";
    for (y = 0; y < size; y += 2) {
      r1 = Math.floor((y - min) / cellSize);
      r2 = Math.floor((y + 1 - min) / cellSize);
      for (x = 0; x < size; x += 1) {
        p = "\u2588";
        if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
          p = " ";
        }
        if (min <= x && x < max && min <= y + 1 && y + 1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
          p += " ";
        } else {
          p += "\u2588";
        }
        ascii += margin < 1 && y + 1 >= max ? blocksLastLineNoMargin[p] : blocks[p];
      }
      ascii += "\n";
    }
    if (size % 2 && margin > 0) {
      return ascii.substring(0, ascii.length - size - 1) + Array(size + 1).join("\u2580");
    }
    return ascii.substring(0, ascii.length - 1);
  };
  _this.createASCII = function(cellSize, margin) {
    cellSize = cellSize || 1;
    if (cellSize < 2) {
      return _createHalfASCII(margin);
    }
    cellSize -= 1;
    margin = typeof margin == "undefined" ? cellSize * 2 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    let y, x, r, p;
    const white = Array(cellSize + 1).join("\u2588\u2588");
    const black = Array(cellSize + 1).join("  ");
    let ascii = "";
    let line = "";
    for (y = 0; y < size; y += 1) {
      r = Math.floor((y - min) / cellSize);
      line = "";
      for (x = 0; x < size; x += 1) {
        p = 1;
        if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
          p = 0;
        }
        line += p ? white : black;
      }
      for (r = 0; r < cellSize; r += 1) {
        ascii += line + "\n";
      }
    }
    return ascii.substring(0, ascii.length - 1);
  };
  _this.renderTo2dContext = function(context, cellSize) {
    cellSize = cellSize || 2;
    const length = _this.getModuleCount();
    for (let row = 0; row < length; row++) {
      for (let col = 0; col < length; col++) {
        context.fillStyle = _this.isDark(row, col) ? "black" : "white";
        context.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
      }
    }
  };
  return _this;
};
qrcode.stringToBytes = function(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    bytes.push(c & 255);
  }
  return bytes;
};
qrcode.createStringToBytes = function(unicodeData, numChars) {
  const unicodeMap = (function() {
    const bin = base64DecodeInputStream(unicodeData);
    const read = function() {
      const b = bin.read();
      if (b == -1) throw "eof";
      return b;
    };
    let count = 0;
    const unicodeMap2 = {};
    while (true) {
      const b0 = bin.read();
      if (b0 == -1) break;
      const b1 = read();
      const b2 = read();
      const b3 = read();
      const k = String.fromCharCode(b0 << 8 | b1);
      const v = b2 << 8 | b3;
      unicodeMap2[k] = v;
      count += 1;
    }
    if (count != numChars) {
      throw count + " != " + numChars;
    }
    return unicodeMap2;
  })();
  const unknownChar = "?".charCodeAt(0);
  return function(s) {
    const bytes = [];
    for (let i = 0; i < s.length; i += 1) {
      const c = s.charCodeAt(i);
      if (c < 128) {
        bytes.push(c);
      } else {
        const b = unicodeMap[s.charAt(i)];
        if (typeof b == "number") {
          if ((b & 255) == b) {
            bytes.push(b);
          } else {
            bytes.push(b >>> 8);
            bytes.push(b & 255);
          }
        } else {
          bytes.push(unknownChar);
        }
      }
    }
    return bytes;
  };
};
var QRMode = {
  MODE_NUMBER: 1 << 0,
  MODE_ALPHA_NUM: 1 << 1,
  MODE_8BIT_BYTE: 1 << 2,
  MODE_KANJI: 1 << 3
};
var QRErrorCorrectionLevel = {
  L: 1,
  M: 0,
  Q: 3,
  H: 2
};
var QRMaskPattern = {
  PATTERN000: 0,
  PATTERN001: 1,
  PATTERN010: 2,
  PATTERN011: 3,
  PATTERN100: 4,
  PATTERN101: 5,
  PATTERN110: 6,
  PATTERN111: 7
};
var QRUtil = (function() {
  const PATTERN_POSITION_TABLE = [
    [],
    [6, 18],
    [6, 22],
    [6, 26],
    [6, 30],
    [6, 34],
    [6, 22, 38],
    [6, 24, 42],
    [6, 26, 46],
    [6, 28, 50],
    [6, 30, 54],
    [6, 32, 58],
    [6, 34, 62],
    [6, 26, 46, 66],
    [6, 26, 48, 70],
    [6, 26, 50, 74],
    [6, 30, 54, 78],
    [6, 30, 56, 82],
    [6, 30, 58, 86],
    [6, 34, 62, 90],
    [6, 28, 50, 72, 94],
    [6, 26, 50, 74, 98],
    [6, 30, 54, 78, 102],
    [6, 28, 54, 80, 106],
    [6, 32, 58, 84, 110],
    [6, 30, 58, 86, 114],
    [6, 34, 62, 90, 118],
    [6, 26, 50, 74, 98, 122],
    [6, 30, 54, 78, 102, 126],
    [6, 26, 52, 78, 104, 130],
    [6, 30, 56, 82, 108, 134],
    [6, 34, 60, 86, 112, 138],
    [6, 30, 58, 86, 114, 142],
    [6, 34, 62, 90, 118, 146],
    [6, 30, 54, 78, 102, 126, 150],
    [6, 24, 50, 76, 102, 128, 154],
    [6, 28, 54, 80, 106, 132, 158],
    [6, 32, 58, 84, 110, 136, 162],
    [6, 26, 54, 82, 110, 138, 166],
    [6, 30, 58, 86, 114, 142, 170]
  ];
  const G15 = 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0;
  const G18 = 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0;
  const G15_MASK = 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1;
  const _this = {};
  const getBCHDigit = function(data) {
    let digit = 0;
    while (data != 0) {
      digit += 1;
      data >>>= 1;
    }
    return digit;
  };
  _this.getBCHTypeInfo = function(data) {
    let d = data << 10;
    while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
      d ^= G15 << getBCHDigit(d) - getBCHDigit(G15);
    }
    return (data << 10 | d) ^ G15_MASK;
  };
  _this.getBCHTypeNumber = function(data) {
    let d = data << 12;
    while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
      d ^= G18 << getBCHDigit(d) - getBCHDigit(G18);
    }
    return data << 12 | d;
  };
  _this.getPatternPosition = function(typeNumber) {
    return PATTERN_POSITION_TABLE[typeNumber - 1];
  };
  _this.getMaskFunction = function(maskPattern) {
    switch (maskPattern) {
      case QRMaskPattern.PATTERN000:
        return function(i, j) {
          return (i + j) % 2 == 0;
        };
      case QRMaskPattern.PATTERN001:
        return function(i, j) {
          return i % 2 == 0;
        };
      case QRMaskPattern.PATTERN010:
        return function(i, j) {
          return j % 3 == 0;
        };
      case QRMaskPattern.PATTERN011:
        return function(i, j) {
          return (i + j) % 3 == 0;
        };
      case QRMaskPattern.PATTERN100:
        return function(i, j) {
          return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 == 0;
        };
      case QRMaskPattern.PATTERN101:
        return function(i, j) {
          return i * j % 2 + i * j % 3 == 0;
        };
      case QRMaskPattern.PATTERN110:
        return function(i, j) {
          return (i * j % 2 + i * j % 3) % 2 == 0;
        };
      case QRMaskPattern.PATTERN111:
        return function(i, j) {
          return (i * j % 3 + (i + j) % 2) % 2 == 0;
        };
      default:
        throw "bad maskPattern:" + maskPattern;
    }
  };
  _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
    let a = qrPolynomial([1], 0);
    for (let i = 0; i < errorCorrectLength; i += 1) {
      a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0));
    }
    return a;
  };
  _this.getLengthInBits = function(mode, type) {
    if (1 <= type && type < 10) {
      switch (mode) {
        case QRMode.MODE_NUMBER:
          return 10;
        case QRMode.MODE_ALPHA_NUM:
          return 9;
        case QRMode.MODE_8BIT_BYTE:
          return 8;
        case QRMode.MODE_KANJI:
          return 8;
        default:
          throw "mode:" + mode;
      }
    } else if (type < 27) {
      switch (mode) {
        case QRMode.MODE_NUMBER:
          return 12;
        case QRMode.MODE_ALPHA_NUM:
          return 11;
        case QRMode.MODE_8BIT_BYTE:
          return 16;
        case QRMode.MODE_KANJI:
          return 10;
        default:
          throw "mode:" + mode;
      }
    } else if (type < 41) {
      switch (mode) {
        case QRMode.MODE_NUMBER:
          return 14;
        case QRMode.MODE_ALPHA_NUM:
          return 13;
        case QRMode.MODE_8BIT_BYTE:
          return 16;
        case QRMode.MODE_KANJI:
          return 12;
        default:
          throw "mode:" + mode;
      }
    } else {
      throw "type:" + type;
    }
  };
  _this.getLostPoint = function(qrcode2) {
    const moduleCount = qrcode2.getModuleCount();
    let lostPoint = 0;
    for (let row = 0; row < moduleCount; row += 1) {
      for (let col = 0; col < moduleCount; col += 1) {
        let sameCount = 0;
        const dark = qrcode2.isDark(row, col);
        for (let r = -1; r <= 1; r += 1) {
          if (row + r < 0 || moduleCount <= row + r) {
            continue;
          }
          for (let c = -1; c <= 1; c += 1) {
            if (col + c < 0 || moduleCount <= col + c) {
              continue;
            }
            if (r == 0 && c == 0) {
              continue;
            }
            if (dark == qrcode2.isDark(row + r, col + c)) {
              sameCount += 1;
            }
          }
        }
        if (sameCount > 5) {
          lostPoint += 3 + sameCount - 5;
        }
      }
    }
    ;
    for (let row = 0; row < moduleCount - 1; row += 1) {
      for (let col = 0; col < moduleCount - 1; col += 1) {
        let count = 0;
        if (qrcode2.isDark(row, col)) count += 1;
        if (qrcode2.isDark(row + 1, col)) count += 1;
        if (qrcode2.isDark(row, col + 1)) count += 1;
        if (qrcode2.isDark(row + 1, col + 1)) count += 1;
        if (count == 0 || count == 4) {
          lostPoint += 3;
        }
      }
    }
    for (let row = 0; row < moduleCount; row += 1) {
      for (let col = 0; col < moduleCount - 6; col += 1) {
        if (qrcode2.isDark(row, col) && !qrcode2.isDark(row, col + 1) && qrcode2.isDark(row, col + 2) && qrcode2.isDark(row, col + 3) && qrcode2.isDark(row, col + 4) && !qrcode2.isDark(row, col + 5) && qrcode2.isDark(row, col + 6)) {
          lostPoint += 40;
        }
      }
    }
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row = 0; row < moduleCount - 6; row += 1) {
        if (qrcode2.isDark(row, col) && !qrcode2.isDark(row + 1, col) && qrcode2.isDark(row + 2, col) && qrcode2.isDark(row + 3, col) && qrcode2.isDark(row + 4, col) && !qrcode2.isDark(row + 5, col) && qrcode2.isDark(row + 6, col)) {
          lostPoint += 40;
        }
      }
    }
    let darkCount = 0;
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row = 0; row < moduleCount; row += 1) {
        if (qrcode2.isDark(row, col)) {
          darkCount += 1;
        }
      }
    }
    const ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
    lostPoint += ratio * 10;
    return lostPoint;
  };
  return _this;
})();
var QRMath = (function() {
  const EXP_TABLE = new Array(256);
  const LOG_TABLE = new Array(256);
  for (let i = 0; i < 8; i += 1) {
    EXP_TABLE[i] = 1 << i;
  }
  for (let i = 8; i < 256; i += 1) {
    EXP_TABLE[i] = EXP_TABLE[i - 4] ^ EXP_TABLE[i - 5] ^ EXP_TABLE[i - 6] ^ EXP_TABLE[i - 8];
  }
  for (let i = 0; i < 255; i += 1) {
    LOG_TABLE[EXP_TABLE[i]] = i;
  }
  const _this = {};
  _this.glog = function(n) {
    if (n < 1) {
      throw "glog(" + n + ")";
    }
    return LOG_TABLE[n];
  };
  _this.gexp = function(n) {
    while (n < 0) {
      n += 255;
    }
    while (n >= 256) {
      n -= 255;
    }
    return EXP_TABLE[n];
  };
  return _this;
})();
var qrPolynomial = function(num2, shift) {
  if (typeof num2.length == "undefined") {
    throw num2.length + "/" + shift;
  }
  const _num = (function() {
    let offset = 0;
    while (offset < num2.length && num2[offset] == 0) {
      offset += 1;
    }
    const _num2 = new Array(num2.length - offset + shift);
    for (let i = 0; i < num2.length - offset; i += 1) {
      _num2[i] = num2[i + offset];
    }
    return _num2;
  })();
  const _this = {};
  _this.getAt = function(index) {
    return _num[index];
  };
  _this.getLength = function() {
    return _num.length;
  };
  _this.multiply = function(e) {
    const num3 = new Array(_this.getLength() + e.getLength() - 1);
    for (let i = 0; i < _this.getLength(); i += 1) {
      for (let j = 0; j < e.getLength(); j += 1) {
        num3[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i)) + QRMath.glog(e.getAt(j)));
      }
    }
    return qrPolynomial(num3, 0);
  };
  _this.mod = function(e) {
    if (_this.getLength() - e.getLength() < 0) {
      return _this;
    }
    const ratio = QRMath.glog(_this.getAt(0)) - QRMath.glog(e.getAt(0));
    const num3 = new Array(_this.getLength());
    for (let i = 0; i < _this.getLength(); i += 1) {
      num3[i] = _this.getAt(i);
    }
    for (let i = 0; i < e.getLength(); i += 1) {
      num3[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i)) + ratio);
    }
    return qrPolynomial(num3, 0).mod(e);
  };
  return _this;
};
var QRRSBlock = (function() {
  const RS_BLOCK_TABLE = [
    // L
    // M
    // Q
    // H
    // 1
    [1, 26, 19],
    [1, 26, 16],
    [1, 26, 13],
    [1, 26, 9],
    // 2
    [1, 44, 34],
    [1, 44, 28],
    [1, 44, 22],
    [1, 44, 16],
    // 3
    [1, 70, 55],
    [1, 70, 44],
    [2, 35, 17],
    [2, 35, 13],
    // 4
    [1, 100, 80],
    [2, 50, 32],
    [2, 50, 24],
    [4, 25, 9],
    // 5
    [1, 134, 108],
    [2, 67, 43],
    [2, 33, 15, 2, 34, 16],
    [2, 33, 11, 2, 34, 12],
    // 6
    [2, 86, 68],
    [4, 43, 27],
    [4, 43, 19],
    [4, 43, 15],
    // 7
    [2, 98, 78],
    [4, 49, 31],
    [2, 32, 14, 4, 33, 15],
    [4, 39, 13, 1, 40, 14],
    // 8
    [2, 121, 97],
    [2, 60, 38, 2, 61, 39],
    [4, 40, 18, 2, 41, 19],
    [4, 40, 14, 2, 41, 15],
    // 9
    [2, 146, 116],
    [3, 58, 36, 2, 59, 37],
    [4, 36, 16, 4, 37, 17],
    [4, 36, 12, 4, 37, 13],
    // 10
    [2, 86, 68, 2, 87, 69],
    [4, 69, 43, 1, 70, 44],
    [6, 43, 19, 2, 44, 20],
    [6, 43, 15, 2, 44, 16],
    // 11
    [4, 101, 81],
    [1, 80, 50, 4, 81, 51],
    [4, 50, 22, 4, 51, 23],
    [3, 36, 12, 8, 37, 13],
    // 12
    [2, 116, 92, 2, 117, 93],
    [6, 58, 36, 2, 59, 37],
    [4, 46, 20, 6, 47, 21],
    [7, 42, 14, 4, 43, 15],
    // 13
    [4, 133, 107],
    [8, 59, 37, 1, 60, 38],
    [8, 44, 20, 4, 45, 21],
    [12, 33, 11, 4, 34, 12],
    // 14
    [3, 145, 115, 1, 146, 116],
    [4, 64, 40, 5, 65, 41],
    [11, 36, 16, 5, 37, 17],
    [11, 36, 12, 5, 37, 13],
    // 15
    [5, 109, 87, 1, 110, 88],
    [5, 65, 41, 5, 66, 42],
    [5, 54, 24, 7, 55, 25],
    [11, 36, 12, 7, 37, 13],
    // 16
    [5, 122, 98, 1, 123, 99],
    [7, 73, 45, 3, 74, 46],
    [15, 43, 19, 2, 44, 20],
    [3, 45, 15, 13, 46, 16],
    // 17
    [1, 135, 107, 5, 136, 108],
    [10, 74, 46, 1, 75, 47],
    [1, 50, 22, 15, 51, 23],
    [2, 42, 14, 17, 43, 15],
    // 18
    [5, 150, 120, 1, 151, 121],
    [9, 69, 43, 4, 70, 44],
    [17, 50, 22, 1, 51, 23],
    [2, 42, 14, 19, 43, 15],
    // 19
    [3, 141, 113, 4, 142, 114],
    [3, 70, 44, 11, 71, 45],
    [17, 47, 21, 4, 48, 22],
    [9, 39, 13, 16, 40, 14],
    // 20
    [3, 135, 107, 5, 136, 108],
    [3, 67, 41, 13, 68, 42],
    [15, 54, 24, 5, 55, 25],
    [15, 43, 15, 10, 44, 16],
    // 21
    [4, 144, 116, 4, 145, 117],
    [17, 68, 42],
    [17, 50, 22, 6, 51, 23],
    [19, 46, 16, 6, 47, 17],
    // 22
    [2, 139, 111, 7, 140, 112],
    [17, 74, 46],
    [7, 54, 24, 16, 55, 25],
    [34, 37, 13],
    // 23
    [4, 151, 121, 5, 152, 122],
    [4, 75, 47, 14, 76, 48],
    [11, 54, 24, 14, 55, 25],
    [16, 45, 15, 14, 46, 16],
    // 24
    [6, 147, 117, 4, 148, 118],
    [6, 73, 45, 14, 74, 46],
    [11, 54, 24, 16, 55, 25],
    [30, 46, 16, 2, 47, 17],
    // 25
    [8, 132, 106, 4, 133, 107],
    [8, 75, 47, 13, 76, 48],
    [7, 54, 24, 22, 55, 25],
    [22, 45, 15, 13, 46, 16],
    // 26
    [10, 142, 114, 2, 143, 115],
    [19, 74, 46, 4, 75, 47],
    [28, 50, 22, 6, 51, 23],
    [33, 46, 16, 4, 47, 17],
    // 27
    [8, 152, 122, 4, 153, 123],
    [22, 73, 45, 3, 74, 46],
    [8, 53, 23, 26, 54, 24],
    [12, 45, 15, 28, 46, 16],
    // 28
    [3, 147, 117, 10, 148, 118],
    [3, 73, 45, 23, 74, 46],
    [4, 54, 24, 31, 55, 25],
    [11, 45, 15, 31, 46, 16],
    // 29
    [7, 146, 116, 7, 147, 117],
    [21, 73, 45, 7, 74, 46],
    [1, 53, 23, 37, 54, 24],
    [19, 45, 15, 26, 46, 16],
    // 30
    [5, 145, 115, 10, 146, 116],
    [19, 75, 47, 10, 76, 48],
    [15, 54, 24, 25, 55, 25],
    [23, 45, 15, 25, 46, 16],
    // 31
    [13, 145, 115, 3, 146, 116],
    [2, 74, 46, 29, 75, 47],
    [42, 54, 24, 1, 55, 25],
    [23, 45, 15, 28, 46, 16],
    // 32
    [17, 145, 115],
    [10, 74, 46, 23, 75, 47],
    [10, 54, 24, 35, 55, 25],
    [19, 45, 15, 35, 46, 16],
    // 33
    [17, 145, 115, 1, 146, 116],
    [14, 74, 46, 21, 75, 47],
    [29, 54, 24, 19, 55, 25],
    [11, 45, 15, 46, 46, 16],
    // 34
    [13, 145, 115, 6, 146, 116],
    [14, 74, 46, 23, 75, 47],
    [44, 54, 24, 7, 55, 25],
    [59, 46, 16, 1, 47, 17],
    // 35
    [12, 151, 121, 7, 152, 122],
    [12, 75, 47, 26, 76, 48],
    [39, 54, 24, 14, 55, 25],
    [22, 45, 15, 41, 46, 16],
    // 36
    [6, 151, 121, 14, 152, 122],
    [6, 75, 47, 34, 76, 48],
    [46, 54, 24, 10, 55, 25],
    [2, 45, 15, 64, 46, 16],
    // 37
    [17, 152, 122, 4, 153, 123],
    [29, 74, 46, 14, 75, 47],
    [49, 54, 24, 10, 55, 25],
    [24, 45, 15, 46, 46, 16],
    // 38
    [4, 152, 122, 18, 153, 123],
    [13, 74, 46, 32, 75, 47],
    [48, 54, 24, 14, 55, 25],
    [42, 45, 15, 32, 46, 16],
    // 39
    [20, 147, 117, 4, 148, 118],
    [40, 75, 47, 7, 76, 48],
    [43, 54, 24, 22, 55, 25],
    [10, 45, 15, 67, 46, 16],
    // 40
    [19, 148, 118, 6, 149, 119],
    [18, 75, 47, 31, 76, 48],
    [34, 54, 24, 34, 55, 25],
    [20, 45, 15, 61, 46, 16]
  ];
  const qrRSBlock = function(totalCount, dataCount) {
    const _this2 = {};
    _this2.totalCount = totalCount;
    _this2.dataCount = dataCount;
    return _this2;
  };
  const _this = {};
  const getRsBlockTable = function(typeNumber, errorCorrectionLevel) {
    switch (errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default:
        return void 0;
    }
  };
  _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {
    const rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);
    if (typeof rsBlock == "undefined") {
      throw "bad rs block @ typeNumber:" + typeNumber + "/errorCorrectionLevel:" + errorCorrectionLevel;
    }
    const length = rsBlock.length / 3;
    const list = [];
    for (let i = 0; i < length; i += 1) {
      const count = rsBlock[i * 3 + 0];
      const totalCount = rsBlock[i * 3 + 1];
      const dataCount = rsBlock[i * 3 + 2];
      for (let j = 0; j < count; j += 1) {
        list.push(qrRSBlock(totalCount, dataCount));
      }
    }
    return list;
  };
  return _this;
})();
var qrBitBuffer = function() {
  const _buffer = [];
  let _length = 0;
  const _this = {};
  _this.getBuffer = function() {
    return _buffer;
  };
  _this.getAt = function(index) {
    const bufIndex = Math.floor(index / 8);
    return (_buffer[bufIndex] >>> 7 - index % 8 & 1) == 1;
  };
  _this.put = function(num2, length) {
    for (let i = 0; i < length; i += 1) {
      _this.putBit((num2 >>> length - i - 1 & 1) == 1);
    }
  };
  _this.getLengthInBits = function() {
    return _length;
  };
  _this.putBit = function(bit) {
    const bufIndex = Math.floor(_length / 8);
    if (_buffer.length <= bufIndex) {
      _buffer.push(0);
    }
    if (bit) {
      _buffer[bufIndex] |= 128 >>> _length % 8;
    }
    _length += 1;
  };
  return _this;
};
var qrNumber = function(data) {
  const _mode = QRMode.MODE_NUMBER;
  const _data = data;
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _data.length;
  };
  _this.write = function(buffer) {
    const data2 = _data;
    let i = 0;
    while (i + 2 < data2.length) {
      buffer.put(strToNum(data2.substring(i, i + 3)), 10);
      i += 3;
    }
    if (i < data2.length) {
      if (data2.length - i == 1) {
        buffer.put(strToNum(data2.substring(i, i + 1)), 4);
      } else if (data2.length - i == 2) {
        buffer.put(strToNum(data2.substring(i, i + 2)), 7);
      }
    }
  };
  const strToNum = function(s) {
    let num2 = 0;
    for (let i = 0; i < s.length; i += 1) {
      num2 = num2 * 10 + chatToNum(s.charAt(i));
    }
    return num2;
  };
  const chatToNum = function(c) {
    if ("0" <= c && c <= "9") {
      return c.charCodeAt(0) - "0".charCodeAt(0);
    }
    throw "illegal char :" + c;
  };
  return _this;
};
var qrAlphaNum = function(data) {
  const _mode = QRMode.MODE_ALPHA_NUM;
  const _data = data;
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _data.length;
  };
  _this.write = function(buffer) {
    const s = _data;
    let i = 0;
    while (i + 1 < s.length) {
      buffer.put(
        getCode(s.charAt(i)) * 45 + getCode(s.charAt(i + 1)),
        11
      );
      i += 2;
    }
    if (i < s.length) {
      buffer.put(getCode(s.charAt(i)), 6);
    }
  };
  const getCode = function(c) {
    if ("0" <= c && c <= "9") {
      return c.charCodeAt(0) - "0".charCodeAt(0);
    } else if ("A" <= c && c <= "Z") {
      return c.charCodeAt(0) - "A".charCodeAt(0) + 10;
    } else {
      switch (c) {
        case " ":
          return 36;
        case "$":
          return 37;
        case "%":
          return 38;
        case "*":
          return 39;
        case "+":
          return 40;
        case "-":
          return 41;
        case ".":
          return 42;
        case "/":
          return 43;
        case ":":
          return 44;
        default:
          throw "illegal char :" + c;
      }
    }
  };
  return _this;
};
var qr8BitByte = function(data) {
  const _mode = QRMode.MODE_8BIT_BYTE;
  const _data = data;
  const _bytes = qrcode.stringToBytes(data);
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _bytes.length;
  };
  _this.write = function(buffer) {
    for (let i = 0; i < _bytes.length; i += 1) {
      buffer.put(_bytes[i], 8);
    }
  };
  return _this;
};
var qrKanji = function(data) {
  const _mode = QRMode.MODE_KANJI;
  const _data = data;
  const stringToBytes2 = qrcode.stringToBytes;
  !(function(c, code) {
    const test = stringToBytes2(c);
    if (test.length != 2 || (test[0] << 8 | test[1]) != code) {
      throw "sjis not supported.";
    }
  })("friend", 38726);
  const _bytes = stringToBytes2(data);
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return ~~(_bytes.length / 2);
  };
  _this.write = function(buffer) {
    const data2 = _bytes;
    let i = 0;
    while (i + 1 < data2.length) {
      let c = (255 & data2[i]) << 8 | 255 & data2[i + 1];
      if (33088 <= c && c <= 40956) {
        c -= 33088;
      } else if (57408 <= c && c <= 60351) {
        c -= 49472;
      } else {
        throw "illegal char at " + (i + 1) + "/" + c;
      }
      c = (c >>> 8 & 255) * 192 + (c & 255);
      buffer.put(c, 13);
      i += 2;
    }
    if (i < data2.length) {
      throw "illegal char at " + (i + 1);
    }
  };
  return _this;
};
var byteArrayOutputStream = function() {
  const _bytes = [];
  const _this = {};
  _this.writeByte = function(b) {
    _bytes.push(b & 255);
  };
  _this.writeShort = function(i) {
    _this.writeByte(i);
    _this.writeByte(i >>> 8);
  };
  _this.writeBytes = function(b, off, len) {
    off = off || 0;
    len = len || b.length;
    for (let i = 0; i < len; i += 1) {
      _this.writeByte(b[i + off]);
    }
  };
  _this.writeString = function(s) {
    for (let i = 0; i < s.length; i += 1) {
      _this.writeByte(s.charCodeAt(i));
    }
  };
  _this.toByteArray = function() {
    return _bytes;
  };
  _this.toString = function() {
    let s = "";
    s += "[";
    for (let i = 0; i < _bytes.length; i += 1) {
      if (i > 0) {
        s += ",";
      }
      s += _bytes[i];
    }
    s += "]";
    return s;
  };
  return _this;
};
var base64EncodeOutputStream = function() {
  let _buffer = 0;
  let _buflen = 0;
  let _length = 0;
  let _base64 = "";
  const _this = {};
  const writeEncoded = function(b) {
    _base64 += String.fromCharCode(encode(b & 63));
  };
  const encode = function(n) {
    if (n < 0) {
      throw "n:" + n;
    } else if (n < 26) {
      return 65 + n;
    } else if (n < 52) {
      return 97 + (n - 26);
    } else if (n < 62) {
      return 48 + (n - 52);
    } else if (n == 62) {
      return 43;
    } else if (n == 63) {
      return 47;
    } else {
      throw "n:" + n;
    }
  };
  _this.writeByte = function(n) {
    _buffer = _buffer << 8 | n & 255;
    _buflen += 8;
    _length += 1;
    while (_buflen >= 6) {
      writeEncoded(_buffer >>> _buflen - 6);
      _buflen -= 6;
    }
  };
  _this.flush = function() {
    if (_buflen > 0) {
      writeEncoded(_buffer << 6 - _buflen);
      _buffer = 0;
      _buflen = 0;
    }
    if (_length % 3 != 0) {
      const padlen = 3 - _length % 3;
      for (let i = 0; i < padlen; i += 1) {
        _base64 += "=";
      }
    }
  };
  _this.toString = function() {
    return _base64;
  };
  return _this;
};
var base64DecodeInputStream = function(str) {
  const _str = str;
  let _pos = 0;
  let _buffer = 0;
  let _buflen = 0;
  const _this = {};
  _this.read = function() {
    while (_buflen < 8) {
      if (_pos >= _str.length) {
        if (_buflen == 0) {
          return -1;
        }
        throw "unexpected end of file./" + _buflen;
      }
      const c = _str.charAt(_pos);
      _pos += 1;
      if (c == "=") {
        _buflen = 0;
        return -1;
      } else if (c.match(/^\s$/)) {
        continue;
      }
      _buffer = _buffer << 6 | decode2(c.charCodeAt(0));
      _buflen += 6;
    }
    const n = _buffer >>> _buflen - 8 & 255;
    _buflen -= 8;
    return n;
  };
  const decode2 = function(c) {
    if (65 <= c && c <= 90) {
      return c - 65;
    } else if (97 <= c && c <= 122) {
      return c - 97 + 26;
    } else if (48 <= c && c <= 57) {
      return c - 48 + 52;
    } else if (c == 43) {
      return 62;
    } else if (c == 47) {
      return 63;
    } else {
      throw "c:" + c;
    }
  };
  return _this;
};
var gifImage = function(width, height) {
  const _width = width;
  const _height = height;
  const _data = new Array(width * height);
  const _this = {};
  _this.setPixel = function(x, y, pixel) {
    _data[y * _width + x] = pixel;
  };
  _this.write = function(out) {
    out.writeString("GIF87a");
    out.writeShort(_width);
    out.writeShort(_height);
    out.writeByte(128);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(255);
    out.writeByte(255);
    out.writeByte(255);
    out.writeString(",");
    out.writeShort(0);
    out.writeShort(0);
    out.writeShort(_width);
    out.writeShort(_height);
    out.writeByte(0);
    const lzwMinCodeSize = 2;
    const raster = getLZWRaster(lzwMinCodeSize);
    out.writeByte(lzwMinCodeSize);
    let offset = 0;
    while (raster.length - offset > 255) {
      out.writeByte(255);
      out.writeBytes(raster, offset, 255);
      offset += 255;
    }
    out.writeByte(raster.length - offset);
    out.writeBytes(raster, offset, raster.length - offset);
    out.writeByte(0);
    out.writeString(";");
  };
  const bitOutputStream = function(out) {
    const _out = out;
    let _bitLength = 0;
    let _bitBuffer = 0;
    const _this2 = {};
    _this2.write = function(data, length) {
      if (data >>> length != 0) {
        throw "length over";
      }
      while (_bitLength + length >= 8) {
        _out.writeByte(255 & (data << _bitLength | _bitBuffer));
        length -= 8 - _bitLength;
        data >>>= 8 - _bitLength;
        _bitBuffer = 0;
        _bitLength = 0;
      }
      _bitBuffer = data << _bitLength | _bitBuffer;
      _bitLength = _bitLength + length;
    };
    _this2.flush = function() {
      if (_bitLength > 0) {
        _out.writeByte(_bitBuffer);
      }
    };
    return _this2;
  };
  const getLZWRaster = function(lzwMinCodeSize) {
    const clearCode = 1 << lzwMinCodeSize;
    const endCode = (1 << lzwMinCodeSize) + 1;
    let bitLength = lzwMinCodeSize + 1;
    const table = lzwTable();
    for (let i = 0; i < clearCode; i += 1) {
      table.add(String.fromCharCode(i));
    }
    table.add(String.fromCharCode(clearCode));
    table.add(String.fromCharCode(endCode));
    const byteOut = byteArrayOutputStream();
    const bitOut = bitOutputStream(byteOut);
    bitOut.write(clearCode, bitLength);
    let dataIndex = 0;
    let s = String.fromCharCode(_data[dataIndex]);
    dataIndex += 1;
    while (dataIndex < _data.length) {
      const c = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;
      if (table.contains(s + c)) {
        s = s + c;
      } else {
        bitOut.write(table.indexOf(s), bitLength);
        if (table.size() < 4095) {
          if (table.size() == 1 << bitLength) {
            bitLength += 1;
          }
          table.add(s + c);
        }
        s = c;
      }
    }
    bitOut.write(table.indexOf(s), bitLength);
    bitOut.write(endCode, bitLength);
    bitOut.flush();
    return byteOut.toByteArray();
  };
  const lzwTable = function() {
    const _map = {};
    let _size = 0;
    const _this2 = {};
    _this2.add = function(key) {
      if (_this2.contains(key)) {
        throw "dup key:" + key;
      }
      _map[key] = _size;
      _size += 1;
    };
    _this2.size = function() {
      return _size;
    };
    _this2.indexOf = function(key) {
      return _map[key];
    };
    _this2.contains = function(key) {
      return typeof _map[key] != "undefined";
    };
    return _this2;
  };
  return _this;
};
var createDataURL = function(width, height, getPixel) {
  const gif = gifImage(width, height);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      gif.setPixel(x, y, getPixel(x, y));
    }
  }
  const b = byteArrayOutputStream();
  gif.write(b);
  const base64 = base64EncodeOutputStream();
  const bytes = b.toByteArray();
  for (let i = 0; i < bytes.length; i += 1) {
    base64.writeByte(bytes[i]);
  }
  base64.flush();
  return "data:image/gif;base64," + base64;
};
var qrcode_default = qrcode;
var stringToBytes = qrcode.stringToBytes;

// src/pairing/pairing-modal.ts
var AddDeviceModal = class extends import_obsidian14.Modal {
  constructor(app, client, settings) {
    super(app);
    this.client = client;
    this.settings = settings;
    this.pairingId = null;
    this.consumedOrRevoked = false;
  }
  onOpen() {
    this.titleEl.setText("Add New Device");
    this.contentEl.createDiv({ text: "Generating the pairing package…", cls: "litesync-history-meta" });
    void this.createAndRender();
  }
  onClose() {
    if (this.pairingId && !this.consumedOrRevoked) {
      const id = this.pairingId;
      this.consumedOrRevoked = true;
      void this.client.deletePairing(id).catch(() => void 0);
    }
  }
  async createAndRender() {
    const { contentEl } = this;
    try {
      const secret = newPairSecret();
      const enrollment = await this.client.createEnrollment(900);
      const config = {
        v: 2,
        serverUrl: this.settings.serverUrl,
        enrollmentSecret: enrollment.secret,
        syncIntervalSeconds: this.settings.syncIntervalSeconds,
        syncObsidian: this.settings.syncObsidian,
        ignorePatterns: this.settings.ignorePatterns
      };
      const ciphertext = await encryptPairingConfig(secret, config);
      const { id } = await this.client.createPairing(ciphertext, 300);
      this.pairingId = id;
      const url = buildPairUrl(this.settings.serverUrl, id, secret);
      secret.fill(0);
      contentEl.empty();
      contentEl.createEl("p", {
        text: "Scan the code with the camera on the new device (or open the link), then import the config in Obsidian as prompted."
      });
      this.renderQr(contentEl, url);
      const input = contentEl.createEl("input", { type: "text", value: url, cls: "litesync-modal-input" });
      input.readOnly = true;
      input.onclick = () => input.select();
      const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
      footer.createEl("button", { text: "Copy Link", cls: "mod-cta" }).onclick = () => {
        void navigator.clipboard.writeText(url).then(() => new import_obsidian14.Notice("Pairing link copied"));
      };
      contentEl.createDiv({
        cls: "litesync-history-meta",
        text: "The link is valid for 5 minutes and can be used only once; the config package is already encrypted on this device and the server stores only ciphertext. Closing this window voids it."
      });
      contentEl.createDiv({
        cls: "litesync-history-meta",
        text: "Security note: the pairing package contains only a one-time registration credential; the new device gets its own dedicated credential (which can be revoked separately). The E2EE password is NOT included — enter it once by hand on the new device."
      });
    } catch (e) {
      contentEl.empty();
      contentEl.createEl("p", {
        text: `Failed to generate the pairing package: ${e instanceof Error ? e.message : String(e)} (the server needs 0.8.0+)`
      });
    }
  }
  /** 用 canvas 绘制二维码（无 innerHTML，无外部资源）。 */
  renderQr(parent, text) {
    const qr = qrcode_default(0, "M");
    qr.addData(text);
    qr.make();
    const modules = qr.getModuleCount();
    const scale = 4;
    const margin = 4 * scale;
    const size = modules * scale + margin * 2;
    const wrap = parent.createDiv({ cls: "litesync-qr-wrap" });
    const canvas = wrap.createEl("canvas", { cls: "litesync-qr" });
    canvas.width = size;
    canvas.height = size;
    const g = canvas.getContext("2d");
    if (!g) return;
    g.fillStyle = "#ffffff";
    g.fillRect(0, 0, size, size);
    g.fillStyle = "#000000";
    for (let r = 0; r < modules; r++) {
      for (let c = 0; c < modules; c++) {
        if (qr.isDark(r, c)) {
          g.fillRect(margin + c * scale, margin + r * scale, scale, scale);
        }
      }
    }
  }
};

// src/settings.ts
var import_obsidian15 = require("obsidian");

// src/utils/timing.ts
var DEFAULT_BATCH_SECONDS = 300;
var DEFAULT_MTIME_GRANULARITY_SECONDS = 3600;
var MIN_BATCH_SECONDS = 30;
function quantizeMtime(mtimeMs, granularitySec) {
  if (!Number.isFinite(mtimeMs) || mtimeMs <= 0) return mtimeMs;
  if (granularitySec <= 0) return mtimeMs;
  const g = granularitySec * 1e3;
  return Math.floor(mtimeMs / g) * g;
}
function nextFlushDelay(nowMs, windowSec, random = Math.random) {
  const w = Math.max(MIN_BATCH_SECONDS, windowSec) * 1e3;
  const nextBoundary = (Math.floor(nowMs / w) + 1) * w;
  const fire = nextBoundary + Math.floor(random() * w);
  return fire - nowMs;
}
function timingDisclosure(windowSec, mtimeGranularitySec) {
  const w = Math.max(MIN_BATCH_SECONDS, windowSec);
  const mins = Math.round(w / 60 * 10) / 10;
  const hrs = Math.round(mtimeGranularitySec / 3600 * 10) / 10;
  return `Uploads will be delayed by about ${mins} min (at most about ${mins * 2} min), the server can only tell which window an edit landed in${mins} min window; file modification times are reported rounded to ${hrs} hours before being reported. Cost: cross-device visible latency and the conflict window both get longer. This feature does not hide "whether you edited in some window" — that would need continuous cover traffic, which this plugin does not do.`;
}

// src/settings.ts
var DEFAULT_SETTINGS = {
  serverUrl: "",
  apiToken: "",
  // 仅作旧版本 data.json 明文值的迁移来源；迁移后始终为空，真实值在 SecretStorage
  deviceName: "",
  autoSync: true,
  syncIntervalSeconds: 30,
  syncObsidian: false,
  ignorePatterns: ".trash/**\n.DS_Store\nThumbs.db",
  vaultChoice: "",
  debug: false,
  trustDevice: true,
  deviceKeyB64: "",
  experimentalMetaEncryption: false,
  allowIrreversibleMetaErase: false,
  padObjectSizes: false,
  padPathPrefixes: "",
  obfuscateTiming: false,
  timingBatchSeconds: DEFAULT_BATCH_SECONDS,
  mtimeGranularitySeconds: DEFAULT_MTIME_GRANULARITY_SECONDS
};
var SyncSettingTab = class extends import_obsidian15.PluginSettingTab {
  constructor(app, plugin) {
    super(app, plugin);
    this.plugin = plugin;
  }
  /** 供 plugin 在弹窗操作成功后调用：重渲染设置页以反映新状态（基类 update 非公开）。 */
  refresh() {
    this.update();
  }
  getSettingDefinitions() {
    const plugin = this.plugin;
    return [
      {
        type: "group",
        heading: "Server",
        items: [
          {
            name: "Server URL",
            desc: createFragment((frag) => {
              frag.appendText("Server address to sync against, e.g. https://sync.example.com. No server yet?");
              frag.createEl("a", {
                text: "View the deployment guide (litesync-server)",
                href: "https://github.com/KJoner/litesync-server"
              });
            }),
            control: { type: "text", key: "serverUrl", placeholder: "https://sync.example.com" }
          },
          {
            name: "API Token",
            desc: "Your account API Token (starts with lsk_; the admin OBSYNC_TOKEN also works). Stored in Obsidian SecretStorage, never in data.json",
            render: (setting) => {
              setting.addText((text) => {
                text.inputEl.type = "password";
                const commit = (0, import_obsidian15.debounce)(
                  (value) => void plugin.setApiToken(value.trim()),
                  800,
                  true
                );
                text.setPlaceholder("Token").setValue(plugin.getApiToken()).onChange((value) => commit(value));
                text.inputEl.addEventListener("blur", () => {
                  void plugin.setApiToken(text.inputEl.value.trim());
                });
              });
            }
          },
          {
            name: "Test Connection",
            desc: "Verifies the server address and token work",
            action: (el) => {
              el.addClass("is-disabled");
              void plugin.testConnection().then((msg) => {
                if (msg !== null) new import_obsidian15.Notice(msg);
                el.removeClass("is-disabled");
              });
            }
          },
          {
            name: "Device Name",
            desc: "Used for conflict file names and server logs, e.g. MacBook",
            control: { type: "text", key: "deviceName", placeholder: "MacBook" }
          }
        ]
      },
      {
        type: "group",
        heading: "Sync",
        items: [
          {
            name: "Auto Sync",
            desc: "Sync automatically after files change (including scheduled pulls of remote changes)",
            control: { type: "toggle", key: "autoSync" }
          },
          {
            name: "Sync Interval",
            desc: import_obsidian15.Platform.isMobileApp ? "Scheduled pulls only run while the app is in the foreground; on mobile the minimum is 60 seconds (a sync is made up automatically when you return to the app)" : "Periodically pull changes made by other devices",
            control: {
              type: "dropdown",
              key: "syncIntervalSeconds",
              options: {
                "15": "15 seconds",
                "30": "30 seconds",
                "60": "60 seconds",
                "120": "2 minutes",
                "300": "5 minutes",
                "0": "Disable scheduled sync"
              }
            }
          },
          {
            name: "Sync Obsidian config directory",
            desc: import_obsidian15.Platform.isMobileApp ? "The config directory is never synced on mobile (desktop and mobile configs differ too much and would overwrite each other)" : "Sync the Obsidian config directory (workspace and this plugin's directory are never synced)",
            control: { type: "toggle", key: "syncObsidian" }
          },
          {
            name: "Ignore Rules",
            desc: "One Glob pattern per line; patterns without a / match against the file name",
            control: { type: "textarea", key: "ignorePatterns", rows: 4 }
          },
          {
            name: "Sync Now",
            desc: "Manually trigger a full sync",
            action: () => void plugin.syncNow()
          }
        ]
      },
      {
        type: "group",
        heading: "Devices & Migration",
        items: [
          {
            name: "Current Vault",
            aliases: ["vault", "vault", "multi-vault", "Rename"],
            render: (setting) => {
              setting.setDesc("Querying the current vault…");
              setting.addButton(
                (btn) => btn.setButtonText("Rename…").onClick(() => new RenameVaultModal(plugin.app, plugin).open())
              );
              void (async () => {
                try {
                  const vaults = await plugin.listRemoteVaults();
                  const cur = vaults.find((v) => v.current);
                  if (!cur) {
                    setting.setDesc("Not yet joined to a remote vault (run the setup wizard to bind)");
                    return;
                  }
                  const extra = vaults.length > 1 ? `; ${vaults.length} vaults` : "";
                  setting.setDesc(
                    `Syncing to "${cur.name || "Default Vault"}" (${cur.fileCount} files${extra}). To switch or create a vault: re-run the setup wizard.`
                  );
                } catch {
                  setting.setDesc("Cannot query (offline, or the server is older than v0.19)");
                }
              })();
            }
          },
          {
            name: "Add New Device",
            desc: "Generate a one-time encrypted pairing QR code/link: the new device scans it and auto-imports the server config (the E2EE password is still entered by hand)",
            action: () => plugin.openAddDeviceModal()
          },
          {
            name: "Import Pairing Link",
            desc: "Paste a pairing link generated on another device to import its server config",
            action: () => plugin.openPasteLinkModal()
          },
          {
            name: "Re-run Setup Wizard",
            desc: "Re-pick the target vault (switch / create) and how to join it (restore from remote / merge)",
            action: () => plugin.rerunBootstrapWizard()
          }
        ]
      },
      {
        type: "group",
        heading: "End-to-End Encryption (E2EE)",
        items: [
          {
            name: "Status",
            aliases: ["E2EE", "E2EE", "Encrypt"],
            render: (setting) => {
              const status = plugin.e2eeStatusText();
              setting.setDesc(status.desc);
              setting.addButton(
                (btn) => btn.setButtonText(status.action).onClick(async () => {
                  await plugin.e2eeAction();
                  this.update();
                })
              );
            }
          },
          {
            name: "Trust This Device (Keep Unlocked)",
            desc: "After unlocking, the Vault Master Key is wrapped with a random device key and stored in Obsidian SecretStorage, so it unlocks automatically on later launches. The E2EE password itself is never saved.",
            control: { type: "toggle", key: "trustDevice" }
          },
          {
            name: "Forget This Device",
            desc: "Deletes the stored key wrapping on this device and locks it; you must re-enter the E2EE password next time",
            visible: () => plugin.hasTrustedDevice(),
            action: () => {
              void plugin.forgetThisDevice().then(() => this.update());
            }
          }
        ]
      },
      {
        type: "group",
        heading: "Experimental (RC — do not use on your only real vault)",
        items: [
          {
            name: "Encrypt Paths & File Names (Experimental)",
            desc: createFragment((frag) => {
              frag.appendText(
                "Enabling this adds the \"Encrypt Paths & File Names\" command. Use it only on a test vault or a fully backed-up copy."
              );
              frag.createEl("br");
              frag.appendText("· Server backups from before the migration still contain plaintext paths — that is both the rollback window and the last plaintext remnant;");
              frag.createEl("br");
              frag.appendText("· It can be abandoned without loss any time before migrating to verifying; after complete and erasure it cannot be rolled back;");
              frag.createEl("br");
              frag.appendText("· Every device must be upgraded first — older versions cannot read a pseudonym-addressed vault.");
              frag.createEl("br");
              frag.appendText("· Before you start, run obsync migration preflight on the server; it checks whether any device has not been upgraded yet.");
            }),
            control: { type: "toggle", key: "experimentalMetaEncryption" }
          },
          {
            name: "Allow Irreversible Plaintext Path Erasure (Developer)",
            desc: "Off by default. While off, the migration stops at the \"pseudonymised but not erased\" **reversible** state — which is what you want in almost every case. Once on, complete really overwrites the plaintext paths left in the database, WAL and blobs, and verifies the overwrite with a sentinel scan. That step is **irreversible**; afterwards only a pre-migration backup can restore the paths. The privacy tombstone ledger landed in v0.13.0, and the deletion barrier stays intact after erasure.",
            visible: () => plugin.settings.experimentalMetaEncryption,
            control: { type: "toggle", key: "allowIrreversibleMetaErase" }
          },
          {
            name: "Abort Path Encryption Migration",
            desc: "Moves the vault's metadata state back from migrating to plain; pseudonymised files stay usable and nothing destructive happens",
            visible: () => plugin.metaMigrationActive(),
            action: () => void plugin.abortMetaMigration()
          }
        ]
      },
      {
        type: "group",
        heading: "Privacy Enhancements",
        items: [
          {
            name: "Obfuscate File Sizes",
            desc: createFragment((frag) => {
              frag.appendText(
                "Pads ciphertext to bucket boundaries so the server sees a size range instead of an exact byte count. Exact size is itself content: a known document's byte count confirms it on a hit, and a file's size sequence draws its editing rhythm."
              );
              frag.createEl("br");
              frag.appendText("· Cost: each object can take up to 12.5% more space; objects under 4KB are all counted as 4KB;");
              frag.createEl("br");
              frag.appendText("· Only affects content written after this is enabled; existing files are padded the next time they are modified;");
              frag.createEl("br");
              frag.appendText("· Deduplication inside the vault is unaffected (padding happens inside the ciphertext, so identical content still produces identical ciphertext).");
            }),
            control: { type: "toggle", key: "padObjectSizes" }
          },
          {
            name: "Obfuscate Sync Timing",
            desc: createFragment((frag) => {
              frag.appendText(
                "Aligns uploads to time windows with random jitter, so the server can tell which window an edit landed in, but not the exact second. Request rhythm is itself a keystroke record: your schedule, timezone, weekdays and holidays, even whether you are awake, can be inferred from it."
              );
              frag.createEl("br");
              frag.appendText(
                timingDisclosure(
                  plugin.settings.timingBatchSeconds,
                  plugin.settings.mtimeGranularitySeconds
                )
              );
              frag.createEl("br");
              frag.appendText("· The \"Sync Now\" command is unaffected — an action the user explicitly asked for is never delayed.");
            }),
            control: { type: "toggle", key: "obfuscateTiming" }
          },
          {
            name: "Only Pad These Paths (one prefix per line)",
            desc: "Leave empty to apply to every file. Most people have only a small number of notes worth the extra space.",
            visible: () => plugin.settings.padObjectSizes,
            control: { type: "textarea", key: "padPathPrefixes" }
          }
        ]
      },
      {
        type: "group",
        heading: "Debug",
        items: [
          {
            name: "Debug Log",
            desc: "Print sync logs to the developer console",
            control: { type: "toggle", key: "debug" }
          }
        ]
      }
    ];
  }
  getControlValue(key) {
    if (key === "syncIntervalSeconds") return String(this.plugin.settings.syncIntervalSeconds);
    return this.plugin.settings[key];
  }
  async setControlValue(key, value) {
    const settings = this.plugin.settings;
    switch (key) {
      case "serverUrl": {
        const url = String(value).trim();
        const changed = this.plugin.settings.serverUrl !== url;
        settings[key] = url;
        if (changed) this.plugin.invalidateBinding("The Server URL changed");
        if (/^http:\/\//i.test(url) && !isLoopbackUrl(url)) {
          new import_obsidian15.Notice("Note: non-local addresses must use https:// — the current http:// configuration will not sync", 8e3);
        }
        break;
      }
      case "deviceName":
        settings[key] = String(value).trim();
        break;
      case "syncIntervalSeconds":
        this.plugin.settings.syncIntervalSeconds = parseInt(String(value), 10) || 0;
        break;
      case "trustDevice":
        await this.plugin.setTrustDevice(value === true);
        this.update();
        return;
      default:
        settings[key] = value;
    }
    await this.plugin.saveSettings();
    this.plugin.applySettings();
  }
};
var RenameVaultModal = class extends import_obsidian15.Modal {
  constructor(app, plugin) {
    super(app);
    this.plugin = plugin;
  }
  onOpen() {
    this.titleEl.setText("Rename Current Vault");
    const { contentEl } = this;
    const info = contentEl.createDiv({ text: "Querying the current vault…" });
    void (async () => {
      let cur;
      try {
        cur = (await this.plugin.listRemoteVaults()).find((v) => v.current);
      } catch (e) {
        info.setText(`Cannot query: ${e instanceof Error ? e.message : String(e)}`);
        return;
      }
      if (!cur) {
        info.setText("Not yet joined to a remote vault.");
        return;
      }
      info.setText(`Current vault: "${cur.name || "Default Vault"}". Renaming only changes the display name; it does not affect sync, encryption or other devices.`);
      contentEl.createDiv({ text: "New name (1–64 characters):" });
      const input = contentEl.createEl("input", { type: "text", cls: "litesync-modal-input", value: cur.name });
      input.setAttribute("autocomplete", "off");
      const errEl = contentEl.createDiv({ cls: "litesync-history-meta" });
      const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
      const btn = footer.createEl("button", { text: "Rename", cls: "mod-cta" });
      const id = cur.id;
      const attemptRename = async (name) => {
        try {
          await this.plugin.renameRemoteVault(id, name);
          new import_obsidian15.Notice(`Vault renamed to "${name}\u300D\u2713`);
          this.close();
          this.plugin.refreshSettingsTab();
        } catch (e) {
          if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
            errEl.setText("Renaming requires your account API Token (this device holds a device credential imported via pairing).");
            input.readOnly = true;
            new TokenPromptModal(
              this.app,
              "Renaming requires your account API Token (starts with lsk_). It will be saved as this device's credential and retried automatically.",
              (t) => {
                void this.plugin.setApiToken(t).then(() => attemptRename(name));
              },
              () => {
                input.readOnly = false;
                input.value = name;
              }
            ).open();
          } else {
            errEl.setText(`Failed: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
      };
      const doRename = () => {
        const name = input.value.trim();
        if (!name || name.length > 64) {
          errEl.setText("The name must be 1–64 characters.");
          return;
        }
        void attemptRename(name);
      };
      btn.onclick = doRename;
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          input.blur();
          doRename();
        }
      });
      footer.createEl("button", { text: "Cancel" }).onclick = () => this.close();
    })();
  }
  onClose() {
    this.contentEl.empty();
  }
};

// src/share/share-modal.ts
var import_obsidian16 = require("obsidian");
var SHARE_IMAGE_EXT = /\.(png|jpe?g|gif|webp|svg|bmp|avif)$/i;
var SHARE_ATTACHMENT_BUDGET = 64 << 20;
async function collectImageEmbeds(ctx, notePath, warn) {
  const file = ctx.app.vault.getAbstractFileByPath(notePath);
  if (!(file instanceof import_obsidian16.TFile)) return [];
  const embeds = ctx.app.metadataCache.getFileCache(file)?.embeds ?? [];
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  let budget = SHARE_ATTACHMENT_BUDGET;
  for (const emb of embeds) {
    const linkpath = emb.link.split("#")[0].split("|")[0].trim();
    if (linkpath === "") continue;
    const target = ctx.app.metadataCache.getFirstLinkpathDest(linkpath, notePath);
    if (!target || seen.has(target.path) || !SHARE_IMAGE_EXT.test(target.path)) continue;
    seen.add(target.path);
    let data;
    try {
      data = await ctx.app.vault.adapter.readBinary(target.path);
    } catch {
      continue;
    }
    if (data.byteLength > budget) {
      warn(`Image exceeded the share attachment budget, skipped: ${target.path}`);
      continue;
    }
    budget -= data.byteLength;
    out.push({ path: target.path, data });
  }
  return out;
}
function shareUrl(serverUrl, id, keyB64url) {
  return `${serverUrl.replace(/\/+$/, "")}/share.html#${id}.${keyB64url}`;
}
async function copyText(text) {
  await navigator.clipboard.writeText(text);
  new import_obsidian16.Notice("Link copied");
}
var ShareModal = class extends import_obsidian16.Modal {
  constructor(ctx, serverUrl, path) {
    super(ctx.app);
    this.ctx = ctx;
    this.serverUrl = serverUrl;
    this.path = path;
  }
  onOpen() {
    this.titleEl.setText(`Share — ${this.path}`);
    const { contentEl } = this;
    contentEl.createEl("p", {
      text: "The content is encrypted with a separate share key and stored on the server; the key is only in the link's # fragment and the server cannot decrypt it.",
      cls: "litesync-history-meta"
    });
    contentEl.createDiv({ text: "Expires:" });
    const select = contentEl.createEl("select", { cls: "litesync-share-select" });
    for (const [label, days] of [
      ["7 days", 7],
      ["30 days", 30],
      ["90 days", 90],
      ["Permanent (revocable at any time)", 0]
    ]) {
      const opt = select.createEl("option", { text: label });
      opt.value = String(days);
    }
    select.createEl("option", { text: "Customize…" }).value = "custom";
    const customRow = contentEl.createDiv({ cls: "litesync-share-custom" });
    const amountInput = customRow.createEl("input", { type: "number", cls: "litesync-share-custom-amount" });
    amountInput.min = "1";
    amountInput.step = "1";
    amountInput.value = "1";
    const unitSelect = customRow.createEl("select", { cls: "litesync-share-select" });
    for (const [label, seconds] of [
      [" min", 60],
      [" h", 3600],
      ["d", 86400]
    ]) {
      const opt = unitSelect.createEl("option", { text: label });
      opt.value = String(seconds);
    }
    customRow.createDiv({
      cls: "litesync-history-meta",
      text: "Reminder: after expiry the ciphertext is quickly reclaimed by the server and cannot be recovered — you can only re-share."
    });
    customRow.hide();
    select.onchange = () => customRow.toggle(select.value === "custom");
    const resultEl = contentEl.createDiv();
    const footer = contentEl.createDiv({ cls: "litesync-resolver-footer" });
    const btn = footer.createEl("button", { text: "Create share link", cls: "mod-cta" });
    btn.onclick = async () => {
      btn.disabled = true;
      btn.setText("Creating…");
      try {
        requireSyncSafe(this.ctx, "Create Share");
        const adapter = this.ctx.app.vault.adapter;
        if (!await adapter.stat(this.path)) throw new Error("File not found");
        const plain = await adapter.readBinary(this.path);
        const keyRaw = randomBytes(32);
        const displayName = this.path.slice(this.path.lastIndexOf("/") + 1);
        const attachments = await collectImageEmbeds(this.ctx, this.path, (m) => new import_obsidian16.Notice(m));
        const payload = await encryptShare(keyRaw, frameShareBundle(displayName, plain, attachments));
        let expiresAt;
        if (select.value === "custom") {
          const n = Number(amountInput.value);
          if (!Number.isInteger(n) || n <= 0) throw new Error("The custom duration must be a positive integer");
          expiresAt = Math.floor(Date.now() / 1e3) + n * Number(unitSelect.value);
        } else {
          const days = parseInt(select.value, 10);
          expiresAt = days > 0 ? Math.floor(Date.now() / 1e3) + days * 86400 : 0;
        }
        const { id } = await this.ctx.client.createShare(expiresAt, payload);
        const keyB64url = b64urlEncode(keyRaw);
        keyRaw.fill(0);
        this.ctx.store.state.shares[id] = {
          path: this.path,
          keyB64url,
          createdAt: Date.now(),
          expiresAt,
          // 标记显示名已在密文里（§7.4）：没有这个标记的旧分享，
          // 真实路径还留在服务器上，管理界面会提示重建
          nameEncrypted: true
        };
        await this.ctx.store.save();
        const url = shareUrl(this.serverUrl, id, keyB64url);
        resultEl.empty();
        resultEl.createDiv({ text: "Share link (contains the decryption key — send it over a secure channel):", cls: "litesync-history-meta" });
        const input = resultEl.createEl("input", { type: "text", value: url, cls: "litesync-modal-input" });
        input.readOnly = true;
        input.onclick = () => input.select();
        const row = resultEl.createDiv({ cls: "litesync-resolver-footer" });
        row.createEl("button", { text: "Copy Link", cls: "mod-cta" }).onclick = () => void copyText(url);
        btn.setText("Created ✓");
      } catch (e) {
        new import_obsidian16.Notice(`Create share failed: ${e instanceof Error ? e.message : String(e)}`);
        btn.disabled = false;
        btn.setText("Create share link");
      }
    };
  }
};
var ShareManageModal = class extends import_obsidian16.Modal {
  constructor(ctx, serverUrl) {
    super(ctx.app);
    this.ctx = ctx;
    this.serverUrl = serverUrl;
  }
  onOpen() {
    this.titleEl.setText("Manage Shares");
    void this.render();
  }
  async render() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.setText("Loading…");
    let shares;
    try {
      shares = await this.ctx.client.listShares();
    } catch (e) {
      contentEl.setText(`Failed to load: ${e instanceof Error ? e.message : String(e)}`);
      return;
    }
    contentEl.empty();
    if (shares.length === 0) {
      contentEl.setText("You have not created any shares yet.");
      return;
    }
    const list = contentEl.createDiv({ cls: "litesync-history-list" });
    for (const s of shares) {
      const row = list.createDiv({ cls: "litesync-history-row" });
      const info = row.createDiv({ cls: "litesync-history-info" });
      const title = info.createDiv();
      const local0 = this.ctx.store.state.shares[s.id];
      title.createSpan({ cls: "litesync-rev", text: local0?.path ?? s.name ?? s.id.slice(0, 8) });
      if (local0 && local0.nameEncrypted !== true) {
        title.createSpan({ cls: "litesync-badge litesync-badge-delete", text: "File name not encrypted" });
      }
      if (s.revoked) title.createSpan({ cls: "litesync-badge litesync-badge-delete", text: "Revoked" });
      else if (s.expired) title.createSpan({ cls: "litesync-badge litesync-badge-delete", text: "Expired" });
      else title.createSpan({ cls: "litesync-badge litesync-badge-current", text: "Valid" });
      info.createDiv({
        cls: "litesync-history-meta",
        text: `Created ${new Date(s.createdAt * 1e3).toLocaleString()}` + (s.expiresAt > 0 ? ` · Expires ${new Date(s.expiresAt * 1e3).toLocaleString()}` : " · Permanent")
      });
      const btns = row.createDiv({ cls: "litesync-history-actions" });
      const local = this.ctx.store.state.shares[s.id];
      if (local && !s.revoked && !s.expired) {
        btns.createEl("button", { text: "Copy Link" }).onclick = () => void copyText(shareUrl(this.serverUrl, s.id, local.keyB64url));
      }
      if (!s.revoked) {
        btns.createEl("button", { text: "Undo" }).onclick = async () => {
          try {
            await this.ctx.client.revokeShare(s.id);
            delete this.ctx.store.state.shares[s.id];
            await this.ctx.store.save();
            new import_obsidian16.Notice("Revoked");
            await this.render();
          } catch (e) {
            new import_obsidian16.Notice(`Revoke failed: ${e instanceof Error ? e.message : String(e)}`);
          }
        };
      }
    }
  }
};

// src/state/store.ts
var SEQUENCE_EVIDENCE_LIMIT = 500;
function emptyState() {
  return {
    deviceId: "",
    lastSequence: 0,
    ledgerVaultId: void 0,
    files: {},
    conflicts: {},
    e2ee: null,
    shares: {},
    pendingDeletes: {},
    bootstrap: { ...PENDING_BOOTSTRAP },
    pendingOps: {},
    blockedChanges: {},
    pendingSwaps: {},
    sequenceEvidence: [],
    trustAnchor: null,
    checkpointChain: [],
    binding: null,
    recovery: null
  };
}
function newOwnershipToken() {
  const raw = new Uint8Array(8);
  crypto.getRandomValues(raw);
  let out = "";
  for (const b of raw) out += b.toString(16).padStart(2, "0");
  return out;
}
var StateStore = class {
  constructor(adapter, path) {
    this.adapter = adapter;
    this.path = path;
    this.state = emptyState();
    /** 两份副本都损坏（且无可用旧版 state.json）：同步必须停机等用户处理。 */
    this.corrupted = false;
    /** 上次成功写入的槽位；save 总是写另一个槽。 */
    this.activeSlot = null;
    this.generation = 0;
    /**
     * 保存串行化（v0.13.2 / §6.2）：任意时刻只有一个保存过程在跑。
     * dirtyGeneration 每次 save() 递增，savedGeneration 记录已落盘到哪一版——
     * 两者相等即「盘上的状态就是内存里的状态」。
     */
    this.saveChain = Promise.resolve();
    this.dirtyGeneration = 0;
    this.savedGeneration = 0;
  }
  slotPath(slot) {
    return this.path.replace(/\.json$/, `-${slot}.json`);
  }
  async readEnvelope(slot) {
    const p = this.slotPath(slot);
    try {
      if (!await this.adapter.exists(p)) return null;
      const env = JSON.parse(await this.adapter.read(p));
      if (env.schemaVersion !== 2 || typeof env.generation !== "number" || !env.payload) return null;
      const expect = await sha256Hex(encodeUtf8(JSON.stringify(env.payload)));
      if (env.checksum !== expect) return null;
      if (env.owner === void 0) env.owner = "";
      return env;
    } catch {
      return null;
    }
  }
  async load() {
    const [a, b] = [await this.readEnvelope("a"), await this.readEnvelope("b")];
    const anySlotExists = await this.adapter.exists(this.slotPath("a")) || await this.adapter.exists(this.slotPath("b"));
    let payload = null;
    if (a || b) {
      const winner = (a?.generation ?? -1) >= (b?.generation ?? -1) ? a : b;
      payload = winner.payload;
      this.generation = winner.generation;
      this.activeSlot = winner === a ? "a" : "b";
    } else if (!anySlotExists) {
      try {
        if (await this.adapter.exists(this.path)) {
          payload = JSON.parse(await this.adapter.read(this.path));
        }
      } catch (e) {
        console.error("[litesync] legacy state.json unreadable", e);
        this.corrupted = true;
        return;
      }
    } else {
      console.error("[litesync] both state replicas are corrupt; sync halted");
      this.corrupted = true;
      return;
    }
    if (payload) this.state = normalizeState(payload);
    const bad = firstInvalidIdentity(this.state.files);
    if (bad !== null) {
      console.error(`[litesync] state contains an invalid identity field (${bad}); sync halted`);
      this.corrupted = true;
      this.state = emptyState();
      return;
    }
    if (!this.state.deviceId) {
      this.state.deviceId = crypto.randomUUID();
      await this.save();
    }
  }
  /**
   * 保存状态（v0.13.2 / 计划书 §6.2：串行化）。
   *
   * 之前每次 `save()` 都直接开写。同步流程里有大量并发的 `await store.save()`
   * （pull/push/迁移各自都会存），两次保存可以交错成：
   *
   *   A 序列化了旧快照 → B 序列化了新快照 → B 写盘 → A 写盘（覆盖了 B）
   *
   * 于是**较早的状态覆盖了较新的状态**，重启后 lastSequence 回退、
   * 刚建立的身份字段消失。这里改成单条 promise 链：任意时刻只有一个保存过程，
   * 并且每次保存都在链上重新序列化当前 state——排队期间产生的新变更一定被带上。
   */
  async save() {
    if (this.corrupted) {
      console.error("[litesync] refusing to save over corrupt state");
      return;
    }
    this.dirtyGeneration++;
    const chained = this.saveChain.then(
      () => this.persistOnce(),
      () => this.persistOnce()
    );
    this.saveChain = chained.catch(() => {
    });
    return chained;
  }
  /**
   * 实际落盘一次：写非活动副本 → 读回校验（generation + checksum + ownership
   * token 三项都要对）→ 切换活动槽。
   *
   * ownership token 是本次写入的随机标记：读回时它必须是我们刚写的那一个。
   * 只比对 generation 无法区分「我写成功了」与「另一个进程/另一份插件实例
   * 恰好写了同样的 generation」——那种情况下两边会互相覆盖而谁都不报错。
   */
  async persistOnce() {
    if (this.corrupted) return;
    const target = this.activeSlot === "a" ? "b" : "a";
    const snapshotGeneration = this.dirtyGeneration;
    const payloadJson = JSON.stringify(this.state);
    const env = {
      schemaVersion: 2,
      generation: this.generation + 1,
      checksum: await sha256Hex(encodeUtf8(payloadJson)),
      owner: newOwnershipToken(),
      payload: JSON.parse(payloadJson)
    };
    const p = this.slotPath(target);
    await this.adapter.write(p, JSON.stringify(env));
    await evalFailpoint(FP.stateAfterSlotWrite);
    const check = await this.readEnvelope(target);
    if (check === null || check.generation !== env.generation) {
      throw new Error(`state replica write verification failed (${p})`);
    }
    if (check.checksum !== env.checksum) {
      throw new Error(`state replica checksum mismatch after write-back (${p})`);
    }
    if (check.owner !== env.owner) {
      throw new Error(
        `state replica was overwritten by another writer (${p}); please make sure no second Obsidian instance has the same vault open`
      );
    }
    await evalFailpoint(FP.stateBeforePointerSwitch);
    this.generation = env.generation;
    this.activeSlot = target;
    this.savedGeneration = snapshotGeneration;
  }
  /** 是否还有尚未落盘的变更（测试与关闭流程用）。 */
  get hasUnsavedChanges() {
    return this.dirtyGeneration > this.savedGeneration;
  }
  get(path) {
    return this.state.files[path];
  }
  /**
   * 全量替换某路径的状态（仅用于「这是一个全新对象」的场景）。
   * 更新已有对象请一律使用 {@link update}——否则会丢身份字段（LS-121-C04）。
   *
   * v0.13.2 §6.11：同步业务代码**禁止**直接调用本方法（ESLint 规则强制），
   * 请改用下方的具名转换 {@link replaceWithNewObject} 等。
   */
  set(path, fs) {
    this.state.files[path] = fs;
  }
  // ---------- §6.11 强类型 FileState 转换 ----------
  //
  // 业务代码只应通过这几个具名转换修改 FileState。每个转换对应一个真实发生的
  // 事件，读代码时能直接看出「这里发生了什么」，而不是看到一个 patch 对象后
  // 还要反推它有没有漏字段。
  /**
   * 内容更新：只改内容相关字段，身份字段一律沿用。
   * 用于「同一个对象的内容变了」——本地保存、下载远端新版本、合并结果落地。
   */
  patchContentState(path, patch) {
    return this.update(path, patch);
  }
  /**
   * 采纳服务器返回的对象身份（上传/下载成功后）。
   *
   * 身份字段只允许经这里进入 FileState。注意它**不改内容字段**：
   * 「服务器确认了身份」和「本地内容变了」是两件事，混在一起写最容易出错。
   */
  applyRemoteIdentity(path, id) {
    return this.update(path, id);
  }
  /**
   * 元数据改名落地：状态整体搬到新路径，身份不变，metaGeneration 前进。
   * fileId / contentGeneration 绝不在改名时变化（INV-05）。
   */
  applyMetaRenameState(from, to, id) {
    this.rename(from, to, id);
  }
  /**
   * 建立一个全新对象的状态（本地新建、或首次见到的远端对象）。
   * 这是唯一允许**从零构造** FileState 的入口。
   */
  replaceWithNewObject(path, fs) {
    this.set(path, fs);
  }
  /**
   * 不再跟踪该路径（本地或远端删除已完成）。
   *
   * 注意：服务器侧的 tombstone 由服务器维护（ADR-002），本地这里只是
   * 「这台设备不再持有该对象的状态」。
   */
  markDeleted(path) {
    delete this.state.files[path];
  }
  /** 删除后重建：走服务器的 restore 语义，身份与 revision 连续（INV-06）。 */
  restoreObject(path, fs) {
    this.set(path, fs);
  }
  /** 登记未解决冲突。 */
  recordConflict(path, c) {
    this.setConflict(path, c);
  }
  /**
   * 某路径此刻的状态视图（§6.11 要求的类型层区分）。
   *
   * 一个路径可能同时挂着 tracked 状态、冲突登记、blocked 记录、待手动删除标记，
   * 各处业务代码各查各的很容易漏掉一种。这里按**优先级**给出唯一答案：
   * 冲突 > 阻塞 > 待手动删除 > 已跟踪 > 未跟踪。
   */
  viewOf(path) {
    const state = this.state.files[path];
    const conflict = this.state.conflicts[path];
    if (conflict !== void 0) return { kind: "conflict", path, state, conflict };
    const blockedKey = state?.fileId ?? path;
    const blocked = this.state.blockedChanges[blockedKey] ?? this.state.blockedChanges[path];
    if (blocked !== void 0) return { kind: "blocked", path, state, blocked };
    if (this.state.pendingDeletes[path] !== void 0) return { kind: "pending-delete", path };
    if (this.state.bootstrap.status === "pending") return { kind: "bootstrap-pending", path, state };
    if (state !== void 0) return { kind: "tracked", path, state };
    return { kind: "untracked", path };
  }
  /**
   * 保身份更新（v0.12.1 / LS-121-C04）。
   *
   * 与旧代码里遍地的 `store.set(path, { hash, serverHash, revision, mtime, size })`
   * 不同：未在 patch 中显式给出（或给出 undefined）的字段一律沿用旧值，
   * 因此 fileId / generation / metaGeneration / serverPseudonym 不可能被
   * 「顺手写一半字段」的调用悄悄抹掉。
   */
  update(path, patch) {
    const prev = this.state.files[path];
    const next = {
      hash: prev?.hash ?? "",
      serverHash: prev?.serverHash ?? "",
      revision: prev?.revision ?? 0,
      mtime: prev?.mtime ?? 0,
      size: prev?.size ?? 0,
      ...prev?.fileId !== void 0 ? { fileId: prev.fileId } : {},
      ...prev?.generation !== void 0 ? { generation: prev.generation } : {},
      ...prev?.metaGeneration !== void 0 ? { metaGeneration: prev.metaGeneration } : {},
      ...prev?.metaFingerprint !== void 0 ? { metaFingerprint: prev.metaFingerprint } : {},
      ...prev?.serverPseudonym !== void 0 ? { serverPseudonym: prev.serverPseudonym } : {}
    };
    for (const [k, v] of Object.entries(patch)) {
      if (v === void 0) continue;
      next[k] = v;
    }
    this.state.files[path] = next;
    return next;
  }
  /**
   * 改名：把状态整体搬到新路径（身份字段全部保留）。
   * meta 模式下伪名不随路径改变，因此 serverPseudonym/fileId 必须原样带走。
   */
  rename(from, to, patch = {}) {
    const prev = this.state.files[from];
    if (prev === void 0) return;
    delete this.state.files[from];
    this.state.files[to] = { ...prev };
    this.update(to, patch);
  }
  delete(path) {
    delete this.state.files[path];
  }
  paths() {
    return Object.keys(this.state.files);
  }
  /** 按稳定文件身份反查本地路径（meta 模式伪名解析用）。 */
  pathByFileId(fileId) {
    for (const [path, fs] of Object.entries(this.state.files)) {
      if (fs.fileId === fileId) return path;
    }
    return void 0;
  }
  /**
   * 跨平台碰撞检查（v0.13.2 / §6.12）。
   *
   * 返回一条已跟踪的、与 `path` 不同但在某个受支持平台上会映射到同一个文件的路径
   * （大小写折叠、NFC/NFD、尾随点与空格、Windows 保留名）。
   *
   * `exceptFileId` 是「这次要落地的那个对象」自己的身份：同一个对象改大小写
   * 不算碰撞，别的对象撞上来才算。
   *
   * 用途：Windows/macOS 上把两个只差大小写的远端文件写到本地，会让后写的那个
   * 静默覆盖先写的那个——必须在写之前拦住，而不是事后发现内容丢了。
   */
  collidingPath(path, exceptFileId) {
    const key = platformCollisionKey(path);
    for (const [p, fs] of Object.entries(this.state.files)) {
      if (p === path) continue;
      if (exceptFileId !== void 0 && fs.fileId === exceptFileId) continue;
      if (platformCollisionKey(p) === key) return p;
    }
    return void 0;
  }
  getConflict(path) {
    return this.state.conflicts[path];
  }
  setConflict(path, c) {
    this.state.conflicts[path] = c;
  }
  clearConflict(path) {
    delete this.state.conflicts[path];
  }
  conflictPaths() {
    return Object.keys(this.state.conflicts);
  }
  // ---------- Bootstrap（首次接入，v8） ----------
  get bootstrapReady() {
    return this.state.bootstrap.status === "ready";
  }
  /**
   * 写入 pending binding（v0.13.1 / 计划书 §5.1）。
   *
   * preflight 一拿到服务器权威状态就调用：此后 bootstrap 期间的 LSE3/LSM1
   * 加解密、伪名解析、Merge 上传都能用上正确的绑定材料，
   * **绝不会**因为「正式状态还没写入」而回退到 LSE1 / 真实路径 / 无 fileId 上传。
   * status 保持 pending——同步入口仍然被 Gate 拦着。
   */
  setPendingBinding(binding) {
    this.state.bootstrap = { ...this.state.bootstrap, ...definedOnly(binding) };
  }
  /**
   * 接入完成：把 pending binding **原子**转为 active。
   * 保留 preflight already 写好的绑定字段，只补齐模式与游标并翻转 status。
   */
  completeBootstrap(mode, remoteVaultId, snapshotSequence, repoEpoch, keyEpoch) {
    this.state.bootstrap = {
      ...this.state.bootstrap,
      ...definedOnly({ remoteVaultId, repoEpoch, keyEpoch }),
      status: "ready",
      mode,
      snapshotSequence,
      completedAt: Date.now()
    };
    if (remoteVaultId) this.state.ledgerVaultId = remoteVaultId;
  }
  // ---------- 灾备恢复（v0.13.1 / 计划书 §5.6） ----------
  get recovery() {
    return this.state.recovery;
  }
  enterRecovery(r) {
    this.state.recovery = r;
  }
  clearRecovery() {
    this.state.recovery = null;
  }
  /** 重置为待接入（vaultId/repoEpoch 变化 / 用户重跑向导 / 导入新配置时）。 */
  resetBootstrap() {
    this.state.bootstrap = { ...PENDING_BOOTSTRAP };
  }
  /**
   * 换仓库（vaultId 变化）时作废整本同步账本（v0.18 实测缺陷，LS-121-C02）。
   *
   * repoEpoch 变化是「同一仓库的灾备恢复」——账本要保留去做恢复合并；
   * vaultId 变化是「对面根本是另一个仓库」（换库/换账户/服务器重装）——
   * files 里的 serverHash/revision、游标、队列、信任锚全都是**对旧仓库**的
   * 陈述，带进新仓库的后果不是错误而是静默：扫描会把「从未上传到这个仓库」
   * 的文件当成「已同步」，push 空转、状态栏假 synced、远端永远是空的。
   *
   * 只清账本，绝不动 Vault 里的用户文件；deviceId（本设备身份）保留。
   */
  resetForNewRepository() {
    this.clearSyncLedger();
    this.state.shares = {};
    this.state.pendingDeletes = {};
    this.state.e2ee = null;
    this.state.recovery = null;
    this.resetBootstrap();
  }
  /**
   * 只作废同步账本（files/游标/队列/冲突/信任锚），不动 bootstrap 与密钥。
   * local-init 对空远端的自愈用（见 bootstrap-manager）：那里 bootstrap 流程
   * 正在进行，不能整个 reset。
   */
  clearSyncLedger() {
    this.state.ledgerVaultId = void 0;
    this.state.files = {};
    this.state.lastSequence = 0;
    this.state.conflicts = {};
    this.state.pendingOps = {};
    this.state.blockedChanges = {};
    this.state.trustAnchor = null;
    this.state.checkpointChain = [];
  }
  // ---------- 待手动删除（移动端删除安全，v6） ----------
  hasPendingDelete(path) {
    return this.state.pendingDeletes[path] !== void 0;
  }
  setPendingDelete(path) {
    this.state.pendingDeletes[path] = Date.now();
  }
  clearPendingDelete(path) {
    delete this.state.pendingDeletes[path];
  }
  // ---------- 绑定指纹（v0.12.1 / LS-121-C02） ----------
  get binding() {
    return this.state.binding;
  }
  /** 当前状态是否绑定到给定指纹（任一字段不同 = 必须重新绑定）。 */
  isBoundTo(fp) {
    const b = this.state.binding;
    return b !== null && b.serverUrl === fp.serverUrl && b.tokenDigest === fp.tokenDigest && b.deviceId === fp.deviceId && b.vaultKeyDigest === fp.vaultKeyDigest && b.vaultChoice === fp.vaultChoice;
  }
  /** 权威校验通过后固定绑定（只能由 SyncManager 的重新绑定流程调用）。 */
  setBinding(fp) {
    this.state.binding = { ...fp };
  }
  clearBinding() {
    this.state.binding = null;
  }
  // ---------- 被阻塞的远端变更（v9；v0.13.2 §6.4 完整记录） ----------
  /**
   * 登记/更新一条被阻塞的远端变更，返回它的键。
   *
   * 键优先取 fileId：同一个对象改名后真实路径会变，用路径当键会在改名后
   * 留下一条永远不会被清除的孤儿记录。
   *
   * 重复登记同一条时累加 retryCount 并保留原 operationId——它是这次「重放」
   * 的幂等键，重试必须沿用。
   */
  setBlockedChange(rec) {
    const key = rec.fileId ?? rec.realPath;
    const prev = this.state.blockedChanges[key];
    this.state.blockedChanges[key] = {
      ...rec,
      retryCount: (prev?.retryCount ?? 0) + 1,
      operationId: prev?.operationId ?? newOwnershipToken() + newOwnershipToken(),
      at: Date.now()
    };
    return key;
  }
  getBlockedChange(key) {
    return this.state.blockedChanges[key];
  }
  clearBlockedChange(key) {
    delete this.state.blockedChanges[key];
  }
  /** 当前所有被阻塞的变更（键 + 记录）。 */
  blockedChanges() {
    return Object.entries(this.state.blockedChanges);
  }
  // ---------- 名字互换的中断恢复（v0.13.2 §6.9） ----------
  setPendingSwap(swap) {
    this.state.pendingSwaps[swap.tempPath] = { ...swap };
  }
  clearPendingSwap(tempPath) {
    delete this.state.pendingSwaps[tempPath];
  }
  pendingSwaps() {
    return Object.values(this.state.pendingSwaps);
  }
  // ---------- sequence 处置证据（v0.14.0-RC §8.8 第 10 条） ----------
  /**
   * 记录一条已确认 sequence 的处置结果。
   *
   * 必须在推进游标**之前**调用：先有证据再确认，顺序反过来的话，
   * 中间崩溃会留下一个「确认了但没人知道为什么」的 sequence。
   */
  recordSequenceEvidence(e) {
    this.state.sequenceEvidence.push(e);
    if (this.state.sequenceEvidence.length > SEQUENCE_EVIDENCE_LIMIT) {
      this.state.sequenceEvidence.splice(0, this.state.sequenceEvidence.length - SEQUENCE_EVIDENCE_LIMIT);
    }
  }
  /** 最近的处置证据（诊断用，最新的在最后）。 */
  sequenceEvidence() {
    return this.state.sequenceEvidence;
  }
};
function normalizeState(raw) {
  const state = {
    deviceId: typeof raw.deviceId === "string" ? raw.deviceId : "",
    lastSequence: typeof raw.lastSequence === "number" ? raw.lastSequence : 0,
    ledgerVaultId: typeof raw.ledgerVaultId === "string" ? raw.ledgerVaultId : void 0,
    files: raw.files && typeof raw.files === "object" ? raw.files : {},
    conflicts: raw.conflicts && typeof raw.conflicts === "object" ? raw.conflicts : {},
    e2ee: raw.e2ee && typeof raw.e2ee === "object" ? raw.e2ee : null,
    shares: raw.shares && typeof raw.shares === "object" ? raw.shares : {},
    pendingDeletes: raw.pendingDeletes && typeof raw.pendingDeletes === "object" ? raw.pendingDeletes : {},
    bootstrap: raw.bootstrap && typeof raw.bootstrap === "object" ? raw.bootstrap : { ...PENDING_BOOTSTRAP },
    pendingOps: normalizePendingOps(raw.pendingOps),
    blockedChanges: normalizeBlockedChanges(raw.blockedChanges),
    pendingSwaps: normalizePendingSwaps(raw.pendingSwaps),
    sequenceEvidence: Array.isArray(raw.sequenceEvidence) ? raw.sequenceEvidence.slice(-SEQUENCE_EVIDENCE_LIMIT) : [],
    trustAnchor: normalizeTrustAnchor(raw.trustAnchor),
    checkpointChain: Array.isArray(raw.checkpointChain) ? raw.checkpointChain.slice(-64) : [],
    binding: normalizeBinding(raw.binding),
    recovery: raw.recovery && typeof raw.recovery === "object" ? raw.recovery : null
  };
  for (const fs of Object.values(state.files)) {
    if (!fs.serverHash) fs.serverHash = fs.hash;
  }
  if (!raw.bootstrap && (state.lastSequence > 0 || Object.keys(state.files).length > 0)) {
    state.bootstrap = { status: "ready", mode: "legacy", completedAt: Date.now() };
  }
  return state;
}
function definedOnly(o) {
  const out = {};
  for (const [k, v] of Object.entries(o)) {
    if (v !== void 0) out[k] = v;
  }
  return out;
}
async function computeBinding(input) {
  const digest = async (label, value) => value === "" ? "" : (await sha256Hex(encodeUtf8(`litesync/v1/binding/${label}:${value}`))).slice(0, 16);
  const keyMaterial = input.vaultKey ? `${input.vaultKey.salt}|${input.vaultKey.wrappedKey}` : "";
  return {
    serverUrl: input.serverUrl.trim().replace(/\/+$/, ""),
    tokenDigest: await digest("token", input.apiToken),
    deviceId: input.deviceId,
    vaultKeyDigest: await digest("vault-key", keyMaterial),
    vaultChoice: input.vaultChoice ?? ""
  };
}
function firstInvalidIdentity(files) {
  for (const [path, fs] of Object.entries(files)) {
    if (fs.fileId !== void 0 && !isFileId(fs.fileId)) return `${path}.fileId`;
    if (fs.generation !== void 0 && !isGeneration(fs.generation)) return `${path}.generation`;
    if (fs.metaGeneration !== void 0 && !isGeneration(fs.metaGeneration)) return `${path}.metaGeneration`;
    if (fs.serverPseudonym !== void 0 && !isFileId(fs.serverPseudonym)) return `${path}.serverPseudonym`;
  }
  return null;
}
function normalizeBinding(raw) {
  if (!raw || typeof raw !== "object") return null;
  const b = raw;
  if (typeof b.serverUrl !== "string" || typeof b.tokenDigest !== "string" || typeof b.deviceId !== "string" || typeof b.vaultKeyDigest !== "string") {
    return null;
  }
  if (typeof b.vaultChoice !== "string") return null;
  return {
    serverUrl: b.serverUrl,
    tokenDigest: b.tokenDigest,
    deviceId: b.deviceId,
    vaultKeyDigest: b.vaultKeyDigest,
    vaultChoice: b.vaultChoice
  };
}
function normalizeBlockedChanges(raw) {
  if (!raw || typeof raw !== "object") return {};
  const out = {};
  for (const [key, v] of Object.entries(raw)) {
    if (!v || typeof v !== "object") continue;
    const b = v;
    const action = b.action === "delete" || b.action === "rename" ? b.action : "upsert";
    out[key] = {
      sequence: typeof b.sequence === "number" ? b.sequence : 0,
      action,
      realPath: typeof b.realPath === "string" ? b.realPath : key,
      reason: typeof b.reason === "string" ? b.reason : " (registered before the upgrade, reason not recorded)",
      retryCount: typeof b.retryCount === "number" ? b.retryCount : 0,
      operationId: typeof b.operationId === "string" ? b.operationId : "",
      at: typeof b.at === "number" ? b.at : Date.now(),
      ...definedOnly({
        fileId: b.fileId,
        serverPseudonym: b.serverPseudonym,
        revision: b.revision,
        contentHash: b.contentHash,
        contentGeneration: b.contentGeneration,
        metaGeneration: b.metaGeneration,
        renameFrom: b.renameFrom,
        renameTo: b.renameTo
      })
    };
  }
  return out;
}
function normalizeTrustAnchor(raw) {
  if (!raw || typeof raw !== "object") return null;
  const a = raw;
  if (typeof a.repoEpoch !== "string" || typeof a.checkpointHash !== "string") return null;
  if (typeof a.headSequence !== "number") return null;
  if (!a.devicePublicKeys || typeof a.devicePublicKeys !== "object") return null;
  return {
    repoEpoch: a.repoEpoch,
    checkpointHash: a.checkpointHash,
    headSequence: a.headSequence,
    devicePublicKeys: a.devicePublicKeys,
    revokedDevices: Array.isArray(a.revokedDevices) ? a.revokedDevices : [],
    updatedAt: typeof a.updatedAt === "number" ? a.updatedAt : 0
  };
}
function normalizePendingSwaps(raw) {
  if (!raw || typeof raw !== "object") return {};
  const out = {};
  for (const [key, v] of Object.entries(raw)) {
    if (!v || typeof v !== "object") continue;
    const s = v;
    if (typeof s.tempPath !== "string" || typeof s.fileId !== "string" || typeof s.targetPath !== "string") {
      continue;
    }
    out[key] = { tempPath: s.tempPath, fileId: s.fileId, targetPath: s.targetPath };
  }
  return out;
}
function normalizePendingOps(raw) {
  if (!raw || typeof raw !== "object") return {};
  const out = {};
  for (const [path, v] of Object.entries(raw)) {
    if (v === "upsert" || v === "delete") {
      out[path] = { action: v };
    } else if (v && typeof v === "object" && "action" in v) {
      const op = v;
      if (op.action === "upsert" || op.action === "delete" || op.action === "move") out[path] = op;
    }
  }
  return out;
}

// src/crypto/signing-key.ts
var SIGNING_KEY_SECRET_ID = "litesync-signing-key";
async function loadOrCreateSigningKey(app) {
  const existing = await readStored(app);
  if (existing !== null) {
    return { privateKeyPkcs8B64: existing.privateKey, publicKeyB64: existing.publicKey, created: false };
  }
  const fresh = await generateSigningKey();
  const stored = {
    v: 1,
    privateKey: fresh.privateKeyPkcs8B64,
    publicKey: fresh.publicKeyB64,
    createdAt: Date.now()
  };
  app.secretStorage.setSecret(SIGNING_KEY_SECRET_ID, JSON.stringify(stored));
  return { privateKeyPkcs8B64: fresh.privateKeyPkcs8B64, publicKeyB64: fresh.publicKeyB64, created: true };
}
async function readStored(app) {
  try {
    const raw = app.secretStorage.getSecret(SIGNING_KEY_SECRET_ID);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed.v !== 1 || !parsed.privateKey || !parsed.publicKey) return null;
    return parsed;
  } catch {
    return null;
  }
}

// src/sync/freshness.ts
async function verifyFreshness(anchor, knownChain, cp, vaultId) {
  const publicKey = anchor.devicePublicKeys[cp.body.signingDeviceId];
  if (publicKey === void 0) {
    return {
      ok: false,
      kind: "unknown-signer",
      message: `checkpoint signed by an unknown device ${cp.body.signingDeviceId.slice(0, 8)}… signed; please add that device to the trust set via pairing first`
    };
  }
  if (anchor.revokedDevices.includes(cp.body.signingDeviceId)) {
    return {
      ok: false,
      kind: "revoked-signer",
      message: `checkpoint signed by a revoked device ${cp.body.signingDeviceId.slice(0, 8)}… signed, rejected`
    };
  }
  if (!await verifyCheckpoint(publicKey, cp)) {
    return { ok: false, kind: "bad-signature", message: "Checkpoint signature verification failed — sync stopped" };
  }
  if (cp.body.vaultId !== vaultId) {
    return { ok: false, kind: "wrong-vault", message: "The checkpoint belongs to another vault — rejected" };
  }
  if (cp.body.repoEpoch !== anchor.repoEpoch) {
    return {
      ok: false,
      kind: "epoch-mismatch",
      message: "The checkpoint's repoEpoch does not match the local trust anchor; after disaster recovery the trust chain must be re-established"
    };
  }
  if (cp.hash === anchor.checkpointHash) {
    return { ok: true, kind: "same", checkpoint: cp };
  }
  if (cp.body.headSequence < anchor.headSequence) {
    return {
      ok: false,
      kind: "rollback",
      message: `The server's vault state is older than what this device has confirmed (head ${cp.body.headSequence} < confirmed ${anchor.headSequence}), sync stopped`
    };
  }
  if (cp.body.headSequence === anchor.headSequence) {
    return {
      ok: false,
      kind: "fork",
      message: `Two different vault states at the same head sequence (${cp.body.headSequence}) — the server may be showing different devices different histories; sync stopped`
    };
  }
  if (!knownChain.includes(cp.body.previousCheckpointHash)) {
    return {
      ok: false,
      kind: "broken-chain",
      message: "The checkpoint cannot be connected to the history this device knows; that usually means the server holds a parallel history — sync stopped"
    };
  }
  return { ok: true, kind: "extends", checkpoint: cp };
}
function advanceAnchor(anchor, knownChain, cp, limit = 64) {
  const chain = [...knownChain, cp.hash];
  return {
    anchor: { ...anchor, checkpointHash: cp.hash, headSequence: cp.body.headSequence, updatedAt: Date.now() },
    chain: chain.slice(-limit)
  };
}

// src/sync/checkpoint-sync.ts
function localCheckpointObjects(ctx) {
  const out = [];
  for (const path of ctx.store.paths()) {
    const fs = ctx.store.get(path);
    if (fs?.fileId === void 0) continue;
    out.push({
      fileId: fs.fileId,
      contentGeneration: fs.generation ?? 0,
      metaGeneration: fs.metaGeneration ?? 0,
      contentHash: fs.serverHash,
      metadataHash: fs.metaFingerprint ?? "",
      state: "live"
    });
  }
  return out;
}
async function verifyCheckpointChain(ctx) {
  const anchor = ctx.store.state.trustAnchor;
  if (anchor === null) return true;
  let bundle;
  try {
    bundle = await ctx.client.checkpoints(anchor.headSequence);
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 405)) {
      ctx.log("checkpoint: the server does not support signed checkpoints, so this round has no freshness protection");
      return true;
    }
    throw e;
  }
  if (bundle.conflicting.length > 1) {
    const msg = `Vault fork detected: at the same position there are ${bundle.conflicting.length} different signed states. The server may be showing different devices different histories — auto-sync stopped`;
    ctx.gate.markIntegrityError(msg);
    ctx.notify(msg);
    return false;
  }
  const effective = {
    ...anchor,
    revokedDevices: [.../* @__PURE__ */ new Set([...anchor.revokedDevices, ...bundle.revokedDevices])]
  };
  let chain = ctx.store.state.checkpointChain;
  for (const cp of bundle.checkpoints) {
    const verdict = await verifyFreshness(effective, chain, cp, ctx.store.state.bootstrap.remoteVaultId ?? "");
    if (!verdict.ok) {
      ctx.gate.markIntegrityError(verdict.message);
      ctx.notify(verdict.message);
      ctx.log(`checkpoint: rejected (${verdict.kind})`);
      return false;
    }
    if (verdict.kind === "same") continue;
    const next = advanceAnchor(effective, chain, cp);
    ctx.store.state.trustAnchor = next.anchor;
    ctx.store.state.checkpointChain = next.chain;
    chain = next.chain;
    ctx.log(`checkpoint: adopted ${cp.hash.slice(0, 12)}\u2026 (head ${cp.body.headSequence})`);
  }
  return true;
}
async function publishCheckpoint(ctx) {
  const anchor = ctx.store.state.trustAnchor;
  const pkcs8 = ctx.signingKeyPkcs8?.();
  if (anchor === null || !pkcs8) return;
  const b = ctx.store.state.bootstrap;
  const head = ctx.store.state.lastSequence;
  if (head <= anchor.headSequence) return;
  try {
    const objects = localCheckpointObjects(ctx);
    const body = {
      version: 1,
      vaultId: b.remoteVaultId ?? "",
      repoEpoch: b.repoEpoch ?? "",
      formatEpoch: b.formatEpoch ?? 1,
      keyEpoch: b.keyEpoch ?? 0,
      headSequence: head,
      objectsRoot: await objectsRoot(objects),
      objectCount: objects.length,
      previousCheckpointHash: anchor.checkpointHash,
      signingDeviceId: ctx.store.state.deviceId,
      timestamp: Date.now()
    };
    const priv = await importSigningPrivateKey(pkcs8);
    const signed = await signCheckpoint(priv, body);
    await ctx.client.publishCheckpoint(signed);
    ctx.store.state.trustAnchor = {
      ...anchor,
      checkpointHash: signed.hash,
      headSequence: head,
      updatedAt: Date.now()
    };
    ctx.store.state.checkpointChain = [...ctx.store.state.checkpointChain, signed.hash].slice(-64);
    ctx.log(`checkpoint: published ${signed.hash.slice(0, 12)}\u2026 (head ${head}, ${objects.length} objects)`);
  } catch (e) {
    ctx.log(`checkpoint: publish failed (${e instanceof Error ? e.message : String(e)})`);
  }
}
async function ensureSigningKeyRegistered(ctx, publicKeyB64) {
  if (!publicKeyB64) return;
  try {
    await ctx.client.registerSigningKey(publicKeyB64);
  } catch (e) {
    ctx.log(`checkpoint: register signing key failed (${e instanceof Error ? e.message : String(e)})`);
    return;
  }
  if (ctx.store.state.trustAnchor !== null) return;
  if (ctx.store.state.bootstrap.mode !== "local-init") {
    ctx.log("checkpoint: no trust chain established (this device is not the first device and needs a trusted anchor via pairing)");
    return;
  }
  ctx.store.state.trustAnchor = {
    repoEpoch: ctx.store.state.bootstrap.repoEpoch ?? "",
    checkpointHash: "",
    headSequence: 0,
    devicePublicKeys: { [ctx.store.state.deviceId]: publicKeyB64 },
    revokedDevices: [],
    updatedAt: Date.now()
  };
  ctx.store.state.checkpointChain = [];
  ctx.log("checkpoint: a genesis trust anchor was established (this device is the vault's first device)");
}

// src/sync/sync-manager.ts
var RETRY_DELAYS = [5, 15, 30, 60, 120, 300];
var MAX_FOLLOW_UPS = 8;
var MAX_FULL_SYNC_ROUNDS = 6;
var SyncManager = class {
  constructor(ctx) {
    this.ctx = ctx;
    /** pull 应用远端变更时置位，供事件监听器忽略自身写入产生的事件。 */
    this.applyingRemote = false;
    this.onStatus = () => {
    };
    this.syncing = false;
    this.runAgain = false;
    /**
     * 本条同步链要不要执行 push（时间混淆，§11.2）。
     *
     * 在 sync() 入口按 reason 评估而不是在 runOnce 里：续轮的 reason 是
     * "follow-up"，无从判断最初是谁触发的；且手动同步撞上进行中的链时只是
     * 设 runAgain 搭车，豁免必须在入口处记下来，否则会被吞掉。
     * 任何一轮实际执行过 push 后清零。
     */
    this.pushWanted = false;
    this.retryTimer = null;
    this.retryIndex = 0;
    /** 当前正在执行的同步链（含 runAgain 续轮）；fullSync 据此等待真正结束（LS-121-C06） */
    this.running = null;
    /** 最近一轮同步的失败原因（fullSync 用它向迁移流程报错，而不是静默成功） */
    this.lastError = null;
    /** 最近一条同步链的累计统计（手动同步的完成提示用；链开始时清零、每成功轮累加） */
    this.lastCounters = null;
    this.protocolWarned = false;
    this.stateCorruptWarned = false;
    this.credentialChecked = false;
    /** 「凭据被拒」只弹一次常驻通知（验收 T5.2）；恢复后复位 */
    this.credentialWarned = false;
    /** 「凭据被拒」的常驻通知句柄：恢复时主动撤下，而不是让用户自己点掉 */
    this.credentialNotice = null;
    /** 本会话是否已确认过重置凭证登记（v0.18）：每会话最多补登记一次 */
    this.resetAuthChecked = false;
    /** 服务器最近上报的 keyEpoch（E2EE 一致性防御用；-1 = 尚未获知） */
    this.serverKeyEpoch = -1;
    /** 「服务器加密状态自相矛盾」的常驻通知句柄（恢复时撤下） */
    this.e2eeMismatchNotice = null;
  }
  get isSyncing() {
    return this.syncing;
  }
  /** 手动触发时调用：清零退避计数，立即重试。 */
  resetRetry() {
    this.retryIndex = 0;
    if (this.retryTimer !== null) {
      window.clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }
  /**
   * 作废当前绑定（v0.12.1 / LS-121-C02）。
   *
   * server URL、Token、设备身份、vault key 文档任一变化时由 main.ts 调用：
   * 会话缓存（credentialChecked）清零，Gate 切到 unbound，
   * 于是上传、删除、MOVE、历史恢复、分享在重新完成权威校验之前一律被拒。
   * 绝不允许把针对原服务器建立的本地状态直接用在另一台服务器上。
   */
  invalidateBinding(reason) {
    this.credentialChecked = false;
    this.ctx.gate.markUnbound(reason);
    this.ctx.gate.markProtocolMismatch(null);
    this.ctx.log(`binding invalidated: ${reason}`);
  }
  /**
   * 触发一轮同步。
   *
   * 返回的 Promise 在**整条同步链**（含因 runAgain 追加的续轮）结束后才 resolve；
   * 已经在同步中时返回正在执行的那条链，调用方 await 它即可获得「至少包含我这次
   * 请求」的完成语义（LS-121-C06）。
   */
  async sync(reason) {
    if (!(this.ctx.deferPush?.(reason) ?? false)) this.pushWanted = true;
    if (this.syncing) {
      this.runAgain = true;
      await this.running;
      return;
    }
    this.lastError = null;
    this.lastCounters = null;
    const chain = this.runChain(reason);
    this.running = chain;
    try {
      await chain;
    } finally {
      if (this.running === chain) this.running = null;
    }
  }
  /** 最近一条同步链的失败原因（手动同步的结果提示用）；成功链为 null。 */
  get lastSyncError() {
    return this.lastError instanceof Error ? this.lastError : null;
  }
  /** 最近一条同步链的累计统计；链没跑成任何一轮（如被 gate 拦下）时为 null。 */
  get lastSyncCounters() {
    return this.lastCounters;
  }
  /**
   * 等待同步彻底收敛（迁移等不可逆流程的前置）。
   *
   * 「设置了 runAgain 就返回」曾让 enableE2ee 在队列还没推完时进入迁移，
   * 于是迁移清单与真实内容不一致。这里要求：同步链结束、没有待续轮、
   * 待推送队列为空、且最近一轮没有失败——任何一项不满足都继续或报错。
   */
  async fullSync(reason = "full-sync") {
    this.lastError = null;
    for (let round = 0; round < MAX_FULL_SYNC_ROUNDS; round++) {
      await this.sync(reason);
      const failure = this.lastError;
      if (failure instanceof Error) throw failure;
      const block = syncGateBlock(this.ctx);
      if (block !== null) throw new Error(`Sync could not complete: ${block.message}`);
      if (!this.syncing && !this.runAgain && this.ctx.queue.size === 0) return;
    }
    throw new Error(
      `Sync did not converge within ${MAX_FULL_SYNC_ROUNDS} rounds (still ${this.ctx.queue.size} items still pending), this operation was aborted`
    );
  }
  /** 执行一轮同步及其所有续轮。 */
  async runChain(reason) {
    let current = reason;
    for (let i = 0; i <= MAX_FOLLOW_UPS; i++) {
      await this.runOnce(current);
      if (!this.runAgain) return;
      this.runAgain = false;
      current = "follow-up";
    }
    this.ctx.log(`sync chain stopped after ${MAX_FOLLOW_UPS} follow-ups`);
  }
  async runOnce(reason) {
    this.syncing = true;
    if (this.retryTimer !== null) {
      window.clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    this.onStatus("syncing");
    const counters = { pulled: 0, pushed: 0, conflicts: 0 };
    try {
      if (this.ctx.store.corrupted) {
        const msg = "The local sync state file is corrupt (neither copy can be read) and sync has stopped; check state-a/state-b.json in the plugin directory or rejoin";
        if (!this.stateCorruptWarned) {
          this.stateCorruptWarned = true;
          this.ctx.notify(msg);
        }
        this.ctx.log(`sync blocked (${reason}): state corrupted`);
        this.onStatus("offline", msg);
        return;
      }
      if (!this.ctx.store.bootstrapReady) {
        this.ctx.log(`sync blocked (${reason}): bootstrap pending`);
        this.onStatus("idle");
        return;
      }
      if (!await this.ensureBinding()) return;
      if (this.ctx.gate.isMigrationActive) {
        this.ctx.log(`sync skipped (${reason}): migration active`);
        this.onStatus("idle");
        return;
      }
      await this.ctx.refreshE2ee();
      if (this.ctx.e2ee.enabled && this.serverKeyEpoch === 0) {
        const msg = "The server's encryption state contradicts itself: the end-to-end encryption key document is enabled, but the vault claims to be unencrypted (keyEpoch=0).\nSync stopped so that undecryptable content is not written. The server administrator should check — usually it is a leftover old key document (the server's startup log will have a matching warning).";
        this.ctx.gate.markProtocolMismatch(msg);
        if (!this.e2eeMismatchNotice) {
          const handle = this.ctx.notify(msg, 0);
          if (handle) this.e2eeMismatchNotice = handle;
        }
        this.ctx.log("sync blocked: e2ee state mismatch (doc enabled, keyEpoch=0)");
        this.onStatus("offline", msg);
        return;
      }
      if (this.e2eeMismatchNotice) {
        this.e2eeMismatchNotice.hide();
        this.e2eeMismatchNotice = null;
      }
      if (this.ctx.e2ee.needsUnlock) {
        this.ctx.log("sync paused: E2EE locked");
        this.onStatus("locked");
        return;
      }
      const block = syncGateBlock(this.ctx);
      if (block !== null) {
        this.ctx.log(`sync blocked (${reason}): ${block.reason}`);
        this.onStatus(block.reason === "key-locked" ? "locked" : "offline", block.message);
        return;
      }
      const pub = this.ctx.signingPublicKey?.() ?? "";
      if (pub) {
        await ensureSigningKeyRegistered(this.ctx, pub);
        this.ctx.onSigningKeyRegistered?.();
      }
      if (!await verifyCheckpointChain(this.ctx)) {
        await this.ctx.store.save();
        this.onStatus("offline", "An abnormal vault state was detected — auto-sync stopped");
        return;
      }
      this.applyingRemote = true;
      await recoverInterruptedSwaps(this.ctx);
      const pull1 = await pullRemoteChanges(this.ctx);
      this.applyingRemote = false;
      await scanLocalChanges(this.ctx);
      let push = { pushed: 0, conflicts: 0 };
      if (this.pushWanted) {
        push = await pushPendingChanges(this.ctx);
        this.pushWanted = false;
      } else if (this.ctx.queue.size > 0) {
        this.ctx.onPushDeferred?.();
      }
      this.applyingRemote = true;
      const pull2 = await pullRemoteChanges(this.ctx);
      this.applyingRemote = false;
      await publishCheckpoint(this.ctx);
      await this.ctx.store.save();
      counters.pulled = pull1.applied + pull2.applied;
      counters.pushed = push.pushed;
      counters.conflicts = pull1.conflicts + push.conflicts + pull2.conflicts;
      this.retryIndex = 0;
      this.lastError = null;
      const prev = this.lastCounters ?? { pulled: 0, pushed: 0, conflicts: 0 };
      this.lastCounters = {
        pulled: prev.pulled + counters.pulled,
        pushed: prev.pushed + counters.pushed,
        conflicts: prev.conflicts + counters.conflicts
      };
      this.ctx.log(
        `sync ok (${reason}): pulled=${counters.pulled} pushed=${counters.pushed} conflicts=${counters.conflicts} lastSequence=${this.ctx.store.state.lastSequence}`
      );
      this.onStatus(counters.conflicts > 0 ? "conflict" : "synced");
    } catch (e) {
      const failure = e instanceof Error ? e : new Error(String(e));
      this.lastError = failure;
      this.ctx.log(`sync failed (${reason}): ${failure.message}`);
      try {
        await this.ctx.store.save();
      } catch {
      }
      if (e instanceof E2eeLockedError) {
        this.onStatus("locked");
      } else if (e instanceof ApiError && e.status === 401) {
        const msg = e.is("TOKEN_REVOKED") ? "This device's credential has been revoked (the server reset the API Token or revoked this device).\nEnter a new API Token in settings and click \"Test Connection\" to resume syncing — local notes, history and encryption keys are unaffected." : "This device's credential is no longer valid: the server rejected it.\nCheck that the API Token in settings is correct (click \"Test Connection\" after replacing it to recover); local data is unaffected.";
        this.ctx.gate.markCredentialRejected(msg);
        if (!this.credentialWarned) {
          this.credentialWarned = true;
          const handle = this.ctx.notify(msg, 0);
          if (handle) this.credentialNotice = handle;
        }
        this.onStatus("offline", msg);
      } else {
        this.onStatus("offline", failure.message);
        this.scheduleRetry();
      }
    } finally {
      this.applyingRemote = false;
      this.syncing = false;
    }
  }
  /**
   * 权威绑定校验（LS-121-C02）。
   *
   * 每轮同步都会比对「本地状态所绑定的指纹」与「当前配置的指纹」。
   * 不一致（换了服务器 / 换了 Token / 换了设备身份 / vault key 文档被替换）时
   * 必须重新执行 /info + 凭据 + vaultId/repoEpoch/keyEpoch 校验，通过后才
   * 固定新绑定并解除 unbound。返回 false 表示本轮同步必须停止。
   */
  async ensureBinding() {
    const cfg = this.ctx.credentials();
    const want = await computeBinding({
      serverUrl: cfg.serverUrl,
      apiToken: cfg.apiToken,
      deviceId: this.ctx.store.state.deviceId,
      vaultKey: this.ctx.e2ee.doc,
      vaultChoice: cfg.vaultChoice
    });
    if (!this.ctx.store.isBoundTo(want)) {
      const prev = this.ctx.store.binding;
      this.credentialChecked = false;
      this.ctx.gate.markUnbound(prev === null ? "First binding" : describeBindingChange(prev, want));
      this.ctx.store.clearBinding();
    }
    const info = await this.ctx.client.info();
    this.ctx.gate.markCredentialRejected(null);
    this.credentialWarned = false;
    this.credentialNotice?.hide();
    this.credentialNotice = null;
    const err = protocolError(info);
    if (err) {
      this.ctx.gate.markProtocolMismatch(err);
      if (!this.protocolWarned) {
        this.protocolWarned = true;
        this.ctx.notify(err);
      }
      this.ctx.log(`sync blocked: ${err}`);
      this.onStatus("offline", err);
      return false;
    }
    this.ctx.gate.markProtocolMismatch(null);
    this.protocolWarned = false;
    if (!await this.adoptRepoIdentity(info)) return false;
    this.serverKeyEpoch = info.keyEpoch ?? 0;
    if (!this.ctx.store.state.ledgerVaultId && info.vaultId) {
      this.ctx.store.state.ledgerVaultId = info.vaultId;
    }
    if (info.resetAuthConfigured === false && !this.resetAuthChecked) {
      this.resetAuthChecked = true;
      void this.registerResetAuthOnce();
    }
    await this.ensureDeviceCredential();
    const fresh = this.ctx.credentials();
    this.ctx.store.setBinding(
      await computeBinding({
        serverUrl: fresh.serverUrl,
        apiToken: fresh.apiToken,
        deviceId: this.ctx.store.state.deviceId,
        vaultKey: this.ctx.e2ee.doc,
        vaultChoice: fresh.vaultChoice
      })
    );
    await this.ctx.store.save();
    this.ctx.gate.markBound();
    return true;
  }
  /** 补登记重置凭证：失败只记日志（下个会话再试），绝不打扰用户。 */
  async registerResetAuthOnce() {
    try {
      const resetAuth = await this.ctx.e2ee.resetAuth();
      if (!resetAuth) return;
      await this.ctx.client.registerResetAuth(resetAuth);
      this.ctx.log("reset-auth registered");
    } catch (e) {
      this.ctx.log(`reset-auth register failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  /**
   * 校验并采纳服务器仓库身份（vaultId / repoEpoch / keyEpoch / metaState）。
   * 返回 false 表示本轮同步必须停止（仓库身份变了，需要重新接入）。
   */
  async adoptRepoIdentity(info) {
    const saved = this.ctx.store.state.bootstrap.remoteVaultId;
    if (saved && info.vaultId && info.vaultId !== saved) {
      this.ctx.store.resetForNewRepository();
      this.ctx.store.clearBinding();
      await this.ctx.store.save();
      const msg = "The sync vault on the server has changed (vaultId changed), so sync is paused and the old vault's sync records are discarded;\nlocal notes are unaffected. Please re-run the setup wizard (or click \"Test Connection\") to confirm how this device joins.";
      this.ctx.notify(msg);
      this.ctx.log(`sync blocked: vaultId changed ${saved} -> ${info.vaultId}`);
      this.onStatus("offline", msg);
      return false;
    }
    const savedEpoch = this.ctx.store.state.bootstrap.repoEpoch;
    if (savedEpoch && info.repoEpoch && info.repoEpoch !== savedEpoch) {
      this.ctx.store.enterRecovery({
        reason: "repo-epoch-changed",
        previousEpoch: savedEpoch,
        serverEpoch: info.repoEpoch,
        localSequence: this.ctx.store.state.lastSequence,
        localFileCount: this.ctx.store.paths().length,
        at: Date.now()
      });
      this.ctx.store.resetBootstrap();
      this.ctx.store.clearBinding();
      await this.ctx.store.save();
      const msg = "The server's data was restored from a backup (repoEpoch changed) and sync is paused.\nPlease re-run the setup wizard — it will enter disaster-recovery merge: everything on this device after the backup point is kept, differences on both sides go through the conflict flow, and nothing is ever silently discarded.";
      this.ctx.gate.markRepoEpochMismatch(msg);
      this.ctx.notify(msg);
      this.ctx.log(
        `disaster recovery: repoEpoch ${savedEpoch} -> ${info.repoEpoch}, localSequence=${this.ctx.store.state.lastSequence}`
      );
      this.onStatus("offline", msg);
      return false;
    }
    this.ctx.gate.markRepoEpochMismatch(null);
    const savedFormat = this.ctx.store.state.bootstrap.formatEpoch;
    if (info.formatEpoch !== void 0 && savedFormat !== void 0 && info.formatEpoch !== savedFormat) {
      if (info.formatEpoch < savedFormat) {
        const msg = "The server's formatEpoch rolled back — sync stopped, waiting for manual confirmation";
        this.ctx.log(`formatEpoch rollback ${savedFormat} -> ${info.formatEpoch}, refusing to adopt`);
        this.ctx.notify("The server's addressing format epoch rolled back — sync stopped; check whether the server was restored from an old backup");
        this.ctx.gate.markIntegrityError(msg);
        this.onStatus("offline", msg);
        return false;
      }
      this.ctx.store.state.bootstrap.formatEpoch = info.formatEpoch;
      this.ctx.store.state.lastSequence = 0;
      await this.ctx.store.save();
      this.ctx.notify("The server has completed path and file name encryption — this device will reconcile once (contents are unaffected)");
      this.ctx.log(`formatEpoch changed ${savedFormat} -> ${info.formatEpoch}, forcing snapshot reconcile`);
    }
    let adopted = false;
    if (!savedEpoch && info.repoEpoch && this.ctx.store.bootstrapReady) {
      this.ctx.store.state.bootstrap.repoEpoch = info.repoEpoch;
      adopted = true;
    }
    if (!saved && info.vaultId && this.ctx.store.bootstrapReady) {
      this.ctx.store.state.bootstrap.remoteVaultId = info.vaultId;
      adopted = true;
    }
    if (info.keyEpoch !== void 0 && info.keyEpoch !== 0) {
      if (!isKeyEpoch(info.keyEpoch)) {
        const msg = `The server returned an invalid keyEpoch (${String(info.keyEpoch)}), sync stopped so that undecryptable content is not written`;
        this.ctx.gate.markIntegrityError(msg);
        this.ctx.notify(msg);
        this.onStatus("offline", msg);
        return false;
      }
      if (this.ctx.store.state.bootstrap.keyEpoch !== info.keyEpoch) {
        this.ctx.store.state.bootstrap.keyEpoch = info.keyEpoch;
        adopted = true;
      }
    }
    if (info.metaState !== void 0 && this.ctx.store.state.bootstrap.metaState !== info.metaState) {
      this.ctx.store.state.bootstrap.metaState = info.metaState;
      adopted = true;
    }
    if (info.formatEpoch !== void 0 && this.ctx.store.state.bootstrap.formatEpoch !== info.formatEpoch) {
      this.ctx.store.state.bootstrap.formatEpoch = info.formatEpoch;
      adopted = true;
    }
    if (info.minimumEnvelopeVersion !== void 0 && this.ctx.store.state.bootstrap.minimumEnvelopeVersion !== info.minimumEnvelopeVersion) {
      this.ctx.store.state.bootstrap.minimumEnvelopeVersion = info.minimumEnvelopeVersion;
      adopted = true;
    }
    if (info.migrationId && info.migrationOwnerDeviceId !== this.ctx.store.state.deviceId) {
      this.ctx.log(`another device is migrating (${info.migrationId}); writes are restricted`);
    }
    if (adopted) await this.ctx.store.save();
    return true;
  }
  /** 根 Token → 设备凭据自动换发（失败不阻塞同步，下次会话重试）。 */
  async ensureDeviceCredential() {
    if (this.credentialChecked || !this.ctx.updateApiToken) return;
    this.credentialChecked = true;
    try {
      const who = await this.ctx.client.whoami();
      if (who.tokenType !== "root") return;
      const cred = await this.ctx.client.createDevice(this.ctx.deviceName());
      await this.ctx.updateApiToken(cred.deviceToken);
      this.ctx.notify("This device has been issued its own sync credential (the root token is no longer stored on the device and this device can be revoked separately on the server)");
      this.ctx.log(`device credential issued: ${cred.deviceId}`);
    } catch (e) {
      this.credentialChecked = false;
      this.ctx.log(`device credential exchange failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  scheduleRetry() {
    const delay = RETRY_DELAYS[Math.min(this.retryIndex, RETRY_DELAYS.length - 1)];
    this.retryIndex++;
    this.ctx.log(`retry in ${delay}s`);
    this.retryTimer = window.setTimeout(() => {
      this.retryTimer = null;
      void this.sync("retry");
    }, delay * 1e3);
  }
  dispose() {
    if (this.retryTimer !== null) {
      window.clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }
};
function describeBindingChange(prev, next) {
  if (prev.serverUrl !== next.serverUrl) return "The Server URL changed";
  if (prev.tokenDigest !== next.tokenDigest) return "The API Token changed";
  if (prev.deviceId !== next.deviceId) return "Device identity changed";
  if (prev.vaultKeyDigest !== next.vaultKeyDigest) return "The end-to-end encryption key document has changed";
  return "Binding information changed";
}

// src/utils/ignore.ts
var IgnoreMatcher = class {
  constructor(syncObsidian, configDir, pluginDir, patternsText) {
    this.syncObsidian = syncObsidian;
    this.configDir = configDir;
    this.pluginDir = pluginDir;
    this.fullPatterns = [];
    this.basenamePatterns = [];
    for (const raw of patternsText.split("\n")) {
      const pattern = raw.trim();
      if (!pattern || pattern.startsWith("#")) continue;
      if (pattern.includes("/")) {
        this.fullPatterns.push(globToRegExp(pattern.replace(/\/+$/, "/**")));
      } else {
        this.basenamePatterns.push(globToRegExp(pattern));
      }
    }
  }
  ignores(path) {
    if (path === this.pluginDir || path.startsWith(this.pluginDir + "/")) return true;
    if (path === `${this.configDir}/workspace.json` || path === `${this.configDir}/workspace-mobile.json`) {
      return true;
    }
    if (!this.syncObsidian && (path === this.configDir || path.startsWith(this.configDir + "/"))) {
      return true;
    }
    for (const re of this.fullPatterns) {
      if (re.test(path)) return true;
    }
    if (this.basenamePatterns.length > 0) {
      const base = path.slice(path.lastIndexOf("/") + 1);
      for (const re of this.basenamePatterns) {
        if (re.test(base)) return true;
      }
    }
    return false;
  }
};
function globToRegExp(glob) {
  let re = "";
  let i = 0;
  while (i < glob.length) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += ".*";
        i += 2;
        if (glob[i] === "/") {
          re += "/?";
          i++;
        }
        continue;
      }
      re += "[^/]*";
    } else if (c === "?") {
      re += "[^/]";
    } else if ("\\^$.|+()[]{}".includes(c)) {
      re += "\\" + c;
    } else {
      re += c;
    }
    i++;
  }
  return new RegExp(`^${re}$`);
}

// src/diagnostics/platform-probe.ts
var import_obsidian17 = require("obsidian");
var PROBE_PREFIX = ".probe";
async function sameFile(app, dir, a, b) {
  const adapter = app.vault.adapter;
  const pa = `${dir}/${a}`;
  const pb = `${dir}/${b}`;
  const marker = new TextEncoder().encode("probe-a").buffer;
  try {
    await adapter.writeBinary(pa, marker);
    const st = await adapter.stat(pb);
    if (!st) return false;
    const read = await adapter.readBinary(pb);
    return new TextDecoder().decode(read) === "probe-a";
  } catch {
    return false;
  } finally {
    for (const p of [pa, pb]) {
      try {
        if (await adapter.stat(p)) await adapter.remove(p);
      } catch {
      }
    }
  }
}
async function canCreate(app, dir, name) {
  const adapter = app.vault.adapter;
  const p = `${dir}/${name}`;
  try {
    await adapter.writeBinary(p, new Uint8Array([1]).buffer);
    const ok = await adapter.stat(p) !== null;
    await adapter.remove(p);
    return ok;
  } catch {
    try {
      if (await adapter.stat(p)) await adapter.remove(p);
    } catch {
    }
    return false;
  }
}
async function runPlatformProbe(app, pluginDir, pluginVersion, committer) {
  const adapter = app.vault.adapter;
  const dir = `${pluginDir}/${PROBE_PREFIX}`;
  if (!await adapter.stat(dir)) await adapter.mkdir(dir);
  const results = [];
  const recordCollision = (name, real, ruleSaysCollide) => {
    const unsafe = real && !ruleSaysCollide;
    results.push({
      name,
      actual: real ? "Yes" : "No",
      expected: ruleSaysCollide ? "Yes" : "No",
      verdict: unsafe ? "unsafe" : "safe",
      ...unsafe ? {
        note: "This device thinks they are the same file but our rules do not — the two files will overwrite each other during sync. **This must be reported to the developer.**"
      } : real === ruleSaysCollide ? {} : { note: "The rules are stricter than this device, so it only blocks once more — no data is lost" }
    });
  };
  const recordCreatable = (name, canCreate2, ruleAccepts) => {
    const broken = ruleAccepts && !canCreate2;
    const limited = canCreate2 && !ruleAccepts;
    results.push({
      name,
      actual: canCreate2 ? "Yes" : "No",
      expected: ruleAccepts ? "Yes" : "No",
      verdict: broken ? "unsafe" : limited ? "limited" : "safe",
      ...broken ? { note: "The rules accept this name but this device cannot create it — the write would fail. **Please report it to the developer.**" } : limited ? {
        note: "This device can create it, but our rules reject it (for Windows compatibility). Such files can still be uploaded, but on a Windows device they are registered as blocked with a warning — no data is lost."
      } : {}
    });
  };
  {
    const actual = await sameFile(app, dir, "Note.md", "note.md");
    const expected = pathsCollide("Note.md", "note.md");
    recordCollision("Note.md and note.md are the same file", actual, expected);
  }
  {
    const nfc = "caf\xE9.md";
    const nfd = "cafe\u0301.md";
    const actual = await sameFile(app, dir, nfc, nfd);
    const expected = pathsCollide(nfc, nfd);
    recordCollision("The NFC and NFD spellings of café.md are the same file", actual, expected);
  }
  for (const [label, name] of [
    ["trailing dot", "trailing."],
    ["trailing space", "trailing "]
  ]) {
    const created = await canCreate(app, dir, `${name}md`);
    const canonical = tryCanonicalizeVaultPath(`${name}md`) !== null;
    recordCreatable(`can create${label} file name`, created, canonical);
  }
  for (const name of ["CON", "AUX", "NUL"]) {
    const created = await canCreate(app, dir, `${name}.md`);
    const canonical = tryCanonicalizeVaultPath(`${name}.md`) !== null;
    recordCreatable(`can create reserved name ${name}.md`, created, canonical);
  }
  {
    const long = "x".repeat(300) + ".md";
    const created = await canCreate(app, dir, long);
    const canonical = tryCanonicalizeVaultPath(long) !== null;
    recordCreatable("can create a 300-character file name", created, canonical);
  }
  let atomicReplace = true;
  if (committer) {
    atomicReplace = await committer.supportsAtomicReplace();
    results.push({
      name: "Supports atomic install (rename into an empty slot with complete content)",
      actual: atomicReplace ? "Yes" : "No",
      expected: "Yes",
      // 不支持不是「不安全」：这正是门槛 11 设计好的退化路径
      verdict: atomicReplace ? "safe" : "limited",
      ...atomicReplace ? {} : {
        note: "This device does not support atomic install: overwriting writes degrade to \"save a copy of the remote version\" and the original file is untouched. Sync still works, but every remote update produces a copy."
      }
    });
  }
  try {
    if (await adapter.stat(dir)) await adapter.rmdir(dir, true);
  } catch {
  }
  return {
    platform: describePlatform(),
    appVersion: app.appId ?? "unknown",
    pluginVersion,
    atomicReplace,
    results,
    hasUnsafe: results.some((r) => r.verdict === "unsafe"),
    hasLimited: results.some((r) => r.verdict === "limited")
  };
}
function describePlatform() {
  const parts = [];
  if (import_obsidian17.Platform.isIosApp) parts.push("iOS");
  else if (import_obsidian17.Platform.isAndroidApp) parts.push("Android");
  else if (import_obsidian17.Platform.isMacOS) parts.push("macOS");
  else if (import_obsidian17.Platform.isWin) parts.push("Windows");
  else if (import_obsidian17.Platform.isLinux) parts.push("Linux");
  else parts.push("unknown");
  parts.push(import_obsidian17.Platform.isMobileApp ? "mobile" : "desktop");
  return parts.join(" / ");
}
function renderProbeReport(rep) {
  const lines = [
    "# LiteSync platform compatibility probe",
    "",
    `- Platform: **${rep.platform}**`,
    `- Plugin version: ${rep.pluginVersion}`,
    `- Supports atomic install: **${rep.atomicReplace ? "Yes" : "No"}**`,
    "",
    rep.hasUnsafe ? "> ⚠️ **Found cases where the rules are looser than this device's actual behavior** (the table below marks them \"unsafe\"). This may cause two files to overwrite each other during sync — **please send this report to the developer.**" : rep.hasLimited ? "> No unsafe items found. There are some \"restricted\" items: such files will not sync on some devices, but no data is lost." : "> No problems found: the rules match this device and reality, or are stricter than reality.",
    "",
    "| Case | Measured here | Rule predicts | Verdict |",
    "| --- | --- | --- | --- |"
  ];
  const label = {
    safe: "✓ Safe",
    limited: "△ Restricted",
    unsafe: "**✗ Unsafe**"
  };
  for (const r of rep.results) {
    lines.push(`| ${r.name} | ${r.actual} | ${r.expected} | ${label[r.verdict]} |`);
  }
  const notes = rep.results.filter((r) => r.note);
  if (notes.length > 0) {
    lines.push("", "## Notes", "");
    for (const r of notes) lines.push(`- **${r.name}**\uFF1A${r.note}`);
  }
  lines.push(
    "",
    "### What the verdicts mean",
    "",
    "- **Safe**: the rules match this device, or are stricter (stricter only blocks once more).",
    "- **Restricted**: this device accepts a name that the rules reject. On a device that rejects it, such a file will be",
    "  is registered as blocked with a warning — **no data is lost**.",
    "- **Unsafe**: the rules are looser than reality — this device treats two names as the same file but the rules do not,",
    "  may cause silent overwrites. Only this class needs immediate action.",
    "",
    "---",
    "",
    "This report only proves the behavior of **this one device**. Two Android machines, for example,",
    "The filesystem may be completely different (internal storage / SD card / mounted network drive), so conclusions do not transfer between them."
  );
  return lines.join("\n");
}

// src/main.ts
function vaultKeyMaterialChanged(before, after) {
  if (before === null && after === null) return false;
  if (before === null || after === null) return true;
  return before.wrappedKey !== after.wrappedKey || before.salt !== after.salt;
}
var DEBOUNCE_MS = 3e3;
var FOREGROUND_DEBOUNCE_MS = 2500;
var MOBILE_MIN_INTERVAL_SECONDS = 60;
var PrivateSyncPlugin = class extends import_obsidian18.Plugin {
  constructor() {
    super(...arguments);
    this.settings = { ...DEFAULT_SETTINGS };
    this.store = null;
    this.queue = new PendingQueue();
    /** 本设备 checkpoint 签名私钥（base64 PKCS#8，v0.15 §9.2）；未生成时为空串 */
    this.signingKeyPkcs8 = "";
    /** 待登记到服务器的签名公钥（登记成功后清空） */
    this.pendingSigningPublicKey = "";
    this.client = null;
    this.manager = null;
    this.ctx = null;
    this.ignoreMatcher = null;
    this.statusEl = null;
    this.debounceTimer = null;
    this.foregroundTimer = null;
    this.intervalId = null;
    this.lastStatus = "idle";
    this.keyring = new Keyring();
    /** 同步安全 Gate（v0.12.1）：手动命令与自动同步共用的许可判断 */
    this.gate = new SyncGate();
    /** 接入向导单例标志（v8）：避免多个同步入口重复弹窗 */
    this.wizardOpen = false;
    /** API Token 运行时值（真实存储在 Obsidian SecretStorage） */
    this.apiTokenValue = "";
    /** 设置页实例：弹窗操作（解锁/启用 E2EE、重命名仓库）完成后就地刷新它 */
    this.settingTab = null;
    /** v3.1 迁移：旧版本明文保存的 E2EE 密码，仅在首次启动时用一次后即抹除 */
    this.legacyE2eePassword = "";
  }
  async onload() {
    await this.loadSettings();
    this.statusEl = this.addStatusBarItem();
    this.updateStatus("idle");
    this.settingTab = new SyncSettingTab(this.app, this);
    this.addSettingTab(this.settingTab);
    this.addCommand({
      id: "sync-now",
      name: "Sync Now (Sync now)",
      callback: () => void this.syncNow()
    });
    this.addCommand({
      id: "file-history",
      name: "File Version History (File history)",
      checkCallback: (checking) => {
        const file = this.app.workspace.getActiveFile();
        if (!file || !this.ctx) return false;
        if (!checking) new HistoryModal(this.ctx, file.path).open();
        return true;
      }
    });
    this.addCommand({
      id: "resolve-conflicts",
      name: "Resolve Sync Conflicts (Resolve conflicts)",
      callback: () => {
        if (this.ctx) new ConflictListModal(this.ctx).open();
      }
    });
    this.addCommand({
      id: "unlock-e2ee",
      name: "Unlock End-to-End Encryption (Unlock E2EE)",
      callback: () => this.openUnlockModal()
    });
    this.addCommand({
      id: "manage-shares",
      name: "Manage Shares (Manage shares)",
      callback: () => {
        if (this.ctx) new ShareManageModal(this.ctx, this.settings.serverUrl).open();
      }
    });
    this.addCommand({
      id: "list-devices",
      name: "Device List (List devices)",
      callback: () => {
        if (this.client) new DeviceListModal(this.app, this.client).open();
      }
    });
    this.addCommand({
      id: "upgrade-envelopes",
      name: "Upgrade Encryption Envelopes LSE1 → LSE3 (Upgrade encryption envelopes)",
      callback: () => void this.runEnvelopeUpgrade()
    });
    this.addCommand({
      id: "encrypt-metadata",
      name: "Encrypt Paths & File Names (Encrypt file paths and names)",
      callback: () => this.confirmMetaEncryption()
    });
    this.addCommand({
      id: "platform-probe",
      name: "Platform Compatibility Probe (Platform compatibility probe)",
      callback: () => void this.runPlatformProbe()
    });
    this.addRibbonIcon("refresh-cw", "LiteSync: Sync Now", () => void this.syncNow());
    this.registerEvent(
      this.app.workspace.on("file-menu", (menu, file) => {
        if (!(file instanceof import_obsidian18.TFile) || !this.ctx) return;
        menu.addItem(
          (item) => item.setTitle("LiteSync: Version History").setIcon("history").onClick(() => new HistoryModal(this.ctx, file.path).open())
        );
        menu.addItem(
          (item) => item.setTitle("LiteSync: Share This File…").setIcon("share-2").onClick(() => new ShareModal(this.ctx, this.settings.serverUrl, file.path).open())
        );
      })
    );
    registerImportHandler(this);
    this.app.workspace.onLayoutReady(() => void this.initialize());
  }
  onunload() {
    this.manager?.dispose();
    if (this.debounceTimer !== null) window.clearTimeout(this.debounceTimer);
    if (this.foregroundTimer !== null) window.clearTimeout(this.foregroundTimer);
    if (this.intervalId !== null) window.clearInterval(this.intervalId);
    void this.store?.save();
  }
  async initialize() {
    const pluginDir = this.manifest.dir ?? `${this.app.vault.configDir}/plugins/${this.manifest.id}`;
    this.store = new StateStore(this.app.vault.adapter, `${pluginDir}/state.json`);
    await this.store.load();
    if (this.store.corrupted) {
      new import_obsidian18.Notice(
        "LiteSync: the local sync state file is corrupt (neither state-a/state-b.json can be read) and sync has stopped.\nDo not delete these two files; restore them from a backup or contact support.",
        0
      );
    }
    this.queue.onChange = (entries) => {
      if (this.store) this.store.state.pendingOps = entries;
    };
    this.queue.persist = async () => {
      await this.store?.save();
    };
    this.queue.restore(this.store.state.pendingOps);
    await this.loadOrMigrateApiToken();
    this.keyring.setDoc(this.store.state.e2ee);
    if (this.keyring.needsUnlock) {
      if (this.settings.trustDevice && this.settings.deviceKeyB64 && this.keyring.doc) {
        const raw = await loadTrustedVmk(this.app, this.settings.deviceKeyB64, this.keyring.doc);
        if (raw) {
          await this.keyring.unlockWithRaw(raw);
          raw.fill(0);
        }
      }
      if (this.keyring.needsUnlock && this.legacyE2eePassword) {
        if (await this.keyring.unlock(this.legacyE2eePassword)) {
          this.settings.trustDevice = true;
          await this.persistTrust();
          new import_obsidian18.Notice("The old \"remember password\" was migrated to \"trust this device\", and the plaintext password was removed from disk");
        }
      }
      this.legacyE2eePassword = "";
    }
    this.rebuildIgnoreMatcher();
    this.client = new ApiClient(() => ({
      vaultChoice: this.settings.vaultChoice,
      serverUrl: this.settings.serverUrl,
      apiToken: this.getApiToken(),
      deviceId: this.store?.state.deviceId ?? "",
      // 逐请求携带（协议 v6 / ADR-006）：与服务器不符时服务器直接拒绝写入，
      // 而不是让我们用过时的寻址方式把数据写坏
      formatEpoch: this.store?.state.bootstrap.formatEpoch ?? 0,
      repoEpoch: this.store?.state.bootstrap.repoEpoch ?? "",
      keyEpoch: this.store?.state.bootstrap.keyEpoch ?? 0
    }));
    if (import_obsidian18.Platform.isMobileApp && this.settings.syncObsidian) {
      new import_obsidian18.Notice("The Obsidian config directory is not synced on mobile (desktop and mobile UI configs are incompatible); ordinary notes and attachments are unaffected");
    }
    try {
      const signing = await loadOrCreateSigningKey(this.app);
      this.signingKeyPkcs8 = signing.privateKeyPkcs8B64;
      this.pendingSigningPublicKey = signing.publicKeyB64;
    } catch (e) {
      console.debug("[litesync] signing key unavailable", e);
    }
    this.committer = new LocalCommitter(this.app, pluginDir, (m) => {
      if (this.settings.debug) console.debug(`[litesync] ${m}`);
    });
    void this.committer.sweep(Date.now());
    const ctx = {
      app: this.app,
      client: this.client,
      store: this.store,
      queue: this.queue,
      committer: this.committer,
      gate: this.gate,
      syncObsidian: () => this.effectiveSyncObsidian(),
      padsSize: (path) => this.padsSize(path),
      reportedMtime: (ms) => this.reportedMtime(ms),
      // 时间混淆（§11.2 / 验收 T4.5）：定时/前台/启动/重试的轮次只拉不推——
      // 上传只在窗口发车点（sync("change")）或用户显式动作时发生
      deferPush: (reason) => this.settings.obfuscateTiming && ["interval", "foreground", "startup", "retry"].includes(reason),
      onPushDeferred: () => this.scheduleDebounced(),
      ignores: (path) => this.ignoreMatcher?.ignores(path) ?? false,
      deviceName: () => this.settings.deviceName || `device-${(this.store?.state.deviceId ?? "").slice(0, 8)}`,
      pluginDir: () => pluginDir,
      signingKeyPkcs8: () => this.signingKeyPkcs8,
      signingPublicKey: () => this.pendingSigningPublicKey,
      onSigningKeyRegistered: () => void (this.pendingSigningPublicKey = ""),
      log: (msg) => {
        if (this.settings.debug) console.debug(`[litesync] ${msg}`);
      },
      notify: (msg, durationMs) => new import_obsidian18.Notice(msg, durationMs ?? 8e3),
      onConflictsChanged: () => this.updateStatus(this.lastStatus),
      e2ee: this.keyring,
      credentials: () => ({
        serverUrl: this.settings.serverUrl,
        apiToken: this.getApiToken(),
        vaultChoice: this.settings.vaultChoice
      }),
      refreshE2ee: async () => {
        const before = this.keyring.doc;
        const doc = await this.client.getVaultKey();
        this.keyring.setDoc(doc);
        if (this.store) this.store.state.e2ee = doc;
        if (vaultKeyMaterialChanged(before, doc)) {
          this.manager?.invalidateBinding("The end-to-end encryption key document has changed");
        }
      },
      // v9.2：根 Token → 设备凭据自动换发（SyncManager 协议检查时调用）
      updateApiToken: async (token) => {
        await this.setApiToken(token);
      }
    };
    this.ctx = ctx;
    this.manager = new SyncManager(ctx);
    this.manager.onStatus = (status, detail) => this.updateStatus(status, detail);
    this.registerVaultEvents();
    this.registerForegroundSync();
    this.applySettings();
    if (this.isConfigured()) {
      if (!this.store.bootstrapReady) {
        this.openBootstrapWizard();
      } else if (this.settings.autoSync) {
        void this.manager.sync("startup");
      }
    }
  }
  // ---------- Bootstrap（首次接入向导，v8） ----------
  get bootstrapReady() {
    return this.store?.bootstrapReady ?? false;
  }
  openBootstrapWizard() {
    if (this.wizardOpen || !this.ctx) return;
    if (!this.isConfigured()) {
      new import_obsidian18.Notice("Fill in the Server URL and API Token in settings first");
      return;
    }
    this.wizardOpen = true;
    new BootstrapWizardModal(this.app, this.ctx, {
      setVaultChoice: (id) => this.setVaultChoice(id),
      vaultChoice: () => this.settings.vaultChoice,
      trustDevice: () => this.settings.trustDevice,
      setTrustDevice: (v) => this.setTrustDevice(v),
      setApiToken: (t) => this.setApiToken(t),
      openUnlock: (onUnlocked) => this.openUnlockModal(onUnlocked),
      onDone: () => {
        this.updateStatus("idle");
        void this.manager?.sync("bootstrap");
      },
      onClosed: () => {
        this.wizardOpen = false;
      }
    }).open();
  }
  /** 重新运行接入向导（设置页入口；会把本设备重置为待接入）。 */
  rerunBootstrapWizard() {
    this.store?.resetBootstrap();
    this.invalidateBinding("Re-run Setup Wizard");
    void this.store?.save();
    this.openBootstrapWizard();
  }
  /** 重置为待接入（导入新配对配置后调用）。 */
  resetBootstrapState() {
    this.store?.resetBootstrap();
    this.invalidateBinding("A new server configuration was imported");
    void this.store?.save();
  }
  /** 「添加新设备」：生成一次性加密配对包并展示二维码/链接。 */
  openAddDeviceModal() {
    if (!this.client || !this.isConfigured()) {
      new import_obsidian18.Notice("Fill in the Server URL and API Token in settings first");
      return;
    }
    new AddDeviceModal(this.app, this.client, this.settings).open();
  }
  /** 「导入配对链接」：手动粘贴其他设备生成的配对链接。 */
  openPasteLinkModal() {
    new PasteLinkModal(this.app, this).open();
  }
  /** 元数据迁移是否停在 migrating（设置页据此显示「放弃迁移」入口）。 */
  metaMigrationActive() {
    return this.store?.state.bootstrap.metaState === "migrating";
  }
  /** 放弃元数据迁移：退回 plain（无破坏性操作）。 */
  async abortMetaMigration() {
    if (!this.ctx) return;
    try {
      const state = await abortMetadataMigration(this.ctx);
      new import_obsidian18.Notice(`Aborted the path encryption migration; vault metadata state: ${state}`);
    } catch (e) {
      new import_obsidian18.Notice(`Abort migration failed: ${e instanceof Error ? e.message : String(e)}`, 1e4);
    }
  }
  /**
   * 「加密路径与文件名」（v9.3 三期）：确认后执行元数据加密迁移。
   *
   * v0.12.1（LS-121-C01）：默认构建里这条命令处于关闭状态，必须在设置页
   * 显式打开「实验功能」；即便打开，不可逆的明文抹除仍需另一个开发者开关。
   */
  confirmMetaEncryption() {
    if (!this.ctx) return;
    if (!this.settings.experimentalMetaEncryption) {
      new import_obsidian18.Notice(
        "\"Encrypt Paths & File Names\" is still experimental in v0.12.x and is off by default.\nTo try it on a test vault, turn it on in Settings → Experimental (never on your only real vault)",
        12e3
      );
      return;
    }
    if (!this.keyring.enabled) {
      new import_obsidian18.Notice("Please enable end-to-end encryption first");
      return;
    }
    if (!this.keyring.unlocked) {
      new import_obsidian18.Notice("Please unlock end-to-end encryption first (Unlock E2EE)");
      return;
    }
    if (this.store?.state.bootstrap.metaState === "encrypted") {
      new import_obsidian18.Notice("Paths and file names are already encrypted");
      return;
    }
    new ConfirmMetaEncryptionModal(this.app, this.settings.allowIrreversibleMetaErase, () => {
      void this.runMetaEncryption();
    }).open();
  }
  async runMetaEncryption() {
    if (!this.ctx || !this.manager) return;
    const progress = new import_obsidian18.Notice("Encrypting paths and file names…", 0);
    try {
      const r = await encryptMetadata(this.ctx, {
        onProgress: (p) => {
          progress.setMessage(`Encrypting metadata ${p.done}/${p.total}\uFF1A${p.current}`);
        },
        fullSync: () => this.manager.fullSync("pre-meta-migration"),
        allowIrreversibleComplete: this.settings.allowIrreversibleMetaErase
      });
      progress.hide();
      new import_obsidian18.Notice(
        r.erased ? `Metadata encryption complete: ${r.migrated} file paths have been pseudonymised and the plaintext paths on the server erased.\nOther devices will reconcile automatically on the next sync (needs 0.12+ and E2EE unlocked)` : `Pseudonymised ${r.migrated} file paths (vault state: ${r.metaState}).\nv0.12.1 does not perform the irreversible plaintext erasure: the server still keeps the old plaintext path records (tombstones/history); wait for the v0.13.0 privacy tombstone ledger for the real erasure.\nYou can always "Abort Path Encryption Migration" in settings to return to plain.`,
        15e3
      );
    } catch (e) {
      progress.hide();
      new import_obsidian18.Notice(`Metadata encryption failed (re-runnable to resume): ${e instanceof Error ? e.message : String(e)}`, 1e4);
    }
  }
  /** 「升级加密信封」（v9.2；v9.3 起目标为 LSE3）：把旧信封密文重新加密。 */
  async runEnvelopeUpgrade() {
    if (!this.ctx) return;
    if (!this.keyring.enabled) {
      new import_obsidian18.Notice("End-to-end encryption is not enabled — no envelope upgrade needed");
      return;
    }
    const progress = new import_obsidian18.Notice("Upgrading encryption envelopes…", 0);
    try {
      await this.manager?.fullSync("pre-envelope-upgrade");
      const r = await upgradeEnvelopes(this.ctx, (p) => {
        progress.setMessage(`Upgrading encryption envelopes ${p.done}/${p.total}\uFF1A${p.current}`);
      });
      progress.hide();
      new import_obsidian18.Notice(
        r.upgraded > 0 ? `Encryption envelope upgrade complete: ${r.upgraded} files upgraded to LSE3${r.skipped ? `\uFF0C${r.skipped} skipped (re-runnable to resume)` : ""}` : "All files are already LSE3 envelopes — no upgrade needed"
      );
    } catch (e) {
      progress.hide();
      new import_obsidian18.Notice(
        e instanceof SyncBlockedError ? e.message : `Envelope upgrade failed: ${e instanceof Error ? e.message : String(e)}`,
        1e4
      );
    }
  }
  /**
   * App 回到前台时同步（v6 移动端策略）：iOS 会暂停后台 App 的定时器，
   * hidden → visible 是移动端最可靠的补同步时机；带防抖避免快速切换风暴。
   */
  registerForegroundSync() {
    this.registerDomEvent(document, "visibilitychange", () => {
      if (document.visibilityState !== "visible") return;
      if (!this.settings.autoSync || !this.isConfigured() || !this.bootstrapReady) return;
      if (this.foregroundTimer !== null) window.clearTimeout(this.foregroundTimer);
      this.foregroundTimer = window.setTimeout(() => {
        this.foregroundTimer = null;
        void this.manager?.sync("foreground");
      }, FOREGROUND_DEBOUNCE_MS);
    });
  }
  /** 移动端第一阶段不同步 .obsidian，无论设置如何（v6 计划 Part 27）。 */
  effectiveSyncObsidian() {
    return this.settings.syncObsidian && !import_obsidian18.Platform.isMobileApp;
  }
  /**
   * 这个路径要不要做大小填充（v0.17 / 计划书 §11.1）。
   *
   * 前缀匹配走规范化后的 vault 路径：设置里写 "Private/" 就只覆盖那一棵子树，
   * 不会因为大小写或反斜杠差异漏掉——那种漏掉最糟，
   * 用户以为开了，实际没开，而且没有任何提示。
   */
  padsSize(path) {
    if (!this.settings.padObjectSizes) return false;
    const prefixes = this.settings.padPathPrefixes.split("\n").map((p) => p.trim().replace(/\\/g, "/").replace(/^\/+/, "").toLowerCase()).filter((p) => p.length > 0);
    if (prefixes.length === 0) return true;
    const target = path.replace(/\\/g, "/").toLowerCase();
    return prefixes.some((p) => target === p || target.startsWith(p.endsWith("/") ? p : p + "/"));
  }
  /**
   * 平台兼容性自检（计划书 §8.4 实机矩阵、§8.8 门槛 3 与 11）。
   *
   * §8.4 要求在各平台跑一遍路径用例矩阵。桌面端可以用 `npm test`
   *（tests/realfs.test.ts 直接操作真实文件系统），**但移动端跑不了 Node**。
   * 于是移动端那一格长期只能靠推理填——而推理错的方向恰好最危险：
   * 我们以为两个名字不同，文件系统认为相同，后写的静默覆盖先写的。
   *
   * 这个命令跑在插件内部、用 Obsidian 自己的 adapter，因此在移动端也能跑。
   * 结果写成一篇笔记，用户可以直接读、直接贴出来。
   */
  async runPlatformProbe() {
    const pluginDir = this.manifest.dir ?? `${this.app.vault.configDir}/plugins/${this.manifest.id}`;
    new import_obsidian18.Notice("LiteSync: probing platform compatibility…");
    try {
      const rep = await runPlatformProbe(this.app, pluginDir, this.manifest.version, this.committer);
      const md = renderProbeReport(rep);
      const stamp = (/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace(/[:T]/g, "-");
      const path = `LiteSync platform probe ${stamp}.md`;
      await this.app.vault.create(path, md);
      const unsafe = rep.results.filter((r) => r.verdict === "unsafe").length;
      const limited = rep.results.filter((r) => r.verdict === "limited").length;
      new import_obsidian18.Notice(
        unsafe > 0 ? `Probe complete: found ${unsafe} unsafe, please send "${path}" and report it to the developer` : limited > 0 ? `Probe complete: no unsafe items, ${limited} restricted, written to "${path}\u300D` : `Probe complete: no problems found, written to "${path}\u300D`
      );
    } catch (e) {
      new import_obsidian18.Notice(`Platform probe failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  /** 设置变化后重建忽略规则和定时器。 */
  applySettings() {
    this.rebuildIgnoreMatcher();
    if (this.intervalId !== null) {
      window.clearInterval(this.intervalId);
      this.intervalId = null;
    }
    if (this.settings.autoSync && this.settings.syncIntervalSeconds > 0) {
      const seconds = import_obsidian18.Platform.isMobileApp ? Math.max(MOBILE_MIN_INTERVAL_SECONDS, this.settings.syncIntervalSeconds) : this.settings.syncIntervalSeconds;
      this.intervalId = window.setInterval(() => {
        if (this.isConfigured() && this.bootstrapReady) void this.manager?.sync("interval");
      }, seconds * 1e3);
      this.registerInterval(this.intervalId);
    }
  }
  async syncNow() {
    if (!this.isConfigured()) {
      new import_obsidian18.Notice("Fill in the Server URL and API Token in settings first");
      return;
    }
    if (!this.manager) {
      new import_obsidian18.Notice("The plugin has not finished initializing — please wait");
      return;
    }
    if (!this.bootstrapReady) {
      this.openBootstrapWizard();
      return;
    }
    this.manager.resetRetry();
    await this.manager.sync("manual");
    const err = this.manager.lastSyncError;
    if (err) {
      new import_obsidian18.Notice(`Sync failed: ${err.message}`, 8e3);
      return;
    }
    const block = this.ctx ? syncGateBlock(this.ctx) : null;
    if (block) {
      new import_obsidian18.Notice(`Sync not run: ${block.message}`, 8e3);
      return;
    }
    const c = this.manager.lastSyncCounters;
    if (!c) {
      new import_obsidian18.Notice("Sync not run: check the status bar or try again later");
      return;
    }
    const detail = c.pulled > 0 || c.pushed > 0 ? `downloaded ${c.pulled}, uploaded ${c.pushed}` : "Already up to date";
    new import_obsidian18.Notice(
      c.conflicts > 0 ? `Sync complete: ${detail}\uFF0C${c.conflicts} conflicts pending (Command palette → Resolve Sync Conflicts)` : `Sync complete ✓ ${detail}`
    );
  }
  /** 返回给设置页展示的消息；null 表示已改为弹出「首次配置三选项」对话框。 */
  async testConnection() {
    if (!this.client) return "The plugin has not finished initializing — please wait";
    if (!this.isConfigured()) return "Fill in the Server URL and API Token first";
    try {
      const info = await this.client.info();
      const perr = protocolError(info);
      if (perr) return perr;
      if ((info.latestSequence ?? 0) === 0 && (info.encryptionState ?? "plaintext") === "plaintext" && !this.bootstrapReady && this.ctx !== null && this.manager !== null) {
        if (await this.hasMultipleVaults()) {
          this.openBootstrapWizard();
          return null;
        }
        new FirstSyncModal(this.app, {
          withE2ee: () => this.openFirstSyncE2eeModal()
        }).open();
        return null;
      }
      if (this.manager && this.gate.sessionBlock()?.reason === "credential-rejected") {
        this.manager.resetRetry();
        void this.manager.sync("manual");
        return `Connected: server version ${info.version}, resuming sync…`;
      }
      return `Connected: server version ${info.version}\uFF0ClatestSequence=${info.latestSequence}`;
    } catch (e) {
      return `Connection failed: ${e instanceof Error ? e.message : String(e)}`;
    }
  }
  /** local-init 接入并触发首轮同步（远端已非空则转交向导）；由 E2EE 启用回调复用。 */
  async firstSyncNow() {
    const pre = await preflight(this.ctx);
    if (pre.remoteFiles.length > 0) {
      new import_obsidian18.Notice("The remote vault already has content — switching to the setup wizard");
      this.openBootstrapWizard();
      return;
    }
    await bootstrapLocalInit(this.ctx, pre);
    this.updateStatus("idle");
    new import_obsidian18.Notice("Initialized, starting the first sync");
    void this.manager.sync("bootstrap");
  }
  /** 首次配置「设置 E2EE 并立即同步」：空仓启用（无迁移）→ local-init → 首轮同步即密文。 */
  openFirstSyncE2eeModal() {
    new EnableE2eeModal(
      this.app,
      this.settings.trustDevice,
      async (password, trustDevice) => {
        await enableE2eeOnEmptyRemote(this.ctx, password);
        await this.setTrustDevice(trustDevice);
        await this.firstSyncNow();
        this.refreshSettingsTab();
        return 0;
      },
      {
        note: "The remote vault is still empty: setting the password takes effect immediately, and the first upload after that is ciphertext — there is no migration step, and plaintext never passes through the server.",
        success: () => "End-to-end encryption enabled, running the first sync (all content uploaded as ciphertext) ✓"
      }
    ).open();
  }
  /**
   * 让打开着的设置页立刻反映刚完成的操作（解锁/启用 E2EE、重命名仓库）。
   * 弹窗是异步交互——设置页按钮点击时的 update() 发生在用户输入之前，
   * 真正的状态变化要在**成功回调**里主动刷新，否则页面停留在旧状态
   * 直到用户离开再进来（0.19.x 实测反馈）。
   */
  refreshSettingsTab() {
    this.settingTab?.refresh();
  }
  /** 名下仓库列表（设置页「当前仓库」展示用；client 为 private，经此公开）。 */
  async listRemoteVaults() {
    if (!this.client) throw new Error("The plugin has not finished initializing");
    return this.client.listVaults();
  }
  /** 重命名仓库（设置页入口；用户级 Token 专属，设备凭据会被服务端拒绝）。 */
  async renameRemoteVault(id, name) {
    if (!this.client) throw new Error("The plugin has not finished initializing");
    await this.client.renameVault(id, name);
  }
  /** 名下是否有多个仓库（v0.19）；旧服务器/查询失败按单仓库处理。 */
  async hasMultipleVaults() {
    try {
      return (await this.client?.listVaults() ?? []).length > 1;
    } catch {
      return false;
    }
  }
  isConfigured() {
    return this.settings.serverUrl !== "" && this.getApiToken() !== "";
  }
  // ---------- API Token（SecretStorage required） ----------
  getApiToken() {
    return this.apiTokenValue;
  }
  async setApiToken(value) {
    const changed = this.apiTokenValue !== value;
    this.apiTokenValue = value;
    this.app.secretStorage.setSecret(API_TOKEN_SECRET_ID, value);
    if (changed) this.invalidateBinding("The API Token changed");
    if (this.settings.apiToken !== "") {
      this.settings.apiToken = "";
      await this.saveSettings();
    }
  }
  /**
   * 立即作废绑定（v0.12.1 / LS-121-C02）。
   *
   * server URL、Token、设备身份、vault key 文档任一变化时调用：会话缓存清零、
   * 状态切 unbound，上传/删除/MOVE/历史恢复/分享在重新完成权威校验前全部被拒。
   */
  /**
   * 设置目标仓库（v0.19 多仓库）。只由接入向导调用——切换仓库 = 重新接入，
   * 账本作废由 vaultId 变化的防线兜底，这里立即作废绑定触发重新校验。
   */
  async setVaultChoice(vaultId) {
    if (this.settings.vaultChoice === vaultId) return;
    this.settings.vaultChoice = vaultId;
    await this.saveSettings();
    this.invalidateBinding("Target vault switched");
  }
  invalidateBinding(reason) {
    this.gate.markUnbound(reason);
    this.manager?.invalidateBinding(reason);
    this.store?.clearBinding();
    this.updateStatus("idle", `${reason}— you must re-validate against the server before syncing can continue`);
  }
  /** 启动时读取 Token；data.json 中的旧版明文值迁移进 SecretStorage 并抹除。 */
  async loadOrMigrateApiToken() {
    const stored = this.app.secretStorage.getSecret(API_TOKEN_SECRET_ID);
    if (stored) {
      this.apiTokenValue = stored;
      if (this.settings.apiToken !== "") {
        this.settings.apiToken = "";
        await this.saveSettings();
      }
    } else if (this.settings.apiToken) {
      this.app.secretStorage.setSecret(API_TOKEN_SECRET_ID, this.settings.apiToken);
      this.apiTokenValue = this.settings.apiToken;
      this.settings.apiToken = "";
      await this.saveSettings();
      new import_obsidian18.Notice("The API Token was migrated to Obsidian SecretStorage");
    }
  }
  rebuildIgnoreMatcher() {
    const configDir = this.app.vault.configDir;
    const pluginDir = this.manifest.dir ?? `${configDir}/plugins/${this.manifest.id}`;
    this.ignoreMatcher = new IgnoreMatcher(
      this.effectiveSyncObsidian(),
      configDir,
      pluginDir,
      this.settings.ignorePatterns
    );
  }
  registerVaultEvents() {
    const enqueue = (p) => {
      void p.catch((e) => {
        new import_obsidian18.Notice(`LiteSync: could not record the pending sync change (${e instanceof Error ? e.message : String(e)}\uFF09`, 8e3);
      });
    };
    const track = (file, action) => {
      if (this.manager?.applyingRemote) return;
      if (this.ignoreMatcher?.ignores(file.path)) return;
      if (file instanceof import_obsidian18.TFile) {
        enqueue(this.queue.add(file.path, action));
        this.scheduleDebounced();
      }
    };
    this.registerEvent(this.app.vault.on("create", (f) => track(f, "upsert")));
    this.registerEvent(this.app.vault.on("modify", (f) => track(f, "upsert")));
    this.registerEvent(
      this.app.vault.on("delete", (f) => {
        if (this.manager?.applyingRemote) return;
        if (f instanceof import_obsidian18.TFolder) {
          for (const path of this.store?.paths() ?? []) {
            if (path.startsWith(f.path + "/")) enqueue(this.queue.add(path, "delete"));
          }
          this.scheduleDebounced();
          return;
        }
        track(f, "delete");
      })
    );
    this.registerEvent(
      this.app.vault.on("rename", (f, oldPath) => {
        if (this.manager?.applyingRemote) return;
        const canMove = (from) => {
          const t = this.store?.get(from);
          if (!t) return false;
          return !this.keyring.enabled || t.generation !== void 0 && !!t.fileId;
        };
        if (f instanceof import_obsidian18.TFolder) {
          for (const path of this.store?.paths() ?? []) {
            if (!path.startsWith(oldPath + "/")) continue;
            const newPath = f.path + "/" + path.slice(oldPath.length + 1);
            if (!this.ignoreMatcher?.ignores(newPath) && canMove(path)) {
              enqueue(this.queue.addMove(newPath, path));
            } else {
              enqueue(this.queue.add(path, "delete"));
            }
          }
          for (const file of this.app.vault.getFiles()) {
            if (!file.path.startsWith(f.path + "/") || this.ignoreMatcher?.ignores(file.path)) continue;
            if (this.queue.getOp(file.path)?.action === "move") continue;
            enqueue(this.queue.add(file.path, "upsert"));
          }
        } else {
          const ignoredOld = this.ignoreMatcher?.ignores(oldPath) ?? false;
          const ignoredNew = this.ignoreMatcher?.ignores(f.path) ?? false;
          if (!ignoredOld && !ignoredNew && canMove(oldPath)) {
            enqueue(this.queue.addMove(f.path, oldPath));
          } else {
            if (!ignoredOld) enqueue(this.queue.add(oldPath, "delete"));
            if (!ignoredNew) enqueue(this.queue.add(f.path, "upsert"));
          }
        }
        this.scheduleDebounced();
      })
    );
  }
  scheduleDebounced() {
    if (!this.settings.autoSync || !this.isConfigured()) return;
    if (this.settings.obfuscateTiming) {
      if (this.debounceTimer !== null) return;
      const delay = nextFlushDelay(Date.now(), this.settings.timingBatchSeconds);
      this.debounceTimer = window.setTimeout(() => {
        this.debounceTimer = null;
        void this.manager?.sync("change");
      }, delay);
      return;
    }
    if (this.debounceTimer !== null) window.clearTimeout(this.debounceTimer);
    this.debounceTimer = window.setTimeout(() => {
      this.debounceTimer = null;
      void this.manager?.sync("change");
    }, DEBOUNCE_MS);
  }
  /**
   * 上报给服务器的 mtime（§11.2）。
   *
   * 文件修改时间是**永久存储**的精确时间戳，比请求时间更值得担心——
   * 请求日志会轮转，数据库不会。本地状态里仍然保存真实 mtime，
   * 量化只发生在出网的那一刻。
   */
  reportedMtime(mtimeMs) {
    if (!this.settings.obfuscateTiming) return mtimeMs;
    return quantizeMtime(mtimeMs, this.settings.mtimeGranularitySeconds);
  }
  updateStatus(status, detail) {
    if (!this.statusEl) return;
    this.lastStatus = status;
    const texts = {
      idle: "LiteSync",
      syncing: "\u21BB Syncing",
      synced: "\u2713 Synced",
      conflict: "! Conflict",
      offline: "\xD7 Offline",
      locked: "\u{1F512} Locked"
    };
    let text = texts[status];
    const pending = this.store?.conflictPaths().length ?? 0;
    if (pending > 0 && status !== "syncing" && status !== "locked") {
      text = `! ${pending} Conflict${pending > 1 ? "s" : ""}`;
    }
    this.statusEl.setText(text);
    this.statusEl.setAttribute("aria-label", detail ?? text);
    const clickable = pending > 0 || status === "locked";
    this.statusEl.toggleClass("litesync-status-clickable", clickable);
    this.statusEl.onclick = !clickable ? null : status === "locked" ? () => this.openUnlockModal() : this.ctx ? () => new ConflictListModal(this.ctx).open() : null;
  }
  // ---------- E2EE ----------
  /** 设置页的 E2EE 状态与按钮文案。 */
  e2eeStatusText() {
    if (!this.keyring.enabled) {
      return { desc: "Not enabled: the server stores plaintext (only the HTTPS transport is encrypted)", action: "Enable End-to-End Encryption…" };
    }
    if (this.keyring.needsUnlock) {
      return { desc: "Enabled · 🔒 Locked (sync is paused)", action: "Unlock…" };
    }
    return { desc: "Enabled · 🔓 Unlocked", action: "Lock This Device" };
  }
  async e2eeAction() {
    if (!this.keyring.enabled) {
      this.openEnableModal();
      return;
    }
    if (this.keyring.needsUnlock) {
      this.openUnlockModal();
      return;
    }
    this.keyring.lock();
    this.updateStatus("locked");
    new import_obsidian18.Notice("Locked, sync on this device is paused");
  }
  /**
   * 打开 E2EE 解锁弹窗。onUnlocked：接入向导传入——解锁成功后原地继续
   * 向导流程（弹窗叠加、向导不关），代替默认的「重开向导」（那会让用户
   * 把选仓库和接入方式各走两遍）。
   */
  openUnlockModal(onUnlocked) {
    new UnlockModal(this.app, this.settings.trustDevice, async (password, trustDevice) => {
      if (!this.keyring.doc) {
        if (!this.client) return "The plugin has not finished initializing";
        try {
          const doc = await this.client.getVaultKey();
          if (!doc) return "The server has not enabled end-to-end encryption";
          this.keyring.setDoc(doc);
          if (this.store) {
            this.store.state.e2ee = doc;
            await this.store.save();
          }
        } catch (e) {
          return `Cannot connect to the server: ${e instanceof Error ? e.message : String(e)}`;
        }
      }
      if (!await this.keyring.unlock(password)) return "Wrong password";
      await this.setTrustDevice(trustDevice);
      new import_obsidian18.Notice("E2EE unlocked ✓");
      this.updateStatus("idle");
      this.refreshSettingsTab();
      if (onUnlocked) {
        onUnlocked();
      } else if (!this.bootstrapReady) {
        this.openBootstrapWizard();
      } else {
        void this.manager?.sync("unlock");
      }
      return null;
    }).open();
  }
  openEnableModal() {
    if (!this.ctx || !this.manager) {
      new import_obsidian18.Notice("The plugin has not finished initializing — please wait");
      return;
    }
    new EnableE2eeModal(this.app, this.settings.trustDevice, async (password, trustDevice, onProgress) => {
      const migrated = await enableE2ee(
        this.ctx,
        password,
        // fullSync：等待当前轮 + 所有续轮 + 队列排空（LS-121-C06）
        () => this.manager.fullSync("pre-e2ee-migration"),
        onProgress
      );
      await this.setTrustDevice(trustDevice);
      this.updateStatus("synced");
      this.refreshSettingsTab();
      return migrated;
    }).open();
  }
  // ---------- Trusted Device ----------
  /** 是否存在可用的设备信任（用于设置页显示「忘记此设备」）。 */
  hasTrustedDevice() {
    return this.settings.trustDevice && this.settings.deviceKeyB64 !== "";
  }
  /** 把当前已解锁的 VMK 持久化为设备信任。 */
  async persistTrust() {
    if (!this.keyring.unlocked) return;
    const deviceKeyB64 = await persistTrustedDevice(this.app, this.settings.deviceKeyB64, this.keyring);
    if (deviceKeyB64 === null) return;
    if (this.settings.deviceKeyB64 !== deviceKeyB64) {
      this.settings.deviceKeyB64 = deviceKeyB64;
    }
    await this.saveSettings();
  }
  /** 开关「信任此设备」：开 → 立即持久化（若已解锁）；关 → 删除本地信任。 */
  async setTrustDevice(value) {
    this.settings.trustDevice = value;
    if (value) {
      await this.saveSettings();
      await this.persistTrust();
    } else {
      forgetTrustedDevice(this.app);
      this.settings.deviceKeyB64 = "";
      await this.saveSettings();
    }
  }
  /** 忘记此设备：删除设备信任并立即锁定。 */
  async forgetThisDevice() {
    forgetTrustedDevice(this.app);
    this.settings.trustDevice = false;
    this.settings.deviceKeyB64 = "";
    await this.saveSettings();
    this.keyring.lock();
    this.updateStatus("locked");
    new import_obsidian18.Notice("Forgot this device and locked it; you will need to re-enter the E2EE password next time");
  }
  async loadSettings() {
    const raw = await this.loadData() ?? {};
    this.legacyE2eePassword = typeof raw.e2eePassword === "string" ? raw.e2eePassword : "";
    const hadLegacyRemember = raw.rememberE2eePassword === true;
    delete raw.e2eePassword;
    delete raw.rememberE2eePassword;
    this.settings = { ...DEFAULT_SETTINGS, ...raw };
    if (hadLegacyRemember) this.settings.trustDevice = true;
    if (this.legacyE2eePassword !== "" || hadLegacyRemember) {
      await this.saveSettings();
    }
  }
  async saveSettings() {
    await this.saveData(this.settings);
  }
};
