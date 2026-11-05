import { createHash } from "node:crypto";

// — unsigned-varint (LEB128-style, as used by the multihash/multicodec spec) —

function encodeVarint(value) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error("varint: value must be a non-negative integer");
  }
  const bytes = [];
  let remaining = value;
  while (remaining > 0x7f) {
    bytes.push((remaining & 0x7f) | 0x80);
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(remaining);
  return Uint8Array.from(bytes);
}

function decodeVarint(bytes, offset) {
  let value = 0;
  let shift = 0;
  let position = offset;
  for (;;) {
    if (position >= bytes.length) throw new Error("varint: unexpected end of input");
    const byte = bytes[position];
    value += (byte & 0x7f) * 2 ** shift;
    position += 1;
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift > 63) throw new Error("varint: value too large");
  }
  return { value, end: position };
}

// — base32 (RFC 4648, lowercase, unpadded), multibase-prefixed with "b" —

const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

function base32Encode(bytes) {
  let bits = 0;
  let buffer = 0;
  let body = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      const shift = bits - 5;
      body += BASE32_ALPHABET[(buffer >>> shift) & 0x1f];
      bits -= 5;
      buffer &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    body += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f];
  }
  return `b${body}`;
}

function base32Decode(text) {
  if (typeof text !== "string" || text[0] !== "b") {
    throw new Error('base32: text must start with the "b" multibase prefix');
  }
  let bits = 0;
  let buffer = 0;
  const bytes = [];
  for (const character of text.slice(1)) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index === -1) throw new Error(`base32: invalid character ${JSON.stringify(character)}`);
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      const shift = bits - 8;
      bytes.push((buffer >>> shift) & 0xff);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  if (bits >= 5 || buffer !== 0) {
    throw new Error("base32: text length or trailing bits are not a canonical encoding");
  }
  return Uint8Array.from(bytes);
}

const base32 = Object.freeze({ prefix: "b", encode: base32Encode, decode: base32Decode });

// — multihash digest (varint code, varint length, digest bytes) —

const Digest = Object.freeze({
  decode(bytes) {
    const codeField = decodeVarint(bytes, 0);
    const sizeField = decodeVarint(bytes, codeField.end);
    const digest = bytes.slice(sizeField.end);
    if (digest.length !== sizeField.value) {
      throw new Error("multihash: declared digest length does not match the remaining bytes");
    }
    return Object.freeze({ code: codeField.value, size: sizeField.value, digest, bytes: Uint8Array.from(bytes) });
  },
  create(code, digest) {
    const codeBytes = encodeVarint(code);
    const sizeBytes = encodeVarint(digest.length);
    const bytes = new Uint8Array(codeBytes.length + sizeBytes.length + digest.length);
    bytes.set(codeBytes, 0);
    bytes.set(sizeBytes, codeBytes.length);
    bytes.set(digest, codeBytes.length + sizeBytes.length);
    return Object.freeze({ code, size: digest.length, digest: Uint8Array.from(digest), bytes });
  },
});

// — SHA-2 hashers, self-describing per the multihash function-code table —

function sha2Hasher(name, code, algorithm) {
  return Object.freeze({
    name,
    code,
    async digest(bytes) {
      const raw = createHash(algorithm).update(bytes).digest();
      return Digest.create(code, new Uint8Array(raw));
    },
  });
}

const sha256 = sha2Hasher("sha2-256", 0x12, "sha256");
const sha512 = sha2Hasher("sha2-512", 0x13, "sha512");

const PROFILES_BY_NAME = new Map([
  [sha256.name, Object.freeze({ hasher: sha256, digestLength: 32 })],
  [sha512.name, Object.freeze({ hasher: sha512, digestLength: 64 })],
]);
const PROFILES_BY_CODE = new Map([
  [sha256.code, PROFILES_BY_NAME.get(sha256.name)],
  [sha512.code, PROFILES_BY_NAME.get(sha512.name)],
]);

export const MULTIHASH_ADDRESS_PROFILE = "multihash/base32-lower/sha2";

export class MultihashAddressRefusal extends Error {
  constructor(code, message) {
    super(message);
    this.name = "MultihashAddressRefusal";
    this.code = code;
  }
}

function refuse(code, message) {
  throw new MultihashAddressRefusal(code, message);
}

function byteString(value) {
  if (!(value instanceof Uint8Array)) {
    refuse("invalid-byte-string", "bytes must be a Uint8Array");
  }
  return Uint8Array.from(value);
}

function sameBytes(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function profileNamed(name) {
  if (typeof name !== "string" || !PROFILES_BY_NAME.has(name)) {
    refuse("unsupported-hash-algorithm", `unsupported multihash algorithm ${JSON.stringify(name)}`);
  }
  return PROFILES_BY_NAME.get(name);
}

function describe(address, digest, hasher) {
  return Object.freeze({
    kind: "multihash-address",
    profile: MULTIHASH_ADDRESS_PROFILE,
    address,
    presentation: Object.freeze({ base: "base32", canonical: true }),
    multihash: Object.freeze({
      algorithm: hasher.name,
      algorithmCode: hasher.code,
      digestLength: digest.digest.length,
      digestBase64url: Buffer.from(digest.digest).toString("base64url"),
      bytesBase64url: Buffer.from(digest.bytes).toString("base64url"),
    }),
  });
}

/** Create the canonical address of an exact byte string under a named SHA-2 multihash profile. */
export async function createMultihash(bytes, { algorithm = "sha2-256" } = {}) {
  const { hasher } = profileNamed(algorithm);
  const digest = await hasher.digest(byteString(bytes));
  return describe(base32.encode(digest.bytes), digest, hasher);
}

/** Read one canonical address into its self-describing multihash coordinates. */
export function readMultihash(address) {
  if (typeof address !== "string" || !address.startsWith(base32.prefix)) {
    refuse("invalid-multihash-address", "multihash address must use the canonical base32-lower presentation");
  }

  let bytes;
  try {
    bytes = base32.decode(address);
  } catch {
    refuse("invalid-multihash-address", "multihash address is not valid base32-lower text");
  }
  if (base32.encode(bytes) !== address) {
    refuse("noncanonical-multihash-address", "multihash address is not in canonical base32-lower form");
  }

  let digest;
  try {
    digest = Digest.decode(bytes);
  } catch {
    refuse("invalid-multihash-address", "address does not contain one complete multihash");
  }
  const profile = PROFILES_BY_CODE.get(digest.code);
  if (profile === undefined) {
    refuse("unsupported-hash-algorithm", `unsupported multihash algorithm code ${digest.code}`);
  }
  const { hasher, digestLength } = profile;
  if (digest.digest.length !== digestLength) {
    refuse("invalid-digest-length", `${hasher.name} digest must contain ${digestLength} bytes`);
  }
  const canonical = Digest.create(digest.code, digest.digest);
  if (!sameBytes(canonical.bytes, bytes)) {
    refuse("noncanonical-multihash-address", "multihash uses a noncanonical binary encoding");
  }
  return describe(address, digest, hasher);
}

/** Verify whether exact bytes satisfy a canonical multihash address. */
export async function verifyMultihash(bytes, address) {
  const claim = readMultihash(address);
  const expected = await createMultihash(byteString(bytes), { algorithm: claim.multihash.algorithm });
  return Object.freeze({
    kind: "multihash-verification",
    profile: MULTIHASH_ADDRESS_PROFILE,
    matches: expected.address === claim.address,
    claimedAddress: claim.address,
    expectedAddress: expected.address,
    algorithm: claim.multihash.algorithm,
  });
}

// Exported so callers that need the exact base32 presentation this service
// commits to (e.g. this package's own tests) never import it from elsewhere.
export { base32 };
