import { base32 as nativeBase32 } from "multiformats/bases/base32";
import * as Digest from "multiformats/hashes/digest";
import { sha256, sha512 } from "multiformats/hashes/sha2";

// This public profile has always admitted exact lowercase, unpadded text.
// The native decoder also accepts uppercase: retain this profile's refusal.
const base32 = Object.freeze({
  prefix: nativeBase32.prefix,
  encode: bytes => nativeBase32.encode(bytes),
  decode(text) {
    const bytes = nativeBase32.decode(text);
    if (nativeBase32.encode(bytes) !== text) throw new TypeError("base32: noncanonical lowercase presentation");
    return bytes;
  },
});

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
