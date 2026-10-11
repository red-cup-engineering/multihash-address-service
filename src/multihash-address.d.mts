export type SupportedMultihashAlgorithm = "sha2-256" | "sha2-512";

export interface MultihashAddressDescription {
  readonly kind: "multihash-address";
  readonly profile: "multihash/base32-lower/sha2";
  readonly address: string;
  readonly presentation: Readonly<{ base: "base32"; canonical: true }>;
  readonly multihash: Readonly<{
    algorithm: SupportedMultihashAlgorithm;
    algorithmCode: number;
    digestLength: number;
    digestBase64url: string;
    bytesBase64url: string;
  }>;
}

export interface MultihashVerification {
  readonly kind: "multihash-verification";
  readonly profile: "multihash/base32-lower/sha2";
  readonly matches: boolean;
  readonly claimedAddress: string;
  readonly expectedAddress: string;
  readonly algorithm: SupportedMultihashAlgorithm;
}

export declare const MULTIHASH_ADDRESS_PROFILE: "multihash/base32-lower/sha2";

export declare class MultihashAddressRefusal extends Error {
  readonly code: string;
}

export declare function createMultihash(
  bytes: Uint8Array,
  options?: Readonly<{ algorithm?: SupportedMultihashAlgorithm }>,
): Promise<MultihashAddressDescription>;

export declare function readMultihash(address: string): MultihashAddressDescription;

export declare function verifyMultihash(
  bytes: Uint8Array,
  address: string,
): Promise<MultihashVerification>;
