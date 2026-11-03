import type {
  MultihashAddressDescription,
  SupportedMultihashAlgorithm,
} from "../src/multihash-address.mjs";

export type { MultihashAddressDescription, SupportedMultihashAlgorithm };

export declare function createMultihash(
  bytes: Uint8Array,
  options?: Readonly<{ algorithm?: SupportedMultihashAlgorithm }>,
): Promise<MultihashAddressDescription>;

export declare function main(request: Readonly<{
  bytes: Readonly<{ encoding: "base64url"; value: string }>;
  algorithm?: SupportedMultihashAlgorithm;
}>): Promise<MultihashAddressDescription>;
