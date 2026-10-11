import type { MultihashVerification } from "../src/multihash-address.mjs";

export type { MultihashVerification };

export declare function verifyMultihash(bytes: Uint8Array, address: string): Promise<MultihashVerification>;
export declare function main(request: Readonly<{
  bytes: Readonly<{ encoding: "base64url"; value: string }>;
  address: string;
}>): Promise<MultihashVerification>;
