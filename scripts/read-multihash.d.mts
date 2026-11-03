import type { MultihashAddressDescription } from "../src/multihash-address.mjs";

export type { MultihashAddressDescription };

export declare function readMultihash(address: string): MultihashAddressDescription;
export declare function main(request: Readonly<{ address: string }>): MultihashAddressDescription;
