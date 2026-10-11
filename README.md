# Multihash address service

This service creates, reads, and verifies self-describing byte commitments. Its carrier is a multihash; its one text presentation is lower-case base32 with a multibase prefix.

The package deliberately stops at exact bytes. A CID service may later pair one of these commitments with an explicit multicodec. NI may render the SHA2-256 digest through RFC 6920. Neither composition changes what this service proves.

## Action surface

Each public operation is both an import-safe module and a package-local command:

| Script | Export | Binary | Meaning |
| --- | --- | --- | --- |
| `scripts/create-multihash.mjs` | `createMultihash` | `create-multihash` | Exact bytes to a commitment address |
| `scripts/read-multihash.mjs` | `readMultihash` | `read-multihash` | address to its carried coordinates |
| `scripts/verify-multihash.mjs` | `verifyMultihash` | `verify-multihash` | Exact bytes and claimed address to a comparison |

Imported functions accept `Uint8Array` values. Commands accept one JSON request on standard input and emit one terminal JSON result. Byte strings cross that boundary as `{ "encoding": "base64url", "value": "..." }`. Success is `{ "ok": true, "value": ... }`; refusal is `{ "ok": false, "refusal": { "code": "...", "message": "..." } }` with a nonzero exit status.

Example:

```sh
printf '%s\n' '{"bytes":{"encoding":"base64url","value":"aGVsbG8"}}' | create-multihash
```

The supported hashing profiles are `sha2-256` and `sha2-512`. Parsing refuses other hash codes, wrong digest lengths, alternate bases, uppercase base32, padded input carriers, trailing multihash bytes, and noncanonical varints.

## Ownership boundary

This is a pure computer-content-addressing service. It performs no filesystem,
network, clock, random, custody, registry, resolution, authorization, evidence,
or settlement effects. In particular, an address is not a resource, sign,
referent, representation meaning, or durable storage receipt.

The machine-readable preconditions, postconditions, laws, and exclusions are in `content/contracts/multihash-address-actions.json`.

Native multiformats 14.0.5 now supplies SHA-2 hashing, digest framing, minimal-varint admission and base32 coding. The canonical lowercase/unpadded SHA2 profile, frozen result coordinates, comparison behavior, import-safe APIs and three JSON commands remain. The hand-written varint/base32/hash algorithms have been removed. The direct ./address export carries this byte algebra without importing command-line I/O. Standalone registry publication and external receiving remain separate from authoring-source proof.
