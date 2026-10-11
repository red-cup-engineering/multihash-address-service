import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { base32 } from "../src/multihash-address.mjs";
import { createMultihash } from "../scripts/create-multihash.mjs";
import { readMultihash } from "../scripts/read-multihash.mjs";
import { verifyMultihash } from "../scripts/verify-multihash.mjs";

const EMPTY_SHA256_ADDRESS = "bciqohmgeikmpyhautl57jsezn64sij5oihsgjg4tjssjlgi3pbjlqvi";
const ABC_SHA256_ADDRESS = "bciqlu6awx6hqdt7kifaubxs5vyrchmadmgrzmf32ts2bb73b6iablli";
const ABC_SHA512_ADDRESS = "bcnan3lzvugjwc6v2zraxgsnoebatcexg7jhitkl6uifj53xgjnk5hgrbskmsuj2pygudnor4eor75255ivguii3ehtua4ku2zfh2ktfet4";
const encoder = new TextEncoder();
const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

function command(script, request) {
  return spawnSync(process.execPath, [fileURLToPath(new URL(`../scripts/${script}.mjs`, import.meta.url))], {
    input: JSON.stringify(request),
    encoding: "utf8",
  });
}

function refusalCode(action) {
  try {
    action();
    assert.fail("expected action to refuse");
  } catch (error) {
    return error.code;
  }
}

test("creates independent SHA2-256 known vectors and carries the exact digest", async () => {
  const empty = await createMultihash(new Uint8Array());
  const abc = await createMultihash(encoder.encode("abc"));
  assert.equal(empty.address, EMPTY_SHA256_ADDRESS);
  assert.equal(abc.address, ABC_SHA256_ADDRESS);
  assert.equal(abc.multihash.algorithmCode, 0x12);
  assert.equal(abc.multihash.digestLength, 32);
  assert.equal(
    abc.multihash.digestBase64url,
    createHash("sha256").update("abc").digest("base64url"),
  );
  assert.deepEqual(
    Buffer.from(abc.multihash.bytesBase64url, "base64url").subarray(0, 2),
    Buffer.from([0x12, 0x20]),
  );
});

test("supports a distinct self-described SHA2-512 profile", async () => {
  const abc = await createMultihash(encoder.encode("abc"), { algorithm: "sha2-512" });
  assert.equal(abc.address, ABC_SHA512_ADDRESS);
  assert.equal(abc.multihash.algorithmCode, 0x13);
  assert.equal(abc.multihash.digestLength, 64);
  assert.equal(abc.multihash.digestBase64url, createHash("sha512").update("abc").digest("base64url"));
});

test("create is deterministic and read(create(bytes)) preserves every coordinate", async () => {
  const first = await createMultihash(Uint8Array.from([0, 255, 1, 128]));
  const second = await createMultihash(Uint8Array.from([0, 255, 1, 128]));
  assert.deepEqual(first, second);
  assert.deepEqual(readMultihash(first.address), first);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.multihash), true);
});

test("verify compares exact bytes without turning mismatch into refusal", async () => {
  const matching = await verifyMultihash(encoder.encode("abc"), ABC_SHA256_ADDRESS);
  const changed = await verifyMultihash(encoder.encode("abd"), ABC_SHA256_ADDRESS);
  assert.equal(matching.matches, true);
  assert.equal(changed.matches, false);
  assert.equal(changed.claimedAddress, ABC_SHA256_ADDRESS);
  assert.notEqual(changed.expectedAddress, ABC_SHA256_ADDRESS);
});

test("refuses unsupported algorithms and malformed byte carriers", async () => {
  await assert.rejects(
    createMultihash(encoder.encode("abc"), { algorithm: "sha3-256" }),
    (error) => error.code === "unsupported-hash-algorithm",
  );
  await assert.rejects(
    createMultihash("abc"),
    (error) => error.code === "invalid-byte-string",
  );
});

test("read refuses alternate bases, case, trailing bytes, and noncanonical varints", () => {
  const canonicalBytes = Buffer.from(readMultihash(ABC_SHA256_ADDRESS).multihash.bytesBase64url, "base64url");
  const trailing = base32.encode(Uint8Array.from([...canonicalBytes, 0]));
  const noncanonicalCode = base32.encode(Uint8Array.from([0x92, 0x00, ...canonicalBytes.subarray(1)]));
  const invalid = [
    ABC_SHA256_ADDRESS.slice(1),
    `b${ABC_SHA256_ADDRESS.slice(1).toUpperCase()}`,
    `${ABC_SHA256_ADDRESS}=`,
    trailing,
    noncanonicalCode,
  ];
  for (const address of invalid) {
    assert.match(refusalCode(() => readMultihash(address)), /^(invalid|noncanonical)-multihash-address$/u);
  }
});

test("read refuses unknown algorithms and wrong digest lengths explicitly", () => {
  const unknown = base32.encode(Uint8Array.from([0x00, 0x01, 0x00]));
  const shortSha256 = base32.encode(Uint8Array.from([0x12, 0x01, 0x00]));
  assert.equal(refusalCode(() => readMultihash(unknown)), "unsupported-hash-algorithm");
  assert.equal(refusalCode(() => readMultihash(shortSha256)), "invalid-digest-length");
});

test("commands and imported actions are the same import-safe algebra", () => {
  const operations = ["create-multihash", "read-multihash", "verify-multihash"];
  for (const operation of operations) {
    assert.equal(packageJson.bin[operation], `./scripts/${operation}.mjs`);
    assert.equal(packageJson.exports[`./${operation}`].import, `./scripts/${operation}.mjs`);
    const imported = spawnSync(process.execPath, ["--input-type=module", "--eval", `import ${JSON.stringify(new URL(`../scripts/${operation}.mjs`, import.meta.url).href)}`], { encoding: "utf8" });
    assert.equal(imported.status, 0, imported.stderr);
    assert.equal(imported.stdout, "");
    assert.equal(imported.stderr, "");
  }
});

test("create command accepts one canonical byte carrier and emits one result", () => {
  const result = command("create-multihash", {
    bytes: { encoding: "base64url", value: "YWJj" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: true,
    value: readMultihash(ABC_SHA256_ADDRESS),
  });
});

test("verify command represents mismatch as a successful comparison", () => {
  const result = command("verify-multihash", {
    bytes: { encoding: "base64url", value: "YWJk" },
    address: ABC_SHA256_ADDRESS,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).value.matches, false);
});

test("command refusal is structured, stable, and nonzero", () => {
  const result = command("create-multihash", {
    bytes: { encoding: "base64url", value: "YWJj=" },
  });
  assert.equal(result.status, 1);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: false,
    refusal: {
      code: "invalid-byte-carrier",
      message: "bytes must be { encoding: 'base64url', value: <canonical base64url> }",
    },
  });
});
