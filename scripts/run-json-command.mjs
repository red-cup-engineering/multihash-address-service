import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

function isEntrypoint(metaUrl) {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(metaUrl));
  } catch {
    return false;
  }
}

function refusalFrom(error) {
  return Object.freeze({
    code: typeof error?.code === "string" ? error.code : "invalid-request",
    message: error instanceof Error ? error.message : String(error),
  });
}

/** Totalize one imported action at the JSON command boundary. */
export async function runJsonCommand(metaUrl, action) {
  if (!isEntrypoint(metaUrl)) return;
  try {
    process.stdin.setEncoding("utf8");
    let text = "";
    for await (const chunk of process.stdin) text += chunk;
    const request = JSON.parse(text);
    const value = await action(request);
    process.stdout.write(`${JSON.stringify({ ok: true, value })}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, refusal: refusalFrom(error) })}\n`);
    process.exitCode = 1;
  }
}

export function readByteCarrier(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
      || value.encoding !== "base64url" || typeof value.value !== "string"
      || !/^[A-Za-z0-9_-]*$/u.test(value.value)) {
    const error = new TypeError("bytes must be { encoding: 'base64url', value: <canonical base64url> }");
    error.code = "invalid-byte-carrier";
    throw error;
  }
  const bytes = Buffer.from(value.value, "base64url");
  if (bytes.toString("base64url") !== value.value) {
    const error = new TypeError("bytes.value must be canonical unpadded base64url");
    error.code = "noncanonical-byte-carrier";
    throw error;
  }
  return bytes;
}
