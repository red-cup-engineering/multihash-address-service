#!/usr/bin/env node
import { verifyMultihash as verify } from "../src/multihash-address.mjs";
import { readByteCarrier, runJsonCommand } from "./run-json-command.mjs";

/** Verify the relation between exact bytes and a claimed multihash address. */
export async function verifyMultihash(bytes, address) {
  return verify(bytes, address);
}

export async function main(request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    const error = new TypeError("request must be an object");
    error.code = "invalid-request";
    throw error;
  }
  return verifyMultihash(readByteCarrier(request.bytes), request.address);
}

await runJsonCommand(import.meta.url, main);
