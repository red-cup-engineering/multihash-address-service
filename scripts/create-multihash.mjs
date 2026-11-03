#!/usr/bin/env node
import { createMultihash as create } from "../src/multihash-address.mjs";
import { readByteCarrier, runJsonCommand } from "./run-json-command.mjs";

/** Create a canonical multihash address from exact bytes. */
export async function createMultihash(bytes, options) {
  return create(bytes, options);
}

export async function main(request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    const error = new TypeError("request must be an object");
    error.code = "invalid-request";
    throw error;
  }
  return createMultihash(readByteCarrier(request.bytes), { algorithm: request.algorithm });
}

await runJsonCommand(import.meta.url, main);
