#!/usr/bin/env node
import { readMultihash as read } from "../src/multihash-address.mjs";
import { runJsonCommand } from "./run-json-command.mjs";

/** Read a canonical multihash address without resolving or interpreting its bytes. */
export function readMultihash(address) {
  return read(address);
}

export function main(request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    const error = new TypeError("request must be an object");
    error.code = "invalid-request";
    throw error;
  }
  return readMultihash(request.address);
}

await runJsonCommand(import.meta.url, main);
