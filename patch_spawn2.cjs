const fs = require("fs");
const file = "src/agents/subagent-spawn.ts";
let content = fs.readFileSync(file, "utf8");

const decodeFn = `
import { promises as fsPromises } from "node:fs";
import path from "node:path";
import { resolveAgentWorkspaceDir } from "./agent-scope.js";

function decodeStrictBase64(value: string, maxDecodedBytes: number): Buffer | null {
  const maxEncodedBytes = Math.ceil(maxDecodedBytes / 3) * 4;
  if (value.length > maxEncodedBytes * 2) {
    return null;
  }
  const normalized = value.replace(/\\s+/g, "");
  if (!normalized || normalized.length % 4 !== 0) {
    return null;
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) {
    return null;
  }
  if (normalized.length > maxEncodedBytes) {
    return null;
  }
  const decoded = Buffer.from(normalized, "base64");
  if (decoded.byteLength > maxDecodedBytes) {
    return null;
  }
  const roundtrip = decoded.toString("base64");
  if (roundtrip !== normalized) {
    return null;
  }
  return decoded;
}

`;

content = content.replace(
  `export function splitModelRef`,
  decodeFn + `export function splitModelRef`,
);

fs.writeFileSync(file, content);
