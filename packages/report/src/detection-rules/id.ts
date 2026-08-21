/**
 * Deterministic, UUID-SHAPED id derivation (B3). Sigma's spec recommends
 * (does not machine-enforce) a UUIDv4 `id:` field; a real random UUID would
 * make generator output non-reproducible and untestable, so this derives a
 * stable, UUID-formatted string from a seed via SHA-1 — same seed always
 * produces the same id, with the version(4)/variant(8) nibbles forced so it
 * reads as a normal UUIDv4 to any consumer/tool that checks the shape.
 */
import { createHash } from "node:crypto";

export function deterministicUuid(seed: string): string {
  const hex = createHash("sha1").update(seed).digest("hex"); // 40 hex chars
  const version = `4${hex.slice(13, 16)}`;
  const variantNibble = ((parseInt(hex[16] ?? "0", 16) & 0x3) | 0x8).toString(16);
  const variant = `${variantNibble}${hex.slice(17, 20)}`;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${version}-${variant}-${hex.slice(20, 32)}`;
}
