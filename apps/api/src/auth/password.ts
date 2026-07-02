/**
 * Password hashing with node:crypto scrypt (no native dependency).
 *
 * Golden rule #3: auth/session/crypto is safety-critical. We use scrypt (a
 * memory-hard KDF) with a per-password random salt and a CONSTANT-TIME compare
 * (`timingSafeEqual`) so verification never leaks timing about the stored hash.
 *
 * Encoded form: `scrypt$N=<n>,r=<r>,p=<p>$<saltB64>$<hashB64>`.
 * The stored string is one-way — the plaintext is never recoverable.
 */
import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

/** scrypt cost parameters. N must be a power of two; ~16 MiB of memory at N=16384,r=8. */
export interface ScryptParams {
  readonly N: number;
  readonly r: number;
  readonly p: number;
  readonly keyLen: number;
}

export const DEFAULT_SCRYPT_PARAMS: ScryptParams = {
  N: 16384,
  r: 8,
  p: 1,
  keyLen: 64,
};

/** scrypt needs ~128*N*r bytes; grant headroom above the 32 MiB default. */
const MAX_MEM = 64 * 1024 * 1024;
const SALT_BYTES = 16;

function deriveKey(
  password: string,
  salt: Buffer,
  keyLen: number,
  p: ScryptParams,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      password.normalize("NFKC"),
      salt,
      keyLen,
      { N: p.N, r: p.r, p: p.p, maxmem: MAX_MEM },
      (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      },
    );
  });
}

/** Hash a plaintext password into the encoded, salted scrypt string. */
export async function hashPassword(
  password: string,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
): Promise<string> {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("password must be a non-empty string");
  }
  const salt = randomBytes(SALT_BYTES);
  const derived = await deriveKey(password, salt, params.keyLen, params);
  return `scrypt$N=${params.N},r=${params.r},p=${params.p}$${salt.toString("base64")}$${derived.toString(
    "base64",
  )}`;
}

interface ParsedHash {
  params: ScryptParams;
  salt: Buffer;
  hash: Buffer;
}

function parseHash(stored: string): ParsedHash | null {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "scrypt") return null;
  const paramPart = parts[1] ?? "";
  const saltB64 = parts[2] ?? "";
  const hashB64 = parts[3] ?? "";
  const m = /^N=(\d+),r=(\d+),p=(\d+)$/.exec(paramPart);
  if (!m) return null;
  const N = Number(m[1]);
  const r = Number(m[2]);
  const p = Number(m[3]);
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return null;
  // N must be a power of two > 1 (scrypt requirement); reject anything else.
  if (N < 2 || (N & (N - 1)) !== 0) return null;
  let salt: Buffer;
  let hash: Buffer;
  try {
    salt = Buffer.from(saltB64, "base64");
    hash = Buffer.from(hashB64, "base64");
  } catch {
    return null;
  }
  if (salt.length === 0 || hash.length === 0) return null;
  return { params: { N, r, p, keyLen: hash.length }, salt, hash };
}

/**
 * Verify a plaintext password against an encoded hash in CONSTANT TIME.
 * Returns false (never throws) on any malformed input so callers can treat
 * "bad password" and "corrupt record" identically.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parsed = parseHash(stored);
  if (!parsed) return false;
  let derived: Buffer;
  try {
    derived = await deriveKey(password, parsed.salt, parsed.params.keyLen, parsed.params);
  } catch {
    return false;
  }
  if (derived.length !== parsed.hash.length) return false;
  return timingSafeEqual(derived, parsed.hash);
}

let decoyHashPromise: Promise<string> | undefined;

/**
 * A stable decoy hash used to equalize timing when a login targets an unknown
 * user — prevents username enumeration via response-time differences. Computed
 * once per process against a random secret.
 */
export function decoyHash(): Promise<string> {
  if (!decoyHashPromise) {
    decoyHashPromise = hashPassword(randomBytes(24).toString("hex"));
  }
  return decoyHashPromise;
}
