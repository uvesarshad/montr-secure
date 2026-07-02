/**
 * Field-level encryption at rest (§11, golden rule #1). AES-256-GCM via
 * node:crypto — authenticated encryption so any tampering with a stored secret
 * is detected on decrypt. Used for the client's BYO LLM key + refresh tokens
 * (the only reversibly-stored secrets; user passwords are argon2 one-way hashes,
 * handled by WS-L).
 *
 * KEY SOURCING (Vault/KMS hook): the 32-byte key MUST come from a secret manager
 * in production — a k8s Secret, HashiCorp Vault, or a cloud KMS. `@montr/config`
 * exposes `security.fieldEncryptionKeyRef`; the loader resolves the referenced
 * secret and hands the material here. NEVER hard-code a key or read it from a
 * committed file. To integrate a KMS that never exposes raw key bytes (envelope
 * encryption), implement the {@link FieldCipher} interface with KMS
 * Encrypt/Decrypt calls and inject it via {@link createStateStore}.
 *
 * ENVELOPE FORMAT (self-describing, rotation-ready):
 *   montr.v1.gcm:<iv_b64>.<authTag_b64>.<ciphertext_b64>
 */
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

const ENVELOPE_PREFIX = "montr.v1.gcm:";
const IV_BYTES = 12; // 96-bit nonce (GCM standard)
const KEY_BYTES = 32; // AES-256
const TAG_BYTES = 16; // 128-bit auth tag

/**
 * Application salt for passphrase-derived keys. A stable salt is required so a
 * restarted process can still decrypt. Supplying a real 32-byte key (base64/hex)
 * bypasses derivation entirely and is STRONGLY preferred in production.
 */
const KDF_SALT = "montr-secure.field-encryption.v1";

/** The cipher contract — swap this out for a KMS-backed implementation. */
export interface FieldCipher {
  /** Encrypt a UTF-8 string. `aad` (e.g. clientId) is authenticated, not stored. */
  encrypt(plaintext: string, aad?: string): string;
  /** Decrypt an envelope produced by {@link encrypt}. Throws if tampered. */
  decrypt(envelope: string, aad?: string): string;
  /** True if `value` looks like an envelope this cipher produced. */
  isEncrypted(value: string): boolean;
}

/** Resolve key material (raw 32-byte base64/hex, else scrypt-derived) to a Buffer. */
export function resolveKey(material: string | Buffer): Buffer {
  if (Buffer.isBuffer(material)) {
    if (material.length !== KEY_BYTES) {
      throw new Error(`field-encryption key must be ${KEY_BYTES} bytes, got ${material.length}`);
    }
    return material;
  }
  const trimmed = material.trim();
  // Exact 64-char hex → 32 bytes.
  if (/^[0-9a-f]{64}$/i.test(trimmed)) return Buffer.from(trimmed, "hex");
  // Base64 that decodes to exactly 32 bytes.
  if (/^[A-Za-z0-9+/]{43}=$/.test(trimmed) || /^[A-Za-z0-9+/]{44}$/.test(trimmed)) {
    const buf = Buffer.from(trimmed, "base64");
    if (buf.length === KEY_BYTES) return buf;
  }
  // Otherwise derive deterministically from the passphrase (dev convenience).
  if (trimmed.length === 0) throw new Error("field-encryption key material is empty");
  return scryptSync(trimmed, KDF_SALT, KEY_BYTES);
}

class AesGcmFieldCipher implements FieldCipher {
  private readonly key: Buffer;

  constructor(material: string | Buffer) {
    this.key = resolveKey(material);
  }

  encrypt(plaintext: string, aad?: string): string {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    if (aad) cipher.setAAD(Buffer.from(aad, "utf8"));
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return (
      ENVELOPE_PREFIX +
      [iv.toString("base64"), tag.toString("base64"), ciphertext.toString("base64")].join(".")
    );
  }

  decrypt(envelope: string, aad?: string): string {
    if (!this.isEncrypted(envelope)) {
      throw new Error("value is not a recognised encryption envelope");
    }
    const body = envelope.slice(ENVELOPE_PREFIX.length);
    const parts = body.split(".");
    if (parts.length !== 3) throw new Error("malformed encryption envelope");
    const [ivB64, tagB64, ctB64] = parts as [string, string, string];
    const iv = Buffer.from(ivB64, "base64");
    const tag = Buffer.from(tagB64, "base64");
    const ciphertext = Buffer.from(ctB64, "base64");
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
      throw new Error("malformed encryption envelope (iv/tag length)");
    }
    const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
    decipher.setAuthTag(tag);
    if (aad) decipher.setAAD(Buffer.from(aad, "utf8"));
    // .final() throws if the auth tag / AAD does not verify (tamper-evident).
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  }

  isEncrypted(value: string): boolean {
    return typeof value === "string" && value.startsWith(ENVELOPE_PREFIX);
  }
}

/** Build the default AES-256-GCM cipher from key material. */
export function createFieldCipher(material: string | Buffer): FieldCipher {
  return new AesGcmFieldCipher(material);
}

/** Generate a fresh base64 32-byte key (for docs / local dev / tests). */
export function generateEncryptionKey(): string {
  return randomBytes(KEY_BYTES).toString("base64");
}

/** Constant-time string comparison helper (e.g. verifying a stored token). */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
