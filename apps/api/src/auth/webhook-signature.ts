/**
 * HMAC signature verification for inbound scan-trigger webhooks (A15).
 *
 * GitHub-compatible: the same `sha256=<hex>` scheme GitHub sends in
 * `X-Hub-Signature-256` for repository webhooks, computed as
 * `HMAC-SHA256(secret, rawRequestBody)`. A provider-agnostic caller (a plain
 * GitHub Actions workflow step, a GitLab webhook, a cron job) can produce the
 * identical header with any standard HMAC-SHA256 tool, so this is not
 * GitHub-specific in practice — only the header NAME follows GitHub's
 * convention for drop-in compatibility with `actions/github-script` /
 * `peter-evans` style workflow steps that already know how to sign it.
 *
 * Verification MUST run over the raw request bytes (not a re-serialized
 * `JSON.stringify(JSON.parse(body))`), since any whitespace/key-order
 * difference would change the HMAC. The route registering this (see
 * ../routes/webhooks.ts) installs a custom content-type parser that preserves
 * the raw buffer for exactly this reason.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

/** Header name mirroring GitHub's `X-Hub-Signature-256` convention. */
export const WEBHOOK_SIGNATURE_HEADER = "x-hub-signature-256";

/** Compute a `sha256=<hex>` HMAC signature over `payload` with `secret`. */
export function signWebhookPayload(secret: string, payload: string | Buffer): string {
  return `sha256=${createHmac("sha256", secret).update(payload).digest("hex")}`;
}

/**
 * Constant-time verification of a GitHub-style `X-Hub-Signature-256` header
 * against the raw request body. Returns `false` (never throws) for a missing
 * header, malformed header, or mismatched signature — callers turn a `false`
 * into a 401, never leaking which of those three occurred.
 */
export function verifyWebhookSignature(
  secret: string,
  payload: string | Buffer,
  header: string | string[] | undefined,
): boolean {
  if (typeof header !== "string" || header.length === 0) return false;

  const expected = signWebhookPayload(secret, payload);
  const expectedBuf = Buffer.from(expected, "utf8");
  const actualBuf = Buffer.from(header, "utf8");

  if (expectedBuf.length !== actualBuf.length) {
    // Still run a comparison of equal-length buffers so a length mismatch
    // doesn't short-circuit faster than a content mismatch (timing leak).
    timingSafeEqual(expectedBuf, expectedBuf);
    return false;
  }
  return timingSafeEqual(expectedBuf, actualBuf);
}
