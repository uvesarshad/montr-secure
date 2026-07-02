import { describe, it, expect } from "vitest";
import { scrubValue } from "@montr/telemetry";
import {
  redactSensitive,
  findLogViolations,
  assertNoSecretsOrCode,
  assertScrubberNeutralizes,
  detectSecretValue,
  looksLikeSourceCode,
  isRedactionPlaceholder,
  LogScrubViolationError,
  ScrubberCertificationError,
  REDACTED,
  REALISTIC_LOG_THREATS,
  ADVERSARIAL_LOG_THREATS,
} from "../packages/security/src/scrubber";

/**
 * WS-N log-scrubber VERIFIER tests (build-plan §4.8, golden rule #1). Proves the
 * verifier (a) redacts sensitive keys / oversize / code / secret bodies, (b)
 * asserts leaks, and (c) certifies `@montr/telemetry`'s real scrubber.
 */

const SECRET = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX";
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKLmnoPQRstuv";
const CODE =
  "export function f(req){\n  return db.$queryRawUnsafe(`SELECT * FROM u WHERE id=${req.id}`);\n}";

describe("redactSensitive", () => {
  it("redacts sensitive-named keys wholesale", () => {
    const out = redactSensitive({
      apiKey: SECRET,
      password: "hunter2",
      nested: { token: JWT },
    }) as Record<string, Record<string, unknown>>;
    expect(out["apiKey"]).toBe(REDACTED);
    expect(out["password"]).toBe(REDACTED);
    expect(out["nested"]!["token"]).toBe(REDACTED);
  });

  it("caps oversize strings and neutralises code / secret VALUES by content", () => {
    const oversize = "A".repeat(2000);
    const out = redactSensitive({ note: CODE, blob: oversize, info: `leak ${SECRET}` }) as Record<
      string,
      string
    >;
    expect(out["note"]).toContain(":code");
    expect(out["blob"]).toContain(":oversize");
    expect(out["info"]).toContain(":secret");
    // the redacted output must itself be certified clean
    expect(() => assertNoSecretsOrCode(out)).not.toThrow();
  });

  it("preserves benign numeric/boolean metadata (even under sensitive-named keys)", () => {
    const out = redactSensitive({ tokenCount: 1234, ok: true, scanId: "s1" }) as Record<
      string,
      unknown
    >;
    expect(out["tokenCount"]).toBe(1234);
    expect(out["ok"]).toBe(true);
    expect(out["scanId"]).toBe("s1");
  });

  it("is cycle-safe", () => {
    const a: Record<string, unknown> = { name: "a" };
    a["self"] = a;
    expect(() => redactSensitive(a)).not.toThrow();
  });
});

describe("detectors", () => {
  it("detectSecretValue matches known secret formats", () => {
    expect(detectSecretValue(SECRET)).toBe("anthropic_api_key");
    expect(detectSecretValue(JWT)).toBe("jwt");
    expect(detectSecretValue("AKIAIOSFODNN7EXAMPLE")).toBe("aws_access_key_id");
    expect(detectSecretValue("just a normal log line")).toBeUndefined();
  });

  it("looksLikeSourceCode flags code bodies, not short prose", () => {
    expect(looksLikeSourceCode(CODE)).toBe(true);
    expect(looksLikeSourceCode("User 'alice' logged in from the console")).toBe(false);
    expect(looksLikeSourceCode("ok")).toBe(false);
  });

  it("recognises redaction placeholders", () => {
    expect(isRedactionPlaceholder(REDACTED)).toBe(true);
    expect(isRedactionPlaceholder("[REDACTED]:oversize:2000b")).toBe(true);
    expect(isRedactionPlaceholder("normal")).toBe(false);
  });
});

describe("findLogViolations / assertNoSecretsOrCode", () => {
  it("returns no violations for a clean metadata payload", () => {
    expect(findLogViolations({ scanId: "abc", latencyMs: 42, ok: true })).toEqual([]);
  });

  it("flags secrets, code bodies and oversize strings in a RAW payload", () => {
    const v = findLogViolations({ apiKey: SECRET, note: CODE, blob: "A".repeat(2000) });
    const kinds = new Set(v.map((x) => x.kind));
    expect(kinds.has("sensitive_value")).toBe(true); // apiKey holds a real value
    expect(kinds.has("code_body")).toBe(true);
    expect(kinds.has("oversize")).toBe(true);
  });

  it("assertNoSecretsOrCode throws LogScrubViolationError on raw code/secret", () => {
    expect(() => assertNoSecretsOrCode({ patch: CODE })).toThrow(LogScrubViolationError);
    expect(() => assertNoSecretsOrCode({ authorization: `Bearer ${JWT}` })).toThrow(
      LogScrubViolationError,
    );
  });

  it("NEVER echoes the offending value in the error message (fail-safe)", () => {
    try {
      assertNoSecretsOrCode({ apiKey: SECRET, note: CODE });
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(LogScrubViolationError);
      const msg = (e as Error).message;
      expect(msg).not.toContain(SECRET);
      expect(msg).not.toContain("queryRawUnsafe");
    }
  });

  it("passes once the payload has been redacted", () => {
    expect(() =>
      assertNoSecretsOrCode(redactSensitive({ apiKey: SECRET, note: CODE })),
    ).not.toThrow();
  });
});

describe("assertScrubberNeutralizes (scrubber certifier)", () => {
  it("certifies @montr/telemetry's real scrubValue against realistic threats", () => {
    const report = assertScrubberNeutralizes((v) => scrubValue(v), REALISTIC_LOG_THREATS);
    expect(report.certified).toBe(true);
    expect(report.samplesChecked).toBe(REALISTIC_LOG_THREATS.length);
  });

  it("certifies @montr/telemetry's real scrubValue against the ADVERSARIAL battery (content-blind gap closed)", () => {
    // Regression guard: telemetry's hot-path scrubber must neutralise a secret
    // value or code body hiding under an innocuous, sub-cap key — not just
    // sensitive KEY names / oversize strings (golden rule #1, WS-N gap).
    const report = assertScrubberNeutralizes((v) => scrubValue(v), ADVERSARIAL_LOG_THREATS);
    expect(report.certified).toBe(true);
    expect(report.samplesChecked).toBe(ADVERSARIAL_LOG_THREATS.length);
  });

  it("scrubValue neutralises code/secret under an innocuous key, keeps benign metadata", () => {
    const out = scrubValue({
      note: CODE, // code body under a benign key
      info: `leak ${SECRET}`, // secret value under a benign key
      scanId: "s1",
      latencyMs: 42,
    }) as Record<string, unknown>;
    expect(out["note"]).toContain(":code");
    expect(out["info"]).toContain(":secret");
    expect(out["scanId"]).toBe("s1");
    expect(out["latencyMs"]).toBe(42);
    expect(() => assertNoSecretsOrCode(out)).not.toThrow();
  });

  it("certifies security's own redactSensitive against the full adversarial battery", () => {
    const report = assertScrubberNeutralizes((v) => redactSensitive(v), ADVERSARIAL_LOG_THREATS);
    expect(report.certified).toBe(true);
  });

  it("FAILS an identity (no-op) scrubber", () => {
    expect(() => assertScrubberNeutralizes((v) => v, REALISTIC_LOG_THREATS)).toThrow(
      ScrubberCertificationError,
    );
  });

  it("reports which samples leaked (metadata only)", () => {
    try {
      assertScrubberNeutralizes((v) => v, REALISTIC_LOG_THREATS);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ScrubberCertificationError);
      const failures = (e as ScrubberCertificationError).failures;
      expect(failures.length).toBeGreaterThan(0);
      expect(failures[0]).toHaveProperty("sampleIndex");
      expect(failures[0]).toHaveProperty("violations");
    }
  });
});
