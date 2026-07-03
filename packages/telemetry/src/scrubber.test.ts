import { describe, it, expect } from "vitest";
import {
  scrubValue,
  scrubFields,
  createScrubber,
  REDACTED,
  DEFAULT_SENSITIVE_KEY_PATTERN,
} from "./scrubber.js";
import {
  assertScrubberNeutralizes,
  findLogViolations,
  ADVERSARIAL_LOG_THREATS,
  REALISTIC_LOG_THREATS,
  ScrubberCertificationError,
} from "../../security/src/scrubber.js";

/**
 * Carry-over #1 (telemetry content-scrubber). The hot-path log scrubber must
 * neutralise a secret VALUE or code BODY even when it hides under an innocuous,
 * sub-cap key — not only by key NAME / SIZE (golden rule #1, §10). Proven by
 * running @montr/security's INDEPENDENT certifier (`assertScrubberNeutralizes`)
 * over telemetry's real `scrubValue` with the ADVERSARIAL battery: ZERO leaks.
 * Co-located with the implementation (mirrors tests/security.scrubber.test.ts).
 */

const SECRET = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX";
const CODE =
  "export async function h(req, res) {\n" +
  "  const rows = await db.$queryRawUnsafe(`SELECT * FROM u WHERE id=${req.query.id}`);\n" +
  "  return res.json(rows);\n" +
  "}";

/** A CONTENT-BLIND scrubber: redacts by sensitive key name + size only (no
 *  content inspection). Stands in for telemetry's PRE-hardening behaviour to
 *  prove the ADVERSARIAL battery actually exercises the content gap. */
function keyAndSizeOnly(input: unknown): unknown {
  const walk = (x: unknown): unknown => {
    if (x === null || typeof x !== "object") {
      return typeof x === "string" && x.length > 1024 ? `${REDACTED}:oversize` : x;
    }
    if (Array.isArray(x)) return x.map(walk);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(x as Record<string, unknown>)) {
      out[k] = DEFAULT_SENSITIVE_KEY_PATTERN.test(k) ? REDACTED : walk(v);
    }
    return out;
  };
  return walk(input);
}

describe("telemetry scrubber — content-based neutralisation (golden rule #1)", () => {
  it("certifies scrubValue against the ADVERSARIAL battery to ZERO leaks", () => {
    const report = assertScrubberNeutralizes((v) => scrubValue(v), ADVERSARIAL_LOG_THREATS);
    expect(report.certified).toBe(true);
    expect(report.samplesChecked).toBe(ADVERSARIAL_LOG_THREATS.length);
    expect(report.failures).toEqual([]);
  });

  it("certifies scrubValue against the realistic (key/size) battery", () => {
    expect(assertScrubberNeutralizes((v) => scrubValue(v), REALISTIC_LOG_THREATS).certified).toBe(
      true,
    );
  });

  it("neutralises a SECRET value hiding under an innocuous, sub-cap key", () => {
    const out = scrubValue({ note: `the token is ${SECRET} fyi` }) as Record<string, string>;
    expect(out.note).toContain(":secret");
    expect(out.note).not.toContain(SECRET);
    expect(findLogViolations(out)).toEqual([]);
  });

  it("neutralises a CODE body hiding under an innocuous, sub-cap key", () => {
    const out = scrubValue({ detail: CODE }) as Record<string, string>;
    expect(out.detail).toContain(":code");
    expect(out.detail).not.toContain("queryRawUnsafe");
    expect(findLogViolations(out)).toEqual([]);
  });

  it("still redacts by sensitive key name and by oversize", () => {
    const out = scrubValue({ password: "hunter2", blob: "A".repeat(2000) }) as Record<
      string,
      string
    >;
    expect(out.password).toBe(REDACTED);
    expect(out.blob).toContain(":oversize");
  });

  it("preserves benign metadata (numbers / booleans / short strings)", () => {
    const out = scrubValue({ scanId: "s1", latencyMs: 42, ok: true });
    expect(out).toEqual({ scanId: "s1", latencyMs: 42, ok: true });
  });

  it("scrubFields and createScrubber share the content guard", () => {
    expect(findLogViolations(scrubFields({ info: `leak ${SECRET}`, note: CODE }))).toEqual([]);
    const scrubber = createScrubber();
    expect(findLogViolations(scrubber.scrubValue({ x: SECRET, y: CODE }))).toEqual([]);
  });

  it("proves the gap: a content-BLIND scrubber passes realistic but LEAKS the adversarial battery", () => {
    // Same key/size logic telemetry had before hardening: fine for key/size threats…
    expect(assertScrubberNeutralizes(keyAndSizeOnly, REALISTIC_LOG_THREATS).certified).toBe(true);
    // …but it leaks a secret/code body hiding under an innocuous key.
    expect(() => assertScrubberNeutralizes(keyAndSizeOnly, ADVERSARIAL_LOG_THREATS)).toThrow(
      ScrubberCertificationError,
    );
  });
});
