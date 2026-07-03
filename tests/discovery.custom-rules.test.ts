import { describe, it, expect, vi } from "vitest";
import type { CustomRule } from "@montr/contracts";
import {
  validateCustomRule,
  validateSemgrepStructure,
  customRuleToDetector,
  loadCustomRules,
  type SemgrepValidateRunner,
} from "@montr/discovery";

/**
 * Phase-4 custom rule authoring (§16). ⛔ A rule is VALIDATED before it may be
 * enabled/used. Semgrep rules get a structural YAML check + (when available) a
 * real `semgrep --validate` pass; secret detectors are validated by compiling
 * their regex. Enabled rules LOAD alongside the curated rulesets. Fully offline —
 * the semgrep subprocess is mocked.
 */

const VALID_SEMGREP = `rules:
  - id: no-eval
    languages: [typescript]
    severity: ERROR
    message: Avoid eval()
    pattern: eval(...)
`;

const STRUCTURALLY_BROKEN_SEMGREP = `rules:
  - id: broken-rule
    languages: [typescript]
`; // missing message + a matcher

function ruleOf(overrides: Partial<CustomRule>): CustomRule {
  return {
    id: overrides.id ?? "rule_1",
    clientId: "client_1",
    name: overrides.name ?? "rule",
    language: overrides.language ?? "typescript",
    engine: overrides.engine ?? "semgrep",
    body: overrides.body ?? VALID_SEMGREP,
    version: overrides.version ?? 1,
    enabled: overrides.enabled ?? false,
    createdBy: "user_1",
    createdAt: "2026-07-03T00:00:00.000Z",
  };
}

describe("validateCustomRule — semgrep", () => {
  it("accepts a structurally valid rule and runs the injected --validate pass", async () => {
    const runner = vi.fn<SemgrepValidateRunner>(async () => ({ ok: true, errors: [] }));
    const res = await validateCustomRule(
      { engine: "semgrep", language: "typescript", body: VALID_SEMGREP },
      { semgrepValidator: runner },
    );
    expect(res.valid).toBe(true);
    expect(res.errors).toEqual([]);
    expect(runner).toHaveBeenCalledOnce();
  });

  it("rejects a structurally broken rule WITHOUT shelling out (fail-fast)", async () => {
    const runner = vi.fn<SemgrepValidateRunner>(async () => ({ ok: true, errors: [] }));
    const res = await validateCustomRule(
      { engine: "semgrep", language: "typescript", body: STRUCTURALLY_BROKEN_SEMGREP },
      { semgrepValidator: runner },
    );
    expect(res.valid).toBe(false);
    expect(res.errors.join(" ")).toMatch(/message is required|needs a matcher/);
    expect(runner).not.toHaveBeenCalled();
  });

  it("surfaces semgrep --validate errors as invalid", async () => {
    const runner = vi.fn<SemgrepValidateRunner>(async () => ({
      ok: false,
      errors: ["invalid pattern syntax"],
    }));
    const res = await validateCustomRule(
      { engine: "semgrep", language: "typescript", body: VALID_SEMGREP },
      { semgrepValidator: runner },
    );
    expect(res.valid).toBe(false);
    expect(res.errors).toContain("invalid pattern syntax");
  });

  it("degrades to structural-only with a warning when the binary is unavailable (runner → null)", async () => {
    const runner = vi.fn<SemgrepValidateRunner>(async () => null);
    const res = await validateCustomRule(
      { engine: "semgrep", language: "typescript", body: VALID_SEMGREP },
      { semgrepValidator: runner },
    );
    expect(res.valid).toBe(true);
    expect(res.warnings.join(" ")).toMatch(/semgrep binary unavailable/i);
  });

  it("useSubprocess:false skips the subprocess entirely", async () => {
    const runner = vi.fn<SemgrepValidateRunner>(async () => ({ ok: false, errors: ["x"] }));
    const res = await validateCustomRule(
      { engine: "semgrep", language: "typescript", body: VALID_SEMGREP },
      { semgrepValidator: runner, useSubprocess: false },
    );
    expect(res.valid).toBe(true);
    expect(runner).not.toHaveBeenCalled();
  });

  it("rejects invalid YAML", () => {
    const res = validateSemgrepStructure(":\n  - not: [valid");
    expect(res.valid).toBe(false);
    expect(res.errors.join(" ")).toMatch(/invalid YAML|non-empty 'rules'/);
  });
});

describe("validateCustomRule — secret detectors", () => {
  it("accepts a bare regex", async () => {
    const res = await validateCustomRule({
      engine: "secret",
      language: "typescript",
      body: "sk_custom_[0-9a-z]{16}",
    });
    expect(res.valid).toBe(true);
  });

  it("accepts a JSON object with a pattern", async () => {
    const res = await validateCustomRule({
      engine: "secret",
      language: "typescript",
      body: '{"pattern":"AKIA[0-9A-Z]{16}","name":"custom AWS key"}',
    });
    expect(res.valid).toBe(true);
  });

  it("rejects an uncompilable regex", async () => {
    const res = await validateCustomRule({
      engine: "secret",
      language: "typescript",
      body: "sk_custom_[0-9a-z", // unbalanced class
    });
    expect(res.valid).toBe(false);
    expect(res.errors.join(" ")).toMatch(/invalid secret-detector regex/i);
  });

  it("rejects a JSON object missing a pattern", async () => {
    const res = await validateCustomRule({
      engine: "secret",
      language: "typescript",
      body: '{"name":"no pattern here"}',
    });
    expect(res.valid).toBe(false);
  });
});

describe("customRuleToDetector — redacts matched values (golden rule #1)", () => {
  it("compiles an enabled secret rule into a detector that never stores the value", () => {
    const rule = ruleOf({
      engine: "secret",
      enabled: true,
      body: "sk_custom_[0-9a-z]{16}",
      name: "cust",
    });
    const detector = customRuleToDetector(rule);
    expect(detector).not.toBeNull();
    const hits = detector!({
      path: "src/config.ts",
      content: "const k = 'sk_custom_abcdef0123456789';",
    });
    expect(hits).toHaveLength(1);
    expect(hits[0]!.category).toBe("hardcoded_secret");
    // ⛔ the raw secret value is never present in the finding.
    expect(JSON.stringify(hits[0])).not.toContain("sk_custom_abcdef0123456789");
    expect(hits[0]!.snippet).toMatch(/redacted/i);
  });

  it("returns null for a semgrep-engine rule (those load via --config, not a detector)", () => {
    expect(customRuleToDetector(ruleOf({ engine: "semgrep" }))).toBeNull();
  });
});

describe("loadCustomRules — only enabled rules feed a scan (fail-safe)", () => {
  it("partitions enabled semgrep + secret rules and skips disabled drafts", () => {
    const rules: CustomRule[] = [
      ruleOf({ id: "a", engine: "semgrep", enabled: true }),
      ruleOf({ id: "b", engine: "secret", enabled: true, body: "TOK_[A-Z0-9]{10}" }),
      ruleOf({ id: "c", engine: "semgrep", enabled: false }), // disabled draft
    ];
    const loaded = loadCustomRules(rules);
    expect(loaded.semgrepRules.map((r) => r.id)).toEqual(["a"]);
    expect(loaded.secretDetectors).toHaveLength(1);
    expect(loaded.skipped).toEqual([{ id: "c", reason: "disabled" }]);
  });
});
