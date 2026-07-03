/**
 * Custom rule authoring support (Phase-4 / Wave 5, PRD §16, build-plan §8).
 *
 * Two responsibilities, both fully offline-testable:
 *   1. ⛔ VALIDATE a client-authored rule BEFORE it may be enabled (golden rule:
 *      "custom rules are validated before use"). Semgrep rules get a structural
 *      YAML check plus, when the binary is available, a real `semgrep --validate`
 *      pass (injectable; degrades to structural-only offline). Secret detectors
 *      are validated by compiling their regex.
 *   2. LOAD enabled custom rules so discovery runs them ALONGSIDE the curated
 *      rulesets — semgrep rules as extra `--config` bodies, secret rules compiled
 *      into {@link FileDetector}s passed via `detectSecretsAndConfig`'s
 *      `extraDetectors` seam. No detector or `runDiscovery` change is required.
 *
 * A custom rule `body` is rule SOURCE (Semgrep YAML / secret-detector definition),
 * never a credential; matched secret VALUES are still redacted at detection time
 * (golden rule #1), exactly like the built-in secret detectors.
 */
import type {
  Category,
  CustomRule,
  CustomRuleValidation,
  Language,
  Severity,
} from "@montr/contracts";
import { parse as parseYaml } from "yaml";
import type { FileDetector, RawFinding } from "./detectors/secrets.js";
import type { RepoFile } from "./util/files.js";
import { errMessage, isBinaryMissing } from "./util/text.js";

/* ============================== validation ============================== */

export interface SemgrepValidateInput {
  /** The Semgrep rule YAML body to validate. */
  body: string;
  signal?: AbortSignal;
}
export interface SemgrepValidateOutcome {
  ok: boolean;
  errors: string[];
}
/**
 * Runs `semgrep --validate` against a rule body. Returns `null` when the semgrep
 * binary is unavailable (validation then degrades to the structural check).
 * Injected in tests; the default shells out.
 */
export type SemgrepValidateRunner = (
  input: SemgrepValidateInput,
) => Promise<SemgrepValidateOutcome | null>;

export interface ValidateCustomRuleOptions {
  /** Injected `semgrep --validate` runner (semgrep engine only). */
  semgrepValidator?: SemgrepValidateRunner;
  /**
   * Run the semgrep subprocess validator after the structural check passes.
   * Default true; set false to force pure-structural validation (offline).
   */
  useSubprocess?: boolean;
  signal?: AbortSignal;
}

const SEMGREP_PATTERN_KEYS = [
  "pattern",
  "patterns",
  "pattern-either",
  "pattern-regex",
  "pattern-sources",
  "pattern-sinks",
] as const;
const SEMGREP_SEVERITIES = new Set(["ERROR", "WARNING", "INFO"]);

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

/** Structural validation of a Semgrep rule YAML (no subprocess). */
export function validateSemgrepStructure(body: string): CustomRuleValidation {
  const errors: string[] = [];
  const warnings: string[] = [];

  let doc: unknown;
  try {
    doc = parseYaml(body);
  } catch (err) {
    return { valid: false, errors: [`invalid YAML: ${errMessage(err)}`], warnings };
  }
  if (!doc || typeof doc !== "object") {
    return {
      valid: false,
      errors: ["rule must be a YAML mapping with a top-level 'rules:' list"],
      warnings,
    };
  }
  const rules = (doc as { rules?: unknown }).rules;
  if (!Array.isArray(rules) || rules.length === 0) {
    errors.push("missing a non-empty 'rules:' array");
    return { valid: false, errors, warnings };
  }
  rules.forEach((raw, i) => {
    if (!raw || typeof raw !== "object") {
      errors.push(`rules[${i}] must be a mapping`);
      return;
    }
    const r = raw as Record<string, unknown>;
    if (!isNonEmptyString(r["id"])) errors.push(`rules[${i}].id is required`);
    const hasPattern = SEMGREP_PATTERN_KEYS.some((k) => k in r) || r["mode"] === "taint";
    if (!hasPattern) {
      errors.push(
        `rules[${i}] needs a matcher (pattern / patterns / pattern-either / pattern-regex) or taint mode`,
      );
    }
    if (!isNonEmptyString(r["message"])) errors.push(`rules[${i}].message is required`);
    const severity = r["severity"];
    if (severity !== undefined && !SEMGREP_SEVERITIES.has(String(severity))) {
      errors.push(`rules[${i}].severity must be one of ERROR | WARNING | INFO`);
    } else if (severity === undefined) {
      warnings.push(`rules[${i}] has no explicit severity (semgrep defaults may apply)`);
    }
    const languages = r["languages"];
    if (languages !== undefined && !Array.isArray(languages)) {
      errors.push(`rules[${i}].languages must be a list`);
    }
  });

  return { valid: errors.length === 0, errors, warnings };
}

/** Parsed secret-detector rule (bare regex string OR a small JSON object). */
interface ParsedSecretRule {
  pattern: string;
  name?: string;
  severity?: Severity;
  category?: Category;
}

function parseSecretRule(body: string): { rule?: ParsedSecretRule; error?: string } {
  const trimmed = body.trim();
  if (trimmed.length === 0) return { error: "secret rule body is empty" };
  if (trimmed.startsWith("{")) {
    let obj: unknown;
    try {
      obj = JSON.parse(trimmed);
    } catch (err) {
      return { error: `secret rule looks like JSON but failed to parse: ${errMessage(err)}` };
    }
    const o = obj as Record<string, unknown>;
    if (!isNonEmptyString(o["pattern"])) {
      return { error: "secret rule object requires a non-empty 'pattern'" };
    }
    return {
      rule: {
        pattern: o["pattern"],
        ...(isNonEmptyString(o["name"]) ? { name: o["name"] } : {}),
        ...(isNonEmptyString(o["severity"]) ? { severity: o["severity"] as Severity } : {}),
        ...(isNonEmptyString(o["category"]) ? { category: o["category"] as Category } : {}),
      },
    };
  }
  return { rule: { pattern: trimmed } };
}

/** Structural validation of a secret-detector rule (compiles the regex). */
export function validateSecretStructure(body: string): CustomRuleValidation {
  const { rule, error } = parseSecretRule(body);
  if (error || !rule)
    return { valid: false, errors: [error ?? "invalid secret rule"], warnings: [] };
  try {
    new RegExp(rule.pattern);
  } catch (err) {
    return {
      valid: false,
      errors: [`invalid secret-detector regex: ${errMessage(err)}`],
      warnings: [],
    };
  }
  const warnings: string[] = [];
  if (/^(\.\*|\.\+)/.test(rule.pattern) || /(\.\*|\.\+)$/.test(rule.pattern)) {
    warnings.push(
      "regex is very broad (leading/trailing .* / .+) — it may over-match and be noisy",
    );
  }
  return { valid: true, errors: [], warnings };
}

/**
 * Default `semgrep --validate` runner — writes the body to a temp file and shells
 * out. Returns `null` when the binary is missing (degrade to structural-only).
 */
export const defaultSemgrepValidateRunner: SemgrepValidateRunner = async ({ body, signal }) => {
  const { execa } = await import("execa");
  const os = await import("node:os");
  const fs = await import("node:fs/promises");
  const nodePath = await import("node:path");
  const { randomUUID } = await import("node:crypto");
  const file = nodePath.join(os.tmpdir(), `montr-custom-rule-${randomUUID()}.yaml`);
  try {
    await fs.writeFile(file, body, "utf8");
    const res = await execa(
      "semgrep",
      ["--validate", "--config", file, "--quiet", "--disable-version-check", "--metrics=off"],
      { reject: false, signal, timeout: 60_000 },
    );
    const errors =
      res.exitCode === 0
        ? []
        : [String(res.stderr || res.stdout || "semgrep validation failed").slice(0, 2000)];
    return { ok: res.exitCode === 0, errors };
  } catch (err) {
    if (isBinaryMissing(err)) return null; // binary absent → structural-only
    throw err;
  } finally {
    await fs.rm(file, { force: true }).catch(() => undefined);
  }
};

/**
 * ⛔ Validate a custom rule before it may be enabled. Structural checks always
 * run; for semgrep rules a real `semgrep --validate` pass runs when available
 * (injectable), else validation degrades to structural-only with a warning.
 */
export async function validateCustomRule(
  rule: Pick<CustomRule, "engine" | "language" | "body">,
  opts: ValidateCustomRuleOptions = {},
): Promise<CustomRuleValidation> {
  if (rule.engine === "secret") return validateSecretStructure(rule.body);

  // semgrep engine.
  const structural = validateSemgrepStructure(rule.body);
  if (!structural.valid || opts.useSubprocess === false) return structural;

  const runner = opts.semgrepValidator ?? defaultSemgrepValidateRunner;
  let outcome: SemgrepValidateOutcome | null;
  try {
    outcome = await runner({ body: rule.body, ...(opts.signal ? { signal: opts.signal } : {}) });
  } catch (err) {
    return {
      valid: false,
      errors: [...structural.errors, `semgrep --validate failed: ${errMessage(err)}`],
      warnings: structural.warnings,
    };
  }
  if (outcome === null) {
    return {
      valid: structural.valid,
      errors: structural.errors,
      warnings: [
        ...structural.warnings,
        "semgrep binary unavailable — used structural validation only",
      ],
    };
  }
  return {
    valid: structural.valid && outcome.ok,
    errors: [...structural.errors, ...outcome.errors],
    warnings: structural.warnings,
  };
}

/* ================================ loading ================================ */

function lineAt(content: string, index: number): number {
  let line = 1;
  const end = Math.min(index, content.length);
  for (let i = 0; i < end; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

function maskSecret(value: string): string {
  const v = value.trim();
  if (v.length <= 4) return "****";
  return `${v.slice(0, 4)}…[REDACTED]`;
}

/**
 * Compile an ENABLED secret custom rule into a {@link FileDetector}. Returns null
 * for non-secret engines or an uncompilable regex (defensive — such a rule should
 * have failed validation before being enabled). Matched values are redacted.
 */
export function customRuleToDetector(rule: CustomRule): FileDetector | null {
  if (rule.engine !== "secret") return null;
  const { rule: parsed } = parseSecretRule(rule.body);
  if (!parsed) return null;
  let compiled: RegExp;
  try {
    compiled = new RegExp(parsed.pattern, "g");
  } catch {
    return null;
  }
  const ruleId = `custom.${rule.id}`;
  const category: Category = parsed.category ?? "hardcoded_secret";
  const severity: Severity = parsed.severity ?? "high";
  const title = parsed.name ?? `Custom secret rule: ${rule.name}`;
  return (file: RepoFile): RawFinding[] => {
    const out: RawFinding[] = [];
    const re = new RegExp(
      compiled.source,
      compiled.flags.includes("g") ? compiled.flags : `${compiled.flags}g`,
    );
    let m: RegExpExecArray | null;
    while ((m = re.exec(file.content)) !== null) {
      out.push({
        source: "custom",
        rule: ruleId,
        category,
        severity,
        line: lineAt(file.content, m.index),
        // ⛔ never store the matched value — redacted, metadata-grade only.
        snippet: `custom secret rule '${rule.name}' matched (value redacted: ${maskSecret(m[0])})`,
        title,
        metadata: {
          detector: "custom-rule",
          ruleId: rule.id,
          ruleName: rule.name,
          engine: "secret",
        },
      });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
    return out;
  };
}

/** An enabled semgrep custom rule ready to be materialized as a `--config` file. */
export interface LoadedSemgrepRule {
  id: string;
  name: string;
  language: Language;
  /** Rule YAML body — write to a temp `.yaml` and pass to `semgrep --config`. */
  body: string;
}

export interface LoadedCustomRules {
  /** Enabled semgrep rules (feed as extra `semgrepRulesets` config paths/bodies). */
  semgrepRules: LoadedSemgrepRule[];
  /** Enabled secret rules compiled to detectors (pass as `extraDetectors`). */
  secretDetectors: FileDetector[];
  /** Rules skipped (disabled, or a secret rule that would not compile). */
  skipped: { id: string; reason: string }[];
}

/**
 * Partition a client's custom rules into the shapes discovery consumes. Only
 * ENABLED rules are loaded (disabled drafts never feed a scan — fail-safe). The
 * caller (the discovery/worker wiring) materializes semgrep bodies to temp config
 * files and merges the returned detectors into `detectSecretsAndConfig`.
 */
export function loadCustomRules(rules: readonly CustomRule[]): LoadedCustomRules {
  const semgrepRules: LoadedSemgrepRule[] = [];
  const secretDetectors: FileDetector[] = [];
  const skipped: { id: string; reason: string }[] = [];
  for (const rule of rules) {
    if (!rule.enabled) {
      skipped.push({ id: rule.id, reason: "disabled" });
      continue;
    }
    if (rule.engine === "semgrep") {
      semgrepRules.push({ id: rule.id, name: rule.name, language: rule.language, body: rule.body });
      continue;
    }
    const detector = customRuleToDetector(rule);
    if (detector) secretDetectors.push(detector);
    else skipped.push({ id: rule.id, reason: "secret rule regex would not compile" });
  }
  return { semgrepRules, secretDetectors, skipped };
}
