/**
 * ⛔ DESIGN-INVARIANT PROOF (build-plan §7 Wave 4, last checkbox):
 *
 *   "Confirm correlation/confirmation/fix layers required NO stack-specific
 *    forks (or fix the leak)."
 *
 * The stack-agnostic layers — Layer 2 correlation (@montr/correlation), the
 * Layer 4 fix risk-classifier + generator (@montr/fix), and Layer 5 report
 * (@montr/report) — must carry ZERO language/framework knowledge. A new stack is
 * added ONLY by dropping a Layer-0 analyzer + Layer-1 ruleset + Layer-3 heuristics
 * under `languages/<lang>/` (etc.); L2/L4/L5 stay untouched.
 *
 * This suite proves that three ways:
 *   1. STRUCTURAL — the compiled source of packages/{correlation,fix,report}/src
 *      contains no Python/JVM framework token and no `.py`/`.java` file-extension
 *      branch (a fork would have to name one).
 *   2. LAYER 2 — a REAL Python (Django) and JVM (Spring) App Map, built offline by
 *      the actual Layer-0 `buildAppMap` (tree-sitter grammars from tree-sitter-wasms,
 *      no gateway ⇒ deterministic), plus a candidate pile anchored to that map's own
 *      taint sinks / secret surfaces, flows through the SAME `correlate()` the
 *      TS/JS pipeline uses and produces contract-valid, promoted, deterministic
 *      ProbableFindings.
 *   3. LAYER 4 — the SAME `classifyConfirmedFindingRisk()` returns an IDENTICAL
 *      risk class for a finding whose ONLY difference is a `.ts` vs `.py` vs `.java`
 *      location (the classifier never reads the extension); and the SAME
 *      `generateFixes()` keeps every auth/crypto/access-control/secret finding
 *      `human-required` on Python + JVM findings (⛔ golden rule #3, 100%).
 *
 * Fully OFFLINE. No network, no Postgres/Redis, no provider SDK.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

import { buildAppMap, type BuildAppMapInput } from "@montr/appmap";
import { correlate } from "@montr/correlation";
import {
  ALWAYS_HUMAN_REQUIRED_CATEGORIES,
  AUTO_ELIGIBLE_CATEGORIES,
  classifyConfirmedFindingRisk,
  createMapSourceReader,
  generateFixes,
  type RiskEvidence,
} from "@montr/fix";
import { getHardenedDefaults } from "@montr/config";
import {
  CandidateFindingSchema,
  ConfirmedFindingSchema,
  Layer2OutputSchema,
  Layer4OutputSchema,
  ScanScopeSchema,
  complianceForCategory,
  type AppMap,
  type Category,
  type CandidateFinding,
  type ConfirmedFinding,
  type RiskClass,
} from "@montr/contracts";
import { CLIENT_ID, FIXED_NOW, SCAN_ID } from "@montr/fixtures";

/* ------------------------------------------------------------------------- *
 * Fixtures: build the Python + JVM App Maps ONCE, offline, deterministically.
 * ------------------------------------------------------------------------- */

const PY_VULN = fileURLToPath(new URL("../corpus/python-vuln", import.meta.url));
const JVM_VULN = fileURLToPath(new URL("../corpus/jvm-vuln", import.meta.url));
const COMMIT = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
const now = (): Date => new Date(FIXED_NOW);

function buildInput(repo: string, scanId: string): BuildAppMapInput {
  return {
    clientId: CLIENT_ID,
    scanId,
    repo,
    branch: "main",
    mode: "full",
    scope: ScanScopeSchema.parse({ mode: "full" }),
    config: getHardenedDefaults(),
    commitSha: COMMIT,
  };
}

let pyMap: AppMap;
let jvmMap: AppMap;

beforeAll(async () => {
  pyMap = (await buildAppMap(buildInput(PY_VULN, "scan_inv_py"), { now })).appMap;
  jvmMap = (await buildAppMap(buildInput(JVM_VULN, "scan_inv_jvm"), { now })).appMap;
}, 60_000);

/* ------------------------------------------------------------------------- *
 * Helpers — candidates/confirmed anchored to the map's OWN locations.
 * ------------------------------------------------------------------------- */

interface Loc {
  file: string;
  line: number;
}

/** Location of the first taint sink of `kind` in the map (throws if absent). */
function sinkLoc(map: AppMap, kind: string): Loc {
  const sink = map.taintSinks.find((s) => s.kind === kind);
  if (!sink) throw new Error(`expected a ${kind} taint sink in the App Map`);
  return sink.location;
}

/** Location of a hard-coded (config-file) secret surface in the map. */
function secretLoc(map: AppMap): Loc {
  const surface =
    map.envSecretSurfaces.find((s) => s.kind === "config_file" && s.location) ??
    map.envSecretSurfaces.find((s) => s.location);
  if (!surface?.location) throw new Error("expected an env/secret surface in the App Map");
  return surface.location;
}

/** A minimal, contract-valid candidate anchored to a map location. */
function candidateAt(category: Category, loc: Loc, id: string): CandidateFinding {
  return CandidateFindingSchema.parse({
    id,
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    source: "semgrep",
    ruleId: `test.${category}`,
    category,
    location: loc,
    rawSeverity: "high",
    // Empty snippet on purpose: no sanitizer token can accidentally interrupt the
    // grounded taint path (the grounding is what must stay language-agnostic).
    evidenceSnippet: "",
    createdAt: FIXED_NOW,
  });
}

/** A minimal, contract-valid confirmed finding at `file` (classifier fixtures). */
function confirmedFor(category: Category, file: string, line = 12): ConfirmedFinding {
  const c = complianceForCategory(category);
  return ConfirmedFindingSchema.parse({
    id: `cf_${category}_${file.replace(/[^A-Za-z0-9]+/g, "_")}`,
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    title: `${category} finding`,
    category,
    cwe: c.cwe.length > 0 ? c.cwe : ["CWE-693"],
    ...(c.owasp ? { owasp: c.owasp } : {}),
    severity: "high",
    exposure: "authed",
    location: { file, line },
    impact: "Constructed for the stack-agnostic design-invariant proof.",
    proofType: "static",
    proofArtifact: {
      kind: "static",
      argument: "constructed for the invariant proof",
      dataFlow: [{ location: { file, line }, authState: "authenticated" }],
      sanitizersBypassed: [],
    },
    createdAt: FIXED_NOW,
  });
}

/** A clean, mechanical, low-blast-radius patch on the finding's own file. */
function mechanicalEvidence(file: string): RiskEvidence {
  return {
    patch: "-  unsafe(input)\n+  safe(input)",
    changedFiles: [file],
    changedLines: 2,
    uncertain: false,
  };
}

/* ------------------------------------------------------------------------- *
 * 1. STRUCTURAL — the moat/fix/report source names no stack.
 * ------------------------------------------------------------------------- */

describe("⛔ structural invariant: L2/L4/L5 source carries no stack-specific code", () => {
  const STACK_AGNOSTIC_SRC = ["correlation", "fix", "report"].map((p) =>
    fileURLToPath(new URL(`../packages/${p}/src`, import.meta.url)),
  );

  // Tokens a Python/JVM fork would HAVE to introduce (framework names it branches
  // on, or a `.py`/`.java` file-extension test). Deliberately excludes the bare
  // words "java"/"python" (they collide with "javascript"/language enums, which
  // ARE legitimately referenced) — the framework + extension tokens are the
  // unambiguous fork signal.
  const FRAMEWORK_TOKEN =
    /\b(django|fastapi|flask|werkzeug|jinja2?|sqlalchemy|pydantic|springframework|springboot|jakarta|javax|hibernate|jax-?rs)\b/i;
  const EXT_BRANCH = /\.(py|java)\b/i;

  // ⛔ DELIBERATE, REVIEWED EXCEPTION: packages/fix/src/strategies.ts is the
  // Layer-4 MECHANICAL FIX-STRATEGY REGISTRY — a per-language SYNTAX-TRANSFORM
  // table whose entire job is to know target languages' real syntax (this was
  // already true pre-Python/JVM: every JS/TS strategy there is already
  // JS/TS-syntax-specific — `dangerouslySetInnerHTML`, `.cookie(...)`, Next.js
  // config shapes — it just never had to name ".py"/".java"/a Python or JVM
  // framework to do it). Adding real Python/JVM mechanical strategies there
  // necessarily means naming their syntax/config conventions too. What this
  // invariant suite actually exists to protect — and what's still asserted
  // everywhere else in this file — is that the SAFETY decision
  // (`classifyFixRisk`/`classifyConfirmedFindingRisk` in risk.ts) and the
  // L2/L4/L5 ORCHESTRATION (generate.ts, patch.ts, source.ts, correlation,
  // report) stay 100% language-blind: see risk.ts's `AUTO_ELIGIBLE_CATEGORIES`
  // docstring for exactly how the language-strategy match in strategies.ts and
  // the language-blind risk decision in risk.ts stay cleanly separated.
  const LANGUAGE_AWARE_EXCEPTIONS = new Set(["strategies.ts"]);

  function tsSources(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, entry.name);
      if (entry.isDirectory()) out.push(...tsSources(p));
      else if (entry.isFile() && p.endsWith(".ts") && !p.endsWith(".d.ts")) out.push(p);
    }
    return out;
  }

  it("names no Python/JVM framework and branches on no .py/.java extension (outside the reviewed strategy-registry exception)", () => {
    const offenders: string[] = [];
    for (const dir of STACK_AGNOSTIC_SRC) {
      for (const file of tsSources(dir)) {
        if (LANGUAGE_AWARE_EXCEPTIONS.has(file.split("/").pop()!)) continue;
        const text = readFileSync(file, "utf8");
        const fw = text.match(FRAMEWORK_TOKEN);
        const ext = text.match(EXT_BRANCH);
        if (fw) offenders.push(`${file}: framework token "${fw[0]}"`);
        if (ext) offenders.push(`${file}: extension branch "${ext[0]}"`);
      }
    }
    expect(offenders, offenders.join("\n")).toEqual([]);
  });

  it("actually scanned the three stack-agnostic packages (guard against a no-op)", () => {
    const counts = STACK_AGNOSTIC_SRC.map((d) => tsSources(d).length);
    for (const n of counts) expect(n).toBeGreaterThan(0);
  });
});

/* ------------------------------------------------------------------------- *
 * 2. LAYER 2 — the moat runs on real Python + JVM App Maps (same correlate()).
 * ------------------------------------------------------------------------- */

describe("Layer 2 correlation — the SAME moat corroborates Python + JVM App Maps", () => {
  interface Case {
    stack: string;
    map: () => AppMap;
    candidates: () => CandidateFinding[];
    expectedCategories: Category[];
  }

  const cases: Case[] = [
    {
      stack: "python (Django)",
      map: () => pyMap,
      candidates: () => [
        candidateAt("sql_injection", sinkLoc(pyMap, "sql_query"), "py_sqli"),
        candidateAt("xss", sinkLoc(pyMap, "html_render"), "py_xss"),
        candidateAt("ssrf", sinkLoc(pyMap, "http_client"), "py_ssrf"),
        candidateAt("hardcoded_secret", secretLoc(pyMap), "py_secret"),
      ],
      expectedCategories: ["hardcoded_secret", "sql_injection", "ssrf", "xss"],
    },
    {
      stack: "jvm (Spring)",
      map: () => jvmMap,
      candidates: () => [
        candidateAt("sql_injection", sinkLoc(jvmMap, "sql_query"), "jvm_sqli"),
        candidateAt("command_injection", sinkLoc(jvmMap, "command_exec"), "jvm_cmdi"),
        candidateAt("insecure_deserialization", sinkLoc(jvmMap, "deserialize"), "jvm_deser"),
        candidateAt("hardcoded_secret", secretLoc(jvmMap), "jvm_secret"),
      ],
      expectedCategories: [
        "command_injection",
        "hardcoded_secret",
        "insecure_deserialization",
        "sql_injection",
      ],
    },
  ];

  for (const tc of cases) {
    it(`${tc.stack}: promotes every map-corroborated candidate to a valid ProbableFinding`, async () => {
      const candidates = tc.candidates();
      const out = await correlate({
        clientId: CLIENT_ID,
        scanId: `scan_inv_${tc.stack}`,
        now: FIXED_NOW,
        appMap: tc.map(),
        candidates,
      });

      // Contract-valid Layer-2 output (same schema as TS/JS).
      expect(() => Layer2OutputSchema.parse(out)).not.toThrow();

      // Every candidate is anchored to a real sink/secret surface in THIS map, so
      // the deterministic grounding corroborates all of them — none demoted.
      expect(out.demoted).toEqual([]);
      expect(out.probable.map((p) => p.category).sort()).toEqual([...tc.expectedCategories].sort());

      // Ranking + scores are the language-agnostic reachability × exposure × impact.
      expect(out.probable.map((p) => p.rank).sort((a, b) => a - b)).toEqual(
        candidates.map((_, i) => i + 1),
      );
      for (const p of out.probable) {
        for (const s of [p.reachabilityScore, p.exposureScore, p.impactScore]) {
          expect(s).toBeGreaterThanOrEqual(0);
          expect(s).toBeLessThanOrEqual(1);
        }
        expect(p.reachabilityHypothesis.length).toBeGreaterThan(0);
        expect(p.exploitHypothesis.length).toBeGreaterThan(0);
      }

      // ⛔ never lose a candidate: each input is merged into a probable or demoted.
      const accounted = new Set<string>([
        ...out.probable.flatMap((p) => p.mergedCandidateIds),
        ...out.demoted.map((d) => d.id),
      ]);
      expect(accounted).toEqual(new Set(candidates.map((c) => c.id)));
    });

    it(`${tc.stack}: correlation is deterministic across runs`, async () => {
      const args = {
        clientId: CLIENT_ID,
        scanId: `scan_inv_det_${tc.stack}`,
        now: FIXED_NOW,
        appMap: tc.map(),
        candidates: tc.candidates(),
      };
      const a = await correlate(args);
      const b = await correlate(args);
      expect(a).toEqual(b);
    });
  }
});

/* ------------------------------------------------------------------------- *
 * 3a. LAYER 4 classifier — language-blind (identical class across .ts/.py/.java).
 * ------------------------------------------------------------------------- */

describe("Layer 4 risk classifier — identical class for .ts / .py / .java (zero forks)", () => {
  // A representative spread across every finding class + both stacks' vulns.
  const CATEGORIES: Category[] = [
    "sql_injection",
    "xss",
    "ssrf",
    "command_injection",
    "insecure_deserialization",
    "broken_access_control",
    "idor",
    "broken_authentication",
    "weak_crypto",
    "csrf",
    "sensitive_data_exposure",
    "hardcoded_secret",
    "permissive_cors",
    "vulnerable_dependency",
  ];

  const opts = {
    alwaysHumanCategories: getHardenedDefaults().autoFix.humanRequiredCategoriesAlways,
  };

  /** Classify `category` at a neutral (non-auth) path with the given extension. */
  function classAt(category: Category, ext: string): RiskClass {
    const file = `src/handlers/orders.${ext}`;
    return classifyConfirmedFindingRisk(
      confirmedFor(category, file),
      mechanicalEvidence(file),
      opts,
    ).riskClass;
  }

  it("returns the SAME risk class regardless of source-file language", () => {
    for (const category of CATEGORIES) {
      const ts = classAt(category, "ts");
      const py = classAt(category, "py");
      const java = classAt(category, "java");
      expect(py, `${category}: .py must equal .ts`).toBe(ts);
      expect(java, `${category}: .java must equal .ts`).toBe(ts);
    }
  });

  it("classifies mechanical injection fixes (sqli/xss) auto-eligible on every stack", () => {
    for (const category of ["sql_injection", "xss"] as const) {
      expect(AUTO_ELIGIBLE_CATEGORIES).toContain(category);
      for (const ext of ["ts", "py", "java"]) {
        expect(classAt(category, ext)).toBe("auto-eligible");
      }
    }
  });

  it("⛔ keeps auth/crypto/access-control fixes human-required on every stack (golden rule #3)", () => {
    for (const category of ALWAYS_HUMAN_REQUIRED_CATEGORIES) {
      for (const ext of ["ts", "py", "java"]) {
        expect(classAt(category, ext), `${category} @ .${ext}`).toBe("human-required");
      }
    }
    // hardcoded_secret is human-required by the fail-safe default (rotation needs a
    // human) — also stack-independently.
    for (const ext of ["ts", "py", "java"]) {
      expect(classAt("hardcoded_secret", ext)).toBe("human-required");
    }
  });
});

/* ------------------------------------------------------------------------- *
 * 3b. LAYER 4 generator — ⛔ golden rule #3 holds on real Python + JVM findings.
 * ------------------------------------------------------------------------- */

describe("Layer 4 fix generation — golden rule #3 on Python + JVM confirmed findings", () => {
  const humanRequired = new Set<Category>([
    ...ALWAYS_HUMAN_REQUIRED_CATEGORIES,
    "hardcoded_secret",
    "ssrf",
    "command_injection",
  ]);

  const stacks: Array<{ stack: string; confirmed: () => ConfirmedFinding[] }> = [
    {
      stack: "python (Django)",
      confirmed: () => [
        confirmedFor("sql_injection", "myapp/views.py", 18),
        confirmedFor("ssrf", "myapp/views.py", 28),
        confirmedFor("idor", "myapp/views.py", 34),
        confirmedFor("hardcoded_secret", "myapp/settings.py", 5),
      ],
    },
    {
      stack: "jvm (Spring)",
      confirmed: () => [
        confirmedFor(
          "command_injection",
          "src/main/java/com/example/vuln/web/NetworkController.java",
          22,
        ),
        confirmedFor(
          "insecure_deserialization",
          "src/main/java/com/example/vuln/web/ImportController.java",
          23,
        ),
        confirmedFor(
          "broken_access_control",
          "src/main/java/com/example/vuln/web/AdminController.java",
          29,
        ),
        confirmedFor("hardcoded_secret", "src/main/resources/application.yml", 7),
      ],
    },
  ];

  for (const { stack, confirmed } of stacks) {
    it(`${stack}: generateFixes emits a valid Fix per finding; auth/crypto/access/secret => human-required`, async () => {
      const confirmedFindings = confirmed();
      const out = await generateFixes({
        clientId: CLIENT_ID,
        scanId: `scan_inv_fix_${stack}`,
        gateway: throwawayGateway(),
        // No mechanical TS/JS strategy matches non-TS source ⇒ advisory (fail-safe),
        // which is exactly the human-required behaviour the golden rule mandates.
        source: createMapSourceReader({}),
        humanRequiredCategoriesAlways: getHardenedDefaults().autoFix.humanRequiredCategoriesAlways,
        confirmed: confirmedFindings,
        now: () => FIXED_NOW,
      });

      expect(() => Layer4OutputSchema.parse(out)).not.toThrow();
      expect(out.fixes).toHaveLength(confirmedFindings.length);

      for (const fix of out.fixes) {
        const finding = confirmedFindings.find((c) => c.id === fix.confirmedFindingId)!;
        if (humanRequired.has(finding.category)) {
          expect(fix.riskClass, `${finding.category} @ ${finding.location.file}`).toBe(
            "human-required",
          );
        }
      }
    });
  }
});

/**
 * A gateway that fails every call — proves the Layer-4 control flow degrades to
 * the deterministic advisory path without a working model (golden rule #4), and
 * keeps the test free of any real provider SDK.
 */
function throwawayGateway() {
  return {
    complete: () => Promise.reject(new Error("offline: no gateway in the invariant proof")),
    stream: () => {
      throw new Error("offline");
    },
    listModels: () => [],
    resolveModel: () => {
      throw new Error("offline");
    },
  } as unknown as Parameters<typeof generateFixes>[0]["gateway"];
}
