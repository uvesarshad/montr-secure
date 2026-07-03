/**
 * Python (Django / FastAPI / Flask) App-Map analyzer — offline corpus test.
 *
 * Runs the real {@link pythonAnalyzer} against `corpus/python-vuln` (planted
 * SQLi, reflected XSS, SSRF, IDOR, hard-coded secret) and `corpus/python-clean`
 * (the secured counterpart). Everything is offline: the `tree-sitter-python`
 * grammar loads from `tree-sitter-wasms`, no network, no LLM (golden rule #6).
 * The assertions couple the analyzer's emitted taint-sink descriptions to the
 * substrings the Layer-3 Python confirmation heuristics key off, so the App-Map
 * parser and the confirmation heuristics stay in lock-step. A final block checks
 * the standalone ground-truth manifest against the analyzer's real output so the
 * corpus labels can never drift from what Layer 0 actually extracts.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Logger } from "@montr/telemetry";
import { pythonAnalyzer } from "./index.js";
import type { AnalyzerInput, AppMapContribution } from "../types.js";
import type { FileInventory } from "../../sources.js";

const VULN_DIR = fileURLToPath(new URL("../../../../../corpus/python-vuln", import.meta.url));
const CLEAN_DIR = fileURLToPath(new URL("../../../../../corpus/python-clean", import.meta.url));
const MANIFEST_PATH = fileURLToPath(
  new URL("../../../../../corpus/python-vuln/ground-truth.manifest.json", import.meta.url),
);

const noopLogger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
  child() {
    return noopLogger;
  },
} as unknown as Logger;

function inputFor(dir: string): AnalyzerInput {
  const inventory: FileInventory = {
    dir,
    sourceFiles: [],
    prismaSchemas: [],
    envFiles: [],
    dependencies: {},
    hasNextConfig: false,
    hasPackageJson: false,
  };
  return { dir, inventory, logger: noopLogger };
}

describe("pythonAnalyzer — corpus/python-vuln", () => {
  it("detects the Python stack from .py sources + a Django manifest", () => {
    expect(pythonAnalyzer.detect(inputFor(VULN_DIR))).toBe(true);
  });

  it("maps Django routes, ORM models, taint sources/sinks, secret surfaces", async () => {
    const c = await pythonAnalyzer.analyze(inputFor(VULN_DIR));

    expect(c.languages).toEqual(["python"]);
    expect(c.frameworks).toContain("django");

    // Routes: the three Django urlpatterns, with dynamic segments normalised
    // (`<int:order_id>` / `(?P<order_id>…)` → `{order_id}`). Django dispatches
    // every method to the view, so routes are method-agnostic (ALL).
    const paths = c.routes.map((r) => `${r.method} ${r.path}`);
    expect(paths).toContain("ALL /search/");
    expect(paths).toContain("ALL /fetch/");
    expect(paths).toContain("ALL /orders/{order_id}/");

    // IDOR route: order_detail carries no auth guard visible at the URLConf →
    // `unknown` (fail-safe; cross-file view auth is correlation's job).
    const orderRoute = c.routes.find((r) => r.path === "/orders/{order_id}/");
    expect(orderRoute?.authState).toBe("unknown");

    // Django `models.Model` → ORM models, with the implicit auto `id` PK, backed
    // by the postgres datasource read from the settings `ENGINE`.
    const order = c.ormModels.find((m) => m.name === "Order");
    expect(order).toBeDefined();
    expect(order?.file).toContain("models.py");
    expect(order?.fields.some((f) => f.name === "id" && f.isId)).toBe(true);
    expect(c.ormModels.some((m) => m.name === "User")).toBe(true);
    expect(c.dataStores.some((d) => d.kind === "postgres" && d.accessedVia === "django")).toBe(
      true,
    );

    // Taint sinks: the three data-flow vulns, each with a description carrying a
    // substring the Python confirmation heuristics treat as UNSANITISED.
    const sql = c.taintSinks.find((s) => s.kind === "sql_query");
    expect(sql?.location.file).toContain("views.py");
    expect(sql?.location.line).toBe(18);
    expect(sql?.description?.toLowerCase()).toContain("raw sql");
    expect(sql?.description?.toLowerCase()).toContain("interpolation");

    const xss = c.taintSinks.find((s) => s.kind === "html_render");
    expect(xss?.location.line).toBe(21);
    expect(xss?.description?.toLowerCase()).toContain("mark_safe");

    const ssrf = c.taintSinks.find((s) => s.kind === "http_client");
    expect(ssrf?.location.line).toBe(28);
    expect(ssrf?.description?.toLowerCase()).toContain("ssrf");

    // Taint sources: both `request.GET.get(...)` reads (the SQLi `q` + the SSRF
    // `url`) surface as query_param sources named for the confirmation param-match.
    const queryParams = c.taintSources.filter((s) => s.kind === "query_param");
    expect(queryParams.length).toBeGreaterThanOrEqual(2);
    expect(queryParams.every((s) => /request\.GET\.get/.test(s.description ?? ""))).toBe(true);

    // Secret surfaces: the hard-coded SECRET_KEY (config_file) + an env read.
    // ⛔ Metadata only — the secret VALUE is never emitted (golden rule #1).
    const secret = c.envSecretSurfaces.find((e) => e.name === "SECRET_KEY");
    expect(secret?.kind).toBe("config_file");
    expect(secret?.location?.line).toBe(5);
    expect(c.envSecretSurfaces.some((e) => e.kind === "process_env")).toBe(true);
    expect(JSON.stringify(c)).not.toContain("hardcoded-abc123def456");
  });
});

describe("pythonAnalyzer — corpus/python-clean", () => {
  it("emits only sanitised sinks + reads the secret from the environment", async () => {
    const c = await pythonAnalyzer.analyze(inputFor(CLEAN_DIR));
    expect(c.languages).toEqual(["python"]);

    // The parameterized `cursor.execute(sql, [q])` is still catalogued as a
    // sql_query sink, but its note carries the base SAFE marker `parameterized`
    // (and never `interpolation`), so confirmation demotes it.
    for (const s of c.taintSinks.filter((s) => s.kind === "sql_query")) {
      expect(s.description?.toLowerCase()).toContain("parameterized");
      expect(s.description?.toLowerCase()).not.toContain("interpolation");
    }
    // No mark_safe (XSS) and no dynamic outbound request (SSRF) in the fix.
    expect(c.taintSinks.filter((s) => s.kind === "html_render")).toHaveLength(0);
    expect(c.taintSinks.filter((s) => s.kind === "http_client")).toHaveLength(0);

    // The secret is read from the environment, so there is no hard-coded
    // config_file secret surface — only `process_env` reads.
    expect(c.envSecretSurfaces.some((e) => e.kind === "config_file")).toBe(false);
    expect(c.envSecretSurfaces.some((e) => e.kind === "process_env")).toBe(true);
  });
});

interface ManifestFinding {
  id: string;
  category: string;
  file: string;
  line: number;
}

describe("python-vuln ground-truth manifest ↔ analyzer", () => {
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8")) as {
    repos: Array<{ name: string; expectedFindings: ManifestFinding[] }>;
  };
  const vuln = manifest.repos.find((r) => r.name === "python-vuln");

  it("declares the five planted findings", () => {
    expect(vuln?.expectedFindings.map((f) => f.category).sort()).toEqual(
      ["hardcoded_secret", "idor", "sql_injection", "ssrf", "xss"].sort(),
    );
  });

  it("corroborates every planted finding against the analyzer's output", async () => {
    const c: AppMapContribution = await pythonAnalyzer.analyze(inputFor(VULN_DIR));
    const findings = vuln?.expectedFindings ?? [];
    expect(findings.length).toBeGreaterThan(0);

    const sinkAt = (file: string, line: number): boolean =>
      c.taintSinks.some((s) => s.location.file.endsWith(file) && s.location.line === line);
    const envAt = (file: string, line: number): boolean =>
      c.envSecretSurfaces.some((e) => e.location?.file.endsWith(file) && e.location.line === line);

    for (const f of findings) {
      const base = f.file.split("/").pop() ?? f.file;
      switch (f.category) {
        case "sql_injection":
        case "xss":
        case "ssrf":
          // A taint sink is planted at the manifest's file:line.
          expect({ id: f.id, sink: sinkAt(base, f.line) }).toEqual({ id: f.id, sink: true });
          break;
        case "hardcoded_secret":
          expect({ id: f.id, env: envAt(base, f.line) }).toEqual({ id: f.id, env: true });
          break;
        case "idor":
          // IDOR is structural (a public route fetching an ORM model by id); the
          // sink-level catalog carries no note for it — correlation ties the
          // route + model together. Assert both structural pieces exist.
          expect(c.routes.some((r) => r.path === "/orders/{order_id}/")).toBe(true);
          expect(c.ormModels.some((m) => m.name === "Order")).toBe(true);
          break;
        default:
          throw new Error(`unexpected manifest category: ${f.category}`);
      }
    }
  });
});
