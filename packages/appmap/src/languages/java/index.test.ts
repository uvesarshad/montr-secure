/**
 * JVM (Spring / JPA) App-Map analyzer — offline corpus test.
 *
 * Runs the real {@link javaAnalyzer} against `corpus/jvm-vuln` (planted SQLi,
 * command injection, insecure deserialization, hard-coded secret, broken access
 * control) and `corpus/jvm-clean` (the secured counterpart). Everything is
 * offline: the `tree-sitter-java` grammar loads from `tree-sitter-wasms`, no
 * network, no LLM (golden rule #6). The assertions couple the analyzer's emitted
 * taint-sink descriptions to the substrings the Layer-3 Java confirmation
 * heuristics rely on, so the two stay in lock-step.
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Logger } from "@montr/telemetry";
import { getHardenedDefaults } from "@montr/config";
import {
  CategorySchema,
  Layer0OutputSchema,
  RiskClassSchema,
  ScanScopeSchema,
  SeveritySchema,
  type Category,
} from "@montr/contracts";
import { javaAnalyzer, parseJava, extractFile } from "./index.js";
import { buildAppMap } from "../../index.js";
import type { AnalyzerInput } from "../types.js";
import type { FileInventory } from "../../sources.js";

const VULN_DIR = fileURLToPath(new URL("../../../../../corpus/jvm-vuln", import.meta.url));
const CLEAN_DIR = fileURLToPath(new URL("../../../../../corpus/jvm-clean", import.meta.url));

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

describe("javaAnalyzer — corpus/jvm-vuln", () => {
  it("detects the JVM stack from .java sources + a build manifest", () => {
    expect(javaAnalyzer.detect(inputFor(VULN_DIR))).toBe(true);
  });

  it("maps Spring routes, JPA models, taint sources/sinks, secret surfaces", async () => {
    const c = await javaAnalyzer.analyze(inputFor(VULN_DIR));

    expect(c.languages).toEqual(["java"]);
    expect(c.frameworks).toContain("spring");

    // Routes: the four Spring handlers, with the base path prefixes applied.
    const paths = c.routes.map((r) => `${r.method} ${r.path}`);
    expect(paths).toContain("GET /api/users/search");
    expect(paths).toContain("GET /api/net/diag");
    expect(paths).toContain("POST /api/import");
    expect(paths).toContain("DELETE /api/admin/orders/{id}");

    // Broken access control signal: the admin route is authenticated but the
    // class @PreAuthorize only requires isAuthenticated() (no role gate).
    const adminRoute = c.routes.find((r) => r.method === "DELETE");
    expect(adminRoute?.authState).toBe("authenticated");
    expect(adminRoute?.authGate).toBe("PreAuthorize");
    // The public SQLi route carries no auth annotation → unknown (fail-safe).
    const searchRoute = c.routes.find((r) => r.path === "/api/users/search");
    expect(searchRoute?.authState).toBe("unknown");

    // JPA entity → ORM model, linked to the postgres datasource from config.
    const order = c.ormModels.find((m) => m.name === "Order");
    expect(order).toBeDefined();
    expect(order?.fields.some((f) => f.name === "id" && f.isId)).toBe(true);
    expect(c.dataStores.some((d) => d.kind === "postgres")).toBe(true);
    expect(order?.dataStore).toBe("postgres");

    // Taint sinks: the three data-flow vulns, each with a description carrying a
    // substring the Java confirmation heuristics key off.
    const sql = c.taintSinks.find((s) => s.kind === "sql_query");
    expect(sql?.location.file).toContain("UserController.java");
    expect(sql?.description?.toLowerCase()).toContain("concat");

    const cmd = c.taintSinks.find((s) => s.kind === "command_exec");
    expect(cmd?.location.file).toContain("NetworkController.java");
    expect(cmd?.description?.toLowerCase()).toContain("exec");

    const deser = c.taintSinks.find((s) => s.kind === "deserialize");
    expect(deser?.location.file).toContain("ImportController.java");
    expect(deser?.description?.toLowerCase()).toContain("readobject");

    // Taint sources: @RequestParam q on the SQLi route, named for confirmation.
    const q = c.taintSources.find((s) => s.description?.includes("@RequestParam q"));
    expect(q?.kind).toBe("query_param");
    expect(q?.routeId).toBeDefined();
    // HttpServletRequest + its getInputStream() feed the deserialization sink.
    expect(c.taintSources.some((s) => s.kind === "request_body")).toBe(true);

    // Secret surfaces from application.yml (metadata only — never the value).
    const secretNames = c.envSecretSurfaces.map((e) => e.name);
    expect(secretNames.some((n) => /password/i.test(n))).toBe(true);
    expect(secretNames.some((n) => /api-?key/i.test(n))).toBe(true);
    for (const e of c.envSecretSurfaces) {
      expect(JSON.stringify(e)).not.toContain("S3cr3tP@ssw0rd");
    }
  });
});

describe("javaAnalyzer — corpus/jvm-clean", () => {
  it("emits no dangerous SQL/command/deserialization sinks", async () => {
    const c = await javaAnalyzer.analyze(inputFor(CLEAN_DIR));
    expect(c.languages).toEqual(["java"]);
    // Parameterized query, no Runtime.exec/ProcessBuilder, no ObjectInputStream.
    expect(c.taintSinks.filter((s) => s.kind === "sql_query")).toHaveLength(0);
    expect(c.taintSinks.filter((s) => s.kind === "command_exec")).toHaveLength(0);
    expect(c.taintSinks.filter((s) => s.kind === "deserialize")).toHaveLength(0);
    // The admin route is properly role-gated (hasRole('ADMIN')).
    const del = c.routes.find((r) => r.method === "DELETE");
    expect(del?.authState).toBe("role_gated");
  });
});

// ---------------------------------------------------------------------------
// Full Layer-0 pipeline (buildAppMap, deterministic — no gateway ⇒ no LLM).
// ---------------------------------------------------------------------------
const FIXED_NOW = "2026-01-01T00:00:00.000Z";
const COMMIT = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";

function buildInput(dir: string, scanId: string) {
  return {
    clientId: "client_jvm",
    scanId,
    repo: dir,
    branch: "main",
    mode: "full" as const,
    scope: ScanScopeSchema.parse({ mode: "full" }),
    config: getHardenedDefaults(),
    commitSha: COMMIT,
  };
}

describe("java appmap — full buildAppMap pipeline (offline, no LLM)", () => {
  it("emits a schema-valid Layer0Output with only valid taint-source kinds", async () => {
    const out = await buildAppMap(buildInput(VULN_DIR, "scan_jvm_vuln"), {
      now: () => new Date(FIXED_NOW),
    });
    // ⛔ Regression guard for the prototype-safety fix (extract.ts `own()`): a Java
    // method named `toString`/`valueOf`/`constructor` must NOT resolve to an
    // inherited Object.prototype FUNCTION and get emitted as a TaintSource.kind —
    // that poisoned value fails this parse and would crash Layer 0 for any real
    // Java repo. `jvm-vuln` calls both `String.valueOf(...)` and `x.toString()`.
    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
    for (const s of out.appMap.taintSources) {
      expect(typeof s.kind).toBe("string");
    }
    expect(out.appMap.languages).toEqual(["java"]);
    expect(out.appMap.frameworks).toContain("spring");
    expect(out.scope.routeCount).toBe(out.appMap.routes.length);
    // ⛔ No hard-coded secret VALUE ever lands in the map (golden rule #1).
    expect(JSON.stringify(out.appMap)).not.toContain("S3cr3tP@ssw0rd");
  });

  it("lands the three data-flow sinks at their ground-truth lines", async () => {
    const out = await buildAppMap(buildInput(VULN_DIR, "scan_jvm_lines"), {
      now: () => new Date(FIXED_NOW),
    });
    const sink = (kind: string) => out.appMap.taintSinks.find((s) => s.kind === kind);
    expect(sink("sql_query")?.location.line).toBe(36); // UserController — gt_jvm_sqli
    expect(sink("command_exec")?.location.line).toBe(22); // NetworkController — gt_jvm_cmdi
    expect(sink("deserialize")?.location.line).toBe(23); // ImportController — gt_jvm_deser
  });

  it("keeps the secured jvm-clean map schema-valid and free of dangerous sinks", async () => {
    const out = await buildAppMap(buildInput(CLEAN_DIR, "scan_jvm_clean"), {
      now: () => new Date(FIXED_NOW),
    });
    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
    for (const kind of ["sql_query", "command_exec", "deserialize"] as const) {
      expect(out.appMap.taintSinks.some((s) => s.kind === kind)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// Ground-truth manifest — the corpus contract the golden-corpus scorer reads.
// Fields are validated against the @montr/contracts enum schemas (the manifest
// also matches @montr/fixtures' GroundTruthManifestSchema; here we stay within
// the appmap package's declared deps and validate field-by-field).
// ---------------------------------------------------------------------------
interface GtFinding {
  id: string;
  category: string;
  cwe: string[];
  owasp: string;
  file: string;
  line: number;
  severity: string;
  expectedRiskClass: string;
  exploitable: boolean;
  description: string;
}
interface GtRepo {
  name: string;
  kind: "vulnerable" | "clean";
  path: string;
  expectedFindings: GtFinding[];
}

async function loadManifest(): Promise<{ version: string; repos: GtRepo[] }> {
  const raw = await readFile(
    new URL("../../../../../corpus/jvm-vuln/ground-truth.manifest.json", import.meta.url),
    "utf8",
  );
  return JSON.parse(raw) as { version: string; repos: GtRepo[] };
}

describe("jvm corpus — ground-truth manifest", () => {
  it("declares jvm-vuln + jvm-clean with the five planted OWASP findings", async () => {
    const m = await loadManifest();
    expect(typeof m.version).toBe("string");
    expect(m.repos.map((r) => r.name).sort()).toEqual(["jvm-clean", "jvm-vuln"]);
    expect(m.repos.find((r) => r.name === "jvm-clean")!.expectedFindings).toHaveLength(0);

    const vuln = m.repos.find((r) => r.name === "jvm-vuln")!;
    const cats = new Set<Category>(vuln.expectedFindings.map((f) => f.category as Category));
    for (const required of [
      "sql_injection",
      "command_injection",
      "insecure_deserialization",
      "broken_access_control",
      "hardcoded_secret",
    ] as const) {
      expect(cats.has(required)).toBe(true);
    }
  });

  it("uses only valid contract enum values for every field", async () => {
    const m = await loadManifest();
    for (const repo of m.repos) {
      for (const f of repo.expectedFindings) {
        expect(CategorySchema.safeParse(f.category).success).toBe(true);
        expect(SeveritySchema.safeParse(f.severity).success).toBe(true);
        expect(RiskClassSchema.safeParse(f.expectedRiskClass).success).toBe(true);
        expect(Array.isArray(f.cwe) && f.cwe.length > 0).toBe(true);
        expect(f.owasp).toMatch(/^A\d{2}:\d{4}$/);
        expect(f.line).toBeGreaterThan(0);
        expect(typeof f.exploitable).toBe("boolean");
      }
    }
  });

  it("⛔ classifies access-control + secret rotation as human-required (golden rule #3)", async () => {
    const vuln = (await loadManifest()).repos.find((r) => r.name === "jvm-vuln")!;
    for (const f of vuln.expectedFindings) {
      if (f.category === "broken_access_control" || f.category === "hardcoded_secret") {
        expect(f.expectedRiskClass).toBe("human-required");
      } else {
        expect(f.expectedRiskClass).toBe("auto-eligible");
      }
    }
  });

  it("anchors the three data-flow findings to the sinks the analyzer emits", async () => {
    const vuln = (await loadManifest()).repos.find((r) => r.name === "jvm-vuln")!;
    const c = await javaAnalyzer.analyze(inputFor(VULN_DIR));
    const sinkKindByCategory: Record<string, string> = {
      sql_injection: "sql_query",
      command_injection: "command_exec",
      insecure_deserialization: "deserialize",
    };
    for (const f of vuln.expectedFindings) {
      const kind = sinkKindByCategory[f.category];
      if (!kind) continue;
      const base = f.file.split("/").pop()!;
      const match = c.taintSinks.find(
        (s) => s.kind === kind && s.location.line === f.line && s.location.file.endsWith(base),
      );
      expect(match, `${f.category} sink at ${f.file}:${f.line}`).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// Parser breadth (inline snippets) — features the corpus does not exercise:
// JAX-RS routing, ProcessBuilder / reflection / SpEL / redirect sinks, role-gated
// auth, @Scheduled entrypoints, @Value config surfaces. Fully offline.
// ---------------------------------------------------------------------------
describe("java appmap — parser breadth (inline snippets, offline)", () => {
  async function extract(src: string, rel = "X.java") {
    const root = await parseJava(src);
    if (!root) throw new Error("parse failed");
    return extractFile(root, rel);
  }

  it("maps JAX-RS @Path + @GET/@POST routes under the class base path", async () => {
    const ex = await extract(
      [
        "package a;",
        "import jakarta.ws.rs.GET;",
        "import jakarta.ws.rs.POST;",
        "import jakarta.ws.rs.Path;",
        '@Path("/api/items")',
        "public class ItemResource {",
        '  @GET @Path("/list")',
        '  public String list() { return "x"; }',
        "  @POST",
        "  public String create(String body) { return body; }",
        "}",
      ].join("\n"),
      "ItemResource.java",
    );
    const paths = ex.routes.map((r) => `${r.method} ${r.path}`);
    expect(paths).toContain("GET /api/items/list");
    expect(paths).toContain("POST /api/items");
  });

  it("reads @PreAuthorize(hasRole) as role_gated and @Scheduled as a cron entrypoint", async () => {
    const ex = await extract(
      [
        "package a;",
        "import org.springframework.web.bind.annotation.GetMapping;",
        "import org.springframework.web.bind.annotation.RestController;",
        "import org.springframework.security.access.prepost.PreAuthorize;",
        "import org.springframework.scheduling.annotation.Scheduled;",
        "@RestController",
        "public class Jobs {",
        '  @GetMapping("/admin/x")',
        "  @PreAuthorize(\"hasRole('ADMIN')\")",
        '  public String x() { return "x"; }',
        "  @Scheduled(fixedRate = 1000)",
        "  public void sweep() {}",
        "}",
      ].join("\n"),
      "Jobs.java",
    );
    const admin = ex.routes.find((r) => r.path === "/admin/x");
    expect(admin?.authState).toBe("role_gated");
    expect(admin?.authGate).toBe("PreAuthorize");
    expect(ex.entrypoints.some((e) => e.kind === "cron")).toBe(true);
  });

  it("catalogs ProcessBuilder / reflection / SpEL / redirect sinks + @Value surfaces", async () => {
    const ex = await extract(
      [
        "package a;",
        "import org.springframework.beans.factory.annotation.Value;",
        "public class Sinks {",
        '  @Value("${app.token}")',
        "  private String token;",
        "  void run(String cmd, String cls, String spel, String url,",
        "           javax.servlet.http.HttpServletResponse resp) throws Exception {",
        "    new ProcessBuilder(cmd).start();",
        "    Class.forName(cls);",
        "    parser.parseExpression(spel);",
        "    resp.sendRedirect(url);",
        "  }",
        "}",
      ].join("\n"),
      "Sinks.java",
    );
    const kinds = new Set(ex.taintSinks.map((s) => s.kind));
    expect(kinds.has("command_exec")).toBe(true); // new ProcessBuilder(...)
    expect(kinds.has("eval")).toBe(true); // Class.forName + parseExpression (SpEL)
    expect(kinds.has("redirect")).toBe(true); // response.sendRedirect(...)
    expect(ex.envSecretSurfaces.some((e) => e.name === "app.token")).toBe(true);
  });
});
