/**
 * WS-F / Layer 1 — unit tests for the three discovery sub-detectors and their
 * offline helpers. Fully offline: external scanner binaries are mocked via the
 * injectable runners, and file access uses the in-memory provider or the real
 * fs walker over the @montr/fixtures sample repos. No network, no DB.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fileURLToPath } from "node:url";
import nodePath from "node:path";
import { tmpdir } from "node:os";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { getHardenedDefaults } from "@montr/config";
import { createNullLogger } from "@montr/telemetry";
import { RequiredDetectorUnavailableError, type ScanScope } from "@montr/contracts";
import { mockAppMap } from "@montr/fixtures";
import {
  // detectors
  detectSast,
  parseSemgrepJson,
  detectSecretsAndConfig,
  runCustomDetectors,
  detectDependencies,
  resolveInstalledPackages,
  collectImportedPackages,
  collectCalledPackages,
  barePackageName,
  parsePkgKey,
  parsePnpmLock,
  parsePackageLock,
  parsePackageJson,
  // advisories + semver
  ADVISORY_DB,
  matchAdvisories,
  semverSatisfies,
  coerceSemver,
  // file providers + types
  memoryFileProvider,
  fsFileProvider,
  type DetectorContext,
  type SemgrepRunner,
  type GitleaksRunner,
  type RepoFile,
} from "@montr/discovery";

const FIXED_NOW = "2026-01-15T10:00:00.000Z";
const VULN_REPO = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/vulnerable-nextjs", import.meta.url),
);
const CLEAN_REPO = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/clean-nextjs", import.meta.url),
);

const FULL_SCOPE: ScanScope = {
  mode: "full",
  includePaths: [],
  excludePaths: [],
  changedFiles: [],
  reachableFromChanges: false,
};

function makeCtx(overrides: Partial<DetectorContext> = {}): DetectorContext {
  const warnings: string[] = [];
  return {
    clientId: "client_test_0001",
    scanId: "scan_test_0001",
    appMap: mockAppMap,
    scope: FULL_SCOPE,
    config: getHardenedDefaults(),
    repoRoot: undefined,
    files: memoryFileProvider([]),
    now: () => FIXED_NOW,
    logger: createNullLogger(),
    signal: undefined,
    warnings,
    warn(detector: string, message: string): void {
      warnings.push(`[${detector}] ${message}`);
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// semver + advisories
// ---------------------------------------------------------------------------

describe("discovery/semver", () => {
  it("compares and satisfies ranges used by advisories", () => {
    expect(semverSatisfies("4.17.11", "<4.17.12")).toBe(true);
    expect(semverSatisfies("4.17.21", "<4.17.12")).toBe(false);
    expect(semverSatisfies("1.2.5", "<1.2.6")).toBe(true);
    expect(semverSatisfies("0.21.1", ">=0.8.1 <0.21.2")).toBe(true);
    expect(semverSatisfies("0.22.0", ">=0.8.1 <0.21.2")).toBe(false);
    expect(semverSatisfies("1.0.0", "*")).toBe(true);
  });

  it("expands caret and tilde ranges", () => {
    expect(semverSatisfies("1.5.0", "^1.2.3")).toBe(true);
    expect(semverSatisfies("2.0.0", "^1.2.3")).toBe(false);
    expect(semverSatisfies("1.2.9", "~1.2.3")).toBe(true);
    expect(semverSatisfies("1.3.0", "~1.2.3")).toBe(false);
  });

  it("coerces version-ish strings", () => {
    expect(coerceSemver("^4.17.11")).toEqual({ major: 4, minor: 17, patch: 11 });
    expect(coerceSemver("not-a-version")).toBeNull();
  });
});

describe("discovery/advisories", () => {
  // The mirror is now the real OSV/GHSA bulk export (curated + refreshed by
  // `scripts/refresh-advisories.mjs`, see README.md), not a 3-entry stub —
  // so a package can legitimately match many real advisories at once. These
  // assertions check the well-known headline CVEs are present/absent at the
  // right boundary rather than asserting an exact match count, so the suite
  // stays green as the mirror is refreshed with newly-published advisories.
  it("matches lodash 4.17.11 (vulnerable) but not the headline CVE once patched at 4.17.12", () => {
    const vuln = matchAdvisories("lodash", "4.17.11");
    const protoPollution = vuln.find((a) => a.id === "GHSA-jf85-cpcp-j695");
    expect(protoPollution).toBeDefined();
    expect(protoPollution?.cwe).toContain("CWE-1321");
    // Patched against THIS specific CVE at 4.17.12 — the real mirror also
    // knows about later, unrelated lodash CVEs (fixed in later releases),
    // which is real/correct and exercised separately below.
    expect(matchAdvisories("lodash", "4.17.21").map((a) => a.id)).not.toContain(
      "GHSA-jf85-cpcp-j695",
    );
  });

  it("matches minimist and axios ranges from the real mirror (headline CVEs)", () => {
    expect(matchAdvisories("minimist", "1.2.5").map((a) => a.id)).toContain(
      "GHSA-xvch-5gv4-984h", // real GHSA id for CVE-2021-44906 (prototype pollution)
    );
    expect(matchAdvisories("minimist", "1.2.6")).toHaveLength(0);
    expect(matchAdvisories("axios", "0.21.1").map((a) => a.id)).toContain("GHSA-cph5-m8f7-6c5x");
    expect(matchAdvisories("axios", "0.21.2").map((a) => a.id)).not.toContain(
      "GHSA-cph5-m8f7-6c5x",
    );
  });

  it("mirror spans npm, PyPI, and Maven with a meaningfully large record count", () => {
    const ecosystems = new Set(ADVISORY_DB.map((a) => a.ecosystem));
    expect(ecosystems.has("npm")).toBe(true);
    expect(ecosystems.has("PyPI")).toBe(true);
    expect(ecosystems.has("Maven")).toBe(true);
    expect(ADVISORY_DB.length).toBeGreaterThan(500);
  });

  it("matchAdvisories defaults to npm (the only ecosystem the Phase-1 SCA detector resolves)", () => {
    // "django" only exists in the PyPI slice of the mirror; the default
    // (npm) match must not leak cross-ecosystem records.
    expect(matchAdvisories("django", "1.0")).toEqual([]);
    expect(matchAdvisories("django", "1.0", ADVISORY_DB, "PyPI").length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// SAST
// ---------------------------------------------------------------------------

const CANNED_SEMGREP = {
  results: [
    {
      check_id: "typescript.prisma.raw-query-unsafe",
      path: "app/api/users/route.ts",
      start: { line: 9, col: 9 },
      end: { line: 9 },
      extra: {
        severity: "ERROR",
        message: "Unsafe raw SQL query via string interpolation",
        lines: "prisma.$queryRawUnsafe(`SELECT * FROM \"User\" WHERE name = '${q}'`)",
        metadata: { cwe: ["CWE-89: SQL Injection"], owasp: ["A03:2021"] },
      },
    },
    {
      check_id: "react.dangerouslySetInnerHTML",
      path: "app/search/page.tsx",
      start: { line: 8 },
      extra: {
        severity: "WARNING",
        message: "Reflected XSS via dangerouslySetInnerHTML",
        lines: "dangerouslySetInnerHTML={{ __html: q }}",
        metadata: { cwe: "CWE-79" },
      },
    },
  ],
};

describe("discovery/sast", () => {
  it("maps Semgrep JSON to tagged candidates (source/rule/cwe/category/severity)", () => {
    const ctx = makeCtx({ repoRoot: VULN_REPO });
    const candidates = parseSemgrepJson(CANNED_SEMGREP, ctx);
    expect(candidates).toHaveLength(2);

    const sqli = candidates.find((c) => c.category === "sql_injection");
    expect(sqli).toBeDefined();
    expect(sqli?.source).toBe("semgrep");
    expect(sqli?.ruleId).toBe("typescript.prisma.raw-query-unsafe");
    expect(sqli?.cwe).toContain("CWE-89");
    expect(sqli?.rawSeverity).toBe("high"); // ERROR -> high
    expect(sqli?.location).toMatchObject({ file: "app/api/users/route.ts", line: 9 });

    const xss = candidates.find((c) => c.category === "xss");
    expect(xss?.cwe).toContain("CWE-79");
    expect(xss?.rawSeverity).toBe("medium"); // WARNING -> medium
  });

  it("runs via an injected runner", async () => {
    const runner: SemgrepRunner = async () => CANNED_SEMGREP;
    const ctx = makeCtx({ repoRoot: VULN_REPO });
    const candidates = await detectSast(ctx, { runner });
    expect(candidates.map((c) => c.category).sort()).toEqual(["sql_injection", "xss"]);
  });

  // A4 (P0): SAST is a REQUIRED detector — an unavailable/erroring Semgrep must
  // THROW (RequiredDetectorUnavailableError), never silently degrade to `[]`.
  // A scan can never complete successfully and look clean while its SAST pass
  // silently didn't run.
  it("THROWS when the runner reports the binary is missing (required detector)", async () => {
    const runner: SemgrepRunner = async () => null;
    const ctx = makeCtx({ repoRoot: VULN_REPO });
    await expect(detectSast(ctx, { runner })).rejects.toThrow(RequiredDetectorUnavailableError);
    await expect(detectSast(ctx, { runner })).rejects.toThrow(/unavailable/i);
  });

  it("THROWS (never silently degrades) when the real semgrep binary is absent", async () => {
    // No injected runner + a real repoRoot -> defaultSemgrepRunner shells out;
    // semgrep is not installed in CI, so this must throw, not degrade to [].
    const ctx = makeCtx({ repoRoot: VULN_REPO });
    await expect(detectSast(ctx)).rejects.toThrow(RequiredDetectorUnavailableError);
  });

  it("THROWS when the runner itself throws (execution error)", async () => {
    const runner: SemgrepRunner = async () => {
      throw new Error("semgrep crashed");
    };
    const ctx = makeCtx({ repoRoot: VULN_REPO });
    await expect(detectSast(ctx, { runner })).rejects.toThrow(RequiredDetectorUnavailableError);
    await expect(detectSast(ctx, { runner })).rejects.toThrow(/semgrep crashed/);
  });

  it("warns (still a graceful skip) when there is neither a runner nor a repoRoot", async () => {
    // Unchanged from before A4: the in-memory-files-only scan shape has no
    // repo checkout for Semgrep to run against at all — never hit by the
    // production Layer 1 runner, which always resolves a repoRoot.
    const ctx = makeCtx();
    const candidates = await detectSast(ctx);
    expect(candidates).toEqual([]);
    expect(ctx.warnings.join(" ")).toMatch(/skipped/i);
  });

  // --- A4: air-gap local rulesetsDir ----------------------------------------
  describe("air-gap rulesetsDir (A4)", () => {
    let LOCAL_RULES_DIR: string;

    beforeAll(async () => {
      // Mirrors import-bundle.sh's install layout: a flat directory of rule
      // YAML files (see deploy/airgap/build-bundle.sh --semgrep-rules-dir).
      LOCAL_RULES_DIR = await mkdtemp(nodePath.join(tmpdir(), "montr-airgap-rules-"));
      await writeFile(
        nodePath.join(LOCAL_RULES_DIR, "sql-injection.yaml"),
        "rules:\n  - id: local.sql-injection\n    languages: [typescript]\n    message: test\n    severity: ERROR\n    pattern: foo(...)\n",
      );
    });

    afterAll(async () => {
      await rm(LOCAL_RULES_DIR, { recursive: true, force: true });
    });

    it("invokes Semgrep against the local rulesetsDir instead of hosted p/... packs", async () => {
      let seenRulesets: string[] = [];
      const runner: SemgrepRunner = async ({ rulesets: r }) => {
        seenRulesets = r;
        return CANNED_SEMGREP;
      };
      const ctx = makeCtx({
        repoRoot: VULN_REPO,
        config: {
          ...getHardenedDefaults(),
          discovery: { rulesetsDir: LOCAL_RULES_DIR },
        },
      });
      const candidates = await detectSast(ctx, { runner, rulesets: ["p/owasp-top-ten"] });
      expect(seenRulesets).toContain(LOCAL_RULES_DIR);
      expect(seenRulesets.some((r) => r.startsWith("p/"))).toBe(false);
      expect(candidates.length).toBeGreaterThan(0);
    });

    it("keeps non-registry (custom rule) paths alongside the local rulesetsDir", async () => {
      let seenRulesets: string[] = [];
      const runner: SemgrepRunner = async ({ rulesets: r }) => {
        seenRulesets = r;
        return { results: [] };
      };
      const ctx = makeCtx({
        repoRoot: VULN_REPO,
        config: {
          ...getHardenedDefaults(),
          discovery: { rulesetsDir: LOCAL_RULES_DIR },
        },
      });
      await detectSast(ctx, {
        runner,
        rulesets: ["p/owasp-top-ten", "/tmp/montr-custom-rules-xyz/rule-1.yaml"],
      });
      expect(seenRulesets).toEqual([LOCAL_RULES_DIR, "/tmp/montr-custom-rules-xyz/rule-1.yaml"]);
    });

    it("THROWS when rulesetsDir is configured but does not exist", async () => {
      const runner: SemgrepRunner = async () => CANNED_SEMGREP;
      const ctx = makeCtx({
        repoRoot: VULN_REPO,
        config: {
          ...getHardenedDefaults(),
          discovery: { rulesetsDir: "/nonexistent/montr-airgap-rules" },
        },
      });
      await expect(detectSast(ctx, { runner })).rejects.toThrow(RequiredDetectorUnavailableError);
      await expect(detectSast(ctx, { runner })).rejects.toThrow(/does not exist|no rule files/);
    });

    it("THROWS when rulesetsDir exists but is empty (no rule files)", async () => {
      const runner: SemgrepRunner = async () => CANNED_SEMGREP;
      const emptyDir = await mkdtemp(nodePath.join(tmpdir(), "montr-empty-rules-"));
      try {
        const ctx = makeCtx({
          repoRoot: VULN_REPO,
          config: { ...getHardenedDefaults(), discovery: { rulesetsDir: emptyDir } },
        });
        await expect(detectSast(ctx, { runner })).rejects.toThrow(RequiredDetectorUnavailableError);
      } finally {
        await rm(emptyDir, { recursive: true, force: true });
      }
    });
  });
});

// ---------------------------------------------------------------------------
// Secrets & Config
// ---------------------------------------------------------------------------

describe("discovery/secrets-config custom detectors", () => {
  it("flags a hardcoded secret and REDACTS the value", () => {
    const file: RepoFile = {
      path: "lib/config.ts",
      content:
        '// comment\nexport const PAYMENTS_API_KEY = "sk_live_51H8xEXAMPLEhardcodedKeyDoNotUse0000";\n',
    };
    const findings = runCustomDetectors(file);
    const secret = findings.find((f) => f.category === "hardcoded_secret");
    expect(secret).toBeDefined();
    expect(secret?.line).toBe(2);
    // ⛔ The raw secret must never appear in the evidence snippet.
    expect(secret?.snippet).not.toContain("sk_live_51H8xEXAMPLEhardcodedKeyDoNotUse0000");
    expect(secret?.snippet).toContain("REDACTED");
  });

  it("does not double-report a specific + generic secret on the same line", () => {
    const file: RepoFile = {
      path: "lib/config.ts",
      content: 'export const API_KEY = "sk_live_ABCDEFGHIJKLMNOP";\n',
    };
    const secrets = runCustomDetectors(file).filter((f) => f.category === "hardcoded_secret");
    expect(secrets).toHaveLength(1);
  });

  it("ignores secrets sourced from process.env (clean pattern)", () => {
    const file: RepoFile = {
      path: "lib/config.ts",
      content: 'export const config = { apiKey: process.env.PAYMENTS_API_KEY ?? "" };\n',
    };
    expect(runCustomDetectors(file).filter((f) => f.category === "hardcoded_secret")).toHaveLength(
      0,
    );
  });

  it("flags wildcard CORS but not a scoped origin", () => {
    const bad: RepoFile = {
      path: "route.ts",
      content: 'headers: { "Access-Control-Allow-Origin": "*" }\n',
    };
    const good: RepoFile = {
      path: "route.ts",
      content: 'headers: { "Access-Control-Allow-Origin": "https://app.example.com" }\n',
    };
    expect(runCustomDetectors(bad).some((f) => f.category === "permissive_cors")).toBe(true);
    expect(runCustomDetectors(good).some((f) => f.category === "permissive_cors")).toBe(false);
  });

  it("flags weak crypto (md5) and client-exposed NEXT_PUBLIC secrets", () => {
    const crypto: RepoFile = { path: "hash.ts", content: 'createHash("md5").update(x)\n' };
    expect(runCustomDetectors(crypto).some((f) => f.category === "weak_crypto")).toBe(true);

    const env: RepoFile = {
      path: "config.ts",
      content: "const k = NEXT_PUBLIC_STRIPE_SECRET_KEY;\n",
    };
    expect(runCustomDetectors(env).some((f) => f.category === "sensitive_data_exposure")).toBe(
      true,
    );
  });

  it("flags an insecure cookie missing HttpOnly/Secure", () => {
    const file: RepoFile = {
      path: "route.ts",
      content: 'res.cookie("sid", token, { path: "/" });\n',
    };
    expect(runCustomDetectors(file).some((f) => f.category === "insecure_cookie")).toBe(true);
  });

  it("flags a next.config without security headers", () => {
    const file: RepoFile = {
      path: "next.config.js",
      content: "const nextConfig = { reactStrictMode: true };\nmodule.exports = nextConfig;\n",
    };
    expect(runCustomDetectors(file).some((f) => f.category === "missing_security_headers")).toBe(
      true,
    );
  });

  it("detectSecretsAndConfig over the vulnerable sample finds the secret + CORS", async () => {
    const ctx = makeCtx({ files: fsFileProvider(VULN_REPO) });
    const gitleaks: GitleaksRunner = async () => []; // binary present, no extra findings
    const candidates = await detectSecretsAndConfig(ctx, { runner: gitleaks });
    const cats = new Set(candidates.map((c) => c.category));
    expect(cats.has("hardcoded_secret")).toBe(true);
    expect(cats.has("permissive_cors")).toBe(true);
    // Every candidate is tagged per §5.2 and free of the raw secret.
    for (const c of candidates) {
      expect(c.source).toBeTruthy();
      expect(c.ruleId).toBeTruthy();
      expect(JSON.stringify(c)).not.toContain("hardcodedKeyDoNotUse");
    }
  });

  it("gitleaks absence degrades gracefully; custom detectors still run", async () => {
    const ctx = makeCtx({ files: fsFileProvider(VULN_REPO) });
    const gitleaks: GitleaksRunner = async () => null; // binary missing
    const candidates = await detectSecretsAndConfig(ctx, { runner: gitleaks });
    expect(ctx.warnings.join(" ")).toMatch(/gitleaks/i);
    expect(candidates.some((c) => c.category === "hardcoded_secret")).toBe(true);
  });

  it("clean sample yields no secrets/config candidates", async () => {
    const ctx = makeCtx({ files: fsFileProvider(CLEAN_REPO) });
    const candidates = await detectSecretsAndConfig(ctx, { runner: async () => [] });
    expect(candidates).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// SCA / dependency
// ---------------------------------------------------------------------------

describe("discovery/sca parsers", () => {
  it("parses pnpm-lock keys (v9 and v5) including scoped names", () => {
    expect(parsePkgKey("lodash@4.17.11")).toEqual({ name: "lodash", version: "4.17.11" });
    expect(parsePkgKey("/@scope/pkg@1.2.3")).toEqual({ name: "@scope/pkg", version: "1.2.3" });
    expect(parsePkgKey("lodash@4.17.11(react@18.0.0)")).toEqual({
      name: "lodash",
      version: "4.17.11",
    });
    expect(parsePkgKey("/lodash/4.17.11")).toEqual({ name: "lodash", version: "4.17.11" });
  });

  it("parses a pnpm-lock.yaml document", async () => {
    const yaml = [
      "lockfileVersion: '9.0'",
      "packages:",
      "  lodash@4.17.11:",
      "    resolution: {integrity: sha512-xxx}",
      "  '@prisma/client@5.20.0':",
      "    resolution: {integrity: sha512-yyy}",
    ].join("\n");
    const pkgs = await parsePnpmLock(yaml);
    expect(pkgs).toContainEqual({ name: "lodash", version: "4.17.11" });
    expect(pkgs).toContainEqual({ name: "@prisma/client", version: "5.20.0" });
  });

  it("parses a package-lock.json (v3 packages map)", () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app" },
        "node_modules/lodash": { version: "4.17.11" },
        "node_modules/@scope/x": { version: "2.0.0" },
      },
    });
    const pkgs = parsePackageLock(lock);
    expect(pkgs).toContainEqual({ name: "lodash", version: "4.17.11" });
    expect(pkgs).toContainEqual({ name: "@scope/x", version: "2.0.0" });
  });

  it("parses package.json ranges as a fallback", () => {
    const pkg = JSON.stringify({ dependencies: { lodash: "4.17.11", next: "^14.2.3" } });
    const pkgs = parsePackageJson(pkg);
    expect(pkgs).toContainEqual({ name: "lodash", version: "4.17.11" });
    expect(pkgs).toContainEqual({ name: "next", version: "14.2.3" });
  });

  it("barePackageName handles scoped, subpath, relative, and builtin specifiers", () => {
    expect(barePackageName("next/server")).toBe("next");
    expect(barePackageName("@prisma/client")).toBe("@prisma/client");
    expect(barePackageName("./local")).toBeNull();
    expect(barePackageName("node:fs")).toBeNull();
  });
});

describe("discovery/sca reachability", () => {
  it("resolves deps + imports from the vulnerable sample", async () => {
    const files = fsFileProvider(VULN_REPO);
    const resolved = await resolveInstalledPackages(files);
    expect(resolved.packages.some((p) => p.name === "lodash" && p.version === "4.17.11")).toBe(
      true,
    );

    const imported = await collectImportedPackages(files);
    expect(imported.has("next")).toBe(true);
    expect(imported.has("@prisma/client")).toBe(true);
    // lodash is declared but never imported -> unreachable.
    expect(imported.has("lodash")).toBe(false);
  });

  it("emits lodash candidates on the vulnerable sample, all tagged unreachable", async () => {
    const ctx = makeCtx({ files: fsFileProvider(VULN_REPO) });
    const candidates = await detectDependencies(ctx);
    const dep = candidates.filter((c) => c.category === "vulnerable_dependency");
    // The real mirror surfaces EVERY advisory affecting the sample's pinned
    // dependencies, not just the original seed's single lodash entry — the
    // sample also pins an outdated "next", which real, current OSV data now
    // flags too (genuinely, not a false positive — see the "next" assertion
    // below). Scope the per-package assertions to lodash specifically.
    const lodashDep = dep.filter((c) => c.metadata?.["package"] === "lodash");
    expect(lodashDep.length).toBeGreaterThan(0);
    expect(lodashDep.every((c) => c.metadata?.["reachable"] === false)).toBe(true);
    expect(
      lodashDep.every((c) => c.location.file === "package.json" && c.location.line === 14),
    ).toBe(true);
    const protoPollution = lodashDep.find((c) => c.ruleId === "GHSA-jf85-cpcp-j695");
    expect(protoPollution).toBeDefined();
    expect(protoPollution?.source).toBe("ghsa");
    expect(protoPollution?.cwe).toContain("CWE-1321");

    // "next" is declared AND imported by the sample (§ reachability test
    // above) — its real matches must be tagged reachable: true.
    const nextDep = dep.filter((c) => c.metadata?.["package"] === "next");
    expect(nextDep.length).toBeGreaterThan(0);
    expect(nextDep.every((c) => c.metadata?.["reachable"] === true)).toBe(true);
  });

  it("marks a vuln reachable when the package is actually imported AND called", async () => {
    const files: RepoFile[] = [
      { path: "package.json", content: JSON.stringify({ dependencies: { lodash: "4.17.11" } }) },
      { path: "src/index.ts", content: 'import _ from "lodash";\n_.defaultsDeep({}, {});\n' },
    ];
    const ctx = makeCtx({ files: memoryFileProvider(files) });
    const candidates = await detectDependencies(ctx);
    expect(candidates[0]?.metadata?.["reachable"]).toBe(true);
  });

  // A12 — SCA reachability is now call-granularity (real ts-morph AST scan),
  // not package-import presence. These two tests are the direct regression
  // coverage the task requires: (1) imported-but-never-called is no longer
  // reachable, even though the OLD `imported.has(pkg.name)` check would have
  // said yes; (2) an actually-called import stays reachable.
  it("does NOT mark a vuln reachable when the package is imported but never CALLED (A12)", async () => {
    const files: RepoFile[] = [
      { path: "package.json", content: JSON.stringify({ dependencies: { lodash: "4.17.11" } }) },
      {
        // `_` is imported and referenced — the OLD package-import-presence
        // check (`collectImportedPackages`) would mark "lodash" reachable —
        // but `_` is never CALLED anywhere.
        path: "src/index.ts",
        content: 'import _ from "lodash";\nexport const kind = typeof _;\n',
      },
    ];
    const oldSignalImported = await collectImportedPackages(memoryFileProvider(files));
    expect(oldSignalImported.has("lodash")).toBe(true); // the old, weaker signal says "reachable"

    const ctx = makeCtx({ files: memoryFileProvider(files) });
    const candidates = await detectDependencies(ctx);
    expect(candidates.length).toBeGreaterThan(0);
    expect(candidates.every((c) => c.metadata?.["reachable"] === false)).toBe(true);
  });

  it("marks a vuln reachable when the imported binding is actually invoked (A12)", async () => {
    const files: RepoFile[] = [
      { path: "package.json", content: JSON.stringify({ dependencies: { lodash: "4.17.11" } }) },
      {
        path: "src/index.ts",
        content: 'import { debounce } from "lodash";\nexport const d = debounce(() => {}, 10);\n',
      },
    ];
    const ctx = makeCtx({ files: memoryFileProvider(files) });
    const candidates = await detectDependencies(ctx);
    expect(candidates.length).toBeGreaterThan(0);
    expect(candidates.every((c) => c.metadata?.["reachable"] === true)).toBe(true);
  });

  it("clean sample (lodash 4.17.21) is patched against every ORIGINAL seed CVE", async () => {
    // clean-nextjs pins lodash@4.17.21, which was fully patched against the
    // toy 3-entry stub's CVEs. The real, current OSV mirror is honest about
    // more than that: it also knows about advisories published AFTER 4.17.21
    // shipped (fixed in the later 4.18.0 release), and about the sample's
    // separately-pinned, now-outdated "next" — a live mirror surfacing those
    // is correct behavior, not a false positive, and is exactly the
    // improvement this mirror ships over the old static stub.
    const ctx = makeCtx({ files: fsFileProvider(CLEAN_REPO) });
    const candidates = await detectDependencies(ctx);
    expect(candidates.length).toBeGreaterThan(0); // the post-4.17.21 CVEs, asserted below
    expect(candidates.find((c) => c.ruleId === "GHSA-jf85-cpcp-j695")).toBeUndefined();
    const lodashDep = candidates.filter((c) => c.metadata?.["package"] === "lodash");
    expect(lodashDep.length).toBeGreaterThan(0);
    for (const c of lodashDep) expect(c.metadata?.["fixedVersion"]).toBe("4.18.0");
    // Every candidate must be attributable to a real dependency the fixture
    // actually declares — nothing invented, nothing off-contract.
    for (const c of candidates) {
      expect(["lodash", "next"]).toContain(c.metadata?.["package"]);
    }
  });

  it("degrades gracefully when there is no manifest at all", async () => {
    const ctx = makeCtx({ files: memoryFileProvider([]) });
    expect(await detectDependencies(ctx)).toEqual([]);
    expect(ctx.warnings.join(" ")).toMatch(/no lockfile/i);
  });
});

// ---------------------------------------------------------------------------
// A12 — collectCalledPackages: real ts-morph call-site reachability
// ---------------------------------------------------------------------------

describe("discovery/sca collectCalledPackages (A12)", () => {
  it("marks `analyzed: false` when there is no TS/JS source at all", async () => {
    const result = await collectCalledPackages(memoryFileProvider([]));
    expect(result.analyzed).toBe(false);
    expect(result.called.size).toBe(0);
  });

  it("default import invoked directly is called", async () => {
    const files = memoryFileProvider([
      { path: "src/a.ts", content: 'import axios from "axios";\naxios("/x");\n' },
    ]);
    const { analyzed, called } = await collectCalledPackages(files);
    expect(analyzed).toBe(true);
    expect(called.has("axios")).toBe(true);
  });

  it("namespace import invoked via property access is called", async () => {
    const files = memoryFileProvider([
      { path: "src/a.ts", content: 'import * as _ from "lodash";\n_.debounce(() => {}, 10);\n' },
    ]);
    const { called } = await collectCalledPackages(files);
    expect(called.has("lodash")).toBe(true);
  });

  it("named import referenced but never called is NOT marked called", async () => {
    const files = memoryFileProvider([
      { path: "src/a.ts", content: 'import { debounce } from "lodash";\nconst d = debounce;\n' },
    ]);
    const { called } = await collectCalledPackages(files);
    expect(called.has("lodash")).toBe(false);
  });

  it("type-only import is never called", async () => {
    const files = memoryFileProvider([
      {
        path: "src/a.ts",
        content:
          'import type { Foo } from "some-types-pkg";\nexport function use(f: Foo): Foo {\n  return f;\n}\n',
      },
    ]);
    const { called } = await collectCalledPackages(files);
    expect(called.has("some-types-pkg")).toBe(false);
  });

  it("constructing an imported class (`new X()`) counts as called", async () => {
    const files = memoryFileProvider([
      {
        path: "src/a.ts",
        content: 'import { PrismaClient } from "@prisma/client";\nconst p = new PrismaClient();\n',
      },
    ]);
    const { called } = await collectCalledPackages(files);
    expect(called.has("@prisma/client")).toBe(true);
  });

  it("a JSX-rendered import counts as called", async () => {
    const files = memoryFileProvider([
      {
        path: "src/a.tsx",
        content: 'import { Icon } from "some-icon-lib";\nexport const view = <Icon />;\n',
      },
    ]);
    const { called } = await collectCalledPackages(files);
    expect(called.has("some-icon-lib")).toBe(true);
  });

  it("a CommonJS require() binding that is invoked counts as called", async () => {
    const files = memoryFileProvider([
      {
        path: "src/a.js",
        content: 'const request = require("request");\nrequest("http://x");\n',
      },
    ]);
    const { called } = await collectCalledPackages(files);
    expect(called.has("request")).toBe(true);
  });
});
