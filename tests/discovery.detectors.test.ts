/**
 * WS-F / Layer 1 — unit tests for the three discovery sub-detectors and their
 * offline helpers. Fully offline: external scanner binaries are mocked via the
 * injectable runners, and file access uses the in-memory provider or the real
 * fs walker over the @montr/fixtures sample repos. No network, no DB.
 */
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { getHardenedDefaults } from "@montr/config";
import { createNullLogger } from "@montr/telemetry";
import type { ScanScope } from "@montr/contracts";
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
  it("matches lodash 4.17.11 (vulnerable) but not 4.17.21 (patched)", () => {
    const vuln = matchAdvisories("lodash", "4.17.11");
    expect(vuln.map((a) => a.id)).toContain("GHSA-jf85-cpcp-j695");
    expect(vuln[0]?.cwe).toContain("CWE-1321");
    expect(matchAdvisories("lodash", "4.17.21")).toHaveLength(0);
  });

  it("matches minimist and axios ranges from the seed DB", () => {
    expect(matchAdvisories("minimist", "1.2.5")).toHaveLength(1);
    expect(matchAdvisories("minimist", "1.2.6")).toHaveLength(0);
    expect(matchAdvisories("axios", "0.21.1").map((a) => a.id)).toContain("GHSA-cph5-m8f7-6c5x");
    expect(matchAdvisories("axios", "0.21.2")).toHaveLength(0);
  });

  it("seed DB is offline-only npm data", () => {
    expect(ADVISORY_DB.every((a) => a.ecosystem === "npm")).toBe(true);
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

  it("degrades gracefully when the runner reports the binary is missing", async () => {
    const runner: SemgrepRunner = async () => null;
    const ctx = makeCtx({ repoRoot: VULN_REPO });
    const candidates = await detectSast(ctx, { runner });
    expect(candidates).toEqual([]);
    expect(ctx.warnings.join(" ")).toMatch(/unavailable/i);
  });

  it("degrades (never throws) when the real semgrep binary is absent", async () => {
    // No injected runner + a real repoRoot -> defaultSemgrepRunner shells out;
    // semgrep is not installed in CI, so this must degrade to [] + a warning.
    const ctx = makeCtx({ repoRoot: VULN_REPO });
    const candidates = await detectSast(ctx);
    expect(candidates).toEqual([]);
    expect(ctx.warnings.length).toBeGreaterThan(0);
  });

  it("warns when there is neither a runner nor a repoRoot", async () => {
    const ctx = makeCtx();
    const candidates = await detectSast(ctx);
    expect(candidates).toEqual([]);
    expect(ctx.warnings.join(" ")).toMatch(/skipped/i);
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

  it("emits exactly one lodash candidate on the vulnerable sample, tagged unreachable", async () => {
    const ctx = makeCtx({ files: fsFileProvider(VULN_REPO) });
    const candidates = await detectDependencies(ctx);
    const dep = candidates.filter((c) => c.category === "vulnerable_dependency");
    expect(dep).toHaveLength(1);
    expect(dep[0]?.source).toBe("ghsa");
    expect(dep[0]?.ruleId).toBe("GHSA-jf85-cpcp-j695");
    expect(dep[0]?.cwe).toContain("CWE-1321");
    expect(dep[0]?.location).toMatchObject({ file: "package.json", line: 14 });
    expect(dep[0]?.metadata?.["reachable"]).toBe(false);
    expect(dep[0]?.metadata?.["package"]).toBe("lodash");
  });

  it("marks a vuln reachable when the package is actually imported", async () => {
    const files: RepoFile[] = [
      { path: "package.json", content: JSON.stringify({ dependencies: { lodash: "4.17.11" } }) },
      { path: "src/index.ts", content: 'import _ from "lodash";\n_.defaultsDeep({}, {});\n' },
    ];
    const ctx = makeCtx({ files: memoryFileProvider(files) });
    const candidates = await detectDependencies(ctx);
    expect(candidates[0]?.metadata?.["reachable"]).toBe(true);
  });

  it("clean sample (lodash patched) yields no SCA candidates", async () => {
    const ctx = makeCtx({ files: fsFileProvider(CLEAN_REPO) });
    expect(await detectDependencies(ctx)).toEqual([]);
  });

  it("degrades gracefully when there is no manifest at all", async () => {
    const ctx = makeCtx({ files: memoryFileProvider([]) });
    expect(await detectDependencies(ctx)).toEqual([]);
    expect(ctx.warnings.join(" ")).toMatch(/no lockfile/i);
  });
});
