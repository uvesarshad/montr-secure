/**
 * E16 — supply-chain risk detector tests. Real fixture files on disk for
 * typosquatting/install-script/non-standard-registry (via `fsFileProvider`,
 * `packages/fixtures/sample-repos/supply-chain-samples/`), plus a targeted
 * in-memory test for the dependency-install-script probe: real `node_modules`
 * fixtures are impossible to commit (this repo's root `.gitignore` excludes
 * `node_modules/` everywhere, by design — see `util/files.ts`'s
 * `IGNORE_DIRS`), so that one check is proven with `memoryFileProvider`
 * instead, which exercises the exact same `FileProvider.read()` path a real
 * on-disk `node_modules` would.
 */
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { getHardenedDefaults } from "@montr/config";
import { createNullLogger } from "@montr/telemetry";
import { AppMapSchema, type ScanScope } from "@montr/contracts";
import {
  detectSupplyChainRisks,
  detectTyposquats,
  levenshtein,
  detectDependencyInstallScriptRisk,
  detectSuspiciousRegistryResolution,
  POPULAR_NPM_PACKAGES,
} from "./supply-chain.js";
import { resolveInstalledPackages } from "./sca.js";
import type { DetectorContext } from "../types.js";
import { fsFileProvider, memoryFileProvider } from "../util/files.js";

const FULL_SCOPE: ScanScope = {
  mode: "full",
  includePaths: [],
  excludePaths: [],
  changedFiles: [],
  reachableFromChanges: false,
};

const minimalAppMap = AppMapSchema.parse({
  id: "appmap_test_0001",
  clientId: "client_test_0001",
  repo: "https://example.test/repo.git",
  branch: "main",
  commitSha: "0000000000000000000000000000000000000a",
  createdAt: "2026-01-15T10:00:00.000Z",
});

function makeCtx(repoRoot: string): DetectorContext {
  const warnings: string[] = [];
  return {
    clientId: "client_test_0001",
    scanId: "scan_test_0001",
    appMap: minimalAppMap,
    scope: FULL_SCOPE,
    config: getHardenedDefaults(),
    repoRoot,
    files: fsFileProvider(repoRoot),
    now: () => "2026-01-15T10:00:00.000Z",
    logger: createNullLogger(),
    signal: undefined,
    warnings,
    warn(detector: string, message: string): void {
      warnings.push(`[${detector}] ${message}`);
    },
  };
}

const FIXTURES_ROOT = fileURLToPath(
  new URL("../../../fixtures/sample-repos/supply-chain-samples/", import.meta.url),
);

describe("discovery/supply-chain — levenshtein", () => {
  it("is 0 for identical strings", () => {
    expect(levenshtein("express", "express")).toBe(0);
  });
  it("counts single-character edits correctly", () => {
    expect(levenshtein("express", "expres")).toBe(1); // deletion
    expect(levenshtein("lodash", "1odash")).toBe(1); // substitution
    expect(levenshtein("axios", "axios1")).toBe(1); // insertion
  });
});

describe("discovery/supply-chain — detectTyposquats (pure)", () => {
  it("flags a name one edit away from a popular package", () => {
    const hits = detectTyposquats([{ name: "expres", version: "4.18.2" }]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.matchedPopular).toBe("express");
    expect(hits[0]?.distance).toBe(1);
  });

  it("never flags an exact match to a popular package", () => {
    for (const name of ["react", "express", "lodash", "@babel/core"]) {
      expect(detectTyposquats([{ name, version: "1.0.0" }])).toEqual([]);
    }
  });

  it("never flags a name that is nowhere near any popular package", () => {
    const hits = detectTyposquats([
      { name: "@my-company/internal-billing-utils", version: "1.0.0" },
    ]);
    expect(hits).toEqual([]);
  });

  it("POPULAR_NPM_PACKAGES is non-trivial (a real curated list, not a stub)", () => {
    expect(POPULAR_NPM_PACKAGES.length).toBeGreaterThan(50);
  });
});

describe("discovery/supply-chain — vulnerable fixture (real files on disk)", () => {
  const repoRoot = nodePath.join(FIXTURES_ROOT, "vulnerable");

  it("flags both typosquatted dependencies (expres->express, lodahs->lodash)", async () => {
    const resolved = await resolveInstalledPackages(fsFileProvider(repoRoot));
    const candidates = await detectSupplyChainRisks(makeCtx(repoRoot), resolved);
    const typosquats = candidates.filter((c) => c.ruleId === "supply-chain.typosquat");
    const flaggedNames = typosquats.map((c) => c.metadata?.["package"]).sort();
    expect(flaggedNames).toEqual(["expres", "lodahs"]);
    expect(typosquats.every((c) => c.category === "vulnerable_dependency")).toBe(true);
  });

  it("flags the suspicious postinstall script (curl | bash)", async () => {
    const resolved = await resolveInstalledPackages(fsFileProvider(repoRoot));
    const candidates = await detectSupplyChainRisks(makeCtx(repoRoot), resolved);
    const script = candidates.find((c) => c.ruleId === "supply-chain.install-script.postinstall");
    expect(script).toBeDefined();
    expect(script?.rawSeverity).toBe("high");
    expect(script?.evidenceSnippet).toContain("shell");
  });

  it("flags the non-standard-registry resolution for 'expres'", async () => {
    const resolved = await resolveInstalledPackages(fsFileProvider(repoRoot));
    const candidates = await detectSupplyChainRisks(makeCtx(repoRoot), resolved);
    const nonStandard = candidates.find((c) => c.ruleId === "supply-chain.non-standard-registry");
    expect(nonStandard).toBeDefined();
    expect(nonStandard?.metadata?.["host"]).toBe("npm.suspicious-mirror.example.com");
  });

  it("detectSuspiciousRegistryResolution directly: react (npmjs) is clean, expres/lodahs' registry.npmjs.org entries are also clean (only expres's host differs)", async () => {
    const content = await fsFileProvider(repoRoot).read("package-lock.json");
    const hits = detectSuspiciousRegistryResolution(content ?? "");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.packageName).toBe("expres");
  });
});

describe("discovery/supply-chain — clean fixture (real files on disk, must produce zero findings)", () => {
  const repoRoot = nodePath.join(FIXTURES_ROOT, "clean");

  it("no typosquats, no install-script risk, no non-standard registry", async () => {
    const resolved = await resolveInstalledPackages(fsFileProvider(repoRoot));
    const candidates = await detectSupplyChainRisks(makeCtx(repoRoot), resolved);
    expect(candidates).toEqual([]);
  });
});

describe("discovery/supply-chain — dependency install-script risk (in-memory node_modules, see module doc)", () => {
  it("flags a suspicious postinstall script in a resolved dependency's own package.json", async () => {
    const files = memoryFileProvider([
      {
        path: "package.json",
        content: JSON.stringify({ name: "app", dependencies: { evilpkg: "1.0.0" } }),
      },
      {
        path: "node_modules/evilpkg/package.json",
        content: JSON.stringify({
          name: "evilpkg",
          version: "1.0.0",
          scripts: { postinstall: "node -e \"eval(Buffer.from('bad','base64').toString())\"" },
        }),
      },
    ]);
    const ctx = makeCtx("/unused");
    ctx.files = files;
    const hits = await detectDependencyInstallScriptRisk(ctx, [
      { name: "evilpkg", version: "1.0.0" },
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe("high");
    expect(hits[0]?.reasons.length).toBeGreaterThan(0);
  });

  it("does not flag a dependency with a benign postinstall script (e.g. a plain build step)", async () => {
    const files = memoryFileProvider([
      {
        path: "node_modules/benign-pkg/package.json",
        content: JSON.stringify({
          name: "benign-pkg",
          version: "1.0.0",
          scripts: { postinstall: "node ./scripts/build.js" },
        }),
      },
    ]);
    const ctx = makeCtx("/unused");
    ctx.files = files;
    const hits = await detectDependencyInstallScriptRisk(ctx, [
      { name: "benign-pkg", version: "1.0.0" },
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe("low");
    expect(hits[0]?.reasons).toEqual([]);
  });

  it("finds nothing when node_modules is absent (true absence, not a swallowed error)", async () => {
    const ctx = makeCtx("/unused");
    ctx.files = memoryFileProvider([{ path: "package.json", content: "{}" }]);
    const hits = await detectDependencyInstallScriptRisk(ctx, [
      { name: "somepkg", version: "1.0.0" },
    ]);
    expect(hits).toEqual([]);
  });
});
