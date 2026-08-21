/**
 * E16 — `buildDependencyInventory` real-fixture tests. Runs against the
 * repo's own `packages/fixtures/sample-repos/vulnerable-nextjs` fixture (real
 * files on disk via `fsFileProvider`, not hand-typed strings) — the same
 * fixture `secrets.real-output.test.ts`/A12's SCA reachability work already
 * exercises, so this proves the SBOM inventory sees the exact same resolved
 * package set + reachability signal the CandidateFinding-producing
 * `detectDependencies` path does, just without dropping the non-vulnerable
 * packages.
 */
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { buildDependencyInventory } from "./sbom.js";
import { fsFileProvider } from "./util/files.js";

const VULNERABLE_NEXTJS = nodePath.join(
  fileURLToPath(new URL("../../fixtures/sample-repos/", import.meta.url)),
  "vulnerable-nextjs",
);

describe("discovery/sbom — buildDependencyInventory (real fixture, no lockfile)", () => {
  it("resolves the full dependency tree from package.json, not just the vulnerable subset", async () => {
    const inventory = await buildDependencyInventory(fsFileProvider(VULNERABLE_NEXTJS));
    const names = inventory.components.map((c) => c.name).sort();
    // Real fixture package.json: next, react, react-dom, @prisma/client, lodash
    // (deps) + prisma (devDep) — ALL of them, not filtered to matched advisories.
    expect(names).toEqual(
      ["@prisma/client", "lodash", "next", "prisma", "react", "react-dom"].sort(),
    );
    expect(inventory.components.every((c) => c.ecosystem === "npm")).toBe(true);
  });

  it("matches lodash@4.17.11 against the real offline advisory mirror", async () => {
    const inventory = await buildDependencyInventory(fsFileProvider(VULNERABLE_NEXTJS));
    const lodashVulns = inventory.vulnerabilities.filter((v) => v.packageName === "lodash");
    expect(lodashVulns.length).toBeGreaterThan(0);
    expect(lodashVulns[0]?.source === "osv" || lodashVulns[0]?.source === "ghsa").toBe(true);
  });

  it("real call-site reachability (A12): lodash is a manifest dependency but never imported/called anywhere in this fixture — reachable: false", async () => {
    const inventory = await buildDependencyInventory(fsFileProvider(VULNERABLE_NEXTJS));
    const lodash = inventory.components.find((c) => c.name === "lodash");
    expect(lodash?.reachable).toBe(false);
    // The vulnerability entry carries the SAME reachability signal as its component.
    const lodashVuln = inventory.vulnerabilities.find((v) => v.packageName === "lodash");
    expect(lodashVuln?.reachable).toBe(false);
  });

  it("returns an empty inventory (not a throw) when no lockfile or package.json exists", async () => {
    const inventory = await buildDependencyInventory(fsFileProvider("/nonexistent-repo-path"));
    expect(inventory).toEqual({ components: [], vulnerabilities: [] });
  });
});
