/**
 * E16 — end-to-end proof that `@montr/discovery`'s `buildDependencyInventory`
 * output structurally satisfies `@montr/report`'s `DependencyInventoryInput`
 * with ZERO adaptation, despite report having no package dependency on
 * discovery (see `packages/report/src/exports/cyclonedx.ts`'s module doc for
 * why that decoupling was chosen). This is the real caller shape: a Layer 5
 * report-assembly site would run `buildDependencyInventory(fileProvider)`
 * from discovery and hand the result straight to
 * `generateExport(report, "cyclonedx", { dependencyInventory })`.
 */
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect, beforeAll } from "vitest";
import type { Report } from "@montr/contracts";
import { buildDependencyInventory, fsFileProvider } from "@montr/discovery";
import { buildReport, generateExport, buildCycloneDxSbom } from "@montr/report";
import { mockScan, mockConfirmedFindings, mockCostRollup, FIXED_LATER } from "@montr/fixtures";

const VULNERABLE_NEXTJS = nodePath.join(
  fileURLToPath(new URL("../packages/fixtures/sample-repos/", import.meta.url)),
  "vulnerable-nextjs",
);

let report: Report;

beforeAll(async () => {
  const out = await buildReport({
    scan: mockScan,
    confirmed: mockConfirmedFindings,
    unconfirmed: [],
    fixes: [],
    costRollup: mockCostRollup,
    autoApply: false,
    generatedAt: FIXED_LATER,
  });
  report = out.report;
});

describe("SBOM end-to-end: discovery's DependencyInventory -> report's CycloneDX exporter", () => {
  it("buildDependencyInventory's real output feeds buildCycloneDxSbom directly, no adapter", async () => {
    const inventory = await buildDependencyInventory(fsFileProvider(VULNERABLE_NEXTJS));
    // No spread, no field mapping — the exact object discovery produced.
    const bom = buildCycloneDxSbom(inventory);
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.components.length).toBe(inventory.components.length);
    expect(bom.vulnerabilities.length).toBe(inventory.vulnerabilities.length);
    const lodash = bom.components.find((c) => c.name === "lodash");
    expect(lodash?.properties).toContainEqual({ name: "montr:reachable", value: "false" });
  });

  it("the same real inventory flows through generateExport's registered 'cyclonedx' exporter", async () => {
    const inventory = await buildDependencyInventory(fsFileProvider(VULNERABLE_NEXTJS));
    const out = await generateExport(report, "cyclonedx", { dependencyInventory: inventory });
    const parsed = JSON.parse(out.content as string);
    expect(parsed.components.length).toBe(inventory.components.length);
    expect(out.artifact.format).toBe("cyclonedx");
  });
});
