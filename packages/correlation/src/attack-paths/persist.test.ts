/**
 * B8 — `discoverAndPersistAttackPaths` wires the pure `buildAttackPaths`
 * graph to `StateStore.attackPaths` (`AttackPathRepository`, B1). Uses a
 * minimal in-memory fake repository — no DB.
 */
import { describe, it, expect } from "vitest";
import {
  AppMapSchema,
  ConfirmedFindingSchema,
  type AppMap,
  type AttackPath,
  type ConfirmedFinding,
} from "@montr/contracts";
import type { AttackPathRepository } from "@montr/state-store";
import { discoverAndPersistAttackPaths } from "./persist.js";

const NOW = "2026-08-22T00:00:00.000Z";

function fakeAttackPathRepo(): AttackPathRepository & { rows: AttackPath[] } {
  const rows: AttackPath[] = [];
  return {
    rows,
    create(clientId, path) {
      const row = { ...path, clientId };
      rows.push(row);
      return Promise.resolve(row);
    },
    get(clientId, id) {
      return Promise.resolve(rows.find((r) => r.id === id && r.clientId === clientId) ?? null);
    },
    list(clientId) {
      return Promise.resolve(rows.filter((r) => r.clientId === clientId));
    },
  };
}

function mkFinding(
  overrides: Partial<ConfirmedFinding> &
    Pick<ConfirmedFinding, "id" | "title" | "category" | "location">,
): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    scanId: "scan_1",
    clientId: "client_1",
    severity: "critical",
    exposure: "public",
    impact: "impact",
    proofType: "static",
    proofArtifact: { kind: "static", argument: "arg", dataFlow: [], sanitizersBypassed: [] },
    createdAt: NOW,
    ...overrides,
  });
}

describe("discoverAndPersistAttackPaths", () => {
  it("persists every discovered chain via the repository, in ranked order", async () => {
    const appMap: AppMap = AppMapSchema.parse({
      id: "appmap_1",
      clientId: "client_1",
      repo: "https://example.internal/x",
      branch: "main",
      commitSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334",
      createdAt: NOW,
      routes: [
        {
          id: "r1",
          path: "/api/convert",
          method: "POST",
          authState: "public",
          isApiRoute: true,
          handler: { file: "a.ts", line: 1 },
        },
        {
          id: "r2",
          path: "/api/reports",
          method: "GET",
          authState: "authenticated",
          isApiRoute: true,
          handler: { file: "b.ts", line: 1 },
        },
      ],
    });
    const rce = mkFinding({
      id: "f1",
      title: "RCE",
      category: "command_injection",
      location: { file: "a.ts", line: 1 },
    });
    const other = mkFinding({
      id: "f2",
      title: "Other",
      category: "rate_limit_missing",
      location: { file: "b.ts", line: 1 },
    });

    const repo = fakeAttackPathRepo();
    const persisted = await discoverAndPersistAttackPaths(repo, {
      clientId: "client_1",
      scanId: "scan_1",
      appMap,
      findings: [rce, other],
      now: NOW,
    });

    expect(persisted).toHaveLength(1);
    expect(repo.rows).toHaveLength(1);
    expect(repo.rows[0]!.clientId).toBe("client_1");
    expect(repo.rows[0]!.steps.map((s) => s.findingId)).toEqual(["f1", "f2"]);
  });

  it("persists nothing when no chain is discovered", async () => {
    const appMap: AppMap = AppMapSchema.parse({
      id: "appmap_1",
      clientId: "client_1",
      repo: "https://example.internal/x",
      branch: "main",
      commitSha: "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334",
      createdAt: NOW,
      routes: [],
    });
    const repo = fakeAttackPathRepo();
    const persisted = await discoverAndPersistAttackPaths(repo, {
      clientId: "client_1",
      scanId: "scan_1",
      appMap,
      findings: [],
      now: NOW,
    });
    expect(persisted).toHaveLength(0);
    expect(repo.rows).toHaveLength(0);
  });
});
