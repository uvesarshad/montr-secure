import { describe, it, expect } from "vitest";
import { RedTeamScenarioSchema, type RedTeamScenario } from "@montr/contracts";
import {
  REDTEAM_SCENARIO_CATALOGUE,
  ALL_OWASP_TOP_10_2021_IDS,
  OWASP_TOP_10_2021,
  owaspCoverage,
  instantiateScenario,
  seedRedTeamCatalogue,
} from "./redteam-catalogue.js";
import type { RedTeamScenarioRepository } from "./types.js";

const SAFE_TARGET = "https://REPLACE_WITH_ALLOWLISTED_STAGING_TARGET.internal.invalid";

/**
 * Mirrors `isRelativePath` in `@montr/confirm`'s `scenarios.ts` (the real
 * structural gate a scenario step is checked against before it can ever be
 * stored/enabled). Reimplemented here rather than imported: `@montr/confirm`
 * depends on `@montr/state-store`, so the reverse import would be circular —
 * this package must stay a leaf w.r.t. `@montr/confirm`.
 */
function isRelativePath(p: string): boolean {
  const trimmed = p.trim();
  if (trimmed.startsWith("//")) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return false;
  return true;
}

describe("REDTEAM_SCENARIO_CATALOGUE", () => {
  it("has at least 10 scenario templates", () => {
    expect(REDTEAM_SCENARIO_CATALOGUE.length).toBeGreaterThanOrEqual(10);
  });

  it("has unique catalogue keys and unique names", () => {
    const keys = REDTEAM_SCENARIO_CATALOGUE.map((t) => t.key);
    const names = REDTEAM_SCENARIO_CATALOGUE.map((t) => t.name);
    expect(new Set(keys).size).toBe(keys.length);
    expect(new Set(names).size).toBe(names.length);
  });

  it("covers every one of the OWASP Top 10 (2021) categories at least once", () => {
    const covered = owaspCoverage();
    for (const id of ALL_OWASP_TOP_10_2021_IDS) {
      expect(covered.has(id), `missing OWASP category ${id} (${OWASP_TOP_10_2021[id]})`).toBe(true);
    }
    expect(covered.size).toBe(10);
  });

  it("gives the commonly-tested categories (A01, A03) more than one scenario", () => {
    const byOwasp = (id: string) => REDTEAM_SCENARIO_CATALOGUE.filter((t) => t.owasp === id);
    expect(byOwasp("A01").length).toBeGreaterThan(1);
    expect(byOwasp("A03").length).toBeGreaterThan(1);
  });

  it("cites a named testing standard/methodology for every scenario", () => {
    for (const t of REDTEAM_SCENARIO_CATALOGUE) {
      expect(t.methodologySource.length).toBeGreaterThan(10);
      // Every citation names a recognized standard (WSTG, PTES, or a CWE id).
      expect(t.methodologySource).toMatch(/WSTG-|PTES|CWE-|OWASP Top 10/);
    }
  });

  it("every template has at least one step with real (non-placeholder) methodology text", () => {
    for (const t of REDTEAM_SCENARIO_CATALOGUE) {
      expect(t.steps.length).toBeGreaterThan(0);
      for (const s of t.steps) {
        expect(s.action.length).toBeGreaterThan(20);
        expect(s.action.toLowerCase()).not.toMatch(/\btodo\b|\bplaceholder\b|\btbd\b/);
      }
    }
  });

  it("every step path is relative to the allowlisted target (passes the same structural gate @montr/confirm enforces)", () => {
    for (const t of REDTEAM_SCENARIO_CATALOGUE) {
      for (const s of t.steps) {
        if (s.path !== undefined) {
          expect(
            isRelativePath(s.path),
            `${t.key} step ${s.order} path is not relative: ${s.path}`,
          ).toBe(true);
        }
      }
    }
  });

  it("no template hardcodes a targetAllowlistRef (must be supplied per-client at instantiation)", () => {
    for (const t of REDTEAM_SCENARIO_CATALOGUE) {
      expect(t).not.toHaveProperty("targetAllowlistRef");
    }
  });

  it("instantiateScenario produces a scenario that validates against the REAL RedTeamScenarioSchema, disabled by default, for every template", () => {
    let i = 0;
    for (const template of REDTEAM_SCENARIO_CATALOGUE) {
      const scenario = instantiateScenario(template, {
        id: `scn_test_${i++}`,
        clientId: "clnt_test",
        targetAllowlistRef: SAFE_TARGET,
        createdBy: "usr_test",
        createdAt: new Date("2026-08-19T00:00:00.000Z").toISOString(),
      });
      // instantiateScenario already calls RedTeamScenarioSchema.parse internally;
      // re-parsing here proves the RETURNED object independently round-trips
      // through the real schema (not just that parse() didn't throw once).
      const reparsed: RedTeamScenario = RedTeamScenarioSchema.parse(scenario);
      expect(reparsed.enabled).toBe(false);
      expect(reparsed.version).toBe(1);
      expect(reparsed.category).toBe(template.category);
      expect(reparsed.targetAllowlistRef).toBe(SAFE_TARGET);
    }
  });
});

/* ============================ seedRedTeamCatalogue ============================ */

function makeFakeRepo(): RedTeamScenarioRepository {
  const rows = new Map<string, RedTeamScenario>();
  return {
    async create(clientId, scenario) {
      const withClient = { ...scenario, clientId };
      rows.set(scenario.id, withClient);
      return withClient;
    },
    async get(_clientId, id) {
      return rows.get(id) ?? null;
    },
    async list(clientId) {
      return [...rows.values()].filter((r) => r.clientId === clientId);
    },
    async update(_clientId, scenario) {
      rows.set(scenario.id, scenario);
      return scenario;
    },
    async delete(_clientId, id) {
      rows.delete(id);
    },
  };
}

describe("seedRedTeamCatalogue", () => {
  it("creates one scenario per catalogue template, all disabled", async () => {
    const repo = makeFakeRepo();
    const { created, skipped } = await seedRedTeamCatalogue(repo, {
      clientId: "clnt_a",
      createdBy: "usr_1",
      targetAllowlistRef: SAFE_TARGET,
    });
    expect(created).toHaveLength(REDTEAM_SCENARIO_CATALOGUE.length);
    expect(skipped).toHaveLength(0);
    expect(created.every((s) => s.enabled === false)).toBe(true);
    expect(created.every((s) => s.clientId === "clnt_a")).toBe(true);
    expect(created.every((s) => s.targetAllowlistRef === SAFE_TARGET)).toBe(true);

    const stored = await repo.list("clnt_a");
    expect(stored).toHaveLength(REDTEAM_SCENARIO_CATALOGUE.length);
  });

  it("is idempotent — re-running skips scenarios that already exist by name", async () => {
    const repo = makeFakeRepo();
    await seedRedTeamCatalogue(repo, {
      clientId: "clnt_a",
      createdBy: "usr_1",
      targetAllowlistRef: SAFE_TARGET,
    });
    const second = await seedRedTeamCatalogue(repo, {
      clientId: "clnt_a",
      createdBy: "usr_1",
      targetAllowlistRef: SAFE_TARGET,
    });
    expect(second.created).toHaveLength(0);
    expect(second.skipped).toHaveLength(REDTEAM_SCENARIO_CATALOGUE.length);

    const stored = await repo.list("clnt_a");
    expect(stored).toHaveLength(REDTEAM_SCENARIO_CATALOGUE.length); // no duplicates
  });

  it("seeding one client never touches another client's scenarios (clientId scoping preserved)", async () => {
    const repo = makeFakeRepo();
    await seedRedTeamCatalogue(repo, {
      clientId: "clnt_a",
      createdBy: "usr_1",
      targetAllowlistRef: SAFE_TARGET,
    });
    const { created } = await seedRedTeamCatalogue(repo, {
      clientId: "clnt_b",
      createdBy: "usr_2",
      targetAllowlistRef: SAFE_TARGET,
    });
    expect(created).toHaveLength(REDTEAM_SCENARIO_CATALOGUE.length); // b starts fresh, not skipped by a's rows
    expect(await repo.list("clnt_a")).toHaveLength(REDTEAM_SCENARIO_CATALOGUE.length);
    expect(await repo.list("clnt_b")).toHaveLength(REDTEAM_SCENARIO_CATALOGUE.length);
  });
});
