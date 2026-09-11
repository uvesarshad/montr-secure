/**
 * WS-E — Layer 0 (@montr/appmap) tests. Fully OFFLINE: scans the on-disk
 * @montr/fixtures sample Next.js/Prisma repos in place (no clone), uses the fake
 * LLM adapter, and stubs persistence with in-memory repos. Verifies the
 * deterministic App Map, the gated LLM auth-boundary pass, cost estimation, diff
 * scoping, DECIDE-2 persistence/reuse, and the ⛔ golden-rule guardrails.
 */
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import {
  buildAppMap,
  createLayer0Runner,
  computeDiffScope,
  createProject,
  collectFiles,
} from "@montr/appmap";
import type { BuildAppMapInput } from "@montr/appmap";
import { getHardenedDefaults } from "@montr/config";
import { createFakeLlmGateway } from "@montr/fixtures";
import { CLIENT_ID, SCAN_ID, FIXED_NOW, COMMIT_SHA } from "@montr/fixtures";
import { createNullLogger } from "@montr/telemetry";
import {
  ScanScopeSchema,
  Layer0OutputSchema,
  type AppMap,
  type AuditEvent,
  type AuditEventInput,
  type LLMGateway,
  type LLMRequest,
} from "@montr/contracts";
import type { AppMapRepository } from "@montr/state-store";
import type { AuditLogClient } from "@montr/telemetry";

const VULN_DIR = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/vulnerable-nextjs", import.meta.url),
);
const CLEAN_DIR = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/clean-nextjs", import.meta.url),
);
const SECOND_COMMIT = "b1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";

function baseInput(overrides: Partial<BuildAppMapInput> = {}): BuildAppMapInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    repo: VULN_DIR,
    branch: "main",
    mode: "full",
    scope: ScanScopeSchema.parse({ mode: "full" }),
    config: getHardenedDefaults(),
    commitSha: COMMIT_SHA,
    ...overrides,
  };
}

const fixedNow = (): Date => new Date(FIXED_NOW);

/** In-memory AppMapRepository (row-scoped like the real one). */
class MemAppMaps implements AppMapRepository {
  rows: AppMap[] = [];
  createCalls = 0;
  create(clientId: string, appMap: AppMap): Promise<AppMap> {
    if (this.rows.some((r) => r.clientId === clientId && r.id === appMap.id)) {
      return Promise.reject(new Error(`duplicate appMap id ${appMap.id}`));
    }
    this.createCalls++;
    const stored = { ...appMap, clientId };
    this.rows.push(stored);
    return Promise.resolve({ ...stored });
  }
  get(clientId: string, id: string): Promise<AppMap | null> {
    return Promise.resolve(this.rows.find((r) => r.clientId === clientId && r.id === id) ?? null);
  }
  list(clientId: string): Promise<AppMap[]> {
    return Promise.resolve(this.rows.filter((r) => r.clientId === clientId));
  }
  latestForCommit(clientId: string, repo: string, commitSha: string): Promise<AppMap | null> {
    const found = [...this.rows]
      .reverse()
      .find((r) => r.clientId === clientId && r.repo === repo && r.commitSha === commitSha);
    return Promise.resolve(found ?? null);
  }
  latestForRepo(clientId: string, repo: string): Promise<AppMap | null> {
    const found = [...this.rows].reverse().find((r) => r.clientId === clientId && r.repo === repo);
    return Promise.resolve(found ?? null);
  }
  markStale(clientId: string, appMapId: string): Promise<void> {
    const m = this.rows.find((r) => r.clientId === clientId && r.id === appMapId);
    if (m) m.stale = true;
    return Promise.resolve();
  }
  invalidateStaleForCommit(
    clientId: string,
    repo: string,
    currentCommitSha: string,
  ): Promise<number> {
    let count = 0;
    for (const r of this.rows) {
      if (
        r.clientId === clientId &&
        r.repo === repo &&
        r.commitSha !== currentCommitSha &&
        !r.stale
      ) {
        r.stale = true;
        count++;
      }
    }
    return Promise.resolve(count);
  }
}

/** In-memory audit client capturing appended events. */
class MemAudit implements AuditLogClient {
  events: AuditEventInput[] = [];
  append(input: AuditEventInput): Promise<AuditEvent> {
    this.events.push(input);
    return Promise.resolve({
      ...input,
      id: `ev_${this.events.length}`,
      sequence: this.events.length,
      prevHash: "",
      hash: `hash_${this.events.length}`,
      at: FIXED_NOW,
      metadata: input.metadata ?? {},
    } as AuditEvent);
  }
  list(): Promise<AuditEvent[]> {
    return Promise.resolve([]);
  }
  verifyChain(): Promise<boolean> {
    return Promise.resolve(true);
  }
}

describe("appmap — deterministic App Map (vulnerable sample repo)", () => {
  it("detects languages, frameworks, routes, models, surfaces, taint", async () => {
    const out = await buildAppMap(baseInput(), { gateway: createFakeLlmGateway(), now: fixedNow });

    // Emits the exact Layer0Output contract.
    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
    const { appMap } = out;
    expect(appMap.createdAt).toBe(FIXED_NOW);
    expect(appMap.commitSha).toBe(COMMIT_SHA);

    expect(appMap.languages).toEqual(expect.arrayContaining(["typescript", "javascript"]));
    expect(appMap.frameworks).toEqual(expect.arrayContaining(["nextjs", "react", "prisma"]));

    // Registered routes (app router: API route.ts + page).
    const users = appMap.routes.find((r) => r.path === "/api/users");
    const search = appMap.routes.find((r) => r.path === "/search");
    expect(users).toBeDefined();
    expect(users?.method).toBe("GET");
    expect(users?.isApiRoute).toBe(true);
    expect(search).toBeDefined();
    expect(search?.isApiRoute).toBe(false);

    // Prisma DMMF models + data store.
    expect(appMap.dataStores.some((d) => d.kind === "postgres")).toBe(true);
    const user = appMap.ormModels.find((m) => m.name === "User");
    expect(user).toBeDefined();
    expect(user?.file).toBe("prisma/schema.prisma");
    expect(user?.fields.map((f) => f.name)).toEqual(
      expect.arrayContaining(["id", "email", "name"]),
    );
    expect(user?.fields.find((f) => f.name === "id")?.isId).toBe(true);

    // Env/secret surface — hardcoded key in a config file.
    const secret = appMap.envSecretSurfaces.find((s) => s.name === "PAYMENTS_API_KEY");
    expect(secret).toBeDefined();
    expect(secret?.kind).toBe("config_file");
    expect(secret?.location.line).toBe(2);

    // Taint sources link to their route; sinks anchor to the tainted line.
    const sqlSink = appMap.taintSinks.find((s) => s.kind === "orm_raw_query");
    expect(sqlSink?.location).toMatchObject({ file: "app/api/users/route.ts", line: 9 });
    const xssSink = appMap.taintSinks.find((s) => s.kind === "html_render");
    expect(xssSink?.location).toMatchObject({ file: "app/search/page.tsx", line: 8 });

    const usersSource = appMap.taintSources.find(
      (s) => s.location.file === "app/api/users/route.ts",
    );
    expect(usersSource).toMatchObject({ kind: "query_param", routeId: users?.id });
    expect(usersSource?.location.line).toBe(6);
    const searchSource = appMap.taintSources.find((s) => s.location.file === "app/search/page.tsx");
    expect(searchSource).toMatchObject({ kind: "query_param", routeId: search?.id });
    expect(searchSource?.location.line).toBe(4);

    // Third-party call surface excludes framework/ORM imports → empty here.
    expect(appMap.thirdPartyCalls).toEqual([]);
  });

  it("projects a cost estimate from map size (full mode, 4 layer line items)", async () => {
    const out = await buildAppMap(baseInput(), { gateway: createFakeLlmGateway(), now: fixedNow });
    expect(out.costEstimate.mode).toBe("full");
    expect(out.costEstimate.projectedTotalTokens).toBeGreaterThan(0);
    expect(out.costEstimate.projectedUsd).toBeGreaterThanOrEqual(0);
    expect(out.costEstimate.byLayer).toHaveLength(4);
    expect(out.scope.routeCount).toBe(out.appMap.routes.length);
    expect(out.scope.fileCount).toBeGreaterThan(0);
    expect(out.scope.reachableFromChanges).toBe(false);
  });
});

describe("appmap — ⛔ LLM semantic pass is gated + code-free (golden rules #1, #6)", () => {
  it("labels auth boundaries only AFTER the deterministic map, with NO code egress", async () => {
    const calls: LLMRequest[] = [];
    const fake = createFakeLlmGateway();
    const spy: LLMGateway = {
      complete: (req) => {
        calls.push(req);
        return fake.complete(req);
      },
      stream: (req) => fake.stream(req),
      listModels: () => fake.listModels(),
      resolveModel: (t) => fake.resolveModel(t),
    };

    const out = await buildAppMap(baseInput(), { gateway: spy, now: fixedNow });

    // Two Layer-0 semantic-pass calls: auth-boundary labeling, then the E6
    // threat-model derivation — both gated on the deterministic map already
    // existing, both code-free.
    expect(calls).toHaveLength(2);
    const req = calls.find((c) => c.metadata.purpose === "appmap_labeling")!;
    expect(req).toBeDefined();
    expect(req.metadata.layer).toBe("layer0");

    // The prompt carries STRUCTURAL data (route paths) — proof the map existed —
    // but NEVER source bodies / secrets.
    const prompt = (req.system ?? "") + JSON.stringify(req.messages);
    expect(prompt).toContain("/api/users");
    expect(prompt).not.toContain("queryRawUnsafe");
    expect(prompt).not.toContain("dangerouslySetInnerHTML");
    expect(prompt).not.toContain("sk_live_");
    expect(prompt).not.toContain("SELECT * FROM");

    // E6: the threat-model call is equally code-free and structural-only.
    const tmReq = calls.find((c) => c.metadata.purpose === "threat_model")!;
    expect(tmReq).toBeDefined();
    expect(tmReq.metadata.layer).toBe("layer0");
    const tmPrompt = (tmReq.system ?? "") + JSON.stringify(tmReq.messages);
    expect(tmPrompt).toContain("/api/users");
    expect(tmPrompt).not.toContain("queryRawUnsafe");
    expect(tmPrompt).not.toContain("dangerouslySetInnerHTML");
    expect(tmPrompt).not.toContain("sk_live_");
    expect(tmPrompt).not.toContain("SELECT * FROM");

    // The canned label flips the unknown public route → public.
    expect(out.appMap.routes.find((r) => r.path === "/api/users")?.authState).toBe("public");
    // A route the model didn't classify stays "unknown" (fail-safe, not guessed).
    expect(out.appMap.routes.find((r) => r.path === "/search")?.authState).toBe("unknown");

    // E6: the threat model is always attached, and is grounded in the real map.
    expect(out.appMap.threatModel).toBeDefined();
    expect(out.appMap.threatModel?.attackSurface.some((e) => e.category === "sql_injection")).toBe(
      true,
    );
  });

  it("produces a valid deterministic-only map when no gateway is wired", async () => {
    const out = await buildAppMap(baseInput(), { now: fixedNow });
    // No LLM ⇒ auth boundary stays at the deterministic default.
    expect(out.appMap.routes.find((r) => r.path === "/api/users")?.authState).toBe("unknown");
    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
  });
});

describe("appmap — clean sample repo", () => {
  it("detects the deterministic auth gate and no raw-query sink", async () => {
    const out = await buildAppMap(baseInput({ repo: CLEAN_DIR, commitSha: SECOND_COMMIT }), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
    });
    const users = out.appMap.routes.find((r) => r.path === "/api/users");
    expect(users?.authState).toBe("authenticated");
    expect(users?.authGate).toBe("requireSession");
    // findMany is parameterized — not a raw-query sink.
    expect(out.appMap.taintSinks.some((s) => s.kind === "orm_raw_query")).toBe(false);
    // The secret is READ from the environment (safe), not hard-coded: the surface
    // is a `process_env` read, and there is NO hardcoded `config_file` secret.
    expect(out.appMap.envSecretSurfaces.some((s) => s.kind === "config_file")).toBe(false);
    const envRead = out.appMap.envSecretSurfaces.find((s) => s.kind === "process_env");
    expect(envRead?.name).toBe("PAYMENTS_API_KEY");
  });
});

describe("appmap — diff mode scoping", () => {
  it("scopes to changed files + reachable graph and discounts cost", async () => {
    const full = await buildAppMap(baseInput(), { gateway: createFakeLlmGateway(), now: fixedNow });
    const diff = await buildAppMap(
      baseInput({ mode: "diff", changedFiles: ["app/api/users/route.ts"] }),
      { gateway: createFakeLlmGateway(), now: fixedNow },
    );

    expect(diff.scope.mode).toBe("diff");
    expect(diff.scope.reachableFromChanges).toBe(true);
    expect(diff.scope.changedFiles).toContain("app/api/users/route.ts");
    expect(diff.scope.includePaths).toContain("app/api/users/route.ts");
    expect(diff.costEstimate.mode).toBe("diff");
    // Diff scan is cheaper than a full scan of the same repo.
    expect(diff.costEstimate.projectedUsd).toBeLessThan(full.costEstimate.projectedUsd);
  });

  it("computeDiffScope returns changed files when the graph has no local edges", async () => {
    const inv = await collectFiles(VULN_DIR);
    const project = createProject(VULN_DIR, inv.sourceFiles);
    const scope = computeDiffScope(project, VULN_DIR, inv.sourceFiles, ["app/search/page.tsx"]);
    expect(scope.changedFiles).toEqual(["app/search/page.tsx"]);
    expect(scope.reachable).toContain("app/search/page.tsx");
  });
});

describe("appmap — DECIDE-2 persistence, invalidation, reuse", () => {
  it("persists the map and audits appmap.built", async () => {
    const appMaps = new MemAppMaps();
    const audit = new MemAudit();
    await buildAppMap(baseInput(), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
      appMaps,
      audit,
    });

    expect(appMaps.rows).toHaveLength(1);
    expect(appMaps.createCalls).toBe(1);
    expect(audit.events.some((e) => e.action === "appmap.built")).toBe(true);
    const built = audit.events.find((e) => e.action === "appmap.built");
    // Audit metadata is counts/ids only — never code bodies.
    expect(built?.metadata).toMatchObject({ repo: VULN_DIR, commitSha: COMMIT_SHA });
    expect(JSON.stringify(built)).not.toContain("sk_live_");
  });

  it("invalidates prior maps on a new commit (never deletes)", async () => {
    const appMaps = new MemAppMaps();
    const audit = new MemAudit();
    await buildAppMap(baseInput({ scanId: "scan_a" }), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
      appMaps,
      audit,
    });
    await buildAppMap(baseInput({ scanId: "scan_b", commitSha: SECOND_COMMIT }), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
      appMaps,
      audit,
    });

    expect(appMaps.rows).toHaveLength(2); // kept, not deleted
    expect(appMaps.rows.find((r) => r.commitSha === COMMIT_SHA)?.stale).toBe(true);
    expect(appMaps.rows.find((r) => r.commitSha === SECOND_COMMIT)?.stale).toBe(false);
    expect(audit.events.some((e) => e.action === "appmap.invalidated")).toBe(true);
  });

  it("reuses a fresh persisted map for the same commit (skips rebuild)", async () => {
    const appMaps = new MemAppMaps();
    await buildAppMap(baseInput({ scanId: "scan_1" }), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
      appMaps,
    });
    const reuse = await buildAppMap(baseInput({ scanId: "scan_2" }), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
      appMaps,
    });

    expect(appMaps.createCalls).toBe(1); // second build reused, no new create
    expect(reuse.appMap.id).toBe("appmap_scan_1");
  });
});

describe("appmap — A9 semantic-index build hook (best-effort, alongside the App Map)", () => {
  it("calls the hook with dir/clientId/appMapId/repo/commitSha while the checkout still exists", async () => {
    const calls: Array<{
      dir: string;
      clientId: string;
      appMapId: string;
      repo: string;
      commitSha: string;
    }> = [];
    const out = await buildAppMap(baseInput(), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
      semanticIndex: async (input) => {
        calls.push(input);
        // Prove the checkout is still readable at call time (not cleaned up yet).
        const { collectFiles: collect } = await import("@montr/appmap");
        const inv = await collect(input.dir);
        expect(inv.sourceFiles.length).toBeGreaterThan(0);
      },
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.clientId).toBe(CLIENT_ID);
    expect(calls[0]?.repo).toBe(VULN_DIR);
    expect(calls[0]?.commitSha).toBe(COMMIT_SHA);
    expect(calls[0]?.appMapId).toBe(out.appMap.id);
  });

  it("a throwing hook is caught and logged — never fails the scan's App Map build", async () => {
    const out = await buildAppMap(baseInput(), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
      semanticIndex: async () => {
        throw new Error("pgvector extension not installed");
      },
    });
    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
    expect(out.appMap.routes.length).toBeGreaterThanOrEqual(2);
  });

  it("is skipped on the DECIDE-2 reuse path (the reused map's index was already built)", async () => {
    const appMaps = new MemAppMaps();
    let calls = 0;
    await buildAppMap(baseInput({ scanId: "scan_reuse_1" }), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
      appMaps,
      semanticIndex: async () => {
        calls++;
      },
    });
    await buildAppMap(baseInput({ scanId: "scan_reuse_2" }), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
      appMaps,
      semanticIndex: async () => {
        calls++;
      },
    });

    expect(appMaps.createCalls).toBe(1); // second build reused, per the existing DECIDE-2 test above
    expect(calls).toBe(1); // semantic index built once, not rebuilt on reuse
  });

  it("omitting the hook leaves the App Map build byte-identical (default, unchanged)", async () => {
    const out = await buildAppMap(baseInput(), { gateway: createFakeLlmGateway(), now: fixedNow });
    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
  });
});

describe("appmap — orchestrator runner adapter", () => {
  it("runs from a LayerContext-shaped input and emits Layer0Output (no double-create)", async () => {
    const appMaps = new MemAppMaps();
    const audit = new MemAudit();
    const runner = createLayer0Runner({ gateway: createFakeLlmGateway() });
    const out = await runner({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: { commitSha: COMMIT_SHA },
      job: {
        repo: VULN_DIR,
        branch: "main",
        mode: "full",
        scope: ScanScopeSchema.parse({ mode: "full" }),
      },
      config: getHardenedDefaults(),
      logger: createNullLogger(),
      store: { appMaps, audit },
      signal: new AbortController().signal,
    });

    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
    expect(out.appMap.routes.length).toBeGreaterThanOrEqual(2);
    // Default runner does NOT persist (orchestrator owns create).
    expect(appMaps.createCalls).toBe(0);
  });

  it("persists + audits when persist:true (standalone use)", async () => {
    const appMaps = new MemAppMaps();
    const audit = new MemAudit();
    const runner = createLayer0Runner({ gateway: createFakeLlmGateway(), persist: true });
    await runner({
      scanId: "scan_standalone",
      clientId: CLIENT_ID,
      scan: { commitSha: COMMIT_SHA },
      job: {
        repo: VULN_DIR,
        branch: "main",
        mode: "full",
        scope: ScanScopeSchema.parse({ mode: "full" }),
      },
      config: getHardenedDefaults(),
      logger: createNullLogger(),
      store: { appMaps, audit },
      signal: new AbortController().signal,
    });
    expect(appMaps.createCalls).toBe(1);
    expect(audit.events.some((e) => e.action === "appmap.built")).toBe(true);
  });

  it("A9 — threads a semanticIndex hook through to buildAppMap", async () => {
    const appMaps = new MemAppMaps();
    const audit = new MemAudit();
    let called = false;
    const runner = createLayer0Runner({
      gateway: createFakeLlmGateway(),
      semanticIndex: async () => {
        called = true;
      },
    });
    await runner({
      scanId: SCAN_ID,
      clientId: CLIENT_ID,
      scan: { commitSha: COMMIT_SHA },
      job: {
        repo: VULN_DIR,
        branch: "main",
        mode: "full",
        scope: ScanScopeSchema.parse({ mode: "full" }),
      },
      config: getHardenedDefaults(),
      logger: createNullLogger(),
      store: { appMaps, audit },
      signal: new AbortController().signal,
    });
    expect(called).toBe(true);
  });
});
