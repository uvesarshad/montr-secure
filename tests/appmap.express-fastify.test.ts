/**
 * A17/A18 — Express/Fastify route extraction (previously a documented gap:
 * both frameworks got detection from `package.json` but no route extractor,
 * so a plain Express or Fastify API yielded zero routes) + route→ORM-model
 * linking (A18). Fully OFFLINE, same convention as `appmap.build.test.ts`:
 * synthetic fixtures under `packages/fixtures/sample-repos/` for the
 * unit-level assertions, PLUS a real-repo integration check against this
 * monorepo's own `apps/api` — a large, real, working Fastify application —
 * proving the extractor isn't just passing on a toy synthetic case.
 */
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  buildAppMap,
  collectFiles,
  createProject,
  scanExpressRoutes,
  scanFastifyRoutes,
  scanRoutes,
  scanPrisma,
  linkRouteModels,
} from "@montr/appmap";
import type { BuildAppMapInput } from "@montr/appmap";
import { getHardenedDefaults } from "@montr/config";
import { createFakeLlmGateway, CLIENT_ID, SCAN_ID, FIXED_NOW, COMMIT_SHA } from "@montr/fixtures";
import { ScanScopeSchema, Layer0OutputSchema } from "@montr/contracts";

const EXPRESS_DIR = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/express-sample", import.meta.url),
);
const FASTIFY_DIR = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/fastify-sample", import.meta.url),
);
const ONEHOP_DIR = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/onehop-nextjs", import.meta.url),
);
const API_DIR = fileURLToPath(new URL("../apps/api", import.meta.url));

const fixedNow = (): Date => new Date(FIXED_NOW);

function baseInput(dir: string, overrides: Partial<BuildAppMapInput> = {}): BuildAppMapInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    repo: dir,
    branch: "main",
    mode: "full",
    scope: ScanScopeSchema.parse({ mode: "full" }),
    config: getHardenedDefaults(),
    commitSha: COMMIT_SHA,
    ...overrides,
  };
}

describe("appmap — Express route extraction (A17)", () => {
  it("scanExpressRoutes extracts path/method/framework-shaped routes directly", async () => {
    const inv = await collectFiles(EXPRESS_DIR);
    const project = createProject(EXPRESS_DIR, inv.sourceFiles);
    const result = scanExpressRoutes(project, EXPRESS_DIR);

    const byKey = new Map(result.routes.map((r) => [`${r.method} ${r.path}`, r]));

    // Same-file `app.use('/users', router)` mount resolution prefixes the
    // router's OWN registrations.
    const list = byKey.get("GET /users");
    expect(list).toBeDefined();
    expect(list?.isApiRoute).toBe(true);

    const create = byKey.get("POST /users/:id");
    expect(create).toBeDefined();
    // `requireAuth` is passed as Express middleware before the handler.
    expect(create?.authState).toBe("authenticated");
    expect(create?.authGate).toBe("requireAuth");

    // A route registered directly on `app` in a DIFFERENT file (public.ts)
    // still surfaces, unprefixed (never mounted).
    const health = byKey.get("GET /health");
    expect(health).toBeDefined();
    expect(health?.authState).toBe("unknown");

    expect(result.handlersByRouteId.size).toBe(result.routes.length);
  });

  it("buildAppMap detects express + emits the extracted routes end to end", async () => {
    const out = await buildAppMap(baseInput(EXPRESS_DIR), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
    });
    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
    expect(out.appMap.frameworks).toContain("express");
    const paths = out.appMap.routes.map((r) => `${r.method} ${r.path}`);
    expect(paths).toEqual(expect.arrayContaining(["GET /users", "POST /users/:id", "GET /health"]));
  });
});

describe("appmap — Fastify route extraction (A17)", () => {
  it("scanFastifyRoutes extracts both the verb-call and app.route({...}) shapes", async () => {
    const inv = await collectFiles(FASTIFY_DIR);
    const project = createProject(FASTIFY_DIR, inv.sourceFiles);
    const result = scanFastifyRoutes(project, FASTIFY_DIR);

    const byKey = new Map(result.routes.map((r) => [`${r.method} ${r.path}`, r]));

    const users = byKey.get("GET /users");
    expect(users).toBeDefined();
    expect(users?.isApiRoute).toBe(true);
    expect(users?.authState).toBe("authenticated");
    expect(users?.authGate).toBe("requireAuth");

    // `app.route({ method, url, handler })` object-config shape.
    const create = byKey.get("POST /users/:id");
    expect(create).toBeDefined();

    // 2-arg verb-call form (no `opts`).
    const health = byKey.get("GET /health");
    expect(health).toBeDefined();
    expect(health?.authState).toBe("unknown");

    expect(result.handlersByRouteId.size).toBe(result.routes.length);
  });

  it("buildAppMap detects fastify + emits the extracted routes end to end", async () => {
    const out = await buildAppMap(baseInput(FASTIFY_DIR), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
    });
    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
    expect(out.appMap.frameworks).toContain("fastify");
    const paths = out.appMap.routes.map((r) => `${r.method} ${r.path}`);
    expect(paths).toEqual(expect.arrayContaining(["GET /users", "POST /users/:id", "GET /health"]));
  });

  it("real-repo proof: extracts apps/api's own registered routes (large, real Fastify app)", async () => {
    const inv = await collectFiles(API_DIR);
    expect(inv.dependencies).toHaveProperty("fastify");
    const project = createProject(API_DIR, inv.sourceFiles);
    const result = scanFastifyRoutes(project, API_DIR);

    // apps/api registers ~47 routes across routes/*.ts (scans, auth, findings,
    // rules, dast, gate, scenarios, schedules, audit, analytics, webhooks...).
    expect(result.routes.length).toBeGreaterThan(30);

    const byKey = new Map(result.routes.map((r) => [`${r.method} ${r.path}`, r]));
    expect(byKey.get("POST /scans")).toBeDefined();
    expect(byKey.get("GET /scans/:id")).toBeDefined();
    expect(byKey.get("GET /scans/:id/status")).toBeDefined();
    expect(byKey.get("POST /scans/:id/cancel")).toBeDefined();
    expect(byKey.get("GET /health")).toBeDefined();
    expect(byKey.get("POST /auth/login")).toBeDefined();

    // Every extracted route resolved a real handler function node (A18 needs this).
    expect(result.handlersByRouteId.size).toBe(result.routes.length);
  });
});

describe("appmap — route→ORM-model linking (A18)", () => {
  it("resolves a DIRECT prisma.<model>.<op> call inside the route handler", async () => {
    const CLEAN_DIR = fileURLToPath(
      new URL("../packages/fixtures/sample-repos/clean-nextjs", import.meta.url),
    );
    const out = await buildAppMap(baseInput(CLEAN_DIR), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
    });
    const users = out.appMap.routes.find((r) => r.path === "/api/users");
    expect(users?.referencedModels).toEqual([{ modelName: "User", operations: ["read"] }]);
  });

  it("resolves ONE HOP through a locally-declared (relative-import) helper function", async () => {
    const inv = await collectFiles(ONEHOP_DIR);
    const project = createProject(ONEHOP_DIR, inv.sourceFiles);
    const { routes, handlersByRouteId } = scanRoutes(project, ONEHOP_DIR);
    const { ormModels } = await scanPrisma(ONEHOP_DIR, inv.prismaSchemas);

    const widgets = routes.find((r) => r.path === "/api/widgets");
    expect(widgets).toBeDefined();
    // Direct scan of the handler alone would find nothing — the prisma call
    // lives inside `getWidgets()` in a different file, one relative import hop away.
    expect(widgets?.referencedModels).toBeUndefined();

    const linked = linkRouteModels(project, ONEHOP_DIR, routes, ormModels, handlersByRouteId);
    const linkedWidgets = linked.find((r) => r.path === "/api/widgets");
    expect(linkedWidgets?.referencedModels).toEqual([
      { modelName: "Widget", operations: ["read"] },
    ]);
  });

  it("leaves routes with no resolvable model reference untouched (no empty array noise)", async () => {
    const VULN_DIR = fileURLToPath(
      new URL("../packages/fixtures/sample-repos/vulnerable-nextjs", import.meta.url),
    );
    const out = await buildAppMap(baseInput(VULN_DIR), {
      gateway: createFakeLlmGateway(),
      now: fixedNow,
    });
    // vulnerable-nextjs's /api/users uses `$queryRawUnsafe` — a client-scoped
    // raw query, not a `prisma.<model>.<op>` call, so it stays unresolved.
    const users = out.appMap.routes.find((r) => r.path === "/api/users");
    expect(users?.referencedModels).toBeUndefined();
  });
});
