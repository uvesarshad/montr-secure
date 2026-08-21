/**
 * A20 — TypeScript auth-boundary detection upgraded from identifier-text regex
 * to real AST control-flow analysis, at two levels (see
 * `packages/appmap/src/languages/typescript/routes.ts`'s module doc comment):
 *
 *   1. HOC-wrap verification: `export const GET = withAuth(handler)` and the
 *      factory form `export const GET = requireRole("admin")(handler)` are
 *      verified as an actual AST call shape, not a substring match against the
 *      whole file.
 *   2. Next.js `middleware.ts` global auth: a root `middleware.ts` referencing
 *      a known guard, with an exported `config.matcher`, propagates
 *      `authenticated` to every route its matcher covers — the Next.js analog
 *      of Express/Fastify's `app.use(authMiddleware)` global middleware.
 *
 * Fixture: `packages/fixtures/sample-repos/nextjs-hoc-auth` (new, self-contained
 * — added for this suite, same convention as the existing
 * `express-sample`/`fastify-sample`/`onehop-nextjs` fixtures).
 */
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { collectFiles, createProject, scanRoutes } from "@montr/appmap";
import {
  getPythonParser,
  parseModule,
  type ParsedModule,
} from "../packages/appmap/src/languages/python/parser";
import { scanPythonRoutes } from "../packages/appmap/src/languages/python/routes";
import {
  extractFile,
  applySpringSecurityAuth,
} from "../packages/appmap/src/languages/java/extract";
import { parseJava } from "../packages/appmap/src/languages/java/parser";

const DIR = fileURLToPath(
  new URL("../packages/fixtures/sample-repos/nextjs-hoc-auth", import.meta.url),
);

async function scan() {
  const inv = await collectFiles(DIR);
  const project = createProject(DIR, inv.sourceFiles);
  return scanRoutes(project, DIR);
}

describe("appmap (TS) — HOC-wrap auth detection (A20)", () => {
  it("verifies `export const GET = withAuth(handler)` as a real call, not text presence", async () => {
    const { routes } = await scan();
    const admin = routes.find((r) => r.path === "/api/admin")!;
    expect(admin.authState).toBe("authenticated");
    expect(admin.authGate).toBe("withAuth");
  });

  it('verifies the factory HOC form `checkPermission("admin")(handler)` via its inner callee', async () => {
    const { routes } = await scan();
    const factory = routes.find((r) => r.path === "/api/factory")!;
    expect(factory.authState).toBe("authenticated");
    expect(factory.authGate).toBe("checkPermission");
  });

  it("leaves a plain, unwrapped export at unknown (no false positive)", async () => {
    const { routes } = await scan();
    const plain = routes.find((r) => r.path === "/api/plain")!;
    expect(plain.authState).toBe("unknown");
  });
});

describe("appmap (TS) — Next.js middleware.ts global auth (A20)", () => {
  it("propagates authenticated to a route matched by config.matcher", async () => {
    const { routes } = await scan();
    const dashboard = routes.find((r) => r.path === "/dashboard/settings")!;
    expect(dashboard.authState).toBe("authenticated");
    expect(dashboard.authGate).toMatch(/middleware\.ts/);
  });

  it("does NOT propagate to a route the matcher does not cover", async () => {
    const { routes } = await scan();
    const pub = routes.find((r) => r.path === "/public")!;
    expect(pub.authState).toBe("unknown");
  });
});

// ---------------------------------------------------------------------------
// Python — Django global `LoginRequiredMiddleware` (A20)
// ---------------------------------------------------------------------------
async function pyMods(entries: Array<[string, string]>): Promise<ParsedModule[]> {
  const parser = await getPythonParser();
  return entries.map(([rel, source]) => {
    const root = parseModule(parser, source);
    if (!root) throw new Error(`parse failed for ${rel}`);
    return { rel, source, root };
  });
}

describe("appmap (Python) — Django global LoginRequiredMiddleware (A20)", () => {
  const settingsWith = (extra: string): string =>
    [
      "MIDDLEWARE = [",
      '    "django.contrib.sessions.middleware.SessionMiddleware",',
      extra,
      "]",
    ].join("\n");
  const urls = [
    "from django.urls import path",
    "from . import views",
    "",
    "urlpatterns = [",
    '    path("orders/<int:id>/", views.order_detail),',
    "]",
  ].join("\n");

  it("propagates authenticated to every URLConf route when the global middleware is present", async () => {
    const mods = await pyMods([
      [
        "myapp/settings.py",
        settingsWith('    "django.contrib.auth.middleware.LoginRequiredMiddleware",'),
      ],
      ["myapp/urls.py", urls],
    ]);
    const { routes } = scanPythonRoutes(mods);
    const order = routes.find((r) => r.path === "/orders/{id}/")!;
    expect(order.authState).toBe("authenticated");
    expect(order.authGate).toMatch(/LoginRequiredMiddleware/);
  });

  it("leaves routes at unknown when the global middleware is absent (no false positive)", async () => {
    const mods = await pyMods([
      ["myapp/settings.py", settingsWith("")],
      ["myapp/urls.py", urls],
    ]);
    const { routes } = scanPythonRoutes(mods);
    const order = routes.find((r) => r.path === "/orders/{id}/")!;
    expect(order.authState).toBe("unknown");
  });

  it("does not fire on an unrelated mention of the string outside the MIDDLEWARE list", async () => {
    const mods = await pyMods([
      [
        "myapp/settings.py",
        [
          settingsWith(""),
          "",
          "# NOTE: we deliberately do NOT use LoginRequiredMiddleware here.",
        ].join("\n"),
      ],
      ["myapp/urls.py", urls],
    ]);
    const { routes } = scanPythonRoutes(mods);
    const order = routes.find((r) => r.path === "/orders/{id}/")!;
    expect(order.authState).toBe("unknown");
  });
});

// ---------------------------------------------------------------------------
// Java — Spring Security declarative `authorizeHttpRequests` filter chain (A20)
// ---------------------------------------------------------------------------
const SECURITY_CONFIG = [
  "class SecurityConfig {",
  "  @Bean",
  "  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {",
  "    http.authorizeHttpRequests(auth -> auth",
  '        .requestMatchers("/admin/**").hasRole("ADMIN")',
  '        .requestMatchers("/public/**").permitAll()',
  "        .anyRequest().authenticated()",
  "    );",
  "    return http.build();",
  "  }",
  "}",
].join("\n");

const ADMIN_CONTROLLER = [
  "@RestController",
  '@RequestMapping("/admin")',
  "class AdminController {",
  '  @GetMapping("/list")',
  "  public String list() {",
  '    return "ok";',
  "  }",
  "}",
].join("\n");

const PUBLIC_CONTROLLER = [
  "@RestController",
  '@RequestMapping("/public")',
  "class PublicController {",
  '  @GetMapping("/info")',
  "  public String info() {",
  '    return "ok";',
  "  }",
  "}",
].join("\n");

const OTHER_CONTROLLER = [
  "@RestController",
  "class OtherController {",
  '  @GetMapping("/other")',
  "  public String other() {",
  '    return "ok";',
  "  }",
  "}",
].join("\n");

async function javaExtractions(
  entries: Array<[string, string]>,
): Promise<{
  files: { root: import("../packages/appmap/src/languages/java/parser").TSNode }[];
  routes: ReturnType<typeof extractFile>["routes"];
}> {
  const files: { root: import("../packages/appmap/src/languages/java/parser").TSNode }[] = [];
  const routes: ReturnType<typeof extractFile>["routes"] = [];
  for (const [rel, source] of entries) {
    const root = await parseJava(source);
    if (!root) throw new Error(`parse failed for ${rel}`);
    files.push({ root });
    routes.push(...extractFile(root, rel).routes);
  }
  return { files, routes };
}

describe("appmap (Java) — Spring Security declarative filter chain (A20)", () => {
  it("resolves role-gated, public, and default-authenticated verdicts by Ant pattern", async () => {
    const { files, routes } = await javaExtractions([
      ["SecurityConfig.java", SECURITY_CONFIG],
      ["AdminController.java", ADMIN_CONTROLLER],
      ["PublicController.java", PUBLIC_CONTROLLER],
      ["OtherController.java", OTHER_CONTROLLER],
    ]);
    applySpringSecurityAuth(files, routes);

    const admin = routes.find((r) => r.path === "/admin/list")!;
    expect(admin.authState).toBe("role_gated");
    expect(admin.authGate).toMatch(/hasRole/);

    const pub = routes.find((r) => r.path === "/public/info")!;
    expect(pub.authState).toBe("public");
    expect(pub.authGate).toMatch(/permitAll/);

    // Falls through to `anyRequest().authenticated()`.
    const other = routes.find((r) => r.path === "/other")!;
    expect(other.authState).toBe("authenticated");
  });

  it("never overrides a route with an existing per-method @PreAuthorize/@Secured signal", async () => {
    const secured = [
      "@RestController",
      "class SecuredController {",
      "  @PreAuthorize(\"hasRole('ADMIN')\")",
      '  @GetMapping("/public/secured")',
      "  public String secured() {",
      '    return "ok";',
      "  }",
      "}",
    ].join("\n");
    const { files, routes } = await javaExtractions([
      ["SecurityConfig.java", SECURITY_CONFIG],
      ["SecuredController.java", secured],
    ]);
    const before = routes.find((r) => r.path === "/public/secured")!.authGate;
    applySpringSecurityAuth(files, routes);
    const after = routes.find((r) => r.path === "/public/secured")!;
    // Filter-chain would say `permitAll` (path matches /public/**) — but the
    // per-method @PreAuthorize signal (already role_gated) must win.
    expect(after.authState).toBe("role_gated");
    expect(after.authGate).toBe(before);
  });

  it("is a no-op when no authorizeHttpRequests chain exists anywhere (fail-safe)", async () => {
    const { files, routes } = await javaExtractions([["OtherController.java", OTHER_CONTROLLER]]);
    applySpringSecurityAuth(files, routes);
    expect(routes.find((r) => r.path === "/other")!.authState).toBe("unknown");
  });
});
