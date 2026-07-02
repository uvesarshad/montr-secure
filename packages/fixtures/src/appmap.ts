import { AppMapSchema, type AppMap } from "@montr/contracts";
import {
  APPMAP_ID,
  CLEAN_APPMAP_ID,
  CLIENT_ID,
  COMMIT_SHA,
  FIXED_NOW,
  REPO_URL,
  BRANCH,
  ROUTE_SEARCH_ID,
  ROUTE_USERS_ID,
  SCAN_ID,
} from "./ids.js";

/** App Map of the intentionally-vulnerable sample repo. Validated on load. */
export const mockAppMap: AppMap = AppMapSchema.parse({
  id: APPMAP_ID,
  clientId: CLIENT_ID,
  scanId: SCAN_ID,
  repo: REPO_URL,
  branch: BRANCH,
  commitSha: COMMIT_SHA,
  createdAt: FIXED_NOW,
  languages: ["typescript", "javascript"],
  frameworks: ["nextjs", "react", "prisma"],
  entrypoints: [
    {
      kind: "http_route",
      name: "GET /api/users",
      location: { file: "app/api/users/route.ts", line: 5 },
    },
    { kind: "http_route", name: "GET /search", location: { file: "app/search/page.tsx", line: 3 } },
  ],
  routes: [
    {
      id: ROUTE_USERS_ID,
      path: "/api/users",
      method: "GET",
      authState: "public",
      isApiRoute: true,
      handler: { file: "app/api/users/route.ts", line: 5 },
    },
    {
      id: ROUTE_SEARCH_ID,
      path: "/search",
      method: "GET",
      authState: "public",
      isApiRoute: false,
      handler: { file: "app/search/page.tsx", line: 3 },
    },
  ],
  dataStores: [{ kind: "postgres", name: "app_db", accessedVia: "prisma" }],
  ormModels: [
    {
      name: "User",
      dataStore: "app_db",
      file: "prisma/schema.prisma",
      fields: [
        { name: "id", type: "Int", isId: true },
        { name: "email", type: "String" },
        { name: "name", type: "String" },
      ],
    },
  ],
  thirdPartyCalls: [],
  envSecretSurfaces: [
    { kind: "config_file", name: "PAYMENTS_API_KEY", location: { file: "lib/config.ts", line: 2 } },
  ],
  taintSources: [
    {
      kind: "query_param",
      location: { file: "app/api/users/route.ts", line: 6 },
      description: "req.nextUrl.searchParams.get('q')",
      routeId: ROUTE_USERS_ID,
    },
    {
      kind: "query_param",
      location: { file: "app/search/page.tsx", line: 4 },
      description: "searchParams.q",
      routeId: ROUTE_SEARCH_ID,
    },
  ],
  taintSinks: [
    {
      kind: "orm_raw_query",
      location: { file: "app/api/users/route.ts", line: 9 },
      description: "prisma.$queryRawUnsafe(`... ${q} ...`)",
    },
    {
      kind: "html_render",
      location: { file: "app/search/page.tsx", line: 8 },
      description: "dangerouslySetInnerHTML={{ __html: q }}",
    },
  ],
  stale: false,
  rebuildPolicy: "rebuild_on_stale_commit",
});

/** App Map of the clean sample repo (no reachable sink from tainted input). */
export const mockCleanAppMap: AppMap = AppMapSchema.parse({
  id: CLEAN_APPMAP_ID,
  clientId: CLIENT_ID,
  repo: "https://example.internal/montr/clean-nextjs",
  branch: BRANCH,
  commitSha: "0f1e2d3c4b5a60718293a4b5c6d7e8f900112233",
  createdAt: FIXED_NOW,
  languages: ["typescript"],
  frameworks: ["nextjs", "react", "prisma"],
  entrypoints: [
    {
      kind: "http_route",
      name: "GET /api/users",
      location: { file: "app/api/users/route.ts", line: 5 },
    },
  ],
  routes: [
    {
      path: "/api/users",
      method: "GET",
      authState: "authenticated",
      isApiRoute: true,
      authGate: "requireSession",
      handler: { file: "app/api/users/route.ts", line: 5 },
    },
  ],
  dataStores: [{ kind: "postgres", name: "app_db", accessedVia: "prisma" }],
  ormModels: [
    {
      name: "User",
      dataStore: "app_db",
      file: "prisma/schema.prisma",
      fields: [{ name: "id", type: "Int", isId: true }],
    },
  ],
  taintSources: [
    {
      kind: "query_param",
      location: { file: "app/api/users/route.ts", line: 6 },
      description: "validated + parameterized",
    },
  ],
  taintSinks: [
    {
      kind: "sql_query",
      location: { file: "app/api/users/route.ts", line: 9 },
      description: "prisma.user.findMany({ where: { email } }) — parameterized",
    },
  ],
  stale: false,
  rebuildPolicy: "rebuild_on_stale_commit",
});
