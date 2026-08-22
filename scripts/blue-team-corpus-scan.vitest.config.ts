import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/**
 * Vitest config for the blue-team detection-corpus REAL-MODE run driver (B12)
 * (`scripts/blue-team-corpus-scan.run.test.ts`, run via
 * `node scripts/blue-team-corpus-scan.mjs` / `pnpm blue-team:scan`). SEPARATE
 * config from the root `vitest.config.ts` — same reasoning as
 * `scripts/corpus-scan.vitest.config.ts`: this driver is never swept up by
 * the ordinary `pnpm test` / `vitest run` run; it only runs when explicitly
 * invoked.
 *
 * The `resolve.alias` block mirrors the root `vitest.config.ts` (tests run
 * against package SOURCE, not built dist). Keep the two in sync if a package
 * is added/removed.
 */
export default defineConfig({
  resolve: {
    alias: {
      "@montr/contracts": src("../packages/contracts/src/index.ts"),
      "@montr/config": src("../packages/config/src/index.ts"),
      "@montr/telemetry": src("../packages/telemetry/src/index.ts"),
      "@montr/security": src("../packages/security/src/index.ts"),
      "@montr/state-store": src("../packages/state-store/src/index.ts"),
      "@montr/appmap": src("../packages/appmap/src/index.ts"),
      "@montr/correlation": src("../packages/correlation/src/index.ts"),
      "@montr/confirm": src("../packages/confirm/src/index.ts"),
      "@montr/report": src("../packages/report/src/index.ts"),
      "@montr/llm-gateway": src("../packages/llm-gateway/src/index.ts"),
      "@montr/qa": src("../packages/qa/src/index.ts"),
      "@montr/fixtures": src("../packages/fixtures/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    include: [src("./blue-team-corpus-scan.run.test.ts")],
    exclude: ["**/node_modules/**", "**/dist/**"],
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
