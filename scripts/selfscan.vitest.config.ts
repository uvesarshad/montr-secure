import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/**
 * Vitest config for the self-scan / dogfood driver (`scripts/selfscan.run.test.ts`,
 * run via `node scripts/selfscan.mjs` / `pnpm selfscan`). This is a SEPARATE config
 * from the root `vitest.config.ts` (not merged into it) — mirrors
 * `scripts/corpus-scan.vitest.config.ts` — so the driver, which shells out to real
 * semgrep/gitleaks and drives the full L0-L3 pipeline over THIS repo's own source,
 * is never swept up by the ordinary `pnpm test` / `vitest run` run; it only runs
 * when explicitly invoked.
 *
 * The `resolve.alias` block mirrors the root `vitest.config.ts` (tests run against
 * package SOURCE, not built dist, same as everywhere else in this repo). Keep the
 * two (and `corpus-scan.vitest.config.ts`) in sync if a package is added/removed.
 */
export default defineConfig({
  resolve: {
    alias: {
      "@montr/contracts": src("../packages/contracts/src/index.ts"),
      "@montr/config": src("../packages/config/src/index.ts"),
      "@montr/telemetry": src("../packages/telemetry/src/index.ts"),
      "@montr/cost-meter": src("../packages/cost-meter/src/index.ts"),
      "@montr/llm-gateway": src("../packages/llm-gateway/src/index.ts"),
      "@montr/state-store": src("../packages/state-store/src/index.ts"),
      "@montr/orchestrator": src("../packages/orchestrator/src/index.ts"),
      "@montr/appmap": src("../packages/appmap/src/index.ts"),
      "@montr/discovery": src("../packages/discovery/src/index.ts"),
      "@montr/correlation": src("../packages/correlation/src/index.ts"),
      "@montr/confirm": src("../packages/confirm/src/index.ts"),
      "@montr/fix": src("../packages/fix/src/index.ts"),
      "@montr/report": src("../packages/report/src/index.ts"),
      "@montr/qa": src("../packages/qa/src/index.ts"),
      "@montr/security": src("../packages/security/src/index.ts"),
      "@montr/fixtures": src("../packages/fixtures/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    include: [src("./selfscan.run.test.ts")],
    exclude: ["**/node_modules/**", "**/dist/**"],
    // Real semgrep/gitleaks subprocesses + a full L0-L3 pipeline run over this
    // repo's own source are slow (registry ruleset fetch, thousands of files) —
    // well above vitest defaults.
    testTimeout: 15 * 60_000,
    hookTimeout: 15 * 60_000,
  },
});
