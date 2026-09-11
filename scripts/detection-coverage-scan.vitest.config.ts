import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/**
 * Vitest config for the detection-coverage REAL-MODE scan driver (suggested
 * enhancement, docs/plan/26-09-12-tasks-red-blue-agentic-posture.md — mirrors
 * `scripts/corpus-scan.vitest.config.ts` / `scripts/blue-team-corpus-scan.vitest.config.ts`
 * exactly). SEPARATE config from the root `vitest.config.ts` (not merged into
 * it) so this driver — which shells out to real semgrep/gitleaks and drives
 * the full L0-L3 pipeline over every golden-corpus repo — is never swept up
 * by the ordinary `pnpm test` / `vitest run` run; it only runs when
 * explicitly invoked via `node scripts/detection-coverage-scan.mjs` /
 * `pnpm run detection-coverage:scan`.
 *
 * The `resolve.alias` block mirrors the root `vitest.config.ts` and the other
 * two corpus-scan configs (tests run against package SOURCE, not built dist).
 * Keep all three in sync if a package is added/removed.
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
    include: [src("./detection-coverage-scan.run.test.ts")],
    exclude: ["**/node_modules/**", "**/dist/**"],
    // Real semgrep/gitleaks subprocesses + a multi-repo L0-L3 pipeline run are
    // slow (registry ruleset fetch, several repos) — same budget as
    // corpus-scan.vitest.config.ts.
    testTimeout: 30 * 60_000,
    hookTimeout: 30 * 60_000,
  },
});
