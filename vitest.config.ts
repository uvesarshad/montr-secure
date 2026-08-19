import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// Tests run against package SOURCE (not built dist) so `pnpm test` works before
// `pnpm build` in CI (install -> lint -> typecheck -> test -> build).
export default defineConfig({
  resolve: {
    alias: {
      "@montr/contracts": src("./packages/contracts/src/index.ts"),
      "@montr/config": src("./packages/config/src/index.ts"),
      "@montr/telemetry": src("./packages/telemetry/src/index.ts"),
      "@montr/cost-meter": src("./packages/cost-meter/src/index.ts"),
      "@montr/llm-gateway": src("./packages/llm-gateway/src/index.ts"),
      "@montr/state-store": src("./packages/state-store/src/index.ts"),
      "@montr/orchestrator": src("./packages/orchestrator/src/index.ts"),
      "@montr/appmap": src("./packages/appmap/src/index.ts"),
      "@montr/discovery": src("./packages/discovery/src/index.ts"),
      "@montr/correlation": src("./packages/correlation/src/index.ts"),
      "@montr/confirm": src("./packages/confirm/src/index.ts"),
      "@montr/fix": src("./packages/fix/src/index.ts"),
      "@montr/report": src("./packages/report/src/index.ts"),
      "@montr/qa": src("./packages/qa/src/index.ts"),
      "@montr/security": src("./packages/security/src/index.ts"),
      "@montr/fixtures": src("./packages/fixtures/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts", "packages/**/src/**/*.test.ts", "apps/**/src/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**", "packages/fixtures/sample-repos/**"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      exclude: ["**/dist/**", "**/*.test.ts", "packages/fixtures/sample-repos/**"],
      // Floor set ~2pp below the measured baseline (2026-08-19, 632 tests):
      // statements 57.03% · branches 70.58% · functions 63.92% · lines 57.03%.
      // Catches real regressions without failing CI on already-committed work.
      // Vitest exits non-zero automatically when a threshold isn't met.
      thresholds: {
        statements: 55,
        branches: 68,
        functions: 61,
        lines: 55,
      },
    },
  },
});
