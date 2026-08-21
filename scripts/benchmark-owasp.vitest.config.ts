import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

/**
 * Vitest config for the OWASP Benchmark REAL-MODE scan driver (E14, closes
 * A29 — `scripts/benchmark-owasp.run.test.ts`, run via
 * `node scripts/benchmark-owasp.mjs` / `pnpm benchmark:owasp`). A SEPARATE
 * config from both the root `vitest.config.ts` and
 * `scripts/corpus-scan.vitest.config.ts`, mirroring the latter's exact
 * rationale: this driver shells out to a real Semgrep and drives the full
 * L0-L3 pipeline over the vendored `corpus/owasp-benchmark/` subset, so it
 * must never be swept up by the ordinary `pnpm test` sweep — it only runs
 * when explicitly invoked.
 *
 * `resolve.alias` is identical to `corpus-scan.vitest.config.ts` (tests run
 * against package SOURCE, not built dist). Keep all three in sync if a
 * package is added/removed.
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
    include: [src("./benchmark-owasp.run.test.ts")],
    exclude: ["**/node_modules/**", "**/dist/**"],
    // One repo (24 vendored test files) is much smaller than the 16-repo
    // golden corpus, but a real Semgrep registry-pack fetch can still take a
    // while on a cold cache.
    testTimeout: 10 * 60_000,
    hookTimeout: 10 * 60_000,
  },
});
