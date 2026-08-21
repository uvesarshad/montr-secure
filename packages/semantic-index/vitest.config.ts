import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// Package-local config so `pnpm --filter @montr/semantic-index test` actually
// discovers this package's co-located tests (see packages/cost-meter's
// identical rationale). Aliases cover this package's own workspace deps plus
// their transitive workspace deps, since tests run against SOURCE, not dist.
export default defineConfig({
  resolve: {
    alias: {
      "@montr/contracts": src("../contracts/src/index.ts"),
      "@montr/config": src("../config/src/index.ts"),
      "@montr/cost-meter": src("../cost-meter/src/index.ts"),
      "@montr/security": src("../security/src/index.ts"),
      "@montr/telemetry": src("../telemetry/src/index.ts"),
      "@montr/llm-gateway": src("../llm-gateway/src/index.ts"),
      "@montr/state-store": src("../state-store/src/index.ts"),
      "@montr/appmap": src("../appmap/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
    testTimeout: 20_000,
  },
});
