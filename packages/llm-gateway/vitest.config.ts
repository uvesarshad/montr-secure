import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// Package-local config so `pnpm --filter @montr/llm-gateway test` actually
// discovers this package's co-located tests (see packages/cost-meter's
// vitest.config.ts for why the root config alone isn't enough when run from
// this package's directory). Test against package SOURCE, not dist.
export default defineConfig({
  resolve: {
    alias: {
      "@montr/contracts": src("../contracts/src/index.ts"),
      "@montr/config": src("../config/src/index.ts"),
      "@montr/cost-meter": src("../cost-meter/src/index.ts"),
      "@montr/security": src("../security/src/index.ts"),
      "@montr/telemetry": src("../telemetry/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
  },
});
