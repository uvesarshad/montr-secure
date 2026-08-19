import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// Package-local config so `pnpm --filter @montr/cost-meter test` actually
// discovers this package's co-located tests: the root config's `include`
// globs are resolved relative to `root`, which vitest defaults to
// process.cwd() (this package's dir) rather than the repo root it was found
// in — so running from here with only the root config picks up NO tests.
// Mirrors the repo root's config: test against package SOURCE, not dist.
export default defineConfig({
  resolve: {
    alias: {
      "@montr/contracts": src("../contracts/src/index.ts"),
      "@montr/telemetry": src("../telemetry/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
  },
});
