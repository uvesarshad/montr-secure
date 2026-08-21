import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const src = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// Package-local config so `pnpm --filter @montr/hardening test` actually
// discovers this package's co-located tests (see @montr/cost-meter's
// vitest.config.ts for why the root config alone isn't enough). Mirrors the
// repo root's config: test against package SOURCE, not dist.
export default defineConfig({
  resolve: {
    alias: {
      "@montr/contracts": src("../contracts/src/index.ts"),
      "@montr/discovery": src("../discovery/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
  },
});
