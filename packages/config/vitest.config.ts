import { defineConfig } from "vitest/config";

// Package-local config so `pnpm --filter @montr/config test` actually
// discovers this package's co-located tests: the root config's `include`
// globs are resolved relative to `root`, which vitest defaults to
// process.cwd() (this package's dir) rather than the repo root it was found
// in — so running from here with only the root config picks up NO tests.
// Mirrors the repo root's config: test against package SOURCE, not dist.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**"],
  },
});
