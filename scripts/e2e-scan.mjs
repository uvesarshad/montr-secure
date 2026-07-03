#!/usr/bin/env node
/**
 * ⛔ THE E2E SCAN runner (build-plan §9.2, PRD §19 Definition of Done).
 *
 * Runs a full, offline, end-to-end security scan of the fixtures'
 * intentionally-vulnerable Next.js/Prisma repo — map → discovery → correlation →
 * static confirmation → fix → report — driven through the orchestrator FSM + the
 * apps/worker in-process driver with the FAKE LLM adapter and an in-memory store.
 * No Postgres, no Redis, no network.
 *
 * This is a thin wrapper over the committed E2E test (`apps/worker/src/e2e-scan.test.ts`)
 * so `pnpm e2e` runs the SAME asserted pipeline the CI DoD gate runs, and prints
 * the money-shot report (headline = confirmed findings, proof, fixes, cost, and
 * which discovery mode ran: real semgrep/gitleaks when installed, else the
 * seeded fixtures candidate pile so L2→L5 still run on real data).
 *
 * Exit code is the test runner's: 0 = DoD assertions passed, non-zero = failed.
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const TEST = "apps/worker/src/e2e-scan.test.ts";
// Resolve the workspace-local vitest (POSIX bin; the CI/dev hosts are darwin/linux).
const vitest = fileURLToPath(new URL("../node_modules/.bin/vitest", import.meta.url));

const result = spawnSync(vitest, ["run", TEST], {
  cwd: root,
  stdio: "inherit",
  env: { ...process.env, E2E_PRINT: "1" },
});

if (result.error) {
  console.error("e2e-scan: failed to launch vitest:", result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
