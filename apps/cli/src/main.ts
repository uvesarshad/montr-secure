#!/usr/bin/env node
/**
 * `montr` CLI process entrypoint (A15). Currently one subcommand: `scan`
 * (`montr scan .`) — see ./cli.ts for the implementation. Exits with the
 * code `run()` returns (see ./exit-codes.ts); never throws past this point.
 */
import { pathToFileURL } from "node:url";
import { run } from "./cli.js";

async function main(): Promise<void> {
  const code = await run(process.argv.slice(2));
  process.exit(code);
}

// Entrypoint guard: only run when invoked directly (never on import), same
// convention as @montr/qa's cli.ts and @montr/security's audit-verify-cli.ts.
const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  main().catch((err: unknown) => {
    console.error("montr fatal error:", err);
    process.exit(1);
  });
}
