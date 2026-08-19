#!/usr/bin/env node
/**
 * Seed the OWASP-Top-10-mapped red-team scenario starter catalogue
 * (`../src/redteam-catalogue.ts`) into a client's scenario library, via the
 * REAL `RedTeamScenarioRepositoryImpl` (Prisma + AES-256-GCM field
 * encryption at rest, same as every other write path — this script adds no
 * side channel).
 *
 * ⛔ SAFETY (mirrors `POST /scenarios` in apps/api, §11):
 *   - Every seeded scenario is created with `enabled: false`. An approver
 *     must explicitly review + enable a scenario before it can ever run.
 *   - `--target-allowlist-ref` is REQUIRED and is never defaulted — this
 *     script refuses to invent or fall back to a placeholder target, so a
 *     seeded scenario can never accidentally bind to a real, live target.
 *   - Idempotent: re-running skips any scenario whose name already exists
 *     for the given client (no duplicate rows on repeat runs).
 *   - This script performs NO network probing itself — it only writes
 *     scenario definitions to the database, exactly like authoring one by
 *     hand through the API.
 *
 * USAGE
 *   DATABASE_URL=postgres://... \
 *   FIELD_ENCRYPTION_KEY=<base64 32-byte key, see @montr/state-store crypto> \
 *     node packages/state-store/scripts/seed-redteam-scenarios.mjs \
 *       --client-id clnt_123 \
 *       --created-by usr_operator_1 \
 *       --target-allowlist-ref https://staging.example-client.com \
 *       [--dry-run]
 *
 * Requires the package to be built first (`pnpm --filter @montr/state-store build`)
 * — this script imports the compiled `../dist/index.js`, matching how every
 * other consumer of this package (apps/api, apps/worker) uses it.
 */
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = path.resolve(SCRIPT_DIR, "..");

function parseArgs(argv) {
  const out = { dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--client-id") out.clientId = argv[++i];
    else if (arg === "--created-by") out.createdBy = argv[++i];
    else if (arg === "--target-allowlist-ref") out.targetAllowlistRef = argv[++i];
    else if (arg === "--dry-run") out.dryRun = true;
    else if (arg === "--help" || arg === "-h") out.help = true;
    else throw new Error(`Unrecognized argument: ${arg}`);
  }
  return out;
}

function printHelp() {
  console.log(`Seed the OWASP-Top-10 red-team scenario catalogue for one client.

Required:
  --client-id <id>                  Client to seed scenarios for
  --created-by <userId>              Attributed author (an operator/approver user id)
  --target-allowlist-ref <url>       This client's own allowlisted DAST staging target
                                      (NEVER defaulted — you must supply a real one)

Optional:
  --dry-run                          Print what would be created, write nothing
  --help                             Show this message

Env (required unless --dry-run):
  DATABASE_URL            Postgres connection string
  FIELD_ENCRYPTION_KEY    AES-256-GCM field-encryption key (scenario steps are encrypted at rest)
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }
  const missing = ["clientId", "createdBy", "targetAllowlistRef"].filter((k) => !args[k]);
  if (missing.length > 0) {
    printHelp();
    throw new Error(`Missing required argument(s): ${missing.join(", ")}`);
  }

  const mod = await import(path.join(PACKAGE_ROOT, "dist", "index.js"));
  const { REDTEAM_SCENARIO_CATALOGUE, owaspCoverage, ALL_OWASP_TOP_10_2021_IDS } = mod;

  console.log(
    `Catalogue: ${REDTEAM_SCENARIO_CATALOGUE.length} scenario template(s), covering OWASP ${
      owaspCoverage().size
    }/${ALL_OWASP_TOP_10_2021_IDS.length} Top-10 (2021) categories.`,
  );

  if (args.dryRun) {
    for (const t of REDTEAM_SCENARIO_CATALOGUE) {
      console.log(`  [dry-run] would create: (${t.owasp}) ${t.name}`);
    }
    console.log("Dry run — nothing written. Re-run without --dry-run to seed the database.");
    return;
  }

  const databaseUrl = process.env.DATABASE_URL;
  const fieldEncryptionKey = process.env.FIELD_ENCRYPTION_KEY;
  if (!databaseUrl) throw new Error("DATABASE_URL is required (or pass --dry-run)");
  if (!fieldEncryptionKey) {
    throw new Error(
      "FIELD_ENCRYPTION_KEY is required — red-team scenario steps are encrypted at rest (or pass --dry-run)",
    );
  }

  const { createStateStore, seedRedTeamCatalogue } = mod;
  const store = createStateStore({ databaseUrl, fieldEncryptionKey });
  try {
    const { created, skipped } = await seedRedTeamCatalogue(store.redTeamScenarios, {
      clientId: args.clientId,
      createdBy: args.createdBy,
      targetAllowlistRef: args.targetAllowlistRef,
    });
    for (const s of created) console.log(`  created: (${s.category}) ${s.name} [${s.id}]`);
    for (const t of skipped) console.log(`  skipped (already exists): ${t.name}`);
    console.log(
      `Done. ${created.length} scenario(s) created, ${skipped.length} skipped. All created disabled (enabled=false) — review and enable via the API before any run.`,
    );
  } finally {
    await store.disconnect();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
