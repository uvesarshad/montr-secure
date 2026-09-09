#!/usr/bin/env node
/**
 * Fixes up `_prisma_migrations` after the A8 zero-padding rename (see
 * docs/plan/26-09-09-audit-july-line-divergence.md A8 and
 * docs/plan/26-09-09-tasks-july-line-divergence.md).
 *
 * BACKGROUND: Prisma applies migrations in lexicographic directory order.
 * Single-digit directory names meant `10_detection_rule_log_signature` and
 * `11_llm_provider_expansion` sorted BEFORE `1_phase4_scale_intelligence`, so
 * a fresh database died applying migration 10 before a table three
 * migrations later actually created it. The fix zero-padded the ten
 * single-digit directories (`0_init` -> `00_init`, ... `9_blue_team_entities`
 * -> `09_blue_team_entities`); `10_` and `11_` were already two digits and are
 * unchanged.
 *
 * THE REMAINING RISK this script closes: Prisma records applied migrations
 * by directory NAME in `_prisma_migrations`. Any database that already
 * applied the OLD names sees the ten renamed migrations as brand new and
 * will try to re-run them on the next `prisma migrate deploy` — which fails
 * (objects already exist) or, worse, partially re-applies destructive DDL.
 * Each renamed migration needs `prisma migrate resolve --applied <new_name>`
 * exactly once, which records the new name as applied WITHOUT re-running its
 * SQL. A fresh database (nothing in `_prisma_migrations` yet) needs nothing —
 * it will apply all twelve migrations under their current (padded) names the
 * first time `prisma migrate deploy` runs.
 *
 * This script does not guess: it connects to the target database, reads what
 * `_prisma_migrations` actually contains, and classifies it into exactly one
 * of three cases before doing anything.
 *
 *   (a) FRESH       — no `_prisma_migrations` table, or it exists but is
 *                      empty. Nothing to do. `prisma migrate deploy` (the
 *                      compose `migrate` service) will apply all twelve
 *                      migrations under their current names on its own.
 *   (b) OLD NAMES    — one or more of the ten renamed migrations is recorded
 *                      under its OLD (unpadded) name and not yet under its
 *                      new (padded) name. These need resolving.
 *   (c) ALREADY OK   — every migration that has ever been applied is already
 *                      recorded under its current (padded) name. Nothing to
 *                      do (this is also the state right after this script's
 *                      `--apply` run completes).
 *
 * If `_prisma_migrations` contains anything this script does not recognize —
 * an unfinished/failed migration (`finished_at IS NULL`), a migration name
 * that isn't one of the twelve this repo ships (old or new spelling) — it
 * REFUSES and prints exactly what it found. It never guesses at a fix for a
 * database in an unexpected state.
 *
 * SAFE BY DEFAULT: dry run unless `--apply` is passed. Dry run only reads
 * `_prisma_migrations`; `--apply` additionally runs, once per migration that
 * needs it, in ascending order:
 *   pnpm --filter @montr/state-store exec prisma migrate resolve --applied <new_name>
 *
 * IDEMPOTENT: every migration is classified independently by what's already
 * in `_prisma_migrations`, so re-running (dry run or `--apply`) after a
 * partial or full previous run only acts on what still needs it, and running
 * it again after everything is resolved reports case (c) and does nothing.
 *
 * Usage:
 *   node scripts/resolve-migration-rename.mjs                       # dry run, deploy/docker/.env's DATABASE_URL
 *   node scripts/resolve-migration-rename.mjs --apply               # actually resolve
 *   node scripts/resolve-migration-rename.mjs --database-url=postgresql://...
 *   node scripts/resolve-migration-rename.mjs --env-file=/path/to/.env
 *   node scripts/resolve-migration-rename.mjs --help
 *
 * Requires `psql` on PATH (used read-only except for the `--apply` step,
 * which shells out to the `prisma` CLI, never to raw SQL, to make the
 * change).
 *
 * Exit codes:
 *   0 — ran successfully: fresh (a), already correct (c), or `--apply`
 *       completed everything it needed to.
 *   1 — refused: the database is in an unexpected state, or `--apply`
 *       failed partway (the printed report says exactly which migrations
 *       were resolved before the failure).
 *   2 — dry run only: found renamed migrations that need `--apply` (case b,
 *       no `--apply` flag given). Not an error — a signal for scripting.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const MIGRATIONS_DIR = join(ROOT, "packages", "state-store", "prisma", "migrations");
const DEFAULT_ENV_FILE = join(ROOT, "deploy", "docker", ".env");

const args = process.argv.slice(2);
const APPLY = args.includes("--apply");
const HELP = args.includes("--help") || args.includes("-h");

function argValue(flag) {
  const prefix = `${flag}=`;
  const hit = args.find((a) => a.startsWith(prefix));
  return hit ? hit.slice(prefix.length) : undefined;
}

const DATABASE_URL_FLAG = argValue("--database-url");
const ENV_FILE_FLAG = argValue("--env-file");

function printHelp() {
  console.log(
    [
      "Usage: node scripts/resolve-migration-rename.mjs [--apply] [--database-url=<url>] [--env-file=<path>]",
      "",
      "Dry run by default (prints what it would do). Pass --apply to actually run",
      "`prisma migrate resolve --applied <new_name>` for whichever of the ten",
      "renamed migrations (A8) still need it.",
      "",
      "DATABASE_URL resolution order: --database-url flag, then the DATABASE_URL",
      "environment variable, then the DATABASE_URL= line in --env-file (default:",
      "deploy/docker/.env).",
      "",
      "Exit codes: 0 = nothing to do / apply succeeded, 1 = refused or apply",
      "failed partway, 2 = dry run found pending renames (needs --apply).",
    ].join("\n"),
  );
}

if (HELP) {
  printHelp();
  process.exit(0);
}

function log(msg) {
  console.log(`[resolve-migration-rename] ${msg}`);
}
function warn(msg) {
  console.warn(`[resolve-migration-rename] WARNING: ${msg}`);
}
function fail(msg) {
  console.error(`[resolve-migration-rename] REFUSED: ${msg}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Step 1 — derive the old/new migration name mapping from the migrations
// directory actually on disk right now. Never hardcoded: only the ten dirs
// whose zero-padded numeric prefix differs from its unpadded form count as
// "renamed" (currently 00_-09_ vs 0_-9_); 10_/11_ come out unchanged because
// their prefix already had two digits.
// ---------------------------------------------------------------------------
function loadMigrations() {
  if (!existsSync(MIGRATIONS_DIR)) {
    fail(`migrations directory not found: ${MIGRATIONS_DIR}`);
  }
  const entries = readdirSync(MIGRATIONS_DIR)
    .filter((name) => statSync(join(MIGRATIONS_DIR, name)).isDirectory())
    .sort();

  const migrations = [];
  for (const newName of entries) {
    const match = /^(\d+)_(.+)$/.exec(newName);
    if (!match) {
      warn(`skipping migration directory that doesn't match <digits>_<name>: ${newName}`);
      continue;
    }
    const [, prefix, rest] = match;
    const numeric = Number.parseInt(prefix, 10);
    // Only collapse a two-digit, zero-padded prefix (00-09) back to its
    // original single-digit form. A prefix already >= 10 is unchanged.
    const oldPrefix =
      prefix.length === 2 && prefix.startsWith("0") && numeric < 10 ? String(numeric) : prefix;
    const oldName = `${oldPrefix}_${rest}`;
    migrations.push({ newName, oldName, renamed: oldName !== newName });
  }
  if (migrations.length === 0) {
    fail(`no migration directories found under ${MIGRATIONS_DIR}`);
  }
  return migrations;
}

// ---------------------------------------------------------------------------
// Step 2 — resolve DATABASE_URL.
// ---------------------------------------------------------------------------
function parseEnvFileForDatabaseUrl(path) {
  if (!existsSync(path)) return undefined;
  const text = readFileSync(path, "utf8");
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    if (key !== "DATABASE_URL") continue;
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    return value || undefined;
  }
  return undefined;
}

function resolveDatabaseUrl() {
  if (DATABASE_URL_FLAG) {
    log(`DATABASE_URL from --database-url flag`);
    return DATABASE_URL_FLAG;
  }
  if (process.env["DATABASE_URL"]) {
    log(`DATABASE_URL from environment`);
    return process.env["DATABASE_URL"];
  }
  const envFile = ENV_FILE_FLAG ?? DEFAULT_ENV_FILE;
  const fromFile = parseEnvFileForDatabaseUrl(envFile);
  if (fromFile) {
    log(`DATABASE_URL from ${envFile}`);
    return fromFile;
  }
  fail(
    `could not determine DATABASE_URL. Pass --database-url=<url>, set the DATABASE_URL ` +
      `environment variable, or point --env-file at a file containing a DATABASE_URL= line ` +
      `(looked at ${envFile}).`,
  );
}

function redact(databaseUrl) {
  try {
    const u = new URL(databaseUrl);
    if (u.password) u.password = "***";
    return u.toString();
  } catch {
    return "<unparseable connection string, not printed>";
  }
}

/**
 * Prisma connection strings commonly carry a `?schema=` query param (this
 * repo's own deploy/docker/.env.example does:
 * `DATABASE_URL=postgresql://...@postgres:5432/montr?schema=public`). Prisma
 * itself understands that param; libpq (and therefore `psql`) does not and
 * hard-errors with "invalid URI query parameter" if it's left in the URI.
 *
 * This derives a `psql`-safe URL (schema param stripped, everything else
 * untouched) plus the actual target schema (defaulting to Postgres's own
 * default, "public", if the param is absent) so every query below can
 * explicitly qualify `_prisma_migrations` with it instead of silently
 * assuming "public".
 */
function psqlConnectionInfo(databaseUrl) {
  let schema = "public";
  let psqlUrl = databaseUrl;
  try {
    const u = new URL(databaseUrl);
    if (u.searchParams.has("schema")) {
      schema = u.searchParams.get("schema") || "public";
      u.searchParams.delete("schema");
      psqlUrl = u.toString();
    }
  } catch {
    // Unparseable as a URL — hand it to psql verbatim and let psql's own
    // error message explain why, rather than guessing here.
  }
  const quotedSchema = `"${schema.replace(/"/g, '""')}"`;
  return { psqlUrl, schema, quotedSchema };
}

// ---------------------------------------------------------------------------
// Step 3 — psql helpers. Read-only for detection; `--apply` never runs raw
// SQL to make changes, only the `prisma` CLI (see runResolve below). Every
// helper below takes the already-stripped `psqlUrl` (see psqlConnectionInfo)
// and the pre-qualified `"<schema>"._prisma_migrations` table name — never
// the original DATABASE_URL, and never a bare unqualified table name.
// ---------------------------------------------------------------------------
function checkPsqlAvailable() {
  const result = spawnSync("psql", ["--version"], { encoding: "utf8" });
  if (result.error) {
    fail(
      `\`psql\` is not on PATH (${result.error.code ?? result.error.message}). Install the ` +
        `Postgres client (e.g. \`brew install libpq\` and add it to PATH, or ` +
        `\`apt-get install postgresql-client\`) to run this script.`,
    );
  }
}

/** Runs one read-only SQL statement, tab-separated / unaligned / tuples-only. Returns raw stdout. */
function psql(psqlUrl, sql) {
  const result = spawnSync(
    "psql",
    [psqlUrl, "-v", "ON_ERROR_STOP=1", "-tA", "-F", "\t", "-c", sql],
    { encoding: "utf8" },
  );
  if (result.error) {
    fail(`failed to invoke psql: ${result.error.message}`);
  }
  if (result.status !== 0) {
    fail(
      `psql exited ${result.status} running a read-only check against the target database.\n` +
        `stderr:\n${(result.stderr ?? "").trim()}`,
    );
  }
  return result.stdout;
}

function tableExistsAndHasRows(psqlUrl, quotedSchema) {
  const existsOut = psql(
    psqlUrl,
    `SELECT CASE WHEN to_regclass('${quotedSchema}._prisma_migrations') IS NULL THEN 'MISSING' ELSE 'PRESENT' END;`,
  ).trim();
  if (existsOut !== "PRESENT") return false;
  const countOut = psql(psqlUrl, `SELECT count(*) FROM ${quotedSchema}._prisma_migrations;`).trim();
  return Number.parseInt(countOut, 10) > 0;
}

function fetchMigrationRows(psqlUrl, quotedSchema) {
  const out = psql(
    psqlUrl,
    "SELECT migration_name, started_at, finished_at, rolled_back_at, applied_steps_count " +
      `FROM ${quotedSchema}._prisma_migrations ORDER BY started_at;`,
  );
  return out
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => {
      const [name, started_at, finished_at, rolled_back_at, applied_steps_count] = line.split("\t");
      return {
        name,
        started_at: started_at || null,
        finished_at: finished_at || null,
        rolled_back_at: rolled_back_at || null,
        applied_steps_count: applied_steps_count || null,
      };
    });
}

function fetchLogsFor(psqlUrl, quotedSchema, migrationName) {
  // Separate, narrow query — logs can contain embedded newlines/tabs, so it
  // is never mixed into the tab-separated table query above.
  const result = spawnSync(
    "psql",
    [
      psqlUrl,
      "-v",
      "ON_ERROR_STOP=1",
      "-x",
      "-c",
      `SELECT logs FROM ${quotedSchema}._prisma_migrations WHERE migration_name = '${migrationName.replace(/'/g, "''")}';`,
    ],
    { encoding: "utf8" },
  );
  if (result.status !== 0 || result.error) return "(could not fetch logs)";
  return result.stdout.trim();
}

// ---------------------------------------------------------------------------
// Step 4 — apply: shell out to the prisma CLI, never raw SQL.
// ---------------------------------------------------------------------------
function runResolve(databaseUrl, newName) {
  log(`applying: prisma migrate resolve --applied ${newName}`);
  const result = spawnSync(
    "pnpm",
    [
      "--filter",
      "@montr/state-store",
      "exec",
      "prisma",
      "migrate",
      "resolve",
      "--applied",
      newName,
    ],
    { cwd: ROOT, env: { ...process.env, DATABASE_URL: databaseUrl }, stdio: "inherit" },
  );
  if (result.error) {
    fail(`failed to invoke pnpm/prisma: ${result.error.message}`);
  }
  return result.status === 0;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
  const migrations = loadMigrations();
  const renamed = migrations.filter((m) => m.renamed);
  log(
    `${migrations.length} migration(s) on disk, ${renamed.length} renamed by the A8 zero-pad fix: ` +
      renamed.map((m) => `${m.oldName} -> ${m.newName}`).join(", "),
  );

  const databaseUrl = resolveDatabaseUrl();
  log(`target database: ${redact(databaseUrl)}`);
  const { psqlUrl, schema, quotedSchema } = psqlConnectionInfo(databaseUrl);
  if (psqlUrl !== databaseUrl) {
    log(
      `stripped Prisma's ?schema=${schema} query param for psql; querying ${quotedSchema}._prisma_migrations explicitly`,
    );
  }
  checkPsqlAvailable();

  const hasRows = tableExistsAndHasRows(psqlUrl, quotedSchema);
  if (!hasRows) {
    console.log(
      "\n=== CASE: FRESH ===\n" +
        "`_prisma_migrations` does not exist or is empty. Nothing to do — the next " +
        "`prisma migrate deploy` (the compose `migrate` service) will apply all " +
        `${migrations.length} migrations under their current (padded) names.\n`,
    );
    process.exit(0);
  }

  const rows = fetchMigrationRows(psqlUrl, quotedSchema);
  const rowsByName = new Map();
  for (const row of rows) {
    if (rowsByName.has(row.name)) {
      fail(
        `\`_prisma_migrations\` has more than one row named '${row.name}'. This script does not ` +
          `guess at duplicate history — investigate manually before re-running.`,
      );
    }
    rowsByName.set(row.name, row);
  }

  // Anomaly check 1: any row that never finished (in-flight or failed and
  // never resolved) — refuse rather than guess.
  const unfinished = rows.filter((r) => !r.finished_at);
  if (unfinished.length > 0) {
    console.error(
      `\n=== REFUSED: unfinished migration row(s) found ===\n` +
        `${unfinished.length} row(s) in \`_prisma_migrations\` have finished_at = NULL — this is ` +
        `either a migration still in progress or one that failed and was never resolved. This ` +
        `script only fixes the A8 rename issue and will not guess at a fix here.\n`,
    );
    for (const r of unfinished) {
      console.error(
        `  - ${r.name} (started_at=${r.started_at}, rolled_back_at=${r.rolled_back_at ?? "null"}, ` +
          `applied_steps_count=${r.applied_steps_count})`,
      );
      console.error(`    logs:\n${fetchLogsFor(psqlUrl, quotedSchema, r.name)}`);
    }
    console.error(
      "\nResolve this manually first (e.g. `prisma migrate resolve --rolled-back <name>` or " +
        "`--applied <name>` once you've confirmed which, per Prisma's own migrate-resolve docs), " +
        "then re-run this script.",
    );
    process.exit(1);
  }

  // Anomaly check 2: any row whose name isn't one of the names this repo's
  // twelve migrations could plausibly be recorded under (old or new form).
  const knownNames = new Set();
  for (const m of migrations) {
    knownNames.add(m.oldName);
    knownNames.add(m.newName);
  }
  const unknown = rows.filter((r) => !knownNames.has(r.name));
  if (unknown.length > 0) {
    console.error(
      `\n=== REFUSED: unrecognized migration name(s) found ===\n` +
        `${unknown.length} row(s) in \`_prisma_migrations\` don't match any migration this repo ` +
        `ships (old or new spelling). This script will not guess what they are or whether they're ` +
        `safe to ignore.\n`,
    );
    for (const r of unknown) console.error(`  - ${r.name}`);
    console.error("\nInvestigate manually before re-running.");
    process.exit(1);
  }

  // Classify each renamed migration independently (idempotent: only acts on
  // what's actually missing under the new name).
  const classified = renamed.map((m) => {
    const oldRow = rowsByName.get(m.oldName);
    const newRow = rowsByName.get(m.newName);
    let status;
    if (newRow)
      status = "resolved"; // already recorded under the new name — nothing to do
    else if (oldRow)
      status = "needs-resolve"; // old name applied, new name missing
    else status = "not-yet-applied"; // never applied under either name — out of scope, migrate deploy handles it
    return { ...m, status };
  });

  console.log("\nPer-migration status:");
  for (const m of classified) {
    console.log(`  [${m.status.padEnd(15)}] ${m.newName}  (old name: ${m.oldName})`);
  }
  // Informational: unchanged migrations (10_/11_), just for a complete report.
  for (const m of migrations.filter((m) => !m.renamed)) {
    const applied = rowsByName.has(m.newName) ? "applied" : "not-yet-applied";
    console.log(`  [${applied.padEnd(15)}] ${m.newName}  (unchanged name)`);
  }

  const needsResolve = classified.filter((m) => m.status === "needs-resolve");

  if (needsResolve.length === 0) {
    console.log(
      "\n=== CASE: ALREADY CORRECT ===\n" +
        "Every migration this database has ever applied is already recorded under its current " +
        "(padded) name. Nothing to do.\n",
    );
    process.exit(0);
  }

  console.log(
    `\n=== CASE: OLD NAMES FOUND — ${needsResolve.length} migration(s) need resolving ===`,
  );
  for (const m of needsResolve) {
    console.log(
      `  would run: pnpm --filter @montr/state-store exec prisma migrate resolve --applied ${m.newName}`,
    );
  }

  if (!APPLY) {
    console.log(
      "\nDry run (default) — no changes made. Re-run with --apply to actually resolve the " +
        `migration(s) above against ${redact(databaseUrl)}.\n`,
    );
    process.exit(2);
  }

  console.log(`\nApplying ${needsResolve.length} resolve(s) against ${redact(databaseUrl)}...`);
  const done = [];
  for (const m of needsResolve) {
    const ok = runResolve(databaseUrl, m.newName);
    if (!ok) {
      console.error(
        `\n=== FAILED applying ${m.newName} ===\n` +
          `Successfully resolved before this failure: ${done.length > 0 ? done.join(", ") : "(none)"}\n` +
          `Stopping here rather than continuing past a failure. Re-running this script is safe — ` +
          `already-resolved migrations will be skipped.`,
      );
      process.exit(1);
    }
    done.push(m.newName);
  }

  // Re-verify against the database rather than trusting the CLI's own exit code alone.
  const rowsAfter = fetchMigrationRows(psqlUrl, quotedSchema);
  const namesAfter = new Set(rowsAfter.map((r) => r.name));
  const stillMissing = needsResolve.filter((m) => !namesAfter.has(m.newName));
  if (stillMissing.length > 0) {
    console.error(
      `\n=== INCONSISTENT STATE ===\nprisma migrate resolve reported success for all ` +
        `${needsResolve.length} migration(s), but re-querying _prisma_migrations still does not ` +
        `show a row for: ${stillMissing.map((m) => m.newName).join(", ")}. Investigate manually.`,
    );
    process.exit(1);
  }

  console.log(
    `\n=== DONE — resolved ${needsResolve.length} migration(s): ${needsResolve.map((m) => m.newName).join(", ")} ===\n` +
      `Verified against ${redact(databaseUrl)}: all now recorded under their current (padded) name. ` +
      `Safe to run \`docker compose run --rm migrate\` (or however this environment runs ` +
      `\`prisma migrate deploy\`) next.\n`,
  );
  process.exit(0);
}

main();
