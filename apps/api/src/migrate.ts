/**
 * `--migrate` CLI path (invoked by apps/main.ts and the docker-compose `migrate`
 * one-shot service). Runs `prisma migrate deploy` against the schema owned by
 * @montr/state-store (packages/state-store/prisma/schema.prisma) as a
 * subprocess — Prisma 5 has no public JS migration-runner API, only the CLI.
 *
 * The CLI binary is resolved via `require.resolve("prisma/build/index.js")`
 * (apps/api declares a direct `prisma` dependency for exactly this) and run
 * with `process.execPath` directly — no shell, so this also works in the
 * distroless runtime image (no /bin/sh there).
 */
import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Default schema location for a local monorepo checkout: this file compiles to
 * apps/api/dist/migrate.js, so three levels up is the repo root.
 * deploy/docker/Dockerfile.api sets `MONTR_PRISMA_SCHEMA=/app/prisma/schema.prisma`
 * (it COPYs the schema + migrations there) so the docker image never relies on
 * this relative fallback.
 */
function defaultSchemaPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "../../../packages/state-store/prisma/schema.prisma");
}

export interface RunMigrationsOptions {
  /** Overrides MONTR_PRISMA_SCHEMA / the repo-relative default. */
  schemaPath?: string;
  /** Overrides process.env.DATABASE_URL. */
  databaseUrl?: string;
}

/** Run `prisma migrate deploy`. Resolves on success; rejects with a clear error otherwise. */
export async function runMigrations(opts: RunMigrationsOptions = {}): Promise<void> {
  const databaseUrl = opts.databaseUrl ?? process.env["DATABASE_URL"];
  if (!databaseUrl) {
    throw new Error("--migrate requires DATABASE_URL to be set.");
  }

  const schemaPath = opts.schemaPath ?? process.env["MONTR_PRISMA_SCHEMA"] ?? defaultSchemaPath();
  if (!existsSync(schemaPath)) {
    throw new Error(
      `--migrate: prisma schema not found at ${schemaPath}. Set MONTR_PRISMA_SCHEMA to override.`,
    );
  }

  const require = createRequire(import.meta.url);
  let cliEntry: string;
  try {
    cliEntry = require.resolve("prisma/build/index.js");
  } catch (cause) {
    throw new Error(
      "--migrate: the `prisma` CLI package is not resolvable. It must be a dependency of @montr/api.",
      { cause },
    );
  }

  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(process.execPath, [cliEntry, "migrate", "deploy", "--schema", schemaPath], {
      env: { ...process.env, DATABASE_URL: databaseUrl },
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (code === 0) {
        resolvePromise();
      } else {
        reject(
          new Error(
            `prisma migrate deploy failed (exit code ${code ?? "null"}, signal ${signal ?? "none"})`,
          ),
        );
      }
    });
  });
}
