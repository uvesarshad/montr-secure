/**
 * Prisma client wrapper (§8.3). One place to construct and configure the
 * PostgreSQL client so repositories and tests share a single type. Repositories
 * accept an injected client (see {@link MontrPrismaClient}) so unit tests can
 * pass an in-memory fake with NO live database.
 */
import { PrismaClient, Prisma } from "@prisma/client";

/** The concrete Prisma client type the repositories are written against. */
export type MontrPrismaClient = PrismaClient;

/** Re-export the Prisma namespace for input/JSON typing in the repos. */
export { Prisma };

export interface CreatePrismaClientOptions {
  databaseUrl: string;
  /** Emit Prisma query/error logs (default: errors + warnings only). */
  logQueries?: boolean;
}

/**
 * Construct a configured PrismaClient. Connection is lazy — Prisma connects on
 * first query, so merely creating this does not touch the database.
 */
export function createPrismaClient(opts: CreatePrismaClientOptions): MontrPrismaClient {
  return new PrismaClient({
    datasources: { db: { url: opts.databaseUrl } },
    log: opts.logQueries ? ["query", "warn", "error"] : ["warn", "error"],
  });
}

/** Cast an arbitrary JSON-serialisable value to a Prisma JSON input value. */
export function toJson(value: unknown): Prisma.InputJsonValue {
  return value as Prisma.InputJsonValue;
}

/** Cast a stored Prisma JSON value back to a known contract type. */
export function fromJson<T>(value: unknown): T {
  return value as T;
}

/** Optional JSON field: `undefined`/`null` map to Prisma's DbNull sentinel. */
export function toJsonOrNull(value: unknown): Prisma.InputJsonValue | typeof Prisma.DbNull {
  return value === undefined || value === null ? Prisma.DbNull : (value as Prisma.InputJsonValue);
}
