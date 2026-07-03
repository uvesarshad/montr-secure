/**
 * A tiny in-memory Prisma stand-in for @montr/state-store unit tests — enough of
 * the delegate surface (create/createMany/findFirst/findMany/updateMany/upsert/
 * deleteMany/$transaction) that the repositories exercise real code paths with
 * NO live Postgres. Supports equality + { not, in, gte, gt, lt, lte } operators,
 * single-key orderBy, take, and select. This is a TEST helper, not production.
 */
import { randomUUID } from "node:crypto";
import { Prisma } from "@prisma/client";

type Row = Record<string, unknown>;

function toComparable(x: unknown): number | string | boolean | null {
  if (x instanceof Date) return x.getTime();
  if (x === null || x === undefined) return null;
  if (typeof x === "number" || typeof x === "string" || typeof x === "boolean") return x;
  return String(x);
}

function eq(a: unknown, b: unknown): boolean {
  return toComparable(a) === toComparable(b);
}

function matchesOperator(cell: unknown, op: string, operand: unknown): boolean {
  const c = toComparable(cell);
  const o = toComparable(operand);
  switch (op) {
    case "not":
      return !eq(cell, operand);
    case "in":
      return Array.isArray(operand) && operand.some((v) => eq(cell, v));
    case "gte":
      return c !== null && o !== null && c >= o;
    case "gt":
      return c !== null && o !== null && c > o;
    case "lte":
      return c !== null && o !== null && c <= o;
    case "lt":
      return c !== null && o !== null && c < o;
    default:
      return false;
  }
}

function isOperatorObject(v: unknown): v is Record<string, unknown> {
  return (
    !!v &&
    typeof v === "object" &&
    !(v instanceof Date) &&
    !Array.isArray(v) &&
    Object.keys(v).some((k) => ["not", "in", "gte", "gt", "lte", "lt"].includes(k))
  );
}

function matches(row: Row, where: Row | undefined): boolean {
  if (!where) return true;
  for (const [key, cond] of Object.entries(where)) {
    if (isOperatorObject(cond)) {
      for (const [op, operand] of Object.entries(cond)) {
        if (!matchesOperator(row[key], op, operand)) return false;
      }
    } else if (!eq(row[key], cond)) {
      return false;
    }
  }
  return true;
}

function applyOrderBy(rows: Row[], orderBy: Row | undefined): Row[] {
  if (!orderBy) return rows;
  const [key, dir] = Object.entries(orderBy)[0] ?? [];
  if (!key) return rows;
  const sign = dir === "desc" ? -1 : 1;
  return [...rows].sort((a, b) => {
    const av = toComparable(a[key]);
    const bv = toComparable(b[key]);
    if (av === bv) return 0;
    if (av === null) return -1 * sign;
    if (bv === null) return 1 * sign;
    return (av < bv ? -1 : 1) * sign;
  });
}

function project(row: Row, select: Row | undefined): Row {
  if (!select) return { ...row };
  const out: Row = {};
  for (const [k, v] of Object.entries(select)) if (v) out[k] = row[k];
  return out;
}

/** Replace Prisma DbNull/JsonNull sentinels with plain null, clone the rest. */
function normalize(data: Row): Row {
  const out: Row = {};
  for (const [k, v] of Object.entries(data)) {
    out[k] = v === Prisma.DbNull || v === Prisma.JsonNull ? null : v;
  }
  return out;
}

class Table {
  rows: Row[] = [];

  create({ data }: { data: Row }): Promise<Row> {
    const row = this.stamp(normalize(data), true);
    this.rows.push(row);
    return Promise.resolve({ ...row });
  }

  createMany({ data }: { data: Row[] }): Promise<{ count: number }> {
    for (const d of data) this.rows.push(this.stamp(normalize(d), true));
    return Promise.resolve({ count: data.length });
  }

  findFirst({
    where,
    orderBy,
    select,
  }: {
    where?: Row;
    orderBy?: Row;
    select?: Row;
  } = {}): Promise<Row | null> {
    const found = applyOrderBy(
      this.rows.filter((r) => matches(r, where)),
      orderBy,
    )[0];
    return Promise.resolve(found ? project(found, select) : null);
  }

  findUnique({ where, select }: { where?: Row; select?: Row } = {}): Promise<Row | null> {
    return this.findFirst({ where, select });
  }

  findMany({
    where,
    orderBy,
    take,
    select,
  }: {
    where?: Row;
    orderBy?: Row;
    take?: number;
    select?: Row;
  } = {}): Promise<Row[]> {
    let rows = applyOrderBy(
      this.rows.filter((r) => matches(r, where)),
      orderBy,
    );
    if (typeof take === "number") rows = rows.slice(0, take);
    return Promise.resolve(rows.map((r) => project(r, select)));
  }

  updateMany({ where, data }: { where?: Row; data: Row }): Promise<{ count: number }> {
    const patch = normalize(data);
    let count = 0;
    for (const row of this.rows) {
      if (matches(row, where)) {
        Object.assign(row, patch, { updatedAt: new Date() });
        count++;
      }
    }
    return Promise.resolve({ count });
  }

  async upsert({ where, create, update }: { where?: Row; create: Row; update: Row }): Promise<Row> {
    const existing = this.rows.find((r) => matches(r, where));
    if (existing) {
      Object.assign(existing, normalize(update), { updatedAt: new Date() });
      return { ...existing };
    }
    return this.create({ data: create });
  }

  deleteMany({ where }: { where?: Row } = {}): Promise<{ count: number }> {
    const before = this.rows.length;
    this.rows = this.rows.filter((r) => !matches(r, where));
    return Promise.resolve({ count: before - this.rows.length });
  }

  count({ where }: { where?: Row } = {}): Promise<number> {
    return Promise.resolve(this.rows.filter((r) => matches(r, where)).length);
  }

  private stamp(row: Row, isCreate: boolean): Row {
    const out: Row = { ...row };
    if (isCreate && (out["id"] === undefined || out["id"] === null)) out["id"] = randomUUID();
    if (isCreate && out["createdAt"] === undefined) out["createdAt"] = new Date();
    if (out["updatedAt"] === undefined) out["updatedAt"] = new Date();
    return out;
  }
}

const MODEL_NAMES = [
  "client",
  "user",
  "llmCredential",
  "appMap",
  "route",
  "taintSource",
  "taintSink",
  "scan",
  "scanState",
  "candidateFinding",
  "probableFinding",
  "confirmedFinding",
  "fix",
  "pullRequest",
  "report",
  "promptVersion",
  "dastTarget",
  "auditEvent",
  // Phase-4 (Wave 5) — scale & intelligence.
  "customRule",
  "redTeamScenario",
  "scanSchedule",
  "postureSnapshot",
] as const;

export type InMemoryPrisma = Record<(typeof MODEL_NAMES)[number], Table> & {
  $transaction<R>(fn: (tx: InMemoryPrisma) => Promise<R>): Promise<R>;
  $disconnect(): Promise<void>;
  __reset(): void;
};

/** Build a fresh in-memory Prisma client. */
export function createInMemoryPrisma(): InMemoryPrisma {
  const tables = {} as Record<(typeof MODEL_NAMES)[number], Table>;
  for (const name of MODEL_NAMES) tables[name] = new Table();

  const client = {
    ...tables,
    $transaction<R>(
      fn: ((tx: InMemoryPrisma) => Promise<R>) | Promise<R>[],
    ): Promise<R> | Promise<R[]> {
      if (Array.isArray(fn)) return Promise.all(fn);
      return fn(client);
    },
    $disconnect(): Promise<void> {
      return Promise.resolve();
    },
    __reset(): void {
      for (const name of MODEL_NAMES) tables[name].rows = [];
    },
  } as unknown as InMemoryPrisma;

  return client;
}
