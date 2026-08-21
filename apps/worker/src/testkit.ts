/**
 * Test-only helpers for the worker package (offline, deterministic). Excluded
 * from the tsc build (see tsconfig `exclude`); resolved by vitest via the source
 * aliases. NOT part of the shipped surface.
 */
import { MontrConfigSchema, type MontrConfig } from "@montr/config";
import type { AuditEvent, AuditEventInput, CostActual, Fix, LayerId, Scan } from "@montr/contracts";
import type { LayerContext, LayerRunners } from "@montr/orchestrator";
import type { StateStore } from "@montr/state-store";
import type { Logger } from "@montr/telemetry";
import type { CostMeter } from "@montr/cost-meter";
import { CLIENT_ID } from "@montr/fixtures";

export const clone = <T>(v: T): T => (v === null || v === undefined ? v : structuredClone(v));

export const silentLogger: Logger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
  child() {
    return silentLogger;
  },
};

interface HasIdScan {
  id: string;
  clientId: string;
  scanId: string;
}

function findingRepo<T extends HasIdScan>() {
  const byClient = new Map<string, T[]>();
  const arr = (c: string): T[] => {
    let a = byClient.get(c);
    if (!a) {
      a = [];
      byClient.set(c, a);
    }
    return a;
  };
  return {
    create: (c: string, e: T) => {
      arr(c).push(clone(e));
      return Promise.resolve(clone(e));
    },
    get: (c: string, id: string) => Promise.resolve(clone(arr(c).find((x) => x.id === id) ?? null)),
    list: (c: string) => Promise.resolve(arr(c).map(clone)),
    bulkCreate: (c: string, es: T[]) => {
      for (const e of es) arr(c).push(clone(e));
      return Promise.resolve(es.map(clone));
    },
    listByScan: (c: string, sid: string) =>
      Promise.resolve(
        arr(c)
          .filter((x) => x.scanId === sid)
          .map(clone),
      ),
  };
}

export interface InMemoryStore {
  store: StateStore;
  audit: AuditEventInput[];
  /** Counts of persistence writes, to assert the persist division (no double-writes). */
  writes: Record<string, number>;
}

/** A minimal in-memory StateStore sufficient for the orchestrator + layer adapters. */
export function makeInMemoryStore(): InMemoryStore {
  const scans = new Map<string, Scan>();
  const appMaps = new Map<string, { id: string; repo?: string; commitSha?: string }>();
  const fixesByClient = new Map<string, Fix[]>();
  const resume = new Map<string, unknown>();
  const auditLog: AuditEventInput[] = [];
  const writes: Record<string, number> = {};
  const bump = (k: string): void => {
    writes[k] = (writes[k] ?? 0) + 1;
  };
  const fixArr = (c: string): Fix[] => {
    let a = fixesByClient.get(c);
    if (!a) {
      a = [];
      fixesByClient.set(c, a);
    }
    return a;
  };

  const candidates = findingRepo();
  const probable = findingRepo();
  const confirmed = findingRepo();
  const unconfirmed = findingRepo();

  const wrapBulk = (repo: ReturnType<typeof findingRepo>, name: string) => ({
    ...repo,
    bulkCreate: (c: string, es: HasIdScan[]) => {
      bump(name);
      return repo.bulkCreate(c, es);
    },
  });

  const store = {
    scans: {
      create: (c: string, s: Scan) => {
        scans.set(`${c}:${s.id}`, clone(s));
        return Promise.resolve(clone(s));
      },
      get: (c: string, id: string) => Promise.resolve(clone(scans.get(`${c}:${id}`) ?? null)),
      list: (c: string) =>
        Promise.resolve(
          [...scans.entries()].filter(([k]) => k.startsWith(`${c}:`)).map(([, v]) => clone(v)),
        ),
      update: (c: string, s: Scan) => {
        scans.set(`${c}:${s.id}`, clone(s));
        return Promise.resolve(clone(s));
      },
      listByStatus: (c: string, status: Scan["status"]) =>
        Promise.resolve(
          [...scans.entries()]
            .filter(([k, v]) => k.startsWith(`${c}:`) && v.status === status)
            .map(([, v]) => clone(v)),
        ),
    },
    appMaps: {
      create: (c: string, m: { id: string }) => {
        bump("appMaps.create");
        appMaps.set(`${c}:${m.id}`, clone(m));
        return Promise.resolve(clone(m));
      },
      get: (c: string, id: string) => Promise.resolve(clone(appMaps.get(`${c}:${id}`) ?? null)),
      list: () => Promise.resolve([]),
      latestForCommit: () => Promise.resolve(null),
      latestForRepo: () => Promise.resolve(null),
      markStale: () => Promise.resolve(),
      invalidateStaleForCommit: () => Promise.resolve(0),
    },
    candidates: wrapBulk(candidates, "candidates.bulkCreate"),
    probable: wrapBulk(probable, "probable.bulkCreate"),
    confirmed: wrapBulk(confirmed, "confirmed.bulkCreate"),
    unconfirmed: wrapBulk(unconfirmed, "unconfirmed.bulkCreate"),
    fixes: {
      create: (c: string, f: Fix) => {
        bump("fixes.create");
        fixArr(c).push(clone(f));
        return Promise.resolve(clone(f));
      },
      get: (c: string, id: string) =>
        Promise.resolve(clone(fixArr(c).find((x) => x.id === id) ?? null)),
      list: (c: string) => Promise.resolve(fixArr(c).map(clone)),
      update: (c: string, f: Fix) => {
        const a = fixArr(c);
        const i = a.findIndex((x) => x.id === f.id);
        if (i >= 0) a[i] = clone(f);
        return Promise.resolve(clone(f));
      },
      listByScan: (c: string, sid: string) =>
        Promise.resolve(
          fixArr(c)
            .filter((x) => x.scanId === sid)
            .map(clone),
        ),
    },
    resume: {
      save: (c: string, t: { scanId: string }) => {
        resume.set(`${c}:${t.scanId}`, clone(t));
        return Promise.resolve(clone(t));
      },
      get: (c: string, sid: string) => Promise.resolve(clone(resume.get(`${c}:${sid}`) ?? null)),
    },
    audit: {
      append: (input: AuditEventInput) => {
        auditLog.push(clone(input));
        const seq = auditLog.length;
        const event: AuditEvent = {
          id: `audit_${seq}`,
          sequence: seq,
          prevHash: "",
          hash: `h${seq}`,
          at: "2026-02-01T00:00:00.000Z",
          ...input,
          metadata: input.metadata ?? {},
        };
        return Promise.resolve(event);
      },
      list: () => Promise.resolve([]),
      verifyChain: () => Promise.resolve(true),
    },
    disconnect: () => Promise.resolve(),
  } as unknown as StateStore;

  return { store, audit: auditLog, writes };
}

function makeActual(scanId: string): CostActual {
  return {
    scanId,
    usage: { inputTokens: 100, outputTokens: 20, totalTokens: 120 },
    actualUsd: 0.01,
    wallClockSeconds: 1,
    byLayer: [],
    byModel: [],
    updatedAt: "2026-02-01T00:00:00.000Z",
  };
}

/** A deterministic cost meter that never trips the budget. */
export function makeMeter(scanId = "scan"): CostMeter {
  return {
    estimate: (() => {
      throw new Error("estimate() not used in tests");
    }) as unknown as CostMeter["estimate"],
    record: () => {},
    actual: () => makeActual(scanId),
    checkBudget: () => ({
      withinBudget: true,
      exceeded: false,
      warn: false,
      spentUsd: 0,
      spentTokens: 0,
    }),
  };
}

export function hardenedConfig(overrides: Record<string, unknown> = {}): MontrConfig {
  return MontrConfigSchema.parse({ clientId: CLIENT_ID, ...overrides });
}

/** Build a LayerContext for directly exercising a single runner adapter. */
export function makeLayerContext<L extends LayerId>(args: {
  scanId: string;
  clientId: string;
  scan: Scan;
  job: LayerContext<L>["job"];
  store: StateStore;
  config?: MontrConfig;
  priorOutputs?: LayerContext<L>["priorOutputs"];
  signal?: AbortSignal;
  costMeter?: CostMeter;
  logger?: Logger;
}): LayerContext<L> {
  const controller = new AbortController();
  return {
    scanId: args.scanId,
    clientId: args.clientId,
    scan: args.scan,
    job: args.job,
    config: args.config ?? hardenedConfig(),
    logger: args.logger ?? silentLogger,
    costMeter: args.costMeter ?? makeMeter(args.scanId),
    store: args.store,
    signal: args.signal ?? controller.signal,
    attempt: 0,
    priorOutputs: args.priorOutputs ?? {},
    emitProgress: () => {},
  } as LayerContext<L>;
}

/** Wrap a set of runners to count invocations and capture each layer's output. */
export function instrument(runners: LayerRunners): {
  runners: LayerRunners;
  calls: Record<LayerId, number>;
  outputs: Partial<Record<LayerId, unknown>>;
} {
  const calls = {
    layer0: 0,
    layer1: 0,
    layer2: 0,
    layer3: 0,
    layer4: 0,
    layer5: 0,
  } as Record<LayerId, number>;
  const outputs: Partial<Record<LayerId, unknown>> = {};
  const layers: LayerId[] = ["layer0", "layer1", "layer2", "layer3", "layer4", "layer5"];
  const wrapped = {} as Record<LayerId, unknown>;
  for (const layer of layers) {
    const original = runners[layer] as (ctx: unknown) => Promise<unknown>;
    wrapped[layer] = async (ctx: unknown) => {
      calls[layer] += 1;
      const out = await original(ctx);
      outputs[layer] = out;
      return out;
    };
  }
  return { runners: wrapped as unknown as LayerRunners, calls, outputs };
}
