import { describe, it, expect } from "vitest";
import {
  KillSwitchSignalSchema,
  ResumeTokenSchema,
  PartialFailureSchema,
  LayerJobDataSchema,
  BaseJobDataSchema,
  ProgressEventSchema,
  PipelineEventSchema,
  RETRY_POLICIES,
  buildIdempotencyKey,
  QUEUE_NAMES,
  KILL_SWITCH_CHANNEL,
  resolveQueueName,
  sanitizeClientIdForQueueName,
} from "./queue.js";

/**
 * Queue & event contracts (§3.3): the ⛔ kill-switch signal, the resume-token
 * checkpoint (a failed Layer-3 must not re-run Layer 0-2), and the per-layer
 * job-data discriminated union. These gate real pipeline-control behavior, so
 * malformed signals/tokens must be rejected rather than silently accepted.
 */

const NOW = "2026-08-19T00:00:00.000Z";

describe("KillSwitchSignalSchema (⛔ halts all active work, esp. DAST)", () => {
  it("accepts a scan-scoped signal", () => {
    const sig = {
      scope: "scan",
      scanId: "scan_1",
      reason: "operator abort",
      requestedBy: "user_1",
      requestedByRole: "approver",
      at: NOW,
    };
    expect(KillSwitchSignalSchema.parse(sig)).toEqual(sig);
  });

  it("accepts a global signal without a scanId", () => {
    const sig = { scope: "global", reason: "incident", requestedBy: "user_1", at: NOW };
    expect(KillSwitchSignalSchema.parse(sig)).toMatchObject({ scope: "global" });
  });

  it("rejects an invalid scope value", () => {
    expect(() =>
      KillSwitchSignalSchema.parse({
        scope: "layer",
        reason: "x",
        requestedBy: "user_1",
        at: NOW,
      }),
    ).toThrow();
  });

  it("rejects a missing required 'reason'", () => {
    expect(() =>
      KillSwitchSignalSchema.parse({ scope: "global", requestedBy: "user_1", at: NOW }),
    ).toThrow();
  });

  it("rejects a missing required 'requestedBy' (kill switch must be attributable)", () => {
    expect(() => KillSwitchSignalSchema.parse({ scope: "global", reason: "x", at: NOW })).toThrow();
  });

  it("rejects an invalid requestedByRole", () => {
    expect(() =>
      KillSwitchSignalSchema.parse({
        scope: "global",
        reason: "x",
        requestedBy: "user_1",
        requestedByRole: "root",
        at: NOW,
      }),
    ).toThrow();
  });
});

describe("ResumeTokenSchema (pipeline resume checkpoint)", () => {
  it("accepts a token with no completed layers yet", () => {
    const parsed = ResumeTokenSchema.parse({ scanId: "scan_1", updatedAt: NOW });
    expect(parsed.completedLayers).toEqual([]);
  });

  it("accepts a token with completed layers and a checkpoint ref", () => {
    const token = {
      scanId: "scan_1",
      completedLayers: ["layer0", "layer1"],
      lastCompletedLayer: "layer1",
      checkpointRef: "state_42",
      updatedAt: NOW,
    };
    expect(ResumeTokenSchema.parse(token)).toEqual(token);
  });

  it("rejects an invalid layer id in completedLayers", () => {
    expect(() =>
      ResumeTokenSchema.parse({
        scanId: "scan_1",
        completedLayers: ["layer9"],
        updatedAt: NOW,
      }),
    ).toThrow();
  });

  it("rejects a missing scanId", () => {
    expect(() => ResumeTokenSchema.parse({ updatedAt: NOW })).toThrow();
  });
});

describe("PartialFailureSchema", () => {
  it("accepts a resumable partial failure", () => {
    const failure = {
      scanId: "scan_1",
      failedLayer: "layer3",
      error: { code: "INTERNAL", message: "boom", retriable: true },
      resumable: true,
      at: NOW,
    };
    expect(PartialFailureSchema.parse(failure)).toEqual(failure);
  });

  it("rejects an invalid nested error envelope code", () => {
    expect(() =>
      PartialFailureSchema.parse({
        scanId: "scan_1",
        failedLayer: "layer3",
        error: { code: "NOT_A_REAL_CODE", message: "boom" },
        resumable: false,
        at: NOW,
      }),
    ).toThrow();
  });

  it("rejects a missing 'resumable' flag", () => {
    expect(() =>
      PartialFailureSchema.parse({
        scanId: "scan_1",
        failedLayer: "layer3",
        error: { code: "INTERNAL", message: "boom" },
        at: NOW,
      }),
    ).toThrow();
  });
});

describe("BaseJobDataSchema", () => {
  it("defaults attempt to 0", () => {
    const parsed = BaseJobDataSchema.parse({
      scanId: "scan_1",
      clientId: "client_1",
      layer: "layer1",
      idempotencyKey: "scan_1:layer1:0",
    });
    expect(parsed.attempt).toBe(0);
  });

  it("rejects an empty idempotencyKey", () => {
    expect(() =>
      BaseJobDataSchema.parse({
        scanId: "scan_1",
        clientId: "client_1",
        layer: "layer1",
        idempotencyKey: "",
      }),
    ).toThrow();
  });
});

describe("LayerJobDataSchema (discriminated union on `layer`)", () => {
  const shared = {
    scanId: "scan_1",
    clientId: "client_1",
    idempotencyKey: "scan_1:layer0:0",
  };

  it("accepts a well-formed Layer0 job", () => {
    const job = {
      ...shared,
      layer: "layer0",
      repo: "org/repo",
      branch: "main",
      mode: "full",
      scope: { mode: "full" },
    };
    const parsed = LayerJobDataSchema.parse(job);
    expect(parsed.layer).toBe("layer0");
  });

  it("Layer3 job defaults allowLive to false (DECIDE-1: live DAST off by default)", () => {
    const job = { ...shared, layer: "layer3" };
    const parsed = LayerJobDataSchema.parse(job) as { layer: "layer3"; allowLive: boolean };
    expect(parsed.allowLive).toBe(false);
  });

  it("Layer5 job defaults autoApply to false (never a silent direct commit)", () => {
    const job = { ...shared, layer: "layer5" };
    const parsed = LayerJobDataSchema.parse(job) as { layer: "layer5"; autoApply: boolean };
    expect(parsed.autoApply).toBe(false);
  });

  it("rejects a job whose extra fields don't match its declared `layer` discriminant", () => {
    // Layer0 requires repo/branch/mode/scope; tagging it as layer2 (no such fields) must fail.
    expect(() =>
      LayerJobDataSchema.parse({
        ...shared,
        layer: "layer0",
        // missing repo/branch/mode/scope
      }),
    ).toThrow();
  });

  it("rejects an unrecognized `layer` discriminant value", () => {
    expect(() => LayerJobDataSchema.parse({ ...shared, layer: "layer9" })).toThrow();
  });
});

describe("ProgressEventSchema / PipelineEventSchema", () => {
  it("ProgressEvent rejects a pct outside [0, 100]", () => {
    expect(() =>
      ProgressEventSchema.parse({ scanId: "s", layer: "layer1", phase: "x", pct: 101, at: NOW }),
    ).toThrow();
    expect(() =>
      ProgressEventSchema.parse({ scanId: "s", layer: "layer1", phase: "x", pct: -1, at: NOW }),
    ).toThrow();
  });

  it("PipelineEvent accepts a 'killed' event", () => {
    const evt = { type: "killed", scanId: "s", reason: "operator abort", at: NOW };
    expect(PipelineEventSchema.parse(evt)).toEqual(evt);
  });

  it("PipelineEvent accepts a 'budget_exceeded' event", () => {
    const evt = { type: "budget_exceeded", scanId: "s", spentUsd: 10, at: NOW };
    expect(PipelineEventSchema.parse(evt)).toMatchObject({ type: "budget_exceeded" });
  });

  it("PipelineEvent rejects an unrecognized event 'type'", () => {
    expect(() => PipelineEventSchema.parse({ type: "paused", scanId: "s", at: NOW })).toThrow();
  });

  it("PipelineEvent rejects a 'failed' event with a malformed nested error envelope", () => {
    expect(() =>
      PipelineEventSchema.parse({
        type: "failed",
        scanId: "s",
        error: { code: "BAD_CODE", message: "x" },
        at: NOW,
      }),
    ).toThrow();
  });
});

describe("buildIdempotencyKey (deterministic — no Date.now()/random)", () => {
  it("is deterministic across repeated calls with the same inputs", () => {
    const a = buildIdempotencyKey("scan_1", "layer2");
    const b = buildIdempotencyKey("scan_1", "layer2");
    expect(a).toBe(b);
    expect(a).toBe("scan_1:layer2:0");
  });

  it("incorporates an explicit discriminator", () => {
    expect(buildIdempotencyKey("scan_1", "layer2", "5")).toBe("scan_1:layer2:5");
  });

  it("produces distinct keys for distinct layers", () => {
    expect(buildIdempotencyKey("scan_1", "layer0")).not.toBe(
      buildIdempotencyKey("scan_1", "layer1"),
    );
  });
});

describe("RETRY_POLICIES (Layer 3 live DAST is deliberately conservative)", () => {
  it("defines a policy for every pipeline layer", () => {
    for (const layer of ["layer0", "layer1", "layer2", "layer3", "layer4", "layer5"] as const) {
      expect(RETRY_POLICIES[layer]).toBeDefined();
    }
  });

  it("gives layer3 fewer attempts and fixed (not exponential) backoff", () => {
    expect(RETRY_POLICIES.layer3.attempts).toBeLessThan(RETRY_POLICIES.layer1.attempts);
    expect(RETRY_POLICIES.layer3.backoff.type).toBe("fixed");
  });
});

describe("QUEUE_NAMES / KILL_SWITCH_CHANNEL constants", () => {
  it("defines one queue name per layer plus a control queue", () => {
    expect(Object.keys(QUEUE_NAMES)).toHaveLength(7);
    expect(QUEUE_NAMES.control).toBe("montr.control");
  });

  it("exposes the kill-switch pub/sub channel name", () => {
    expect(KILL_SWITCH_CHANNEL).toBe("montr.control.kill");
  });
});

describe("resolveQueueName (A27 — per-tenant queue isolation, opt-in)", () => {
  it("tenantIsolation=false returns the shared QUEUE_NAMES entry unchanged (regression safety)", () => {
    for (const layer of ["layer0", "layer1", "layer2", "layer3", "layer4", "layer5"] as const) {
      expect(resolveQueueName(layer, "client_1", false)).toBe(QUEUE_NAMES[layer]);
    }
  });

  it("tenantIsolation=false ignores clientId entirely", () => {
    expect(resolveQueueName("layer2", "client_a", false)).toBe(
      resolveQueueName("layer2", "client_b", false),
    );
  });

  it("tenantIsolation=true derives a distinct queue name per clientId", () => {
    expect(resolveQueueName("layer2", "client_a", true)).toBe("montr.layer2.client_a");
    expect(resolveQueueName("layer2", "client_b", true)).toBe("montr.layer2.client_b");
  });

  it("tenantIsolation=true never collides with the shared (off) queue name", () => {
    const shared = resolveQueueName("layer0", "client_1", false);
    const isolated = resolveQueueName("layer0", "client_1", true);
    expect(isolated).not.toBe(shared);
    expect(isolated.startsWith(shared)).toBe(true);
  });

  it("rejects a clientId with characters unsafe for a Redis/BullMQ queue name", () => {
    expect(() => resolveQueueName("layer0", "client with spaces", true)).toThrow(
      /unsafe to use in a BullMQ\/Redis queue name/,
    );
    expect(() => resolveQueueName("layer0", "client:1", true)).toThrow();
    expect(() => resolveQueueName("layer0", "", true)).toThrow();
  });

  it("accepts a clientId of letters, digits, dashes and underscores", () => {
    expect(sanitizeClientIdForQueueName("Client-9_ok")).toBe("Client-9_ok");
  });
});
