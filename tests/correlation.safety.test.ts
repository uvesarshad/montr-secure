import { describe, it, expect } from "vitest";
import {
  mockAppMap,
  mockCandidateFindings,
  createFakeLlmGateway,
  CLIENT_ID,
  SCAN_ID,
  FIXED_NOW,
} from "@montr/fixtures";
import { MontrMetrics } from "@montr/telemetry";
import type { AppMap, AuditAction, AuditEventInput } from "@montr/contracts";
import { correlate } from "@montr/correlation";
import { makeFakeAudit } from "./correlation.helpers.js";

const base = { clientId: CLIENT_ID, scanId: SCAN_ID, now: FIXED_NOW } as const;
const CODE_MARKERS = ["$queryRawUnsafe", "__html", "sk_live", "PAYMENTS_API_KEY"];
const countAction = (events: AuditEventInput[], action: AuditAction) =>
  events.filter((e) => e.action === action).length;

describe("@montr/correlation — audit trail & metrics (safety)", () => {
  it("audit-logs every promotion, demotion, and LLM call — metadata only", async () => {
    const { client, events } = makeFakeAudit();
    const out = await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      gateway: createFakeLlmGateway(),
      audit: client,
    });

    expect(countAction(events, "finding.promoted_probable")).toBe(out.probable.length);
    expect(countAction(events, "finding.demoted")).toBe(1); // the vulnerable dependency
    expect(countAction(events, "llm.call")).toBe(out.probable.length);

    // ⛔ No code/secret body may appear anywhere in the audit metadata.
    const serialized = JSON.stringify(events);
    for (const marker of CODE_MARKERS) expect(serialized).not.toContain(marker);

    // Actor is the correlation agent.
    const promoted = events.find((e) => e.action === "finding.promoted_probable")!;
    expect(promoted.actor).toEqual({ type: "agent", id: "layer2-correlation" });
    expect(promoted.metadata).toMatchObject({
      category: expect.any(String),
      rank: expect.any(Number),
    });
  });

  it("LLM-call audit records ONLY metadata (tokens/model), never the prompt", async () => {
    const { client, events } = makeFakeAudit();
    await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      gateway: createFakeLlmGateway(),
      audit: client,
    });
    const llmCall = events.find((e) => e.action === "llm.call")!;
    const meta = llmCall.metadata ?? {};
    expect(meta).toMatchObject({
      purpose: "correlation",
      model: expect.any(String),
      inputTokens: expect.any(Number),
      outputTokens: expect.any(Number),
      latencyMs: expect.any(Number),
    });
    for (const forbidden of ["prompt", "messages", "content", "system", "evidenceSnippet"]) {
      expect(meta).not.toHaveProperty(forbidden);
    }
  });

  it("records per-layer metrics (findings in/out, demotion, LLM calls)", async () => {
    const metrics = new MontrMetrics();
    await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      gateway: createFakeLlmGateway(),
      metrics,
    });
    const snap = metrics.snapshot();
    expect(snap.findingsIn["layer2"]).toBe(mockCandidateFindings.length);
    expect(snap.findingsOut["layer2"]).toBe(4);
    expect(snap.demoted).toBe(1);
    expect(snap.llmCalls).toBe(4);
  });

  it("deterministic-first: makes ZERO LLM calls when no gateway is provided", async () => {
    const metrics = new MontrMetrics();
    const { client, events } = makeFakeAudit();
    await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      metrics,
      audit: client,
    });
    expect(metrics.snapshot().llmCalls).toBe(0);
    expect(countAction(events, "llm.call")).toBe(0);
    // Promotions + demotions are still audited without any LLM involvement.
    expect(countAction(events, "finding.promoted_probable")).toBeGreaterThan(0);
    expect(countAction(events, "finding.demoted")).toBe(1);
  });

  it("⛔ refuses to run (and never calls the LLM) before an App Map exists", async () => {
    const metrics = new MontrMetrics();
    await expect(
      correlate({
        ...base,
        appMap: undefined as unknown as AppMap,
        candidates: mockCandidateFindings,
        gateway: createFakeLlmGateway(),
        metrics,
      }),
    ).rejects.toThrow(/App Map/i);
    expect(metrics.snapshot().llmCalls).toBe(0);
  });

  it("honors a custom audit actor id", async () => {
    const { client, events } = makeFakeAudit();
    await correlate({
      ...base,
      appMap: mockAppMap,
      candidates: mockCandidateFindings,
      audit: client,
      actorId: "orchestrator-worker-7",
    });
    expect(events.every((e) => e.actor.id === "orchestrator-worker-7")).toBe(true);
    expect(events.every((e) => e.actor.type === "agent")).toBe(true);
  });
});
