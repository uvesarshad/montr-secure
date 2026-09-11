/**
 * A5 — the bounded agentic fix loop (`proposeFixWithAgent` in generate.ts).
 * Colocated under packages/fix/src (not tests/fix.*.test.ts) so `pnpm vitest
 * run packages/fix` selects it directly.
 *
 * Design under test (see generate.ts's module + `proposeFixWithAgent` doc
 * comments for the full rationale): the loop drives its retry/feedback cycle
 * against a CHEAP, in-process oracle (`cheapPatchOracle` — a pure `diff`
 * patch-apply plus the strategy's own vulnerability regex predicate), never
 * against `patch.ts`'s real-`vitest` `validatePatch` or the ephemeral-Docker
 * `validatePatchWithContainerReplay`. Those still run — unchanged, exactly
 * once per final candidate — in `generateOne`, after this loop has already
 * returned. `generate.agent-loop.expensive-verification.test.ts` proves that
 * separation directly with a spy; this file proves the loop's own observable
 * behavior (retries, bounding, opt-in default, sandboxed tool use) using only
 * a queued fake gateway — no mocking of this package's own modules.
 */
import { describe, it, expect } from "vitest";
import {
  ConfirmedFindingSchema,
  type ConfirmedFinding,
  type LLMGateway,
  type LLMRequest,
  type LLMResponse,
  type LLMStreamEvent,
  type LLMToolCall,
  type ModelDescriptor,
  type StopReason,
} from "@montr/contracts";
import { MontrMetrics, type AuditLogClient } from "@montr/telemetry";
import { generateFixes, type GenerateFixesInput } from "./generate.js";
import { createMapSourceReader } from "./source.js";

const CLIENT_ID = "client_agent_loop_test";
const SCAN_ID = "scan_agent_loop_test";
const FIXED_NOW = "2026-01-01T00:00:00.000Z";

/** A minimal, schema-valid `xss` ConfirmedFinding at `file` — built directly
 * (no @montr/fixtures dependency: this package doesn't otherwise depend on
 * that workspace package, and colocating tests under packages/fix/src keeps
 * this file inside the tsc project graph @montr/fix itself declares). */
function makeXssFinding(file: string): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    id: "conf_agent_loop_0001",
    scanId: SCAN_ID,
    clientId: CLIENT_ID,
    title: "Reflected XSS via dangerouslySetInnerHTML",
    category: "xss",
    severity: "high",
    exposure: "public",
    location: { file, line: 2 },
    impact: "Attacker-controlled markup is rendered unescaped.",
    proofType: "static",
    proofArtifact: {
      kind: "static",
      argument: "tainted q reaches dangerouslySetInnerHTML",
      dataFlow: [],
      sanitizersBypassed: [],
    },
    createdAt: FIXED_NOW,
  });
}

// ---------------------------------------------------------------------------
// A small, deterministic fixture: one line carries the xss strategy's
// vulnerable pattern (`dangerouslySetInnerHTML`); everything else is filler.
// ---------------------------------------------------------------------------
const ORIGINAL_LINES = [
  "export default function Comp({ q }) {",
  "  return <div dangerouslySetInnerHTML={{ __html: q }} />;",
  "}",
  "",
];
const ORIGINAL = ORIGINAL_LINES.join("\n");
const VULN_LINE_NO = 2;

/** The strategy's own transform, applied by hand — an edit a model COULD legitimately propose. */
const FIXED_LINE = ORIGINAL_LINES[VULN_LINE_NO - 1]!.replace(
  /<(\w+)\s+dangerouslySetInnerHTML=\{\{\s*__html:\s*([\s\S]*?)\s*\}\}\s*\/>/,
  (_m, tag: string, expr: string) => `<${tag}>{${expr.trim()}}</${tag}>`,
);
/** A structurally-valid edit that changes something but LEAVES the vulnerable pattern in place. */
const STILL_VULNERABLE_LINE = `${ORIGINAL_LINES[VULN_LINE_NO - 1]!} // TODO`;

function goodEditsJson(): string {
  return JSON.stringify({
    edits: [{ startLine: VULN_LINE_NO, endLine: VULN_LINE_NO, replacement: FIXED_LINE }],
    rationale: "removed dangerouslySetInnerHTML",
  });
}

function stillVulnerableEditsJson(): string {
  return JSON.stringify({
    edits: [{ startLine: VULN_LINE_NO, endLine: VULN_LINE_NO, replacement: STILL_VULNERABLE_LINE }],
    rationale: "attempted fix",
  });
}

function overlappingInvalidEditsJson(): string {
  // Structurally invalid per parseLlmEdits: two overlapping ranges.
  return JSON.stringify({
    edits: [
      { startLine: 1, endLine: 2, replacement: "x" },
      { startLine: 2, endLine: 3, replacement: "y" },
    ],
    rationale: "bad edits",
  });
}

let responseSeq = 0;
function nextId(prefix: string): string {
  responseSeq++;
  return `${prefix}_${responseSeq}`;
}

function textResponse(content: string, stopReason: StopReason = "end_turn"): LLMResponse {
  return {
    id: nextId("resp"),
    provider: "anthropic",
    model: "claude-sonnet-5",
    content,
    stopReason,
    usage: { inputTokens: 10, outputTokens: 10, totalTokens: 20 },
    latencyMs: 1,
  };
}

function toolUseResponse(toolCalls: LLMToolCall[]): LLMResponse {
  return {
    id: nextId("resp_tool"),
    provider: "anthropic",
    model: "claude-sonnet-5",
    content: "",
    stopReason: "tool_use",
    usage: { inputTokens: 10, outputTokens: 10, totalTokens: 20 },
    latencyMs: 1,
    toolCalls,
  };
}

const FAKE_MODEL_DESCRIPTOR: ModelDescriptor = {
  provider: "anthropic",
  modelId: "claude-sonnet-5",
  tier: "default",
  contextWindow: 1_000_000,
  maxOutputTokens: 128_000,
  supportsTools: true,
  supportsStreaming: true,
  belowFloor: false,
};

/** A gateway that returns queued responses in order, recording every request it receives. */
class QueueGateway implements LLMGateway {
  readonly requests: LLMRequest[] = [];
  private readonly queue: LLMResponse[];

  constructor(responses: LLMResponse[]) {
    this.queue = [...responses];
  }

  complete(request: LLMRequest): Promise<LLMResponse> {
    // Snapshot `messages` — the loop mutates its own array IN PLACE across
    // iterations, so without cloning here every recorded request would alias
    // the SAME ever-growing array and all end up reflecting its FINAL state.
    this.requests.push({ ...request, messages: [...request.messages] });
    const next = this.queue.shift();
    if (!next) {
      throw new Error(
        `QueueGateway: complete() called more times (${this.requests.length}) than responses were queued`,
      );
    }
    return Promise.resolve(next);
  }

  async *stream(request: LLMRequest): AsyncGenerator<LLMStreamEvent> {
    const response = await this.complete(request);
    yield { type: "text_delta", text: response.content };
    yield { type: "message_done", usage: response.usage, stopReason: response.stopReason };
  }

  listModels(): ModelDescriptor[] {
    return [FAKE_MODEL_DESCRIPTOR];
  }

  resolveModel(): ModelDescriptor {
    return FAKE_MODEL_DESCRIPTOR;
  }
}

function baseInput(
  filePath: string,
  gateway: LLMGateway,
  overrides: Partial<GenerateFixesInput> = {},
): GenerateFixesInput {
  const finding = makeXssFinding(filePath);
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    confirmed: [finding],
    gateway,
    source: createMapSourceReader({ [filePath]: ORIGINAL }),
    now: () => FIXED_NOW,
    ...overrides,
  };
}

describe("@montr/fix — proposeFixWithAgent (A5 bounded agent loop)", () => {
  // This candidate still goes through the real vitest-subprocess validatePatch
  // once (by design — see the file header). That alone is a multi-second cost
  // on a fast machine; on GitHub's windows-latest runner it crossed the default
  // 5000ms and failed as a timeout, not a logic error (confirmed: this exact
  // test passed on a real Windows run once retried manually). Generous,
  // explicit timeout rather than a flaky default.
  const REAL_VALIDATION_TIMEOUT_MS = 20_000;

  it(
    "is OFF by default: a single-shot response that fails validation is never retried",
    async () => {
      const gateway = new QueueGateway([textResponse(stillVulnerableEditsJson())]);
      const out = await generateFixes(baseInput("app/agent-loop/off-by-default.tsx", gateway));

      expect(gateway.requests).toHaveLength(1);
      const fix = out.fixes[0]!;
      // The model's (rejected) proposal falls back to the deterministic transform —
      // exactly the pre-existing single-shot behavior, completely unchanged.
      expect(fix.riskClass).toBe("auto-eligible");
      expect(fix.rationale).not.toContain("Model-proposed");
      expect(fix.rationale).toContain("Deterministic patch");
    },
    REAL_VALIDATION_TIMEOUT_MS,
  );

  it("retries after a structurally invalid edit list and succeeds on the next attempt", async () => {
    const metrics = new MontrMetrics();
    const gateway = new QueueGateway([
      textResponse(overlappingInvalidEditsJson()),
      textResponse(goodEditsJson()),
    ]);

    const out = await generateFixes(
      baseInput("app/agent-loop/retry-invalid-edits.tsx", gateway, {
        agentLoop: { enabled: true, maxIterations: 3 },
        metrics,
      }),
    );

    expect(gateway.requests).toHaveLength(2);
    // A14's existing failure-visibility bookkeeping fires for the bad attempt.
    expect(metrics.snapshot().errors).toBeGreaterThan(0);

    const fix = out.fixes[0]!;
    expect(fix.riskClass).toBe("auto-eligible");
    expect(fix.rationale).toContain("Model-proposed");
    expect(fix.proofOfFixTest.failsPrePatch).toBe(true);
    expect(fix.proofOfFixTest.passesPostPatch).toBe(true);

    // The retry feedback the model was actually sent named the real problem.
    const secondRequest = gateway.requests[1]!;
    const feedback = secondRequest.messages[secondRequest.messages.length - 1]!;
    expect(feedback.role).toBe("user");
    expect(String(feedback.content)).toMatch(/overlapping|out-of-range|malformed/);
  });

  it("retries after a proposal that leaves the vulnerability in place and succeeds on a later attempt", async () => {
    const gateway = new QueueGateway([
      textResponse(stillVulnerableEditsJson()),
      textResponse(goodEditsJson()),
    ]);

    const out = await generateFixes(
      baseInput("app/agent-loop/retry-still-vulnerable.tsx", gateway, {
        agentLoop: { enabled: true, maxIterations: 3 },
      }),
    );

    expect(gateway.requests).toHaveLength(2);
    const fix = out.fixes[0]!;
    expect(fix.riskClass).toBe("auto-eligible");
    expect(fix.rationale).toContain("Model-proposed");
    expect(fix.proofOfFixTest.failsPrePatch).toBe(true);
    expect(fix.proofOfFixTest.passesPostPatch).toBe(true);

    // The feedback after the rejected attempt is the SPECIFIC "still present" reason.
    const secondRequest = gateway.requests[1]!;
    const feedback = secondRequest.messages[secondRequest.messages.length - 1]!;
    expect(String(feedback.content)).toMatch(/did NOT remove the vulnerability/);
  });

  // Same rationale as REAL_VALIDATION_TIMEOUT_MS above: the final candidate's
  // real vitest-subprocess validatePatch run is a genuine multi-second cost,
  // and this test timed out at the vitest default on GitHub's windows-latest
  // runner. Explicit, generous timeout rather than a flaky default.
  it(
    "respects maxIterations: never calls the gateway more times than the bound allows",
    async () => {
      const gateway = new QueueGateway([
        textResponse(stillVulnerableEditsJson()),
        textResponse(stillVulnerableEditsJson()),
        textResponse(stillVulnerableEditsJson()),
      ]);

      const out = await generateFixes(
        baseInput("app/agent-loop/max-iterations.tsx", gateway, {
          agentLoop: { enabled: true, maxIterations: 3 },
        }),
      );

      // Exactly 3 — never a 4th call (which would have thrown inside QueueGateway
      // and been silently swallowed by the loop's own catch, masking a real bug).
      expect(gateway.requests).toHaveLength(3);

      // The model never produced a validated proposal within the bound, so the
      // pipeline still degrades safely to the deterministic transform.
      const fix = out.fixes[0]!;
      expect(fix.riskClass).toBe("auto-eligible");
      expect(fix.rationale).not.toContain("Model-proposed");
    },
    REAL_VALIDATION_TIMEOUT_MS,
  );

  it("exposes a sandboxed read_file tool whose results come from ctx.source, never raw fs", async () => {
    const filePath = "app/agent-loop/with-tool.tsx";
    const helperContents = 'export const HELPER = "sandboxed-value";\n';

    const readCall: LLMToolCall = {
      id: "call_1",
      name: "read_file",
      input: { path: "shared/helper.ts" },
    };
    const missingCall: LLMToolCall = {
      id: "call_2",
      name: "read_file",
      input: { path: "shared/does-not-exist.ts" },
    };

    const gateway = new QueueGateway([
      toolUseResponse([readCall]),
      toolUseResponse([missingCall]),
      textResponse(goodEditsJson()),
    ]);

    const out = await generateFixes(
      baseInput(filePath, gateway, {
        agentLoop: { enabled: true, maxIterations: 3, maxToolCalls: 2 },
        source: createMapSourceReader({
          [filePath]: ORIGINAL,
          "shared/helper.ts": helperContents,
        }),
      }),
    );

    // Two tool rounds + one proposal round = 3 gateway calls, but only ONE
    // proposal attempt was consumed (tool rounds are bounded separately).
    expect(gateway.requests).toHaveLength(3);

    // The request tools were actually offered (agent loop with maxToolCalls > 0).
    expect(gateway.requests[0]!.tools?.some((t) => t.name === "read_file")).toBe(true);

    // The SECOND request's history carries the first tool's real, sandboxed result.
    const afterFirstTool = gateway.requests[1]!.messages;
    const firstToolResult = afterFirstTool.find(
      (m) => m.role === "tool" && m.toolCallId === "call_1",
    );
    expect(firstToolResult?.content).toBe(helperContents);

    // The THIRD request's history carries the not-found placeholder for the
    // missing path — never a thrown error, never raw filesystem access.
    const afterSecondTool = gateway.requests[2]!.messages;
    const secondToolResult = afterSecondTool.find(
      (m) => m.role === "tool" && m.toolCallId === "call_2",
    );
    expect(secondToolResult?.content).toMatch(/file not found or unreadable/);
    expect(String(secondToolResult?.content)).toContain("shared/does-not-exist.ts");

    const fix = out.fixes[0]!;
    expect(fix.riskClass).toBe("auto-eligible");
    expect(fix.rationale).toContain("Model-proposed");
  });

  it("audit-logs the round-trip count (metadata only) alongside the existing fix.generated fields", async () => {
    class CapturingAudit implements AuditLogClient {
      readonly events: Parameters<AuditLogClient["append"]>[0][] = [];
      append(input: Parameters<AuditLogClient["append"]>[0]) {
        this.events.push(input);
        return Promise.resolve({
          id: "audit_1",
          clientId: input.clientId,
          sequence: 1,
          scanId: input.scanId,
          actor: input.actor,
          action: input.action,
          targetType: input.targetType,
          targetId: input.targetId,
          summary: input.summary,
          metadata: input.metadata ?? {},
          prevHash: "",
          hash: "hash",
          at: FIXED_NOW,
        });
      }
      list() {
        return Promise.resolve([]);
      }
      verifyChain() {
        return Promise.resolve(true);
      }
    }

    const audit = new CapturingAudit();
    const gateway = new QueueGateway([
      textResponse(stillVulnerableEditsJson()),
      textResponse(goodEditsJson()),
    ]);

    await generateFixes(
      baseInput("app/agent-loop/audit-iterations.tsx", gateway, {
        agentLoop: { enabled: true, maxIterations: 3 },
        audit,
      }),
    );

    expect(audit.events).toHaveLength(1);
    const meta = audit.events[0]!.metadata as Record<string, unknown>;
    expect(meta.iterations).toBe(2);
    // ⛔ still metadata only — no code bodies leaked via the new field.
    expect(JSON.stringify(meta)).not.toContain("dangerouslySetInnerHTML");
  });
});
