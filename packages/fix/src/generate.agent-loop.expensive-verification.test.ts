/**
 * A5 — proves the central design constraint of the bounded agent loop
 * directly: the EXPENSIVE, real-`vitest`-subprocess `validatePatch` (patch.ts)
 * is called exactly ONCE for the accepted candidate, never once per retry
 * iteration, no matter how many times `proposeFixWithAgent` looped against
 * its cheap in-process oracle first.
 *
 * Isolated into its own file (rather than folded into
 * generate.agent-loop.test.ts) because `vi.mock` is file-scoped — every test
 * in a file that mocks "./patch.js" runs through the wrapped module, and this
 * keeps that blast radius to just the one assertion it exists for.
 */
import { vi, describe, it, expect, beforeEach } from "vitest";

const { validatePatchSpy } = vi.hoisted(() => ({ validatePatchSpy: vi.fn() }));

vi.mock("./patch.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./patch.js")>();
  return {
    ...actual,
    validatePatch: async (...args: Parameters<typeof actual.validatePatch>) => {
      validatePatchSpy(...args);
      return actual.validatePatch(...args);
    },
  };
});

import {
  ConfirmedFindingSchema,
  type ConfirmedFinding,
  type LLMGateway,
  type LLMRequest,
  type LLMResponse,
  type LLMStreamEvent,
  type ModelDescriptor,
} from "@montr/contracts";
import { generateFixes, type GenerateFixesInput } from "./generate.js";
import { createMapSourceReader } from "./source.js";

const CLIENT_ID = "client_expensive_verification_test";
const SCAN_ID = "scan_expensive_verification_test";
const FIXED_NOW = "2026-01-01T00:00:00.000Z";

/** A minimal, schema-valid `xss` ConfirmedFinding at `file` (see
 * generate.agent-loop.test.ts's identical helper for why this is built
 * directly rather than via @montr/fixtures — not a dependency of @montr/fix). */
function makeXssFinding(file: string): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    id: "conf_expensive_verification_0001",
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

const ORIGINAL_LINES = [
  "export default function Comp({ q }) {",
  "  return <div dangerouslySetInnerHTML={{ __html: q }} />;",
  "}",
  "",
];
const ORIGINAL = ORIGINAL_LINES.join("\n");
const VULN_LINE_NO = 2;
const FIXED_LINE = ORIGINAL_LINES[VULN_LINE_NO - 1]!.replace(
  /<(\w+)\s+dangerouslySetInnerHTML=\{\{\s*__html:\s*([\s\S]*?)\s*\}\}\s*\/>/,
  (_m, tag: string, expr: string) => `<${tag}>{${expr.trim()}}</${tag}>`,
);
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

let responseSeq = 0;
function textResponse(content: string): LLMResponse {
  responseSeq++;
  return {
    id: `resp_${responseSeq}`,
    provider: "anthropic",
    model: "claude-sonnet-5",
    content,
    stopReason: "end_turn",
    usage: { inputTokens: 10, outputTokens: 10, totalTokens: 20 },
    latencyMs: 1,
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

class QueueGateway implements LLMGateway {
  readonly requests: LLMRequest[] = [];
  private readonly queue: LLMResponse[];
  constructor(responses: LLMResponse[]) {
    this.queue = [...responses];
  }
  complete(request: LLMRequest): Promise<LLMResponse> {
    this.requests.push({ ...request, messages: [...request.messages] });
    const next = this.queue.shift();
    if (!next) throw new Error("QueueGateway: out of queued responses");
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

describe("@montr/fix — A5 agent loop never runs real vitest-subprocess verification per iteration", () => {
  beforeEach(() => {
    validatePatchSpy.mockClear();
  });

  it("calls the REAL validatePatch exactly once even after several failed cheap-oracle retries", async () => {
    // Three rejected-by-the-cheap-oracle attempts, then one that finally
    // removes the vulnerability — four gateway round-trips, but the real
    // vitest-subprocess validatePatch must fire only for the ONE candidate
    // that is ultimately accepted by generateOne, not once per retry.
    const gateway = new QueueGateway([
      textResponse(stillVulnerableEditsJson()),
      textResponse(stillVulnerableEditsJson()),
      textResponse(stillVulnerableEditsJson()),
      textResponse(goodEditsJson()),
    ]);

    const out = await generateFixes(
      baseInput("app/agent-loop/expensive-once.tsx", gateway, {
        agentLoop: { enabled: true, maxIterations: 5 },
      }),
    );

    expect(gateway.requests).toHaveLength(4); // the loop really did retry 3 times
    expect(validatePatchSpy).toHaveBeenCalledTimes(1); // but real verification ran once

    const fix = out.fixes[0]!;
    expect(fix.riskClass).toBe("auto-eligible");
    expect(fix.rationale).toContain("Model-proposed");
    expect(fix.proofOfFixTest.failsPrePatch).toBe(true);
    expect(fix.proofOfFixTest.passesPostPatch).toBe(true);
  }, 30_000);

  it("still calls real validatePatch at most twice (llm + deterministic candidates) when every retry is exhausted", async () => {
    // The model never produces an accepted proposal within the bound — the
    // loop makes exactly maxIterations gateway calls, then generateOne falls
    // through to the deterministic candidate. Real verification is bounded by
    // the (fixed, small) candidate list, NOT by how many iterations the loop took.
    const gateway = new QueueGateway([
      textResponse(stillVulnerableEditsJson()),
      textResponse(stillVulnerableEditsJson()),
      textResponse(stillVulnerableEditsJson()),
    ]);

    const out = await generateFixes(
      baseInput("app/agent-loop/expensive-bounded.tsx", gateway, {
        agentLoop: { enabled: true, maxIterations: 3 },
      }),
    );

    expect(gateway.requests).toHaveLength(3);
    // llm candidate (still vulnerable, real-validated and rejected) + deterministic candidate (accepted) = 2.
    expect(validatePatchSpy).toHaveBeenCalledTimes(2);

    const fix = out.fixes[0]!;
    expect(fix.riskClass).toBe("auto-eligible");
    expect(fix.rationale).not.toContain("Model-proposed");
  }, 30_000);
});
