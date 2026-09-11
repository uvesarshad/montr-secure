/**
 * Regression test for A17's discovery in `runOneVerifier` (adversarial.ts):
 * this call site shares `metadata.purpose: "confirmation"` with
 * `static.ts`'s `runLlmReview`, but asks its own lenses for a DIFFERENT JSON
 * shape (`{confirm, rationale}` vs. `static.ts`'s `{confirmed, argument}`).
 * Without an explicit `request.responseSchema` override, a real provider's
 * schema-constrained decoding (packages/llm-gateway/src/structured-output.ts
 * resolves the purpose-keyed `confirmation` schema by default) would force
 * every real response into the WRONG shape and `rec.confirm`/`rec.rationale`
 * would always read `undefined` — every verifier silently voting reject
 * forever. A hand-mocked `LLMGateway.complete()` (as used here and in
 * tests/confirm.investigation.test.ts) bypasses real schema enforcement
 * entirely, so this bug was invisible to every existing test.
 */
import { describe, it, expect } from "vitest";
import type { AppMap, LLMGateway, LLMRequest, LLMResponse } from "@montr/contracts";
import { AppMapSchema } from "@montr/contracts";
import { getHardenedDefaults } from "@montr/config";
import { runAdversarialVerification } from "./adversarial.js";
import type { ConfirmDeps, ConfirmInput } from "./types.js";

function minimalAppMap(): AppMap {
  return AppMapSchema.parse({
    id: "map_1",
    clientId: "client_1",
    repo: "example/repo",
    branch: "main",
    commitSha: "abcdef1",
    createdAt: "2026-01-15T10:00:00.000Z",
  });
}

function minimalInput(): ConfirmInput {
  return {
    clientId: "client_1",
    scanId: "scan_1",
    appMap: minimalAppMap(),
    probable: [],
    allowLive: false,
    config: getHardenedDefaults(),
  };
}

describe("adversarial.ts — runOneVerifier's own responseSchema (A17 regression)", () => {
  it("sends an explicit responseSchema matching {confirm, rationale} — not the shared confirmation-purpose default", async () => {
    const seenRequests: LLMRequest[] = [];
    const llm: LLMGateway = {
      complete(request: LLMRequest): Promise<LLMResponse> {
        seenRequests.push(request);
        return Promise.resolve({
          id: "r1",
          provider: "anthropic",
          model: "claude-opus-5",
          content: JSON.stringify({ confirm: true, rationale: "reachable and exploitable" }),
          stopReason: "end_turn",
          usage: { inputTokens: 10, outputTokens: 10, totalTokens: 20 },
          latencyMs: 1,
        });
      },
    } as unknown as LLMGateway;

    const deps: ConfirmDeps = { llm, investigation: { verifierCount: 1 } };
    const outcome = await runAdversarialVerification(
      deps,
      minimalInput(),
      { id: "f1", category: "idor", exposure: "public", location: { file: "a.ts", line: 1 } },
      "candidate rationale",
      "evidence summary",
    );

    expect(seenRequests).toHaveLength(1);
    const schema = seenRequests[0]?.responseSchema as
      { properties?: Record<string, unknown> } | undefined;
    expect(schema).toBeDefined();
    expect(schema?.properties).toHaveProperty("confirm");
    expect(schema?.properties).toHaveProperty("rationale");
    // The shared "confirmation" purpose default (static.ts's contract) uses
    // DIFFERENT field names — assert this call site does not silently fall
    // back to it.
    expect(schema?.properties).not.toHaveProperty("confirmed");
    expect(schema?.properties).not.toHaveProperty("argument");

    // And the fix actually restores correct voting: a real `{confirm:true}`
    // reply is read as a confirm vote, not silently dropped.
    expect(outcome?.confirmVotes).toBe(1);
    expect(outcome?.confirmed).toBe(true);
  });
});
