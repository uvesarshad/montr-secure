import { describe, it, expect } from "vitest";
import { LLMRequestSchema, type LLMRequest } from "@montr/contracts";
import {
  resolveStructuredOutputSchema,
  resolveAnthropicOutputFormat,
} from "./structured-output.js";

/**
 * A13: per-purpose JSON schema resolution. These schemas are derived from
 * each real call site's OWN already-existing parsed-JSON expectations
 * (appmap/src/llm.ts, discovery/src/triage.ts, correlation/src/llm.ts,
 * confirm/src/static.ts, fix/src/generate.ts — read-only verified, none
 * edited by this change) — see structured-output.ts's module doc comment.
 */

function req(overrides: Partial<LLMRequest> = {}): LLMRequest {
  return LLMRequestSchema.parse({
    messages: [{ role: "user", content: "x" }],
    maxTokens: 64,
    metadata: { purpose: "correlation" },
    responseFormat: "json",
    ...overrides,
  });
}

describe("resolveStructuredOutputSchema", () => {
  it("returns undefined for responseFormat: text", () => {
    expect(resolveStructuredOutputSchema(req({ responseFormat: "text" }))).toBeUndefined();
  });

  it("returns undefined when tools are present (a tool-use turn has no JSON body to constrain)", () => {
    const r = req({
      tools: [{ name: "grep", description: "search", parameters: { type: "object" } }],
    });
    expect(resolveStructuredOutputSchema(r)).toBeUndefined();
  });

  it("prefers an explicit request.responseSchema over the purpose-keyed default", () => {
    const custom = { type: "object", properties: { x: { type: "string" } } };
    const r = req({ responseSchema: custom });
    expect(resolveStructuredOutputSchema(r)).toEqual(custom);
  });

  it("resolves the correlation schema matching correlation/src/llm.ts's ParsedCorrelation", () => {
    const schema = resolveStructuredOutputSchema(req({ metadata: { purpose: "correlation" } }));
    expect(schema).toMatchObject({
      type: "object",
      properties: {
        reachabilityScore: { type: "number" },
        impactScore: { type: "number" },
        reachabilityHypothesis: { type: "string" },
        exploitHypothesis: { type: "string" },
      },
      additionalProperties: false,
    });
  });

  it("resolves the confirmation schema matching confirm/src/static.ts's LlmReview", () => {
    const schema = resolveStructuredOutputSchema(req({ metadata: { purpose: "confirmation" } }));
    expect(schema).toMatchObject({
      type: "object",
      properties: {
        confirmed: { type: "boolean" },
        argument: { type: "string" },
      },
      additionalProperties: false,
    });
  });

  it("resolves the fix_generation schema matching fix/src/edits.ts's LlmEdit list (A14)", () => {
    const schema = resolveStructuredOutputSchema(req({ metadata: { purpose: "fix_generation" } }));
    expect(schema).toMatchObject({
      type: "object",
      properties: {
        edits: {
          type: "array",
          items: {
            type: "object",
            properties: {
              startLine: { type: "integer" },
              endLine: { type: "integer" },
              replacement: { type: "string" },
            },
            required: ["startLine", "endLine", "replacement"],
          },
        },
        rationale: { type: "string" },
      },
      // Top-level required:[] permits `{}` — the model's documented
      // "cannot fix it safely" response.
      required: [],
      additionalProperties: false,
    });
  });

  it("resolves the triage schema matching discovery/src/triage.ts's wrapped {items:[...]} shape", () => {
    const schema = resolveStructuredOutputSchema(req({ metadata: { purpose: "triage" } }));
    expect(schema).toMatchObject({
      type: "object",
      properties: {
        items: {
          type: "array",
          items: {
            type: "object",
            properties: {
              i: { type: "integer" },
              keep: { type: "boolean" },
              reason: { type: "string" },
            },
          },
        },
      },
      required: ["items"],
      additionalProperties: false,
    });
  });

  it("resolves the appmap_labeling schema matching appmap/src/llm.ts's {authBoundaries:[...]} shape", () => {
    const schema = resolveStructuredOutputSchema(req({ metadata: { purpose: "appmap_labeling" } }));
    expect(schema).toMatchObject({
      type: "object",
      properties: {
        authBoundaries: {
          type: "array",
          items: {
            type: "object",
            properties: {
              authState: { enum: ["public", "authenticated", "role_gated", "unknown"] },
            },
          },
        },
      },
      required: ["authBoundaries"],
      additionalProperties: false,
    });
  });

  it("returns undefined for purposes with no real caller (report_synthesis, other)", () => {
    expect(
      resolveStructuredOutputSchema(req({ metadata: { purpose: "report_synthesis" } })),
    ).toBeUndefined();
    expect(resolveStructuredOutputSchema(req({ metadata: { purpose: "other" } }))).toBeUndefined();
  });
});

describe("resolveAnthropicOutputFormat", () => {
  it("wraps the resolved schema in the output_config.format wire shape", () => {
    const format = resolveAnthropicOutputFormat(req({ metadata: { purpose: "confirmation" } }));
    expect(format?.type).toBe("json_schema");
    expect(format?.schema).toMatchObject({ type: "object" });
  });

  it("returns undefined when no schema resolves", () => {
    expect(resolveAnthropicOutputFormat(req({ responseFormat: "text" }))).toBeUndefined();
  });
});
