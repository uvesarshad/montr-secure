import type { LLMPurpose, LLMRequest } from "@montr/contracts";

/**
 * Real structured-output enforcement (A13). Only Azure previously set any
 * response format (`json_object`, no schema) — Anthropic, Bedrock, and Vertex
 * requested JSON in prose and relied on `try { JSON.parse() } catch`, so a
 * deployment-wide collapse in LLM contribution (every call silently falling
 * back to the deterministic path) had no signal anywhere.
 *
 * This module resolves a real JSON schema for a request WITHOUT requiring any
 * change to the five real call sites (packages/appmap/src/llm.ts,
 * packages/discovery/src/triage.ts, packages/correlation/src/llm.ts,
 * packages/confirm/src/static.ts, packages/fix/src/generate.ts — all
 * READ-ONLY verified against, none edited by this change). Each already sets
 * `metadata.purpose` and `responseFormat: "json"`; {@link resolveStructuredOutputSchema}
 * keys off `metadata.purpose` alone, so every existing caller gets real
 * schema-constrained output automatically. `request.responseSchema` remains
 * available as an explicit escape hatch for a future caller (e.g. E1's
 * agentic loop) that wants a schema this map doesn't know about.
 *
 * Each schema below mirrors that call site's OWN already-existing parsed-JSON
 * expectations (interface field names/optionality), not a hand-invented
 * divergent shape — see each file's local ad-hoc parse-result interface:
 *   - appmap_labeling  → appmap/src/llm.ts's `AuthBoundary` + `{authBoundaries: [...]}` wrapper
 *   - triage           → discovery/src/triage.ts's `TriageVerdict` + `{items: [...]}` wrapper
 *   - correlation      → correlation/src/llm.ts's `ParsedCorrelation`
 *   - confirmation     → confirm/src/static.ts's `LlmReview`
 *   - fix_generation   → fix/src/generate.ts's edit-list contract (A14: a
 *                        targeted `{edits:[{startLine,endLine,replacement}],
 *                        rationale}` shape, NOT a whole-file `fixedSource` —
 *                        see edits.ts's `LlmEdit` / `parseLlmEdits`)
 *
 * `report_synthesis` and `other` have no real caller today (A10) and are left
 * unmapped — those requests fall back to prose-JSON + `JSON.parse`, unchanged.
 */

const AUTH_STATE_ENUM = ["public", "authenticated", "role_gated", "unknown"] as const;

const AUTH_BOUNDARY_ITEM_SCHEMA: Record<string, unknown> = {
  type: "object",
  properties: {
    route: { type: "string" },
    method: { type: "string" },
    authState: { type: "string", enum: [...AUTH_STATE_ENUM] },
    authGate: { type: "string" },
  },
  required: [],
  additionalProperties: false,
};

/** Per-purpose JSON schemas, keyed by {@link LLMPurpose}. */
const PURPOSE_JSON_SCHEMAS: Partial<Record<LLMPurpose, Record<string, unknown>>> = {
  appmap_labeling: {
    type: "object",
    properties: {
      authBoundaries: { type: "array", items: AUTH_BOUNDARY_ITEM_SCHEMA },
    },
    required: ["authBoundaries"],
    additionalProperties: false,
  },
  triage: {
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
          required: ["i", "keep"],
          additionalProperties: false,
        },
      },
    },
    required: ["items"],
    additionalProperties: false,
  },
  correlation: {
    type: "object",
    properties: {
      reachabilityScore: { type: "number" },
      impactScore: { type: "number" },
      reachabilityHypothesis: { type: "string" },
      exploitHypothesis: { type: "string" },
    },
    required: [],
    additionalProperties: false,
  },
  confirmation: {
    type: "object",
    properties: {
      confirmed: { type: "boolean" },
      argument: { type: "string" },
    },
    required: [],
    additionalProperties: false,
  },
  fix_generation: {
    // A14: a targeted line-range edit list, not a whole-file rewrite — see
    // fix/src/edits.ts's LlmEdit/parseLlmEdits (all three edit fields are
    // required together; missing any one invalidates that edit entry).
    // Top-level `required: []` permits `{}`, which the prompt explicitly
    // asks for when the model "cannot fix it safely."
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
          additionalProperties: false,
        },
      },
      rationale: { type: "string" },
    },
    required: [],
    additionalProperties: false,
  },
};

/**
 * Resolve the JSON schema to enforce for a request, or `undefined` when
 * structured output shouldn't be requested (not `responseFormat: "json"`,
 * tools are in play — a tool-calling turn's response is the tool call, not
 * the final JSON text — or no schema is known for the purpose).
 */
export function resolveStructuredOutputSchema(
  request: LLMRequest,
): Record<string, unknown> | undefined {
  if (request.responseFormat !== "json") return undefined;
  if (request.tools && request.tools.length > 0) return undefined;
  return request.responseSchema ?? PURPOSE_JSON_SCHEMAS[request.metadata.purpose];
}

/** The Anthropic/Bedrock wire shape for `output_config.format`. */
export interface JsonSchemaOutputFormat {
  type: "json_schema";
  schema: Record<string, unknown>;
}

/** Build `output_config.format` for Anthropic-style (Anthropic + Bedrock) requests. */
export function resolveAnthropicOutputFormat(
  request: LLMRequest,
): JsonSchemaOutputFormat | undefined {
  const schema = resolveStructuredOutputSchema(request);
  return schema ? { type: "json_schema", schema } : undefined;
}
