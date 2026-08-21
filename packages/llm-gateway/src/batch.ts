import type { LLMCallMetadata, LLMRequest, LLMResponse } from "@montr/contracts";

/**
 * Gateway-level Batch API types (A31, audit finding A31 item 3). The Batch
 * API is a genuinely different mechanism from triage's "batch all candidates
 * into one prompt" pattern (`packages/discovery/src/triage.ts`) — that is
 * request-shaping (one big prompt), this is Anthropic's async, queued,
 * 50%-discounted request MODE (`POST /v1/messages/batches`), where each
 * "request" in the batch is its own independent `LLMRequest`.
 *
 * These types live outside @montr/contracts (out of scope for this change —
 * see docs/modules/llm-gateway.md's A31 section) so `submitBatch`/`pollBatch`/
 * `getBatchResults` are additive methods on the concrete `MontrLlmGateway`
 * class, not part of the shared `LLMGateway` interface every layer package
 * codes against.
 */

/** One request to submit as part of a batch. */
export interface LLMBatchRequestItem {
  /** Caller-chosen id, unique within the batch — echoed back on each result row. */
  customId: string;
  request: LLMRequest;
}

export type LLMBatchProcessingStatus = "in_progress" | "canceling" | "ended";

export interface LLMBatchHandle {
  batchId: string;
  processingStatus: LLMBatchProcessingStatus;
}

export interface LLMBatchCounts {
  processing: number;
  succeeded: number;
  errored: number;
  canceled: number;
  expired: number;
}

export interface LLMBatchStatus extends LLMBatchHandle {
  requestCounts: LLMBatchCounts;
}

export type LLMBatchResultItem =
  | { customId: string; status: "succeeded"; response: LLMResponse }
  | { customId: string; status: "errored"; errorType: string; message: string }
  | { customId: string; status: "canceled" }
  | { customId: string; status: "expired" };

/**
 * Options for `getBatchResults()`. Batch results are available for up to 29
 * days and may be polled by a different process/restart than the one that
 * submitted the batch (a real worker crash/restart is exactly the case A3's
 * resumability work exists for) — so the gateway deliberately does NOT cache
 * a customId→metadata association in memory across calls. A caller that wants
 * per-result cost accounting into a scan's CostMeter must re-supply that
 * mapping here, the same way a real consumer would need to re-associate a
 * batch result with its originating scan/finding from its OWN persisted job
 * records after a restart.
 */
export interface LLMBatchResultsOptions {
  /** customId -> the original request's metadata, for per-result cost accounting. */
  metadataByCustomId?: Record<string, LLMCallMetadata>;
}
