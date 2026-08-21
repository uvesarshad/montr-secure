import {
  BudgetExceededError,
  LLMRequestSchema,
  NotImplementedError,
  type KeyTier,
  type LLMCallLog,
  type LLMCallMetadata,
  type LLMGateway,
  type LLMRequest,
  type LLMResponse,
  type LLMStreamEvent,
  type ModelDescriptor,
  type ModelTier,
  type Provider,
  type TokenUsage,
} from "@montr/contracts";
import type {
  LLMBatchHandle,
  LLMBatchRequestItem,
  LLMBatchResultItem,
  LLMBatchResultsOptions,
  LLMBatchStatus,
} from "./batch.js";
import type { MontrConfig } from "@montr/config";
import {
  priceUsageUsd,
  type BudgetRegistry,
  type CostMeter,
  type MeterEntry,
} from "@montr/cost-meter";
import { createEgressGuard, type EgressGuard } from "@montr/security";
import { createLogger, getMetrics, type Logger } from "@montr/telemetry";
import { createAdapter, type AdapterCompletion, type ProviderAdapter } from "./adapters/index.js";
import {
  DEFAULT_CONFIDENCE_THRESHOLD,
  DEFAULT_MAX_ESCALATIONS,
  evaluateConfidence,
  isEligibleForEscalation,
  withEscalatedTier,
  type ConfidenceSignal,
  type EscalationPolicy,
} from "./escalation.js";
import { toGatewayError } from "./errors.js";
import {
  assertModelFloor,
  buildDescriptors,
  isBelowFloor,
  nextTier,
  resolveDescriptor,
} from "./models.js";
import { applyKeyTierGuard, detectKeyTier } from "./keytier.js";
import { buildCallLog, logCall } from "./logging.js";
import { contentToString } from "./mapping.js";
import {
  resolvePromptTemplate,
  resolvePromptVersionTemplate,
  type PromptVersionSource,
  type ResolvePromptOptions,
} from "./prompts.js";
import {
  DEFAULT_RETRY_POLICY,
  runWithTimeout,
  withIteratorTimeout,
  withRetryAndFallback,
  type RetryPolicy,
  type SleepFn,
} from "./retry.js";

/** Default per-call wall-clock timeout (ms). */
export const DEFAULT_TIMEOUT_MS = 60_000;

export interface CreateGatewayOptions {
  config: MontrConfig;
  /** Structured logger; defaults to the telemetry console logger (with scrubber). */
  logger?: Logger;
  /** Cost meter that receives per-call token accounting (golden rule #8). */
  costMeter?: CostMeter;
  /** Injectable provider adapter (tests / custom transports). */
  adapter?: ProviderAdapter;
  /** Metadata-only per-call hook (e.g. to the audit log). NEVER receives bodies. */
  onCall?: (log: LLMCallLog) => void;
  /** Operator-declared key tier — the highest-confidence key-tier-guard signal. */
  declaredKeyTier?: KeyTier;
  /** Injectable clock (deterministic timestamps/latency in tests). */
  now?: () => Date;
  /** Injectable sleep for retry backoff (no real timers in tests). */
  sleep?: SleepFn;
  maxRetries?: number;
  timeoutMs?: number;
  /** Hard-fail (throw ModelBelowFloorError) instead of warning on a sub-floor confirmation model. */
  strictModelFloor?: boolean;
  /**
   * Versioned-prompt lookup (§8.2, §15) — typically `store.promptVersions`
   * from @montr/state-store, injected structurally (see prompts.ts) so this
   * package doesn't take a build-time dependency on @montr/state-store.
   * Omit to make {@link MontrLlmGateway.resolvePrompt} a pure pass-through
   * to each call's hardcoded fallback (today's behavior, unchanged).
   */
  promptSource?: PromptVersionSource;
  /**
   * ⛔ PRE-call budget guard (A2, DECIDE-4). Looked up per request by
   * `request.metadata.scanId` — one gateway instance serves every concurrent
   * scan, so the fixed `costMeter` above can't carry a per-scan ceiling. When
   * a registry is supplied and the scan has a registered `CostMeter` +
   * `BudgetPolicy`, `complete()`/`stream()` estimate the pending call's cost
   * and refuse to dispatch it (`BudgetExceededError`) when spend-so-far plus
   * that estimate would clear the ceiling — BEFORE the provider is called,
   * not just between layers. Omit to leave today's between-layers-only
   * enforcement (`orchestrator/controller.ts`'s `enforceBudget`) unchanged.
   */
  budgetRegistry?: BudgetRegistry;
  /**
   * ⛔ OPT-IN dynamic model-tier escalation (E9). Default OFF (undefined) —
   * a caller that does not set this sees `complete()` behave byte-for-byte
   * identically to before this option existed: a single dispatch, no
   * confidence evaluation, `response.confidence` never populated. When
   * enabled, a request that resolves via `request.tier` (NOT a pinned
   * `request.model` — see escalation.ts's `isEligibleForEscalation`) whose
   * response comes back low-confidence is retried against the NEXT tier up
   * (triage → default → confirmation), bounded by `maxEscalations` and never
   * past the top configured tier. Each escalated attempt still passes
   * through the SAME retry policy, model-fallback cascade (A11), and
   * pre-call budget guard (A2) as any other call — escalation composes with
   * those mechanisms rather than replacing any of them. See escalation.ts
   * for the confidence-signal extraction and docs/modules/llm-gateway.md's
   * E9 section for the full design rationale.
   */
  escalation?: EscalationPolicy;
}

/**
 * The Montr Secure LLM gateway (§8.2). Unified `complete()`/`stream()` over four
 * provider adapters with retries+backoff, per-call timeouts, structured errors,
 * ⛔ metadata-only logging (golden rule #1), the ⛔ key-tier guard, the model-floor
 * warning (DECIDE-3), and per-call token accounting emitted to the Cost Meter.
 */
export class MontrLlmGateway implements LLMGateway {
  private readonly config: MontrConfig;
  private readonly logger: Logger;
  private readonly costMeter?: CostMeter;
  private readonly adapter: ProviderAdapter;
  private readonly onCall?: (log: LLMCallLog) => void;
  private readonly now: () => Date;
  private readonly retryPolicy: RetryPolicy;
  private readonly timeoutMs: number;
  private readonly descriptors: ModelDescriptor[];
  private readonly warnedFloorModels = new Set<string>();
  /** Versioned-prompt lookup (§8.2, §15) — undefined means "no DB, use hardcoded". */
  private readonly promptSource?: PromptVersionSource;
  /** ⛔ PRE-call budget guard (A2) — see {@link CreateGatewayOptions.budgetRegistry}. */
  private readonly budgetRegistry?: BudgetRegistry;
  /** ⛔ OPT-IN dynamic model-tier escalation (E9) — see {@link CreateGatewayOptions.escalation}. */
  private readonly escalation?: EscalationPolicy;

  /**
   * ⛔ Default-deny egress guard (golden rule #1, §4.8). Compiled + validated at
   * construction (worker boot) so the only reachable outbound host is the client
   * LLM endpoint; asserted again before every outbound provider call.
   */
  readonly egress: EgressGuard;

  /** The classified retention tier of the configured key (§11 key-tier guard). */
  readonly keyTier: KeyTier;

  constructor(opts: CreateGatewayOptions) {
    this.config = opts.config;
    this.logger =
      opts.logger ??
      createLogger({ name: "llm-gateway", bindings: { clientId: opts.config.clientId } });
    this.costMeter = opts.costMeter;
    this.budgetRegistry = opts.budgetRegistry;
    this.escalation = opts.escalation;
    this.promptSource = opts.promptSource;
    this.onCall = opts.onCall;
    this.now = opts.now ?? (() => new Date());
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retryPolicy = {
      ...DEFAULT_RETRY_POLICY,
      ...(opts.maxRetries !== undefined ? { maxRetries: opts.maxRetries } : {}),
      ...(opts.sleep ? { sleep: opts.sleep } : {}),
    };
    // ⛔ Egress guard (golden rule #1): default-deny, LLM endpoint only. Compiled
    // + validated here (throws on a non-default-deny policy or an unreachable LLM
    // destination); provider-default warnings surface to the structured log. Built
    // BEFORE the adapter so it can be threaded in for per-request egress asserts.
    this.egress = createEgressGuard(opts.config, {
      onWarning: (message) => this.logger.warn("egress.warning", { message }),
    });
    this.adapter =
      opts.adapter ?? createAdapter(opts.config.llm.provider, opts.config, this.egress);
    this.descriptors = buildDescriptors(opts.config);

    // ⛔ Key-tier guard — may throw KeyTierRejectedError when policy is "block".
    this.keyTier = detectKeyTier({
      provider: this.provider,
      declaredTier: opts.declaredKeyTier,
      apiKey: opts.config.llm.apiKey,
    });
    applyKeyTierGuard(this.keyTier, opts.config.llm.keyTierGuard, this.provider, this.logger);

    // Model floor (DECIDE-3) — warn once at construction (or throw when strict).
    assertModelFloor(opts.config, { strict: opts.strictModelFloor ?? false, logger: this.logger });
  }

  private get provider(): Provider {
    return this.adapter.provider;
  }

  /**
   * ⛔ Assert the outbound LLM destination is on the default-deny allowlist
   * before dispatching. When an explicit endpoint is configured, that is the
   * exact host the adapter will hit; otherwise the provider-default host was
   * already validated as reachable at construction. The concrete adapter also
   * asserts the resolved outbound host (endpoint or provider default) via the
   * threaded egress guard before EVERY request — this is the outer layer.
   */
  private assertEgress(): void {
    const endpoint = this.config.llm.endpoint;
    if (endpoint) this.egress.assert(endpoint);
  }

  listModels(): ModelDescriptor[] {
    return [...this.descriptors];
  }

  resolveModel(tierOrId: ModelTier | string): ModelDescriptor {
    return resolveDescriptor(this.config, tierOrId);
  }

  /**
   * Resolve prompt `name`'s live template (§8.2, §15): the active
   * DB-versioned template when a `promptSource` was configured at
   * construction and has one for this client/global scope; otherwise
   * `fallback` unchanged — so a caller migrating from a hardcoded prompt
   * constant to `gateway.resolvePrompt("fix.system", FIX_SYSTEM_PROMPT)`
   * behaves identically until a version is actually created + activated in
   * the DB. A lookup failure is logged and treated as "no active version" —
   * never thrown, never blocks the call.
   */
  async resolvePrompt(
    name: string,
    fallback: string,
    opts: ResolvePromptOptions = {},
  ): Promise<string> {
    return resolvePromptTemplate(
      this.promptSource,
      name,
      fallback,
      { clientId: opts.clientId ?? this.config.clientId },
      (err) => this.logger.warn("llm.prompt_resolve_failed", { name, error: String(err) }),
    );
  }

  /**
   * Resolve prompt `name`'s template at a SPECIFIC version rather than
   * whichever is active (E15 — eval-driven prompt optimization). Mirrors
   * {@link resolvePrompt}'s fail-safe contract exactly (never throws; a
   * missing source, a source without version listing, a version that doesn't
   * exist, or a lookup error all resolve to `fallback`). Not called by any of
   * the five real pipeline call sites today — those resolve the ACTIVE
   * version via {@link resolvePrompt}, unchanged; this is the seam an eval
   * harness (`@montr/qa`'s `prompt-eval.ts`) or a future promotion workflow
   * uses to score a candidate version before it is ever marked active.
   */
  async resolvePromptVersion(
    name: string,
    version: number,
    fallback: string,
    opts: ResolvePromptOptions = {},
  ): Promise<string> {
    return resolvePromptVersionTemplate(
      this.promptSource,
      name,
      version,
      fallback,
      { clientId: opts.clientId ?? this.config.clientId },
      (err) =>
        this.logger.warn("llm.prompt_version_resolve_failed", {
          name,
          version,
          error: String(err),
        }),
    );
  }

  /**
   * Fast, LOCAL, offline token-count heuristic (A19; `chars/4`, unchanged).
   * Deliberately kept this way: this is the estimator `assertPreCallBudget()`
   * calls on EVERY gated `complete()`/`stream()` — a real per-call network
   * round-trip to a provider's token-counting endpoint (see
   * {@link MontrLlmGateway.countTokens}, added for A19) would add real
   * latency and an extra request to every LLM call in the pipeline for a
   * marginal accuracy gain over this heuristic, which already errs
   * conservative (chars/4 is a reasonable upper-ish bound for English/JSON
   * text — see https://github.com/anthropics tokenizer notes; the budget
   * guard's whole job is to refuse BEFORE dispatch, so slightly
   * over-estimating input tokens here is the safe failure direction, not a
   * bug to "fix" by adding latency to the hot path). Callers that need a
   * precise, provider-verified count and can afford the extra round-trip
   * should call {@link MontrLlmGateway.countTokens} instead.
   */
  estimateTokens(request: LLMRequest): Promise<number> {
    const text =
      (request.system ?? "") + request.messages.map((m) => contentToString(m.content)).join("");
    return Promise.resolve(Math.ceil(text.length / 4));
  }

  /**
   * Real, provider-verified token count (A19) — calls the adapter's
   * `countTokens` (Anthropic's `messages.countTokens` endpoint today; see
   * `adapters/anthropic.ts`) when available. NOT used by the pre-call budget
   * guard, which stays on the fast heuristic above for latency reasons — this
   * is for callers that want precision and can afford a network round-trip
   * (tooling, calibration, a future non-hot-path caller). Falls back to
   * {@link estimateTokens}'s heuristic — logging a warning, never throwing —
   * when the adapter has no real counting endpoint (Bedrock/Vertex/Azure
   * today) or the real call itself fails.
   */
  async countTokens(request: LLMRequest): Promise<number> {
    const parsed = LLMRequestSchema.parse(request);
    const modelId = this.resolveModelId(parsed);
    if (this.adapter.countTokens) {
      try {
        this.assertEgress();
        return await this.adapter.countTokens(parsed, modelId);
      } catch (err) {
        this.logger.warn("llm.count_tokens_failed", {
          provider: this.provider,
          model: modelId,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    return this.estimateTokens(parsed);
  }

  /**
   * ⛔ Public entry point. A thin wrapper over {@link completeOnce} — when
   * `escalation` (E9) isn't configured, this is EXACTLY the prior `complete()`
   * body, unchanged. When it is, `completeWithEscalation` may dispatch more
   * than one `completeOnce` call, walking the tier ladder on low confidence.
   */
  async complete(request: LLMRequest): Promise<LLMResponse> {
    const parsed = LLMRequestSchema.parse(request);
    if (!this.escalation?.enabled) return this.completeOnce(parsed);
    return this.completeWithEscalation(parsed);
  }

  /**
   * ⛔ OPT-IN dynamic model-tier escalation (E9). Runs `completeOnce` against
   * the caller's requested tier, evaluates confidence (escalation.ts), and —
   * while the response is low-confidence, the request is tier-eligible (see
   * `isEligibleForEscalation`), a next tier exists, and the per-call
   * escalation cap hasn't been reached — retries the SAME request against
   * the next tier up. Bounded on two independent axes so cost can never run
   * away: `maxEscalations` (attempts) and `nextTier` returning `undefined`
   * once the top configured tier (`confirmation`) is reached.
   */
  private async completeWithEscalation(parsed: LLMRequest): Promise<LLMResponse> {
    const policy = this.escalation!;
    const threshold = policy.confidenceThreshold ?? DEFAULT_CONFIDENCE_THRESHOLD;
    const maxEscalations = policy.maxEscalations ?? DEFAULT_MAX_ESCALATIONS;

    let current = parsed;
    let response = await this.completeOnce(current);
    let signal = evaluateConfidence(
      current.responseFormat,
      response.content,
      response.stopReason,
      threshold,
    );
    let attempts = 0;

    while (attempts < maxEscalations && signal.low && isEligibleForEscalation(current)) {
      const fromTier = current.tier!;
      const toTier = nextTier(fromTier);
      if (!toTier) break; // already at the top configured tier — never escalate past it
      attempts++;
      this.recordEscalation(current, fromTier, toTier, signal);
      current = withEscalatedTier(current, toTier);
      response = await this.completeOnce(current);
      signal = evaluateConfidence(
        current.responseFormat,
        response.content,
        response.stopReason,
        threshold,
      );
    }

    // Surface the FINAL attempt's confidence signal (self-reported or proxy)
    // on the response actually returned, so a caller can see why escalation
    // stopped (high confidence, cap reached, or top tier reached).
    return signal.confidence !== undefined
      ? { ...response, confidence: signal.confidence }
      : response;
  }

  /** Metric + structured log for a tier-escalation attempt (E9), mirroring `recordFallback`'s pattern. */
  private recordEscalation(
    request: LLMRequest,
    fromTier: ModelTier,
    toTier: ModelTier,
    signal: ConfidenceSignal,
  ): void {
    getMetrics().recordError("llm_gateway.model_escalation");
    this.logger.warn("llm.model_escalation", {
      provider: this.provider,
      fromTier,
      toTier,
      reason: signal.source,
      confidence: signal.confidence,
      purpose: request.metadata.purpose,
      layer: request.metadata.layer,
      scanId: request.metadata.scanId,
    });
    this.escalation?.onEscalate?.(fromTier, toTier, signal);
  }

  /**
   * The original single-dispatch `complete()` body (retry+fallback, pre-call
   * budget guard, parse-failure metric, accounting) — unchanged by E9.
   * `complete()` calls this once directly when escalation isn't configured,
   * or up to `1 + maxEscalations` times via `completeWithEscalation`.
   */
  private async completeOnce(request: LLMRequest): Promise<LLMResponse> {
    const parsed = LLMRequestSchema.parse(request);
    this.assertEgress();
    const modelId = this.resolveModelId(parsed);
    this.maybeWarnFloor(parsed, modelId);
    // ⛔ PRE-call budget guard (A2, DECIDE-4) — BEFORE dispatch, not just between layers.
    await this.assertPreCallBudget(parsed, modelId);

    const start = this.now().getTime();
    let completion;
    try {
      // A11: primary model gets the full retry policy (unchanged behavior);
      // only once that's exhausted does the configured fallback model (if
      // any) get its one bounded attempt — see fallbackModelIds().
      completion = await withRetryAndFallback(
        modelId,
        (attemptModelId, _attempt) =>
          runWithTimeout(
            (signal) => this.adapter.complete(parsed, attemptModelId, signal),
            this.timeoutMs,
            this.provider,
          ),
        this.retryPolicy,
        {
          fallbackModels: this.fallbackModelIds(modelId),
          onFallback: (fromModelId, toModelId) =>
            this.recordFallback(parsed, fromModelId, toModelId),
        },
      );
    } catch (err) {
      throw toGatewayError(err, this.provider);
    }
    const latencyMs = this.now().getTime() - start;

    this.maybeRecordParseFailure(parsed, completion);

    const response: LLMResponse = {
      id: completion.id,
      provider: this.provider,
      model: completion.model,
      content: completion.content,
      stopReason: completion.stopReason,
      usage: completion.usage,
      latencyMs,
      ...(completion.toolCalls ? { toolCalls: completion.toolCalls } : {}),
    };
    this.account(parsed.metadata, completion.model, completion.usage, latencyMs);
    return response;
  }

  /**
   * ⛔ LLM response parse-failure metric (A13). Every real call site sets
   * `responseFormat: "json"` and does its own `try { JSON.parse() } catch`
   * with a fail-safe fallback — a fallback that quietly "succeeds" (e.g.
   * confirm/src/static.ts's `safeJson` returning `undefined`, or
   * correlation/src/llm.ts's `parseCorrelationResponse` returning `null`) is
   * indistinguishable from a healthy call anywhere those layers currently
   * look, so a deployment-wide collapse in LLM contribution had no signal.
   * Checked centrally here — once, at the gateway boundary — rather than
   * duplicated across five layer packages (several of which are out of scope
   * for this change): independent of whatever fallback each caller's own
   * parse layers on top, so it still fires even when the caller's fallback
   * "succeeds" with an empty/degraded result. A structured-output-enforced
   * response (A13 item 1) should make this rare for supported providers —
   * this metric is what proves that in production.
   */
  private maybeRecordParseFailure(request: LLMRequest, completion: AdapterCompletion): void {
    if (request.responseFormat !== "json") return;
    if (completion.toolCalls && completion.toolCalls.length > 0) return; // tool-use turn, no JSON body expected
    try {
      JSON.parse(completion.content);
    } catch {
      getMetrics().recordError("llm_gateway.response_parse_failure");
      this.logger.warn("llm.response_parse_failure", {
        provider: this.provider,
        model: completion.model,
        purpose: request.metadata.purpose,
        layer: request.metadata.layer,
      });
    }
  }

  async *stream(request: LLMRequest): AsyncGenerator<LLMStreamEvent, void, unknown> {
    const parsed = LLMRequestSchema.parse(request);
    this.assertEgress();
    const modelId = this.resolveModelId(parsed);
    this.maybeWarnFloor(parsed, modelId);
    // ⛔ PRE-call budget guard (A2, DECIDE-4) — BEFORE dispatch, not just between layers.
    await this.assertPreCallBudget(parsed, modelId);

    const start = this.now().getTime();
    const controller = new AbortController();
    let usage: TokenUsage | undefined;
    let failed = false;

    try {
      const source = this.adapter.stream(parsed, modelId, controller.signal);
      for await (const event of withIteratorTimeout(source, this.timeoutMs, this.provider)) {
        if (event.type === "message_done") usage = event.usage;
        yield event;
      }
    } catch (err) {
      failed = true;
      controller.abort();
      const gerr = toGatewayError(err, this.provider);
      this.logger.warn("llm.stream_error", {
        provider: this.provider,
        model: modelId,
        code: gerr.code,
        purpose: parsed.metadata.purpose,
      });
      yield { type: "error", message: gerr.message };
    }

    const latencyMs = this.now().getTime() - start;
    if (!failed && usage) this.account(parsed.metadata, modelId, usage, latencyMs);
  }

  /**
   * Submit a Batch API job (A31 item 3) — async, queued, 50% discounted,
   * intended for non-latency-sensitive work with no user waiting
   * synchronously. Requires an adapter that implements `submitBatch`
   * (only `AnthropicAdapter` does today — see `adapters/anthropic.ts`);
   * other providers throw `NotImplementedError`.
   *
   * Each item's own `request.metadata`/`request.tier`/`request.model` is
   * resolved and floor-checked exactly like a `complete()` call, but there is
   * NO pre-call budget guard here: `assertPreCallBudget` estimates a single
   * call's worst-case cost against a scan's LIVE remaining budget, which is
   * meaningless for a batch that may not resolve for up to 24 hours — by the
   * time results come back, the scan's spend and ceiling may have moved. A
   * caller that wants a budget check on batch spend must check its own
   * estimate before submitting.
   *
   * NOT currently called by any pipeline layer (see docs/modules/llm-gateway.md's
   * A31 section) — the orchestrator's FSM is built around synchronous layer
   * completion, which a job that may take up to 24h to resolve cannot fit
   * without deeper resumability work than this change's scope. Built and
   * fully tested so the capability exists for a future layer or an offline/
   * bulk consumer, mirroring how A10 handled gateway streaming.
   */
  async submitBatch(items: LLMBatchRequestItem[]): Promise<LLMBatchHandle> {
    this.assertEgress();
    if (!this.adapter.submitBatch) {
      throw new NotImplementedError(`Batch API not supported for provider '${this.provider}'`, {
        provider: this.provider,
      });
    }
    const resolved = items.map((item) => {
      const parsed = LLMRequestSchema.parse(item.request);
      const modelId = this.resolveModelId(parsed);
      this.maybeWarnFloor(parsed, modelId);
      return { customId: item.customId, request: parsed, modelId };
    });
    const handle = await this.adapter.submitBatch(resolved);
    return {
      batchId: handle.batchId,
      processingStatus: handle.processingStatus as LLMBatchHandle["processingStatus"],
    };
  }

  /** Poll a submitted batch's processing status + per-outcome counts (A31). */
  async pollBatch(batchId: string): Promise<LLMBatchStatus> {
    this.assertEgress();
    if (!this.adapter.pollBatch) {
      throw new NotImplementedError(`Batch API not supported for provider '${this.provider}'`, {
        provider: this.provider,
      });
    }
    const status = await this.adapter.pollBatch(batchId);
    return {
      batchId: status.batchId,
      processingStatus: status.processingStatus as LLMBatchStatus["processingStatus"],
      requestCounts: status.counts,
    };
  }

  /**
   * Stream a completed (or partially completed) batch's per-request results
   * (A31), normalized into `LLMResponse` shape like `complete()`'s return
   * value. Pass `metadataByCustomId` (see {@link LLMBatchResultsOptions}) to
   * also record each succeeded result's usage into that scan's CostMeter at
   * the batch-discounted rate ({@link priceUsageUsd}'s `batch: true`) —
   * mirroring `account()`, but keyed by the metadata the caller supplies
   * rather than metadata the gateway tracked itself (see the interface's
   * docstring for why: batch results may be polled well after this process
   * restarted).
   */
  async *getBatchResults(
    batchId: string,
    opts: LLMBatchResultsOptions = {},
  ): AsyncGenerator<LLMBatchResultItem, void, unknown> {
    this.assertEgress();
    if (!this.adapter.getBatchResults) {
      throw new NotImplementedError(`Batch API not supported for provider '${this.provider}'`, {
        provider: this.provider,
      });
    }
    for await (const item of this.adapter.getBatchResults(batchId)) {
      if (item.status === "succeeded") {
        const response: LLMResponse = {
          id: item.completion.id,
          provider: this.provider,
          model: item.completion.model,
          content: item.completion.content,
          stopReason: item.completion.stopReason,
          usage: item.completion.usage,
          // Batch responses have no meaningful single-call latency (the job
          // may have run minutes to hours after submission).
          latencyMs: 0,
          ...(item.completion.toolCalls ? { toolCalls: item.completion.toolCalls } : {}),
        };
        const metadata = opts.metadataByCustomId?.[item.customId];
        if (metadata)
          this.account(metadata, item.completion.model, item.completion.usage, 0, { batch: true });
        yield { customId: item.customId, status: "succeeded", response };
      } else if (item.status === "errored") {
        yield {
          customId: item.customId,
          status: "errored",
          errorType: item.errorType,
          message: item.message,
        };
      } else {
        yield { customId: item.customId, status: item.status };
      }
    }
  }

  private resolveModelId(request: LLMRequest): string {
    return request.model ?? resolveDescriptor(this.config, request.tier ?? "default").modelId;
  }

  /**
   * Fallback chain for `complete()` (A11). Currently a single client-configured
   * `config.llm.fallbackModel`, applied across every tier — bounded to one
   * fallback attempt by construction (see {@link withRetryAndFallback}), not
   * infinite. Empty when unset (today's fail-outright-after-retries behavior)
   * or when it equals the primary model (no self-fallback).
   */
  private fallbackModelIds(primaryModelId: string): string[] {
    const fallback = this.config.llm.fallbackModel;
    if (!fallback || fallback === primaryModelId) return [];
    return [fallback];
  }

  /** Metric + structured log for a model-fallback attempt (A11). */
  private recordFallback(request: LLMRequest, fromModelId: string, toModelId: string): void {
    getMetrics().recordError("llm_gateway.model_fallback");
    this.logger.warn("llm.model_fallback", {
      provider: this.provider,
      fromModel: fromModelId,
      toModel: toModelId,
      purpose: request.metadata.purpose,
      layer: request.metadata.layer,
      scanId: request.metadata.scanId,
    });
  }

  /** Warn (once per model) when a confirmation call runs on a sub-floor model. */
  private maybeWarnFloor(request: LLMRequest, modelId: string): void {
    if (!this.config.llm.enforceModelFloor) return;
    const isConfirmation =
      request.tier === "confirmation" || request.metadata.purpose === "confirmation";
    if (!isConfirmation || !isBelowFloor(modelId) || this.warnedFloorModels.has(modelId)) return;
    this.warnedFloorModels.add(modelId);
    this.logger.warn("llm.model_below_floor", {
      provider: this.provider,
      model: modelId,
      purpose: request.metadata.purpose,
    });
  }

  /**
   * ⛔ PRE-call budget guard (A2, DECIDE-4). Estimates the pending call's cost
   * (input tokens via `estimateTokens`; output tokens conservatively taken as
   * `request.maxTokens` — the worst case the model is allowed to spend) and
   * refuses to dispatch it when spend-so-far plus that estimate would clear
   * the scan's ceiling. A no-op when no `budgetRegistry` was configured, the
   * request carries no `scanId`, no context is registered for that scan (e.g.
   * a non-`hard_halt` policy scan, or one that hasn't started a layer), or
   * neither budget dimension is configured on the policy. This is ADDITIVE to
   * `orchestrator/controller.ts`'s post-layer `enforceBudget` — that check
   * still runs, catching drift between estimates and provider-reported
   * actuals; this one stops a single call from ever reaching the provider in
   * the first place.
   */
  private async assertPreCallBudget(request: LLMRequest, modelId: string): Promise<void> {
    if (!this.budgetRegistry) return;
    const scanId = request.metadata.scanId;
    if (!scanId) return;
    const ctx = this.budgetRegistry.get(scanId);
    if (!ctx) return;
    const { meter, policy } = ctx;
    if (policy.maxUsd === undefined && policy.maxTotalTokens === undefined) return;
    if (policy.enforcement !== "hard_halt") return;

    const estimatedInputTokens = await this.estimateTokens(request);
    // Worst-case output: the model is free to use the entire requested budget.
    const estimatedOutputTokens = request.maxTokens;
    const estimatedUsage: TokenUsage = {
      inputTokens: estimatedInputTokens,
      outputTokens: estimatedOutputTokens,
      totalTokens: estimatedInputTokens + estimatedOutputTokens,
    };
    const estimatedUsd = priceUsageUsd(estimatedUsage, modelId);

    const spent = meter.checkBudget(policy);
    const projectedUsd = spent.spentUsd + estimatedUsd;
    const projectedTokens = spent.spentTokens + estimatedUsage.totalTokens;
    const overUsd = policy.maxUsd !== undefined && projectedUsd > policy.maxUsd;
    const overTokens =
      policy.maxTotalTokens !== undefined && projectedTokens > policy.maxTotalTokens;
    if (!overUsd && !overTokens) return;

    getMetrics().recordBudgetBreach(1, { enforcement: policy.enforcement, phase: "pre_call" });
    this.logger.error("llm.budget_precall_refused", {
      scanId,
      provider: this.provider,
      model: modelId,
      purpose: request.metadata.purpose,
      layer: request.metadata.layer,
      estimatedUsd,
      estimatedTokens: estimatedUsage.totalTokens,
      spentUsd: spent.spentUsd,
      spentTokens: spent.spentTokens,
      maxUsd: policy.maxUsd,
      maxTotalTokens: policy.maxTotalTokens,
    });
    throw new BudgetExceededError(
      "Budget ceiling would be exceeded by this call — refused before dispatch",
      {
        phase: "pre_call",
        scanId,
        provider: this.provider,
        modelId,
        estimatedUsd,
        estimatedTokens: estimatedUsage.totalTokens,
        spentUsd: spent.spentUsd,
        spentTokens: spent.spentTokens,
        maxUsd: policy.maxUsd,
        maxTotalTokens: policy.maxTotalTokens,
      },
    );
  }

  /**
   * ⛔ Metadata-only accounting: cost meter(s) + audit hook + structured log.
   *
   * A32: recorded usage MUST land in the same per-scan `CostMeter` instance
   * `assertPreCallBudget()` reads from (looked up via `budgetRegistry` by
   * `metadata.scanId`, mirroring that lookup exactly) — that is also the
   * SAME instance `orchestrator/controller.ts`'s `getMeter(scanId)` hands to
   * `enforceBudget` between layers (both come from the controller's single
   * `this.meters` cache; see `budgetRegistry.register(scanId, meter, ...)`
   * in `runLayerJob`). Without this, both the pre-call guard and the
   * between-layers check evaluate against a meter that never accumulates
   * real recorded spend — the whole point of A2's budget enforcement.
   *
   * The standalone `opts.costMeter` (constructor-level, not per-scan) is
   * still recorded into when configured — it remains legitimate for callers
   * that don't use `budgetRegistry` at all (tests, one-off/non-worker
   * tooling). If it happens to resolve to the exact same instance as the
   * registry-resolved meter, skip the duplicate `record()` call so a single
   * completed call's spend isn't double-counted.
   */
  private account(
    metadata: LLMCallMetadata,
    model: string,
    usage: TokenUsage,
    latencyMs: number,
    opts: { batch?: boolean } = {},
  ): void {
    const log = buildCallLog({
      provider: this.provider,
      model,
      usage,
      latencyMs,
      metadata,
      at: this.now().toISOString(),
    });
    logCall(this.logger, log);
    this.onCall?.(log);

    const entry: MeterEntry = {
      modelId: model,
      usage,
      ...(metadata.layer ? { layer: metadata.layer } : {}),
      // A31: Batch API results are billed at the 50% discount — carried
      // through to CostMeter.record() -> priceUsageUsd's `batch` option.
      ...(opts.batch ? { batch: true } : {}),
    };

    const scanMeter = metadata.scanId
      ? this.budgetRegistry?.get(metadata.scanId)?.meter
      : undefined;
    scanMeter?.record(entry);

    if (this.costMeter && this.costMeter !== scanMeter) {
      this.costMeter.record(entry);
    }
  }
}

/** Construct the configured LLM gateway. */
export function createLlmGateway(opts: CreateGatewayOptions): LLMGateway {
  return new MontrLlmGateway(opts);
}
