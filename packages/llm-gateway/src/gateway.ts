import {
  BudgetExceededError,
  LLMRequestSchema,
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
import { toGatewayError } from "./errors.js";
import { assertModelFloor, buildDescriptors, isBelowFloor, resolveDescriptor } from "./models.js";
import { applyKeyTierGuard, detectKeyTier } from "./keytier.js";
import { buildCallLog, logCall } from "./logging.js";
import { contentToString } from "./mapping.js";
import {
  resolvePromptTemplate,
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

  estimateTokens(request: LLMRequest): Promise<number> {
    const text =
      (request.system ?? "") + request.messages.map((m) => contentToString(m.content)).join("");
    return Promise.resolve(Math.ceil(text.length / 4));
  }

  async complete(request: LLMRequest): Promise<LLMResponse> {
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
