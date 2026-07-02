import {
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
import type { CostMeter } from "@montr/cost-meter";
import { createEgressGuard, type EgressGuard } from "@montr/security";
import { createLogger, type Logger } from "@montr/telemetry";
import { createAdapter, type ProviderAdapter } from "./adapters/index.js";
import { toGatewayError } from "./errors.js";
import { assertModelFloor, buildDescriptors, isBelowFloor, resolveDescriptor } from "./models.js";
import { applyKeyTierGuard, detectKeyTier } from "./keytier.js";
import { buildCallLog, logCall } from "./logging.js";
import { contentToString } from "./mapping.js";
import {
  DEFAULT_RETRY_POLICY,
  runWithTimeout,
  withIteratorTimeout,
  withRetry,
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
    this.onCall = opts.onCall;
    this.now = opts.now ?? (() => new Date());
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retryPolicy = {
      ...DEFAULT_RETRY_POLICY,
      ...(opts.maxRetries !== undefined ? { maxRetries: opts.maxRetries } : {}),
      ...(opts.sleep ? { sleep: opts.sleep } : {}),
    };
    this.adapter = opts.adapter ?? createAdapter(opts.config.llm.provider, opts.config);
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

    // ⛔ Egress guard (golden rule #1): default-deny, LLM endpoint only. Throws
    // on a non-default-deny policy or an unreachable LLM destination; warnings
    // (e.g. a broad provider-default suffix) surface to the structured log.
    this.egress = createEgressGuard(opts.config, {
      onWarning: (message) => this.logger.warn("egress.warning", { message }),
    });
  }

  private get provider(): Provider {
    return this.adapter.provider;
  }

  /**
   * ⛔ Assert the outbound LLM destination is on the default-deny allowlist
   * before dispatching. When an explicit endpoint is configured, that is the
   * exact host the adapter will hit; otherwise the provider-default host was
   * already validated as reachable at construction.
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

    const start = this.now().getTime();
    let completion;
    try {
      completion = await withRetry(
        () =>
          runWithTimeout(
            (signal) => this.adapter.complete(parsed, modelId, signal),
            this.timeoutMs,
            this.provider,
          ),
        this.retryPolicy,
      );
    } catch (err) {
      throw toGatewayError(err, this.provider);
    }
    const latencyMs = this.now().getTime() - start;

    const response: LLMResponse = {
      id: completion.id,
      provider: this.provider,
      model: completion.model,
      content: completion.content,
      stopReason: completion.stopReason,
      usage: completion.usage,
      latencyMs,
    };
    this.account(parsed.metadata, completion.model, completion.usage, latencyMs);
    return response;
  }

  async *stream(request: LLMRequest): AsyncGenerator<LLMStreamEvent, void, unknown> {
    const parsed = LLMRequestSchema.parse(request);
    this.assertEgress();
    const modelId = this.resolveModelId(parsed);
    this.maybeWarnFloor(parsed, modelId);

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

  /** ⛔ Metadata-only accounting: cost meter + audit hook + structured log. */
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
    this.costMeter?.record({
      modelId: model,
      usage,
      ...(metadata.layer ? { layer: metadata.layer } : {}),
    });
  }
}

/** Construct the configured LLM gateway. */
export function createLlmGateway(opts: CreateGatewayOptions): LLMGateway {
  return new MontrLlmGateway(opts);
}
