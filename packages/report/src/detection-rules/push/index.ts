/**
 * Detection-rule push adapter factory — mirrors
 * packages/llm-gateway/src/embeddings.ts's `createEmbeddingAdapter` matrix
 * precedent (A9) exactly: one real adapter, everything else an honest
 * `NotImplementedError` stub. See ./types.ts for the full design rationale.
 */
import { NotImplementedError } from "@montr/contracts";
import { SplunkHecPusher, type HecHttpClient } from "./splunk-hec.js";
import type {
  DetectionRulePushResult,
  DetectionRulePushTargetType,
  DetectionRulePusher,
} from "./types.js";

export * from "./types.js";
export { SplunkHecPusher, buildHecEvent, type HecHttpClient } from "./splunk-hec.js";

/** Honest stub for a listed-but-unimplemented push target (./types.ts's `UNIMPLEMENTED_PUSH_TARGET_TYPES`). Never no-ops or reports success. */
class UnimplementedDetectionRulePusher implements DetectionRulePusher {
  constructor(readonly type: DetectionRulePushTargetType) {}

  async pushRule(): Promise<DetectionRulePushResult> {
    throw new NotImplementedError(
      `Detection-rule push is not implemented for target type '${this.type}' — Splunk HEC ` +
        `('splunk_hec') is the only real push integration today. See ` +
        `packages/report/src/detection-rules/push/types.ts's UNIMPLEMENTED_PUSH_TARGET_TYPES ` +
        `for the documented follow-up scope.`,
      { targetType: this.type },
    );
  }
}

export interface CreateDetectionRulePusherOptions {
  /** Injectable HTTP client for the Splunk HEC adapter (tests / an alternate transport). Ignored by every other target type. */
  httpClient?: HecHttpClient;
}

/** Build the pusher for a target type. Never returns a fake/no-op adapter for an unimplemented type — see the class above. */
export function createDetectionRulePusher(
  type: DetectionRulePushTargetType,
  opts: CreateDetectionRulePusherOptions = {},
): DetectionRulePusher {
  switch (type) {
    case "splunk_hec":
      return new SplunkHecPusher(opts.httpClient);
    case "elastic":
    case "sentinel":
      return new UnimplementedDetectionRulePusher(type);
    default: {
      const exhaustive: never = type;
      throw new Error(`Unknown detection-rule push target type: ${String(exhaustive)}`);
    }
  }
}
