/**
 * apps/worker — BullMQ worker host that runs the orchestrator + layer agents.
 * The BullMQ processing loop is WS-D's remaining work; the ⛔ egress boot guard
 * below is wired now so the worker (the process that actually reaches the LLM
 * via @montr/llm-gateway) validates default-deny egress before any work starts.
 */
import { NotImplementedError } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import { assertStartupEgress } from "@montr/security";
import { createLogger } from "@montr/telemetry";

export interface Worker {
  start(): Promise<void>;
  stop(): Promise<void>;
}

export function startWorker(config: MontrConfig): Worker {
  const logger = createLogger({ name: "montr-worker", bindings: { clientId: config.clientId } });
  // ⛔ Golden rule #1: compile + validate the default-deny egress policy at boot.
  // Throws on a non-default-deny policy or an unreachable LLM endpoint. DAST
  // staging targets are included so live-probe egress (when enabled) is scoped
  // to the same allowlist. The gateway re-asserts per outbound call.
  assertStartupEgress(config, {
    includeDastTargets: true,
    onWarning: (message) => logger.warn("egress.warning", { message }),
  });
  throw new NotImplementedError("startWorker — WS-D (egress boot guard is wired)");
}
