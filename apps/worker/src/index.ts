/**
 * apps/worker — BullMQ worker host that runs the orchestrator + layer agents.
 * Wave 0 stub; WS-D builds it against the queue contracts in @montr/contracts.
 */
import { NotImplementedError } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";

export interface Worker {
  start(): Promise<void>;
  stop(): Promise<void>;
}

export function startWorker(_config: MontrConfig): Worker {
  throw new NotImplementedError("startWorker — WS-D");
}
