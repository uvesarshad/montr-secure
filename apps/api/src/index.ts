/**
 * apps/api — Fastify HTTP API + RBAC + OpenAPI. Wave 0 stub; WS-L/WS-D build it.
 * All request/response shapes come from @montr/contracts; every mutating action
 * binds to an audit event.
 */
import { NotImplementedError } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";

export interface ApiServer {
  listen(port: number): Promise<void>;
  close(): Promise<void>;
}

export function createApiServer(_config: MontrConfig): ApiServer {
  throw new NotImplementedError("createApiServer — WS-L/WS-D");
}
