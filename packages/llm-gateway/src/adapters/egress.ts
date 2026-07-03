/**
 * ⛔ Per-request egress assertion for provider adapters (golden rule #1, §4.8).
 *
 * Defense-in-depth ATOP the k8s default-deny NetworkPolicy: every adapter asserts
 * the exact outbound host it is about to contact BEFORE it dispatches, so the only
 * reachable destination is the operator-configured client LLM endpoint (or its
 * provider default). The asserter is a STRUCTURAL subset of @montr/security's
 * `EgressGuard` (which satisfies it directly) — kept minimal so the adapter layer
 * stays decoupled from the security package and injected test doubles are trivial.
 */
export interface AdapterEgress {
  /** ⛔ Throws EgressBlockedError when `target` is not the permitted LLM endpoint. */
  assert(target: string): void;
}

/**
 * The exact outbound host an adapter will contact: the operator-configured
 * `llm.endpoint` when set, otherwise the provider's default host. The result is
 * what @montr/security's default-deny policy permits (the configured endpoint, an
 * exact provider host, or a provider suffix such as `.amazonaws.com`).
 */
export function resolveOutboundTarget(
  endpoint: string | undefined,
  providerDefaultHost: string,
): string {
  return endpoint ?? providerDefaultHost;
}
