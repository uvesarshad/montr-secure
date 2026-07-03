/**
 * EGRESS GUARD (build-plan §4.8, §11, golden rule #1).
 *
 * ⛔ "No inbound internet dependency at runtime beyond the client LLM endpoint."
 * This module compiles a DEFAULT-DENY egress policy from configuration and
 * asserts that the only permitted outbound destination is the configured client
 * LLM endpoint (plus any explicitly operator-approved infra host). Everything
 * else is denied with a typed {@link EgressBlockedError}.
 *
 * Usable at two points:
 *   - startup:     {@link assertStartupEgress} — compile + validate the policy once.
 *   - per-request: {@link assertEgressAllowed} — call before every outbound fetch.
 *
 * Deliberately consumes a STRUCTURAL subset of `@montr/config`'s `MontrConfig`
 * (see {@link EgressConfig}) so the guard does not couple to the config package's
 * build; a real `MontrConfig` satisfies it. The values still come from config.
 */
import { EgressBlockedError, type Provider } from "@montr/contracts";

/**
 * Provider default egress hosts, used only when no explicit `llm.endpoint` is
 * configured. Entries beginning with "." are broad SUFFIX matches and trigger a
 * warning — operators should set `llm.endpoint` to narrow egress to one host.
 */
export const PROVIDER_DEFAULT_HOSTS: Record<Provider, readonly string[]> = {
  anthropic: ["api.anthropic.com"],
  bedrock: [".amazonaws.com"],
  vertex: [".googleapis.com"],
  azure: [".openai.azure.com"],
  // Direct BYO-key providers — exact hosts (narrow default-deny). Operators can
  // override with `llm.endpoint` (e.g. a regional/intl or private-proxy host).
  openai: ["api.openai.com"],
  google: ["generativelanguage.googleapis.com"],
  xai: ["api.x.ai"],
  moonshot: ["api.moonshot.ai"],
  zhipu: ["open.bigmodel.cn"],
  deepseek: ["api.deepseek.com"],
};

/** Structural subset of `MontrConfig` the egress guard needs. */
export interface EgressConfig {
  readonly llm?: { readonly provider?: Provider; readonly endpoint?: string };
  readonly security?: {
    readonly egressPolicy?: string;
    readonly allowedEgressHosts?: readonly string[];
  };
  readonly telemetry?: { readonly enabled?: boolean; readonly endpoint?: string };
  readonly dast?: { readonly allowlist?: readonly string[] };
}

export type EgressAllowSource =
  "llm-endpoint" | "provider-default" | "config-allowlist" | "telemetry" | "dast-target";

export interface EgressAllowEntry {
  /** Lowercased host, or a suffix like ".amazonaws.com" when `suffix` is true. */
  readonly host: string;
  readonly source: EgressAllowSource;
  readonly suffix: boolean;
}

export interface EgressPolicy {
  /** Always default-deny (golden rule). */
  readonly policy: "default-deny";
  readonly entries: readonly EgressAllowEntry[];
  /** Exact hostnames allowed (lowercased). */
  readonly allowedHosts: ReadonlySet<string>;
  /** Suffix rules (host must end with one of these). */
  readonly allowedSuffixes: readonly string[];
  /** Non-fatal advisories (e.g. a broad provider default is in effect). */
  readonly warnings: readonly string[];
  /** The primary allowed LLM host, if determinable. */
  readonly llmHost?: string;
}

export interface DeriveEgressOptions {
  /** Also allow the configured DAST staging targets (worker process only). */
  readonly includeDastTargets?: boolean;
  /** Extra operator-approved hosts (e.g. an offline OSV/ruleset mirror). */
  readonly extraHosts?: readonly string[];
}

/**
 * Normalise a URL or bare host into a lowercased hostname (port/path stripped).
 * Throws on empty/invalid input.
 */
export function normalizeHost(target: string): string {
  const t = target.trim();
  if (!t) throw new EgressBlockedError("empty egress target", { target });
  try {
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(t)) return new URL(t).hostname.toLowerCase();
    if (t.startsWith("//")) return new URL(`http:${t}`).hostname.toLowerCase();
    return new URL(`http://${t}`).hostname.toLowerCase();
  } catch {
    throw new EgressBlockedError(`invalid egress target: ${t}`, { target: t });
  }
}

/** Compile a default-deny egress policy from configuration. */
export function deriveEgressPolicy(
  config: EgressConfig,
  opts: DeriveEgressOptions = {},
): EgressPolicy {
  const entries: EgressAllowEntry[] = [];
  const warnings: string[] = [];
  const addExact = (raw: string, source: EgressAllowSource): void => {
    entries.push({ host: normalizeHost(raw), source, suffix: false });
  };

  let llmHost: string | undefined;
  const endpoint = config.llm?.endpoint;
  if (endpoint) {
    llmHost = normalizeHost(endpoint);
    entries.push({ host: llmHost, source: "llm-endpoint", suffix: false });
  } else {
    const provider: Provider = config.llm?.provider ?? "anthropic";
    for (const d of PROVIDER_DEFAULT_HOSTS[provider] ?? []) {
      if (d.startsWith(".")) {
        entries.push({ host: d.toLowerCase(), source: "provider-default", suffix: true });
        warnings.push(
          `egress: provider '${provider}' has no explicit llm.endpoint; allowing broad suffix '${d}'. Set llm.endpoint to narrow egress to a single host.`,
        );
      } else {
        entries.push({ host: d.toLowerCase(), source: "provider-default", suffix: false });
        llmHost = d.toLowerCase();
      }
    }
  }

  for (const h of config.security?.allowedEgressHosts ?? []) addExact(h, "config-allowlist");
  for (const h of opts.extraHosts ?? []) addExact(h, "config-allowlist");

  if (config.telemetry?.enabled && config.telemetry.endpoint) {
    addExact(config.telemetry.endpoint, "telemetry");
  }

  if (opts.includeDastTargets) {
    for (const t of config.dast?.allowlist ?? []) {
      try {
        addExact(t, "dast-target");
      } catch {
        /* skip malformed allowlist entries; DAST layer validates them itself */
      }
    }
  }

  const policy = config.security?.egressPolicy ?? "default-deny";
  if (policy !== "default-deny") {
    warnings.push(`egress policy is '${policy}', expected 'default-deny' (golden rule #1).`);
  }

  return {
    policy: "default-deny",
    entries,
    allowedHosts: new Set(entries.filter((e) => !e.suffix).map((e) => e.host)),
    allowedSuffixes: entries.filter((e) => e.suffix).map((e) => e.host),
    warnings,
    ...(llmHost ? { llmHost } : {}),
  };
}

/** True if `target` (URL or host) is permitted by the policy. */
export function isEgressAllowed(policy: EgressPolicy, target: string): boolean {
  let host: string;
  try {
    host = normalizeHost(target);
  } catch {
    return false;
  }
  if (policy.allowedHosts.has(host)) return true;
  return policy.allowedSuffixes.some((s) => host === s.slice(1) || host.endsWith(s));
}

/**
 * ⛔ Assert an outbound destination is permitted. Throws {@link EgressBlockedError}
 * for anything not on the compiled allowlist. Call before EVERY outbound request.
 */
export function assertEgressAllowed(policy: EgressPolicy, target: string): void {
  if (!isEgressAllowed(policy, target)) {
    // Metadata only: the target host is not a secret, but never include bodies.
    throw new EgressBlockedError(`egress denied: ${target} is not the configured LLM endpoint`, {
      target,
      allowedHostCount: policy.allowedHosts.size,
      allowedSuffixCount: policy.allowedSuffixes.length,
    });
  }
}

export interface StartupEgressOptions extends DeriveEgressOptions {
  /** Sink for warnings (e.g. a logger.warn). Defaults to a no-op. */
  readonly onWarning?: (message: string) => void;
}

/**
 * Compile + validate the egress policy at startup. Enforces default-deny and
 * that at least one destination (the LLM endpoint/provider) is reachable; throws
 * {@link EgressBlockedError} on misconfiguration. Returns the compiled policy.
 */
export function assertStartupEgress(
  config: EgressConfig,
  opts: StartupEgressOptions = {},
): EgressPolicy {
  const policy = deriveEgressPolicy(config, opts);
  const configured = config.security?.egressPolicy ?? "default-deny";
  if (configured !== "default-deny") {
    throw new EgressBlockedError(
      `egress policy must be 'default-deny', got '${configured}' (golden rule #1).`,
      { egressPolicy: configured },
    );
  }
  if (policy.allowedHosts.size === 0 && policy.allowedSuffixes.length === 0) {
    throw new EgressBlockedError(
      "no egress destination resolved — configure llm.endpoint or a provider so the LLM is reachable.",
    );
  }
  const warn = opts.onWarning;
  if (warn) for (const w of policy.warnings) warn(w);
  return policy;
}

/** Ergonomic guard bundling the compiled policy with per-request checks. */
export interface EgressGuard {
  readonly policy: EgressPolicy;
  readonly warnings: readonly string[];
  isAllowed(target: string): boolean;
  assert(target: string): void;
}

/** Build an {@link EgressGuard} from configuration (validates at startup). */
export function createEgressGuard(
  config: EgressConfig,
  opts: StartupEgressOptions = {},
): EgressGuard {
  const policy = assertStartupEgress(config, opts);
  return {
    policy,
    warnings: policy.warnings,
    isAllowed: (target: string) => isEgressAllowed(policy, target),
    assert: (target: string) => assertEgressAllowed(policy, target),
  };
}
