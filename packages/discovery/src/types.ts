/**
 * Shared types for Layer 1 discovery. Detectors import ONLY from here (one
 * direction: detectors → types), so there are no import cycles and every
 * external scanner is expressed as an injectable interface (offline-testable).
 */
import type { AppMap, CustomRule, LLMGateway, ScanScope } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { Logger } from "@montr/telemetry";
import type { FileProvider, RepoFile } from "./util/files.js";

// ---------------------------------------------------------------------------
// Injectable external-scanner runners. In production these shell out to the
// real binaries (execa); in tests they are stubbed with canned JSON. A runner
// returning `null` means "tool unavailable" → the detector degrades to empty.
// ---------------------------------------------------------------------------

/** Subset of Semgrep's `--json` output the SAST parser consumes. */
export interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col?: number };
  end?: { line: number; col?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: Record<string, unknown>;
  };
}
export interface SemgrepJson {
  results?: SemgrepResult[];
  errors?: unknown[];
}
export interface SemgrepRunArgs {
  repoRoot: string;
  rulesets: string[];
  signal?: AbortSignal;
}
export type SemgrepRunner = (args: SemgrepRunArgs) => Promise<SemgrepJson | null>;

/** One entry of gitleaks' JSON report (subset). */
export interface GitleaksFinding {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  EndLine?: number;
  Match?: string;
  Secret?: string;
}
export interface GitleaksRunArgs {
  repoRoot: string;
  signal?: AbortSignal;
}
export type GitleaksRunner = (args: GitleaksRunArgs) => Promise<GitleaksFinding[] | null>;

// ---------------------------------------------------------------------------
// Discovery inputs + context
// ---------------------------------------------------------------------------

/** Injectable dependencies — all optional so the default path is offline-safe. */
export interface DiscoveryDeps {
  /** Clock for `createdAt`. Inject a fixed clock for deterministic tests. */
  now?: () => string;
  logger?: Logger;
  /** ⛔ Kill switch — detectors and subprocesses stop when this aborts (§11). */
  signal?: AbortSignal;
  /**
   * Optional gateway enabling the LLM triage/explain pass. The LLM NEVER detects
   * (golden rule #6); it only annotates candidates the tools already produced,
   * and only after the App Map exists (guaranteed — it is a required input).
   */
  gateway?: LLMGateway;
  /** Explicitly enable/disable triage (default: on iff a gateway is provided). */
  enableTriage?: boolean;
  /** Override file access (else derived from `files` or `repoRoot`). */
  fileProvider?: FileProvider;
  /** Injectable Semgrep runner (default shells out to the real binary). */
  semgrep?: SemgrepRunner;
  /** Injectable gitleaks runner (default shells out to the real binary). */
  gitleaks?: GitleaksRunner;
  /** Curated Semgrep rulesets (default {@link DEFAULT_SEMGREP_RULESETS}). */
  semgrepRulesets?: string[];
}

/** Input to {@link runDiscovery}. Extends the frozen Wave-0 stub shape. */
export interface RunDiscoveryInput {
  clientId: string;
  scanId: string;
  appMap: AppMap;
  scope: ScanScope;
  config: MontrConfig;
  /** Checked-out repo root (enables the on-disk file provider + real scanners). */
  repoRoot?: string;
  /** In-memory files (alternative to `repoRoot`; wins for the content detectors). */
  files?: RepoFile[];
  /**
   * ⛔ Client-authored custom rules (Phase-4 / Wave 5, §16). Only ENABLED rules
   * are loaded (via {@link loadCustomRules}) and run ALONGSIDE the curated
   * rulesets: enabled secret rules become extra secret detectors; enabled semgrep
   * bodies are materialized to temporary `--config` files for the SAST pass.
   * Disabled drafts NEVER feed a scan (fail-safe). Omitting this leaves the
   * standard scan path byte-for-byte unchanged.
   */
  customRules?: readonly CustomRule[];
  deps?: DiscoveryDeps;
}

/** Everything a single detector needs, assembled by {@link runDiscovery}. */
export interface DetectorContext {
  clientId: string;
  scanId: string;
  appMap: AppMap;
  scope: ScanScope;
  config: MontrConfig;
  repoRoot?: string;
  files: FileProvider;
  now: () => string;
  logger: Logger;
  signal?: AbortSignal;
  /** Record a graceful-degradation warning (also logged). */
  warn(detector: string, message: string): void;
  readonly warnings: string[];
}
