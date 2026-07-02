/**
 * Internal + public types for @montr/appmap (Layer 0).
 *
 * `buildAppMap` takes a {@link BuildAppMapInput} (what to scan) plus optional
 * {@link BuildAppMapDeps} (injected collaborators). Everything external — the LLM
 * gateway, the state store, the audit log, git, the clock, id generation — is
 * injected so the layer builds and tests fully OFFLINE against @montr/fixtures.
 */
import type { AppMap, Layer0Output, ScanMode, ScanScope } from "@montr/contracts";
import type { MontrConfig } from "@montr/config";
import type { LLMGateway } from "@montr/contracts";
import type { AppMapRepository } from "@montr/state-store";
import type { AuditLogClient } from "@montr/telemetry";
import type { Logger } from "@montr/telemetry";

/** What Layer 0 is asked to map. Mirrors {@link import("@montr/contracts").Layer0JobData}. */
export interface BuildAppMapInput {
  clientId: string;
  scanId: string;
  /** Local filesystem path OR a git URL. A local path is scanned in place. */
  repo: string;
  branch: string;
  mode: ScanMode;
  /** The requested scope; Layer 0 enriches it (route/file counts, diff graph). */
  scope: ScanScope;
  config: MontrConfig;
  /** Stable AppMap id. Defaults to `appmap_${scanId}` (deterministic). */
  appMapId?: string;
  /**
   * Known commit SHA. When omitted: read from git if the workspace is a repo,
   * else a deterministic content hash is derived so the map is still addressable.
   */
  commitSha?: string;
  /**
   * Pre-computed changed files for `diff` mode (e.g. supplied by CI). When
   * omitted, Layer 0 asks git for the diff against the merge-base.
   */
  changedFiles?: string[];
}

/** Minimal git surface Layer 0 needs — satisfied by `simple-git`, mockable in tests. */
export interface GitClient {
  clone(repoUrl: string, dir: string): Promise<void>;
  checkout(dir: string, branch: string): Promise<void>;
  revparseHead(dir: string): Promise<string | null>;
  /** Files changed vs the diff base (merge-base of `branch`), repo-relative. */
  changedFiles(dir: string, branch: string): Promise<string[]>;
}

/** Injected collaborators. All optional — absent ones degrade gracefully. */
export interface BuildAppMapDeps {
  /**
   * ⛔ The semantic pass. When present, an LLM labels auth boundaries + fills
   * gaps AFTER the deterministic map exists (golden rule #6). Absent ⇒ the map
   * is deterministic-only (still valid).
   */
  gateway?: LLMGateway;
  /** Persist + DECIDE-2 stale-commit invalidation. Absent ⇒ no persistence. */
  appMaps?: AppMapRepository;
  /** Append-only audit of `appmap.built` / `appmap.invalidated`. */
  audit?: AuditLogClient;
  logger?: Logger;
  /** Injectable clock for deterministic `createdAt`. */
  now?: () => Date;
  /** Git client for URL checkout + diff. Absent ⇒ URL repos cannot be cloned. */
  git?: GitClient;
  /** Root for sandboxed clones. Defaults to the OS temp dir. */
  workspaceRoot?: string;
  /**
   * ⛔ Kill switch. Checked before the (only) LLM call; an aborted signal skips
   * the semantic pass and returns the deterministic map (fail-safe).
   */
  signal?: AbortSignal;
  /** Emit intra-layer progress (0..100). */
  onProgress?: (phase: string, pct: number, message?: string) => void;
}

/** Result of resolving the intake target to an on-disk workspace. */
export interface Workspace {
  /** Absolute path to the checked-out / in-place repo root. */
  dir: string;
  commitSha: string;
  /** True when we cloned into a sandbox that must be cleaned up. */
  cloned: boolean;
  cleanup: () => Promise<void>;
}

/** The deterministic map plus the file inventory the builders share. */
export interface DeterministicResult {
  appMap: AppMap;
  /** Repo-relative source file paths that were scanned. */
  files: string[];
}

export type { AppMap, Layer0Output, ScanMode, ScanScope };
