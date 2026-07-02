import type {
  Scan,
  AuditEvent,
  ConfirmedFinding,
  Report,
  AppMap,
  CostEstimate,
  Fix,
  PullRequest,
  ProgressEvent,
  Role,
  Id,
} from "@montr/contracts";
import type { CurrentUser } from "../rbac.js";

/**
 * Local request/response envelope types for the web ↔ API boundary. Every
 * pipeline entity is a `@montr/contracts` shape (golden rule #10); these
 * envelopes only wrap them for transport and always echo the AuditEvent that a
 * mutation produced (golden rule #7 — every mutation is audit-logged).
 */

export interface SessionResponse {
  user: CurrentUser;
  /**
   * Users selectable in the dev role-switcher. With the real API this is just
   * `[user]` (switcher hidden); the mock returns one user per role so the
   * operator/approver/viewer views are all demonstrable.
   */
  availableUsers: CurrentUser[];
}

/** The actor performing a mutation. Sent as headers; enforced server-side. */
export interface Actor {
  id: Id;
  role: Role;
}

export interface ScanMutationResult {
  scan: Scan;
  audit: AuditEvent;
}

export interface FalsePositiveResult {
  scanId: Id;
  findingId: Id;
  /** The finding remains in the report, re-tiered for the FP regression corpus. */
  finding: ConfirmedFinding;
  audit: AuditEvent;
}

export interface ScanDetailBundle {
  scan: Scan;
  appMap: AppMap | null;
  progress: ProgressEvent[];
}

export type { Scan, AuditEvent, Report, AppMap, CostEstimate, Fix, PullRequest, ProgressEvent };
