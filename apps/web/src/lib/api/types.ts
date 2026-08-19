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
   * `[user]` (switcher hidden — GET /auth/me returns only the caller); the
   * MSW mock returns one user per role so the operator/approver/viewer views
   * are all demonstrable.
   */
  availableUsers: CurrentUser[];
}

/** The raw shape `GET /auth/me` (real) or the MSW mock returns before the
 * client derives a `CurrentUser` — the real API's `AuthenticatedUser` has no
 * `name` field, so the client synthesizes one from the email local-part. */
export interface RawSessionUser {
  id: Id;
  email: string;
  role: Role;
  name?: string;
}

/**
 * The current, authenticated actor — identity/role read from the verified
 * session (JWT cookie), NOT a client-supplied header. Used for client-side UI
 * gating only; the real API independently re-derives + enforces the actor
 * from the session on every request (never trusts the client).
 */
export interface Actor {
  id: Id;
  role: Role;
}

/** `POST /scans/:id/estimate/approve` and `.../gate/approve` return `{ scan }`
 * only — no echoed audit event. `audit` stays optional so the (richer) MSW
 * mock response, which does include one, still type-checks. */
export interface ScanMutationResult {
  scan: Scan;
  audit?: AuditEvent;
}

/** `POST /findings/:id/false-positive` returns `{ ok, findingId }` for real;
 * `finding`/`audit`/`scanId` are optional so the (richer) MSW mock response
 * still type-checks. */
export interface FalsePositiveResult {
  ok?: boolean;
  scanId?: Id;
  findingId: Id;
  /** The finding remains in the report, re-tiered for the FP regression corpus. */
  finding?: ConfirmedFinding;
  audit?: AuditEvent;
}

export interface ScanDetailBundle {
  scan: Scan;
  appMap: AppMap | null;
  progress: ProgressEvent[];
}

export type { Scan, AuditEvent, Report, AppMap, CostEstimate, Fix, PullRequest, ProgressEvent };
