import type { Role, Id } from "@montr/contracts";

/**
 * RBAC (PRD §10). Roles: operator, approver, viewer.
 * Golden rules #3/#5 & §11: the human gate (fix approval) AND DAST authorization
 * are approver-only; uncertainty resolves toward *less* autonomy, so viewers are
 * strictly read-only and mutating actions are explicitly allow-listed by role.
 */

/** The signed-in principal. `User` is persisted by @montr/state-store; the web
 * app only needs identity + role, so this is a deliberately small view type. */
export interface CurrentUser {
  id: Id;
  email: string;
  name: string;
  role: Role;
}

export const ROLE_LABEL: Record<Role, string> = {
  operator: "Operator",
  approver: "Approver",
  viewer: "Viewer",
};

export const ROLE_DESCRIPTION: Record<Role, string> = {
  operator: "Runs scans, reviews reports, triages findings (mark false positive).",
  approver: "Everything an operator can do, plus clears the human gate and authorizes live DAST.",
  viewer: "Read-only access to scans, reports, and the audit log.",
};

export type IconKey =
  | "dashboard"
  | "scans"
  | "pull-requests"
  | "dast"
  | "audit"
  | "report"
  | "estimate"
  | "overview"
  | "fixes"
  // Phase-4 (Wave 5) — scale & intelligence.
  | "dashboards"
  | "rules"
  | "scenarios"
  | "schedules";

export interface NavItem {
  id: string;
  label: string;
  href: string;
  icon: IconKey;
  roles: readonly Role[];
}

/** Top-level sidebar navigation, gated by role. */
export const NAV_SECTIONS: readonly NavItem[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    href: "/",
    icon: "dashboard",
    roles: ["operator", "approver", "viewer"],
  },
  {
    id: "scans",
    label: "Scans",
    href: "/scans",
    icon: "scans",
    roles: ["operator", "approver", "viewer"],
  },
  {
    id: "pull-requests",
    label: "Pull Requests",
    href: "/pull-requests",
    icon: "pull-requests",
    roles: ["operator", "approver", "viewer"],
  },
  {
    id: "dashboards",
    label: "Dashboards",
    href: "/dashboards",
    icon: "dashboards",
    roles: ["operator", "approver", "viewer"],
  },
  {
    id: "dast-authorization",
    label: "DAST Authorization",
    href: "/dast",
    icon: "dast",
    roles: ["approver"],
  },
  // ⛔ Red-team scenarios are the most sensitive Phase-4 surface (attack
  // playbooks bound to live targets) — approver-only, mirroring DAST auth.
  {
    id: "red-team",
    label: "Red-Team Scenarios",
    href: "/scenarios",
    icon: "scenarios",
    roles: ["approver"],
  },
  {
    id: "custom-rules",
    label: "Custom Rules",
    href: "/rules",
    icon: "rules",
    roles: ["operator", "approver"],
  },
  {
    id: "scan-schedules",
    label: "Schedules",
    href: "/schedules",
    icon: "schedules",
    roles: ["operator", "approver"],
  },
  {
    id: "audit-log",
    label: "Audit Log",
    href: "/audit",
    icon: "audit",
    roles: ["operator", "approver", "viewer"],
  },
];

export function canAccess(role: Role, roles: readonly Role[]): boolean {
  return roles.includes(role);
}

export function navForRole(role: Role): NavItem[] {
  return NAV_SECTIONS.filter((item) => canAccess(role, item.roles));
}

/* --------------------------------- capabilities --------------------------------- */

export function canCreateScan(role: Role): boolean {
  return role === "operator" || role === "approver";
}

/** Estimate acknowledgement gate — operator OR approver (BudgetPolicy §8.4). */
export function canApproveEstimate(role: Role): boolean {
  return role === "operator" || role === "approver";
}

/** ⛔ The human fix-gate is approver-only (§10, §11, golden rule #3). */
export function canApproveFixGate(role: Role): boolean {
  return role === "approver";
}

/** ⛔ Live DAST authorization is approver-only (§10, §11). */
export function canAuthorizeDast(role: Role): boolean {
  return role === "approver";
}

/** FP feedback loop (§15) — operators/approvers triage; viewers cannot mutate. */
export function canMarkFalsePositive(role: Role): boolean {
  return role === "operator" || role === "approver";
}

/** ⛔ Kill switch is operational — any non-viewer may halt active work (§11). */
export function canActivateKillSwitch(role: Role): boolean {
  return role === "operator" || role === "approver";
}

/* ----------------------- Phase-4 (Wave 5) capabilities ----------------------- */

/** Author/edit custom detection rules — operator or approver (§16). */
export function canAuthorRules(role: Role): boolean {
  return role === "operator" || role === "approver";
}

/** Create/edit scheduled scans — operator or approver (§16). */
export function canManageSchedules(role: Role): boolean {
  return role === "operator" || role === "approver";
}

/**
 * ⛔ Run a red-team scenario against a live (allowlisted) target — approver-only,
 * exactly like live-DAST authorization (§11, golden rule #3).
 */
export function canRunRedTeam(role: Role): boolean {
  return role === "approver";
}

export const ALL_ROLES: readonly Role[] = ["operator", "approver", "viewer"];
