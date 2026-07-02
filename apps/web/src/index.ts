/**
 * apps/web — Next.js 14 (App Router) operator console + report UI.
 *
 * Wave 0 placeholder: this stub keeps the workspace type-consistent. WS-K
 * converts it into a real Next.js app (Tailwind + shadcn/ui, RBAC-aware nav,
 * API client typed from @montr/contracts, MSW mocks). Keeping it a plain TS
 * package for now avoids pulling the Next toolchain into the Wave 0 barrier.
 */
import type { Role } from "@montr/contracts";

export const WEB_APP_NAME = "montr-secure-web" as const;

/** Nav sections gated by RBAC role — the shape WS-K will render. */
export const NAV_SECTIONS: ReadonlyArray<{ id: string; label: string; roles: Role[] }> = [
  { id: "scans", label: "Scans", roles: ["operator", "approver", "viewer"] },
  { id: "cost-approval", label: "Cost Approval", roles: ["operator", "approver"] },
  { id: "report", label: "Report", roles: ["operator", "approver", "viewer"] },
  { id: "dast-authorization", label: "DAST Authorization", roles: ["approver"] },
  { id: "pull-requests", label: "Pull Requests", roles: ["operator", "approver"] },
  { id: "audit-log", label: "Audit Log", roles: ["approver", "viewer"] },
];
