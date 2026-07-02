import type {
  Severity,
  GateState,
  ScanStatus,
  FixStatus,
  PullRequestStatus,
  RiskClass,
} from "@montr/contracts";

/** Highest → lowest, for sorting confirmed findings by severity. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Tailwind classes for a severity chip (tokens defined in globals.css). */
export const SEVERITY_CHIP: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/15 text-sev-high border-sev-high/30",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  low: "bg-sev-low/15 text-sev-low border-sev-low/30",
  info: "bg-sev-info/15 text-sev-info border-sev-info/30",
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[b] - SEVERITY_ORDER[a];
}

export const GATE_LABEL: Record<GateState, string> = {
  not_started: "Not started",
  estimate_pending: "Estimate pending",
  estimate_approved: "Estimate approved",
  running: "Running",
  fix_gate_pending: "Fix gate pending",
  auto_approved: "Auto-approved",
  approved: "Approved",
  rejected: "Rejected",
  blocked: "Blocked",
};

export const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  queued: "Queued",
  running: "Running",
  paused: "Paused",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
  partial: "Partial",
};

/** Semantic tone for status/gate chips. */
export type Tone = "neutral" | "info" | "success" | "warning" | "danger";

export function scanStatusTone(status: ScanStatus): Tone {
  switch (status) {
    case "completed":
      return "success";
    case "running":
    case "queued":
      return "info";
    case "paused":
      return "warning";
    case "partial":
      return "warning";
    case "failed":
    case "cancelled":
      return "danger";
    default:
      return "neutral";
  }
}

export function gateStateTone(gate: GateState): Tone {
  switch (gate) {
    case "approved":
    case "auto_approved":
    case "estimate_approved":
      return "success";
    case "estimate_pending":
    case "fix_gate_pending":
      return "warning";
    case "running":
      return "info";
    case "rejected":
    case "blocked":
      return "danger";
    default:
      return "neutral";
  }
}

export const FIX_STATUS_LABEL: Record<FixStatus, string> = {
  proposed: "Proposed",
  "pr-open": "PR open",
  merged: "Merged",
  rejected: "Rejected",
};

export const PR_STATUS_LABEL: Record<PullRequestStatus, string> = {
  draft: "Draft",
  open: "Open",
  merged: "Merged",
  closed: "Closed",
};

export const RISK_CLASS_LABEL: Record<RiskClass, string> = {
  "auto-eligible": "Auto-eligible",
  "human-required": "Human-required",
};

export function toneClasses(tone: Tone): string {
  switch (tone) {
    case "success":
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
    case "info":
      return "bg-sky-500/15 text-sky-300 border-sky-500/30";
    case "warning":
      return "bg-amber-500/15 text-amber-300 border-amber-500/30";
    case "danger":
      return "bg-red-500/15 text-red-300 border-red-500/30";
    default:
      return "bg-secondary text-secondary-foreground border-border";
  }
}

export function formatUsd(usd: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: usd < 1 ? 4 : 2,
    maximumFractionDigits: usd < 1 ? 4 : 2,
  }).format(usd);
}

export function formatTokens(tokens: number): string {
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(
    tokens,
  );
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat("en-US").format(n);
}

/** e.g. -0.09 -> "-9.0%". */
export function formatPercent(fraction: number, digits = 1): string {
  const sign = fraction > 0 ? "+" : "";
  return `${sign}${(fraction * 100).toFixed(digits)}%`;
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return s === 0 ? `${m}m` : `${m}m ${s}s`;
}

/** Short id for display, e.g. scan_fixture_0001 -> …e_0001. */
export function shortId(id: string, tail = 8): string {
  return id.length <= tail ? id : `…${id.slice(-tail)}`;
}
