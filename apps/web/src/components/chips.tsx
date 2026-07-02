import * as React from "react";
import type {
  Severity,
  GateState,
  ScanStatus,
  FixStatus,
  PullRequestStatus,
  RiskClass,
  Exposure,
  ProofType,
} from "@montr/contracts";
import { Badge } from "./ui/badge.js";
import { DotIcon } from "./icons.js";
import { cn } from "../lib/utils.js";
import {
  SEVERITY_CHIP,
  SEVERITY_LABEL,
  GATE_LABEL,
  SCAN_STATUS_LABEL,
  FIX_STATUS_LABEL,
  PR_STATUS_LABEL,
  RISK_CLASS_LABEL,
  gateStateTone,
  scanStatusTone,
  toneClasses,
  type Tone,
} from "../lib/format.js";

export function StatusChip({
  tone,
  children,
  className,
}: {
  tone: Tone;
  children: React.ReactNode;
  className?: string;
}) {
  return <Badge className={cn(toneClasses(tone), className)}>{children}</Badge>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge className={cn(SEVERITY_CHIP[severity], "uppercase tracking-wide")}>
      <DotIcon className="h-2.5 w-2.5" />
      {SEVERITY_LABEL[severity]}
    </Badge>
  );
}

export function GateBadge({ gate }: { gate: GateState }) {
  return <StatusChip tone={gateStateTone(gate)}>{GATE_LABEL[gate]}</StatusChip>;
}

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return <StatusChip tone={scanStatusTone(status)}>{SCAN_STATUS_LABEL[status]}</StatusChip>;
}

export function RiskBadge({ riskClass }: { riskClass: RiskClass }) {
  const tone: Tone = riskClass === "human-required" ? "warning" : "success";
  return <StatusChip tone={tone}>{RISK_CLASS_LABEL[riskClass]}</StatusChip>;
}

const FIX_TONE: Record<FixStatus, Tone> = {
  proposed: "neutral",
  "pr-open": "info",
  merged: "success",
  rejected: "danger",
};

export function FixStatusBadge({ status }: { status: FixStatus }) {
  return <StatusChip tone={FIX_TONE[status]}>{FIX_STATUS_LABEL[status]}</StatusChip>;
}

const PR_TONE: Record<PullRequestStatus, Tone> = {
  draft: "neutral",
  open: "info",
  merged: "success",
  closed: "danger",
};

export function PrStatusBadge({ status }: { status: PullRequestStatus }) {
  return <StatusChip tone={PR_TONE[status]}>{PR_STATUS_LABEL[status]}</StatusChip>;
}

export function ExposureBadge({ exposure }: { exposure: Exposure }) {
  const tone: Tone = exposure === "public" ? "danger" : "info";
  return <StatusChip tone={tone}>{exposure === "public" ? "Public" : "Authenticated"}</StatusChip>;
}

export function ProofBadge({ proofType }: { proofType: ProofType }) {
  const tone: Tone = proofType === "live" ? "warning" : "info";
  return (
    <StatusChip tone={tone}>{proofType === "live" ? "Live DAST proof" : "Static proof"}</StatusChip>
  );
}
