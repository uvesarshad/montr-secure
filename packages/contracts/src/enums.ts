import { z } from "zod";

/**
 * Canonical enums for the pipeline. String values are the single source of
 * truth — the Prisma schema mirrors these exact strings (via @map where an
 * enum value is not a valid Prisma identifier, e.g. "auto-eligible").
 */

/** Full scan vs. changed-files-only diff scan. */
export const ScanModeSchema = z.enum(["full", "diff"]);
export type ScanMode = z.infer<typeof ScanModeSchema>;

/** Coarse exposure of a confirmed finding. */
export const ExposureSchema = z.enum(["public", "authed"]);
export type Exposure = z.infer<typeof ExposureSchema>;

/** How a finding was confirmed. */
export const ProofTypeSchema = z.enum(["static", "live"]);
export type ProofType = z.infer<typeof ProofTypeSchema>;

/**
 * Safety classification of a fix. `human-required` is a HARD rule for
 * auth/session/crypto/access-control or wide blast radius (§11, golden rule #3).
 */
export const RiskClassSchema = z.enum(["auto-eligible", "human-required"]);
export type RiskClass = z.infer<typeof RiskClassSchema>;

/** Lifecycle of a proposed fix. */
export const FixStatusSchema = z.enum(["proposed", "pr-open", "merged", "rejected"]);
export type FixStatus = z.infer<typeof FixStatusSchema>;

/** Tier a finding currently sits in. */
export const FindingStatusSchema = z.enum(["candidate", "probable", "confirmed", "unconfirmed"]);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

/** Severity scale (final severity is set at confirmation). */
export const SeveritySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof SeveritySchema>;

/** RBAC roles (§10). Approver is required for the human gate and DAST authorization. */
export const RoleSchema = z.enum(["operator", "approver", "viewer"]);
export type Role = z.infer<typeof RoleSchema>;

/**
 * The human/auto gate is an explicit PIPELINE STATE, not a config flag
 * (golden rule #5, §6.2). Drives whether code changes may proceed.
 */
export const GateStateSchema = z.enum([
  "not_started",
  "estimate_pending", // cost estimate awaiting operator/approver acknowledgement
  "estimate_approved",
  "running",
  "fix_gate_pending", // fixes generated, awaiting auto-eligible bar OR approver
  "auto_approved", // passed the auto-eligible bar
  "approved", // explicit human approval
  "rejected",
  "blocked", // budget hard-halt / kill switch / policy stop
]);
export type GateState = z.infer<typeof GateStateSchema>;

/** Execution status of a scan (distinct from the gate state). */
export const ScanStatusSchema = z.enum([
  "queued",
  "running",
  "paused",
  "completed",
  "failed",
  "cancelled",
  "partial", // partial report emitted (e.g. budget hard-halt)
]);
export type ScanStatus = z.infer<typeof ScanStatusSchema>;

/** Pipeline layers L0..L5. */
export const LayerIdSchema = z.enum(["layer0", "layer1", "layer2", "layer3", "layer4", "layer5"]);
export type LayerId = z.infer<typeof LayerIdSchema>;

/** HTTP methods for registered routes. */
export const HttpMethodSchema = z.enum([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "HEAD",
  "ALL",
]);
export type HttpMethod = z.infer<typeof HttpMethodSchema>;

/** Auth state gating a route (route-level; finer than Exposure). */
export const AuthStateSchema = z.enum(["public", "authenticated", "role_gated", "unknown"]);
export type AuthState = z.infer<typeof AuthStateSchema>;

/** Detected languages (Phase 1 is Node/TS-first; more added in Phase 3). */
export const LanguageSchema = z.enum([
  "typescript",
  "javascript",
  "python",
  "java",
  "go",
  "ruby",
  "php",
  "csharp",
  "other",
]);
export type Language = z.infer<typeof LanguageSchema>;

/** Detected frameworks. */
export const FrameworkSchema = z.enum([
  "nextjs",
  "react",
  "express",
  "fastify",
  "node",
  "prisma",
  "django",
  "fastapi",
  "flask",
  "spring",
  "other",
]);
export type Framework = z.infer<typeof FrameworkSchema>;

/** The deterministic tool (or LLM triage) that produced a candidate finding. */
export const ToolSourceSchema = z.enum([
  "semgrep",
  "gitleaks",
  "osv",
  "ghsa",
  "trivy",
  "custom",
  "llm-triage",
]);
export type ToolSource = z.infer<typeof ToolSourceSchema>;

/** Where tainted input can enter the app. */
export const TaintSourceKindSchema = z.enum([
  "http_request",
  "query_param",
  "path_param",
  "request_body",
  "request_header",
  "cookie",
  "env",
  "file_read",
  "cli_arg",
  "websocket",
  "third_party_response",
]);
export type TaintSourceKind = z.infer<typeof TaintSourceKindSchema>;

/** Dangerous operations tainted input can reach. */
export const TaintSinkKindSchema = z.enum([
  "sql_query",
  "orm_raw_query",
  "command_exec",
  "fs_write",
  "fs_read",
  "http_response",
  "template_render",
  "html_render",
  "redirect",
  "eval",
  "deserialize",
  "logger",
  "http_client",
  "crypto",
]);
export type TaintSinkKind = z.infer<typeof TaintSinkKindSchema>;
