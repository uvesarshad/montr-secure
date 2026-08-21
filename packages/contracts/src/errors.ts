import { z } from "zod";

/**
 * Typed error taxonomy (§3.2). Runtime error classes + a serializable envelope
 * for crossing the queue/API boundary. No provider SDK — pure TypeScript.
 */

export const ErrorCodeSchema = z.enum([
  "BUDGET_EXCEEDED",
  "EGRESS_BLOCKED",
  "DAST_TARGET_NOT_ALLOWLISTED",
  "GATE_NOT_PASSED",
  "KEY_TIER_REJECTED",
  "MODEL_BELOW_FLOOR",
  "KILL_SWITCH_ACTIVATED",
  "SCAN_NOT_RESUMABLE",
  "CONFIG_VALIDATION",
  "PROVIDER_NOT_CONFIGURED",
  "HUMAN_APPROVAL_REQUIRED",
  "RATE_LIMIT_EXCEEDED",
  "NOT_IMPLEMENTED",
  "REQUIRED_DETECTOR_UNAVAILABLE",
  "INTERNAL",
]);
export type ErrorCode = z.infer<typeof ErrorCodeSchema>;

/** Serialized error shape passed across process/queue boundaries. */
export const ErrorEnvelopeSchema = z.object({
  code: ErrorCodeSchema,
  message: z.string(),
  retriable: z.boolean().default(false),
  details: z.record(z.string(), z.unknown()).optional(),
});
export type ErrorEnvelope = z.infer<typeof ErrorEnvelopeSchema>;

export interface MontrErrorOptions {
  retriable?: boolean;
  details?: Record<string, unknown>;
  cause?: unknown;
}

/** Base class for all typed Montr Secure errors. */
export class MontrError extends Error {
  readonly code: ErrorCode;
  readonly retriable: boolean;
  readonly details?: Record<string, unknown>;

  constructor(code: ErrorCode, message: string, opts: MontrErrorOptions = {}) {
    super(message, opts.cause !== undefined ? { cause: opts.cause } : undefined);
    this.name = new.target.name;
    this.code = code;
    this.retriable = opts.retriable ?? false;
    this.details = opts.details;
    // Preserve instanceof across the ES target down-level.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toEnvelope(): ErrorEnvelope {
    return {
      code: this.code,
      message: this.message,
      retriable: this.retriable,
      ...(this.details ? { details: this.details } : {}),
    };
  }
}

export function isMontrError(err: unknown): err is MontrError {
  return err instanceof MontrError;
}

/** ⛔ Budget ceiling exceeded — hard halt + partial report (DECIDE-4). */
export class BudgetExceededError extends MontrError {
  constructor(message = "Budget ceiling exceeded", details?: Record<string, unknown>) {
    super("BUDGET_EXCEEDED", message, { retriable: false, details });
  }
}

/** ⛔ An attempt to send client code anywhere but the client's own LLM key. */
export class EgressBlockedError extends MontrError {
  constructor(message = "Code egress blocked", details?: Record<string, unknown>) {
    super("EGRESS_BLOCKED", message, { retriable: false, details });
  }
}

/** ⛔ Live DAST target is not on the allowlist / is production. */
export class DastTargetNotAllowlistedError extends MontrError {
  constructor(message = "DAST target not allowlisted", details?: Record<string, unknown>) {
    super("DAST_TARGET_NOT_ALLOWLISTED", message, { retriable: false, details });
  }
}

/** ⛔ A code change was attempted without passing the gate. */
export class GateNotPassedError extends MontrError {
  constructor(message = "Pipeline gate not passed", details?: Record<string, unknown>) {
    super("GATE_NOT_PASSED", message, { retriable: false, details });
  }
}

/** ⛔ Suspected data-retaining (non-enterprise) key tier rejected by policy. */
export class KeyTierRejectedError extends MontrError {
  constructor(message = "LLM key tier rejected by policy", details?: Record<string, unknown>) {
    super("KEY_TIER_REJECTED", message, { retriable: false, details });
  }
}

/** Configured model is below the confirmation floor (DECIDE-3). */
export class ModelBelowFloorError extends MontrError {
  constructor(message = "Model below confirmation floor", details?: Record<string, unknown>) {
    super("MODEL_BELOW_FLOOR", message, { retriable: false, details });
  }
}

/** ⛔ Kill switch activated — all active work (esp. DAST) must stop. */
export class KillSwitchActivatedError extends MontrError {
  constructor(message = "Kill switch activated", details?: Record<string, unknown>) {
    super("KILL_SWITCH_ACTIVATED", message, { retriable: false, details });
  }
}

/** A scan could not be resumed from its persisted state. */
export class ScanNotResumableError extends MontrError {
  constructor(message = "Scan is not resumable", details?: Record<string, unknown>) {
    super("SCAN_NOT_RESUMABLE", message, { retriable: false, details });
  }
}

/** Configuration failed validation — fatal and explicit. */
export class ConfigValidationError extends MontrError {
  constructor(message = "Configuration validation failed", details?: Record<string, unknown>) {
    super("CONFIG_VALIDATION", message, { retriable: false, details });
  }
}

/** No LLM provider/endpoint/key configured. */
export class ProviderNotConfiguredError extends MontrError {
  constructor(message = "LLM provider not configured", details?: Record<string, unknown>) {
    super("PROVIDER_NOT_CONFIGURED", message, { retriable: false, details });
  }
}

/** Uncertainty resolved toward human review (golden rule #4). */
export class HumanApprovalRequiredError extends MontrError {
  constructor(message = "Human approval required", details?: Record<string, unknown>) {
    super("HUMAN_APPROVAL_REQUIRED", message, { retriable: false, details });
  }
}

/** Rate/blast-radius cap hit (retriable). */
export class RateLimitExceededError extends MontrError {
  constructor(message = "Rate limit exceeded", details?: Record<string, unknown>) {
    super("RATE_LIMIT_EXCEEDED", message, { retriable: true, details });
  }
}

/** Wave 0 stub marker — thrown by not-yet-implemented package internals. */
export class NotImplementedError extends MontrError {
  constructor(what = "Not implemented", details?: Record<string, unknown>) {
    super("NOT_IMPLEMENTED", what, { retriable: false, details });
  }
}

/**
 * ⛔ A REQUIRED detector (e.g. SAST/Semgrep) could not run at all — binary
 * missing, execution error, or a configured local ruleset source that is
 * absent/empty (air-gap `discovery.rulesetsDir`, A4). Layer 1 must NEVER
 * complete successfully on an empty scan and have it look clean: this error
 * propagates out of the layer runner and fails the scan (see
 * `packages/orchestrator/src/controller.ts` `failScan`), rather than being
 * swallowed into a warning + `[]`.
 */
export class RequiredDetectorUnavailableError extends MontrError {
  constructor(message = "Required detector unavailable", details?: Record<string, unknown>) {
    super("REQUIRED_DETECTOR_UNAVAILABLE", message, { retriable: false, details });
  }
}
