import { http, HttpResponse, type PathParams } from "msw";
import type { ErrorEnvelope, ExportArtifact, ExportFormat, Role } from "@montr/contracts";
import { routePatterns, ACTOR_ID_HEADER, ACTOR_ROLE_HEADER } from "../lib/api/config.js";
import type { Actor } from "../lib/api/types.js";
import { db } from "./data.js";

/**
 * MSW request handlers — the mock API. Mirrors the contract-typed endpoints in
 * lib/api/config.ts so the console is fully navigable before apps/api is wired.
 * RBAC is ALSO enforced here (defense in depth): approver-only gates reject other
 * roles with 403, matching the client-side guards (§10, §11).
 */

function str(v: PathParams[string]): string {
  return Array.isArray(v) ? (v[0] ?? "") : ((v as string | undefined) ?? "");
}

function getActor(request: Request): Actor | null {
  const id = request.headers.get(ACTOR_ID_HEADER);
  const role = request.headers.get(ACTOR_ROLE_HEADER);
  if (!id || (role !== "operator" && role !== "approver" && role !== "viewer")) return null;
  return { id, role };
}

function toAuditActor(actor: Actor): { type: "user"; id: string; role: Role } {
  return { type: "user", id: actor.id, role: actor.role };
}

function error(
  status: number,
  code: ErrorEnvelope["code"],
  message: string,
): HttpResponse<ErrorEnvelope> {
  const body: ErrorEnvelope = { code, message, retriable: false };
  return HttpResponse.json(body, { status });
}

function notFound(what: string): HttpResponse<ErrorEnvelope> {
  return error(404, "INTERNAL", `${what} not found`);
}

async function readReason(request: Request): Promise<string> {
  try {
    const body = (await request.json()) as { reason?: string; stagingUrl?: string } | null;
    return body?.reason ?? "";
  } catch {
    return "";
  }
}

export const handlers = [
  /* ------------------------------- session ------------------------------- */
  http.get(routePatterns.me, () =>
    HttpResponse.json({
      user: db.users.operator,
      availableUsers: [db.users.operator, db.users.approver, db.users.viewer],
    }),
  ),

  /* -------------------------------- reads -------------------------------- */
  http.get(routePatterns.scans, () => HttpResponse.json(db.listScans())),

  http.get(routePatterns.scan, ({ params }) => {
    const scan = db.getScan(str(params.scanId));
    return scan ? HttpResponse.json(scan) : notFound("Scan");
  }),

  http.get(routePatterns.progress, ({ params }) =>
    HttpResponse.json(db.getProgress(str(params.scanId))),
  ),

  http.get(routePatterns.appMap, ({ params }) => {
    const appMap = db.getAppMap(str(params.scanId));
    return appMap ? HttpResponse.json(appMap) : notFound("App Map");
  }),

  http.get(routePatterns.estimate, ({ params }) => {
    const est = db.getEstimate(str(params.scanId));
    return est ? HttpResponse.json(est) : notFound("Cost estimate");
  }),

  http.get(routePatterns.report, ({ params }) => {
    const report = db.getReport(str(params.scanId));
    return report
      ? HttpResponse.json(report)
      : error(409, "GATE_NOT_PASSED", "Report is not available until the scan completes.");
  }),

  http.get(routePatterns.fixes, ({ params }) => HttpResponse.json(db.getFixes(str(params.scanId)))),

  http.get(routePatterns.scanPullRequests, ({ params }) =>
    HttpResponse.json(db.getScanPullRequests(str(params.scanId))),
  ),

  http.get(routePatterns.pullRequests, () => HttpResponse.json(db.listPullRequests())),

  http.get(routePatterns.audit, ({ request }) => {
    const url = new URL(request.url);
    const scanId = url.searchParams.get("scanId") ?? undefined;
    return HttpResponse.json(db.listAudit(scanId));
  }),

  /* ------------------------------ mutations ------------------------------ */

  http.post(routePatterns.approveEstimate, ({ request, params }) => {
    const actor = getActor(request);
    if (!actor || (actor.role !== "operator" && actor.role !== "approver")) {
      return error(
        403,
        "HUMAN_APPROVAL_REQUIRED",
        "Operator or approver role required to approve the estimate.",
      );
    }
    const result = db.approveEstimate(str(params.scanId), toAuditActor(actor));
    return result ? HttpResponse.json(result) : notFound("Scan");
  }),

  http.post(routePatterns.approveFixGate, ({ request, params }) => {
    const actor = getActor(request);
    if (!actor || actor.role !== "approver") {
      return error(
        403,
        "HUMAN_APPROVAL_REQUIRED",
        "Approver role required to clear the fix gate (§11).",
      );
    }
    const result = db.approveFixGate(str(params.scanId), toAuditActor(actor));
    return result ? HttpResponse.json(result) : notFound("Scan");
  }),

  http.post(routePatterns.authorizeDast, async ({ request, params }) => {
    const actor = getActor(request);
    if (!actor || actor.role !== "approver") {
      return error(
        403,
        "HUMAN_APPROVAL_REQUIRED",
        "Approver role required to authorize live DAST (§11).",
      );
    }
    let stagingUrl = "";
    try {
      const body = (await request.json()) as { stagingUrl?: string } | null;
      stagingUrl = body?.stagingUrl ?? "";
    } catch {
      stagingUrl = "";
    }
    if (!stagingUrl) {
      return error(
        400,
        "DAST_TARGET_NOT_ALLOWLISTED",
        "A staging target URL is required; production is blocked by policy.",
      );
    }
    const result = db.authorizeDast(str(params.scanId), toAuditActor(actor), stagingUrl);
    return result ? HttpResponse.json(result) : notFound("Scan");
  }),

  http.post(routePatterns.killSwitch, async ({ request, params }) => {
    const actor = getActor(request);
    if (!actor || actor.role === "viewer") {
      return error(
        403,
        "KILL_SWITCH_ACTIVATED",
        "Operator or approver role required to activate the kill switch.",
      );
    }
    const reason = (await readReason(request)) || "manual kill switch";
    const result = db.killSwitch(str(params.scanId), toAuditActor(actor), reason);
    return result ? HttpResponse.json(result) : notFound("Scan");
  }),

  http.post(routePatterns.markFalsePositive, async ({ request, params }) => {
    const actor = getActor(request);
    if (!actor || actor.role === "viewer") {
      return error(
        403,
        "HUMAN_APPROVAL_REQUIRED",
        "Operator or approver role required to mark a finding as false positive.",
      );
    }
    const reason = (await readReason(request)) || "operator judgement";
    const result = db.markFalsePositive(
      str(params.scanId),
      str(params.findingId),
      toAuditActor(actor),
      reason,
    );
    return result ? HttpResponse.json(result) : notFound("Finding");
  }),

  http.post(routePatterns.export, ({ request, params }) => {
    const actor = getActor(request);
    if (!actor) return error(403, "INTERNAL", "Authentication required.");
    const url = new URL(request.url);
    const format = (url.searchParams.get("format") ?? "sarif") as ExportFormat;
    const scanId = str(params.scanId);
    const artifact: ExportArtifact = {
      scanId,
      format,
      filename: `montr-secure-${scanId}.${format === "pdf" ? "pdf" : "json"}`,
      contentType: format === "pdf" ? "application/pdf" : "application/json",
      sizeBytes: 20_480,
      uri: `/exports/${scanId}.${format}`,
      generatedAt: new Date().toISOString(),
    };
    return HttpResponse.json(artifact);
  }),
];
