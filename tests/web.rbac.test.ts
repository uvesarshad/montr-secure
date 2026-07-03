import { describe, it, expect } from "vitest";
import type { Role } from "@montr/contracts";
import {
  canCreateScan,
  canApproveEstimate,
  canApproveFixGate,
  canAuthorizeDast,
  canMarkFalsePositive,
  canActivateKillSwitch,
  canAccess,
  navForRole,
  ALL_ROLES,
} from "../apps/web/src/lib/rbac";

/**
 * RBAC capability + nav gating (§10, §11, golden rules #3/#5). The console must
 * enforce that the human fix-gate and DAST authorization are approver-only, and
 * that viewers are strictly read-only — uncertainty resolves toward LESS autonomy.
 */

describe("approver-only safety gates (§11, golden rule #3)", () => {
  it("only approver may clear the fix gate", () => {
    expect(canApproveFixGate("approver")).toBe(true);
    expect(canApproveFixGate("operator")).toBe(false);
    expect(canApproveFixGate("viewer")).toBe(false);
  });

  it("only approver may authorize live DAST", () => {
    expect(canAuthorizeDast("approver")).toBe(true);
    expect(canAuthorizeDast("operator")).toBe(false);
    expect(canAuthorizeDast("viewer")).toBe(false);
  });
});

describe("operator + approver capabilities (viewer read-only)", () => {
  const operatorAndApprover: Role[] = ["operator", "approver"];
  it("estimate approval, FP-marking, kill switch, scan creation are non-viewer", () => {
    for (const role of ALL_ROLES) {
      const expected = operatorAndApprover.includes(role);
      expect(canApproveEstimate(role)).toBe(expected);
      expect(canMarkFalsePositive(role)).toBe(expected);
      expect(canActivateKillSwitch(role)).toBe(expected);
      expect(canCreateScan(role)).toBe(expected);
    }
  });

  it("viewer cannot perform any mutating action", () => {
    expect(canApproveEstimate("viewer")).toBe(false);
    expect(canApproveFixGate("viewer")).toBe(false);
    expect(canAuthorizeDast("viewer")).toBe(false);
    expect(canMarkFalsePositive("viewer")).toBe(false);
    expect(canActivateKillSwitch("viewer")).toBe(false);
    expect(canCreateScan("viewer")).toBe(false);
  });
});

describe("role-gated navigation", () => {
  it("DAST authorization appears only for approvers", () => {
    const has = (role: Role) => navForRole(role).some((n) => n.id === "dast-authorization");
    expect(has("approver")).toBe(true);
    expect(has("operator")).toBe(false);
    expect(has("viewer")).toBe(false);
  });

  it("dashboard, scans, pull-requests and audit are visible to every role", () => {
    for (const role of ALL_ROLES) {
      const ids = navForRole(role).map((n) => n.id);
      expect(ids).toEqual(
        expect.arrayContaining(["dashboard", "scans", "pull-requests", "audit-log"]),
      );
    }
  });

  it("canAccess respects the allow-list", () => {
    expect(canAccess("approver", ["approver"])).toBe(true);
    expect(canAccess("operator", ["approver"])).toBe(false);
  });
});
