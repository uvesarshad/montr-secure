import { ScanSchema, type Scan } from "@montr/contracts";
import {
  SCAN_ID,
  CLIENT_ID,
  APPMAP_ID,
  COMMIT_SHA,
  REPO_URL,
  BRANCH,
  OPERATOR_ID,
  APPROVER_ID,
  FIXED_NOW,
} from "./ids.js";
import { mockCostEstimate, mockCostActual } from "./cost.js";

export const mockScan: Scan = ScanSchema.parse({
  id: SCAN_ID,
  clientId: CLIENT_ID,
  appMapId: APPMAP_ID,
  repo: REPO_URL,
  branch: BRANCH,
  commitSha: COMMIT_SHA,
  mode: "full",
  scope: {
    mode: "full",
    includePaths: ["app/", "lib/", "prisma/"],
    routeCount: 2,
    fileCount: 6,
  },
  status: "completed",
  gateState: "approved",
  operator: OPERATOR_ID,
  approver: APPROVER_ID,
  budgetPolicy: { enforcement: "hard_halt", requireEstimateApproval: true, maxUsd: 5 },
  costEstimate: mockCostEstimate,
  costActual: mockCostActual,
  startedAt: FIXED_NOW,
  finishedAt: "2026-01-15T10:03:00.000Z",
  createdAt: FIXED_NOW,
});
