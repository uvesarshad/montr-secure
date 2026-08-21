import { describe, it, expect } from "vitest";
import { memoryFileProvider } from "@montr/discovery";
import { detectNetworkPolicyGaps } from "./network-policy.js";
import { confirmedFinding } from "../test-helpers.js";

const DEPLOYMENT_YAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: web:latest
`;

describe("detectNetworkPolicyGaps", () => {
  it("produces nothing when there are no SSRF findings", async () => {
    const files = memoryFileProvider([]);
    const drafts = await detectNetworkPolicyGaps(files, [
      confirmedFinding({ category: "sql_injection" }),
    ]);
    expect(drafts).toHaveLength(0);
  });

  it("gives cloud security-group guidance when no K8s manifests exist", async () => {
    const files = memoryFileProvider([{ path: "src/app.ts", content: "// no k8s here" }]);
    const finding = confirmedFinding({ id: "f1", category: "ssrf" });
    const drafts = await detectNetworkPolicyGaps(files, [finding]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.gap).toContain("No Kubernetes manifests");
    expect(drafts[0]?.recommendation).toContain("security-group");
    expect(drafts[0]?.relatedFindingIds).toEqual(["f1"]);
  });

  it("gives a NetworkPolicy YAML snippet when K8s workloads exist with no NetworkPolicy", async () => {
    const files = memoryFileProvider([{ path: "k8s/deployment.yaml", content: DEPLOYMENT_YAML }]);
    const finding = confirmedFinding({ id: "f1", category: "ssrf" });
    const drafts = await detectNetworkPolicyGaps(files, [finding]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.recommendation).toContain("kind: NetworkPolicy");
    expect(drafts[0]?.gap).toContain("no NetworkPolicy at all");
  });

  it("recommends adding a metadata-IP egress rule when a NetworkPolicy exists but doesn't mention it", async () => {
    const netpol = `apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default\nspec:\n  podSelector: {}\n`;
    const files = memoryFileProvider([
      { path: "k8s/deployment.yaml", content: DEPLOYMENT_YAML },
      { path: "k8s/netpol.yaml", content: netpol },
    ]);
    const finding = confirmedFinding({ id: "f1", category: "ssrf" });
    const drafts = await detectNetworkPolicyGaps(files, [finding]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.title).toContain("metadata-IP");
  });

  it("produces NOTHING when a NetworkPolicy already references the metadata IP (precision)", async () => {
    const netpol = `apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default\nspec:\n  podSelector: {}\n  egress:\n    - to:\n        - ipBlock:\n            cidr: 0.0.0.0/0\n            except:\n              - 169.254.169.254/32\n`;
    const files = memoryFileProvider([
      { path: "k8s/deployment.yaml", content: DEPLOYMENT_YAML },
      { path: "k8s/netpol.yaml", content: netpol },
    ]);
    const finding = confirmedFinding({ id: "f1", category: "ssrf" });
    const drafts = await detectNetworkPolicyGaps(files, [finding]);
    expect(drafts).toHaveLength(0);
  });
});
