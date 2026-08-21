/**
 * E16 — IaC agent (Dockerfile/Kubernetes/Terraform) real-fixture tests.
 *
 * Exercises `detectIac` end to end against real files on disk via
 * `fsFileProvider` (not in-memory strings), reading the vulnerable/clean
 * fixture pair under `packages/fixtures/sample-repos/iac-samples/` — the same
 * "real files, not hand-typed strings" discipline
 * `secrets.real-output.test.ts` uses for gitleaks output. No `semgrep`
 * runner is injected, so the optional Semgrep IaC pass gracefully degrades
 * (binary very likely absent in CI) and every assertion below is entirely
 * attributable to the structural detectors.
 */
import nodePath from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { getHardenedDefaults } from "@montr/config";
import { createNullLogger } from "@montr/telemetry";
import { AppMapSchema, type ScanScope } from "@montr/contracts";
import { detectIac } from "./iac.js";
import type { DetectorContext } from "../types.js";
import { fsFileProvider, emptyFileProvider } from "../util/files.js";

const FULL_SCOPE: ScanScope = {
  mode: "full",
  includePaths: [],
  excludePaths: [],
  changedFiles: [],
  reachableFromChanges: false,
};

const minimalAppMap = AppMapSchema.parse({
  id: "appmap_test_0001",
  clientId: "client_test_0001",
  repo: "https://example.test/repo.git",
  branch: "main",
  commitSha: "0000000000000000000000000000000000000a",
  createdAt: "2026-01-15T10:00:00.000Z",
});

const FIXTURES_ROOT = fileURLToPath(
  new URL("../../../fixtures/sample-repos/iac-samples/", import.meta.url),
);

function makeCtx(repoRoot: string): DetectorContext {
  const warnings: string[] = [];
  return {
    clientId: "client_test_0001",
    scanId: "scan_test_0001",
    appMap: minimalAppMap,
    scope: FULL_SCOPE,
    config: getHardenedDefaults(),
    repoRoot,
    files: fsFileProvider(repoRoot),
    now: () => "2026-01-15T10:00:00.000Z",
    logger: createNullLogger(),
    signal: undefined,
    warnings,
    warn(detector: string, message: string): void {
      warnings.push(`[${detector}] ${message}`);
    },
  };
}

function rulesOf(candidates: { ruleId: string }[]): string[] {
  return candidates.map((c) => c.ruleId).sort();
}

describe("discovery/iac — vulnerable fixture (real files on disk)", () => {
  const repoRoot = nodePath.join(FIXTURES_ROOT, "vulnerable");

  it("flags every real Dockerfile anti-pattern in the fixture", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    const dockerFindings = candidates.filter((c) => c.location.file === "Dockerfile");
    const rules = rulesOf(dockerFindings);

    expect(rules).toContain("dockerfile.missing-user");
    expect(rules).toContain("dockerfile.unpinned-base-image");
    expect(rules).toContain("dockerfile.add-remote-url");
    expect(rules).toContain("dockerfile.add-instead-of-copy");
    expect(rules).toContain("dockerfile.secret-in-arg");
    expect(rules).toContain("dockerfile.secret-in-env");
    // release.tar.gz IS an archive — ADD is legitimate there, no finding.
    expect(dockerFindings.filter((c) => c.metadata?.["kind"] === "local-non-archive")).toHaveLength(
      1,
    );

    // Secret values must never appear in the candidate (golden rule #1).
    const serialized = JSON.stringify(dockerFindings);
    expect(serialized).not.toContain("SuperSecretPass123");
    expect(serialized).not.toContain("sk_live_abcdefghijklmnopqrstuvwx");
  });

  it("flags the missing .dockerignore secret-exposure risk", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    const finding = candidates.find(
      (c) => c.ruleId === "dockerfile.missing-dockerignore-secret-exposure",
    );
    expect(finding).toBeDefined();
    expect(finding?.category).toBe("hardcoded_secret");
  });

  it("flags every real Kubernetes manifest issue in the fixture", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    const k8sFindings = candidates.filter((c) => c.location.file === "k8s/deployment.yaml");
    const rules = rulesOf(k8sFindings);

    expect(rules).toContain("k8s.host-network");
    expect(rules).toContain("k8s.privileged-container");
    expect(rules).toContain("k8s.missing-resource-limits");
    expect(rules).toContain("k8s.secret-as-plain-env-var");

    const serialized = JSON.stringify(k8sFindings);
    expect(serialized).not.toContain("SuperSecretPass123");
  });

  it("flags the missing NetworkPolicy (repo-level, spans all manifests)", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    const finding = candidates.find((c) => c.ruleId === "k8s.missing-network-policy");
    expect(finding).toBeDefined();
    expect(finding?.category).toBe("broken_access_control");
  });

  it("flags every real Terraform issue in the fixture", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    const tfFindings = candidates.filter((c) => c.location.file === "terraform/main.tf");
    const rules = rulesOf(tfFindings);

    expect(rules.filter((r) => r === "terraform.hardcoded-credential")).toHaveLength(3); // access_key, secret_key, password
    expect(rules).toContain("terraform.permissive-security-group");
    expect(rules).toContain("terraform.permissive-iam-policy");
    expect(rules).toContain("terraform.s3-bucket-no-encryption");
    expect(rules).toContain("terraform.unencrypted-storage");

    const serialized = JSON.stringify(tfFindings);
    expect(serialized).not.toContain("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY1");
    expect(serialized).not.toContain("SuperSecretDbPass1");
  });

  it("assigns every IaC finding a real Category the contracts taxonomy recognizes", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    expect(candidates.length).toBeGreaterThan(10);
    for (const c of candidates) {
      expect([
        "hardcoded_secret",
        "insecure_configuration",
        "broken_access_control",
        "weak_crypto",
      ]).toContain(c.category);
    }
  });
});

describe("discovery/iac — clean fixture (real files on disk, must produce zero findings)", () => {
  const repoRoot = nodePath.join(FIXTURES_ROOT, "clean");

  it("Dockerfile: no findings (pinned digest, non-root USER, no secrets, no bare ADD)", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    const dockerFindings = candidates.filter((c) => c.location.file === "Dockerfile");
    expect(dockerFindings).toEqual([]);
  });

  it("does not flag a missing .dockerignore when one is present", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    expect(
      candidates.find((c) => c.ruleId === "dockerfile.missing-dockerignore-secret-exposure"),
    ).toBeUndefined();
  });

  it("Kubernetes: no per-container findings (resource limits set, non-privileged, secretKeyRef)", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    const k8sFindings = candidates.filter((c) => c.location.file === "k8s/deployment.yaml");
    expect(k8sFindings).toEqual([]);
  });

  it("does not flag missing NetworkPolicy when one is present", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    expect(candidates.find((c) => c.ruleId === "k8s.missing-network-policy")).toBeUndefined();
  });

  it("Terraform: no findings (scoped CIDR, least-privilege IAM, encrypted storage)", async () => {
    const candidates = await detectIac(makeCtx(repoRoot));
    const tfFindings = candidates.filter((c) => c.location.file === "terraform/main.tf");
    expect(tfFindings).toEqual([]);
  });
});

describe("discovery/iac — degrades gracefully with no Semgrep binary/runner", () => {
  it("still returns the structural findings when the injected Semgrep runner reports the binary missing", async () => {
    const repoRoot = nodePath.join(FIXTURES_ROOT, "vulnerable");
    const ctx = makeCtx(repoRoot);
    const candidates = await detectIac(ctx, { runner: async () => null });
    expect(candidates.length).toBeGreaterThan(0);
    expect(ctx.warnings.some((w) => w.includes("iac"))).toBe(true);
  });

  it("in-memory-only scan shape (no repoRoot, no runner, no files) never throws and returns empty", async () => {
    const ctx = makeCtx("/nonexistent");
    ctx.repoRoot = undefined;
    ctx.files = emptyFileProvider();
    const candidates = await detectIac(ctx);
    expect(candidates).toEqual([]);
  });
});
