/**
 * E16 — Kubernetes manifest issue detection (offline, no Semgrep dependency).
 * Real YAML parsing (the `yaml` package — already a `@montr/discovery`
 * dependency for pnpm-lock.yaml parsing, see `detectors/sca.ts`), not regex
 * over YAML text.
 *
 * A YAML file is only ever treated as a Kubernetes manifest when it parses
 * and carries BOTH `apiVersion` and `kind` — the standard discriminator — so
 * `docker-compose.yml`, GitHub Actions workflows, `pnpm-workspace.yaml`, etc.
 * are silently skipped rather than misread.
 *
 * Findings are anchored at the document's start line (a real offset resolved
 * from the `yaml` package's node ranges), not at the specific offending key —
 * exact per-container/per-key line resolution would need substantially more
 * machinery for marginal benefit; the finding's title/snippet always names
 * the specific container/field so the location is still actionable.
 */
import { parseAllDocuments } from "yaml";
import type { Category, Severity } from "@montr/contracts";
import { looksLikePlaceholder } from "../secrets.js";
import type { RepoFile } from "../../util/files.js";

export interface RawFinding {
  rule: string;
  category: Category;
  severity: Severity;
  line: number;
  snippet: string;
  title: string;
  metadata?: Record<string, unknown>;
}

interface K8sContainer {
  name?: string;
  resources?: { limits?: { cpu?: unknown; memory?: unknown }; requests?: unknown };
  securityContext?: { privileged?: boolean };
  env?: Array<{ name?: string; value?: string; valueFrom?: unknown }>;
}

interface K8sManifest {
  apiVersion?: string;
  kind?: string;
  metadata?: { name?: string; namespace?: string };
  spec?: Record<string, unknown>;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

/** The pod spec (containers/hostNetwork/hostPID) for a manifest's `kind`, wherever nested. */
function extractPodSpec(kind: string, manifest: K8sManifest): Record<string, unknown> | undefined {
  const spec = manifest.spec;
  switch (kind) {
    case "Pod":
      return spec;
    case "Deployment":
    case "StatefulSet":
    case "DaemonSet":
    case "ReplicaSet":
    case "Job":
      return asRecord(asRecord(spec?.["template"])?.["spec"]);
    case "CronJob": {
      const jobTemplate = asRecord(spec?.["jobTemplate"]);
      const jobSpec = asRecord(jobTemplate?.["spec"]);
      return asRecord(asRecord(jobSpec?.["template"])?.["spec"]);
    }
    default:
      return undefined;
  }
}

function containersOf(podSpec: Record<string, unknown>): K8sContainer[] {
  return [
    ...asArray(podSpec["containers"]),
    ...asArray(podSpec["initContainers"]),
  ] as K8sContainer[];
}

function lineAtOffset(content: string, offset: number): number {
  let line = 1;
  const end = Math.min(offset, content.length);
  for (let i = 0; i < end; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

const SECRET_ENV_NAME_RE = /(?:KEY|SECRET|TOKEN|PASSWORD|PWD|CREDENTIAL|PRIVATE)/i;

function checkContainers(
  containers: readonly K8sContainer[],
  kind: string,
  name: string,
  line: number,
): RawFinding[] {
  const out: RawFinding[] = [];
  for (const c of containers) {
    const cname = c.name ?? "(unnamed container)";

    // Missing resource limits (DoS/noisy-neighbor exposure — no ceiling on
    // CPU/memory a compromised or buggy container can consume).
    const limits = c.resources?.limits;
    if (!limits || (limits.cpu === undefined && limits.memory === undefined)) {
      out.push({
        rule: "k8s.missing-resource-limits",
        category: "insecure_configuration",
        severity: "medium",
        line,
        snippet: `${kind} ${name}: container "${cname}" has no resources.limits`,
        title: `Container "${cname}" has no CPU/memory resource limits`,
        metadata: { detector: "iac-kubernetes", kind, resource: name, container: cname },
      });
    }

    // Privileged container — full host device/kernel access.
    if (c.securityContext?.privileged === true) {
      out.push({
        rule: "k8s.privileged-container",
        category: "insecure_configuration",
        severity: "critical",
        line,
        snippet: `${kind} ${name}: container "${cname}" runs privileged: true`,
        title: `Container "${cname}" runs privileged (full host access)`,
        metadata: { detector: "iac-kubernetes", kind, resource: name, container: cname },
      });
    }

    // Secrets passed as plain literal env values instead of a Secret ref.
    for (const e of c.env ?? []) {
      if (!e?.name || e.value === undefined || e.valueFrom !== undefined) continue;
      if (!SECRET_ENV_NAME_RE.test(e.name)) continue;
      const value = String(e.value);
      if (looksLikePlaceholder(value) || value.length < 8) continue;
      out.push({
        rule: "k8s.secret-as-plain-env-var",
        category: "hardcoded_secret",
        severity: "high",
        line,
        snippet: `${kind} ${name}: container "${cname}" env ${e.name}=<redacted>`,
        title: `Secret "${e.name}" set as a plain literal env value instead of a Secret reference`,
        metadata: {
          detector: "iac-kubernetes",
          kind,
          resource: name,
          container: cname,
          variable: e.name,
        },
      });
    }
  }
  return out;
}

/** Run all per-manifest structural checks over one YAML file's parsed documents. */
export function detectKubernetesIssues(file: RepoFile): RawFinding[] {
  let docs;
  try {
    docs = parseAllDocuments(file.content);
  } catch {
    return [];
  }
  const out: RawFinding[] = [];

  for (const doc of docs) {
    if (doc.errors && doc.errors.length > 0) continue; // malformed doc — skip, don't guess
    let manifest: unknown;
    try {
      manifest = doc.toJS();
    } catch {
      continue;
    }
    const m = asRecord(manifest);
    if (!m) continue;
    const apiVersion = m["apiVersion"];
    const kind = m["kind"];
    // The standard K8s discriminator — absent either field, this is not a
    // recognizable manifest (docker-compose.yml, a GH Actions workflow, ...).
    if (typeof apiVersion !== "string" || typeof kind !== "string") continue;

    const metadata = asRecord(m["metadata"]);
    const name =
      typeof metadata?.["name"] === "string" ? (metadata["name"] as string) : "(unnamed)";
    const contentOffset =
      typeof (doc.contents as { range?: number[] } | null)?.range?.[0] === "number"
        ? ((doc.contents as { range: number[] }).range[0] ?? 0)
        : 0;
    const line = lineAtOffset(file.content, contentOffset);

    const podSpec = extractPodSpec(kind, m as K8sManifest);
    if (podSpec) {
      const containers = containersOf(podSpec);
      out.push(...checkContainers(containers, kind, name, line));

      if (podSpec["hostNetwork"] === true) {
        out.push({
          rule: "k8s.host-network",
          category: "insecure_configuration",
          severity: "high",
          line,
          snippet: `${kind} ${name}: hostNetwork: true`,
          title: `${kind} "${name}" shares the host's network namespace (hostNetwork: true)`,
          metadata: { detector: "iac-kubernetes", kind, resource: name },
        });
      }
      if (podSpec["hostPID"] === true) {
        out.push({
          rule: "k8s.host-pid",
          category: "insecure_configuration",
          severity: "high",
          line,
          snippet: `${kind} ${name}: hostPID: true`,
          title: `${kind} "${name}" shares the host's PID namespace (hostPID: true)`,
          metadata: { detector: "iac-kubernetes", kind, resource: name },
        });
      }
    }
  }
  return out;
}

/** A parsed manifest doc, retained across files for the repo-level NetworkPolicy check. */
export interface RecognizedManifest {
  file: string;
  kind: string;
  line: number;
}

/** Parse a YAML file's documents into recognized-K8s-manifest summaries (kind + anchor line only). */
export function summarizeManifests(file: RepoFile): RecognizedManifest[] {
  let docs;
  try {
    docs = parseAllDocuments(file.content);
  } catch {
    return [];
  }
  const out: RecognizedManifest[] = [];
  for (const doc of docs) {
    if (doc.errors && doc.errors.length > 0) continue;
    let manifest: unknown;
    try {
      manifest = doc.toJS();
    } catch {
      continue;
    }
    const m = asRecord(manifest);
    const apiVersion = m?.["apiVersion"];
    const kind = m?.["kind"];
    if (typeof apiVersion !== "string" || typeof kind !== "string") continue;
    const contentOffset =
      typeof (doc.contents as { range?: number[] } | null)?.range?.[0] === "number"
        ? ((doc.contents as { range: number[] }).range[0] ?? 0)
        : 0;
    out.push({ file: file.path, kind, line: lineAtOffset(file.content, contentOffset) });
  }
  return out;
}

const WORKLOAD_KINDS = new Set([
  "Deployment",
  "StatefulSet",
  "DaemonSet",
  "ReplicaSet",
  "Pod",
  "Job",
  "CronJob",
  "Service",
]);

export interface AnchoredFinding {
  finding: RawFinding;
  file: string;
}

/**
 * K8s manifests define at least one workload/Service but the manifest set has
 * NO `NetworkPolicy` anywhere — i.e. there is no default-deny (or any)
 * network-level access control between pods. Repo-level (spans every
 * recognized manifest), so run once by the IaC entry point.
 */
export function detectMissingNetworkPolicy(
  manifests: readonly RecognizedManifest[],
): AnchoredFinding[] {
  const workloads = manifests.filter((m) => WORKLOAD_KINDS.has(m.kind));
  if (workloads.length === 0) return [];
  const hasNetworkPolicy = manifests.some((m) => m.kind === "NetworkPolicy");
  if (hasNetworkPolicy) return [];
  const anchor = workloads[0];
  if (!anchor) return [];
  return [
    {
      file: anchor.file,
      finding: {
        rule: "k8s.missing-network-policy",
        category: "broken_access_control",
        severity: "medium",
        line: anchor.line,
        snippet: `${workloads.length} workload/Service manifest(s) found, 0 NetworkPolicy`,
        title:
          "No NetworkPolicy found — pods have unrestricted network access to each other by default",
        metadata: {
          detector: "iac-kubernetes",
          check: "missing-network-policy",
          workloadCount: workloads.length,
        },
      },
    },
  ];
}
