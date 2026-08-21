/**
 * Network policy (B9), scoped to SSRF findings specifically per this task's
 * brief. Reuses E16's real Kubernetes manifest detection
 * (`@montr/discovery`'s `summarizeManifests`/`detectMissingNetworkPolicy` —
 * read-only, no duplication of that YAML-parsing logic) to decide WHICH
 * concrete guidance to give:
 *
 *   - Real K8s manifests present, no NetworkPolicy at all -> a concrete
 *     NetworkPolicy YAML snippet (deny-all egress + explicit metadata-IP block).
 *   - A NetworkPolicy exists but never mentions the cloud metadata IP -> a
 *     narrower "add this egress rule" recommendation (lower severity — some
 *     policy already exists).
 *   - A NetworkPolicy exists and already references the metadata IP -> no
 *     recommendation (precision — already covered).
 *   - No K8s manifests at all -> cloud security-group / IMDSv2 guidance,
 *     honestly framed as the fallback for a non-Kubernetes target.
 */
import type { ConfirmedFinding } from "@montr/contracts";
import {
  detectMissingNetworkPolicy,
  isYamlFile,
  readAll,
  summarizeManifests,
  type FileProvider,
} from "@montr/discovery";
import type { RecommendationDraft } from "../types.js";

const METADATA_IP = "169.254.169.254";

const NETWORK_POLICY_SNIPPET = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress-to-cloud-metadata
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    # Allow DNS and normal cluster/internet egress, then explicitly carve out
    # the cloud metadata endpoint every SSRF-to-credential-theft chain targets.
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - ${METADATA_IP}/32`;

export async function detectNetworkPolicyGaps(
  files: FileProvider,
  confirmedFindings: readonly ConfirmedFinding[],
): Promise<RecommendationDraft[]> {
  const ssrfFindings = confirmedFindings.filter((f) => f.category === "ssrf");
  if (ssrfFindings.length === 0) return [];

  const relatedFindingIds = ssrfFindings.map((f) => f.id);
  const evidenceHeader = ssrfFindings.map(
    (f) => `${f.title} (${f.location.file}:${f.location.line})`,
  );

  const yamlFiles = await readAll(files, isYamlFile);
  const manifests = yamlFiles.flatMap((f) => summarizeManifests(f));

  if (manifests.length === 0) {
    return [
      {
        category: "network_policy",
        severity: "high",
        title: "Restrict SSRF-reachable egress at the cloud/security-group layer",
        gap: "No Kubernetes manifests were found in this repo — Kubernetes NetworkPolicy guidance does not apply; egress restriction must be applied at the cloud security-group / VPC layer instead.",
        recommendation: [
          "AWS: enforce IMDSv2 (require a session token, HttpTokens: required, HttpPutResponseHopLimit: 1) on every instance profile the app runs under, and add a security-group egress rule denying outbound to 169.254.169.254/32 for the app's own subnet/instances where the app does not need the metadata endpoint.",
          "GCP: block metadata.google.internal / 169.254.169.254 via a VPC firewall egress-deny rule scoped to the app's service, and require the `Metadata-Flavor: Google` header check the metadata server already enforces.",
          "Azure: restrict egress to 169.254.169.254 via an NSG (Network Security Group) outbound deny rule scoped to the app's subnet/NIC.",
        ].join("\n"),
        rationale:
          "A confirmed SSRF finding can reach the cloud metadata endpoint and exfiltrate instance credentials unless egress to it is explicitly blocked at the network layer — an app-level code fix alone does not close this if the underlying network path stays open.",
        evidence: [...evidenceHeader, "No Kubernetes manifests found in the repo"],
        relatedFindingIds,
      },
    ];
  }

  const missing = detectMissingNetworkPolicy(manifests);
  if (missing.length > 0) {
    return [
      {
        category: "network_policy",
        severity: "high",
        title: "Add a NetworkPolicy restricting egress to the cloud metadata endpoint",
        gap: `Kubernetes workload manifest(s) found (${manifests.length} recognized) with no NetworkPolicy at all — pods have unrestricted egress, including to the cloud metadata endpoint (${METADATA_IP}).`,
        recommendation: NETWORK_POLICY_SNIPPET,
        rationale:
          "A confirmed SSRF finding combined with unrestricted pod egress means the metadata endpoint (and any other internal service) is reachable from a compromised request handler.",
        evidence: [
          ...evidenceHeader,
          `${manifests.length} Kubernetes workload manifest(s) found, 0 NetworkPolicy`,
        ],
        relatedFindingIds,
      },
    ];
  }

  const mentionsMetadataIp = yamlFiles.some((f) => f.content.includes(METADATA_IP));
  if (!mentionsMetadataIp) {
    return [
      {
        category: "network_policy",
        severity: "medium",
        title: "Add an explicit metadata-IP egress-deny rule to the existing NetworkPolicy",
        gap: `A NetworkPolicy exists in this repo, but none references ${METADATA_IP} — the existing policy may not actually block SSRF-to-metadata exfiltration.`,
        recommendation: NETWORK_POLICY_SNIPPET,
        rationale:
          "An existing NetworkPolicy that does not explicitly carve out the cloud metadata IP may still permit egress to it (e.g. a broad allow-all-except-nothing egress rule).",
        evidence: [
          ...evidenceHeader,
          "A NetworkPolicy manifest exists but does not mention 169.254.169.254",
        ],
        relatedFindingIds,
      },
    ];
  }

  // A NetworkPolicy exists and already references the metadata IP — assume covered (precision).
  return [];
}
