import { z } from "zod";
import {
  CategorySchema,
  CweIdSchema,
  OwaspIdSchema,
  SeveritySchema,
  RiskClassSchema,
} from "@montr/contracts";

/**
 * Ground-truth manifest for the sample repos. The golden-corpus scorer (WS-P)
 * measures precision/recall against this. `exploitable` distinguishes findings
 * that should reach the CONFIRMED tier from ones that should be DEMOTED to the
 * appendix (present but not reachable/exploitable).
 */

export const GroundTruthFindingSchema = z.object({
  id: z.string(),
  category: CategorySchema,
  cwe: z.array(CweIdSchema),
  owasp: OwaspIdSchema,
  file: z.string(),
  line: z.number().int().positive(),
  severity: SeveritySchema,
  /** What the risk classifier should decide (§11 hard rules). */
  expectedRiskClass: RiskClassSchema,
  /** True => should be CONFIRMED; false => should be DEMOTED to the appendix. */
  exploitable: z.boolean(),
  description: z.string(),
});
export type GroundTruthFinding = z.infer<typeof GroundTruthFindingSchema>;

export const GroundTruthRepoSchema = z.object({
  name: z.string(),
  kind: z.enum(["vulnerable", "clean"]),
  path: z.string(),
  expectedFindings: z.array(GroundTruthFindingSchema),
});
export type GroundTruthRepo = z.infer<typeof GroundTruthRepoSchema>;

export const GroundTruthManifestSchema = z.object({
  version: z.string(),
  repos: z.array(GroundTruthRepoSchema),
});
export type GroundTruthManifest = z.infer<typeof GroundTruthManifestSchema>;

export const groundTruthManifest: GroundTruthManifest = GroundTruthManifestSchema.parse({
  version: "1.0.0",
  repos: [
    {
      name: "vulnerable-nextjs",
      kind: "vulnerable",
      path: "sample-repos/vulnerable-nextjs",
      expectedFindings: [
        {
          id: "gt_sqli",
          category: "sql_injection",
          cwe: ["CWE-89"],
          owasp: "A03:2021",
          file: "app/api/users/route.ts",
          line: 9,
          severity: "critical",
          expectedRiskClass: "auto-eligible",
          exploitable: true,
          description: "Tainted `q` reaches prisma.$queryRawUnsafe on a public route.",
        },
        {
          id: "gt_xss",
          category: "xss",
          cwe: ["CWE-79"],
          owasp: "A03:2021",
          file: "app/search/page.tsx",
          line: 8,
          severity: "high",
          expectedRiskClass: "auto-eligible",
          exploitable: true,
          description: "`q` rendered via dangerouslySetInnerHTML without escaping.",
        },
        {
          id: "gt_secret",
          category: "hardcoded_secret",
          cwe: ["CWE-798"],
          owasp: "A07:2021",
          file: "lib/config.ts",
          line: 2,
          severity: "high",
          expectedRiskClass: "human-required",
          exploitable: true,
          description: "Hard-coded live payments API key; rotation requires a human.",
        },
        {
          id: "gt_dep",
          category: "vulnerable_dependency",
          cwe: ["CWE-1321"],
          owasp: "A06:2021",
          file: "package.json",
          line: 14,
          severity: "medium",
          expectedRiskClass: "auto-eligible",
          exploitable: false,
          description: "lodash prototype pollution present but not reachably called (demote).",
        },
        {
          id: "gt_cors",
          category: "permissive_cors",
          cwe: ["CWE-942"],
          owasp: "A05:2021",
          file: "app/api/users/route.ts",
          line: 12,
          severity: "medium",
          expectedRiskClass: "auto-eligible",
          exploitable: false,
          description: "Wildcard CORS on a non-credentialed endpoint (demote).",
        },
      ],
    },
    {
      name: "clean-nextjs",
      kind: "clean",
      path: "sample-repos/clean-nextjs",
      expectedFindings: [],
    },
  ],
});
