/**
 * E16 — Terraform (HCL) issue detection (offline, no Semgrep dependency).
 *
 * No HCL parser is a dependency of this monorepo today (checked: neither the
 * workspace root nor any package pulls in `@cdktf/hcl2json`, `hcl2-parser`, or
 * similar — see the E16 task notes), so this is a well-chosen, block-aware
 * structural scan rather than a full HCL AST: `extractResourceBlocks` finds
 * every top-level `resource "<type>" "<name>" { ... }` header via regex, then
 * resolves its matching closing brace with a small string-literal-aware
 * brace-depth counter (so a `"{"` inside a quoted value never miscounts). Each
 * rule below then runs targeted regex checks scoped to ONE resource block's
 * body — real structural scoping, not a flat whole-file regex, at a fraction
 * of a real parser's cost. Nested blocks (`ingress { ... }` inside a security
 * group resource) are matched by substring within the already-scoped body,
 * which is sufficient for the checks here.
 */
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

export interface ResourceBlock {
  resourceType: string;
  resourceName: string;
  body: string;
  /** 1-based line of the `resource "..." "..." {` header. */
  line: number;
}

function lineAtOffset(content: string, offset: number): number {
  let line = 1;
  const end = Math.min(offset, content.length);
  for (let i = 0; i < end; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

/** Resolve the index of the `}` matching the `{` at `openIdx`, string-literal aware. */
function matchBraceEnd(content: string, openIdx: number): number {
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = openIdx; i < content.length; i++) {
    const c = content[i];
    if (inString) {
      if (escape) escape = false;
      else if (c === "\\") escape = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

const RESOURCE_HEADER_RE = /\bresource\s+"([\w.-]+)"\s+"([\w.-]+)"\s*\{/g;

/** Real, block-scoped Terraform resource extraction — see module doc comment. */
export function extractResourceBlocks(content: string): ResourceBlock[] {
  const out: ResourceBlock[] = [];
  const re = new RegExp(RESOURCE_HEADER_RE.source, RESOURCE_HEADER_RE.flags);
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const openIdx = m.index + m[0].length - 1;
    const closeIdx = matchBraceEnd(content, openIdx);
    if (closeIdx < 0) {
      re.lastIndex = openIdx + 1;
      continue;
    }
    out.push({
      resourceType: m[1] ?? "",
      resourceName: m[2] ?? "",
      body: content.slice(openIdx + 1, closeIdx),
      line: lineAtOffset(content, m.index),
    });
    re.lastIndex = closeIdx + 1;
  }
  return out;
}

const TF_SECRET_KEY_RE =
  /\b(access_key|secret_key|password|client_secret|api_key|private_key|admin_password|db_password)\s*=\s*"([^"$]{8,})"/gi;

/** Hardcoded credentials as a literal attribute value anywhere in the file. */
function checkHardcodedCredentials(content: string): RawFinding[] {
  const out: RawFinding[] = [];
  const re = new RegExp(TF_SECRET_KEY_RE.source, TF_SECRET_KEY_RE.flags);
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const attr = m[1] ?? "";
    const value = (m[2] ?? "").trim();
    if (looksLikePlaceholder(value)) continue;
    out.push({
      rule: "terraform.hardcoded-credential",
      category: "hardcoded_secret",
      severity: "high",
      line: lineAtOffset(content, m.index),
      snippet: `${attr} = <redacted, ${value.length} chars>`,
      title: `Hardcoded credential in Terraform attribute "${attr}"`,
      metadata: { detector: "iac-terraform", attribute: attr },
    });
  }
  return out;
}

const WILDCARD_CIDR_RE = /cidr_blocks\s*=\s*\[[^\]]*(?:0\.0\.0\.0\/0|::\/0)[^\]]*\]/i;

/** Overly permissive security-group ingress: a `0.0.0.0/0`/`::/0` CIDR on an ingress rule. */
function checkPermissiveSecurityGroup(block: ResourceBlock): RawFinding | null {
  const isSgResource = /^aws_security_group$/i.test(block.resourceType);
  const isSgRuleResource = /^aws_(security_group_rule|vpc_security_group_ingress_rule)$/i.test(
    block.resourceType,
  );
  if (!isSgResource && !isSgRuleResource) return null;

  if (isSgRuleResource) {
    const isIngress =
      /type\s*=\s*"ingress"/i.test(block.body) || block.resourceType.includes("ingress");
    if (!isIngress) return null;
    if (
      !WILDCARD_CIDR_RE.test(block.body) &&
      !/cidr_ipv4\s*=\s*"(?:0\.0\.0\.0\/0|::\/0)"/i.test(block.body)
    )
      return null;
  } else {
    const hasIngress = /\bingress\b/.test(block.body);
    if (!hasIngress || !WILDCARD_CIDR_RE.test(block.body)) return null;
  }

  return {
    rule: "terraform.permissive-security-group",
    category: "broken_access_control",
    severity: "high",
    line: block.line,
    snippet: `resource "${block.resourceType}" "${block.resourceName}": ingress open to 0.0.0.0/0`,
    title: `Security group "${block.resourceName}" allows ingress from anywhere (0.0.0.0/0)`,
    metadata: {
      detector: "iac-terraform",
      resourceType: block.resourceType,
      resource: block.resourceName,
    },
  };
}

const IAM_RESOURCE_RE = /^aws_iam_(policy|role_policy|user_policy|group_policy|policy_document)$/i;
// Matches BOTH raw-JSON-string policies (`"Action": "*"`) and the more common
// `jsonencode({ Action = "*" })` HCL-map form, whose keys are conventionally
// capitalized barewords mirroring AWS's own JSON policy key casing (hence
// `actions?` case-insensitive, not just the HCL-idiomatic lowercase plural).
const WILDCARD_ACTION_RE =
  /"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])|actions?\s*=\s*(?:"\*"|\[\s*"\*"\s*\])/i;
const WILDCARD_RESOURCE_RE =
  /"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])|resources?\s*=\s*(?:"\*"|\[\s*"\*"\s*\])/i;
const ALLOW_EFFECT_RE = /"Effect"\s*:\s*"Allow"|effect\s*=\s*"Allow"/i;

/** Overly permissive IAM policy: Action:* + Resource:* (+ Allow, or a data source that implies it). */
function checkPermissiveIam(block: ResourceBlock): RawFinding | null {
  if (!IAM_RESOURCE_RE.test(block.resourceType)) return null;
  if (!WILDCARD_ACTION_RE.test(block.body) || !WILDCARD_RESOURCE_RE.test(block.body)) return null;
  const isDataSource = block.resourceType === "aws_iam_policy_document";
  if (!isDataSource && !ALLOW_EFFECT_RE.test(block.body)) return null;
  return {
    rule: "terraform.permissive-iam-policy",
    category: "broken_access_control",
    severity: "high",
    line: block.line,
    snippet: `resource "${block.resourceType}" "${block.resourceName}": Action:* + Resource:*`,
    title: `IAM policy "${block.resourceName}" grants "*" actions on "*" resources`,
    metadata: {
      detector: "iac-terraform",
      resourceType: block.resourceType,
      resource: block.resourceName,
    },
  };
}

const ENCRYPTABLE_RESOURCE_RE = /^aws_(ebs_volume|db_instance|rds_cluster|dynamodb_table)$/i;

/** Explicit `encrypted = false` / `storage_encrypted = false` on a storage resource. */
function checkExplicitlyUnencrypted(block: ResourceBlock): RawFinding | null {
  if (!ENCRYPTABLE_RESOURCE_RE.test(block.resourceType)) return null;
  if (!/\b(?:encrypted|storage_encrypted)\s*=\s*false\b/i.test(block.body)) return null;
  return {
    rule: "terraform.unencrypted-storage",
    category: "weak_crypto",
    severity: "high",
    line: block.line,
    snippet: `resource "${block.resourceType}" "${block.resourceName}": encryption explicitly disabled`,
    title: `Storage resource "${block.resourceName}" has encryption explicitly disabled`,
    metadata: {
      detector: "iac-terraform",
      resourceType: block.resourceType,
      resource: block.resourceName,
    },
  };
}

/**
 * S3 buckets with no `server_side_encryption_configuration` ANYWHERE in the
 * file (inline, on the `aws_s3_bucket` resource itself, or as a separate
 * `aws_s3_bucket_server_side_encryption_configuration` resource referencing
 * it — the modern AWS provider's split-resource pattern). File-scoped, not
 * cross-file: a bucket encrypted via a config living in a different .tf file
 * is not resolved here — documented gap, not a full Terraform module graph.
 */
function checkS3BucketsWithoutEncryption(
  content: string,
  blocks: readonly ResourceBlock[],
): RawFinding[] {
  const buckets = blocks.filter((b) => b.resourceType === "aws_s3_bucket");
  if (buckets.length === 0) return [];
  if (/server_side_encryption/i.test(content)) return [];
  return buckets.map((b) => ({
    rule: "terraform.s3-bucket-no-encryption",
    category: "weak_crypto" as Category,
    severity: "medium" as Severity,
    line: b.line,
    snippet: `resource "aws_s3_bucket" "${b.resourceName}": no server_side_encryption_configuration found in file`,
    title: `S3 bucket "${b.resourceName}" has no server-side encryption configuration`,
    metadata: { detector: "iac-terraform", resourceType: b.resourceType, resource: b.resourceName },
  }));
}

/** Run all Terraform checks over one `.tf` file's content. */
export function detectTerraformIssues(file: RepoFile): RawFinding[] {
  const blocks = extractResourceBlocks(file.content);
  const out: RawFinding[] = [];

  out.push(...checkHardcodedCredentials(file.content));

  for (const block of blocks) {
    const sg = checkPermissiveSecurityGroup(block);
    if (sg) out.push(sg);
    const iam = checkPermissiveIam(block);
    if (iam) out.push(iam);
    const unenc = checkExplicitlyUnencrypted(block);
    if (unenc) out.push(unenc);
  }
  out.push(...checkS3BucketsWithoutEncryption(file.content, blocks));

  return out;
}
