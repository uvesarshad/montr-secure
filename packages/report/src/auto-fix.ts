/**
 * Auto-fix PR flow (build-plan §5.6, PRD §7 L5).
 *
 * ⛔ Opens PRs ONLY (never direct commits) and ONLY for `auto-eligible` fixes
 * that pass the gate. `human-required` fixes never reach this flow — they stay
 * recommendations in the report. Planning is PURE (deterministic, offline);
 * opening is delegated to an injected {@link PullRequestOpener} so the whole
 * flow is unit-testable without a network, a VCS token, or a git binary.
 */
import {
  complianceForCategory,
  type ConfirmedFinding,
  type Fix,
  type PullRequest,
  type VcsProvider,
} from "@montr/contracts";
import { assertPrGate, prGateDecision, type PrGateContext } from "./gate.js";
import type { AutoFixFlowInput, AutoFixPrPlan } from "./types.js";

/** Branch/id-safe slug (keeps VCS-legal chars; collapses the rest to "-"). */
function slug(value: string): string {
  return value.replace(/[^A-Za-z0-9._/-]+/g, "-").replace(/^-+|-+$/g, "") || "fix";
}

function resolveProvider(input: AutoFixFlowInput): VcsProvider {
  return input.opener?.provider ?? input.provider ?? "github";
}

function resolveBaseBranch(input: AutoFixFlowInput): string {
  return input.baseBranch ?? input.scan.branch ?? "main";
}

/** One markdown section per fix: finding context + rationale + proof-of-fix test. */
function renderFixSection(fix: Fix, finding: ConfirmedFinding | undefined): string {
  const lines: string[] = [];
  if (finding) {
    const c = complianceForCategory(finding.category);
    const cwe = finding.cwe.length > 0 ? finding.cwe.join(", ") : c.cwe.join(", ");
    lines.push(`### ${finding.title}`);
    lines.push(
      `- **Severity:** ${finding.severity}  •  **Exposure:** ${finding.exposure}  •  **${c.owasp} ${c.owaspTitle}**  •  ${cwe}`,
    );
    lines.push(`- **Location:** \`${finding.location.file}:${finding.location.line}\``);
    lines.push(`- **Impact:** ${finding.impact}`);
  } else {
    lines.push(`### Fix ${fix.id}`);
  }
  lines.push("");
  lines.push(fix.rationale);
  lines.push("");
  const test = fix.proofOfFixTest;
  lines.push(
    `**Proof-of-fix test** (${test.framework ?? "test"}): fails before this patch, passes after.`,
  );
  if (test.filePath) lines.push(`\n\`${test.filePath}\`:`);
  lines.push("\n```" + (test.framework === "vitest" ? "ts" : ""));
  lines.push(test.code);
  lines.push("```");
  return lines.join("\n");
}

/** Assemble the full PR body for a set of fixes (rationale + tests + safety note). */
export function buildPrBody(fixes: Fix[], findingsById: Map<string, ConfirmedFinding>): string {
  const header = [
    "## Montr Secure — automated security fix",
    "",
    `This PR contains ${fixes.length} **auto-eligible** fix${fixes.length === 1 ? "" : "es"} for confirmed, proven-exploitable finding${fixes.length === 1 ? "" : "s"}. Each carries a proof-of-fix test.`,
    "",
    "> ⛔ Auth/session/crypto/access-control fixes are **human-required** and are NOT auto-opened — they appear as recommendations in the Montr report, never here.",
    "",
    "---",
    "",
  ].join("\n");
  const sections = fixes
    .map((f) => renderFixSection(f, findingsById.get(f.confirmedFindingId)))
    .join("\n\n---\n\n");
  return `${header}${sections}\n`;
}

/**
 * Plan the auto-fix PRs for a run. PURE: returns one plan per eligible fix
 * (default, each independently reviewable) or a single grouped plan. Only
 * `auto-eligible` fixes whose gate has passed are included; everything else is
 * silently excluded (it stays a recommendation). Returns `[]` when the gate has
 * not passed or auto-apply is off.
 */
export function planAutoFixPullRequests(input: AutoFixFlowInput): AutoFixPrPlan[] {
  const ctx: PrGateContext = { autoApply: input.autoApply, gateState: input.scan.gateState };
  const eligible = input.fixes.filter((f) => prGateDecision(ctx, f).eligible);
  if (eligible.length === 0) return [];

  const provider = resolveProvider(input);
  const baseBranch = resolveBaseBranch(input);
  const scanId = input.scan.id;
  const clientId = input.scan.clientId;
  const findingsById = new Map(input.confirmed.map((f) => [f.id, f] as const));

  if (input.prStrategy === "grouped") {
    const branch = `montr/auto-fix/${slug(scanId)}`;
    const n = eligible.length;
    return [
      {
        scanId,
        clientId,
        provider,
        branch,
        baseBranch,
        title: `Montr Secure: fix ${n} confirmed vulnerabilit${n === 1 ? "y" : "ies"}`,
        bodySummary: buildPrBody(eligible, findingsById),
        fixIds: eligible.map((f) => f.id),
        patch: eligible.map((f) => f.patch).join("\n"),
        prId: `pr_${scanId}`,
      },
    ];
  }

  // Default: one PR per fix (each independently reviewable, §7 L5).
  return eligible.map((fix) => {
    const finding = findingsById.get(fix.confirmedFindingId);
    const key = slug(fix.confirmedFindingId);
    return {
      scanId,
      clientId,
      provider,
      branch: `montr/fix/${slug(scanId)}/${key}`,
      baseBranch,
      title: finding
        ? `Montr Secure: fix ${finding.title}`
        : `Montr Secure: fix ${fix.confirmedFindingId}`,
      bodySummary: buildPrBody([fix], findingsById),
      fixIds: [fix.id],
      patch: fix.patch,
      prId: `pr_${scanId}_${slug(fix.id)}`,
    };
  });
}

/**
 * Open the planned auto-fix PRs via the injected opener. Re-asserts the gate for
 * every fix before any network call (defense-in-depth) and audit-logs each
 * opened PR (`fix.pr_opened`, metadata only — never the patch/test bodies).
 *
 * Returns `[]` (opening nothing) when there is no opener, when auto-apply is off,
 * or when the gate has not passed — the fixes remain recommendations.
 */
export async function openAutoFixPullRequests(input: AutoFixFlowInput): Promise<PullRequest[]> {
  const plans = planAutoFixPullRequests(input);
  if (plans.length === 0) return [];

  if (!input.opener) {
    input.logger?.warn("report.autofix.no_opener", {
      scanId: input.scan.id,
      plannedPrs: plans.length,
    });
    return [];
  }

  const ctx: PrGateContext = { autoApply: input.autoApply, gateState: input.scan.gateState };
  const fixById = new Map(input.fixes.map((f) => [f.id, f] as const));
  const opened: PullRequest[] = [];

  for (const plan of plans) {
    // ⛔ Never open a PR that isn't gate-permitted; never a direct commit.
    for (const fixId of plan.fixIds) {
      const fix = fixById.get(fixId);
      if (fix) assertPrGate(ctx, fix);
    }
    if (plan.branch === plan.baseBranch) {
      // Defense-in-depth: a PR must target a NON-base branch (never a direct commit).
      throw new Error(`refusing to open PR: head branch equals base branch (${plan.branch})`);
    }

    const pr = await input.opener.open(plan);
    opened.push(pr);

    await input.audit?.append({
      clientId: input.scan.clientId,
      scanId: input.scan.id,
      actor: { type: "agent", id: "montr-report" },
      action: "fix.pr_opened",
      targetType: "pull_request",
      targetId: pr.id,
      summary: `Opened ${plan.provider} PR for ${plan.fixIds.length} auto-eligible fix(es) on ${plan.branch}`,
      metadata: {
        provider: plan.provider,
        branch: plan.branch,
        baseBranch: plan.baseBranch,
        fixIds: plan.fixIds,
        prNumber: pr.number,
        prUrl: pr.url,
      },
    });

    input.logger?.info("report.autofix.pr_opened", {
      scanId: input.scan.id,
      prId: pr.id,
      provider: plan.provider,
      branch: plan.branch,
      fixCount: plan.fixIds.length,
    });
  }

  return opened;
}

/** Map every fix id that landed in a PR to that PR's id (for `fix.pullRequestId`). */
export function prIdByFixId(prs: PullRequest[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const pr of prs) for (const fixId of pr.fixIds) map.set(fixId, pr.id);
  return map;
}
