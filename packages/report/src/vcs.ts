/**
 * Concrete VCS openers for the auto-fix PR flow (build-plan §5.6).
 *
 * ⛔ PR-ONLY, NEVER A DIRECT COMMIT (golden rule #5): every opener pushes the
 * patch to a NON-base branch and opens a PR/MR — it refuses if head === base.
 * GitHub uses @octokit/rest, GitLab uses @gitbeaker/rest; both stage the patch
 * with simple-git (branch → apply → commit → push). All three SDKs are LAZILY
 * imported and structurally bridged so this module builds without them present
 * and unit tests exercise the flow through a FAKE {@link PullRequestOpener}
 * instead. The concrete path is covered at integration (real repo + token).
 *
 * Tokens are secrets: they are passed to the SDK and NEVER logged.
 */
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PullRequestSchema, type PullRequest } from "@montr/contracts";
import type { Logger } from "@montr/telemetry";
import type { AutoFixPrPlan, PullRequestOpener } from "./types.js";

/* ------------------------------------------------------------------ *
 * simple-git — stage the patch on a fresh branch and push it.
 * ------------------------------------------------------------------ */

interface SimpleGitLike {
  checkout(what: string): Promise<unknown>;
  checkoutLocalBranch(branch: string): Promise<unknown>;
  add(files: string | string[]): Promise<unknown>;
  commit(message: string): Promise<unknown>;
  push(remote: string, branch: string, options?: string[]): Promise<unknown>;
  raw(commands: string[]): Promise<string>;
}
type SimpleGitFactory = (baseDir?: string) => SimpleGitLike;

async function loadSimpleGit(): Promise<SimpleGitFactory> {
  const mod = (await import("simple-git")) as unknown as {
    simpleGit?: SimpleGitFactory;
    default?: SimpleGitFactory;
  };
  const factory = mod.simpleGit ?? mod.default;
  if (!factory) throw new Error("simple-git did not expose a factory");
  return factory;
}

/**
 * Branch off `baseBranch`, apply the unified diff, commit, and push. Returns
 * nothing; throws on any git failure. `workdir` is a local checkout of the
 * client's repo (provided by the worker), never a Montr-owned clone.
 */
export async function stagePatchOnBranch(opts: {
  workdir: string;
  baseBranch: string;
  branch: string;
  patch: string;
  commitMessage: string;
  remote?: string;
}): Promise<void> {
  if (opts.branch === opts.baseBranch) {
    throw new Error(`refusing to stage: branch equals base branch (${opts.branch})`);
  }
  const git = (await loadSimpleGit())(opts.workdir);
  await git.checkout(opts.baseBranch);
  await git.checkoutLocalBranch(opts.branch);

  const dir = await mkdtemp(join(tmpdir(), "montr-patch-"));
  const patchFile = join(dir, "fix.patch");
  try {
    await writeFile(patchFile, opts.patch, "utf8");
    await git.raw(["apply", "--whitespace=nowarn", patchFile]);
    await git.add(["--all"]);
    await git.commit(opts.commitMessage);
    await git.push(opts.remote ?? "origin", opts.branch, ["--set-upstream"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/* ------------------------------------------------------------------ *
 * GitHub — @octokit/rest
 * ------------------------------------------------------------------ */

interface OctokitLike {
  pulls: {
    create(params: {
      owner: string;
      repo: string;
      title: string;
      head: string;
      base: string;
      body?: string;
      draft?: boolean;
    }): Promise<{ data: { html_url: string; number: number } }>;
  };
}
interface OctokitCtor {
  new (opts: { auth?: string; baseUrl?: string }): OctokitLike;
}

export interface GitHubOpenerOptions {
  /** BYO token (secret) — passed to Octokit, never logged. */
  token: string;
  owner: string;
  repo: string;
  /** GitHub Enterprise API base URL, e.g. https://ghe.internal/api/v3. */
  apiBaseUrl?: string;
  /** Local checkout to stage the patch in. Omit to skip git (branch pre-pushed). */
  workdir?: string;
  remote?: string;
  /** Open PRs as drafts (default true — human review is the point). */
  draft?: boolean;
  logger?: Logger;
  now?: () => string;
}

export class GitHubPullRequestOpener implements PullRequestOpener {
  readonly provider = "github" as const;
  constructor(private readonly opts: GitHubOpenerOptions) {}

  async open(plan: AutoFixPrPlan): Promise<PullRequest> {
    if (plan.branch === plan.baseBranch) {
      throw new Error("refusing to open PR: head branch equals base branch");
    }
    if (this.opts.workdir) {
      await stagePatchOnBranch({
        workdir: this.opts.workdir,
        baseBranch: plan.baseBranch,
        branch: plan.branch,
        patch: plan.patch,
        commitMessage: plan.title,
        ...(this.opts.remote ? { remote: this.opts.remote } : {}),
      });
    }

    const { Octokit } = (await import("@octokit/rest")) as unknown as { Octokit: OctokitCtor };
    const octokit = new Octokit({
      auth: this.opts.token,
      ...(this.opts.apiBaseUrl ? { baseUrl: this.opts.apiBaseUrl } : {}),
    });
    const res = await octokit.pulls.create({
      owner: this.opts.owner,
      repo: this.opts.repo,
      title: plan.title,
      head: plan.branch,
      base: plan.baseBranch,
      body: plan.bodySummary,
      draft: this.opts.draft ?? true,
    });

    this.opts.logger?.info("report.vcs.github.pr_opened", {
      prNumber: res.data.number,
      branch: plan.branch,
    });
    return PullRequestSchema.parse({
      id: plan.prId,
      scanId: plan.scanId,
      clientId: plan.clientId,
      provider: "github",
      url: res.data.html_url,
      number: res.data.number,
      branch: plan.branch,
      baseBranch: plan.baseBranch,
      title: plan.title,
      bodySummary: plan.bodySummary,
      fixIds: plan.fixIds,
      status: (this.opts.draft ?? true) ? "draft" : "open",
      createdAt: (this.opts.now ?? (() => new Date().toISOString()))(),
    });
  }
}

/* ------------------------------------------------------------------ *
 * GitLab — @gitbeaker/rest
 * ------------------------------------------------------------------ */

interface MergeRequestsLike {
  create(
    projectId: string | number,
    sourceBranch: string,
    targetBranch: string,
    title: string,
    options?: { description?: string },
  ): Promise<{ web_url: string; iid: number }>;
}
interface GitlabLike {
  MergeRequests: MergeRequestsLike;
}
interface GitlabCtor {
  new (opts: { host?: string; token: string }): GitlabLike;
}

export interface GitLabOpenerOptions {
  /** BYO token (secret) — passed to gitbeaker, never logged. */
  token: string;
  /** Project id or "group/project" path. */
  projectId: string | number;
  /** GitLab host, e.g. https://gitlab.internal. */
  host?: string;
  workdir?: string;
  remote?: string;
  logger?: Logger;
  now?: () => string;
}

export class GitLabPullRequestOpener implements PullRequestOpener {
  readonly provider = "gitlab" as const;
  constructor(private readonly opts: GitLabOpenerOptions) {}

  async open(plan: AutoFixPrPlan): Promise<PullRequest> {
    if (plan.branch === plan.baseBranch) {
      throw new Error("refusing to open MR: source branch equals target branch");
    }
    if (this.opts.workdir) {
      await stagePatchOnBranch({
        workdir: this.opts.workdir,
        baseBranch: plan.baseBranch,
        branch: plan.branch,
        patch: plan.patch,
        commitMessage: plan.title,
        ...(this.opts.remote ? { remote: this.opts.remote } : {}),
      });
    }

    const { Gitlab } = (await import("@gitbeaker/rest")) as unknown as { Gitlab: GitlabCtor };
    const api = new Gitlab({
      token: this.opts.token,
      ...(this.opts.host ? { host: this.opts.host } : {}),
    });
    const mr = await api.MergeRequests.create(
      this.opts.projectId,
      plan.branch,
      plan.baseBranch,
      plan.title,
      { description: plan.bodySummary },
    );

    this.opts.logger?.info("report.vcs.gitlab.mr_opened", {
      iid: mr.iid,
      branch: plan.branch,
    });
    return PullRequestSchema.parse({
      id: plan.prId,
      scanId: plan.scanId,
      clientId: plan.clientId,
      provider: "gitlab",
      url: mr.web_url,
      number: mr.iid,
      branch: plan.branch,
      baseBranch: plan.baseBranch,
      title: plan.title,
      bodySummary: plan.bodySummary,
      fixIds: plan.fixIds,
      status: "open",
      createdAt: (this.opts.now ?? (() => new Date().toISOString()))(),
    });
  }
}

/* ------------------------------------------------------------------ *
 * GitHub PR/issue comment — arbitrary-PR annotation (A15).
 *
 * Distinct from `GitHubPullRequestOpener` above: that class OPENS the
 * auto-fix PR itself (golden rule #5, PR-only). This helper instead posts a
 * COMMENT on a PR that already exists — e.g. the PR a webhook-triggered
 * diff-mode scan (`POST /webhooks/scan-trigger`, apps/api) was raised for.
 * GitHub's REST API models PR comments as issue comments (a PR *is* an issue
 * for this endpoint), so `@octokit/rest`'s `issues.createComment` is the
 * correct, minimal surface — no new dependency, same lazy-import pattern as
 * `GitHubPullRequestOpener`.
 *
 * Deliberately a single summary comment, not per-line review annotations —
 * per-line `pulls.createReview` requires diff-position math (which file/line
 * a comment anchors to) that is out of scope here; a summary comment is the
 * scoped-down, real, working piece (see docs/plan/26-08-22-tasks-ai-depth.md
 * A15 notes).
 * ------------------------------------------------------------------ */

interface OctokitIssuesLike {
  issues: {
    createComment(params: {
      owner: string;
      repo: string;
      issue_number: number;
      body: string;
    }): Promise<{ data: { html_url: string; id: number } }>;
  };
}
interface OctokitIssuesCtor {
  new (opts: { auth?: string; baseUrl?: string }): OctokitIssuesLike;
}

export interface GitHubCommentOptions {
  /** BYO token (secret) — passed to Octokit, never logged. */
  token: string;
  owner: string;
  repo: string;
  /** PR number (GitHub PR numbers and issue numbers share one namespace). */
  issueNumber: number;
  body: string;
  /** GitHub Enterprise API base URL, e.g. https://ghe.internal/api/v3. */
  apiBaseUrl?: string;
  logger?: Logger;
}

/** Post one summary comment on an arbitrary GitHub PR (or issue). */
export async function postGitHubComment(opts: GitHubCommentOptions): Promise<{ url: string }> {
  const { Octokit } = (await import("@octokit/rest")) as unknown as { Octokit: OctokitIssuesCtor };
  const octokit = new Octokit({
    auth: opts.token,
    ...(opts.apiBaseUrl ? { baseUrl: opts.apiBaseUrl } : {}),
  });
  const res = await octokit.issues.createComment({
    owner: opts.owner,
    repo: opts.repo,
    issue_number: opts.issueNumber,
    body: opts.body,
  });

  opts.logger?.info("report.vcs.github.comment_posted", {
    owner: opts.owner,
    repo: opts.repo,
    issueNumber: opts.issueNumber,
  });
  return { url: res.data.html_url };
}
