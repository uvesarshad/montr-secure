/**
 * E13 — Real proof-of-fix in an ephemeral container, closing A22.
 *
 * `patch.ts`'s `validatePatch` is real (a `.proof-of-fix.test.ts` executed
 * twice through a genuine `vitest` subprocess), but its test body is a
 * filesystem read plus `expect(source).not.toMatch(vulnerable)` — it proves
 * the vulnerable PATTERN is gone from the file, not that the application is
 * secure at runtime (A22).
 *
 * `validatePatchWithContainerReplay` is a STRICT, ADDITIVE upgrade over
 * `validatePatch` (same `PatchValidation` shape, plus an optional
 * `containerReplay` evidence block — see `ContainerPatchValidation` below):
 *
 *  - When the finding being fixed has a REAL live-DAST proof artifact (a
 *    `ConfirmedFinding.proofArtifact` of kind `"live"`, produced by
 *    `packages/confirm/src/live.ts`) AND the caller supplies a filesystem
 *    checkout of the full target application (`targetRepoDir` — `validatePatch`
 *    only ever sees one file's source, but a container needs the whole app),
 *    this function builds/starts a genuinely ephemeral container from the
 *    PRE-patch source, replays the EXACT SAME probe the live-DAST engine
 *    already ran (`exploit-replay.ts`'s `pickReplayExchange` +
 *    `rewriteRequestForContainer`) and asserts it reproduces the recorded
 *    exploit evidence; then rebuilds from the POST-patch source and asserts
 *    the SAME probe no longer reproduces it. `failsPrePatch`/`passesPostPatch`
 *    are derived from this REAL runtime exploit outcome, not a regex.
 *  - Otherwise — a static-proof-only or investigation-path confirmation with
 *    no live-DAST transcript to replay, no `targetRepoDir` supplied, or an
 *    empty transcript — this is a STRICT fallback (requirement 4): it calls
 *    the EXISTING `validatePatch` mechanism unchanged. Coverage for findings
 *    without live evidence is never broken by this upgrade.
 *  - If container replay is attempted but the container infrastructure itself
 *    fails (docker unavailable, build/start error, readiness timeout — the
 *    harness in `container-harness.ts` is already fail-closed and always
 *    tears down on any of these), this function ALSO degrades to the existing
 *    `validatePatch` mechanism rather than failing the whole fix outright —
 *    but it reports the container attempt's error on `containerReplay.error`
 *    so the degrade is visible, never silent.
 */
import { applyPatch } from "diff";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, sep } from "node:path";

import type { ConfirmedFinding, ContainerReplayEvidence, HttpExchange } from "@montr/contracts";

import {
  countChangedLines,
  validatePatch,
  type PatchValidation,
  type ValidatePatchOptions,
} from "./patch.js";
import { startEphemeralContainer, type ContainerHarnessKind } from "./container-harness.js";
import {
  exploitEvidenceMatches,
  pickReplayExchange,
  replayAgainstContainer,
  rewriteRequestForContainer,
  truncateForEvidence,
} from "./exploit-replay.js";

export type { ContainerReplayEvidence } from "@montr/contracts";

/** The `prePatch`/`postPatch` phase shape inside `ContainerReplayEvidence` —
 * pulled out here purely for local readability (same Zod-inferred type). */
export type ContainerReplayPhaseEvidence = NonNullable<ContainerReplayEvidence["prePatch"]>;

export interface ContainerPatchValidation extends PatchValidation {
  containerReplay: ContainerReplayEvidence;
}

export interface ValidatePatchWithContainerReplayOptions extends ValidatePatchOptions {
  /** The finding this patch fixes. Container replay only engages when its
   * `proofArtifact.kind === "live"` and the transcript is non-empty. */
  confirmedFinding?: ConfirmedFinding;
  /** Filesystem checkout of the FULL target application (build context) — the
   * file at `filePath` inside it is overwritten with the exact source under
   * test before each container build, mirroring how `patch.ts` writes the
   * exact source into its vitest temp workspace. */
  targetRepoDir?: string;
  /** Shared timeout budget (ms) for EACH container lifecycle (pre- and
   * post-patch are budgeted independently). Default 120_000. */
  containerTimeoutMs?: number;
  /** Override the docker binary (tests may point this at a stub). */
  dockerBin?: string;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function copyRepoExcludingHeavyDirs(src: string, dest: string): Promise<void> {
  await cp(src, dest, {
    recursive: true,
    filter: (source) => {
      const rel = relative(src, source);
      if (rel === "") return true;
      const segments = rel.split(sep);
      return !segments.includes("node_modules") && !segments.includes(".git");
    },
  });
}

interface ContainerPhaseResult {
  matched: boolean;
  replayExchange: HttpExchange;
  harness: ContainerHarnessKind;
}

/** Build + start ONE ephemeral container from `source` written at `filePath`
 * inside a disposable copy of `repoDir`, replay `exchange`, then always tear
 * the container (and the disposable copy) down. */
async function runContainerPhase(opts: {
  repoDir: string;
  filePath: string;
  source: string;
  exchange: HttpExchange;
  timeoutMs: number;
  dockerBin?: string;
}): Promise<ContainerPhaseResult> {
  const workDir = await mkdtemp(join(tmpdir(), "montr-fix-container-"));
  let running: Awaited<ReturnType<typeof startEphemeralContainer>> | undefined;
  try {
    await copyRepoExcludingHeavyDirs(opts.repoDir, workDir);
    const targetAbs = join(workDir, opts.filePath);
    await mkdir(dirname(targetAbs), { recursive: true });
    await writeFile(targetAbs, opts.source, "utf8");

    running = await startEphemeralContainer({
      repoDir: workDir,
      timeoutMs: opts.timeoutMs,
      ...(opts.dockerBin ? { dockerBin: opts.dockerBin } : {}),
    });

    const req = rewriteRequestForContainer(opts.exchange, running.baseUrl);
    const replay = await replayAgainstContainer(req, opts.timeoutMs);
    const matched = exploitEvidenceMatches(opts.exchange, replay);

    const replayExchange: HttpExchange = {
      request: {
        method: req.method,
        url: req.url,
        ...(req.headers ? { headers: req.headers } : {}),
        ...(req.body !== undefined ? { bodySnippet: truncateForEvidence(req.body) } : {}),
      },
      response: {
        status: replay.status,
        headers: replay.headers,
        bodySnippet: truncateForEvidence(replay.body),
      },
      note: matched
        ? "container replay reproduced the recorded exploit evidence"
        : "container replay did NOT reproduce the recorded exploit evidence",
    };

    return { matched, replayExchange, harness: running.harness };
  } finally {
    if (running) await running.stop().catch(() => undefined);
    await rm(workDir, { recursive: true, force: true });
  }
}

async function fallbackToVitest(
  original: string,
  patch: string,
  options: ValidatePatchOptions,
  extra: Partial<ContainerReplayEvidence>,
): Promise<ContainerPatchValidation> {
  const base = await validatePatch(original, patch, options);
  return { ...base, containerReplay: { attempted: false, replayed: false, ...extra } };
}

/**
 * See the module doc comment for the full contract. Real container replay
 * only ever engages when there is real live-DAST evidence AND a real target
 * checkout to build from; every other case is the existing, unchanged
 * `validatePatch` mechanism.
 */
export async function validatePatchWithContainerReplay(
  original: string,
  patch: string,
  options: ValidatePatchWithContainerReplayOptions,
): Promise<ContainerPatchValidation> {
  const finding = options.confirmedFinding;

  if (!finding) {
    return fallbackToVitest(original, patch, options, {
      reason: "no confirmed finding supplied; using the vitest-subprocess proof",
    });
  }
  if (finding.proofArtifact.kind !== "live") {
    return fallbackToVitest(original, patch, options, {
      reason:
        `confirmed finding has a "${finding.proofArtifact.kind}" proof artifact, not "live"; ` +
        "using the vitest-subprocess proof (E13's container replay only ever engages when a " +
        "real live-DAST exploit transcript exists to replay)",
    });
  }
  if (finding.proofArtifact.transcript.length === 0) {
    return fallbackToVitest(original, patch, options, {
      reason: "confirmed finding's live-DAST proof artifact has an empty transcript",
    });
  }
  if (!options.targetRepoDir) {
    return fallbackToVitest(original, patch, options, {
      reason:
        "live-DAST evidence exists but no targetRepoDir (a checkout of the full target " +
        "application) was supplied; a single file's source is not enough to build a container",
    });
  }

  const exchange = pickReplayExchange(finding.proofArtifact.transcript);
  if (!exchange) {
    return fallbackToVitest(original, patch, options, {
      reason: "no replayable exchange found in the live-DAST transcript",
    });
  }

  const applied = applyPatch(original, patch);
  const applies = applied !== false;
  const appliedSource = applies ? applied : null;
  const changedLines = countChangedLines(patch);
  const timeoutMs = options.containerTimeoutMs ?? 120_000;
  const probeReplayed = { method: exchange.request.method, url: exchange.request.url };

  let pre: ContainerReplayPhaseEvidence | undefined;
  let post: ContainerReplayPhaseEvidence | undefined;
  let harness: ContainerHarnessKind | undefined;
  let hardError: string | undefined;

  try {
    const preResult = await runContainerPhase({
      repoDir: options.targetRepoDir,
      filePath: options.filePath,
      source: original,
      exchange,
      timeoutMs,
      ...(options.dockerBin ? { dockerBin: options.dockerBin } : {}),
    });
    harness = preResult.harness;
    pre = { exploitSucceeded: preResult.matched, exchange: preResult.replayExchange };
  } catch (err) {
    hardError = `pre-patch container replay failed: ${errMsg(err)}`;
  }

  if (!hardError && applies && appliedSource !== null) {
    try {
      const postResult = await runContainerPhase({
        repoDir: options.targetRepoDir,
        filePath: options.filePath,
        source: appliedSource,
        exchange,
        timeoutMs,
        ...(options.dockerBin ? { dockerBin: options.dockerBin } : {}),
      });
      harness = postResult.harness;
      post = { exploitSucceeded: postResult.matched, exchange: postResult.replayExchange };
    } catch (err) {
      hardError = `post-patch container replay failed: ${errMsg(err)}`;
    }
  }

  if (hardError) {
    // Fail closed on container infra failure (never claim a container-backed
    // proof), but never leave the fix without ANY evidence — degrade honestly
    // to the vitest mechanism, same as the "no live evidence" fallback above,
    // just with the container attempt's own error attached and visible.
    return fallbackToVitest(original, patch, options, {
      attempted: true,
      category: finding.category,
      ...(harness ? { harness } : {}),
      probeReplayed,
      ...(pre ? { prePatch: pre } : {}),
      ...(post ? { postPatch: post } : {}),
      error: hardError,
    });
  }

  return {
    applies,
    appliedSource,
    failsPrePatch: pre?.exploitSucceeded ?? false,
    passesPostPatch: applies ? post?.exploitSucceeded === false : false,
    changedLines,
    containerReplay: {
      attempted: true,
      replayed: true,
      category: finding.category,
      ...(harness ? { harness } : {}),
      probeReplayed,
      ...(pre ? { prePatch: pre } : {}),
      ...(post ? { postPatch: post } : {}),
    },
  };
}
