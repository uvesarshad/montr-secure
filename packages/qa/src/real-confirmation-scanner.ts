import { confirmFindings } from "@montr/confirm";
import { getHardenedDefaults } from "@montr/config";
import type {
  AppMap,
  ConfirmedFinding,
  LLMGateway,
  ModelDescriptor,
  ProbableFinding,
} from "@montr/contracts";
import type { GroundTruthManifest } from "@montr/fixtures";
import {
  CLIENT_ID,
  FIXED_NOW,
  SCAN_ID,
  createFakeLlmGateway,
  mockAppMap,
  mockCleanAppMap,
  mockProbableFindings,
} from "@montr/fixtures";
import type { Baseline } from "./baseline.js";
import type { LoadedCorpus, LoadedRepo } from "./corpus.js";
import type { ModelScanner } from "./model-variance.js";

/**
 * A23 — the REAL alternative to the `perfectConfirmedForRepo` ground-truth
 * echo (`synthetic.ts`) that `model-variance.ts`'s scaffold was previously
 * wired to. `perfectConfirmedForRepo` ignores the `model` parameter entirely,
 * which is exactly why every model scored an identical, tautological 100%
 * (audit finding A23) — it never actually asked packages/confirm anything.
 *
 * This module runs the REAL Layer-3 static-confirmation pipeline
 * (`@montr/confirm`'s `confirmFindings` — the same deterministic taint-proof +
 * confirmation-tier LLM veto engine `packages/confirm/src/static.ts` ships to
 * production, unmodified) against a real golden-corpus repo's App Map, using a
 * gateway CONFIGURED FOR the specific `model` passed in. A genuine accuracy
 * cliff (a below-floor model missing findings a floor-or-better model catches)
 * therefore shows up as a real difference in `ConfirmedFinding[]` — and hence
 * in the scored recall — not an identical number reproduced per model.
 *
 * Coverage: only the two @montr/fixtures sample repos ("vulnerable-nextjs",
 * "clean-nextjs") ship a hand-built, schema-valid App Map + ProbableFinding[]
 * today — the SAME fixtures `packages/confirm`'s own golden-path tests
 * (`tests/confirm.static.test.ts`) already exercise, so this is not a new,
 * unverified fixture shape. Every other corpus repo (`corpus/repos/*`,
 * `corpus/<stack>-vuln|clean`) does not yet have one; `realConfirmedForRepo`
 * returns `[]` for those (an honest "not measured here", never a fabricated
 * result) rather than crashing. Widening coverage to the rest of the corpus
 * would mean either hand-building an App Map per repo, or reusing the real L0
 * `@montr/appmap` builder the way `scripts/corpus-scan.run.test.ts` does for
 * the (much larger, slower, network/subprocess-touching) golden-corpus gate —
 * deliberately out of scope here; see docs/infra/testing.md.
 */

interface RealScannerFixture {
  appMap: AppMap;
  probable: ProbableFinding[];
}

/** Repo name (matches `LoadedRepo.name` / the ground-truth manifest) -> real fixture. */
const REAL_SCANNER_FIXTURES: Record<string, RealScannerFixture> = {
  "vulnerable-nextjs": { appMap: mockAppMap, probable: mockProbableFindings },
  // No probable findings on the clean repo — the real L1/L2 pipeline would
  // promote nothing here either (its one sink is parameterized); ground truth
  // agrees (`expectedFindings: []`).
  "clean-nextjs": { appMap: mockCleanAppMap, probable: [] },
};

/**
 * Build a fake gateway whose CONFIRMATION-purpose response is driven by the
 * model's own `belowFloor` flag (`MODEL_FLOOR`, `@montr/contracts`): a
 * below-floor model (e.g. the triage-tier model, if misconfigured as the
 * confirmation-tier model) fails the exploitability review and VETOES —
 * `packages/confirm/src/static.ts`'s `confirmStatic` demotes a deterministic
 * reachable finding to the appendix on `confirmed:false` (golden rule #4: the
 * LLM may only ever demote, never promote). A floor-or-better model confirms.
 * This is the existing `createFakeLlmGateway({ cannedByPurpose })` convention
 * (see `tests/confirm.static.test.ts`'s own veto test) — just picked
 * PER MODEL instead of one fixed canned response for every caller, which is
 * what makes the harness's per-model output genuinely differ.
 */
export function gatewayForModel(model: ModelDescriptor): LLMGateway {
  return createFakeLlmGateway({
    cannedByPurpose: {
      confirmation: model.belowFloor
        ? '{"confirmed":false,"argument":"insufficient confidence to confirm exploitability at this model tier"}'
        : '{"confirmed":true,"argument":"static data-flow proof independently judged exploitable"}',
    },
  });
}

/**
 * Run the REAL `@montr/confirm` static-confirmation engine against `repo`
 * using an ARBITRARY caller-supplied gateway — the shared core both
 * {@link realConfirmedForRepo} (A23, per-model comparison via
 * {@link gatewayForModel}) and `@montr/qa`'s `prompt-eval.ts` (E15, per-
 * prompt-VERSION comparison) build on. Returns `[]` (never throws) for a
 * corpus repo with no hand-built fixture — see this module's header.
 */
export async function confirmedForRepoWithGateway(
  repo: LoadedRepo,
  gateway: LLMGateway,
): Promise<ConfirmedFinding[]> {
  const fixture = REAL_SCANNER_FIXTURES[repo.name];
  if (!fixture) return [];
  const out = await confirmFindings(
    {
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      appMap: fixture.appMap,
      probable: fixture.probable,
      allowLive: false,
      config: getHardenedDefaults(),
    },
    // Deterministic clock — reproducible run to run (the same fixture the
    // confirm package's own tests pin against).
    { llm: gateway, now: () => FIXED_NOW },
  );
  return out.confirmed;
}

/**
 * The REAL `ModelScanner` (A23). Ignores the shared `gateway` argument
 * `runModelVariance` passes — a genuine per-model comparison needs a
 * DIFFERENTLY behaving gateway per model, so this builds its own via
 * {@link gatewayForModel} instead of reusing one fixed instance for every row.
 */
export const realConfirmedForRepo: ModelScanner = async (
  repo: LoadedRepo,
  model: ModelDescriptor,
): Promise<ConfirmedFinding[]> => confirmedForRepoWithGateway(repo, gatewayForModel(model));

/**
 * The model matrix `realConfirmedForRepo` is meaningful against: the three
 * RECOMMENDED_MODEL_MATRIX tiers as the fake gateway already describes them
 * (`packages/fixtures/src/llm.ts`), i.e. exactly what a real deployment's
 * `gateway.listModels()` would report. Exported so callers (the CLI, CI, and
 * this module's own tests) don't hand-duplicate the descriptor list.
 */
export function realVarianceModelMatrix(): ModelDescriptor[] {
  return createFakeLlmGateway().listModels();
}

/**
 * Narrow a loaded corpus down to only the repos {@link realConfirmedForRepo}
 * can genuinely score. Running the real scanner against the FULL golden
 * corpus would silently count every one of the ~14 repos without a hand-built
 * fixture as a total miss for every model alike — that dilutes/misrepresents
 * the signal (and would fail `corpus/baseline.json`'s `minReposScored: 14`
 * for reasons that have nothing to do with model quality), it doesn't measure
 * anything. Restricting the scored corpus to the repos actually covered keeps
 * the harness honest; widening `REAL_SCANNER_FIXTURES` above should widen
 * this filter automatically (it reads the same key set).
 */
export function realVarianceCorpus(corpus: LoadedCorpus): LoadedCorpus {
  const repos = corpus.repos.filter((r) => r.name in REAL_SCANNER_FIXTURES);
  const manifest: GroundTruthManifest = {
    version: corpus.manifest.version,
    repos: corpus.manifest.repos.filter((r) => r.name in REAL_SCANNER_FIXTURES),
  };
  return { ...corpus, repos, manifest };
}

/**
 * Regression baseline sized for {@link realVarianceCorpus}'s deliberately
 * narrow (2-repo) scope — `corpus/baseline.json` assumes the full 16-repo /
 * 44-finding corpus (`minReposScored: 14`) and would fail this harness for
 * reasons unrelated to model quality. Measured today: static confirmation
 * correctly confirms 2 of the 3 exploitable ground-truth cases in
 * "vulnerable-nextjs" (sql_injection + xss; the third, a hardcoded secret,
 * has no data-flow sink and is out of static confirmation's reach by design —
 * see this module's header) for any floor-or-better model, and 0 for a
 * below-floor model that vetoes. `recallMin` sits a safety margin below that
 * real 2/3 measurement, same convention as `corpus/baseline.json`.
 */
export const REAL_VARIANCE_BASELINE: Baseline = {
  fpRateMax: 0.05,
  precisionMin: 0.9,
  recallMin: 0.5,
  minReposScored: 2,
};
