/**
 * E1 + E2 + E4, wired together as ONE coherent alternate path to `confirmed`.
 *
 * This is the piece `confirm.ts` calls when BOTH the deterministic static
 * proof and live DAST failed to confirm a finding. It is the only place in
 * this package where all three enhancements meet, and it is where the one
 * hard invariant lives:
 *
 *   Nothing reaches `confirmed: true` through this path unless ALL of the
 *   following hold:
 *     1. E1 — the investigation loop (`investigate.ts`) concluded
 *        "confirmed_candidate" (never on budget exhaustion — see that file).
 *     2. E2 — `evidence.ts` produced REAL executable evidence for that exact
 *        candidate: an existing repo test that FAILS against current code.
 *        No evidence ⇒ stop here, finding stays unconfirmed. A model's
 *        opinion alone (step 1) is NEVER sufficient by itself.
 *     3. E4 — `adversarial.ts`'s N-verifier panel (including an explicit
 *        refutation lens) reached a STRICT MAJORITY confirm vote over the
 *        combined candidate + evidence. Disagreement ⇒ stop here too.
 *
 * Any failure at any step returns `undefined` and `confirm.ts` falls through
 * to its existing (unchanged) unconfirmed-appendix path — this module can
 * only ever ADD a confirmation on top of full proof, never subtract from the
 * existing deterministic/live paths, which do not call this file at all.
 */
import type {
  AppMap,
  ConfirmedFinding,
  ProbableFinding,
  Route,
  StaticProof,
} from "@montr/contracts";
import { assembleConfirmed } from "./static.js";
import { gatherExecutableEvidence, type ExecutableEvidence } from "./evidence.js";
import { runAdversarialVerification, type AdversarialOutcome } from "./adversarial.js";
import { runInvestigation, type InvestigationOutcome } from "./investigate.js";
import type { ConfirmDeps, ConfirmInput } from "./types.js";

export interface InvestigationPathResult {
  finding: ConfirmedFinding;
  investigation: InvestigationOutcome;
  evidence: ExecutableEvidence;
  adversarial: AdversarialOutcome;
}

function findRouteForInvestigation(
  appMap: AppMap,
  finding: ProbableFinding,
  targetRouteId: string | undefined,
): Route | undefined {
  if (targetRouteId) {
    const byId = appMap.routes.find((r) => r.id === targetRouteId);
    if (byId) return byId;
  }
  if (finding.routeId) {
    const byFindingRoute = appMap.routes.find((r) => r.id === finding.routeId);
    if (byFindingRoute) return byFindingRoute;
  }
  return appMap.routes.find((r) => r.handler?.file === finding.location.file);
}

function buildInvestigationArgument(
  finding: ProbableFinding,
  investigation: InvestigationOutcome,
  evidence: ExecutableEvidence,
  adversarial: AdversarialOutcome,
): string {
  const verifierLines = adversarial.verdicts
    .map((v) => `  - ${v.lens}: ${v.confirm ? "CONFIRM" : "reject"} — ${v.rationale}`)
    .join("\n");
  return [
    "Agentic investigation proof (E1 investigation + E2 executable evidence + E4 adversarial majority):",
    `Investigator's rationale: ${investigation.rationale}`,
    investigation.ownershipCheckFound === false
      ? "The investigator actively looked for an ownership/authorization check and did NOT find one."
      : undefined,
    `Executable evidence (${evidence.kind}): ${evidence.summary}`,
    `Adversarial verifier panel: ${adversarial.confirmVotes}/${adversarial.totalVerifiers} confirmed (required ${adversarial.requiredVotes}):`,
    verifierLines,
    `Exploit hypothesis: ${finding.exploitHypothesis}`,
  ]
    .filter((l): l is string => Boolean(l))
    .join("\n");
}

/**
 * Attempt the full E1→E2→E4 path for one finding that neither static nor
 * live confirmation could resolve. Returns `undefined` at the first gate
 * that isn't cleared (no `deps.llm`, investigation not enabled, verdict not
 * `confirmed_candidate`, no executable evidence, or no adversarial
 * majority) — every one of those is a normal, expected outcome, not an
 * error, and `confirm.ts` treats it identically to "static/live didn't
 * confirm either" (fail-safe by construction).
 */
export async function attemptInvestigationConfirmation(
  finding: ProbableFinding,
  input: ConfirmInput,
  deps: ConfirmDeps,
  priorStaticReason: string | undefined,
): Promise<InvestigationPathResult | undefined> {
  if (!deps.llm || !deps.investigation?.enabled) return undefined;

  const investigation = await runInvestigation(finding, input, deps, priorStaticReason);
  if (investigation.verdict !== "confirmed_candidate") return undefined;

  const evidence = await gatherExecutableEvidence({
    ...(input.repoRoot ? { repoRoot: input.repoRoot } : {}),
    ...(investigation.existingTestFile ? { existingTestFile: investigation.existingTestFile } : {}),
    ...(deps.testRunner ? { testRunner: deps.testRunner } : {}),
  });
  if (!evidence) return undefined; // E2 gate: no proof, no promotion — a model's opinion is never enough.

  const adversarial = await runAdversarialVerification(
    deps,
    input,
    {
      id: finding.id,
      category: finding.category,
      exposure: finding.exposure,
      location: finding.location,
    },
    investigation.rationale,
    evidence.summary,
  );
  if (!adversarial || !adversarial.confirmed) return undefined; // E4 gate: no majority, no promotion.

  const route = findRouteForInvestigation(input.appMap, finding, investigation.targetRouteId);
  const proof: StaticProof = {
    kind: "static",
    argument: buildInvestigationArgument(finding, investigation, evidence, adversarial),
    dataFlow: [
      {
        location: finding.location,
        authState: route?.authState ?? "unknown",
        transform: "agentic investigation (E1) — read the handler + traced the flow across files",
      },
    ],
    sanitizersBypassed: [],
  };
  const assembled = assembleConfirmed(finding, route, undefined, proof, "static", deps);
  return { finding: assembled, investigation, evidence, adversarial };
}
