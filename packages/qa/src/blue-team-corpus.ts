/**
 * B12 — the blue-team golden corpus: a hand-labelled ground truth of "given
 * this real red-team scenario from the catalogue and the real B3-generated
 * Sigma detection rule for its target finding category, does that rule
 * STRUCTURALLY fire against the scenario's real request shape?" This is the
 * blue-team mirror of `corpus/baseline.json` — the golden corpus measures
 * whether the pipeline confirms real vulnerabilities; this corpus measures
 * whether B3's generated detection rules would actually have caught the
 * red-team scenarios B5's purple-loop runs (packages/confirm/src/purple-loop.ts).
 *
 * SCOPE (honest, not exhaustive): `REDTEAM_SCENARIO_CATALOGUE`
 * (packages/state-store/src/redteam-catalogue.ts) has 13 templates. 9 of the
 * 13 (69%) are labelled here — the ones with a single, coherent target
 * route/method a B3 rule could plausibly be generated for. The 4 EXCLUDED
 * templates (`owasp-a02-crypto-failures`, `owasp-a05-security-misconfiguration`,
 * `owasp-a06-vulnerable-components`, `owasp-a09-logging-monitoring`) each probe
 * SEVERAL structurally unrelated endpoints for several distinct sub-checks
 * (e.g. A05 hits `/api/products/%00malformed`, `/actuator/env`,
 * `/swagger.json`, and an `OPTIONS /` probe in one scenario) — there is no
 * single coherent "target route" a real confirmed finding's App-Map-resolved
 * route would represent, so any ground-truth label for them would be an
 * arbitrary pick among several unrelated targets dressed up as a reasoned
 * trace. Labelling only the 9 scenarios with an honest, traceable target is a
 * smaller but REAL corpus, not a padded one (see this task's brief: "a real,
 * reasoned ground-truth label, not a guess").
 *
 * HOW EACH GROUND-TRUTH LABEL WAS DERIVED (traced by hand against the REAL
 * evaluator, `evaluateSigmaRule`/`evaluateDetectionRuleAgainstScenario` in
 * packages/confirm/src/purple-loop.ts, and the REAL rule generator,
 * `buildRuleContext`/`buildSigmaRule` in packages/report/src/detection-rules):
 *
 *   1. `buildFromStaticProof` (context.ts) resolves a `Route` for the finding
 *      via `resolveRoute` — a literal match of `route.handler.file ===
 *      finding.location.file`. So each case below builds ONE `AppMap` route
 *      whose `handler.file` matches the paired `ConfirmedFinding.location.file`,
 *      with `route.path`/`route.method` set to the scenario's real target
 *      endpoint (taken verbatim from the catalogue template's own
 *      `RedTeamStep.path`/`method` — never invented).
 *   2. `CATEGORY_MARKERS` (context.ts) either DOES or DOES NOT have an entry
 *      for the finding's category:
 *        - NO entry (idor, broken_access_control, mass_assignment,
 *          broken_authentication) => `buildSigmaRule` emits
 *          `condition: selection_route` alone — the rule fires on ANY request
 *          matching path-prefix + method, no payload required.
 *        - AN entry (sql_injection, command_injection, xss,
 *          insecure_deserialization, ssrf) => the rule additionally requires
 *          `1 of selection_payload_*` — a marker substring in the query
 *          string OR body.
 *   3. The scenario's OWN steps (verbatim from `REDTEAM_SCENARIO_CATALOGUE`,
 *      never hand-edited) are walked in order: does ANY step's concretized
 *      request (via `scenarios.ts`'s `concretePath` — `[id]`/`:id` segments
 *      become `1`) match path-prefix + method, AND (when markers are
 *      required) contain a marker substring in its query string? `runScenario`
 *      never sends a request body (`RedTeamStep` carries no body field —
 *      documented in confirmation.md's B5 AGENT NOTE), so a marker that only
 *      ever appears in a POST body in the scenario's real-world narrative
 *      (not literally encoded into `RedTeamStep.path`) can never be found —
 *      three of the nine labelled cases below (`A03_CMD_INJECTION`,
 *      `A08_INTEGRITY_FAILURES`, `A10_SSRF`) are genuine, structural MISSES
 *      for exactly this reason, not mislabelled.
 *
 * `runBlueTeamCorpus` below does not hand-compute the aggregate — it
 * ACTUALLY invokes the real `generateDetectionRules` (B3) and the real
 * `runPurpleTeamScenario` (B5) for every case and reports what really
 * happened, which `scripts/blue-team-corpus-scan.mjs` then compares against
 * the `expectedFired` labels below.
 */
import {
  AppMapSchema,
  ConfirmedFindingSchema,
  type AppMap,
  type Category,
  type ConfirmedFinding,
  type DetectionRule,
  type RedTeamScenario,
} from "@montr/contracts";
import { getHardenedDefaults, type MontrConfig } from "@montr/config";
import {
  instantiateScenario,
  REDTEAM_SCENARIO_CATALOGUE,
  type RedTeamScenarioTemplate,
} from "@montr/state-store";
import { generateDetectionRules } from "@montr/report";
import {
  runPurpleTeamScenario,
  type LiveHttpTransport,
  type RunPurpleTeamScenarioDeps,
} from "@montr/confirm";

export const BLUE_TEAM_STAGING_TARGET = "https://staging.blue-team-corpus.test";
export const BLUE_TEAM_CLIENT_ID = "client_blue_team_corpus";
const FIXED_NOW = "2026-08-22T00:00:00.000Z";

/** One hand-labelled ground-truth case (see module header for how it was traced). */
export interface BlueTeamGroundTruthCase {
  /** `RedTeamScenarioTemplate.key` in REDTEAM_SCENARIO_CATALOGUE — never re-authored. */
  templateKey: string;
  /** The finding category the scenario is verifying detection coverage for. */
  findingCategory: Category;
  /** Route this case's synthetic finding resolves to (verbatim from the template's own steps). */
  targetRoute: { path: string; method: string };
  /** `Route.handler.file` / `ConfirmedFinding.location.file` — links the two records (resolveRoute's match key). */
  handlerFile: string;
  /** Expected structural verdict, hand-traced against the real evaluator (see module header). */
  expectedFired: boolean;
  /** Human-readable trace of WHY, for the corpus JSON / CI failure output. */
  expectedReason: string;
}

/**
 * The labelled subset — 9 of the 13 REDTEAM_SCENARIO_CATALOGUE templates (see
 * module header for the 4 excluded and why). Ordered to match the catalogue's
 * own OWASP-Top-10 ordering.
 */
export const BLUE_TEAM_GROUND_TRUTH: readonly BlueTeamGroundTruthCase[] = [
  {
    templateKey: "owasp-a01-idor",
    findingCategory: "idor",
    targetRoute: { path: "/api/orders/[id]", method: "GET" },
    handlerFile: "app/api/orders/[id]/route.ts",
    expectedFired: true,
    expectedReason:
      "idor has no CATEGORY_MARKERS entry, so buildSigmaRule emits condition: selection_route alone (no payload gate). " +
      "Step 0 (GET /api/orders/:ownResourceId, the scenario's own baseline request) already concretizes to GET " +
      "/api/orders/1, which matches the route's path-prefix + method on its own — fires before the cross-user " +
      "payload in step 1 is even reached.",
  },
  {
    templateKey: "owasp-a01-privilege-escalation",
    findingCategory: "broken_access_control",
    targetRoute: { path: "/api/admin/users/[targetUserId]/role", method: "POST" },
    handlerFile: "app/api/admin/users/[id]/role/route.ts",
    expectedFired: true,
    expectedReason:
      "broken_access_control has no CATEGORY_MARKERS entry — route-only condition. Step 1 (POST " +
      "/api/admin/users/:targetUserId/role with a standard-user token) concretizes to POST " +
      "/api/admin/users/1/role, matching path-prefix + method — fires.",
  },
  {
    templateKey: "owasp-a03-sql-injection",
    findingCategory: "sql_injection",
    targetRoute: { path: "/api/products", method: "GET" },
    handlerFile: "app/api/products/route.ts",
    expectedFired: true,
    expectedReason:
      'sql_injection has CATEGORY_MARKERS including "UNION SELECT" — condition requires route+method AND a ' +
      "payload marker in the query string. Step 4's path literally embeds " +
      '"?id=-1 UNION SELECT NULL,version(),NULL--" — the decoded query string contains "UNION SELECT" ' +
      "case-insensitively — fires (steps 0-3's payloads use markers not in the CATEGORY_MARKERS list, e.g. " +
      '"pg_sleep(5)" != "SLEEP(5)--", so step 4 is the actual firing exchange).',
  },
  {
    templateKey: "owasp-a03-command-injection",
    findingCategory: "command_injection",
    targetRoute: { path: "/api/reports/export", method: "POST" },
    handlerFile: "app/api/reports/export/route.ts",
    expectedFired: false,
    expectedReason:
      'command_injection has CATEGORY_MARKERS (e.g. "&& id", "$(id)") — condition requires a marker in the ' +
      'query string or body. All 3 of this scenario\'s steps use the IDENTICAL literal path "/api/reports/export" ' +
      "with no query string (the narrative describes the payload going into a POST body/form field, but " +
      "RedTeamStep carries no body field and runScenario's transport.send call never sends one — the documented " +
      "B5 structural gap). Route matches on every step; no marker is ever findable — does NOT fire.",
  },
  {
    templateKey: "owasp-a03-xss",
    findingCategory: "xss",
    targetRoute: { path: "/search", method: "GET" },
    handlerFile: "app/search/page.tsx",
    expectedFired: true,
    expectedReason:
      'xss has CATEGORY_MARKERS including "<script>". Step 1\'s path is ' +
      "\"/search?q=<script>document.title='mtr-xss-poc'</script>\" — the decoded query string literally contains " +
      '"<script>" — fires (step 0\'s canary payload has no script marker, so step 1 is the firing exchange).',
  },
  {
    templateKey: "owasp-a04-business-logic-abuse",
    findingCategory: "mass_assignment",
    targetRoute: { path: "/api/checkout/cart-item", method: "POST" },
    handlerFile: "app/api/checkout/cart-item/route.ts",
    expectedFired: true,
    expectedReason:
      "mass_assignment has no CATEGORY_MARKERS entry — route-only condition. Step 2 (POST " +
      "/api/checkout/cart-item, the client-tampered price/quantity probe) matches path+method exactly — fires. " +
      "(Steps 0/1/3 hit sibling checkout endpoints with DIFFERENT paths, so this case also proves the rule is " +
      "path-SPECIFIC, not a blanket match on the whole scenario.)",
  },
  {
    templateKey: "owasp-a07-auth-failures",
    findingCategory: "broken_authentication",
    targetRoute: { path: "/api/auth/login", method: "POST" },
    handlerFile: "app/api/auth/login/route.ts",
    expectedFired: true,
    expectedReason:
      "broken_authentication has no CATEGORY_MARKERS entry — route-only condition. Step 0 (POST /api/auth/login, " +
      "the lockout-threshold probe) matches path+method on its own — fires.",
  },
  {
    templateKey: "owasp-a08-software-data-integrity",
    findingCategory: "insecure_deserialization",
    targetRoute: { path: "/api/webhooks/receive", method: "POST" },
    handlerFile: "app/api/webhooks/receive/route.ts",
    expectedFired: false,
    expectedReason:
      'insecure_deserialization has CATEGORY_MARKERS (e.g. "__proto__", "rO0AB") — condition requires a ' +
      "marker in the query string or body. All 3 steps use the IDENTICAL literal path " +
      '"/api/webhooks/receive" with no query string (the tampered/altered payload lives in the POST body per ' +
      "the narrative, which runScenario never sends — same structural gap as command_injection above). Route " +
      "matches every step; no marker is ever findable — does NOT fire.",
  },
  {
    templateKey: "owasp-a10-ssrf",
    findingCategory: "ssrf",
    targetRoute: { path: "/api/integrations/webhook-url", method: "POST" },
    handlerFile: "app/api/integrations/webhook-url/route.ts",
    expectedFired: false,
    expectedReason:
      'ssrf has CATEGORY_MARKERS (e.g. "169.254.169.254", "http://localhost") — condition requires a marker ' +
      "in the query string or body. All 4 steps use the IDENTICAL literal path " +
      '"/api/integrations/webhook-url" with no query string (the malicious target URL is the request BODY ' +
      "parameter per the narrative, never sent by runScenario — same structural gap). Route matches every step; " +
      "no marker is ever findable — does NOT fire.",
  },
];

/** Look up a catalogue template by key — throws loudly if the catalogue ever drops one this corpus depends on. */
function templateFor(key: string): RedTeamScenarioTemplate {
  const template = REDTEAM_SCENARIO_CATALOGUE.find((t) => t.key === key);
  if (!template) {
    throw new Error(
      `blue-team-corpus: no REDTEAM_SCENARIO_CATALOGUE template with key "${key}" — the catalogue changed underneath this corpus`,
    );
  }
  return template;
}

/** Build the real, Zod-validated `RedTeamScenario` for a labelled case — steps verbatim from the catalogue template. */
export function buildBlueTeamScenario(caseDef: BlueTeamGroundTruthCase): RedTeamScenario {
  const template = templateFor(caseDef.templateKey);
  return instantiateScenario(template, {
    id: `scn_bluecorp_${template.key}`,
    clientId: BLUE_TEAM_CLIENT_ID,
    targetAllowlistRef: BLUE_TEAM_STAGING_TARGET,
    createdBy: "blue_team_corpus",
    createdAt: FIXED_NOW,
  });
}

/**
 * Build the paired `ConfirmedFinding` + single-route `AppMap` for a labelled
 * case. `finding.location.file === appMap.routes[0].handler.file` is the ONLY
 * signal `resolveRoute` (packages/report/src/detection-rules/route.ts) uses —
 * this is what makes `generateDetectionRules` resolve to `caseDef.targetRoute`
 * exactly, the same way it would for a real confirmed finding.
 */
export function buildBlueTeamFindingAndAppMap(caseDef: BlueTeamGroundTruthCase): {
  finding: ConfirmedFinding;
  appMap: AppMap;
} {
  const template = templateFor(caseDef.templateKey);
  const finding = ConfirmedFindingSchema.parse({
    id: `conf_bluecorp_${template.key}`,
    scanId: "scan_blue_team_corpus",
    clientId: BLUE_TEAM_CLIENT_ID,
    title: `${template.name} — blue-team corpus finding`,
    category: caseDef.findingCategory,
    cwe: [],
    severity: "high",
    exposure: "public",
    location: { file: caseDef.handlerFile, line: 1 },
    impact:
      "Synthetic finding built for the B12 blue-team detection corpus (not a real scan result).",
    proofType: "static",
    proofArtifact: {
      kind: "static",
      argument: `Synthetic static proof for the B12 blue-team corpus case "${template.key}".`,
      dataFlow: [],
      sanitizersBypassed: [],
    },
    createdAt: FIXED_NOW,
  });

  const appMap = AppMapSchema.parse({
    id: `appmap_bluecorp_${template.key}`,
    clientId: BLUE_TEAM_CLIENT_ID,
    scanId: "scan_blue_team_corpus",
    repo: "https://example.internal/blue-team-corpus",
    branch: "main",
    commitSha: "0000000000000000000000000000000000000a",
    createdAt: FIXED_NOW,
    routes: [
      {
        path: caseDef.targetRoute.path,
        method: caseDef.targetRoute.method,
        authState: "unknown",
        isApiRoute: true,
        handler: { file: caseDef.handlerFile, line: 1 },
      },
    ],
  });

  return { finding, appMap };
}

/** A deterministic, in-process fake transport — never touches the network. Mirrors tests/confirm.purple-loop.test.ts's fakeEngine. */
function fakeTransport(): LiveHttpTransport {
  return { send: async () => ({ status: 200, headers: {}, body: "ok" }) };
}

/**
 * `maxMutatingRequests` (the blast-radius cap — packages/config's
 * DastScopeContractSchema) defaults to 0, and `runScenario` (scenarios.ts)
 * HALTS the entire scenario run — not just the one offending step — the
 * moment ANY step is refused by the guard (its per-step loop `break`s on the
 * first guardrail rejection). Several labelled cases below have their
 * confirming request behind an earlier mutating (POST/PUT) step in the SAME
 * scenario (e.g. `owasp-a07-auth-failures`'s very first step is a POST), so
 * the default cap of 0 would silently starve every later step of a chance to
 * run at all — a real finding from this corpus's first real run (every case
 * with a mutating confirming step measured `actualFired: false` for the
 * WRONG reason: guard-blocked, not rule-mismatch). This corpus is measuring
 * B3's detection-rule STRUCTURAL coverage of a scenario's real request
 * shapes, not re-testing the (separately, already tested — guard.ts's own
 * suite) blast-radius cap — so, exactly as `dast.scope.maxMutatingRequests`'s
 * own doc comment invites ("0 by default ... unless an operator explicitly
 * raises it"), this corpus explicitly raises it. 10 comfortably covers every
 * labelled case's total step count (the largest, owasp-a10-ssrf, has 4).
 */
const BLUE_TEAM_MAX_MUTATING_REQUESTS = 10;

function blueTeamConfig(): MontrConfig {
  const base = getHardenedDefaults();
  return {
    ...base,
    dast: {
      ...base.dast,
      enabled: true,
      allowlist: [BLUE_TEAM_STAGING_TARGET],
      scope: { ...base.dast.scope, maxMutatingRequests: BLUE_TEAM_MAX_MUTATING_REQUESTS },
    },
  };
}

const passEgress = { assert: () => undefined, isAllowed: () => true };

/** Real per-scenario measured outcome (what actually happened, not what was expected). */
export interface BlueTeamScenarioResult {
  templateKey: string;
  scenarioName: string;
  findingCategory: Category;
  expectedFired: boolean;
  actualFired: boolean;
  /** Real evaluator evidence text (evaluateDetectionRuleAgainstScenario's reason). */
  evidence: string;
  /** How many real sigma DetectionRules were generated and evaluated for this case (should always be exactly 1). */
  sigmaRulesEvaluated: number;
}

export interface RunBlueTeamCorpusOptions {
  cases?: readonly BlueTeamGroundTruthCase[];
  now?: () => string;
}

/**
 * ⛔ THE real run: for every labelled case, build the real scenario (verbatim
 * catalogue steps) + real finding/AppMap, generate the REAL B3 Sigma rule via
 * `generateDetectionRules`, and evaluate it via the REAL B5 evaluator
 * (`runPurpleTeamScenario`, which itself calls `runScenario` through the
 * identical gated engine every other scenario caller uses — see
 * purple-loop.ts's header). Nothing here is hand-computed; this function
 * reports what the real code actually did.
 */
export async function runBlueTeamCorpus(
  opts: RunBlueTeamCorpusOptions = {},
): Promise<BlueTeamScenarioResult[]> {
  const cases = opts.cases ?? BLUE_TEAM_GROUND_TRUTH;
  const now = opts.now ?? (() => FIXED_NOW);
  const config = blueTeamConfig();
  const results: BlueTeamScenarioResult[] = [];

  for (const caseDef of cases) {
    const scenario = buildBlueTeamScenario(caseDef);
    const { finding, appMap } = buildBlueTeamFindingAndAppMap(caseDef);
    const rules: DetectionRule[] = generateDetectionRules(finding, { appMap, now }).filter(
      (r) => r.format === "sigma",
    );

    const deps: RunPurpleTeamScenarioDeps = {
      egressGuard: passEgress,
      transport: fakeTransport(),
      detectionRules: rules,
      now,
    };

    const result = await runPurpleTeamScenario(
      { scenario, finding, config, allowLive: true },
      deps,
    );

    results.push({
      templateKey: caseDef.templateKey,
      scenarioName: scenario.name,
      findingCategory: caseDef.findingCategory,
      expectedFired: caseDef.expectedFired,
      actualFired: result.overall.fired,
      evidence: result.overall.evidence ?? "",
      sigmaRulesEvaluated: rules.length,
    });
  }

  return results;
}

/* ============================ scoring ============================ */

/** Detection confusion-matrix counts + rates (see module header for the definitions used). */
export interface BlueTeamCorpusScore {
  totalScenarios: number;
  /** Scenarios ground-truth-labelled expectedFired: true. */
  expectedPositives: number;
  expectedNegatives: number;
  /** actualFired: true AND expectedFired: true. */
  truePositives: number;
  /** actualFired: true AND expectedFired: false (the rule fired but shouldn't have). */
  falsePositives: number;
  /** actualFired: false AND expectedFired: true (the rule should have fired but didn't). */
  falseNegatives: number;
  /** actualFired: false AND expectedFired: false. */
  trueNegatives: number;
  /** Of the rules that fired, how many SHOULD have (per ground truth). TP / (TP + FP). 1.0 when nothing fired. */
  detectionPrecision: number;
  /** Of the scenarios that SHOULD trigger detection, how many actually fired. TP / (TP + FN). 1.0 when nothing should have fired. */
  detectionRecall: number;
  /** (TP + TN) / total — every case, not just the positive-labelled ones. */
  accuracy: number;
  perScenario: BlueTeamScenarioResult[];
}

/** Pure scorer — no I/O, no real invocation. Computes the aggregate from already-measured per-scenario results. */
export function scoreBlueTeamResults(
  results: readonly BlueTeamScenarioResult[],
): BlueTeamCorpusScore {
  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;

  for (const r of results) {
    if (r.expectedFired && r.actualFired) truePositives++;
    else if (!r.expectedFired && r.actualFired) falsePositives++;
    else if (r.expectedFired && !r.actualFired) falseNegatives++;
    else trueNegatives++;
  }

  const expectedPositives = truePositives + falseNegatives;
  const expectedNegatives = trueNegatives + falsePositives;
  const detectionPrecision =
    truePositives + falsePositives === 0 ? 1 : truePositives / (truePositives + falsePositives);
  const detectionRecall =
    truePositives + falseNegatives === 0 ? 1 : truePositives / (truePositives + falseNegatives);
  const accuracy = results.length === 0 ? 1 : (truePositives + trueNegatives) / results.length;

  return {
    totalScenarios: results.length,
    expectedPositives,
    expectedNegatives,
    truePositives,
    falsePositives,
    falseNegatives,
    trueNegatives,
    detectionPrecision,
    detectionRecall,
    accuracy,
    perScenario: [...results],
  };
}
