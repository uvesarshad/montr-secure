/**
 * A16 (build-plan tasks, P1) — `parseSemgrepJson` had only ever been exercised
 * against hand-built fixture JSON (see `tests/discovery.detectors.test.ts`'s
 * `CANNED_SEMGREP`), never the REAL semgrep binary's actual `--json` output
 * shape. This file replays a REAL semgrep run captured against the repo's own
 * `packages/fixtures/sample-repos/vulnerable-nextjs` corpus, so the parser is
 * proven against ground truth rather than an assumption of the schema.
 *
 * Provenance of `__fixtures__/semgrep-real-output.json`: captured 2026-08-19
 * by running the exact invocation `defaultSemgrepRunner` (sast.ts) uses —
 *   semgrep --json --quiet --disable-version-check --metrics=off \
 *     --config p/owasp-top-ten --config p/typescript --config p/nextjs \
 *     --config p/react --config p/secrets .
 * — via real semgrep 1.136.0 (OSS engine, installed with
 * `python3 -m pip install semgrep`) against
 * `packages/fixtures/sample-repos/vulnerable-nextjs`. Raw stdout, byte for
 * byte (only re-indented with `python3 -m json.tool` for readability) — not
 * hand-edited.
 *
 * This is a fixture-REPLAY test: it does not require semgrep to be installed
 * to run (the captured JSON is checked into the repo). The separate
 * `golden-corpus` CI job (A2) covers the live-binary invocation end to end;
 * this test covers the parser's handling of the real JSON *shape* at the
 * unit level, including a real quirk the hand-built fixture never had (see
 * below).
 */
import { readFile } from "node:fs/promises";
import { describe, it, expect } from "vitest";
import { getHardenedDefaults } from "@montr/config";
import { createNullLogger } from "@montr/telemetry";
import { AppMapSchema, type ScanScope } from "@montr/contracts";
import { parseSemgrepJson } from "./sast.js";
import type { DetectorContext, SemgrepJson } from "../types.js";
import { memoryFileProvider } from "../util/files.js";

const FULL_SCOPE: ScanScope = {
  mode: "full",
  includePaths: [],
  excludePaths: [],
  changedFiles: [],
  reachableFromChanges: false,
};

// Minimal valid AppMap (no dependency on @montr/fixtures, which this package
// does not depend on) — parseSemgrepJson never reads it, but DetectorContext
// requires the field.
const minimalAppMap = AppMapSchema.parse({
  id: "appmap_test_0001",
  clientId: "client_test_0001",
  repo: "https://example.test/repo.git",
  branch: "main",
  commitSha: "0000000000000000000000000000000000000a",
  createdAt: "2026-01-15T10:00:00.000Z",
});

function makeCtx(): DetectorContext {
  const warnings: string[] = [];
  return {
    clientId: "client_test_0001",
    scanId: "scan_test_0001",
    appMap: minimalAppMap,
    scope: FULL_SCOPE,
    config: getHardenedDefaults(),
    repoRoot: undefined,
    files: memoryFileProvider([]),
    now: () => "2026-01-15T10:00:00.000Z",
    logger: createNullLogger(),
    signal: undefined,
    warnings,
    warn(detector: string, message: string): void {
      warnings.push(`[${detector}] ${message}`);
    },
  };
}

async function loadFixture(): Promise<SemgrepJson> {
  const raw = await readFile(
    new URL("./__fixtures__/semgrep-real-output.json", import.meta.url),
    "utf8",
  );
  return JSON.parse(raw) as SemgrepJson;
}

describe("discovery/sast — real semgrep output (A16)", () => {
  it("parses the real captured semgrep JSON without throwing (schema validation included)", async () => {
    const json = await loadFixture();
    const ctx = makeCtx();
    // buildCandidate() runs every candidate through CandidateFindingSchema.parse
    // internally — if the real tool's field shapes didn't line up with what
    // candidateFromSemgrep() assumes, this throws.
    const candidates = parseSemgrepJson(json, ctx);
    expect(candidates).toHaveLength(2);
  });

  it("maps the real XSS finding (dangerouslySetInnerHTML) with correct fields", async () => {
    const json = await loadFixture();
    const ctx = makeCtx();
    const candidates = parseSemgrepJson(json, ctx);

    const xss = candidates.find((c) => c.ruleId.includes("dangerouslysetinnerhtml"));
    expect(xss).toBeDefined();
    expect(xss?.source).toBe("semgrep");
    expect(xss?.ruleId).toBe(
      "typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml",
    );
    // Real semgrep nests CWE metadata as "CWE-79: Improper Neutralization ..."
    // (not the bare "CWE-79" the hand-built CANNED_SEMGREP fixture used) —
    // normalizeCwe() must still extract the numeric id correctly.
    expect(xss?.cwe).toContain("CWE-79");
    expect(xss?.category).toBe("xss");
    expect(xss?.rawSeverity).toBe("medium"); // real severity token: "WARNING"
    expect(xss?.location).toMatchObject({ file: "app/search/page.tsx", line: 8, column: 47 });
    expect(xss?.metadata).toMatchObject({ engine: "semgrep" });
  });

  it("maps the real hardcoded-secret finding (p/secrets ruleset) with correct fields", async () => {
    const json = await loadFixture();
    const ctx = makeCtx();
    const candidates = parseSemgrepJson(json, ctx);

    const secret = candidates.find((c) => c.ruleId.includes("detected-stripe-api-key"));
    expect(secret).toBeDefined();
    expect(secret?.source).toBe("semgrep");
    expect(secret?.category).toBe("hardcoded_secret"); // via CWE-798 metadata, not rule-id heuristic
    expect(secret?.cwe).toContain("CWE-798");
    expect(secret?.rawSeverity).toBe("high"); // real severity token: "ERROR"
    expect(secret?.location).toMatchObject({ file: "lib/config.ts", line: 2 });
    // The secret VALUE itself is never in the candidate — semgrep's own message
    // does not echo matched text for this rule, and even so nothing here comes
    // from `extra.lines` verbatim (see the quirk documented below).
    expect(JSON.stringify(secret)).not.toContain("hardcodedKeyDoNotUse");
  });

  it('documents a REAL schema quirk the hand-built fixture never had: anonymous OSS CLI runs against registry rulesets (p/*) return extra.lines/extra.fingerprint as the literal string "requires login", not the matched code', async () => {
    // This is real, unauthenticated `semgrep --config p/...` behavior (confirmed
    // in the raw capture) — the hand-built CANNED_SEMGREP fixture always used a
    // real code excerpt for `extra.lines`, which is NOT representative of what
    // an anonymous CI run of the curated p/* rulesets actually returns. The
    // parser must not crash on this (it doesn't — `snippet` is just a string),
    // but it does mean `evidenceSnippet` can end up non-substantive in
    // production; this test locks in the parser's (safe) handling of that shape
    // rather than silently letting behavior drift.
    const json = await loadFixture();
    expect(json.results?.every((r) => r.extra?.lines === "requires login")).toBe(true);
    const ctx = makeCtx();
    const candidates = parseSemgrepJson(json, ctx);
    for (const c of candidates) {
      expect(() => JSON.stringify(c)).not.toThrow();
      expect(typeof c.evidenceSnippet).toBe("string");
    }
  });
});
