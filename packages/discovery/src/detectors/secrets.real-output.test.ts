/**
 * A16 (build-plan tasks, P1) — `candidatesFromGitleaks` had only ever been
 * exercised indirectly, via an injected `GitleaksRunner` returning an
 * ad hoc/hand-built array (`tests/discovery.detectors.test.ts`), never the
 * REAL gitleaks binary's actual `--report-format json` output shape. This file
 * replays a REAL gitleaks run captured against the repo's own
 * `packages/fixtures/sample-repos/vulnerable-nextjs` corpus (which plants a
 * known Stripe-shaped secret in `lib/config.ts`).
 *
 * Provenance of `__fixtures__/gitleaks-real-output.json`: captured 2026-08-19
 * by running the exact invocation `defaultGitleaksRunner` (secrets.ts) uses —
 *   gitleaks detect --source <repo> --no-git --redact \
 *     --report-format json --report-path <tmp>.json
 * — via real gitleaks 8.30.1 against
 * `packages/fixtures/sample-repos/vulnerable-nextjs`. Raw report-path
 * contents, byte for byte (only re-indented with `python3 -m json.tool` for
 * readability) — not hand-edited. `candidatesFromGitleaks` is now exported
 * (previously module-private) specifically so it can be exercised directly
 * here.
 *
 * This is a fixture-REPLAY test: it does not require gitleaks to be
 * installed to run. The separate `golden-corpus` CI job (A2) covers the
 * live-binary invocation end to end; this test covers the parser's handling
 * of the real JSON shape at the unit level.
 */
import { readFile } from "node:fs/promises";
import { describe, it, expect } from "vitest";
import { getHardenedDefaults } from "@montr/config";
import { createNullLogger } from "@montr/telemetry";
import { AppMapSchema, type ScanScope } from "@montr/contracts";
import { candidatesFromGitleaks } from "./secrets.js";
import type { DetectorContext, GitleaksFinding } from "../types.js";
import { memoryFileProvider } from "../util/files.js";

const FULL_SCOPE: ScanScope = {
  mode: "full",
  includePaths: [],
  excludePaths: [],
  changedFiles: [],
  reachableFromChanges: false,
};

// Minimal valid AppMap (no dependency on @montr/fixtures, which this package
// does not depend on) — candidatesFromGitleaks never reads it, but
// DetectorContext requires the field.
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

async function loadFixture(): Promise<GitleaksFinding[]> {
  const raw = await readFile(
    new URL("./__fixtures__/gitleaks-real-output.json", import.meta.url),
    "utf8",
  );
  const parsed: unknown = JSON.parse(raw);
  return Array.isArray(parsed) ? (parsed as GitleaksFinding[]) : [];
}

describe("discovery/secrets — real gitleaks output (A16)", () => {
  it("parses the real captured gitleaks JSON without throwing (schema validation included)", async () => {
    const findings = await loadFixture();
    const ctx = makeCtx();
    // buildCandidate() runs every candidate through CandidateFindingSchema.parse
    // internally — if the real tool's field shapes didn't line up with what
    // candidatesFromGitleaks() assumes, this throws.
    const candidates = candidatesFromGitleaks(ctx, findings);
    expect(candidates).toHaveLength(1);
  });

  it("maps the real planted Stripe secret with correct fields, and never emits the secret value", async () => {
    const findings = await loadFixture();
    const ctx = makeCtx();
    const [candidate] = candidatesFromGitleaks(ctx, findings);

    expect(candidate?.source).toBe("gitleaks");
    expect(candidate?.ruleId).toBe("stripe-access-token"); // real rule id gitleaks matched
    expect(candidate?.category).toBe("hardcoded_secret");
    expect(candidate?.rawSeverity).toBe("high");
    expect(candidate?.location).toMatchObject({ file: "lib/config.ts", line: 2 });
    expect(candidate?.title).toContain("Stripe Access Token");

    // golden rule #1: secret VALUES never land in the candidate. Real
    // `--redact` output already replaces Match/Secret with "REDACTED", and
    // candidatesFromGitleaks() never reads those fields regardless — assert
    // both the redacted placeholder and the actual planted secret are absent.
    const serialized = JSON.stringify(candidate);
    expect(serialized).not.toContain("hardcodedKeyDoNotUse");
    expect(serialized).not.toContain("sk_live_");
  });

  it("real gitleaks report entries carry extra fields (Entropy, Tags, Fingerprint, SymlinkFile, ...) the hand-typed GitleaksFinding interface doesn't declare — these must be ignored, not break parsing", async () => {
    const findings = await loadFixture();
    // Confirms the fixture really does carry fields beyond the narrow
    // GitleaksFinding TS interface (proving this is real tool output, not a
    // fixture trimmed to only the fields the code already expects).
    const raw = findings[0] as unknown as Record<string, unknown>;
    expect(raw).toHaveProperty("Entropy");
    expect(raw).toHaveProperty("Fingerprint");
    expect(raw).toHaveProperty("Tags");

    const ctx = makeCtx();
    expect(() => candidatesFromGitleaks(ctx, findings)).not.toThrow();
  });
});
