#!/usr/bin/env node
/**
 * CI check: every declared "seam" below — an exported factory function or
 * gateway method meant to be consumed in production — must have at least one
 * NON-TEST caller outside the package that defines it (apps/**\/src or a
 * different packages/**\/src consumer). Grep-based and deliberately simple,
 * per audit finding A10 (docs/plan/26-08-22-audit-ai-depth.md): the Vault key
 * source (packages/config/src/key-source.ts), the LLM prompt registry
 * (gateway.resolvePrompt), and the §15 false-positive tuning loop
 * (store.falsePositiveMarks) all shipped as real, fully-tested code with
 * ZERO production callers across multiple audit cycles — nothing ever
 * verified a seam was actually reachable, only that it existed and had unit
 * tests. This script is that verification, wired into `pnpm run
 * check:unwired-seams` and CI (.github/workflows/ci.yml).
 *
 * Usage: node scripts/check-unwired-seams.mjs
 * Exit code: 0 = every seam has a qualifying caller, 1 = at least one
 * seam regressed to unwired (or the grep tooling itself failed).
 *
 * Add a new seam here whenever a new exported factory/hook in
 * packages/config, packages/llm-gateway, or another pluggable-by-design
 * package is meant to be consumed in production — see each package's
 * index.ts / README-style header comment for what's "meant to be wired".
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

/**
 * `pattern` is matched as a FIXED STRING (grep -F) across every non-test
 * `.ts`/`.tsx` file under apps/ and packages/, excluding node_modules, dist,
 * and .turbo output.
 *
 * `definedIn` is the package whose OWN internal usage doesn't count as
 * "wired" (a seam only called by its own plumbing isn't reaching production)
 * — UNLESS `allowSelfPackage` is set, for helpers that are legitimately only
 * ever called by another exported function in the same file/package (e.g.
 * `resolveFieldEncryptionKey` calling `createKeySource` internally).
 */
const SEAMS = [
  {
    name: "packages/config: resolveFieldEncryptionKey() — pluggable env/file/Vault key source (A10)",
    pattern: "resolveFieldEncryptionKey(",
    definedIn: "packages/config",
  },
  {
    name: "packages/config: createKeySource() — pluggable env/file/Vault key source (A10)",
    pattern: "createKeySource(",
    definedIn: "packages/config",
    allowSelfPackage: true,
  },
  {
    name: "packages/llm-gateway: gateway.resolvePrompt(...) — DB-versioned prompt registry (A10)",
    pattern: ".resolvePrompt?.(",
    definedIn: "packages/llm-gateway",
  },
  {
    name: "packages/llm-gateway: createLlmGateway() — the one BYO-key LLM egress factory",
    pattern: "createLlmGateway(",
    definedIn: "packages/llm-gateway",
  },
  {
    name: "packages/cost-meter: createBudgetRegistry() — pre-call + real-time budget guard (A2/A32)",
    pattern: "createBudgetRegistry(",
    definedIn: "packages/cost-meter",
  },
  {
    name: "packages/state-store: store.falsePositiveMarks — §15 FP-feedback tuning loop (A10)",
    pattern: "falsePositiveMarks",
    definedIn: "packages/state-store",
  },
  {
    name: "packages/llm-gateway: createEmbeddingAdapter() — embeddings capability for the semantic codebase index (A9)",
    pattern: "createEmbeddingAdapter(",
    definedIn: "packages/llm-gateway",
  },
  {
    name: "packages/semantic-index: buildSemanticIndex() — AST-chunked pgvector code index, built alongside Layer 0's App Map (A9)",
    pattern: "buildSemanticIndex(",
    definedIn: "packages/semantic-index",
  },
  {
    name: "packages/semantic-index: querySemanticIndex() — semantic retrieval consumed by Layer 2 correlation + Layer 3 confirmation (A9)",
    pattern: "querySemanticIndex(",
    definedIn: "packages/semantic-index",
  },
];

/**
 * Seams that are REAL, TESTED, working code but are a deliberate judgment
 * call to leave unconsumed by any pipeline layer for now (documented, not
 * silently dropped). Printed as informational only — never fails the build.
 * Revisit if a layer gains a genuine streaming consumer (a console/UI
 * surface, or a multi-turn agent loop per the audit's enhancement E10).
 */
const KNOWN_UNWIRED = [
  {
    name: "packages/llm-gateway: gateway.stream() — implemented in every adapter, no layer consumes it yet (A10)",
    reason:
      "Every current layer call is a small, single-shot metadata request with no UI/console to " +
      "stream tokens to; verified working end-to-end instead via " +
      "packages/llm-gateway/src/streaming.integration.test.ts (real adapter, fake transport).",
  },
];

function grepFiles(pattern) {
  try {
    const out = execFileSync(
      "grep",
      [
        "-rl",
        "-F",
        "--include=*.ts",
        "--include=*.tsx",
        "--exclude=*.test.ts",
        "--exclude-dir=node_modules",
        "--exclude-dir=dist",
        "--exclude-dir=.turbo",
        pattern,
        "apps",
        "packages",
      ],
      { cwd: root, encoding: "utf8" },
    );
    return out.split("\n").filter(Boolean);
  } catch (err) {
    // grep exits 1 (not an error) when there are simply no matches.
    if (err.status === 1) return [];
    throw err;
  }
}

function checkSeam(seam) {
  const matches = grepFiles(seam.pattern);
  const qualifying = seam.allowSelfPackage
    ? matches
    : matches.filter((f) => !f.startsWith(`${seam.definedIn}/`));
  return { seam, matches, qualifying, ok: qualifying.length > 0 };
}

function main() {
  const results = SEAMS.map(checkSeam);
  const failures = results.filter((r) => !r.ok);

  console.log(
    "Unwired-seam check (A10) — every declared production seam must have a real caller\n",
  );
  for (const r of results) {
    const status = r.ok ? "OK  " : "FAIL";
    console.log(`[${status}] ${r.seam.name}`);
    if (r.qualifying.length > 0) {
      for (const f of r.qualifying) console.log(`         called from ${f}`);
    }
  }

  if (KNOWN_UNWIRED.length > 0) {
    console.log("\nKnown, documented exceptions (informational — do not fail the build):");
    for (const k of KNOWN_UNWIRED) {
      console.log(`  - ${k.name}`);
      console.log(`    ${k.reason}`);
    }
  }

  if (failures.length > 0) {
    console.error(
      `\n${failures.length} seam(s) regressed to "built but unwired" — see docs/plan/26-08-22-audit-ai-depth.md A10:\n`,
    );
    for (const f of failures) {
      console.error(`  - ${f.seam.name}`);
      console.error(
        `    No non-test caller found outside ${f.seam.definedIn} (searched for "${f.seam.pattern}").`,
      );
    }
    process.exit(1);
  }

  console.log("\nAll declared seams have a real production caller.");
  process.exit(0);
}

main();
