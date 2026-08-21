import { describe, expect, it, beforeAll } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ConfirmedFinding } from "@montr/contracts";
import { ConfirmedFindingSchema } from "@montr/contracts";
import { buildUnifiedDiff, validatePatchWithContainerReplay } from "@montr/fix";

/**
 * E13 — real proof-of-fix in an ephemeral container (closes A22).
 *
 * The first describe block is the CORE, LOAD-BEARING proof for this task: a
 * genuinely vulnerable Node HTTP server is built into a REAL, throwaway Docker
 * container (no mocking of `docker`, `execa`, or the network) from a synthesized
 * Dockerfile (the app ships no Dockerfile of its own — this exercises the
 * "standard `npm start`" generalization path), a recorded live-DAST exploit
 * transcript is replayed against it and must succeed, the SAME probe is
 * replayed again against a freshly-built container running the FIXED source
 * and must now fail. Real container build + start + HTTP round trip + teardown
 * happen twice (pre-patch, post-patch).
 *
 * This spins up real Docker containers — expect this file alone to take
 * 30-90s+ depending on how warm the local `node:20-alpine` image cache is.
 */

const REFLECTED_MARKER = "<script>alert(1)</script>";

function vulnerableServerJs(): string {
  return [
    'const http = require("node:http");',
    'const { URL } = require("node:url");',
    "",
    "const server = http.createServer((req, res) => {",
    '  const u = new URL(req.url, "http://localhost");',
    '  const q = u.searchParams.get("q") ?? "";',
    '  res.writeHead(200, { "content-type": "text/html" });',
    "  res.end(`<html><body>RESULT:${q}</body></html>`);",
    "});",
    "",
    "server.listen(process.env.PORT || 3000, () => { /* ready */ });",
    "",
  ].join("\n");
}

function fixedServerJs(): string {
  return [
    'const http = require("node:http");',
    'const { URL } = require("node:url");',
    "",
    "function escapeHtml(s) {",
    "  return String(s)",
    '    .replace(/&/g, "&amp;")',
    '    .replace(/</g, "&lt;")',
    '    .replace(/>/g, "&gt;");',
    "}",
    "",
    "const server = http.createServer((req, res) => {",
    '  const u = new URL(req.url, "http://localhost");',
    '  const q = u.searchParams.get("q") ?? "";',
    '  res.writeHead(200, { "content-type": "text/html" });',
    "  res.end(`<html><body>RESULT:${escapeHtml(q)}</body></html>`);",
    "});",
    "",
    "server.listen(process.env.PORT || 3000, () => { /* ready */ });",
    "",
  ].join("\n");
}

function liveConfirmedXssFinding(): ConfirmedFinding {
  return ConfirmedFindingSchema.parse({
    id: "conf_container_xss_0001",
    scanId: "scan_container_replay",
    clientId: "client_container_replay",
    title: "Reflected XSS in GET /echo (q parameter) — confirmed live",
    category: "xss",
    cwe: ["CWE-79"],
    owasp: "A03:2021",
    severity: "high",
    exposure: "public",
    location: { file: "server.js", line: 8 },
    impact: "Confirmed live: an unescaped `q` reflects directly into the HTML response body.",
    proofType: "live",
    proofArtifact: {
      kind: "live",
      target: "https://staging.example.internal",
      transcript: [
        {
          request: {
            method: "GET",
            url: "https://staging.example.internal/echo?q=hello",
          },
          response: { status: 200, bodySnippet: "<html><body>RESULT:hello</body></html>" },
          note: "baseline",
        },
        {
          request: {
            method: "GET",
            url: `https://staging.example.internal/echo?q=${encodeURIComponent(REFLECTED_MARKER)}`,
          },
          response: {
            status: 200,
            bodySnippet: `<html><body>RESULT:${REFLECTED_MARKER}</body></html>`,
          },
          note: "unescaped reflection of the injected marker",
        },
      ],
    },
    createdAt: "2026-08-22T00:00:00.000Z",
  });
}

/**
 * Uses `node:child_process` directly (not `execa`) so this availability probe
 * resolves cleanly from a top-level `tests/` file regardless of workspace
 * module-resolution boundaries — the actual harness (`container-harness.ts`,
 * inside `packages/fix/src`, where `execa` is a real declared dependency)
 * still uses `execa` throughout, unchanged.
 */
async function dockerAvailable(): Promise<boolean> {
  const { execFile } = await import("node:child_process");
  return new Promise((resolve) => {
    execFile("docker", ["version"], { timeout: 10_000 }, (error) => {
      resolve(!error);
    });
  });
}

let hasDocker = false;
beforeAll(async () => {
  hasDocker = await dockerAvailable();
  if (!hasDocker) {
    console.warn(
      "tests/fix.container-replay.test.ts: docker is not available — skipping the real-container suite.",
    );
  }
}, 15_000);

describe("@montr/fix — E13 real ephemeral-container proof-of-fix (REAL docker)", () => {
  it("replays the confirmed live-DAST exploit against a real container: succeeds pre-patch, fails post-patch", async () => {
    if (!hasDocker) return;

    const appDir = await mkdtemp(join(tmpdir(), "montr-fixproof-app-"));
    try {
      await writeFile(
        join(appDir, "package.json"),
        JSON.stringify({
          name: "vuln-app-fixture",
          version: "1.0.0",
          private: true,
          scripts: { start: "node server.js" },
        }),
      );
      // No Dockerfile in this fixture app — exercises the SYNTHESIZED-Node path.
      await writeFile(join(appDir, "server.js"), vulnerableServerJs(), "utf8");

      const original = vulnerableServerJs();
      const fixed = fixedServerJs();
      const patch = buildUnifiedDiff("server.js", original, fixed);
      const finding = liveConfirmedXssFinding();

      const result = await validatePatchWithContainerReplay(original, patch, {
        filePath: "server.js",
        proofTestCode: fallbackProofTestCode(),
        confirmedFinding: finding,
        targetRepoDir: appDir,
        containerTimeoutMs: 120_000,
      });

      expect(result.containerReplay.attempted).toBe(true);
      expect(result.containerReplay.error).toBeUndefined();
      expect(result.containerReplay.replayed).toBe(true);
      expect(result.containerReplay.harness).toBe("synthesized-node");
      expect(result.containerReplay.prePatch?.exploitSucceeded).toBe(true);
      expect(result.containerReplay.postPatch?.exploitSucceeded).toBe(false);

      // The real container-derived verdict flows through the SAME
      // failsPrePatch/passesPostPatch fields the vitest mechanism produces.
      expect(result.applies).toBe(true);
      expect(result.failsPrePatch).toBe(true);
      expect(result.passesPostPatch).toBe(true);

      // The attached transcript is the REAL request/response pair from each
      // container run, not the original staging-target evidence replayed back.
      expect(result.containerReplay.prePatch?.exchange.response.bodySnippet).toContain(
        REFLECTED_MARKER,
      );
      expect(result.containerReplay.postPatch?.exchange.response.bodySnippet).not.toContain(
        REFLECTED_MARKER,
      );
    } finally {
      await rm(appDir, { recursive: true, force: true });
    }
  }, 180_000);
});

describe("@montr/fix — E13 fallback to the vitest-subprocess proof (no live-DAST evidence)", () => {
  it("falls back to validatePatch when the confirmed finding has a static (non-live) proof artifact", async () => {
    const original = "const x = UNSAFE(value);\n";
    const fixed = "const x = SAFE(value);\n";
    const patch = buildUnifiedDiff("app/x.ts", original, fixed);
    const staticFinding = ConfirmedFindingSchema.parse({
      id: "conf_static_0001",
      scanId: "scan_container_replay",
      clientId: "client_container_replay",
      title: "SQL Injection (static proof only)",
      category: "sql_injection",
      cwe: ["CWE-89"],
      severity: "high",
      exposure: "public",
      location: { file: "app/x.ts", line: 1 },
      impact: "Static-only confirmation — no live-DAST evidence exists to replay.",
      proofType: "static",
      proofArtifact: {
        kind: "static",
        argument: "Tainted input reaches a dangerous sink with no sanitizer on the path.",
        dataFlow: [],
        sanitizersBypassed: [],
      },
      createdAt: "2026-08-22T00:00:00.000Z",
    });

    const result = await validatePatchWithContainerReplay(original, patch, {
      filePath: "app/x.ts",
      proofTestCode: proofTestFor("app/x.ts", /UNSAFE/),
      confirmedFinding: staticFinding,
      targetRepoDir: "/nonexistent/should-not-be-used",
    });

    expect(result.containerReplay.attempted).toBe(false);
    expect(result.containerReplay.replayed).toBe(false);
    expect(result.containerReplay.reason).toMatch(/proof artifact, not "live"/);
    // The EXISTING vitest-subprocess mechanism still ran for real and produced
    // a real verdict — coverage for non-live-evidence findings is unbroken.
    expect(result.applies).toBe(true);
    expect(result.failsPrePatch).toBe(true);
    expect(result.passesPostPatch).toBe(true);
  }, 30_000);

  it("falls back when live-DAST evidence exists but no targetRepoDir was supplied", async () => {
    const original = "const x = UNSAFE(value);\n";
    const fixed = "const x = SAFE(value);\n";
    const patch = buildUnifiedDiff("app/x.ts", original, fixed);

    const result = await validatePatchWithContainerReplay(original, patch, {
      filePath: "app/x.ts",
      proofTestCode: proofTestFor("app/x.ts", /UNSAFE/),
      confirmedFinding: liveConfirmedXssFinding(),
      // targetRepoDir intentionally omitted
    });

    expect(result.containerReplay.attempted).toBe(false);
    expect(result.containerReplay.reason).toMatch(/no targetRepoDir/);
    expect(result.failsPrePatch).toBe(true);
    expect(result.passesPostPatch).toBe(true);
  }, 30_000);

  it("falls back with no confirmed finding at all (behaves exactly like validatePatch)", async () => {
    const original = "const x = UNSAFE(value);\n";
    const fixed = "const x = SAFE(value);\n";
    const patch = buildUnifiedDiff("app/x.ts", original, fixed);

    const result = await validatePatchWithContainerReplay(original, patch, {
      filePath: "app/x.ts",
      proofTestCode: proofTestFor("app/x.ts", /UNSAFE/),
    });

    expect(result.containerReplay.attempted).toBe(false);
    expect(result.failsPrePatch).toBe(true);
    expect(result.passesPostPatch).toBe(true);
  }, 30_000);
});

/** Mirrors the exact shape strategies.ts generates (see tests/fix.patch.test.ts). */
function proofTestFor(filePath: string, vulnerable: RegExp): string {
  return [
    `import { readFileSync } from "node:fs";`,
    `import { describe, it, expect } from "vitest";`,
    `const source = readFileSync(${JSON.stringify(filePath)}, "utf8");`,
    `describe("proof-of-fix", () => {`,
    `  it("no longer contains the vulnerable pattern", () => {`,
    `    expect(source).not.toMatch(${vulnerable.toString()});`,
    `  });`,
    `});`,
    ``,
  ].join("\n");
}

/** A generic, always-passing-shape placeholder proof test for the container-path
 * test above — it is never actually run (container replay succeeds), it only
 * needs to satisfy the `ValidatePatchOptions` contract. */
function fallbackProofTestCode(): string {
  return proofTestFor("server.js", /RESULT:\$\{q\}<\/body>/);
}
