/**
 * `montr scan` (A15) — argument parsing + the polling/gating loop. The HTTP
 * layer is fully mocked (`MontrApiClient`) so these tests never touch a real
 * API server; git detection is injected too, so they never touch this repo's
 * actual git state.
 */
import { describe, expect, it, vi } from "vitest";
import type { ConfirmedFinding, Scan } from "@montr/contracts";
import { run, parseArgs, CLI_EXIT } from "./cli.js";
import { CliApiError, type MontrApiClient } from "./http.js";

function baseScan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: "scan_1",
    clientId: "default",
    repo: "acme/app",
    branch: "main",
    mode: "full",
    scope: {
      mode: "full",
      includePaths: [],
      excludePaths: [],
      changedFiles: [],
      reachableFromChanges: false,
    },
    status: "running",
    gateState: "not_started",
    operator: "user_1",
    createdAt: "2026-08-22T00:00:00.000Z",
    ...overrides,
  } as Scan;
}

function confirmedFinding(severity: ConfirmedFinding["severity"]): ConfirmedFinding {
  return { id: `f_${severity}`, severity } as ConfirmedFinding;
}

function makeGit(
  overrides: Partial<{
    detectBranch: () => string | undefined;
    detectRepoName: () => string;
    detectChangedFiles: () => string[];
  }> = {},
) {
  return {
    detectBranch: overrides.detectBranch ?? (() => "main"),
    detectRepoName: overrides.detectRepoName ?? (() => "acme/app"),
    detectChangedFiles: overrides.detectChangedFiles ?? (() => []),
  };
}

function makeClient(overrides: Partial<MontrApiClient> = {}): MontrApiClient {
  return {
    login: vi.fn(async () => "token-from-login"),
    createScan: vi.fn(async () => baseScan()),
    getScan: vi.fn(async () => baseScan({ status: "completed" })),
    getProgress: vi.fn(async () => []),
    getFindings: vi.fn(async () => ({ confirmed: [], unconfirmed: [] })),
    ...overrides,
  };
}

const noopSleep = async () => {};

describe("parseArgs", () => {
  it("defaults: path '.', mode full, fail-on high", () => {
    const args = parseArgs(["scan"]);
    expect(args.path).toBe(".");
    expect(args.mode).toBe("full");
    expect(args.failOn).toBe("high");
    expect(args.json).toBe(false);
  });

  it("accepts a positional path and strips a leading 'scan' subcommand token", () => {
    const args = parseArgs(["scan", "./my-repo"]);
    expect(args.path).toBe("./my-repo");
  });

  it("parses --mode diff, --base, --changed-files", () => {
    const args = parseArgs([
      "scan",
      "--mode",
      "diff",
      "--base",
      "develop",
      "--changed-files",
      "a.ts, b.ts",
    ]);
    expect(args.mode).toBe("diff");
    expect(args.base).toBe("develop");
    expect(args.changedFiles).toEqual(["a.ts", "b.ts"]);
  });

  it("rejects an invalid --mode", () => {
    expect(() => parseArgs(["scan", "--mode", "bogus"])).toThrow(/--mode/);
  });

  it("rejects an invalid --fail-on", () => {
    expect(() => parseArgs(["scan", "--fail-on", "extreme"])).toThrow(/--fail-on/);
  });

  it("rejects an unknown option", () => {
    expect(() => parseArgs(["scan", "--nope"])).toThrow(/unknown option/);
  });

  it("rejects a second positional argument", () => {
    expect(() => parseArgs(["scan", "a", "b"])).toThrow(/extra argument/);
  });

  it("rejects an option missing its value", () => {
    expect(() => parseArgs(["scan", "--branch"])).toThrow(/requires a value/);
  });
});

describe("run", () => {
  it("--help prints usage and returns OK without making any network call", async () => {
    const out = vi.fn();
    const client = makeClient();
    const code = await run(["scan", "--help"], {
      out,
      createClient: () => client,
      git: makeGit(),
      sleep: noopSleep,
    });
    expect(code).toBe(CLI_EXIT.OK);
    expect(out).toHaveBeenCalled();
    expect(client.createScan).not.toHaveBeenCalled();
  });

  it("returns USAGE when no --token/--email+--password is available", async () => {
    const err = vi.fn();
    const code = await run(["scan", "--api-url", "http://x"], {
      out: vi.fn(),
      err,
      env: {},
      createClient: () => makeClient(),
      git: makeGit(),
      sleep: noopSleep,
    });
    expect(code).toBe(CLI_EXIT.USAGE);
    expect(err).toHaveBeenCalled();
  });

  it("logs in via --email/--password when --token is absent, then creates the scan", async () => {
    const client = makeClient({
      getScan: vi.fn(async () => baseScan({ status: "completed" })),
    });
    const createClientSpy = vi.fn(() => client);
    const code = await run(["scan", "--email", "op@example.com", "--password", "hunter2hunter2"], {
      out: vi.fn(),
      createClient: createClientSpy,
      git: makeGit(),
      sleep: noopSleep,
    });
    expect(client.login).toHaveBeenCalledWith("op@example.com", "hunter2hunter2");
    expect(client.createScan).toHaveBeenCalledTimes(1);
    expect(code).toBe(CLI_EXIT.OK);
  });

  it("polls until terminal, then exits OK when no confirmed finding meets --fail-on", async () => {
    let calls = 0;
    const client = makeClient({
      getScan: vi.fn(async () => {
        calls += 1;
        return baseScan({ status: calls < 2 ? "running" : "completed" });
      }),
      getFindings: vi.fn(async () => ({
        confirmed: [confirmedFinding("low"), confirmedFinding("medium")],
        unconfirmed: [],
      })),
    });
    const code = await run(["scan", "--token", "tok"], {
      out: vi.fn(),
      createClient: () => client,
      git: makeGit(),
      sleep: noopSleep,
    });
    expect(code).toBe(CLI_EXIT.OK);
    expect(client.getScan).toHaveBeenCalledTimes(2);
  });

  it("exits FINDINGS when a confirmed finding meets/exceeds --fail-on", async () => {
    const client = makeClient({
      getScan: vi.fn(async () => baseScan({ status: "completed" })),
      getFindings: vi.fn(async () => ({
        confirmed: [confirmedFinding("critical")],
        unconfirmed: [],
      })),
    });
    const out = vi.fn();
    const code = await run(["scan", "--token", "tok", "--fail-on", "high"], {
      out,
      createClient: () => client,
      git: makeGit(),
      sleep: noopSleep,
    });
    expect(code).toBe(CLI_EXIT.FINDINGS);
    expect(out.mock.calls.some(([line]) => String(line).includes("FAIL"))).toBe(true);
  });

  it("respects a lower --fail-on threshold (medium catches what high would miss)", async () => {
    const client = makeClient({
      getScan: vi.fn(async () => baseScan({ status: "completed" })),
      getFindings: vi.fn(async () => ({
        confirmed: [confirmedFinding("medium")],
        unconfirmed: [],
      })),
    });
    const code = await run(["scan", "--token", "tok", "--fail-on", "medium"], {
      out: vi.fn(),
      createClient: () => client,
      git: makeGit(),
      sleep: noopSleep,
    });
    expect(code).toBe(CLI_EXIT.FINDINGS);
  });

  it("exits SCAN_FAILED when the scan ends failed", async () => {
    const client = makeClient({ getScan: vi.fn(async () => baseScan({ status: "failed" })) });
    const err = vi.fn();
    const code = await run(["scan", "--token", "tok"], {
      out: vi.fn(),
      err,
      createClient: () => client,
      git: makeGit(),
      sleep: noopSleep,
    });
    expect(code).toBe(CLI_EXIT.SCAN_FAILED);
    expect(client.getFindings).not.toHaveBeenCalled();
  });

  it("exits SCAN_FAILED on timeout without ever reaching a terminal status", async () => {
    const client = makeClient({ getScan: vi.fn(async () => baseScan({ status: "running" })) });
    let t = 0;
    const code = await run(["scan", "--token", "tok", "--timeout", "10", "--poll-interval", "1"], {
      out: vi.fn(),
      err: vi.fn(),
      createClient: () => client,
      git: makeGit(),
      sleep: noopSleep,
      now: () => (t += 20), // jumps straight past the 10ms deadline on first check
    });
    expect(code).toBe(CLI_EXIT.SCAN_FAILED);
  });

  it("exits API_ERROR when the API rejects scan creation", async () => {
    const client = makeClient({
      createScan: vi.fn(async () => {
        throw new CliApiError(403, "forbidden", "FORBIDDEN");
      }),
    });
    const err = vi.fn();
    const code = await run(["scan", "--token", "tok"], {
      out: vi.fn(),
      err,
      createClient: () => client,
      git: makeGit(),
      sleep: noopSleep,
    });
    expect(code).toBe(CLI_EXIT.API_ERROR);
    expect(err.mock.calls.some(([line]) => String(line).includes("403"))).toBe(true);
  });

  it("mode=diff sends the git-detected changed files as scope.changedFiles", async () => {
    const client = makeClient({ getScan: vi.fn(async () => baseScan({ status: "completed" })) });
    await run(["scan", "--token", "tok", "--mode", "diff"], {
      out: vi.fn(),
      createClient: () => client,
      git: makeGit({ detectChangedFiles: () => ["src/a.ts", "src/b.ts"] }),
      sleep: noopSleep,
    });
    expect(client.createScan).toHaveBeenCalledWith(
      expect.objectContaining({
        mode: "diff",
        scope: expect.objectContaining({ changedFiles: ["src/a.ts", "src/b.ts"] }),
      }),
    );
  });

  it("--changed-files overrides the git-detected list", async () => {
    const client = makeClient({ getScan: vi.fn(async () => baseScan({ status: "completed" })) });
    await run(["scan", "--token", "tok", "--mode", "diff", "--changed-files", "only.ts"], {
      out: vi.fn(),
      createClient: () => client,
      git: makeGit({ detectChangedFiles: () => ["should-not-be-used.ts"] }),
      sleep: noopSleep,
    });
    expect(client.createScan).toHaveBeenCalledWith(
      expect.objectContaining({ scope: expect.objectContaining({ changedFiles: ["only.ts"] }) }),
    );
  });

  it("emits a JSON summary when --json is set", async () => {
    const client = makeClient({
      getScan: vi.fn(async () => baseScan({ status: "completed" })),
      getFindings: vi.fn(async () => ({ confirmed: [confirmedFinding("high")], unconfirmed: [] })),
    });
    const out = vi.fn();
    const code = await run(["scan", "--token", "tok", "--json"], {
      out,
      createClient: () => client,
      git: makeGit(),
      sleep: noopSleep,
    });
    expect(code).toBe(CLI_EXIT.FINDINGS);
    const jsonLine = out.mock.calls.map(([l]) => String(l)).find((l) => l.trim().startsWith("{"));
    expect(jsonLine).toBeTruthy();
    const parsed = JSON.parse(jsonLine as string) as { gated: boolean; scanId: string };
    expect(parsed.gated).toBe(true);
    expect(parsed.scanId).toBe("scan_1");
  });
});
