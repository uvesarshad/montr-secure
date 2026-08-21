/**
 * `montr scan` (A15) — the CLI entry point into the real `apps/api` pipeline:
 * create (or diff-scope) a scan, poll it to completion, print a readable
 * summary, and exit non-zero when a CONFIRMED finding at/above `--fail-on`
 * exists — the shape a CI job needs to gate a PR on.
 *
 * Talks ONLY to the real HTTP API (`./http.ts`, the same `POST /scans` /
 * `GET /scans/:id/progress` / `GET /scans/:id/findings` routes the web
 * console's contract is built on) — it never touches the orchestrator,
 * database, or LLM gateway directly. `run()` takes every side effect
 * (network, git, clock, output) as injectable deps so it is unit-testable
 * without a real API server or git repo (see ./cli.test.ts).
 */
import { SeveritySchema, type ConfirmedFinding, type Scan, type Severity } from "@montr/contracts";
import { createApiClient, CliApiError, type MontrApiClient } from "./http.js";
import { detectBranch, detectChangedFiles, detectRepoName } from "./git.js";
import { CLI_EXIT, exitLabel } from "./exit-codes.js";

const SEVERITY_ORDER: readonly Severity[] = SeveritySchema.options; // info < low < medium < high < critical
const DEFAULT_API_URL = "http://localhost:3001";
const DEFAULT_FAIL_ON: Severity = "high";
const DEFAULT_POLL_INTERVAL_MS = 4_000;
const DEFAULT_TIMEOUT_MS = 30 * 60 * 1_000; // 30 minutes
const TERMINAL_STATUSES = new Set(["completed", "failed", "cancelled", "partial"]);

export const USAGE = `montr scan — trigger and gate on a Montr Secure scan (A15)

Usage:
  montr scan [path] [options]

Arguments:
  path                    Local repo path to scan (default: ".")

Options:
  --repo <name>            Repository identifier sent to the API
                            (default: parsed from the "origin" git remote, else the directory name)
  --branch <name>           Branch name (default: current git branch, else "main")
  --mode <full|diff>        Scan mode (default: "full")
  --base <ref>              Base ref to diff against for --mode diff (default: "main")
  --changed-files <a,b,c>   Explicit changed-files list for --mode diff (overrides the git-derived list)
  --api-url <url>           API base URL (default: $MONTR_API_URL or ${DEFAULT_API_URL})
  --token <jwt>             Bearer auth token (default: $MONTR_API_TOKEN)
  --email <email>           Login email, used with --password when --token is not given (default: $MONTR_API_EMAIL)
  --password <password>     Login password (default: $MONTR_API_PASSWORD)
  --fail-on <severity>      Exit non-zero if a CONFIRMED finding at/above this severity exists
                            (info|low|medium|high|critical, default: "${DEFAULT_FAIL_ON}")
  --poll-interval <ms>      Progress poll interval in ms (default: ${DEFAULT_POLL_INTERVAL_MS})
  --timeout <ms>            Max time to wait for the scan to finish, in ms (default: ${DEFAULT_TIMEOUT_MS})
  --json                    Emit a machine-readable JSON summary instead of text
  -h, --help                Show this help

Exit codes: 0 OK · 1 FINDINGS · 2 USAGE · 3 API_ERROR · 4 SCAN_FAILED · 5 RUNTIME_ERROR`;

interface ParsedArgs {
  path: string;
  repo?: string;
  branch?: string;
  mode: "full" | "diff";
  base: string;
  changedFiles?: string[];
  apiUrl?: string;
  token?: string;
  email?: string;
  password?: string;
  failOn: Severity;
  pollIntervalMs: number;
  timeoutMs: number;
  json: boolean;
  help: boolean;
}

class UsageError extends Error {}

function isSeverity(v: string): v is Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(v);
}

function parsePositiveInt(name: string, raw: string): number {
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) throw new UsageError(`${name} must be a positive integer`);
  return n;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const rest = argv[0] === "scan" ? argv.slice(1) : argv;
  const args: ParsedArgs = {
    path: ".",
    mode: "full",
    base: "main",
    failOn: DEFAULT_FAIL_ON,
    pollIntervalMs: DEFAULT_POLL_INTERVAL_MS,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    json: false,
    help: false,
  };
  let sawPositional = false;

  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i] as string;
    const needValue = (): string => {
      const v = rest[++i];
      if (v === undefined) throw new UsageError(`option ${arg} requires a value`);
      return v;
    };
    switch (arg) {
      case "--repo":
        args.repo = needValue();
        break;
      case "--branch":
        args.branch = needValue();
        break;
      case "--mode": {
        const v = needValue();
        if (v !== "full" && v !== "diff") throw new UsageError(`--mode must be "full" or "diff"`);
        args.mode = v;
        break;
      }
      case "--base":
        args.base = needValue();
        break;
      case "--changed-files":
        args.changedFiles = needValue()
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      case "--api-url":
        args.apiUrl = needValue();
        break;
      case "--token":
        args.token = needValue();
        break;
      case "--email":
        args.email = needValue();
        break;
      case "--password":
        args.password = needValue();
        break;
      case "--fail-on": {
        const v = needValue();
        if (!isSeverity(v))
          throw new UsageError(`--fail-on must be one of ${SEVERITY_ORDER.join("|")}`);
        args.failOn = v;
        break;
      }
      case "--poll-interval":
        args.pollIntervalMs = parsePositiveInt("--poll-interval", needValue());
        break;
      case "--timeout":
        args.timeoutMs = parsePositiveInt("--timeout", needValue());
        break;
      case "--json":
        args.json = true;
        break;
      case "-h":
      case "--help":
        args.help = true;
        break;
      default:
        if (arg.startsWith("-")) throw new UsageError(`unknown option: ${arg}`);
        if (sawPositional) throw new UsageError(`unexpected extra argument: ${arg}`);
        args.path = arg;
        sawPositional = true;
    }
  }
  return args;
}

function severityAtLeast(sev: Severity, floor: Severity): boolean {
  return SEVERITY_ORDER.indexOf(sev) >= SEVERITY_ORDER.indexOf(floor);
}

function summarizeBySeverity(findings: ConfirmedFinding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

export interface RunDeps {
  out?: (s: string) => void;
  err?: (s: string) => void;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  createClient?: (opts: { baseUrl: string; token?: string }) => MontrApiClient;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  git?: {
    detectBranch: typeof detectBranch;
    detectRepoName: typeof detectRepoName;
    detectChangedFiles: typeof detectChangedFiles;
  };
}

interface ScanSummary {
  scanId: string;
  status: Scan["status"];
  repo: string;
  branch: string;
  mode: string;
  confirmedBySeverity: Record<Severity, number>;
  highestSeverity: Severity | null;
  gated: boolean;
  failOn: Severity;
}

function printSummary(out: (s: string) => void, s: ScanSummary, json: boolean): void {
  if (json) {
    out(JSON.stringify(s, null, 2));
    return;
  }
  out("");
  out(`Scan ${s.scanId} — ${s.repo}@${s.branch} (${s.mode}) — ${s.status}`);
  out("Confirmed findings by severity:");
  for (const sev of SEVERITY_ORDER) {
    const count = s.confirmedBySeverity[sev];
    if (count > 0) out(`  ${sev.padEnd(8)} ${count}`);
  }
  if (Object.values(s.confirmedBySeverity).every((c) => c === 0)) out("  (none)");
  out(
    s.gated
      ? `⛔ FAIL — a confirmed finding at/above "${s.failOn}" severity exists.`
      : `OK — no confirmed finding at/above "${s.failOn}" severity.`,
  );
}

/**
 * Run the CLI and return an exit code (never calls process.exit — testable).
 * Every side effect (network, git, clock, output) is injectable via `deps`.
 */
export async function run(argv: string[], deps: RunDeps = {}): Promise<number> {
  const out = deps.out ?? console.log;
  const err = deps.err ?? console.error;
  const env = deps.env ?? process.env;
  const sleep = deps.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  const now = deps.now ?? Date.now;
  const git = deps.git ?? { detectBranch, detectRepoName, detectChangedFiles };
  const createClient = deps.createClient ?? createApiClient;

  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (e) {
    err(e instanceof Error ? e.message : String(e));
    err(USAGE);
    return CLI_EXIT.USAGE;
  }
  if (args.help) {
    out(USAGE);
    return CLI_EXIT.OK;
  }

  try {
    const repo = args.repo ?? git.detectRepoName(args.path);
    const branch = args.branch ?? git.detectBranch(args.path) ?? "main";
    const apiUrl = args.apiUrl ?? env["MONTR_API_URL"] ?? DEFAULT_API_URL;

    let token = args.token ?? env["MONTR_API_TOKEN"];
    const email = args.email ?? env["MONTR_API_EMAIL"];
    const password = args.password ?? env["MONTR_API_PASSWORD"];

    let client = createClient({ baseUrl: apiUrl, ...(token ? { token } : {}) });
    if (!token) {
      if (!email || !password) {
        err(
          "Authentication required: pass --token (or $MONTR_API_TOKEN), or " +
            "--email/--password (or $MONTR_API_EMAIL/$MONTR_API_PASSWORD).",
        );
        err(USAGE);
        return CLI_EXIT.USAGE;
      }
      token = await client.login(email, password);
      client = createClient({ baseUrl: apiUrl, token });
    }

    const scope =
      args.mode === "diff"
        ? {
            mode: "diff" as const,
            changedFiles: args.changedFiles ?? git.detectChangedFiles(args.path, args.base),
            reachableFromChanges: true,
          }
        : undefined;

    const created = await client.createScan({
      repo,
      branch,
      mode: args.mode,
      ...(scope ? { scope } : {}),
    });
    out(`Created scan ${created.id} for ${repo}@${branch} (${args.mode})`);

    const deadline = now() + args.timeoutMs;
    let scan: Scan = created;
    let printedProgress = 0;
    while (!TERMINAL_STATUSES.has(scan.status)) {
      if (now() >= deadline) {
        err(`Timed out after ${args.timeoutMs}ms waiting for scan ${scan.id} to finish.`);
        return CLI_EXIT.SCAN_FAILED;
      }
      await sleep(args.pollIntervalMs);
      const [progress, latest] = await Promise.all([
        client.getProgress(scan.id),
        client.getScan(scan.id),
      ]);
      if (!args.json) {
        for (const evt of progress.slice(printedProgress)) {
          out(`  [${evt.layer}] ${evt.phase} ${evt.pct}%`);
        }
      }
      printedProgress = progress.length;
      scan = latest;
    }

    if (scan.status === "failed" || scan.status === "cancelled") {
      err(`Scan ${scan.id} ended with status "${scan.status}".`);
      return CLI_EXIT.SCAN_FAILED;
    }

    const findings = await client.getFindings(scan.id);
    const confirmedBySeverity = summarizeBySeverity(findings.confirmed);
    const highestSeverity =
      findings.confirmed.length > 0
        ? findings.confirmed.reduce<Severity>(
            (max, f) => (severityAtLeast(f.severity, max) ? f.severity : max),
            "info",
          )
        : null;
    const gated = findings.confirmed.some((f) => severityAtLeast(f.severity, args.failOn));

    printSummary(
      out,
      {
        scanId: scan.id,
        status: scan.status,
        repo,
        branch,
        mode: args.mode,
        confirmedBySeverity,
        highestSeverity,
        gated,
        failOn: args.failOn,
      },
      args.json,
    );

    return gated ? CLI_EXIT.FINDINGS : CLI_EXIT.OK;
  } catch (e) {
    if (e instanceof CliApiError) {
      err(`API error (${e.status}${e.code ? ` ${e.code}` : ""}): ${e.message}`);
      return CLI_EXIT.API_ERROR;
    }
    err(`unexpected error: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
    return CLI_EXIT.RUNTIME_ERROR;
  }
}

export { CLI_EXIT, exitLabel };
