#!/usr/bin/env node
/**
 * `montr-audit-verify` — tamper-evident audit-log verification CLI (§4.8, §8.5).
 *
 * Recomputes and validates the append-only audit hash chain and exits NON-ZERO
 * on any break (golden rule #7 — a tampered/truncated audit log must fail CI).
 *
 * Sources (choose one):
 *   --file <path>   verify a JSON audit export ({ events: [...] } or [...]).
 *   (stdin)         same, piped on stdin when no --file is given.
 *
 * The export is produced by `@montr/state-store`'s audit exporter; verifying the
 * export keeps this CLI a dependency-light leaf (no Prisma runtime). For live DB
 * verification, pipe that exporter's output here, or call state-store's own
 * `verifyChain` directly.
 *
 * Output is METADATA ONLY — sequence numbers, actions, break location. It never
 * prints audit metadata bodies (which are already scrubbed at write time).
 */
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { isMontrError } from "@montr/contracts";
import {
  AuditInputError,
  parseAuditExport,
  verifyAuditEvents,
  type AuditVerifyReport,
} from "./audit-verify.js";
import { SEC_EXIT, secExitLabel } from "./exit-codes.js";

const USAGE = `montr-audit-verify — tamper-evident audit hash-chain verifier

Usage:
  montr-audit-verify --file <export.json> [--client <id>] [--json]
  cat export.json | montr-audit-verify [--client <id>] [--json]

Options:
  --file <path>     Verify a JSON audit export (envelope or bare array).
  --client <id>     Restrict verification to one client id.
  --json            Emit a machine-readable JSON report.
  -h, --help        Show this help.

Exit codes: 0 OK · 1 CHAIN_BROKEN · 2 USAGE · 3 INPUT_ERROR · 4 RUNTIME_ERROR`;

interface ParsedArgs {
  file?: string;
  client?: string;
  json: boolean;
  help: boolean;
}

class UsageError extends Error {}

function parseArgs(argv: string[]): ParsedArgs {
  const args: ParsedArgs = { json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const needValue = (): string => {
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`option ${arg} requires a value`);
      return v;
    };
    switch (arg) {
      case "--file":
        args.file = needValue();
        break;
      case "--client":
        args.client = needValue();
        break;
      case "--json":
        args.json = true;
        break;
      case "-h":
      case "--help":
        args.help = true;
        break;
      default:
        throw new UsageError(`unknown option: ${arg}`);
    }
  }
  return args;
}

async function readStdin(stream: NodeJS.ReadableStream = process.stdin): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function formatReport(r: AuditVerifyReport): string {
  const lines: string[] = [];
  lines.push(`audit chain verification — ${r.ok ? "OK (intact)" : "TAMPER DETECTED"}`);
  const events = r.totalEvents < 0 ? "?" : String(r.totalEvents);
  lines.push(`clients: ${r.clients.length}  events: ${events}`);
  for (const c of r.clients) {
    const count = c.count < 0 ? "?" : String(c.count);
    if (c.ok) {
      const range =
        c.firstSequence !== undefined ? ` (seq ${c.firstSequence}-${c.lastSequence})` : "";
      lines.push(`  OK  ${c.clientId}: ${count} events${range} intact`);
    } else {
      lines.push(
        `  XX  ${c.clientId}: BROKEN at record ${c.brokenAt ?? "?"} - ${c.reason ?? "unknown"}`,
      );
    }
  }
  return lines.join("\n");
}

/**
 * Run the CLI and return an exit code (does not call process.exit — testable).
 * `out`/`err`/`stdin` are injectable for tests.
 */
export async function run(
  argv: string[],
  out: (s: string) => void = console.log,
  err: (s: string) => void = console.error,
  stdin: NodeJS.ReadableStream = process.stdin,
): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (e) {
    err(e instanceof Error ? e.message : String(e));
    err(USAGE);
    return SEC_EXIT.USAGE;
  }
  if (args.help) {
    out(USAGE);
    return SEC_EXIT.OK;
  }

  try {
    let text: string;
    try {
      text = args.file ? readFileSync(args.file, "utf8") : await readStdin(stdin);
    } catch (e) {
      throw new AuditInputError(
        `could not read ${args.file ? `file ${args.file}` : "stdin"}: ${(e as Error).message}`,
      );
    }
    const events = parseAuditExport(text);
    const report: AuditVerifyReport = verifyAuditEvents(
      events,
      args.client ? { clientId: args.client } : {},
    );

    if (args.json) out(JSON.stringify(report, null, 2));
    else out(formatReport(report));
    return report.ok ? SEC_EXIT.OK : SEC_EXIT.CHAIN_BROKEN;
  } catch (e) {
    if (e instanceof AuditInputError) {
      err(`input error: ${e.message}`);
      return SEC_EXIT.INPUT_ERROR;
    }
    if (isMontrError(e)) {
      err(`${e.code}: ${e.message}`);
      return SEC_EXIT.RUNTIME_ERROR;
    }
    err(`unexpected error: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
    return SEC_EXIT.RUNTIME_ERROR;
  }
}

// Entrypoint guard: only run when invoked directly (never on import).
const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  run(process.argv.slice(2))
    .then((code) => {
      if (code !== SEC_EXIT.OK) console.error(`audit-verify exit ${code} (${secExitLabel(code)})`);
      process.exit(code);
    })
    .catch((e) => {
      console.error(e);
      process.exit(SEC_EXIT.RUNTIME_ERROR);
    });
}
