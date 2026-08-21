/**
 * E1 — READ-ONLY repo tools for the Layer 3 agentic investigation loop
 * (`investigate.ts`). Every tool here is a pure read: no tool in this file can
 * write a file, execute a subprocess, or make a network call (that is a hard
 * invariant of the investigation loop's safety — it can look, never touch).
 * The one EXECUTION step in the E1/E2 story — running an existing test the
 * agent identifies — is deliberately kept OUT of this tool surface and lives
 * in `evidence.ts`, invoked only after the loop concludes, exactly once, on
 * exactly the one file path the model named (never agent-directed mid-loop).
 *
 * Tools read from two sources only: the already-built `AppMap` (routes, ORM
 * models, taint sources/sinks/flows — structural facts Layer 0 already
 * extracted) and, when a repo checkout is available (`ConfirmInput.repoRoot`),
 * the actual source tree via a small local file-read/scan helper (below).
 * `repoRoot` is optional — when absent (e.g. a resumed/distributed run with no
 * local checkout), `read_file`/`grep`/`find_definition` degrade to a clear
 * "no repo checkout available" message rather than throwing, and the AppMap
 * tools (`list_routes`, `get_orm_model`, `query_call_graph`) still work fully,
 * since they only ever read the in-memory App Map.
 *
 * Deliberately NOT reused: `@montr/appmap`'s `readRepoFile`/`collectFiles`.
 * No other Layer 1-5 package takes a build-time dependency on `@montr/appmap`
 * (each layer depends only on `@montr/contracts`' shared `AppMap` TYPE, never
 * the Layer-0 package itself — the same "no build-time dependency across
 * layer packages" discipline `tuning.ts` documents for `@montr/qa`), and this
 * task's file scope treats `packages/appmap/src/**` as read-only. The two
 * helpers below are small, self-contained equivalents scoped to exactly what
 * these tools need.
 */
import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import type { AppMap } from "@montr/contracts";
import type { LLMToolDefinition } from "@montr/contracts";

const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  ".turbo",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
  "target",
  ".idea",
  ".vscode",
]);
const SOURCE_EXT = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".java",
  ".go",
  ".rb",
  ".php",
]);
const MAX_SCANNED_FILES = 2000;
const MAX_SCAN_DEPTH = 14;

/** Read a repo-relative text file; `null` when missing/unreadable (mirrors `@montr/appmap`'s convention). */
async function readRepoFileLocal(dir: string, rel: string): Promise<string | null> {
  try {
    return await readFile(join(dir, rel), "utf8");
  } catch {
    return null;
  }
}

/** Bounded recursive walk collecting repo-relative source file paths. */
async function listSourceFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(current: string, depth: number): Promise<void> {
    if (out.length >= MAX_SCANNED_FILES || depth > MAX_SCAN_DEPTH) return;
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= MAX_SCANNED_FILES) return;
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name) || entry.name.startsWith(".")) continue;
        await walk(join(current, entry.name), depth + 1);
      } else if (entry.isFile()) {
        const ext = entry.name.slice(entry.name.lastIndexOf("."));
        if (SOURCE_EXT.has(ext)) out.push(relative(dir, join(current, entry.name)));
      }
    }
  }
  await walk(dir, 0);
  return out.sort();
}

/** Everything an investigation tool call needs to resolve against. */
export interface InvestigationToolContext {
  appMap: AppMap;
  /** Local checkout root for the scan's repo. Absent ⇒ file/grep tools degrade gracefully. */
  repoRoot?: string;
}

const MAX_READ_LINES = 400;
const MAX_LINE_LEN = 500;
const MAX_GREP_FILES = 400;
const MAX_GREP_MATCHES = 40;
const MAX_TOOL_RESULT_CHARS = 12_000;

function truncateLine(line: string): string {
  return line.length > MAX_LINE_LEN ? `${line.slice(0, MAX_LINE_LEN)}…[truncated]` : line;
}

function capResult(text: string): string {
  return text.length > MAX_TOOL_RESULT_CHARS
    ? `${text.slice(0, MAX_TOOL_RESULT_CHARS)}\n…[tool result truncated at ${MAX_TOOL_RESULT_CHARS} chars]`
    : text;
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.trim().length > 0 ? v.trim() : undefined;
}

function asNumber(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/* ------------------------------ tool: read_file ------------------------------ */

async function toolReadFile(
  input: Record<string, unknown>,
  ctx: InvestigationToolContext,
): Promise<string> {
  const path = asString(input.path);
  if (!path) return JSON.stringify({ error: "read_file requires a non-empty 'path'." });
  if (!ctx.repoRoot) {
    return JSON.stringify({
      error: "no repo checkout available in this run; cannot read source files directly.",
      hint: "use list_routes / get_orm_model / query_call_graph, which read the already-built App Map instead.",
    });
  }
  const content = await readRepoFileLocal(ctx.repoRoot, path);
  if (content === null) {
    return JSON.stringify({ error: `file not found or unreadable: ${path}` });
  }
  const lines = content.split(/\r?\n/);
  const start = Math.max(1, asNumber(input.startLine) ?? 1);
  const requestedEnd = asNumber(input.endLine) ?? start + MAX_READ_LINES - 1;
  const end = Math.min(lines.length, Math.min(requestedEnd, start + MAX_READ_LINES - 1));
  const slice = lines
    .slice(start - 1, end)
    .map((l, i) => `${start + i}: ${truncateLine(l)}`)
    .join("\n");
  return capResult(
    JSON.stringify({
      path,
      totalLines: lines.length,
      startLine: start,
      endLine: end,
      content: slice,
    }),
  );
}

/* -------------------------------- tool: grep --------------------------------- */

interface GrepMatch {
  file: string;
  line: number;
  text: string;
}

async function grepRepo(
  repoRoot: string,
  pattern: string,
  onlyPath: string | undefined,
  maxMatches: number,
): Promise<GrepMatch[]> {
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch {
    re = new RegExp(escapeRegExp(pattern));
  }
  const matches: GrepMatch[] = [];
  const files = onlyPath ? [onlyPath] : (await listSourceFiles(repoRoot)).slice(0, MAX_GREP_FILES);
  for (const file of files) {
    if (matches.length >= maxMatches) break;
    const content = await readRepoFileLocal(repoRoot, file);
    if (content === null) continue;
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      if (matches.length >= maxMatches) break;
      const line = lines[i] ?? "";
      if (re.test(line)) {
        matches.push({ file, line: i + 1, text: truncateLine(line.trim()) });
      }
    }
  }
  return matches;
}

async function toolGrep(
  input: Record<string, unknown>,
  ctx: InvestigationToolContext,
): Promise<string> {
  const pattern = asString(input.pattern);
  if (!pattern) return JSON.stringify({ error: "grep requires a non-empty 'pattern'." });
  if (!ctx.repoRoot) {
    return JSON.stringify({
      error: "no repo checkout available in this run; cannot grep source files.",
    });
  }
  const path = asString(input.path);
  const maxMatches = Math.min(asNumber(input.maxMatches) ?? MAX_GREP_MATCHES, MAX_GREP_MATCHES);
  const matches = await grepRepo(ctx.repoRoot, pattern, path, maxMatches);
  return capResult(
    JSON.stringify({ pattern, path: path ?? null, matchCount: matches.length, matches }),
  );
}

/* ---------------------------- tool: find_definition --------------------------- */

const DEFINITION_MARKERS =
  /\b(function|const|let|var|class|interface|type|def|public|private|protected|static|async)\b/;

async function toolFindDefinition(
  input: Record<string, unknown>,
  ctx: InvestigationToolContext,
): Promise<string> {
  const symbol = asString(input.symbol);
  if (!symbol) return JSON.stringify({ error: "find_definition requires a non-empty 'symbol'." });
  if (!ctx.repoRoot) {
    return JSON.stringify({
      error: "no repo checkout available in this run; cannot search for definitions.",
    });
  }
  const occurrences = await grepRepo(ctx.repoRoot, `\\b${escapeRegExp(symbol)}\\b`, undefined, 200);
  const definitions = occurrences.filter(
    (m) => DEFINITION_MARKERS.test(m.text) && m.text.includes(symbol),
  );
  const results = (definitions.length > 0 ? definitions : occurrences).slice(0, 20);
  return capResult(
    JSON.stringify({
      symbol,
      likelyDefinitions: results,
      note:
        definitions.length > 0
          ? undefined
          : "no line matched a definition-shaped pattern; returning raw occurrences instead.",
    }),
  );
}

/* ------------------------------ tool: query_call_graph ------------------------ */

function queryCallGraph(appMap: AppMap, file: string, line?: number): unknown[] {
  const edges = (appMap.taintFlows ?? []).filter(
    (e) =>
      e.sourceLocation.file === file ||
      e.sinkLocation.file === file ||
      e.throughLocation?.file === file,
  );
  const scoped = line
    ? edges.filter(
        (e) =>
          e.sourceLocation.line === line ||
          e.sinkLocation.line === line ||
          e.throughLocation?.line === line,
      )
    : edges;
  return (scoped.length > 0 ? scoped : edges).map((e) => ({
    source: e.sourceLocation,
    sourceKind: e.sourceKind,
    through: e.throughFunction,
    throughLocation: e.throughLocation,
    sink: e.sinkLocation,
    sinkKind: e.sinkKind,
    resolution: e.resolution,
    hops: e.hops,
    crossFile: e.crossFile,
  }));
}

function toolQueryCallGraph(input: Record<string, unknown>, ctx: InvestigationToolContext): string {
  const file = asString(input.file);
  if (!file) return JSON.stringify({ error: "query_call_graph requires a non-empty 'file'." });
  const line = asNumber(input.line);
  const edges = queryCallGraph(ctx.appMap, file, line);
  return capResult(JSON.stringify({ file, line: line ?? null, edgeCount: edges.length, edges }));
}

/* -------------------------------- tool: list_routes ---------------------------- */

function toolListRoutes(input: Record<string, unknown>, ctx: InvestigationToolContext): string {
  const path = asString(input.path);
  const method = asString(input.method)?.toUpperCase();
  const routes = ctx.appMap.routes.filter(
    (r) => (!path || r.path.includes(path)) && (!method || r.method === method),
  );
  return capResult(
    JSON.stringify({
      routeCount: routes.length,
      routes: routes.map((r) => ({
        id: r.id,
        path: r.path,
        method: r.method,
        authState: r.authState,
        authGate: r.authGate,
        handler: r.handler,
        referencedModels: r.referencedModels ?? null,
      })),
    }),
  );
}

/* ------------------------------ tool: get_orm_model ---------------------------- */

function toolGetOrmModel(input: Record<string, unknown>, ctx: InvestigationToolContext): string {
  const name = asString(input.name);
  if (!name) return JSON.stringify({ error: "get_orm_model requires a non-empty 'name'." });
  const model = ctx.appMap.ormModels.find((m) => m.name.toLowerCase() === name.toLowerCase());
  if (!model) {
    return JSON.stringify({
      error: `no ORM model named "${name}" in the App Map`,
      knownModels: ctx.appMap.ormModels.map((m) => m.name),
    });
  }
  return capResult(JSON.stringify({ model }));
}

/* -------------------------------- registry ------------------------------------ */

/** The name the loop treats as terminal — see `investigate.ts`. Not itself a repo tool. */
export const SUBMIT_CONCLUSION_TOOL = "submit_conclusion";

/**
 * The six READ-ONLY repo tools (E1) plus the one terminal tool the loop uses
 * to end an investigation with a structured verdict (`investigate.ts` treats a
 * call to `submit_conclusion` as the end of the loop, never executes it here).
 */
export const INVESTIGATION_TOOL_DEFINITIONS: LLMToolDefinition[] = [
  {
    name: "read_file",
    description:
      "Read a slice of a file from the target repository checkout, with 1-based line numbers. Bounded to 400 lines per call — request a narrower range for a large file.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Repo-relative file path." },
        startLine: { type: "number", description: "1-based start line (default 1)." },
        endLine: { type: "number", description: "1-based end line (default startLine+399)." },
      },
      required: ["path"],
    },
  },
  {
    name: "grep",
    description:
      "Search the repository (or one file) for a regular expression and return matching file:line:text triples. Bounded to 40 matches.",
    parameters: {
      type: "object",
      properties: {
        pattern: { type: "string", description: "Regular expression (JS syntax)." },
        path: { type: "string", description: "Restrict the search to this repo-relative file." },
        maxMatches: { type: "number", description: "Cap on returned matches (max 40)." },
      },
      required: ["pattern"],
    },
  },
  {
    name: "find_definition",
    description:
      "Locate the likely definition site(s) of a function/class/variable/type by name across the repository.",
    parameters: {
      type: "object",
      properties: { symbol: { type: "string", description: "The identifier to locate." } },
      required: ["symbol"],
    },
  },
  {
    name: "query_call_graph",
    description:
      "Query the App Map's resolved interprocedural taint-flow edges (source → intermediate function → sink) touching a given file, optionally at a specific line.",
    parameters: {
      type: "object",
      properties: {
        file: { type: "string", description: "Repo-relative file path." },
        line: { type: "number", description: "Optional 1-based line to narrow the query." },
      },
      required: ["file"],
    },
  },
  {
    name: "list_routes",
    description:
      "List registered HTTP routes from the App Map, with auth state, auth gate, handler location, and referenced ORM models. Optionally filter by path substring or method.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Substring to filter route paths by." },
        method: { type: "string", description: "HTTP method to filter by (e.g. GET, POST)." },
      },
    },
  },
  {
    name: "get_orm_model",
    description: "Look up an ORM model's fields and data store by name from the App Map.",
    parameters: {
      type: "object",
      properties: { name: { type: "string", description: "The ORM model name." } },
      required: ["name"],
    },
  },
  {
    name: SUBMIT_CONCLUSION_TOOL,
    description:
      "Call this EXACTLY ONCE, when investigation is complete, to submit your final verdict and end the investigation. Do not call any other tool afterward.",
    parameters: {
      type: "object",
      properties: {
        verdict: {
          type: "string",
          enum: ["confirmed_candidate", "refuted", "inconclusive"],
          description:
            "'confirmed_candidate' only when you found a concrete, reasoned exploit path with NO ownership/authorization check interrupting it. 'refuted' when you found the check that prevents exploitation. 'inconclusive' when you could not determine either way.",
        },
        rationale: {
          type: "string",
          description: "Your reasoning, citing the specific files/lines you inspected.",
        },
        ownershipCheckFound: {
          type: "boolean",
          description: "Whether you found an explicit ownership/role check guarding the resource.",
        },
        existingTestFile: {
          type: "string",
          description:
            "Repo-relative path of a REAL, EXISTING test file you found (via grep/read_file) that already exercises this exact code path, if any.",
        },
        targetRouteId: {
          type: "string",
          description:
            "The App Map route id this finding concerns, if you identified one via list_routes.",
        },
      },
      required: ["verdict", "rationale"],
    },
  },
];

/** Execute one non-terminal tool call by name. Never throws — errors are returned as tool content. */
export async function executeInvestigationTool(
  name: string,
  input: Record<string, unknown>,
  ctx: InvestigationToolContext,
): Promise<string> {
  try {
    switch (name) {
      case "read_file":
        return await toolReadFile(input, ctx);
      case "grep":
        return await toolGrep(input, ctx);
      case "find_definition":
        return await toolFindDefinition(input, ctx);
      case "query_call_graph":
        return toolQueryCallGraph(input, ctx);
      case "list_routes":
        return toolListRoutes(input, ctx);
      case "get_orm_model":
        return toolGetOrmModel(input, ctx);
      default:
        return JSON.stringify({ error: `unknown tool "${name}"` });
    }
  } catch (err) {
    return JSON.stringify({
      error: `tool "${name}" failed: ${err instanceof Error ? err.message : String(err)}`,
    });
  }
}
