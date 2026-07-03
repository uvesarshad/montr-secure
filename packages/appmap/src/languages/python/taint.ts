/**
 * Python taint sources + sinks catalog (Layer 0, deterministic).
 *
 * Sources = where untrusted input enters: Django `request.GET/POST/COOKIES/…`,
 * Flask `request.args/form/json`, DRF `request.data/query_params`, and FastAPI
 * `Query()/Body()/Path()/…` parameters. Sinks = dangerous operations tainted
 * input may reach: raw SQL (`cursor.execute` interpolation, Django `.raw()/.extra()`),
 * command exec (`os.system`/`subprocess`), `eval`/`exec`, template/HTML injection
 * (`mark_safe`, `render_template_string`, unescaped `HttpResponse`), SSRF
 * (`requests`/`httpx` on a dynamic URL), open-redirect, path traversal (`open`),
 * and unsafe deserialization (`pickle`/`yaml.load`).
 *
 * ⚠️ Sink DESCRIPTIONS are the confirmation contract: `confirm/taxonomy.ts`
 * scans them for unsafe/safe markers. Dangerous notes deliberately avoid every
 * safe-marker substring (`parameteri`, `escap`, `saniti`, `validate`, `allowlist`,
 * `placeholder`) so a dangerous sink is never mis-read as sanitized, and safe
 * notes carry `parameterized` so a fixed call is correctly demoted.
 */
import type { TaintSink, TaintSinkKind, TaintSource, TaintSourceKind } from "@montr/contracts";
import {
  calleeText,
  descendants,
  field,
  isDynamicString,
  isFString,
  lineOf,
  positionalArgs,
  stringValue,
  type ParsedModule,
} from "./parser.js";

export interface PythonTaintResult {
  taintSources: TaintSource[];
  taintSinks: TaintSink[];
}

/** `request.<TOKEN>` → source kind. */
const SOURCE_KIND: Record<string, TaintSourceKind> = {
  GET: "query_param",
  args: "query_param",
  query_params: "query_param",
  values: "query_param",
  POST: "request_body",
  form: "request_body",
  data: "request_body",
  json: "request_body",
  body: "request_body",
  files: "request_body",
  COOKIES: "cookie",
  cookies: "cookie",
  headers: "request_header",
  META: "request_header",
};

/** FastAPI parameter constructor → source kind. */
const PARAM_CTOR_KIND: Record<string, TaintSourceKind> = {
  Query: "query_param",
  Body: "request_body",
  Form: "request_body",
  File: "request_body",
  Path: "path_param",
  Header: "request_header",
  Cookie: "cookie",
};

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

function scanSources(mod: ParsedModule, routeId: string | undefined, out: TaintSource[]): void {
  const push = (kind: TaintSourceKind, line: number, description: string): void => {
    out.push({
      kind,
      location: { file: mod.rel, line },
      description,
      ...(routeId ? { routeId } : {}),
    });
  };

  // `request.GET.get("x")`, `request.form.get("y")`, `request.get_json()`
  for (const call of descendants(mod.root, "call")) {
    const callee = calleeText(call);
    const getM = /^request\.([A-Za-z_]+)\.get$/.exec(callee);
    if (getM?.[1] && SOURCE_KIND[getM[1]]) {
      const param = stringValue(positionalArgs(call)[0]);
      push(
        SOURCE_KIND[getM[1]]!,
        lineOf(call),
        `request.${getM[1]}.get(${param ? `'${param}'` : "…"})`,
      );
      continue;
    }
    if (/^request\.get_json$/.test(callee)) {
      push("request_body", lineOf(call), "request.get_json()");
    }
  }

  // `request.GET["x"]`, `request.form["y"]`
  for (const sub of descendants(mod.root, "subscript")) {
    const value = field(sub, "value")?.text ?? "";
    const m = /^request\.([A-Za-z_]+)$/.exec(value);
    if (!m?.[1] || !SOURCE_KIND[m[1]]) continue;
    const param = stringValue(field(sub, "subscript"));
    push(SOURCE_KIND[m[1]]!, lineOf(sub), `request.${m[1]}[${param ? `'${param}'` : "…"}]`);
  }

  // Bare reads: `request.data`, `request.body`, `request.json`, `request.GET`
  for (const attr of descendants(mod.root, "attribute")) {
    const m = /^request\.([A-Za-z_]+)$/.exec(attr.text);
    if (!m?.[1] || !SOURCE_KIND[m[1]]) continue;
    push(SOURCE_KIND[m[1]]!, lineOf(attr), `request.${m[1]}`);
  }

  // FastAPI parameter injectors: `q: str = Query(...)`, `id: int = Path(...)`
  for (const call of descendants(mod.root, "call")) {
    const leaf = calleeText(call).split(".").pop() ?? "";
    const kind = PARAM_CTOR_KIND[leaf];
    if (!kind) continue;
    const parent = call.parent;
    const paramName =
      parent && (parent.type === "typed_default_parameter" || parent.type === "default_parameter")
        ? (field(parent, "name")?.text ?? undefined)
        : undefined;
    push(kind, lineOf(call), `${paramName ? `${paramName} = ` : ""}${leaf}(…) [FastAPI param]`);
  }
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

function scanSinks(mod: ParsedModule, out: TaintSink[]): void {
  const push = (kind: TaintSinkKind, line: number, description: string): void => {
    out.push({ kind, location: { file: mod.rel, line }, description });
  };

  for (const call of descendants(mod.root, "call")) {
    const callee = calleeText(call);
    const leaf = callee.split(".").pop() ?? callee;
    const args = positionalArgs(call);
    const arg0 = args[0];
    const arg0Line = arg0 ? lineOf(arg0) : lineOf(call);

    // 1. Django raw ORM: `.raw(...)` / `.extra(...)`
    if (leaf === "raw" || leaf === "extra") {
      push("orm_raw_query", arg0Line, `${callee}(…) — raw orm sql, bypasses the query builder`);
      continue;
    }
    // 2. DB cursor execute → SQL. Parameterized (>=2 args) is SAFE; interpolation is not.
    if (leaf === "execute" || leaf === "executemany") {
      if (args.length >= 2) {
        push("sql_query", arg0Line, `${callee}(…, params) — parameterized query`);
      } else if (isDynamicString(arg0)) {
        push("sql_query", arg0Line, `${callee}(…) — raw sql via string interpolation`);
      }
      continue;
    }
    // 3. OS command execution.
    if (callee === "os.system" || callee === "os.popen") {
      push("command_exec", lineOf(call), `${callee}(…) — os command from request input`);
      continue;
    }
    if (
      /^subprocess\.(call|run|Popen|check_output|check_call|getoutput|getstatusoutput)$/.test(
        callee,
      )
    ) {
      const shell = /shell\s*=\s*True/.test(call.text);
      push(
        "command_exec",
        lineOf(call),
        `${callee}(…${shell ? ", shell=True" : ""}) — subprocess from request input`,
      );
      continue;
    }
    // 4. Dynamic code execution.
    if (callee === "eval" || callee === "exec") {
      push("eval", lineOf(call), `${callee}(…) — dynamic code execution`);
      continue;
    }
    // 5. Template / HTML injection.
    if (leaf === "mark_safe") {
      push("html_render", lineOf(call), `mark_safe(…) — raw html marked safe (xss)`);
      continue;
    }
    if (leaf === "render_template_string") {
      push(
        "template_render",
        lineOf(call),
        `render_template_string(…) — server-side template injection`,
      );
      continue;
    }
    if (leaf === "render" && /Template\s*\(/.test(callee)) {
      push(
        "template_render",
        lineOf(call),
        `Template(…).render(…) — server-side template injection`,
      );
      continue;
    }
    // Only a DIRECT f-string body is a reflected-XSS sink; wrapping a variable
    // (`HttpResponse(html)`) or fetched bytes is not, and would be noise.
    if ((leaf === "HttpResponse" || leaf === "HTMLResponse") && arg0 && isFString(arg0)) {
      push("html_render", arg0Line, `${leaf}(…) — raw html response body (xss)`);
      continue;
    }
    // 6. SSRF — outbound request to a dynamic URL.
    if (
      /^(requests|httpx)\.(get|post|put|patch|delete|head|options|request)$/.test(callee) &&
      isDynamicString(arg0)
    ) {
      push(
        "http_client",
        lineOf(call),
        `${callee}(…) — server-side request to a user-controlled url (ssrf)`,
      );
      continue;
    }
    if (
      (/(^|\.)urlopen$/.test(callee) || callee === "urllib.request.urlopen") &&
      isDynamicString(arg0)
    ) {
      push(
        "http_client",
        lineOf(call),
        `${leaf}(…) — server-side request to a user-controlled url (ssrf)`,
      );
      continue;
    }
    // 7. Open redirect.
    if (
      (leaf === "redirect" || leaf === "HttpResponseRedirect" || leaf === "RedirectResponse") &&
      isDynamicString(arg0)
    ) {
      push("redirect", lineOf(call), `${leaf}(…) — open redirect to user input`);
      continue;
    }
    // 8. Unsafe deserialization.
    if (/^(pickle|marshal|dill|cpickle|_pickle)\.(loads?|load)$/.test(callee)) {
      push("deserialize", lineOf(call), `${callee}(…) — untrusted deserialization`);
      continue;
    }
    if (callee === "yaml.load") {
      const safeLoader = /Safe(Loader|)/.test(call.text) && /safe/i.test(call.text);
      if (!safeLoader)
        push("deserialize", lineOf(call), `yaml.load(…) — unsafe yaml deserialization`);
      continue;
    }
    // 9. Filesystem open with a dynamic path.
    if (callee === "open" && isDynamicString(arg0)) {
      const mode = stringValue(args[1]) ?? "r";
      const write = /[wax+]/.test(mode);
      push(
        write ? "fs_write" : "fs_read",
        lineOf(call),
        `open(…, '${mode}') — filesystem path from request input (path traversal)`,
      );
      continue;
    }
  }
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

function dedupeByLoc<T extends { kind: string; location: { file: string; line: number } }>(
  arr: T[],
): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const x of arr) {
    const key = `${x.kind}:${x.location.file}:${x.location.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(x);
  }
  return out;
}

function sortByLoc<T extends { location: { file: string; line: number } }>(arr: T[]): T[] {
  return arr.sort(
    (a, b) => a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line,
  );
}

/** Catalog taint sources + sinks across all modules, linking sources to routes by file. */
export function scanPythonTaint(
  mods: ParsedModule[],
  routeIdsByFile: Map<string, string[]>,
): PythonTaintResult {
  const taintSources: TaintSource[] = [];
  const taintSinks: TaintSink[] = [];
  for (const mod of mods) {
    const routeId = routeIdsByFile.get(mod.rel)?.[0];
    scanSources(mod, routeId, taintSources);
    scanSinks(mod, taintSinks);
  }
  return {
    taintSources: sortByLoc(dedupeByLoc(taintSources)),
    taintSinks: sortByLoc(dedupeByLoc(taintSinks)),
  };
}
