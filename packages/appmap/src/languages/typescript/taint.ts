/**
 * Taint sources + sinks catalog (build-plan §5.1, deterministic).
 *
 * Sources = points where untrusted input enters (req query/body/params/headers/
 * cookies, Next page `searchParams`, `req.json()`, `cookies()`/`headers()`).
 * Sinks = dangerous operations tainted input may reach (raw SQL/ORM, command
 * exec, fs, `dangerouslySetInnerHTML`/`innerHTML`, redirect, eval, deserialize).
 * Sinks anchor to the tainted ARGUMENT line (e.g. the interpolated template), so
 * locations line up with ground truth. Sources link to the route in their file.
 */
import { Node, SyntaxKind } from "ts-morph";
import type { Project, SourceFile } from "ts-morph";
import type { TaintSink, TaintSinkKind, TaintSource, TaintSourceKind } from "@montr/contracts";
import { toRepoRelative } from "../../sources.js";

export interface TaintScanResult {
  taintSources: TaintSource[];
  taintSinks: TaintSink[];
}

function relPath(abs: string, dir: string): string {
  return toRepoRelative(abs, dir);
}

const REQ_PROP_KIND: Record<string, TaintSourceKind> = {
  query: "query_param",
  body: "request_body",
  params: "path_param",
  headers: "request_header",
  cookies: "cookie",
};

function isTemplateOrConcat(node: Node | undefined): boolean {
  if (!node) return false;
  const k = node.getKind();
  return (
    k === SyntaxKind.TemplateExpression ||
    k === SyntaxKind.NoSubstitutionTemplateLiteral ||
    k === SyntaxKind.BinaryExpression
  );
}

function scanSources(
  sf: SourceFile,
  rel: string,
  routeId: string | undefined,
  out: TaintSource[],
): void {
  const push = (kind: TaintSourceKind, line: number, description: string): void => {
    out.push({
      kind,
      location: { file: rel, line },
      description,
      ...(routeId ? { routeId } : {}),
    });
  };

  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression().getText();
    if (/\.searchParams\.get$/.test(callee) || /(^|\.)searchParams\.getAll$/.test(callee)) {
      push("query_param", call.getStartLineNumber(), `${callee}(...)`);
    } else if (/^(req|request)\.(json|formData|text)$/.test(callee)) {
      push("request_body", call.getStartLineNumber(), `${callee}()`);
    } else if (/\bcookies\(\)\.get$/.test(callee)) {
      push("cookie", call.getStartLineNumber(), "cookies().get(...)");
    } else if (/\bheaders\(\)\.get$/.test(callee)) {
      push("request_header", call.getStartLineNumber(), "headers().get(...)");
    }
  }

  for (const pa of sf.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    const exprText = pa.getExpression().getText();
    const name = pa.getName();
    // Next.js page prop: `searchParams.<field>`.
    if (exprText === "searchParams" && name !== "get" && name !== "getAll") {
      push("query_param", pa.getStartLineNumber(), `searchParams.${name}`);
      continue;
    }
    // Express/Next request members: `req.query`, `req.body`, `req.params`, ...
    if (/^(req|request|ctx\.req)$/.test(exprText)) {
      const kind = REQ_PROP_KIND[name];
      if (kind) push(kind, pa.getStartLineNumber(), `${exprText}.${name}`);
    }
  }
}

function scanSinks(sf: SourceFile, rel: string, out: TaintSink[]): void {
  const push = (kind: TaintSinkKind, line: number, description: string): void => {
    out.push({ kind, location: { file: rel, line }, description });
  };

  // Call-expression sinks.
  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression().getText();
    const args = call.getArguments();
    const arg0 = args[0];
    const anchor =
      isTemplateOrConcat(arg0) && arg0 ? arg0.getStartLineNumber() : call.getStartLineNumber();

    if (/\.\$(queryRawUnsafe|executeRawUnsafe|queryRaw|executeRaw)$/.test(callee)) {
      const short = callee.replace(/^.*\./, "");
      push("orm_raw_query", anchor, `prisma.${short}(...)`);
    } else if (/(^|\.)query$/.test(callee) && isTemplateOrConcat(arg0)) {
      push("sql_query", anchor, `${callee}(<interpolated>)`);
    } else if (/(^|\.)(exec|execSync|spawn|spawnSync|execFile|execFileSync)$/.test(callee)) {
      push("command_exec", call.getStartLineNumber(), `${callee}(...)`);
    } else if (/(^|\.)(writeFile|writeFileSync|appendFile|appendFileSync)$/.test(callee)) {
      push("fs_write", call.getStartLineNumber(), `${callee}(...)`);
    } else if (/(^|\.)(readFile|readFileSync|createReadStream)$/.test(callee)) {
      push("fs_read", call.getStartLineNumber(), `${callee}(...)`);
    } else if (callee === "eval") {
      push("eval", call.getStartLineNumber(), "eval(...)");
    } else if (/(^|\.)redirect$/.test(callee)) {
      push("redirect", call.getStartLineNumber(), `${callee}(...)`);
    } else if (/(^|\.)(unserialize|deserialize)$/.test(callee)) {
      push("deserialize", call.getStartLineNumber(), `${callee}(...)`);
    } else if (/(^|\.)render$/.test(callee) && /^(res|response|ctx)\./.test(callee)) {
      push("template_render", call.getStartLineNumber(), `${callee}(...)`);
    }
  }

  // Tagged templates: `sql`...`` / prisma `$queryRaw`...``.
  for (const tt of sf.getDescendantsOfKind(SyntaxKind.TaggedTemplateExpression)) {
    const tag = tt.getTag().getText();
    if (/\.\$(queryRaw|executeRaw)$/.test(tag)) {
      push(
        "orm_raw_query",
        tt.getTemplate().getStartLineNumber(),
        `${tag.replace(/^.*\./, "prisma.")}\`...\``,
      );
    }
  }

  // JSX + DOM HTML sinks.
  for (const attr of sf.getDescendantsOfKind(SyntaxKind.JsxAttribute)) {
    if (attr.getNameNode().getText() === "dangerouslySetInnerHTML") {
      push("html_render", attr.getStartLineNumber(), "dangerouslySetInnerHTML");
    }
  }
  for (const bin of sf.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
    if (bin.getOperatorToken().getKind() !== SyntaxKind.EqualsToken) continue;
    const left = bin.getLeft().getText();
    if (/\.(innerHTML|outerHTML)$/.test(left)) {
      push("html_render", bin.getStartLineNumber(), `${left} = ...`);
    }
  }
}

/** Catalog taint sources + sinks across the project, linking sources to routes. */
export function scanTaint(
  project: Project,
  dir: string,
  routeIdsByFile: Map<string, string[]>,
): TaintScanResult {
  const taintSources: TaintSource[] = [];
  const taintSinks: TaintSink[] = [];

  for (const sf of project.getSourceFiles()) {
    const rel = relPath(sf.getFilePath(), dir);
    const routeId = routeIdsByFile.get(rel)?.[0];
    scanSources(sf, rel, routeId, taintSources);
    scanSinks(sf, rel, taintSinks);
  }

  const dedup = <T extends { kind: string; location: { file: string; line: number } }>(
    arr: T[],
  ): T[] => {
    const seen = new Set<string>();
    const res: T[] = [];
    for (const x of arr) {
      const key = `${x.kind}:${x.location.file}:${x.location.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      res.push(x);
    }
    return res;
  };

  const sortByLoc = <T extends { location: { file: string; line: number } }>(arr: T[]): T[] =>
    arr.sort(
      (a, b) => a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line,
    );

  return {
    taintSources: sortByLoc(dedup(taintSources)),
    taintSinks: sortByLoc(dedup(taintSinks)),
  };
}
