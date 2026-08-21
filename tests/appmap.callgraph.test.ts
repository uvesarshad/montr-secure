/**
 * A21 — Python and JVM interprocedural (call-graph) taint-flow resolution.
 *
 * Mirrors the bounded-scope contract `typescript/callgraph.ts` already has,
 * proven the same way `tests/appmap.python.test.ts` proves the TS one: build
 * small, precise fixtures for each resolved pattern (same-file direct-call,
 * same-file return-propagated, one-hop relative-import for Python), then run
 * the real analyzer over a slice of this repo's OWN vulnerable-app corpus as
 * an offline, no-crash integration smoke check (real code is far messier than
 * any hand-built fixture, and neither corpus was written to exercise this
 * analyzer's specific bounded patterns — see the module doc comments for
 * exactly what tier each language reaches and why).
 */
import { fileURLToPath } from "node:url";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, it, expect } from "vitest";

import { scanPythonTaintFlows } from "../packages/appmap/src/languages/python/callgraph";
import {
  getPythonParser,
  parseModule,
  type ParsedModule,
} from "../packages/appmap/src/languages/python/parser";
import {
  scanJavaTaintFlows,
  type JavaFileForCallgraph,
} from "../packages/appmap/src/languages/java/callgraph";
import { parseJava } from "../packages/appmap/src/languages/java/parser";

const PYGOAT_DIR = fileURLToPath(new URL("../corpus/pygoat", import.meta.url));
const JAVASECCODE_DIR = fileURLToPath(new URL("../corpus/javaseccode", import.meta.url));
const JVM_VULN_DIR = fileURLToPath(new URL("../corpus/jvm-vuln", import.meta.url));

async function pyMods(entries: Array<[string, string]>): Promise<ParsedModule[]> {
  const parser = await getPythonParser();
  return entries.map(([rel, source]) => {
    const root = parseModule(parser, source);
    if (!root) throw new Error(`parse failed for ${rel}`);
    return { rel, source, root };
  });
}

async function javaFiles(entries: Array<[string, string]>): Promise<JavaFileForCallgraph[]> {
  const out: JavaFileForCallgraph[] = [];
  for (const [rel, source] of entries) {
    const root = await parseJava(source);
    if (!root) throw new Error(`parse failed for ${rel}`);
    out.push({ rel, root });
  }
  return out;
}

/** Minimal recursive walk (no fast-glob dep at repo-root test scope) collecting
 * every file under `dir` whose name ends with `ext`, skipping build output. */
async function walkFiles(dir: string, ext: string, base = ""): Promise<string[]> {
  const entries = await readdir(join(dir, base), { withFileTypes: true });
  const out: string[] = [];
  for (const entry of entries) {
    if (entry.name === "target" || entry.name === "build" || entry.name === "node_modules")
      continue;
    const rel = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.push(...(await walkFiles(dir, ext, rel)));
    } else if (entry.isFile() && entry.name.endsWith(ext)) {
      out.push(rel);
    }
  }
  return out;
}

async function loadRealTree(dir: string, ext: string): Promise<Array<[string, string]>> {
  const files = (await walkFiles(dir, ext)).sort();
  const out: Array<[string, string]> = [];
  for (const rel of files) {
    out.push([rel, await readFile(join(dir, rel), "utf8")]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Python — tier (a)+(b)+(c)
// ---------------------------------------------------------------------------
describe("python callgraph — bounded interprocedural taint flows (A21)", () => {
  it("resolves a same-file DIRECT pass-through (tier b, hops=1)", async () => {
    const mods = await pyMods([
      [
        "views.py",
        [
          "def helper(x):",
          "    cursor.execute(x)",
          "",
          "def handler():",
          "    uid = request.args.get('id')",
          "    helper(uid)",
        ].join("\n"),
      ],
    ]);
    const edges = scanPythonTaintFlows(mods);
    expect(edges).toHaveLength(1);
    const e = edges[0]!;
    expect(e.resolution).toBe("direct-call");
    expect(e.hops).toBe(1);
    expect(e.crossFile).toBe(false);
    expect(e.throughFunction).toBe("helper");
    expect(e.sinkKind).toBe("sql_query");
    expect(e.sourceKind).toBe("query_param");
  });

  it("resolves a same-file RETURN-PROPAGATED wrapped call (tier b, hops=2)", async () => {
    const mods = await pyMods([
      [
        "views.py",
        [
          "def passthrough(x):",
          "    return x",
          "",
          "def handler():",
          "    uid = request.args.get('id')",
          "    cursor.execute(passthrough(uid))",
        ].join("\n"),
      ],
    ]);
    const edges = scanPythonTaintFlows(mods);
    expect(edges).toHaveLength(1);
    const e = edges[0]!;
    expect(e.resolution).toBe("return-propagated");
    expect(e.hops).toBe(2);
    expect(e.sinkKind).toBe("sql_query");
  });

  it("resolves a same-file RETURN-PROPAGATED assign-then-later-use (tier b, hops=2)", async () => {
    const mods = await pyMods([
      [
        "views.py",
        [
          "def passthrough(x):",
          "    return x",
          "",
          "def handler():",
          "    uid = request.args.get('id')",
          "    safe = passthrough(uid)",
          "    cursor.execute(safe)",
        ].join("\n"),
      ],
    ]);
    const edges = scanPythonTaintFlows(mods);
    expect(edges).toHaveLength(1);
    expect(edges[0]!.resolution).toBe("return-propagated");
    expect(edges[0]!.hops).toBe(2);
  });

  it("resolves a ONE-HOP relative import across files (tier c, crossFile=true)", async () => {
    const mods = await pyMods([
      ["myapp/helpers.py", ["def parse_id(x):", "    cursor.execute(x)"].join("\n")],
      [
        "myapp/views.py",
        [
          "from .helpers import parse_id",
          "",
          "def handler():",
          "    uid = request.args.get('id')",
          "    parse_id(uid)",
        ].join("\n"),
      ],
    ]);
    const edges = scanPythonTaintFlows(mods);
    expect(edges).toHaveLength(1);
    const e = edges[0]!;
    expect(e.crossFile).toBe(true);
    expect(e.throughLocation?.file).toBe("myapp/helpers.py");
    expect(e.sourceLocation.file).toBe("myapp/views.py");
    expect(e.sinkKind).toBe("sql_query");
  });

  it("does NOT resolve a bare/absolute import (only relative specifiers are in scope)", async () => {
    const mods = await pyMods([
      ["myapp/utils.py", ["def parse_id(x):", "    cursor.execute(x)"].join("\n")],
      [
        "myapp/views.py",
        [
          "from myapp.utils import parse_id",
          "",
          "def handler():",
          "    uid = request.args.get('id')",
          "    parse_id(uid)",
        ].join("\n"),
      ],
    ]);
    expect(scanPythonTaintFlows(mods)).toHaveLength(0);
  });

  it("does NOT resolve a class-method call (self.foo()) — module-level only", async () => {
    const mods = await pyMods([
      [
        "views.py",
        [
          "class Handler:",
          "    def helper(self, x):",
          "        cursor.execute(x)",
          "    def handle(self):",
          "        uid = request.args.get('id')",
          "        self.helper(uid)",
        ].join("\n"),
      ],
    ]);
    expect(scanPythonTaintFlows(mods)).toHaveLength(0);
  });

  it("runs offline over the real pygoat corpus without throwing (smoke, no assumed edges)", async () => {
    const entries = await loadRealTree(PYGOAT_DIR, ".py");
    const mods = await pyMods(entries);
    expect(() => scanPythonTaintFlows(mods)).not.toThrow();
    const edges = scanPythonTaintFlows(mods);
    expect(Array.isArray(edges)).toBe(true);
    // Every location an edge claims must sit inside a file we actually parsed.
    const files = new Set(mods.map((m) => m.rel));
    for (const e of edges) {
      expect(files.has(e.sourceLocation.file)).toBe(true);
      expect(files.has(e.sinkLocation.file)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Java — tier (a)+(b); tier (c) NOT attempted (see callgraph.ts doc comment)
// ---------------------------------------------------------------------------
describe("java callgraph — bounded interprocedural taint flows (A21)", () => {
  it("resolves a same-class DIRECT pass-through from an @RequestParam (tier b, hops=1)", async () => {
    const files = await javaFiles([
      [
        "Controller.java",
        [
          "class Controller {",
          "  void handler(@RequestParam String id) {",
          "    helper(id);",
          "  }",
          "  void helper(String x) {",
          "    db.execute(x);",
          "  }",
          "}",
        ].join("\n"),
      ],
    ]);
    const edges = scanJavaTaintFlows(files);
    expect(edges).toHaveLength(1);
    const e = edges[0]!;
    expect(e.resolution).toBe("direct-call");
    expect(e.hops).toBe(1);
    expect(e.crossFile).toBe(false);
    expect(e.throughFunction).toBe("Controller.helper");
    expect(e.sinkKind).toBe("sql_query");
    expect(e.sourceKind).toBe("query_param");
  });

  it("resolves a same-file cross-class STATIC-STYLE call (tier b, hops=1)", async () => {
    const files = await javaFiles([
      [
        "Controller.java",
        [
          "class Controller {",
          "  void handler(@RequestParam String cmd) {",
          "    Util.run(cmd);",
          "  }",
          "}",
          "class Util {",
          "  static void run(String c) {",
          "    Runtime.getRuntime().exec(c);",
          "  }",
          "}",
        ].join("\n"),
      ],
    ]);
    const edges = scanJavaTaintFlows(files);
    expect(edges).toHaveLength(1);
    expect(edges[0]!.throughFunction).toBe("Util.run");
    expect(edges[0]!.sinkKind).toBe("command_exec");
  });

  it("resolves a same-class RETURN-PROPAGATED assign-then-later-use (tier b, hops=2)", async () => {
    const files = await javaFiles([
      [
        "Controller.java",
        [
          "class Controller {",
          "  void handler(@RequestParam String id) {",
          "    String r = helper(id);",
          "    db.execute(r);",
          "  }",
          "  String helper(String x) {",
          "    return x;",
          "  }",
          "}",
        ].join("\n"),
      ],
    ]);
    const edges = scanJavaTaintFlows(files);
    expect(edges).toHaveLength(1);
    const e = edges[0]!;
    expect(e.resolution).toBe("return-propagated");
    expect(e.hops).toBe(2);
    expect(e.sinkKind).toBe("sql_query");
  });

  it("resolves an inline HttpServletRequest getter used directly as the call argument", async () => {
    const files = await javaFiles([
      [
        "Controller.java",
        [
          "class Controller {",
          "  void handler(HttpServletRequest request) {",
          '    helper(request.getParameter("id"));',
          "  }",
          "  void helper(String x) {",
          "    db.execute(x);",
          "  }",
          "}",
        ].join("\n"),
      ],
    ]);
    const edges = scanJavaTaintFlows(files);
    expect(edges).toHaveLength(1);
    expect(edges[0]!.sourceKind).toBe("query_param");
  });

  it("does NOT resolve a call through a locally-typed instance variable (documented limitation)", async () => {
    const files = await javaFiles([
      [
        "Controller.java",
        [
          "class Controller {",
          "  void handler(@RequestParam String id) {",
          "    Service service = new Service();",
          "    service.run(id);",
          "  }",
          "}",
          "class Service {",
          "  void run(String x) {",
          "    db.execute(x);",
          "  }",
          "}",
        ].join("\n"),
      ],
    ]);
    expect(scanJavaTaintFlows(files)).toHaveLength(0);
  });

  it("runs offline over real javaseccode/jvm-vuln corpus files without throwing (smoke)", async () => {
    const entries = [
      ...(await loadRealTree(JAVASECCODE_DIR, ".java")),
      ...(await loadRealTree(JVM_VULN_DIR, ".java")),
    ];
    const files = await javaFiles(entries);
    expect(() => scanJavaTaintFlows(files)).not.toThrow();
    const edges = scanJavaTaintFlows(files);
    expect(Array.isArray(edges)).toBe(true);
    const relFiles = new Set(files.map((f) => f.rel));
    for (const e of edges) {
      expect(relFiles.has(e.sourceLocation.file)).toBe(true);
      expect(relFiles.has(e.sinkLocation.file)).toBe(true);
    }
  });
});
