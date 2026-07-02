/**
 * Diff-mode scoping (build-plan §5.1): scope = changed files + the reachable
 * call graph from those changes. Reachability is computed both ways over the
 * import graph — DOWNSTREAM (what the changes call, to reach affected sinks) and
 * UPSTREAM (what calls the changes, to reach affected entry points/routes) — so
 * a diff scan still sees the entry points a change is exploitable through.
 */
import { dirname, join, normalize } from "node:path";
import type { Project } from "ts-morph";

const EXTS = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];

function posix(p: string): string {
  return p.replace(/\\/g, "/").replace(/^\.\//, "");
}

/** Resolve an import specifier from `fromRel` to a repo-relative file we scanned. */
function resolveImport(fromRel: string, spec: string, fileSet: Set<string>): string | null {
  let base: string | null = null;
  if (spec.startsWith(".")) {
    base = posix(normalize(join(dirname(fromRel), spec)));
  } else if (spec.startsWith("@/")) {
    // Next.js default alias — try repo root and `src/`.
    base = spec.slice(2);
  } else if (spec.startsWith("~/")) {
    base = spec.slice(2);
  } else {
    return null; // bare/external specifier — not in scope graph
  }

  const candidates: string[] = [];
  for (const b of base === spec.slice(2) ? [base, `src/${base}`] : [base]) {
    candidates.push(b);
    for (const ext of EXTS) candidates.push(`${b}.${ext}`);
    for (const ext of EXTS) candidates.push(`${b}/index.${ext}`);
  }
  for (const c of candidates) {
    const norm = posix(c);
    if (fileSet.has(norm)) return norm;
  }
  return null;
}

export interface DiffScope {
  changedFiles: string[];
  /** Changed files ∪ reachable (both directions) over the import graph. */
  reachable: string[];
}

/** Compute the diff scope from the project's import graph + the changed files. */
export function computeDiffScope(
  project: Project,
  dir: string,
  sourceFiles: string[],
  changedFilesRaw: string[],
): DiffScope {
  const fileSet = new Set(sourceFiles.map(posix));
  const forward = new Map<string, Set<string>>(); // file → files it imports
  const reverse = new Map<string, Set<string>>(); // file → files that import it

  for (const sf of project.getSourceFiles()) {
    const abs = sf.getFilePath();
    const rel = posix(abs.startsWith(dir) ? abs.slice(dir.length).replace(/^\//, "") : abs);
    if (!fileSet.has(rel)) continue;
    for (const imp of sf.getImportDeclarations()) {
      const target = resolveImport(rel, imp.getModuleSpecifierValue(), fileSet);
      if (!target || target === rel) continue;
      (forward.get(rel) ?? forward.set(rel, new Set()).get(rel)!).add(target);
      (reverse.get(target) ?? reverse.set(target, new Set()).get(target)!).add(rel);
    }
  }

  const changed = changedFilesRaw.map(posix).filter((f) => fileSet.has(f));
  const seed = changed.length > 0 ? changed : [];

  const bfs = (graph: Map<string, Set<string>>, start: string[]): Set<string> => {
    const visited = new Set<string>(start);
    const queue = [...start];
    while (queue.length > 0) {
      const cur = queue.shift() as string;
      for (const next of graph.get(cur) ?? []) {
        if (!visited.has(next)) {
          visited.add(next);
          queue.push(next);
        }
      }
    }
    return visited;
  };

  const reachable = new Set<string>(seed);
  for (const f of bfs(forward, seed)) reachable.add(f);
  for (const f of bfs(reverse, seed)) reachable.add(f);

  return {
    changedFiles: [...new Set(changed)].sort(),
    reachable: [...reachable].sort(),
  };
}
