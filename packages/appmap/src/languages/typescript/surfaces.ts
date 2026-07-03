/**
 * Third-party call surface + env/secret surface (build-plan §5.1, deterministic).
 *
 * Third-party calls: external SDK imports (framework/ORM/runtime excluded) plus
 * network egress (`fetch`/axios/got/http.request). Env/secret surface: every
 * `process.env.X` read, secret-looking exported constants in config files, and
 * `.env` keys — the inputs the correlation + secrets layers reason over.
 */
import { SyntaxKind } from "ts-morph";
import type { Project, SourceFile } from "ts-morph";
import type { EnvSecretSurface, ThirdPartyCall, ThirdPartyCallKind } from "@montr/contracts";
import { readRepoFile } from "../../workspace.js";
import { toRepoRelative } from "../../sources.js";

/** Import specifiers that are framework/runtime/ORM, not third-party integrations. */
const NOT_THIRD_PARTY = [
  /^next(\/|$)/,
  /^react(-dom)?(\/|$)/,
  /^@prisma\//,
  /^prisma(\/|$)/,
  /^node:/,
];
const NODE_BUILTINS = new Set([
  "fs",
  "path",
  "http",
  "https",
  "crypto",
  "os",
  "url",
  "stream",
  "util",
  "events",
  "child_process",
  "zlib",
  "buffer",
  "net",
  "tls",
  "dns",
  "assert",
]);

/** Names that read secrets/config when they appear as a `process.env.X` key. */
const SECRET_NAME_RE =
  /(API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY|CLIENT_?SECRET|_KEY$|^KEY$|WEBHOOK)/i;
/** Literal values that are almost certainly secrets. */
const SECRET_VALUE_RE =
  /(sk_live_[A-Za-z0-9]+|sk_test_[A-Za-z0-9]+|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

const CONFIG_FILE_RE = /(^|\/)(config|constants|secrets|env|settings)\.(t|j)sx?$/i;

function relPath(abs: string, dir: string): string {
  return toRepoRelative(abs, dir);
}

function isThirdParty(spec: string): boolean {
  if (
    spec.startsWith(".") ||
    spec.startsWith("/") ||
    spec.startsWith("@/") ||
    spec.startsWith("~")
  ) {
    return false;
  }
  if (NODE_BUILTINS.has(spec.split("/")[0] ?? spec)) return false;
  return !NOT_THIRD_PARTY.some((re) => re.test(spec));
}

function packageName(spec: string): string {
  if (spec.startsWith("@")) {
    const parts = spec.split("/");
    return parts.slice(0, 2).join("/");
  }
  return spec.split("/")[0] ?? spec;
}

/** Detect external SDK imports + network calls across the project. */
export function scanThirdPartyCalls(project: Project, dir: string): ThirdPartyCall[] {
  const byKey = new Map<string, ThirdPartyCall>();
  const add = (
    kind: ThirdPartyCallKind,
    name: string,
    file: string,
    line: number,
    target?: string,
  ): void => {
    const key = `${kind}:${name}`;
    if (byKey.has(key)) return;
    byKey.set(key, {
      kind,
      name,
      location: { file, line },
      ...(target ? { target } : {}),
    });
  };

  for (const sf of project.getSourceFiles()) {
    const rel = relPath(sf.getFilePath(), dir);
    for (const imp of sf.getImportDeclarations()) {
      const spec = imp.getModuleSpecifierValue();
      if (isThirdParty(spec)) {
        add("sdk", packageName(spec), rel, imp.getStartLineNumber(), spec);
      }
    }
    // Network egress calls.
    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const expr = call.getExpression().getText();
      if (expr === "fetch") add("http", "fetch", rel, call.getStartLineNumber());
      else if (/^axios(\.\w+)?$/.test(expr) || expr === "got")
        add("http", expr.split(".")[0] ?? expr, rel, call.getStartLineNumber());
      else if (/^https?\.(request|get)$/.test(expr))
        add("http", expr, rel, call.getStartLineNumber());
    }
  }
  return [...byKey.values()].sort(
    (a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name),
  );
}

function scanProcessEnv(
  sf: SourceFile,
  rel: string,
  out: EnvSecretSurface[],
  seen: Set<string>,
): void {
  for (const pa of sf.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    if (pa.getExpression().getText() === "process.env") {
      const name = pa.getName();
      const key = `process_env:${name}`;
      if (name && !seen.has(key)) {
        seen.add(key);
        out.push({
          kind: "process_env",
          name,
          location: { file: rel, line: pa.getStartLineNumber() },
        });
      }
    }
  }
  for (const ea of sf.getDescendantsOfKind(SyntaxKind.ElementAccessExpression)) {
    if (ea.getExpression().getText() !== "process.env") continue;
    const arg = ea.getArgumentExpression();
    if (arg && arg.getKind() === SyntaxKind.StringLiteral) {
      const name = arg.getText().replace(/^["'`]|["'`]$/g, "");
      const key = `process_env:${name}`;
      if (name && !seen.has(key)) {
        seen.add(key);
        out.push({
          kind: "process_env",
          name,
          location: { file: rel, line: ea.getStartLineNumber() },
        });
      }
    }
  }
}

function scanConfigSecrets(
  sf: SourceFile,
  rel: string,
  out: EnvSecretSurface[],
  seen: Set<string>,
): void {
  if (!CONFIG_FILE_RE.test(rel)) return;
  for (const vs of sf.getVariableStatements()) {
    if (!vs.isExported()) continue;
    for (const decl of vs.getDeclarations()) {
      const name = decl.getName();
      const init = decl.getInitializer();
      const value = init && init.getKind() === SyntaxKind.StringLiteral ? init.getText() : "";
      const looksSecret = SECRET_NAME_RE.test(name) || SECRET_VALUE_RE.test(value);
      const key = `config_file:${name}`;
      if (looksSecret && !seen.has(key)) {
        seen.add(key);
        out.push({
          kind: "config_file",
          name,
          location: { file: rel, line: decl.getStartLineNumber() },
        });
      }
    }
  }
}

/** Build the env/secret surface: process.env reads + config secrets + .env keys. */
export async function scanEnvSecretSurfaces(
  project: Project,
  dir: string,
  envFiles: string[],
): Promise<EnvSecretSurface[]> {
  const out: EnvSecretSurface[] = [];
  const seen = new Set<string>();

  for (const sf of project.getSourceFiles()) {
    const rel = relPath(sf.getFilePath(), dir);
    scanProcessEnv(sf, rel, out, seen);
    scanConfigSecrets(sf, rel, out, seen);
  }

  for (const envFile of envFiles) {
    const content = await readRepoFile(dir, envFile);
    if (!content) continue;
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = (lines[i] ?? "").trim();
      if (!line || line.startsWith("#")) continue;
      const eq = line.indexOf("=");
      if (eq <= 0) continue;
      const name = line.slice(0, eq).trim();
      const key = `dotenv:${name}`;
      if (name && !seen.has(key)) {
        seen.add(key);
        out.push({ kind: "dotenv", name, location: { file: envFile, line: i + 1 } });
      }
    }
  }

  out.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}
