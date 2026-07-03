/**
 * Third-party call surface + env/secret surface for Python (Layer 0).
 *
 * Third-party: external package imports (stdlib + the app's own web framework
 * excluded) and network egress (`requests`/`httpx`/`urllib`/`aiohttp`). Env
 * surface: `os.environ[...]` / `os.environ.get(...)` / `os.getenv(...)` /
 * `python-decouple config(...)` reads, plus hard-coded secret-looking constants
 * in settings modules (`SECRET_KEY = "…"`). These feed the correlation + secrets
 * layers; nothing here is LLM-driven.
 */
import type { EnvSecretSurface, ThirdPartyCall, ThirdPartyCallKind } from "@montr/contracts";
import {
  calleeText,
  descendants,
  field,
  lineOf,
  namedChildren,
  positionalArgs,
  stringValue,
  type ParsedModule,
} from "./parser.js";

/** Python standard-library top-level modules (never a third-party integration). */
const STDLIB = new Set([
  "os",
  "sys",
  "re",
  "json",
  "math",
  "time",
  "datetime",
  "typing",
  "collections",
  "itertools",
  "functools",
  "logging",
  "pathlib",
  "subprocess",
  "hashlib",
  "hmac",
  "base64",
  "uuid",
  "random",
  "io",
  "abc",
  "enum",
  "dataclasses",
  "asyncio",
  "contextlib",
  "urllib",
  "http",
  "socket",
  "threading",
  "multiprocessing",
  "decimal",
  "secrets",
  "string",
  "copy",
  "warnings",
  "traceback",
  "csv",
  "sqlite3",
  "unittest",
  "argparse",
  "glob",
  "shutil",
  "tempfile",
  "pickle",
  "struct",
  "email",
  "html",
  "xml",
  "gzip",
  "zlib",
  "operator",
  "inspect",
  "importlib",
  "types",
  "weakref",
  "signal",
  "queue",
  "concurrent",
  "ssl",
]);

/** The app's own web framework / ORM — infrastructure, not an integration. */
const FRAMEWORK = new Set([
  "django",
  "flask",
  "fastapi",
  "starlette",
  "sqlalchemy",
  "pydantic",
  "rest_framework",
  "werkzeug",
  "jinja2",
  "asgiref",
  "uvicorn",
  "gunicorn",
  "click",
  "wtforms",
]);

/** Names that read secrets/config when assigned a literal in a settings module. */
const SECRET_NAME_RE =
  /(SECRET|_KEY$|^KEY$|API_?KEY|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY|CLIENT_?SECRET|SALT|WEBHOOK)/;

function topModule(spec: string): string {
  return spec.replace(/^\.+/, "").split(".")[0] ?? spec;
}

function isThirdParty(spec: string): boolean {
  if (spec.startsWith(".")) return false; // relative import
  const top = topModule(spec);
  return top.length > 0 && !STDLIB.has(top) && !FRAMEWORK.has(top);
}

// ---------------------------------------------------------------------------
// Third-party imports + network egress
// ---------------------------------------------------------------------------

function scanThirdParty(mod: ParsedModule, byKey: Map<string, ThirdPartyCall>): void {
  const add = (kind: ThirdPartyCallKind, name: string, line: number, target?: string): void => {
    const key = `${kind}:${name}`;
    if (byKey.has(key)) return;
    byKey.set(key, {
      kind,
      name,
      location: { file: mod.rel, line },
      ...(target ? { target } : {}),
    });
  };

  // `import requests`, `import boto3.session as s`
  for (const imp of descendants(mod.root, "import_statement")) {
    for (const child of namedChildren(imp)) {
      const spec =
        child.type === "aliased_import" ? (field(child, "name")?.text ?? "") : child.text;
      if (spec && isThirdParty(spec)) add("sdk", topModule(spec), lineOf(imp), spec);
    }
  }
  // `from stripe import Client`
  for (const imp of descendants(mod.root, "import_from_statement")) {
    const moduleName = field(imp, "module_name")?.text ?? "";
    if (moduleName && isThirdParty(moduleName))
      add("sdk", topModule(moduleName), lineOf(imp), moduleName);
  }
  // Network egress calls.
  for (const call of descendants(mod.root, "call")) {
    const callee = calleeText(call);
    if (/^(requests|httpx)\.(get|post|put|patch|delete|head|options|request)$/.test(callee)) {
      add("http", callee.split(".")[0] ?? callee, lineOf(call));
    } else if (/(^|\.)urlopen$/.test(callee) || /^urllib\.request\.urlopen$/.test(callee)) {
      add("http", "urllib", lineOf(call));
    } else if (/^(aiohttp|session)\.(get|post|put|patch|delete)$/.test(callee)) {
      add("http", "aiohttp", lineOf(call));
    }
  }
}

// ---------------------------------------------------------------------------
// Env / secret surface
// ---------------------------------------------------------------------------

function isSettingsModule(mod: ParsedModule): boolean {
  return (
    /(^|\/)settings(\/|\.py$)|settings\.py$/.test(mod.rel) || /\bSECRET_KEY\b/.test(mod.source)
  );
}

function scanEnv(mod: ParsedModule, out: EnvSecretSurface[], seen: Set<string>): void {
  const push = (kind: "process_env" | "config_file", name: string, line: number): void => {
    const key = `${kind}:${name}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, name, location: { file: mod.rel, line } });
  };

  // os.environ["X"]
  for (const sub of descendants(mod.root, "subscript")) {
    if (field(sub, "value")?.text !== "os.environ") continue;
    const idx = field(sub, "subscript");
    const name = stringValue(idx);
    if (name) push("process_env", name, lineOf(sub));
  }
  // os.environ.get("X") / os.getenv("X") / config("X") / env("X") / env.str("X")
  for (const call of descendants(mod.root, "call")) {
    const callee = calleeText(call);
    if (
      /^os\.environ\.get$/.test(callee) ||
      /^os\.getenv$/.test(callee) ||
      /(^|\.)getenv$/.test(callee) ||
      /^(config|env)$/.test(callee) ||
      /^env\.(str|int|bool|list)$/.test(callee) ||
      /(^|\.)environ\.get$/.test(callee)
    ) {
      const name = stringValue(positionalArgs(call)[0]);
      if (name) push("process_env", name, lineOf(call));
    }
  }
  // Hard-coded secret-looking constants in a settings module.
  if (isSettingsModule(mod)) {
    for (const assign of descendants(mod.root, "assignment")) {
      const left = field(assign, "left");
      const right = field(assign, "right");
      if (!left || left.type !== "identifier" || !right || right.type !== "string") continue;
      const name = left.text;
      const value = stringValue(right) ?? "";
      const looksSecret = SECRET_NAME_RE.test(name);
      if (looksSecret && value.length >= 8) push("config_file", name, lineOf(assign));
    }
  }
}

export interface PythonSurfaceResult {
  thirdPartyCalls: ThirdPartyCall[];
  envSecretSurfaces: EnvSecretSurface[];
}

/** Build the third-party call surface + env/secret surface across all modules. */
export function scanPythonSurfaces(mods: ParsedModule[]): PythonSurfaceResult {
  const byKey = new Map<string, ThirdPartyCall>();
  const env: EnvSecretSurface[] = [];
  const seen = new Set<string>();
  for (const mod of mods) {
    scanThirdParty(mod, byKey);
    scanEnv(mod, env, seen);
  }
  const thirdPartyCalls = [...byKey.values()].sort(
    (a, b) => a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name),
  );
  env.sort((a, b) => a.name.localeCompare(b.name));
  return { thirdPartyCalls, envSecretSurfaces: env };
}
