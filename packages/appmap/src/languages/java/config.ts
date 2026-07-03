/**
 * Spring configuration scan (deterministic, offline): `application.properties` /
 * `application.yml` → data stores (from `spring.datasource.url`) + env/secret
 * surfaces (secret-looking config keys). Mirrors the Prisma builder's role for
 * the JVM stack: it turns declared infrastructure into the language-agnostic
 * App-Map pieces without executing anything.
 */
import type { DataStore, DataStoreKind, EnvSecretSurface } from "@montr/contracts";
import { readRepoFile } from "../../workspace.js";

export interface ConfigScan {
  dataStores: DataStore[];
  /** Primary datastore name (for linking JPA models), if any datasource was found. */
  primaryStore: string | undefined;
  envSecretSurfaces: EnvSecretSurface[];
}

/** A flattened `dotted.key = value` config entry with its 1-based line. */
interface ConfigEntry {
  key: string;
  value: string;
  file: string;
  line: number;
}

/** Config keys whose NAME implies a secret/credential value. */
const SECRET_KEY_RE =
  /(password|passwd|secret|token|api[._-]?key|access[._-]?key|private[._-]?key|client[._-]?secret|credential)/i;

/** Map a JDBC / driver URL (or mongo/redis URI) to a coarse store kind. */
function urlToKind(url: string): DataStoreKind {
  const u = url.toLowerCase();
  if (/postgres/.test(u)) return "postgres";
  if (/mysql|mariadb/.test(u)) return "mysql";
  if (/sqlite/.test(u)) return "sqlite";
  if (/mongodb/.test(u)) return "mongodb";
  if (/redis/.test(u)) return "redis";
  if (/elasticsearch/.test(u)) return "elasticsearch";
  return "other";
}

/** Parse a `.properties` file into flattened entries. */
function parseProperties(content: string, file: string): ConfigEntry[] {
  const out: ConfigEntry[] = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = (lines[i] ?? "").trim();
    if (!raw || raw.startsWith("#") || raw.startsWith("!")) continue;
    const eq = raw.search(/[=:]/);
    if (eq <= 0) continue;
    const key = raw.slice(0, eq).trim();
    const value = raw.slice(eq + 1).trim();
    if (key) out.push({ key, value, file, line: i + 1 });
  }
  return out;
}

/**
 * Minimal YAML flattener for Spring config: tracks the indent stack and joins
 * nested `key:` levels into dotted paths. Handles the `key: value` /
 * nested-mapping subset Spring uses; sequences and anchors are ignored.
 */
function parseYaml(content: string, file: string): ConfigEntry[] {
  const out: ConfigEntry[] = [];
  const lines = content.split("\n");
  const stack: Array<{ indent: number; key: string }> = [];
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i] ?? "";
    const noComment = rawLine.replace(/\s+#.*$/, "");
    if (!noComment.trim() || noComment.trim().startsWith("#") || noComment.trim().startsWith("-")) {
      continue;
    }
    const indent = noComment.length - noComment.trimStart().length;
    const m = /^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/.exec(noComment.trim());
    if (!m || !m[1]) continue;
    const key = m[1];
    const value = (m[2] ?? "").trim();
    while (stack.length > 0 && (stack[stack.length - 1]?.indent ?? -1) >= indent) stack.pop();
    const prefix = stack.map((s) => s.key).join(".");
    const dotted = prefix ? `${prefix}.${key}` : key;
    if (value === "" || value === "|" || value === ">") {
      stack.push({ indent, key });
    } else {
      out.push({ key: dotted, value: value.replace(/^["']|["']$/g, ""), file, line: i + 1 });
    }
  }
  return out;
}

function isYaml(path: string): boolean {
  return /\.ya?ml$/i.test(path);
}

/** Build data stores + secret config surfaces from Spring config files. */
export async function scanJavaConfig(dir: string, configFiles: string[]): Promise<ConfigScan> {
  const dataStores: DataStore[] = [];
  const envSecretSurfaces: EnvSecretSurface[] = [];
  const storeKinds = new Set<string>();
  let primaryStore: string | undefined;

  for (const file of configFiles) {
    const content = await readRepoFile(dir, file);
    if (!content) continue;
    const entries = isYaml(file) ? parseYaml(content, file) : parseProperties(content, file);

    for (const e of entries) {
      const keyLower = e.key.toLowerCase();
      // Datasource → a DataStore (one per distinct kind).
      if (/(datasource|data\.mongodb|data\.redis)\.(url|uri|jdbc-url|jdbcurl)$/.test(keyLower)) {
        const kind = urlToKind(e.value);
        if (!storeKinds.has(kind)) {
          storeKinds.add(kind);
          dataStores.push({ kind, name: kind, accessedVia: "spring" });
          primaryStore ??= kind;
        }
      }
      // Secret-looking config key → an env/secret surface (metadata only; no value).
      if (SECRET_KEY_RE.test(e.key)) {
        envSecretSurfaces.push({
          kind: "config_file",
          name: e.key,
          location: { file: e.file, line: e.line },
        });
      }
    }
  }

  return { dataStores, primaryStore, envSecretSurfaces };
}
