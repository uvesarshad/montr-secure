/**
 * Data stores + ORM models via Prisma DMMF (build-plan §5.1, deterministic).
 *
 * Primary path: `@prisma/internals` `getDMMF` (in-process WASM — offline, no DB).
 * If the WASM engine is unavailable or the schema is malformed, a lightweight
 * regex parser recovers model/field names so the map degrades gracefully rather
 * than failing the whole scan.
 */
import type * as PrismaInternals from "@prisma/internals";
import type { DataStore, DataStoreKind, OrmModel } from "@montr/contracts";
import { readRepoFile } from "./workspace.js";

interface OrmField {
  name: string;
  type: string;
  isId: boolean;
}

export interface PrismaScanResult {
  dataStores: DataStore[];
  ormModels: OrmModel[];
}

/** Load `getDMMF` across the CJS/ESM boundary (see build-plan tooling notes). */
async function loadGetDMMF(): Promise<typeof PrismaInternals.getDMMF | undefined> {
  try {
    const mod = (await import("@prisma/internals")) as unknown as {
      getDMMF?: typeof PrismaInternals.getDMMF;
      default?: { getDMMF?: typeof PrismaInternals.getDMMF };
    };
    return mod.getDMMF ?? mod.default?.getDMMF;
  } catch {
    return undefined;
  }
}

function providerToKind(provider: string): DataStoreKind {
  switch (provider.toLowerCase()) {
    case "postgresql":
    case "postgres":
      return "postgres";
    case "mysql":
      return "mysql";
    case "sqlite":
      return "sqlite";
    case "mongodb":
      return "mongodb";
    default:
      return "other";
  }
}

/** Extract `{ blockName, provider }` for every datasource block in a schema. */
function parseDatasources(schema: string): Array<{ name: string; provider: string }> {
  const out: Array<{ name: string; provider: string }> = [];
  const re = /datasource\s+(\w+)\s*\{([\s\S]*?)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(schema)) !== null) {
    const name = m[1] ?? "db";
    const body = m[2] ?? "";
    const pm = /provider\s*=\s*"([^"]+)"/.exec(body);
    out.push({ name, provider: pm?.[1] ?? "other" });
  }
  return out;
}

/** Regex fallback model/field extraction (used when DMMF is unavailable). */
function parseModelsRegex(schema: string): Array<{ name: string; fields: OrmField[] }> {
  const models: Array<{ name: string; fields: OrmField[] }> = [];
  const re = /model\s+(\w+)\s*\{([\s\S]*?)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(schema)) !== null) {
    const name = m[1] ?? "";
    const body = m[2] ?? "";
    const fields: OrmField[] = [];
    for (const line of body.split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("//") || t.startsWith("@@")) continue;
      const fm = /^(\w+)\s+([A-Za-z0-9_[\]?]+)/.exec(t);
      if (!fm || !fm[1] || !fm[2]) continue;
      fields.push({ name: fm[1], type: fm[2].replace(/[?[\]]/g, ""), isId: /@id\b/.test(t) });
    }
    if (name) models.push({ name, fields });
  }
  return models;
}

/** Build data stores + ORM models from every Prisma schema in the repo. */
export async function scanPrisma(dir: string, schemas: string[]): Promise<PrismaScanResult> {
  const dataStores: DataStore[] = [];
  const ormModels: OrmModel[] = [];
  const storeNames = new Set<string>();
  const getDMMF = await loadGetDMMF();

  for (const schemaPath of schemas) {
    const schema = await readRepoFile(dir, schemaPath);
    if (!schema) continue;

    // Data stores (regex is sufficient + avoids a second WASM call).
    const datasources = parseDatasources(schema);
    const primaryStore = datasources[0]?.name ?? "db";
    for (const ds of datasources) {
      if (storeNames.has(ds.name)) continue;
      storeNames.add(ds.name);
      dataStores.push({ kind: providerToKind(ds.provider), name: ds.name, accessedVia: "prisma" });
    }

    // ORM models — DMMF first, regex fallback.
    let parsed: Array<{ name: string; fields: OrmField[] }> = [];
    if (getDMMF) {
      try {
        const dmmf = await getDMMF({ datamodel: schema });
        parsed = dmmf.datamodel.models.map((model) => ({
          name: model.name,
          fields: model.fields.map((f) => ({
            name: f.name,
            type: String(f.type),
            isId: Boolean(f.isId),
          })),
        }));
      } catch {
        parsed = parseModelsRegex(schema);
      }
    } else {
      parsed = parseModelsRegex(schema);
    }

    for (const model of parsed) {
      ormModels.push({
        name: model.name,
        dataStore: primaryStore,
        file: schemaPath,
        fields: model.fields,
      });
    }
  }

  dataStores.sort((a, b) => a.name.localeCompare(b.name));
  ormModels.sort((a, b) => a.name.localeCompare(b.name));
  return { dataStores, ormModels };
}
