/**
 * ORM model + data-store extraction for Python (Layer 0, deterministic).
 *
 *   • Django      — `class X(models.Model)`; each `f = models.CharField(...)`
 *     class attribute becomes a field (`primary_key=True` / an `id` field marks
 *     the PK). The DB engine is read from a settings `ENGINE` string.
 *   • SQLAlchemy  — `class X(Base)` / `class X(db.Model)` with `Column(...)` /
 *     `mapped_column(...)` attributes; the engine is read from `create_engine(url)`.
 *
 * Emits the frozen `OrmModel` / `DataStore` `@montr/contracts` shapes.
 */
import type { Node } from "web-tree-sitter";
import type { DataStore, DataStoreKind, OrmModel } from "@montr/contracts";
import {
  calleeText,
  descendants,
  field,
  keywordArg,
  namedChildren,
  positionalArgs,
  stringValue,
  type ParsedModule,
} from "./parser.js";

export interface PythonModelResult {
  ormModels: OrmModel[];
  dataStores: DataStore[];
}

const DJANGO_FIELD_RE = /Field$|^(?:ForeignKey|OneToOneField|ManyToManyField)$/;

interface ClassField {
  name: string;
  type: string;
  isId: boolean;
}

/** A class-body attribute `name = <call>(...)`, if it is a model field. */
function fieldFromAssignment(
  assign: Node,
  matcher: (callee: string) => string | null,
): ClassField | null {
  const left = field(assign, "left");
  const right = field(assign, "right");
  if (!left || left.type !== "identifier" || !right || right.type !== "call") return null;
  const type = matcher(calleeText(right));
  if (type === null) return null;
  const name = left.text;
  const pk = keywordArg(right, "primary_key");
  const isId = name === "id" || pk?.text === "True";
  return { name, type, isId };
}

/** Iterate the direct `name = value` statements of a class body. */
function classBodyAssignments(cls: Node): Node[] {
  const body = field(cls, "body");
  if (!body) return [];
  const out: Node[] = [];
  for (const stmt of namedChildren(body)) {
    if (stmt.type !== "expression_statement") continue;
    const inner = namedChildren(stmt)[0];
    if (inner && inner.type === "assignment") out.push(inner);
  }
  return out;
}

function djangoFieldType(callee: string): string | null {
  const leaf = callee.split(".").pop() ?? callee;
  return DJANGO_FIELD_RE.test(leaf) ? leaf : null;
}

function sqlAlchemyFieldType(callee: string): string | null {
  const leaf = callee.split(".").pop() ?? callee;
  return leaf === "Column" || leaf === "mapped_column" ? "column" : null;
}

function collectModels(mod: ParsedModule, out: OrmModel[]): { django: boolean; alchemy: boolean } {
  let django = false;
  let alchemy = false;
  for (const cls of descendants(mod.root, "class_definition")) {
    const supers = field(cls, "superclasses")?.text ?? "";
    const name = field(cls, "name")?.text;
    if (!name) continue;

    // Explicit superclass signals only (avoids misclassifying unrelated classes).
    const djangoHit = /models\.Model/.test(supers);
    const alchemyHit =
      /\bBase\b/.test(supers) || /db\.Model/.test(supers) || /DeclarativeBase/.test(supers);
    if (!djangoHit && !alchemyHit) continue;

    const matcher = djangoHit ? djangoFieldType : sqlAlchemyFieldType;
    const fields: ClassField[] = [];
    for (const assign of classBodyAssignments(cls)) {
      const f = fieldFromAssignment(assign, matcher);
      if (f) fields.push(f);
    }
    if (djangoHit && fields.length > 0 && !fields.some((f) => f.isId)) {
      // Django adds an implicit auto `id` PK when none is declared.
      fields.unshift({ name: "id", type: "AutoField", isId: true });
    }
    if (djangoHit) django = true;
    if (alchemyHit && !djangoHit) alchemy = true;

    out.push({
      name,
      file: mod.rel,
      fields: fields.map((f) => ({ name: f.name, type: f.type, isId: f.isId })),
    });
  }
  return { django, alchemy };
}

const ENGINE_KINDS: Array<[RegExp, DataStoreKind]> = [
  [/postgres/i, "postgres"],
  [/mysql|mariadb/i, "mysql"],
  [/sqlite/i, "sqlite"],
  [/mongo/i, "mongodb"],
  [/redis/i, "redis"],
  [/elastic/i, "elasticsearch"],
];

function engineKind(text: string): DataStoreKind | null {
  for (const [re, kind] of ENGINE_KINDS) if (re.test(text)) return kind;
  return null;
}

/** Detect the DB engine from Django settings `ENGINE=` or SQLAlchemy `create_engine(url)`. */
function detectEngine(mods: ParsedModule[]): DataStoreKind | null {
  for (const mod of mods) {
    for (const call of descendants(mod.root, "call")) {
      if (!/(^|\.)create_engine$/.test(calleeText(call))) continue;
      const url = stringValue(positionalArgs(call)[0]);
      const kind = url ? engineKind(url) : null;
      if (kind) return kind;
    }
    // Django `"ENGINE": "django.db.backends.postgresql"` string literals.
    for (const str of descendants(mod.root, "string")) {
      if (/django\.db\.backends\./.test(str.text)) {
        const kind = engineKind(str.text);
        if (kind) return kind;
      }
    }
  }
  return null;
}

/** Extract ORM models + the backing data store(s). */
export function scanPythonModels(mods: ParsedModule[]): PythonModelResult {
  const ormModels: OrmModel[] = [];
  let anyDjango = false;
  let anyAlchemy = false;
  for (const mod of mods) {
    const { django, alchemy } = collectModels(mod, ormModels);
    anyDjango = anyDjango || django;
    anyAlchemy = anyAlchemy || alchemy;
  }

  const dataStores: DataStore[] = [];
  if (anyDjango || anyAlchemy) {
    const kind = detectEngine(mods) ?? "other";
    dataStores.push({
      kind,
      name: "default",
      ...(anyDjango ? { accessedVia: "django" as const } : {}),
    });
  }

  ormModels.sort((a, b) => a.name.localeCompare(b.name));
  return { ormModels, dataStores };
}
