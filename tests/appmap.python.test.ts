/**
 * WS-Q — Phase-3 PYTHON stack (Django / FastAPI / Flask) breadth tests.
 *
 * Fully OFFLINE: parses the on-disk `corpus/python-*` apps in place with the
 * prebuilt `tree-sitter-python` grammar (from `tree-sitter-wasms`, no network),
 * runs the whole Layer-0 pipeline via `buildAppMap` (no gateway ⇒ deterministic
 * only), and validates the Python discovery ruleset + confirmation heuristics.
 *
 * The stack-agnostic invariant (build-plan §7): the Python analyzer emits the SAME
 * frozen `@montr/contracts` App-Map / finding shapes as TS/JS — correlation (L2),
 * fix (L4) and report (L5) get NO Python-specific logic. This suite proves the
 * Python Layer-0 + Layer-1 ruleset + Layer-3 heuristics fill those seams and that
 * the corpus ground truth lines up with what the analyzer actually extracts.
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";

import { buildAppMap, collectFiles, pythonAnalyzer, type BuildAppMapInput } from "@montr/appmap";
import { getHardenedDefaults } from "@montr/config";
import { createNullLogger } from "@montr/telemetry";
import { ScanScopeSchema, Layer0OutputSchema, type Category } from "@montr/contracts";
import { CLIENT_ID, SCAN_ID, FIXED_NOW, COMMIT_SHA } from "@montr/fixtures";
import { GroundTruthManifestSchema } from "@montr/fixtures";
import {
  selectSemgrepRulesets,
  selectScaEcosystems,
  selectCustomDetectors,
  runCustomDetectors,
} from "@montr/discovery";
import { resolveHeuristics, assessSink, extractParam } from "@montr/confirm";

// Deterministic Python builders (owned dir) — exercised directly for the
// FastAPI/Flask/SQLAlchemy breadth the Django corpus does not cover.
import {
  getPythonParser,
  parseModule,
  type ParsedModule,
} from "../packages/appmap/src/languages/python/parser";
import { scanPythonRoutes } from "../packages/appmap/src/languages/python/routes";
import { scanPythonModels } from "../packages/appmap/src/languages/python/models";
import { scanPythonTaint } from "../packages/appmap/src/languages/python/taint";
// Raw Python confirmation-heuristics markers (owned dir) — for the ⛔ safety invariant.
import { pythonHeuristics } from "../packages/confirm/src/heuristics/python/index";

const VULN_DIR = fileURLToPath(new URL("../corpus/python-vuln", import.meta.url));
const CLEAN_DIR = fileURLToPath(new URL("../corpus/python-clean", import.meta.url));
const CLEAN_COMMIT = "b1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
const fixedNow = (): Date => new Date(FIXED_NOW);

function baseInput(overrides: Partial<BuildAppMapInput> = {}): BuildAppMapInput {
  return {
    clientId: CLIENT_ID,
    scanId: SCAN_ID,
    repo: VULN_DIR,
    branch: "main",
    mode: "full",
    scope: ScanScopeSchema.parse({ mode: "full" }),
    config: getHardenedDefaults(),
    commitSha: COMMIT_SHA,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Ground-truth manifest — the corpus contract the golden-corpus scorer reads.
// ---------------------------------------------------------------------------
describe("python corpus — ground-truth manifest", () => {
  it("validates against GroundTruthManifestSchema with the 5 planted OWASP findings", async () => {
    const raw = await readFile(
      new URL("../corpus/python-vuln/ground-truth.manifest.json", import.meta.url),
      "utf8",
    );
    const manifest = GroundTruthManifestSchema.parse(JSON.parse(raw));

    expect(manifest.repos.map((r) => r.name).sort()).toEqual(["python-clean", "python-vuln"]);
    const vuln = manifest.repos.find((r) => r.name === "python-vuln")!;
    const clean = manifest.repos.find((r) => r.name === "python-clean")!;

    expect(clean.expectedFindings).toHaveLength(0);
    const categories = new Set<Category>(vuln.expectedFindings.map((f) => f.category));
    for (const required of ["sql_injection", "xss", "ssrf", "idor", "hardcoded_secret"] as const) {
      expect(categories.has(required)).toBe(true);
    }
  });

  it("classifies access-control + secret-rotation as human-required (⛔ golden rule #3)", async () => {
    const raw = await readFile(
      new URL("../corpus/python-vuln/ground-truth.manifest.json", import.meta.url),
      "utf8",
    );
    const manifest = GroundTruthManifestSchema.parse(JSON.parse(raw));
    const vuln = manifest.repos.find((r) => r.name === "python-vuln")!;

    for (const f of vuln.expectedFindings) {
      if (f.category === "idor" || f.category === "hardcoded_secret") {
        expect(f.expectedRiskClass).toBe("human-required");
      } else {
        expect(f.expectedRiskClass).toBe("auto-eligible");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Layer 0 — the Django vulnerable app, end-to-end through buildAppMap (offline).
// ---------------------------------------------------------------------------
describe("python appmap — vulnerable Django app (buildAppMap, no LLM)", () => {
  it("detects the python/django stack and emits a valid Layer0Output", async () => {
    const inv = await collectFiles(VULN_DIR);
    expect(
      pythonAnalyzer.detect({ dir: VULN_DIR, inventory: inv, logger: createNullLogger() }),
    ).toBe(true);

    const out = await buildAppMap(baseInput(), { now: fixedNow });
    expect(() => Layer0OutputSchema.parse(out)).not.toThrow();
    expect(out.appMap.languages).toEqual(["python"]);
    expect(out.appMap.frameworks).toEqual(["django"]);
    // Cost is still projected from map size for a pure-Python repo (4 layer items).
    expect(out.costEstimate.byLayer).toHaveLength(4);
    expect(out.scope.routeCount).toBe(out.appMap.routes.length);
  });

  it("introspects Django urlpatterns (path + re_path), normalising dynamic segments", async () => {
    const out = await buildAppMap(baseInput(), { now: fixedNow });
    const paths = out.appMap.routes.map((r) => r.path).sort();
    expect(paths).toEqual(["/fetch/", "/orders/{order_id}/", "/search/"]);
    // Django dispatches every verb to the view → method-agnostic ALL.
    for (const r of out.appMap.routes) expect(r.method).toBe("ALL");
    // Handlers anchor to the URLConf; cross-file @login_required stays unknown here
    // (resolved later by stack-agnostic correlation — the documented seam).
    const search = out.appMap.routes.find((r) => r.path === "/search/")!;
    expect(search.handler?.file).toBe("myapp/urls.py");
    expect(search.authState).toBe("unknown");
  });

  it("extracts Django ORM models with the implicit auto id PK + the postgres store", async () => {
    const out = await buildAppMap(baseInput(), { now: fixedNow });
    const user = out.appMap.ormModels.find((m) => m.name === "User")!;
    const order = out.appMap.ormModels.find((m) => m.name === "Order")!;
    expect(user.fields.map((f) => f.name)).toEqual(["id", "name", "email"]);
    expect(user.fields.find((f) => f.name === "id")?.isId).toBe(true);
    expect(order.fields.map((f) => f.name)).toEqual(["id", "user", "total", "created"]);
    expect(out.appMap.dataStores).toEqual([
      { kind: "postgres", name: "default", accessedVia: "django" },
    ]);
  });

  it("catalogs the hard-coded SECRET_KEY as a config_file surface (never its value)", async () => {
    const out = await buildAppMap(baseInput(), { now: fixedNow });
    const secret = out.appMap.envSecretSurfaces.find((s) => s.name === "SECRET_KEY")!;
    expect(secret.kind).toBe("config_file");
    expect(secret.location.line).toBe(5); // matches ground truth
    // ⛔ No secret value ever lands in the map (golden rule #1).
    expect(JSON.stringify(out.appMap)).not.toContain("django-insecure-hardcoded");
    // requests is surfaced as a third-party integration (import + egress).
    expect(out.appMap.thirdPartyCalls.some((c) => c.name === "requests")).toBe(true);
  });

  it("catalogs taint sinks at the exact ground-truth lines (SQLi/XSS/SSRF)", async () => {
    const out = await buildAppMap(baseInput(), { now: fixedNow });
    const sinkAt = (line: number) => out.appMap.taintSinks.find((s) => s.location.line === line);

    expect(sinkAt(18)?.kind).toBe("sql_query"); // gt_py_sqli — raw f-string interpolation
    expect(sinkAt(21)?.kind).toBe("html_render"); // gt_py_xss  — mark_safe
    expect(sinkAt(28)?.kind).toBe("http_client"); // gt_py_ssrf — requests.get(user url)
    for (const s of out.appMap.taintSinks) expect(s.location.file).toBe("myapp/views.py");

    // request.GET sources are catalogued for the tainted params.
    const sources = out.appMap.taintSources;
    expect(sources.length).toBe(2);
    expect(sources.every((s) => s.kind === "query_param")).toBe(true);

    // IDOR (order lookup by id, line 34) is access-control, NOT a data-flow sink —
    // the analyzer must NOT over-report it as taint (correlation confirms it).
    expect(out.appMap.taintSinks.some((s) => s.location.line === 34)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Layer 0 — the secured Django counterpart demotes cleanly.
// ---------------------------------------------------------------------------
describe("python appmap — clean Django app", () => {
  it("marks the parameterized query safe and finds no hard-coded secret", async () => {
    const out = await buildAppMap(
      baseInput({ repo: CLEAN_DIR, scanId: "scan_clean", commitSha: CLEAN_COMMIT }),
      {
        now: fixedNow,
      },
    );
    // The only SQL sink is a parameterized query — its description carries the
    // `parameterized` safe-marker (so confirmation demotes it, see below).
    const sql = out.appMap.taintSinks.find((s) => s.kind === "sql_query");
    expect(sql?.description).toContain("parameterized");
    // Secret is read from the environment → a process_env read, not config_file.
    expect(out.appMap.envSecretSurfaces.some((s) => s.kind === "config_file")).toBe(false);
    // No raw-interpolation / mark_safe / SSRF sinks survive in the secured app.
    expect(out.appMap.taintSinks.some((s) => s.kind === "html_render")).toBe(false);
    expect(out.appMap.taintSinks.some((s) => s.kind === "http_client")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Layer 0 — FastAPI / Flask / SQLAlchemy breadth (in-memory, via the builders).
// ---------------------------------------------------------------------------
describe("python appmap — FastAPI / Flask / SQLAlchemy breadth", () => {
  const FASTAPI = `
from fastapi import FastAPI, APIRouter, Depends, Query
from .auth import get_current_user

app = FastAPI()
router = APIRouter(prefix="/api/v1")

@app.get("/items")
def list_items(q: str = Query(None)):
    return q

@router.post("/orders")
def create_order(user = Depends(get_current_user)):
    return user
`;

  const FLASK = `
from flask import Flask, request
app = Flask(__name__)

@app.route("/login", methods=["POST"])
@login_required
def login():
    name = request.form.get("name")
    return name
`;

  const SQLALCHEMY = `
from sqlalchemy import Column, Integer, String
from .db import Base

class Account(Base):
    id = Column(Integer, primary_key=True)
    email = Column(String)
`;

  const SINKS = `
import os
import subprocess
import pickle
from jinja2 import Template

def handler(request):
    cmd = request.GET.get("cmd")
    os.system(cmd)
    subprocess.run(cmd, shell=True)
    code = request.GET.get("code")
    eval(code)
    data = request.body
    pickle.loads(data)
    tpl = request.GET.get("tpl")
    Template(tpl).render()
    p = request.GET.get("path")
    open(p, "w")
`;

  async function mods(entries: Array<[string, string]>): Promise<ParsedModule[]> {
    const parser = await getPythonParser();
    return entries.map(([rel, source]) => {
      const root = parseModule(parser, source);
      if (!root) throw new Error(`parse failed for ${rel}`);
      return { rel, source, root };
    });
  }

  it("parses FastAPI decorator routes with an APIRouter prefix + Depends() auth", async () => {
    const m = await mods([["api/main.py", FASTAPI]]);
    const { routes } = scanPythonRoutes(m);
    const items = routes.find((r) => r.path === "/items")!;
    const orders = routes.find((r) => r.path === "/api/v1/orders")!;
    expect(items.method).toBe("GET");
    expect(items.isApiRoute).toBe(true);
    expect(orders.method).toBe("POST"); // prefix applied
    expect(orders.authState).toBe("authenticated"); // Depends(get_current_user)
    expect(orders.authGate).toContain("Depends");

    // FastAPI Query() parameter is a taint source.
    const { taintSources } = scanPythonTaint(m, new Map());
    expect(taintSources.some((s) => s.kind === "query_param")).toBe(true);
  });

  it("parses a Flask @route(methods=[...]) with a stacked @login_required guard", async () => {
    const m = await mods([["app.py", FLASK]]);
    const { routes } = scanPythonRoutes(m);
    const login = routes.find((r) => r.path === "/login")!;
    expect(login.method).toBe("POST");
    expect(login.authState).toBe("authenticated");
    expect(login.authGate).toBe("login_required");

    const { taintSources } = scanPythonTaint(m, new Map());
    expect(taintSources.some((s) => s.kind === "request_body")).toBe(true); // request.form.get
  });

  it("extracts SQLAlchemy models (Column / primary_key PK)", async () => {
    const m = await mods([["models.py", SQLALCHEMY]]);
    const { ormModels } = scanPythonModels(m);
    const account = ormModels.find((x) => x.name === "Account")!;
    expect(account.fields.map((f) => f.name)).toEqual(["id", "email"]);
    expect(account.fields.find((f) => f.name === "id")?.isId).toBe(true);
  });

  it("catalogs command-exec / eval / deserialize / template / fs sinks", async () => {
    const m = await mods([["h.py", SINKS]]);
    const { taintSinks } = scanPythonTaint(m, new Map());
    const kinds = new Set(taintSinks.map((s) => s.kind));
    for (const k of [
      "command_exec",
      "eval",
      "deserialize",
      "template_render",
      "fs_write",
    ] as const) {
      expect(kinds.has(k)).toBe(true);
    }
    // shell=True is surfaced on the subprocess sink note.
    expect(
      taintSinks.some((s) => s.kind === "command_exec" && /shell=True/.test(s.description ?? "")),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Layer 1 — Python discovery ruleset + offline config/secrets detectors.
// ---------------------------------------------------------------------------
describe("python discovery — ruleset selection + config detectors", () => {
  const pyApp = { languages: ["python"] as const };

  it("selects the curated Python Semgrep rulesets + PyPI SCA ecosystem", () => {
    expect(selectSemgrepRulesets(pyApp)).toEqual(["p/python", "p/django", "p/flask"]);
    expect(selectScaEcosystems(pyApp)).toEqual(["PyPI"]);
    expect(selectCustomDetectors(pyApp).length).toBeGreaterThan(0);
  });

  it("flags DEBUG / wildcard hosts / hard-coded SECRET_KEY in the vulnerable settings (values redacted)", async () => {
    const content = await readFile(
      new URL("../corpus/python-vuln/myapp/settings.py", import.meta.url),
      "utf8",
    );
    const findings = runCustomDetectors(
      { path: "myapp/settings.py", content },
      selectCustomDetectors(pyApp),
    );
    const byRule = new Map(findings.map((f) => [f.rule, f]));

    expect(byRule.get("python.django.hardcoded-secret-key")?.line).toBe(5); // matches ground truth
    expect(byRule.get("python.django.debug-true")?.line).toBe(8);
    expect(byRule.get("python.django.wildcard-allowed-hosts")?.line).toBe(9);
    // ⛔ Never emit the secret value (golden rule #1).
    for (const f of findings) expect(f.snippet).not.toContain("django-insecure-hardcoded");
  });

  it("raises NO config findings on the secured settings (secret from env, DEBUG off)", async () => {
    const content = await readFile(
      new URL("../corpus/python-clean/myapp/settings.py", import.meta.url),
      "utf8",
    );
    const findings = runCustomDetectors(
      { path: "myapp/settings.py", content },
      selectCustomDetectors(pyApp),
    );
    expect(findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Layer 3a — Python confirmation heuristics feed the stack-agnostic proof.
// ---------------------------------------------------------------------------
describe("python confirm — heuristics make the source→sink proof precise", () => {
  const pyApp = { languages: ["python"] as const };

  it("confirms every vulnerable Django sink as dangerous, demotes the parameterized one", async () => {
    const h = resolveHeuristics(pyApp);
    expect(h.unsafeMarkers.length).toBeGreaterThan(0);

    const vuln = await buildAppMap(baseInput(), { now: fixedNow });
    for (const sink of vuln.appMap.taintSinks) {
      expect(assessSink(sink, h).dangerous).toBe(true);
    }

    const clean = await buildAppMap(
      baseInput({ repo: CLEAN_DIR, scanId: "scan_clean2", commitSha: CLEAN_COMMIT }),
      {
        now: fixedNow,
      },
    );
    const sql = clean.appMap.taintSinks.find((s) => s.kind === "sql_query")!;
    const assessment = assessSink(sql, h);
    expect(assessment.dangerous).toBe(false);
    expect(assessment.sanitizer).toBe("parameterized");
  });

  it("extracts the request parameter name via the Python source patterns", () => {
    const h = resolveHeuristics(pyApp);
    expect(extractParam("request.GET.get('q')", h)).toBe("q");
    // Subscript form is Python-specific (base patterns don't cover request.form[...]).
    expect(extractParam("request.form['name']", h)).toBe("name");
  });

  it("⛔ no Python unsafe-marker collides with a base safe-marker (never mis-demoted)", async () => {
    const BASE_SAFE = ["parameteri", "escap", "saniti", "validate", "allowlist", "placeholder"];
    for (const marker of pythonHeuristics.unsafeMarkers ?? []) {
      for (const safe of BASE_SAFE) expect(marker.toLowerCase().includes(safe)).toBe(false);
    }
    // And the dangerous corpus sink notes themselves carry no base safe substring.
    const vuln = await buildAppMap(baseInput({ scanId: "scan_inv" }), { now: fixedNow });
    for (const sink of vuln.appMap.taintSinks) {
      const d = (sink.description ?? "").toLowerCase();
      for (const safe of BASE_SAFE) expect(d.includes(safe)).toBe(false);
    }
  });
});
