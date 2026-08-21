/**
 * Threat-model report (B7) — a report-quality, human-readable rendering of a
 * scan's persisted `ThreatModel` (`AppMap.threatModel`, B1): trust
 * boundaries, a STRIDE breakdown per boundary AND per attack-surface
 * category, and abuse cases, written so a security-lead / AppSec "buyer"
 * (PRD §Primary buyer) can see what is actually at risk in THIS application —
 * not a generic OWASP/STRIDE textbook dump.
 *
 * Distinct from E6 (`packages/appmap/src/threat-model.ts`), which derives the
 * SAME `ThreatModel` shape to DRIVE Layer 1/Layer 3 scan-scope prioritization
 * (`ThreatModel.scopeHints`). This module never re-derives anything — it only
 * renders an already-computed `ThreatModel` — and it deliberately drops
 * `scopeHints` from the rendered artifact: that field is an internal
 * prioritization signal for the pipeline, not something a report reader would
 * find meaningful (a "priority category" line with no accompanying evidence
 * would read as an unexplained assertion; the SAME evidence already appears,
 * fully explained, in `attackSurface` and `trustBoundaries[].stride` below).
 *
 * Same `build<X>` -> plain data model -> `render<X>Json`/`render<X>Markdown`
 * split every other exporter in this directory follows (see `owasp.ts`,
 * `cyclonedx.ts`). Two text renderings rather than three: `Report`-shaped
 * exporters that also ship HTML (`owasp.ts`, `html.ts`) render CONFIRMED
 * FINDINGS, which benefit from styled severity badges/tables; a threat model
 * is prose + a handful of small lists, which markdown already renders
 * cleanly (and drops straight into a PR description or wiki page — this
 * product's own automated PR flow already speaks markdown). An HTML/PDF
 * rendering can be added the same way `owasp.ts` layers `renderOwaspHtml` on
 * top of `buildOwaspCoverage` whenever B10 wires this into the main report.
 *
 * NOT wired into the main report-assembly/builder (`index.ts`'s
 * `generateExport`/`EXPORTERS` registry) — that is B10's job in a later wave,
 * once the compliance-export + blue-team-section work in flight this same
 * wave has landed. Standalone and independently testable in the meantime.
 */
import {
  STRIDE_LABELS,
  type AbuseCase,
  type AttackSurfaceEntry,
  type StrideCategory,
  type SurfacePlausibility,
  type ThreatModel,
  type TrustBoundary,
} from "@montr/contracts";

export interface ThreatModelReportOptions {
  scanId?: string;
  repo?: string;
  /** Deterministic generation time (tests). Defaults to now. */
  now?: string;
}

/** One trust boundary, with its STRIDE classification spelled out (never a bare enum list). */
export interface RenderedTrustBoundary {
  name: string;
  description: string;
  routePaths: readonly string[];
  stride: Array<{ category: StrideCategory; label: string; rationale: string }>;
}

/** One attack-surface category worth showing the reader — `plausibility: "none"` entries are dropped. */
export interface RenderedAttackSurfaceEntry {
  category: string;
  plausibility: SurfacePlausibility;
  rationale: string;
  stride: Array<{ category: StrideCategory; label: string }>;
}

/** Roll-up: how many boundaries and how many attack-surface categories genuinely trigger each STRIDE letter. */
export interface StrideRollupRow {
  category: StrideCategory;
  label: string;
  boundaryCount: number;
  attackSurfaceCount: number;
}

export interface ThreatModelReport {
  scanId?: string;
  repo?: string;
  generatedAt: string;
  generatedByLlm: boolean;
  /** Plain-language headline for a non-technical/AppSec-lead reader — grounded in the counts below, never boilerplate. */
  summary: string;
  trustBoundaries: RenderedTrustBoundary[];
  strideRollup: StrideRollupRow[];
  attackSurface: RenderedAttackSurfaceEntry[];
  abuseCases: readonly AbuseCase[];
}

const PLAUSIBILITY_ORDER: Record<SurfacePlausibility, number> = {
  high: 0,
  medium: 1,
  low: 2,
  none: 3,
};

const STRIDE_ORDER: readonly StrideCategory[] = [
  "spoofing",
  "tampering",
  "repudiation",
  "information_disclosure",
  "denial_of_service",
  "elevation_of_privilege",
];

function renderBoundary(b: TrustBoundary): RenderedTrustBoundary {
  return {
    name: b.name,
    description: b.description,
    routePaths: b.routePaths,
    stride: b.stride.map((s) => ({
      category: s.category,
      label: STRIDE_LABELS[s.category],
      rationale: s.rationale,
    })),
  };
}

function renderAttackSurfaceEntry(e: AttackSurfaceEntry): RenderedAttackSurfaceEntry {
  return {
    category: e.category,
    plausibility: e.plausibility,
    rationale: e.rationale,
    stride: e.stride.map((c) => ({ category: c, label: STRIDE_LABELS[c] })),
  };
}

function buildStrideRollup(
  trustBoundaries: readonly TrustBoundary[],
  attackSurface: readonly AttackSurfaceEntry[],
): StrideRollupRow[] {
  return STRIDE_ORDER.map((category) => ({
    category,
    label: STRIDE_LABELS[category],
    boundaryCount: trustBoundaries.filter((b) => b.stride.some((s) => s.category === category))
      .length,
    attackSurfaceCount: attackSurface.filter((e) => e.stride.includes(category)).length,
  }));
}

function buildSummary(threatModel: ThreatModel, trustBoundaries: RenderedTrustBoundary[]): string {
  const weakBoundaries = trustBoundaries.filter((b) =>
    b.stride.some((s) => s.category === "spoofing"),
  );
  const plausible = threatModel.attackSurface.filter((e) => e.plausibility !== "none");
  const highPlausible = plausible.filter((e) => e.plausibility === "high");
  const strideTouched = STRIDE_ORDER.filter(
    (c) =>
      trustBoundaries.some((b) => b.stride.some((s) => s.category === c)) ||
      threatModel.attackSurface.some((e) => e.stride.includes(c)),
  );

  const parts: string[] = [];
  parts.push(
    `This application has ${trustBoundaries.length} identified trust boundar${trustBoundaries.length === 1 ? "y" : "ies"}` +
      (weakBoundaries.length > 0
        ? `, ${weakBoundaries.length} of which accept${weakBoundaries.length === 1 ? "s" : ""} requests with no verified caller identity.`
        : ", none of which accept unauthenticated requests to a route with real evidence of risk."),
  );
  parts.push(
    `Of the six STRIDE threat categories, ${strideTouched.length} genuinely apply somewhere in this application — ` +
      `${strideTouched.map((c) => STRIDE_LABELS[c]).join(", ") || "none"} — each grounded in a specific route, ` +
      "ORM model, or code-level sink, not a generic checklist.",
  );
  if (plausible.length > 0) {
    parts.push(
      `${plausible.length} finding categor${plausible.length === 1 ? "y has" : "ies have"} real, structural attack surface` +
        (highPlausible.length > 0
          ? `; ${highPlausible.length} of them (${highPlausible.map((e) => e.category).join(", ")}) are high-plausibility.`
          : "."),
    );
  } else {
    parts.push(
      "No finding category has real structural attack surface in this application's current shape.",
    );
  }
  if (threatModel.abuseCases.length > 0) {
    parts.push(
      `${threatModel.abuseCases.length} concrete abuse-case scenario${threatModel.abuseCases.length === 1 ? "" : "s"} ` +
        "below walk through exactly how an attacker would exploit this.",
    );
  }
  return parts.join(" ");
}

/** Build the plain-data threat-model report model from a persisted `ThreatModel`. */
export function buildThreatModelReport(
  threatModel: ThreatModel,
  opts: ThreatModelReportOptions = {},
): ThreatModelReport {
  const trustBoundaries = threatModel.trustBoundaries.map(renderBoundary);
  const attackSurface = threatModel.attackSurface
    .filter((e) => e.plausibility !== "none")
    .slice()
    .sort((a, b) => PLAUSIBILITY_ORDER[a.plausibility] - PLAUSIBILITY_ORDER[b.plausibility])
    .map(renderAttackSurfaceEntry);

  return {
    ...(opts.scanId ? { scanId: opts.scanId } : {}),
    ...(opts.repo ? { repo: opts.repo } : {}),
    generatedAt: opts.now ?? new Date().toISOString(),
    generatedByLlm: threatModel.generatedByLlm,
    summary: buildSummary(threatModel, trustBoundaries),
    trustBoundaries,
    strideRollup: buildStrideRollup(threatModel.trustBoundaries, threatModel.attackSurface),
    attackSurface,
    abuseCases: threatModel.abuseCases,
  };
}

/** Machine-readable JSON rendering of the threat-model report. */
export function renderThreatModelReportJson(
  threatModel: ThreatModel,
  opts: ThreatModelReportOptions = {},
): string {
  return JSON.stringify(buildThreatModelReport(threatModel, opts), null, 2);
}

function mdEscape(value: string): string {
  // Neutralize markdown table/formatting metacharacters in interpolated
  // finding/route text so a crafted route path or rationale can't break the
  // table layout (defense in depth — this text is App-Map-derived, not
  // free-form user prose, but never trust it further downstream than needed).
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function boundaryMarkdown(b: RenderedTrustBoundary): string {
  const lines: string[] = [];
  lines.push(`### ${mdEscape(b.name)}`);
  lines.push("");
  lines.push(mdEscape(b.description));
  if (b.routePaths.length > 0) {
    lines.push("");
    lines.push(`Routes: ${b.routePaths.map((p) => `\`${mdEscape(p)}\``).join(", ")}`);
  }
  if (b.stride.length > 0) {
    lines.push("");
    lines.push("| STRIDE | Why it applies here |");
    lines.push("| --- | --- |");
    for (const s of b.stride) {
      lines.push(`| **${mdEscape(s.label)}** | ${mdEscape(s.rationale)} |`);
    }
  } else {
    lines.push("");
    lines.push("_No STRIDE category has grounded evidence against this boundary._");
  }
  return lines.join("\n");
}

/**
 * Human-readable markdown rendering — the reviewable deliverable an operator
 * or security-conscious buyer reads directly (drops straight into a PR
 * description, wiki page, or the compliance bundle B10 assembles later).
 */
export function renderThreatModelReportMarkdown(
  threatModel: ThreatModel,
  opts: ThreatModelReportOptions = {},
): string {
  const report = buildThreatModelReport(threatModel, opts);
  const lines: string[] = [];

  lines.push("# Threat Model");
  lines.push("");
  const meta: string[] = [];
  if (report.repo) meta.push(`**Repo:** ${mdEscape(report.repo)}`);
  if (report.scanId) meta.push(`**Scan:** \`${mdEscape(report.scanId)}\``);
  meta.push(`**Generated:** ${mdEscape(report.generatedAt)}`);
  meta.push(
    `**Enriched by LLM:** ${report.generatedByLlm ? "yes" : "no (deterministic baseline only)"}`,
  );
  lines.push(meta.join(" · "));
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(report.summary);

  lines.push("");
  lines.push("## STRIDE at a glance");
  lines.push("");
  lines.push(
    "| STRIDE category | Trust boundaries affected | Attack-surface categories affected |",
  );
  lines.push("| --- | --- | --- |");
  for (const row of report.strideRollup) {
    lines.push(`| ${mdEscape(row.label)} | ${row.boundaryCount} | ${row.attackSurfaceCount} |`);
  }

  lines.push("");
  lines.push("## Trust boundaries");
  lines.push("");
  if (report.trustBoundaries.length === 0) {
    lines.push("_No trust boundaries were identified (no routes in the App Map)._");
  } else {
    for (const b of report.trustBoundaries) {
      lines.push(boundaryMarkdown(b));
      lines.push("");
    }
  }

  lines.push("## Attack surface");
  lines.push("");
  if (report.attackSurface.length === 0) {
    lines.push(
      "_No finding category has real structural attack surface in this application's current shape._",
    );
  } else {
    lines.push("| Category | Plausibility | STRIDE | Why |");
    lines.push("| --- | --- | --- | --- |");
    for (const e of report.attackSurface) {
      const stride = e.stride.map((s) => s.label).join(", ") || "—";
      lines.push(
        `| ${mdEscape(e.category)} | ${e.plausibility} | ${mdEscape(stride)} | ${mdEscape(e.rationale)} |`,
      );
    }
  }

  lines.push("");
  lines.push("## Abuse cases");
  lines.push("");
  if (report.abuseCases.length === 0) {
    lines.push("_No concrete abuse-case scenarios were derived for this application._");
  } else {
    for (const ac of report.abuseCases) {
      lines.push(`### ${mdEscape(ac.title)}`);
      lines.push("");
      lines.push(mdEscape(ac.description));
      if (ac.routePaths.length > 0) {
        lines.push("");
        lines.push(`Routes: ${ac.routePaths.map((p) => `\`${mdEscape(p)}\``).join(", ")}`);
      }
      if (ac.categories.length > 0) {
        lines.push("");
        lines.push(`Categories: ${ac.categories.map((c) => mdEscape(c)).join(", ")}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n").trimEnd() + "\n";
}
