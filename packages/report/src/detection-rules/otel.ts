/**
 * B3 — OTel query variant. Concrete syntax choice: OTTL (OpenTelemetry
 * Transformation Language) boolean CONDITIONS — the real expression language
 * the OpenTelemetry Collector's `filter`/`transform` processors evaluate
 * against span/log attributes
 * (https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/ottl),
 * e.g. as a `filter/detection` processor's condition list. Chosen over a
 * bespoke query DSL because it is a real, versioned, already-standard part of
 * the OTel ecosystem rather than an invented syntax.
 *
 * Attributes referenced use OTel semantic-convention names where one exists:
 * `url.path`, `url.query`, `http.request.method` (semconv v1.24+ — the
 * `http.target`/`http.method` names they replaced are NOT used here). There
 * is no standard semconv attribute for raw HTTP request body content (bodies
 * are rarely captured as span/log attributes, for PII reasons); this uses
 * `http.request.body.content` as the attribute name a body-capturing
 * collector/receiver config would populate — call out to your own pipeline's
 * actual attribute name if it differs.
 *
 * Expresses the SAME logic as the Sigma rule (sigma.ts): same route
 * path/method, same payload markers, matched case-insensitively via OTTL's
 * `IsMatch` regex predicate.
 */
import type { RuleContext } from "./context.js";

function regexEscape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function markerRegex(markers: string[]): string {
  return `(?i)(${markers.map(regexEscape).join("|")})`;
}

export function buildOtelQuery(ctx: RuleContext): string {
  if (ctx.kind === "file-fallback") {
    const target = ctx.fileTarget ?? "";
    return [
      `// OTTL condition (log_record) — file/config-class finding, no HTTP route.`,
      `IsMatch(attributes["log.file.path"], ${JSON.stringify(`(?i)${regexEscape(target)}`)})`,
    ].join("\n");
  }

  const clauses: string[] = [`attributes["url.path"] == ${JSON.stringify(ctx.path)}`];
  if (ctx.method !== "ANY") {
    clauses.push(`attributes["http.request.method"] == ${JSON.stringify(ctx.method)}`);
  }
  const routeClause = clauses.join(" and ");

  if (ctx.markers.length === 0) {
    return `// OTTL condition (span or log_record) — route match only, no payload markers available.\n${routeClause}`;
  }

  const pattern = markerRegex(ctx.markers);
  const payloadClause = [
    `IsMatch(attributes["url.query"], ${JSON.stringify(pattern)})`,
    `IsMatch(attributes["http.request.body.content"], ${JSON.stringify(pattern)})`,
  ].join(" or ");

  return [
    `// OTTL condition (span or log_record) — evaluated by an OpenTelemetry Collector filter/transform processor.`,
    `(${routeClause}) and (${payloadClause})`,
  ].join("\n");
}
