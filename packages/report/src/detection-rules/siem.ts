/**
 * B3 — SIEM query variant. Concrete syntax choice: Splunk SPL (Search
 * Processing Language) — a real, widely-deployed SIEM query dialect (as
 * opposed to a bespoke generic syntax), so the output is directly pastable
 * into a Splunk search bar. Field names (`uri_path`, `uri_query`, `method`,
 * `body`) follow Splunk's common web-log CIM (Common Information Model)
 * `Web` datamodel naming.
 *
 * Expresses the SAME logic as the Sigma rule (sigma.ts) / OTel condition
 * (otel.ts) — same route path/method, same payload markers, matched
 * case-insensitively via Splunk's PCRE-flavored `match()`.
 */
import type { RuleContext } from "./context.js";

function splQuote(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function regexEscape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function markerRegex(markers: string[]): string {
  return `(?i)(${markers.map(regexEscape).join("|")})`;
}

export function buildSiemQuery(ctx: RuleContext): string {
  if (ctx.kind === "file-fallback") {
    const target = ctx.fileTarget ?? "";
    return `index=file_integrity sourcetype=file_event TargetFilename=${splQuote(`*${target}*`)}`;
  }

  const filters = [`uri_path=${splQuote(ctx.path)}`];
  if (ctx.method !== "ANY") filters.push(`method=${splQuote(ctx.method)}`);
  const base = `index=web sourcetype=access_combined ${filters.join(" ")}`;

  if (ctx.markers.length === 0) return base;

  const pattern = splQuote(markerRegex(ctx.markers));
  return [
    base,
    `| eval montr_payload_match=if(match(uri_query, ${pattern}) OR match(body, ${pattern}), 1, 0)`,
    `| where montr_payload_match=1`,
  ].join("\n");
}
