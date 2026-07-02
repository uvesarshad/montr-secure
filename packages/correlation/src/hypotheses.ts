/**
 * Deterministic reachability + exploit hypotheses. Every ProbableFinding must
 * carry both (PRD §7 Layer 2 output). These templates are grounded in the App
 * Map facts; when a gateway is available the LLM refines this prose, but a sound
 * default always exists (fail-safe: the pipeline never depends on the LLM).
 */
import type { AppMap, CandidateFinding, Category } from "@montr/contracts";
import type { Grounding } from "./grounding.js";
import { humanize } from "./taxonomy.js";

function authLabel(g: Grounding): string {
  switch (g.authState) {
    case "public":
      return "public";
    case "authenticated":
      return "authenticated";
    case "role_gated":
      return "role-gated";
    default:
      return "unspecified-auth";
  }
}

function routeLabel(g: Grounding): string {
  return g.route?.path ?? "an unmapped handler";
}

function loc(cand: CandidateFinding): string {
  return `${cand.location.file}:${cand.location.line}`;
}

/** Best-effort tainted-parameter name from the mapped source (metadata only). */
function paramName(g: Grounding): string {
  const desc = g.matchedSource?.description ?? "";
  const quoted = desc.match(/['"`]([A-Za-z_]\w*)['"`]/);
  if (quoted?.[1]) return quoted[1];
  const dotted = desc.match(/\.([A-Za-z_]\w*)\b(?!\s*\()/);
  if (dotted?.[1]) return dotted[1];
  return "input";
}

export function reachabilityHypothesis(cand: CandidateFinding, g: Grounding): string {
  switch (g.klass) {
    case "injection":
      if (g.taintReaches) {
        return `Tainted input (${humanize(g.matchedSource?.kind ?? "request")}) enters the ${authLabel(g)} route ${routeLabel(g)} and flows into a ${humanize(g.matchedSink?.kind ?? "sink")} at ${loc(cand)} with no validator or sanitizer on the path.`;
      }
      return `A ${humanize(g.matchedSink?.kind ?? "dangerous")} sink exists at ${loc(cand)} on the ${authLabel(g)} route ${routeLabel(g)}; a tainted source was not traced statically, so reachability is unproven and kept for human review.`;
    case "config":
      return `Security misconfiguration (${humanize(cand.category)}) on the ${authLabel(g)} registered route ${routeLabel(g)} at ${loc(cand)}.`;
    case "secret":
      return `A hard-coded secret is present in the mapped configuration surface at ${loc(cand)}; it is reachable to anyone with source or build access.`;
    case "dependency":
      return `The vulnerable dependency at ${loc(cand)} is imported/called via the App Map graph (${g.corroborationBasis}).`;
    case "access":
      return `An access-control-sensitive handler on the ${authLabel(g)} route ${routeLabel(g)} at ${loc(cand)}.`;
    default:
      return `Finding at ${loc(cand)}${g.route ? ` on route ${routeLabel(g)}` : ""}, corroborated by ${g.corroborationBasis}.`;
  }
}

const EXPLOIT_TEMPLATES: Partial<Record<Category, (p: string, model: string) => string>> = {
  sql_injection: (p, model) =>
    `Supplying \`${p}=' OR '1'='1\` (or a UNION-based query) lets an attacker read or modify ${model} beyond intended authorization.`,
  nosql_injection: (p) =>
    `Supplying an operator payload such as \`${p}[$ne]=\` bypasses the intended query filter and returns unauthorized documents.`,
  command_injection: (p) =>
    `Supplying \`${p}=; id\` (shell metacharacters) causes the server to execute attacker-controlled OS commands.`,
  xss: (p) =>
    `Supplying \`${p}=<img src=x onerror=alert(1)>\` causes the payload to execute in a victim's browser session (reflected XSS).`,
  ssrf: (p) =>
    `Supplying \`${p}=http://169.254.169.254/\` makes the server issue requests to internal/metadata endpoints on the attacker's behalf.`,
  path_traversal: (p) =>
    `Supplying \`${p}=../../../../etc/passwd\` lets an attacker read files outside the intended directory.`,
  open_redirect: (p) =>
    `Supplying \`${p}=https://evil.example\` redirects victims to an attacker-controlled site for phishing.`,
  insecure_deserialization: () =>
    `A crafted serialized payload can trigger unexpected object instantiation and potentially remote code execution.`,
  xxe: () =>
    `A crafted XML document with an external entity can exfiltrate local files or trigger SSRF.`,
  permissive_cors: () =>
    `A malicious origin can read responses cross-origin; impact stays limited while the endpoint is public and carries no credentials/cookies.`,
  hardcoded_secret: () =>
    `The exposed credential can be used to authenticate directly to the associated service, bypassing application controls.`,
  vulnerable_dependency: () =>
    `The known CVE in this dependency is exploitable where the vulnerable code path is reachable at runtime.`,
  missing_security_headers: () =>
    `Absent headers (CSP/HSTS/etc.) widen the blast radius of other client-side attacks (clickjacking, MIME sniffing, downgrade).`,
  insecure_cookie: () =>
    `Missing Secure/HttpOnly/SameSite flags let a network or XSS attacker steal or replay the session cookie.`,
  weak_crypto: () =>
    `The weak algorithm/parameters allow an attacker to recover plaintext or forge values that should be protected.`,
  csrf: () =>
    `A forged cross-site request performs a state-changing action using the victim's authenticated session.`,
  idor: (p) =>
    `Incrementing \`${p}\` to another tenant's identifier returns records the caller is not authorized to see.`,
  broken_access_control: () =>
    `The missing authorization check lets a lower-privileged caller invoke a privileged action.`,
  broken_authentication: () =>
    `Weaknesses in the authentication flow let an attacker impersonate a legitimate user.`,
};

export function exploitHypothesis(cand: CandidateFinding, g: Grounding, appMap: AppMap): string {
  const p = paramName(g);
  const model = appMap.ormModels[0]?.name
    ? `the ${appMap.ormModels[0]?.name} model`
    : "the database";
  const template = EXPLOIT_TEMPLATES[cand.category];
  if (template) return template(p, model);
  return `If reachable, this ${humanize(cand.category)} weakness could compromise the confidentiality, integrity, or availability of the affected component.`;
}
