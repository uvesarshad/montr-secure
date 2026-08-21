/**
 * Framework configuration (B9) — the leftover, framework-specific hardening
 * gaps that don't fit the other six categories: Next.js's `poweredByHeader`
 * disclosure, Express's `X-Powered-By` header, and a missing/incorrect
 * `trust proxy` setting that would break IP-based rate-limit/logging logic.
 */
import type { AppMap } from "@montr/contracts";
import { isSourceFile, readAll, type FileProvider } from "@montr/discovery";
import { detectAnyDependency, findFilesByBasename, matches } from "../detect.js";
import type { RecommendationDraft } from "../types.js";

const NEXT_CONFIG_BASENAMES = [
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "next.config.cjs",
];
const POWERED_BY_KEY_RE = /poweredByHeader\s*:\s*(true|false)/;
const DISABLE_X_POWERED_BY_RE = /\.disable\(\s*["']x-powered-by["']\s*\)/i;
const TRUST_PROXY_EXPRESS_RE = /\.set\(\s*["']trust proxy["']/i;
const TRUST_PROXY_FASTIFY_RE = /trustProxy\s*[:=]/;
const REQ_IP_RE = /\breq\.ip\b|\brequest\.ip\b/;
const RATE_LIMIT_PACKAGES = ["express-rate-limit", "@fastify/rate-limit", "rate-limiter-flexible"];

export interface FrameworkConfigurationOptions {
  /** From security-headers.ts's detection — helmet's default config already disables X-Powered-By. */
  helmetDetected: boolean;
}

export async function detectFrameworkConfigurationGaps(
  appMap: AppMap,
  files: FileProvider,
  options: FrameworkConfigurationOptions,
): Promise<RecommendationDraft[]> {
  const drafts: RecommendationDraft[] = [];
  const frameworks = new Set(appMap.frameworks);

  if (frameworks.has("nextjs")) {
    const configPaths = await findFilesByBasename(files, NEXT_CONFIG_BASENAMES);
    let disclosed = configPaths.length === 0; // no config at all -> the Next.js default (true) applies.
    let inspectedPath: string | undefined;
    for (const p of configPaths) {
      const content = await files.read(p);
      if (!content) continue;
      const m = POWERED_BY_KEY_RE.exec(content);
      if (m) {
        inspectedPath = p;
        disclosed = m[1] === "true";
        break;
      }
      // Config exists but never sets poweredByHeader at all -> Next.js default (true, disclosed).
      inspectedPath ??= p;
      disclosed = true;
    }
    if (disclosed) {
      drafts.push({
        category: "framework_configuration",
        severity: "low",
        title: "Disable Next.js's X-Powered-By header",
        gap: inspectedPath
          ? `${inspectedPath} does not set \`poweredByHeader: false\` (or sets it to \`true\`) — Next.js discloses \`X-Powered-By: Next.js\` on every response.`
          : "No next.config.* found — Next.js's default X-Powered-By header disclosure is unchanged.",
        recommendation: "module.exports = {\n  poweredByHeader: false,\n};",
        rationale:
          "Disclosing the framework in a response header gives an attacker a free technology-fingerprinting signal for no functional benefit.",
        evidence: inspectedPath
          ? [`${inspectedPath}: poweredByHeader not set to false`]
          : ["No next.config.{js,mjs,ts,cjs} found in the repo"],
        framework: "nextjs",
      });
    }
  }

  if (frameworks.has("express") && !options.helmetDetected) {
    const sources = await filesSourceContent(files);
    const disabled = sources.some(({ content }) => matches(content, DISABLE_X_POWERED_BY_RE));
    if (!disabled) {
      drafts.push({
        category: "framework_configuration",
        severity: "low",
        title: "Disable Express's X-Powered-By header",
        gap: 'No `app.disable("x-powered-by")` call was found, and no helmet dependency (which disables it by default) was detected — Express discloses `X-Powered-By: Express` on every response.',
        recommendation: 'app.disable("x-powered-by");',
        rationale:
          "Disclosing the framework in a response header gives an attacker a free technology-fingerprinting signal for no functional benefit.",
        evidence: [
          'No app.disable("x-powered-by") call found in the repo',
          "No helmet dependency detected",
        ],
        framework: "express",
      });
    }
  }

  if (frameworks.has("express")) {
    const sources = await filesSourceContent(files);
    const usesReqIp = sources.some(({ content }) => REQ_IP_RE.test(content));
    const rateLimitDep = await detectAnyDependency(files, RATE_LIMIT_PACKAGES);
    const needsTrustProxy = usesReqIp || rateLimitDep.present;
    const configured = sources.some(({ content }) => TRUST_PROXY_EXPRESS_RE.test(content));
    if (needsTrustProxy && !configured) {
      drafts.push({
        category: "framework_configuration",
        severity: "medium",
        title: 'Configure Express\'s "trust proxy" setting',
        gap: `The app uses IP-based logic (${usesReqIp ? "req.ip" : "a rate-limit middleware"}) but no \`app.set("trust proxy", ...)\` was found — behind a reverse proxy/load balancer, \`req.ip\` resolves to the proxy's address for every request, not the real client, breaking IP-based rate limiting and audit logging.`,
        recommendation:
          '// Set to the actual number of trusted proxy hops in front of the app (or a\n// specific CIDR/IP allowlist) — NEVER `app.set("trust proxy", true)` blindly,\n// which trusts the X-Forwarded-For header from any client.\napp.set("trust proxy", 1);',
        rationale:
          "An unconfigured (or blindly-true) trust proxy setting either breaks IP-based rate limiting entirely or lets a client spoof its own IP via X-Forwarded-For to bypass it.",
        evidence: [
          usesReqIp
            ? "req.ip usage found in source"
            : "A rate-limit middleware dependency was detected",
          'No app.set("trust proxy", ...) call found',
        ],
        framework: "express",
      });
    }
  }

  if (frameworks.has("fastify")) {
    const sources = await filesSourceContent(files);
    const usesReqIp = sources.some(({ content }) => /\brequest\.ip\b/.test(content));
    const rateLimitDep = await detectAnyDependency(files, RATE_LIMIT_PACKAGES);
    const needsTrustProxy = usesReqIp || rateLimitDep.present;
    const configured = sources.some(({ content }) => TRUST_PROXY_FASTIFY_RE.test(content));
    if (needsTrustProxy && !configured) {
      drafts.push({
        category: "framework_configuration",
        severity: "medium",
        title: "Configure Fastify's trustProxy option",
        gap: `The app uses IP-based logic (${usesReqIp ? "request.ip" : "a rate-limit middleware"}) but no \`trustProxy\` option was found on the Fastify instance — behind a reverse proxy, \`request.ip\` resolves to the proxy's address, breaking IP-based rate limiting and audit logging.`,
        recommendation:
          "// Set to the number of trusted proxy hops, or a specific CIDR — never blindly `true`.\nconst app = fastify({ trustProxy: 1 });",
        rationale:
          "An unconfigured trustProxy option either breaks IP-based rate limiting entirely or lets a client spoof its own IP via X-Forwarded-For to bypass it.",
        evidence: [
          usesReqIp
            ? "request.ip usage found in source"
            : "A rate-limit middleware dependency was detected",
          "No trustProxy option found on the Fastify instance",
        ],
        framework: "fastify",
      });
    }
  }

  return drafts;
}

async function filesSourceContent(
  files: FileProvider,
): Promise<{ path: string; content: string }[]> {
  return readAll(files, isSourceFile);
}
