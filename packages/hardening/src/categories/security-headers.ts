/**
 * Security headers (B9). Framework-idiomatic wiring recommendations for
 * Express/Fastify (`helmet()` / `@fastify/helmet`) and Next.js (a
 * `headers()` config function) — grounded in the App Map's detected
 * `frameworks` and a real dependency-presence check (see `../detect.js`'s
 * `detectAnyDependency`, reusing `@montr/discovery`'s import-detection
 * infrastructure), not emitted unconditionally.
 */
import type { AppMap } from "@montr/contracts";
import type { FileProvider } from "@montr/discovery";
import { detectAnyDependency, findFilesByBasename, matches } from "../detect.js";
import type { RecommendationDraft } from "../types.js";

const NEXT_CONFIG_BASENAMES = [
  "next.config.js",
  "next.config.mjs",
  "next.config.ts",
  "next.config.cjs",
];
const HEADERS_FN_RE = /async\s+headers\s*\(/;

export const HELMET_PACKAGE = "helmet";
export const FASTIFY_HELMET_PACKAGE = "@fastify/helmet";

export interface SecurityHeaderSignals {
  /** True when a helmet-family dependency was detected for the app's framework. */
  helmetDetected: boolean;
}

/**
 * Detect missing security-header wiring. Returns both the recommendation
 * drafts and the raw signals (`helmetDetected`) so `framework-configuration.ts`
 * can avoid a redundant "disable x-powered-by" recommendation when helmet
 * already covers it (helmet's default config includes `hidePoweredBy`).
 */
export async function detectSecurityHeaderGaps(
  appMap: AppMap,
  files: FileProvider,
): Promise<{ drafts: RecommendationDraft[]; signals: SecurityHeaderSignals }> {
  const drafts: RecommendationDraft[] = [];
  const frameworks = new Set(appMap.frameworks);
  let helmetDetected = false;

  if (frameworks.has("express") || frameworks.has("fastify")) {
    const isFastify = frameworks.has("fastify");
    const pkg = isFastify ? FASTIFY_HELMET_PACKAGE : HELMET_PACKAGE;
    const dep = await detectAnyDependency(files, [pkg]);
    helmetDetected = dep.present;

    if (!dep.present) {
      drafts.push({
        category: "security_headers",
        severity: "medium",
        title: isFastify
          ? "Register @fastify/helmet for baseline security headers"
          : "Wire helmet() into the Express app",
        gap: `No \`${pkg}\` dependency detected (checked the resolved lockfile/package.json install set and the import graph) — the app is not setting baseline security response headers.`,
        recommendation: isFastify
          ? [
              'import fastifyHelmet from "@fastify/helmet";',
              "",
              "app.register(fastifyHelmet, {",
              "  // Tune per-directive as needed; this is the safe baseline.",
              "});",
            ].join("\n")
          : ['import helmet from "helmet";', "", "app.use(helmet());"].join("\n"),
        rationale:
          "Without helmet (or an equivalent header middleware), the app ships with no X-Frame-Options (clickjacking), no X-Content-Type-Options (MIME-sniffing), and no Strict-Transport-Security (protocol downgrade) protection by default.",
        evidence: [
          `No \`${pkg}\` in the resolved dependency set or the import graph`,
          `Detected framework: ${isFastify ? "fastify" : "express"}`,
        ],
        framework: isFastify ? "fastify" : "express",
      });
    }
  }

  if (frameworks.has("nextjs")) {
    const configPaths = await findFilesByBasename(files, NEXT_CONFIG_BASENAMES);
    let hasHeadersFn = false;
    let inspectedPath: string | undefined;
    for (const p of configPaths) {
      const content = await files.read(p);
      if (content && matches(content, HEADERS_FN_RE)) {
        hasHeadersFn = true;
        inspectedPath = p;
        break;
      }
      inspectedPath ??= p;
    }

    if (!hasHeadersFn) {
      drafts.push({
        category: "security_headers",
        severity: "medium",
        title: "Add a headers() function to next.config for baseline security headers",
        gap:
          configPaths.length > 0
            ? `${inspectedPath} has no \`async headers()\` export — no baseline security headers are configured.`
            : "No next.config.{js,mjs,ts,cjs} was found in the repo — no baseline security headers are configured.",
        recommendation: [
          "/** @type {import('next').NextConfig} */",
          "module.exports = {",
          "  async headers() {",
          "    return [",
          "      {",
          '        source: "/:path*",',
          "        headers: [",
          '          { key: "X-Frame-Options", value: "DENY" },',
          '          { key: "X-Content-Type-Options", value: "nosniff" },',
          '          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },',
          '          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },',
          "        ],",
          "      },",
          "    ];",
          "  },",
          "};",
        ].join("\n"),
        rationale:
          "Next.js does not set these headers by default; without an explicit headers() config the app has no clickjacking, MIME-sniffing, or protocol-downgrade protection.",
        evidence:
          configPaths.length > 0
            ? [`${inspectedPath}: no async headers() export found`]
            : ["No next.config.{js,mjs,ts,cjs} file found in the repo"],
        framework: "nextjs",
      });
    }
  }

  return { drafts, signals: { helmetDetected } };
}
