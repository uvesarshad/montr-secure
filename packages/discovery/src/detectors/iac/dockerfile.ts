/**
 * E16 — Dockerfile anti-pattern detection (offline, no Semgrep dependency).
 * Line/instruction-oriented pattern matching over raw Dockerfile text, mirroring
 * `detectors/secrets.ts`'s `RawFinding`/`FileDetector` convention exactly (a
 * per-file detector returning raw hits, mapped to `CandidateFinding` by the
 * caller via `buildCandidate`).
 *
 * Deliberately NOT a full Dockerfile parser (no BuildKit frontend, no
 * heredoc/line-continuation joining) — well-chosen, instruction-anchored
 * regex per the audit's own framing. Multi-line `RUN a \` + `  && b` forms are
 * scanned per physical line, so a check that needs the WHOLE instruction body
 * (e.g. ADD/FROM/USER/ENV/ARG, which are single-line in the overwhelming
 * majority of real Dockerfiles) works reliably; continuation-joined RUN bodies
 * are out of scope.
 */
import type { Category, Severity } from "@montr/contracts";
import type { RepoFile } from "../../util/files.js";
import { looksLikePlaceholder } from "../secrets.js";

export interface RawFinding {
  rule: string;
  category: Category;
  severity: Severity;
  line: number;
  snippet: string;
  title: string;
  metadata?: Record<string, unknown>;
}

interface Instruction {
  keyword: string;
  args: string;
  line: number;
  raw: string;
}

/** Split a Dockerfile into its top-level instructions (1-based line numbers). */
function parseInstructions(content: string): Instruction[] {
  const lines = content.split(/\r?\n/);
  const out: Instruction[] = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const m = /^([A-Za-z]+)\s+(.*)$/.exec(trimmed);
    if (!m) continue;
    const keyword = (m[1] ?? "").toUpperCase();
    const args = (m[2] ?? "").trim();
    out.push({ keyword, args, line: i + 1, raw: trimmed });
  }
  return out;
}

const KNOWN_INSTRUCTIONS = new Set([
  "FROM",
  "RUN",
  "CMD",
  "LABEL",
  "MAINTAINER",
  "EXPOSE",
  "ENV",
  "ADD",
  "COPY",
  "ENTRYPOINT",
  "VOLUME",
  "USER",
  "WORKDIR",
  "ARG",
  "ONBUILD",
  "STOPSIGNAL",
  "HEALTHCHECK",
  "SHELL",
]);

/** Keep only real Dockerfile instructions (drops stray text that happened to match the shape). */
function instructions(content: string): Instruction[] {
  return parseInstructions(content).filter((i) => KNOWN_INSTRUCTIONS.has(i.keyword));
}

const ARCHIVE_EXT_RE = /\.(?:tar(?:\.gz|\.bz2|\.xz)?|tgz|zip)$/i;

/** First whitespace-separated token of an ADD/COPY argument list (the source). */
function firstArg(args: string): string {
  // Handle the JSON array form: ["src", "dest"].
  const jsonMatch = /^\s*\[\s*"([^"]+)"/.exec(args);
  if (jsonMatch?.[1]) return jsonMatch[1];
  return (args.split(/\s+/)[0] ?? "").replace(/^--[^\s]+\s*/, "");
}

/**
 * A1: `ADD` used where `COPY` should be. Two distinct risks, flagged
 * separately: a remote-URL ADD fetches and (for archives) auto-extracts
 * attacker-reachable content with no integrity check; a local-path ADD that
 * isn't an archive gains ADD's implicit tar-auto-extraction behavior for zero
 * benefit over the more predictable COPY.
 */
function checkAddVsCopy(ins: Instruction): RawFinding | null {
  if (ins.keyword !== "ADD") return null;
  const src = firstArg(ins.args);
  if (!src) return null;
  if (/^https?:\/\//i.test(src)) {
    return {
      rule: "dockerfile.add-remote-url",
      category: "insecure_configuration",
      severity: "medium",
      line: ins.line,
      snippet: ins.raw,
      title: "ADD fetches a remote URL with no integrity verification",
      metadata: { detector: "iac-dockerfile", instruction: "ADD", kind: "remote-url" },
    };
  }
  if (!ARCHIVE_EXT_RE.test(src)) {
    return {
      rule: "dockerfile.add-instead-of-copy",
      category: "insecure_configuration",
      severity: "low",
      line: ins.line,
      snippet: ins.raw,
      title: "ADD used for a local, non-archive source — COPY is safer and more predictable",
      metadata: { detector: "iac-dockerfile", instruction: "ADD", kind: "local-non-archive" },
    };
  }
  return null;
}

/** A1: the image runs as root — no `USER` instruction, or the last one is root/0. */
function checkRunsAsRoot(all: Instruction[]): RawFinding | null {
  const userIns = all.filter((i) => i.keyword === "USER");
  const last = userIns[userIns.length - 1];
  if (!last) {
    const from = all.filter((i) => i.keyword === "FROM").pop();
    return {
      rule: "dockerfile.missing-user",
      category: "insecure_configuration",
      severity: "high",
      line: from?.line ?? 1,
      snippet: "no USER instruction found",
      title: "No USER instruction — container runs as root by default",
      metadata: { detector: "iac-dockerfile", instruction: "USER" },
    };
  }
  const user = last.args.split(":")[0]?.trim().toLowerCase();
  if (user === "root" || user === "0") {
    return {
      rule: "dockerfile.user-root",
      category: "insecure_configuration",
      severity: "high",
      line: last.line,
      snippet: last.raw,
      title: `Container explicitly runs as ${last.args.trim()} (root)`,
      metadata: { detector: "iac-dockerfile", instruction: "USER" },
    };
  }
  return null;
}

/** A1: base image with no pinned tag/digest (`FROM x` or `FROM x:latest`). */
function checkUnpinnedBaseImage(all: Instruction[]): RawFinding[] {
  const aliases = new Set<string>();
  const out: RawFinding[] = [];
  for (const ins of all) {
    if (ins.keyword !== "FROM") continue;
    const m = /^(\S+)(?:\s+AS\s+(\S+))?/i.exec(ins.args);
    const image = m?.[1] ?? "";
    const alias = m?.[2];
    if (alias) aliases.add(alias.toLowerCase());
    if (!image || image.toLowerCase() === "scratch") continue;
    if (aliases.has(image.toLowerCase())) continue; // references a prior build stage, not a registry image
    if (image.includes("@sha256:")) continue; // digest-pinned — the strongest form
    const tagMatch = /:([^/@]+)$/.exec(image);
    const tag = tagMatch?.[1];
    if (!tag || tag === "latest") {
      out.push({
        rule: "dockerfile.unpinned-base-image",
        category: "insecure_configuration",
        severity: "medium",
        line: ins.line,
        snippet: ins.raw,
        title: tag
          ? `Base image uses the floating ":latest" tag: ${image}`
          : `Base image has no tag or digest pin (defaults to :latest): ${image}`,
        metadata: { detector: "iac-dockerfile", instruction: "FROM", image },
      });
    }
  }
  return out;
}

const SECRET_ENV_NAME_RE = /(?:KEY|SECRET|TOKEN|PASSWORD|PWD|CREDENTIAL|PRIVATE)/i;

/** Secrets baked into an image layer via a literal ENV/ARG assignment. */
function checkSecretEnvArg(ins: Instruction): RawFinding | null {
  if (ins.keyword !== "ENV" && ins.keyword !== "ARG") return null;
  // Handle `ENV NAME=value`, `ENV NAME value` (legacy single-var form), and
  // `ARG NAME=default` / valueless `ARG NAME`. Multi-var `ENV A=1 B=2` only
  // resolves its first var — an acceptable gap for a pattern-based check.
  const m = /^([A-Za-z_][A-Za-z0-9_]*)(?:=(.*)|\s+(.*))?$/.exec(ins.args);
  const name = m?.[1];
  let value = (m?.[2] ?? m?.[3] ?? "").trim();
  if (!name || !value) return null;
  value = value.replace(/^["']|["']$/g, "");
  if (!SECRET_ENV_NAME_RE.test(name)) return null;
  if (looksLikePlaceholder(value)) return null;
  if (value.length < 8) return null;
  return {
    rule: `dockerfile.secret-in-${ins.keyword.toLowerCase()}`,
    category: "hardcoded_secret",
    severity: "high",
    line: ins.line,
    snippet: `${ins.keyword} ${name}=<redacted, ${value.length} chars>`,
    title: `Secret baked into an image layer via ${ins.keyword} ${name}`,
    metadata: { detector: "iac-dockerfile", instruction: ins.keyword, variable: name },
  };
}

/** Run all Dockerfile checks over one file's content. */
export function detectDockerfileIssues(file: RepoFile): RawFinding[] {
  const all = instructions(file.content);
  if (all.length === 0) return [];
  const out: RawFinding[] = [];

  const rootFinding = checkRunsAsRoot(all);
  if (rootFinding) out.push(rootFinding);

  out.push(...checkUnpinnedBaseImage(all));

  for (const ins of all) {
    const add = checkAddVsCopy(ins);
    if (add) out.push(add);
    const secret = checkSecretEnvArg(ins);
    if (secret) out.push(secret);
  }

  return out;
}

/** Sensitive filenames a missing `.dockerignore` risks baking into the build context. */
const SENSITIVE_ROOT_FILES: readonly RegExp[] = [
  /^\.env(\..+)?$/i,
  /^id_rsa$/i,
  /^\.npmrc$/i,
  /^\.aws\/credentials$/i,
  /^.*\.pem$/i,
  /^credentials\.json$/i,
  /^\.git\/config$/i,
];

export interface AnchoredFinding {
  finding: RawFinding;
  /** Repo-relative path the finding is anchored to (the caller has no natural single-file loop for a repo-level check). */
  file: string;
}

/**
 * A1: a Dockerfile with no `.dockerignore` risks baking secret-bearing files
 * (`.env`, `id_rsa`, `.npmrc` auth tokens, AWS credentials, ...) straight into
 * the build context / an image layer. Repo-level (not per-file), so it is run
 * once by the IaC entry point over the full file listing.
 */
export function detectMissingDockerignore(files: readonly RepoFile[]): AnchoredFinding[] {
  const paths = files.map((f) => f.path.replace(/^\.\//, ""));
  const dockerfiles = files.filter((f) => /(^|\/)Dockerfile(\.[^/]+)?$/i.test(f.path));
  if (dockerfiles.length === 0) return [];
  const hasDockerignore = paths.some((p) => /(^|\/)\.dockerignore$/i.test(p));
  if (hasDockerignore) return [];
  const exposedFiles = paths.filter((p) => {
    const base = p.split("/").pop() ?? p;
    return SENSITIVE_ROOT_FILES.some((re) => re.test(p) || re.test(base));
  });
  if (exposedFiles.length === 0) return [];
  const anchor = dockerfiles[0];
  if (!anchor) return [];
  return [
    {
      file: anchor.path,
      finding: {
        rule: "dockerfile.missing-dockerignore-secret-exposure",
        category: "hardcoded_secret",
        severity: "high",
        line: 1,
        snippet: `no .dockerignore; repo contains: ${exposedFiles.slice(0, 5).join(", ")}`,
        title:
          "Missing .dockerignore risks baking secret-bearing files into the image build context",
        metadata: {
          detector: "iac-dockerfile",
          check: "missing-dockerignore",
          exposedFiles: exposedFiles.slice(0, 20),
        },
      },
    },
  ];
}
