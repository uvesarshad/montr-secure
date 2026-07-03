/**
 * Python-specific secrets/config detectors (Layer 1 stack breadth).
 *
 * Offline regex detectors, authored as {@link FileDetector}s and APPENDED to the
 * always-on base set via the ruleset's `customDetectors`. They cover the Django /
 * Flask misconfigurations that the base (Node-oriented) detectors miss:
 * `DEBUG = True`, wildcard `ALLOWED_HOSTS`, a hard-coded `SECRET_KEY`,
 * `app.run(debug=True)`, weak `hashlib` hashes, and disabled TLS verification.
 *
 * Each detector is scoped to `.py` files so it never fires on the TS/JS surface
 * in a mixed repo. ⛔ Secret VALUES are never emitted — snippets are redacted
 * (golden rule #1), matching the base secrets detector.
 *
 * NOTE (seam): the shared secrets file provider only reads `.env` + a fixed text
 * allow-list (`util/files.ts` `TEXT_EXT`), which does NOT include `.py`, so these
 * run only once `.py` is added there. Semgrep `p/django`/`p/python` already cover
 * the same rules in the online path; these are the air-gapped/offline fallback.
 */
import type { FileDetector, RawFinding } from "../../detectors/secrets.js";
import type { RepoFile } from "../../util/files.js";

function isPython(file: RepoFile): boolean {
  return file.path.endsWith(".py");
}

function lineAt(content: string, index: number): number {
  let line = 1;
  const end = Math.min(index, content.length);
  for (let i = 0; i < end; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

/** Run a global regex, yielding a {@link RawFinding} per match via `make`. */
function scan(
  file: RepoFile,
  re: RegExp,
  make: (m: RegExpExecArray, line: number) => RawFinding,
): RawFinding[] {
  const out: RawFinding[] = [];
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  let m: RegExpExecArray | null;
  while ((m = rx.exec(file.content)) !== null) {
    out.push(make(m, lineAt(file.content, m.index)));
    if (m.index === rx.lastIndex) rx.lastIndex++;
  }
  return out;
}

/** Django `DEBUG = True` — leaks stack traces / settings in production. */
export const detectDjangoDebug: FileDetector = (file) => {
  if (!isPython(file)) return [];
  return scan(file, /^[ \t]*DEBUG[ \t]*=[ \t]*True\b/m, (_m, line) => ({
    rule: "python.django.debug-true",
    category: "sensitive_data_exposure",
    cwe: ["CWE-489"],
    severity: "medium",
    line,
    snippet: "DEBUG = True (disable in production)",
    title: "Django DEBUG enabled",
    metadata: { detector: "python-config", rule: "django.debug-true" },
  }));
};

/** Wildcard `ALLOWED_HOSTS = ["*"]` — enables host-header attacks. */
export const detectWildcardAllowedHosts: FileDetector = (file) => {
  if (!isPython(file)) return [];
  return scan(file, /ALLOWED_HOSTS[ \t]*=[ \t]*\[[^\]]*['"]\*['"][^\]]*\]/, (_m, line) => ({
    rule: "python.django.wildcard-allowed-hosts",
    category: "sensitive_data_exposure",
    cwe: ["CWE-183"],
    severity: "medium",
    line,
    snippet: "ALLOWED_HOSTS = ['*'] (wildcard host)",
    title: "Django wildcard ALLOWED_HOSTS",
    metadata: { detector: "python-config", rule: "django.wildcard-allowed-hosts" },
  }));
};

/** Hard-coded `SECRET_KEY = "…"` (not read from the environment). */
export const detectHardcodedSecretKey: FileDetector = (file) => {
  if (!isPython(file)) return [];
  // Literal string RHS only; `SECRET_KEY = os.environ[...]` / `config(...)` is safe.
  return scan(file, /^[ \t]*SECRET_KEY[ \t]*=[ \t]*['"][^'"\n]{8,}['"]/m, (_m, line) => ({
    rule: "python.django.hardcoded-secret-key",
    category: "hardcoded_secret",
    cwe: ["CWE-798"],
    severity: "high",
    line,
    // ⛔ Never emit the value.
    snippet: "hard-coded Django SECRET_KEY (value redacted)",
    title: "Hard-coded Django SECRET_KEY",
    metadata: { detector: "python-config", rule: "django.hardcoded-secret-key" },
  }));
};

/** Flask `app.run(debug=True)` — remote code execution via the debugger PIN. */
export const detectFlaskDebug: FileDetector = (file) => {
  if (!isPython(file)) return [];
  return scan(file, /\.run\(\s*[^)]*\bdebug[ \t]*=[ \t]*True/, (_m, line) => ({
    rule: "python.flask.debug-run",
    category: "sensitive_data_exposure",
    cwe: ["CWE-489"],
    severity: "medium",
    line,
    snippet: "app.run(debug=True) (Werkzeug debugger enabled)",
    title: "Flask debug mode enabled",
    metadata: { detector: "python-config", rule: "flask.debug-run" },
  }));
};

/** Weak hash (`hashlib.md5` / `hashlib.sha1`) used for a security purpose. */
export const detectWeakHash: FileDetector = (file) => {
  if (!isPython(file)) return [];
  return scan(file, /hashlib\.(md5|sha1)\s*\(/, (m, line) => ({
    rule: "python.crypto.weak-hash",
    category: "weak_crypto",
    cwe: ["CWE-327"],
    severity: "medium",
    line,
    snippet: `weak hash function hashlib.${m[1]}()`,
    title: "Weak hash function (MD5/SHA-1)",
    metadata: { detector: "python-config", rule: "crypto.weak-hash" },
  }));
};

/** `requests(..., verify=False)` — TLS certificate verification disabled. */
export const detectDisabledTlsVerify: FileDetector = (file) => {
  if (!isPython(file)) return [];
  return scan(
    file,
    /\b(?:requests|httpx|session)\.[a-z]+\([^)]*\bverify[ \t]*=[ \t]*False/,
    (_m, line) => ({
      rule: "python.tls.verify-disabled",
      category: "sensitive_data_exposure",
      cwe: ["CWE-295"],
      severity: "medium",
      line,
      snippet: "TLS verification disabled (verify=False)",
      title: "Disabled TLS certificate verification",
      metadata: { detector: "python-config", rule: "tls.verify-disabled" },
    }),
  );
};

/** The Python config detectors, exported for the ruleset's `customDetectors`. */
export const PYTHON_DETECTORS: readonly FileDetector[] = [
  detectDjangoDebug,
  detectWildcardAllowedHosts,
  detectHardcodedSecretKey,
  detectFlaskDebug,
  detectWeakHash,
  detectDisabledTlsVerify,
];
