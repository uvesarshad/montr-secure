/**
 * JVM (Spring / JPA) secrets/config + weak-crypto detectors (Layer 1 stack breadth).
 *
 * Offline regex detectors authored as {@link FileDetector}s and APPENDED to the
 * always-on base set via the ruleset's `customDetectors`. They cover the Spring
 * misconfigurations the base (Node-oriented) detectors miss: a hard-coded
 * `spring.datasource.password` / `api-key` in `application.{properties,yml}`, a
 * wildcard actuator exposure, weak JCA algorithms (`MessageDigest`/`Cipher`),
 * and a disabled CSRF filter.
 *
 * Each detector is scoped by file type so it never fires on the TS/JS surface in
 * a mixed repo. ⛔ Secret VALUES are never emitted — snippets are redacted
 * (golden rule #1), matching the base secrets detector.
 *
 * NOTE (seam): the shared secrets file provider reads `.env` + a fixed text
 * allow-list (`util/files.ts` `TEXT_EXT`: `.yml`/`.yaml`/`.conf`/… but NOT
 * `.properties` or `.java`). So the config detectors fire on the YAML path today
 * and the `.java` detectors run once `.java` is added there (or when a caller
 * supplies the file directly). Semgrep `p/java`/`p/spring` already cover the same
 * rules in the online path; these are the air-gapped/offline fallback. This
 * mirrors the Python ruleset's `.py` seam note exactly.
 */
import type { FileDetector, RawFinding } from "../../detectors/secrets.js";
import type { RepoFile } from "../../util/files.js";

/** `application.yml` / `bootstrap.properties` / … — Spring externalized config. */
function isSpringConfig(file: RepoFile): boolean {
  const base = file.path.split("/").pop() ?? "";
  return /^(?:application|bootstrap)(?:-[\w.]+)?\.(?:properties|ya?ml)$/i.test(base);
}

function isJava(file: RepoFile): boolean {
  return file.path.endsWith(".java");
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
  make: (m: RegExpExecArray, line: number) => RawFinding | null,
): RawFinding[] {
  const out: RawFinding[] = [];
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  let m: RegExpExecArray | null;
  while ((m = rx.exec(file.content)) !== null) {
    const f = make(m, lineAt(file.content, m.index));
    if (f) out.push(f);
    if (m.index === rx.lastIndex) rx.lastIndex++;
  }
  return out;
}

/** A config value that is externalized (`${ENV}`) or an obvious placeholder is NOT a hard-coded secret. */
function isPlaceholderValue(raw: string): boolean {
  const v = raw.trim().replace(/^["']|["']$/g, "");
  if (v.length < 6) return true;
  if (/\$\{[^}]*\}/.test(v)) return true; // ${DB_PASSWORD} / ${...:default}
  if (/^#\{[^}]*\}$/.test(v)) return true; // SpEL #{...}
  if (/^(?:changeme|change-me|example|placeholder|dummy|todo|none|null|your[_-].*)$/i.test(v)) {
    return true;
  }
  return false;
}

/**
 * Hard-coded credential in Spring externalized config: a literal
 * `password` / `secret` / `api-key` / `token` value (not a `${ENV}` reference).
 */
export const detectSpringHardcodedSecret: FileDetector = (file) => {
  if (!isSpringConfig(file)) return [];
  const re =
    /(?:^|[.\s])(password|passwd|secret|api[._-]?key|access[._-]?key|private[._-]?key|client[._-]?secret|token|credential)\s*[:=]\s*(\S[^\r\n]*)/gim;
  return scan(file, re, (m, line) => {
    const value = m[2] ?? "";
    if (isPlaceholderValue(value)) return null;
    return {
      rule: "java.spring.hardcoded-secret",
      category: "hardcoded_secret",
      cwe: ["CWE-798"],
      severity: "high",
      line,
      // ⛔ Never emit the value.
      snippet: `hard-coded ${(m[1] ?? "credential").toLowerCase()} in Spring config (value redacted)`,
      title: "Hard-coded credential in Spring configuration",
      metadata: { detector: "java-config", rule: "spring.hardcoded-secret" },
    };
  });
};

/**
 * Wildcard actuator exposure — flattened `management.endpoints.web.exposure.include=*`
 * (properties) or a nested `include: "*"` line (YAML). The nested form is matched
 * line-anchored (not by spanning `exposure:`→`include:`), so an interleaved comment
 * or blank line between the two YAML keys — as in `corpus/jvm-vuln` — does not defeat
 * detection. Scoped to `application*.{properties,yml}` (isSpringConfig) so a bare
 * `include: "*"` there is the actuator wildcard, keeping false positives low.
 */
export const detectActuatorExposure: FileDetector = (file) => {
  if (!isSpringConfig(file)) return [];
  const re =
    /management\.endpoints\.web\.exposure\.include\s*[:=]\s*["']?\*|^[ \t]*include:[ \t]*["']?\*/im;
  return scan(file, re, (_m, line) => ({
    rule: "java.spring.actuator-exposed",
    category: "sensitive_data_exposure",
    cwe: ["CWE-16"],
    severity: "medium",
    line,
    snippet: "management.endpoints.web.exposure.include='*' exposes all actuator endpoints",
    title: "All Spring Boot actuator endpoints exposed",
    metadata: { detector: "java-config", rule: "spring.actuator-exposed" },
  }));
};

/** Weak JCA hash (`MessageDigest.getInstance("MD5"|"SHA-1")`) used in code. */
export const detectWeakHash: FileDetector = (file) => {
  if (!isJava(file)) return [];
  return scan(file, /MessageDigest\.getInstance\(\s*"(MD2|MD4|MD5|SHA-?1)"/g, (m, line) => ({
    rule: "java.crypto.weak-hash",
    category: "weak_crypto",
    cwe: ["CWE-327"],
    severity: "medium",
    line,
    snippet: `weak hash algorithm MessageDigest.getInstance("${m[1]}")`,
    title: "Weak hash algorithm (MD5/SHA-1)",
    metadata: { detector: "java-crypto", rule: "crypto.weak-hash" },
  }));
};

/** Weak/insecure JCA cipher (`Cipher.getInstance("DES"|"RC4"|"…/ECB/…")`). */
export const detectWeakCipher: FileDetector = (file) => {
  if (!isJava(file)) return [];
  return scan(
    file,
    /Cipher\.getInstance\(\s*"(DES|DESede|RC2|RC4|ARCFOUR|Blowfish|[^"]*\/ECB\/[^"]*)"/g,
    (m, line) => ({
      rule: "java.crypto.weak-cipher",
      category: "weak_crypto",
      cwe: ["CWE-327"],
      severity: "medium",
      line,
      snippet: `insecure cipher Cipher.getInstance("${m[1]}") (DES/RC4/ECB)`,
      title: "Insecure/weak cipher (DES/RC4/ECB mode)",
      metadata: { detector: "java-crypto", rule: "crypto.weak-cipher" },
    }),
  );
};

/** Disabled CSRF protection — `http.csrf().disable()` / `csrf(c -> c.disable())`. */
export const detectCsrfDisabled: FileDetector = (file) => {
  if (!isJava(file)) return [];
  return scan(
    file,
    /\.csrf\s*\([^)]*\)\s*\.disable\s*\(\)|csrf\([^)]*\.disable\(\)\s*\)/g,
    (_m, line) => ({
      rule: "java.spring.csrf-disabled",
      category: "csrf",
      cwe: ["CWE-352"],
      severity: "medium",
      line,
      snippet: "Spring Security CSRF protection disabled (csrf().disable())",
      title: "CSRF protection disabled",
      metadata: { detector: "java-security", rule: "spring.csrf-disabled" },
    }),
  );
};

/** The JVM config/crypto detectors, exported for the ruleset's `customDetectors`. */
export const JAVA_DETECTORS: readonly FileDetector[] = [
  detectSpringHardcodedSecret,
  detectActuatorExposure,
  detectWeakHash,
  detectWeakCipher,
  detectCsrfDisabled,
];
