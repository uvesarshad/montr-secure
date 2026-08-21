/**
 * JVM (Spring / JPA) discovery ruleset + offline detector tests (Layer 1 breadth).
 *
 * Fully OFFLINE: runs the Java custom detectors against the on-disk `corpus/jvm-*`
 * config + source files and asserts the ruleset selection knobs. ⛔ Secret VALUES
 * are never emitted (golden rule #1). This is the JVM analogue of the Python
 * discovery assertions in `tests/appmap.python.test.ts`; it stays within the
 * `@montr/discovery` package's own surface (no cross-package test deps).
 */
import { readFile } from "node:fs/promises";
import { describe, it, expect } from "vitest";
import { runCustomDetectors, type RawFinding } from "../../detectors/secrets.js";
import { selectCustomDetectors, selectSemgrepRulesets, selectScaEcosystems } from "../registry.js";
import { javaRuleset } from "./index.js";
import { JAVA_DETECTORS } from "./detectors.js";

const javaApp = { languages: ["java"] as const };
const corpus = (p: string): URL => new URL("../../../../../" + p, import.meta.url);

async function detect(path: string): Promise<RawFinding[]> {
  const content = await readFile(corpus(path), "utf8");
  return runCustomDetectors({ path, content }, selectCustomDetectors(javaApp));
}
const byRule = (findings: RawFinding[]): Map<string, RawFinding> =>
  new Map(findings.map((f) => [f.rule, f]));

const VULN_YML = "corpus/jvm-vuln/src/main/resources/application.yml";
const VULN_HASH = "corpus/jvm-vuln/src/main/java/com/example/vuln/util/HashUtil.java";
const VULN_SEC = "corpus/jvm-vuln/src/main/java/com/example/vuln/config/SecurityConfig.java";

describe("java discovery — ruleset selection", () => {
  it("selects the curated JVM Semgrep rulesets + Maven SCA + java custom detectors", () => {
    // A33: p/spring was dropped (dead Registry pack, verified 404) — see
    // ../index.ts's module doc for the full evidence and the structural fix.
    expect(selectSemgrepRulesets(javaApp)).toEqual(["p/java"]);
    expect(selectScaEcosystems(javaApp)).toEqual(["Maven"]);
    expect(selectCustomDetectors(javaApp).length).toBeGreaterThan(0);
    expect(javaRuleset.appliesTo(["java"])).toBe(true);
    expect(javaRuleset.appliesTo(["typescript"])).toBe(false);
  });

  it("does not leak the java detectors onto a non-JVM (TS-only) app", () => {
    expect(selectCustomDetectors({ languages: ["typescript"] })).toHaveLength(0);
    expect(JAVA_DETECTORS).toHaveLength(5);
  });
});

describe("java discovery — vulnerable corpus (values redacted)", () => {
  it("flags the hard-coded Spring datasource password + api-key (never the value)", async () => {
    const found = await detect(VULN_YML);
    const lines = found
      .filter((f) => f.rule === "java.spring.hardcoded-secret")
      .map((f) => f.line)
      .sort((a, b) => a - b);
    expect(lines).toContain(7); // spring.datasource.password — matches ground truth
    expect(lines).toContain(14); // app.api-key
    // ⛔ golden rule #1 — no secret value survives in any snippet/metadata.
    for (const f of found) {
      expect(JSON.stringify(f)).not.toContain("S3cr3tP@ssw0rd");
      expect(JSON.stringify(f)).not.toContain("51H8xLcAbCdEfGhIjKlMnOpQrStUv");
    }
  });

  it("flags the wildcard actuator exposure despite the interleaved comment line", async () => {
    const actuator = byRule(await detect(VULN_YML)).get("java.spring.actuator-exposed");
    expect(actuator).toBeDefined();
    expect(actuator?.line).toBe(21);
  });

  it("flags weak MD5 hashing in HashUtil.java", async () => {
    const hash = byRule(await detect(VULN_HASH)).get("java.crypto.weak-hash");
    expect(hash?.line).toBe(16);
    expect(hash?.cwe).toContain("CWE-327");
  });

  it("flags disabled CSRF protection in SecurityConfig.java", async () => {
    const csrf = byRule(await detect(VULN_SEC)).get("java.spring.csrf-disabled");
    expect(csrf?.line).toBe(18);
    expect(csrf?.cwe).toContain("CWE-352");
  });

  it("flags an insecure DES cipher (synthetic — the corpus plants no Cipher use)", () => {
    const found = runCustomDetectors(
      { path: "Crypto.java", content: 'Cipher c = Cipher.getInstance("DES");' },
      selectCustomDetectors(javaApp),
    );
    expect(found.some((f) => f.rule === "java.crypto.weak-cipher")).toBe(true);
  });
});

describe("java discovery — secured corpus raises no config findings", () => {
  it("finds nothing in the clean yml / HashUtil / SecurityConfig", async () => {
    for (const p of [
      "corpus/jvm-clean/src/main/resources/application.yml",
      "corpus/jvm-clean/src/main/java/com/example/clean/util/HashUtil.java",
      "corpus/jvm-clean/src/main/java/com/example/clean/config/SecurityConfig.java",
    ]) {
      expect(await detect(p)).toEqual([]);
    }
  });
});
