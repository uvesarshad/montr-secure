/**
 * JVM (Spring / JPA) confirmation-heuristics tests (Layer 3a stack breadth).
 *
 * The static-confirmation engine (`static.ts` / `taxonomy.ts`) is stack-agnostic;
 * these tests assert the Java plugin's EXTRA lexical hints make the JVM App-Map
 * sink notes confirmable, correctly demote a genuinely-parameterized JPA path, and
 * extract the request-parameter name — while ⛔ never bypassing the deterministic
 * proof (golden rules #4, #6). Sink descriptions are the exact strings the JVM
 * analyzer emits (`@montr/appmap` `languages/java/extract.ts`), so the two layers
 * stay in lock-step. Stays within the `@montr/confirm` package (no cross-package deps).
 */
import { describe, it, expect } from "vitest";
import type { TaintSink, TaintSinkKind } from "@montr/contracts";
import { assessSink, extractParam } from "../../taxonomy.js";
import { resolveHeuristics } from "../registry.js";
import { javaHeuristics } from "./index.js";

const javaApp = { languages: ["java"] as const };
const H = resolveHeuristics(javaApp);

function sink(kind: TaintSinkKind, description: string): TaintSink {
  return { kind, location: { file: "Controller.java", line: 1 }, description };
}

// The exact sink notes emitted by languages/java/extract.ts for the vuln corpus.
const SQLI = sink(
  "sql_query",
  "stmt.executeQuery(<string concatenation>) — raw SQL built by concatenation",
);
const CMDI = sink("command_exec", "Runtime.getRuntime().exec(...) runs an OS command");
const DESER = sink("deserialize", "ObjectInputStream.readObject() deserializes untrusted data");

describe("java confirm — heuristics registry", () => {
  it("resolves non-empty JVM markers + param patterns, and adds NO raw sink kinds", () => {
    expect(javaHeuristics.appliesTo(["java"])).toBe(true);
    expect(javaHeuristics.appliesTo(["python"])).toBe(false);
    expect(H.unsafeMarkers.length).toBeGreaterThan(0);
    expect(H.safeMarkers.length).toBeGreaterThan(0);
    expect(H.paramPatterns.length).toBeGreaterThan(0);
    // ⛔ fail-safe: the plugin adds no rawSinkKinds, so a bare `sql_query` with no
    // marker stays UNCONFIRMED rather than being auto-promoted.
    expect(H.rawSinkKinds).toHaveLength(0);
  });
});

describe("java confirm — confirms the corpus data-flow sinks", () => {
  it("marks the concatenated JDBC / Runtime.exec / readObject sinks dangerous", () => {
    for (const s of [SQLI, CMDI, DESER]) {
      expect(assessSink(s, H).dangerous).toBe(true);
    }
  });

  it("demotes a genuinely parameterized JPA query (setParameter) to sanitized", () => {
    const safe = sink("sql_query", "createQuery(...) bound via setParameter — no concatenation");
    const a = assessSink(safe, H);
    expect(a.dangerous).toBe(false);
    expect(a.sanitizer).toBe("setparameter");
  });

  it("⛔ leaves a bare sql_query with no marker UNCONFIRMED (fail-safe)", () => {
    // No concat / raw-sql / native-query marker, and sql_query is not a raw kind.
    expect(assessSink(sink("sql_query", "executeQuery(sqlText)"), H).dangerous).toBe(false);
  });
});

describe("java confirm — extracts the request parameter name", () => {
  it("reads the Spring annotation + HttpServletRequest getter forms", () => {
    expect(extractParam("@RequestParam q", H)).toBe("q");
    expect(extractParam("@PathVariable userId", H)).toBe("userId");
    expect(extractParam("@RequestBody dto", H)).toBe("dto");
    expect(extractParam('getParameter("id")', H)).toBe("id");
    expect(extractParam('getHeader("X_Api_Key")', H)).toBe("X_Api_Key");
  });

  it("needs the JVM patterns — the stack-agnostic base alone cannot read @RequestParam", () => {
    // With no extras (base patterns only) the Spring annotation form is unmatched.
    expect(extractParam("@RequestParam q")).toBeUndefined();
  });
});

describe("java confirm — ⛔ safety invariants (never mis-demote a dangerous sink)", () => {
  // Base SAFE-marker stems (taxonomy.ts SAFE_MARKERS). No JVM unsafe marker may
  // contain one, or a dangerous JVM sink note could be read as sanitized.
  const BASE_SAFE_STEMS = [
    "parameteri",
    "prepared",
    "sanitis",
    "sanitiz",
    "escap",
    "validate",
    "allowlist",
    "whitelist",
    "encoded",
    "dompurify",
    "findmany",
    "findunique",
    "findfirst",
    "where:",
    "placeholder",
    "bound param",
  ];

  it("no JVM unsafe marker collides with a base safe-marker stem", () => {
    for (const marker of javaHeuristics.unsafeMarkers ?? []) {
      for (const stem of BASE_SAFE_STEMS) {
        expect(marker.toLowerCase().includes(stem)).toBe(false);
      }
    }
  });

  it("every JVM safe marker demotes a sink on its own", () => {
    for (const marker of javaHeuristics.safeMarkers ?? []) {
      expect(assessSink(sink("sql_query", marker), H).dangerous).toBe(false);
    }
  });

  it("the corpus sink notes carry no base safe substring (so they always confirm)", () => {
    for (const s of [SQLI, CMDI, DESER]) {
      const d = (s.description ?? "").toLowerCase();
      for (const stem of BASE_SAFE_STEMS) expect(d.includes(stem)).toBe(false);
    }
  });
});
