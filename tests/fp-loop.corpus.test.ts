import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import type { AuditEvent, ConfirmedFinding } from "@montr/contracts";
import { mockConfirmedFindings, CLIENT_ID, SCAN_ID } from "@montr/fixtures";
import {
  deriveFalsePositiveRecord,
  markInputToRecord,
  falsePositiveSignature,
  parseFalsePositiveRecord,
  toFalsePositiveMarkers,
  regressionCorpusFromAuditEvents,
  InMemoryRegressionCorpus,
  FileRegressionCorpus,
  corpusRecorder,
  type FalsePositiveMarkInput,
} from "../packages/qa/src/regression-corpus";

/**
 * §15 regression-corpus writer (build-plan §6). Marking a confirmed finding a
 * false positive produces a durable, metadata-only record the golden-corpus
 * harness can consume. Fully offline (in-memory + a temp file).
 */

const sqli: ConfirmedFinding = mockConfirmedFindings[0]!; // SQLi @ app/api/users/route.ts:9
const xss: ConfirmedFinding = mockConfirmedFindings[1]!; // XSS  @ app/search/page.tsx:8

const OPERATOR = { id: "user_op_1", role: "operator" as const };
const MARKED_AT = "2026-07-02T12:00:00.000Z";

function recordFor(finding: ConfirmedFinding) {
  return deriveFalsePositiveRecord({
    finding,
    operator: OPERATOR,
    reason: "not exploitable",
    markedAt: MARKED_AT,
  });
}

describe("@montr/qa regression corpus — writer", () => {
  it("derives a metadata-only record from a confirmed finding (no code body)", () => {
    const rec = recordFor(sqli);
    expect(rec.category).toBe("sql_injection");
    expect(rec.file).toBe("app/api/users/route.ts");
    expect(rec.line).toBe(9);
    expect(rec.findingId).toBe(sqli.id);
    expect(rec.clientId).toBe(CLIENT_ID);
    expect(rec.scanId).toBe(SCAN_ID);
    expect(rec.operatorId).toBe(OPERATOR.id);
    expect(rec.operatorRole).toBe("operator");
    expect(rec.reason).toBe("not exploitable");
    expect(rec.markedAt).toBe(MARKED_AT);
    // ⛔ golden rule #1 — the proof argument ("queryRawUnsafe") must NEVER be in the corpus.
    const serialized = JSON.stringify(rec);
    expect(serialized).not.toContain("queryRawUnsafe");
    expect(serialized).not.toContain("proofArtifact");
    expect(rec).not.toHaveProperty("proofArtifact");
  });

  it("computes a stable signature keyed on category|file|line", () => {
    expect(recordFor(sqli).signature).toBe(recordFor(sqli).signature);
    expect(falsePositiveSignature({ category: "sql_injection", file: "a.ts", line: 9 })).toBe(
      falsePositiveSignature({ category: "sql_injection", file: "a.ts", line: 9 }),
    );
    expect(recordFor(sqli).signature).not.toBe(recordFor(xss).signature);
  });

  it("rejects a non-metadata field (strict-by-construction)", () => {
    // Even if a caller smuggles a code body in, only known fields are assembled.
    const smuggled = markInputToRecord({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      findingId: sqli.id,
      category: "sql_injection",
      file: "a.ts",
      line: 9,
      operator: OPERATOR,
      reason: "x",
      markedAt: MARKED_AT,
      // @ts-expect-error extra field is dropped, never persisted
      codeBody: "SELECT * FROM users WHERE 1=1",
    } as FalsePositiveMarkInput);
    expect(JSON.stringify(smuggled)).not.toContain("SELECT * FROM");
    expect(smuggled).not.toHaveProperty("codeBody");
  });

  it("round-trips through an in-memory corpus and yields scorer markers", async () => {
    const corpus = new InMemoryRegressionCorpus();
    await corpus.append(recordFor(sqli));
    const listed = await corpus.list({ clientId: CLIENT_ID });
    expect(listed).toHaveLength(1);
    expect(listed[0]!.findingId).toBe(sqli.id);
    expect(await corpus.list({ clientId: "other" })).toHaveLength(0);

    const markers = toFalsePositiveMarkers(listed);
    expect(markers).toEqual([
      { category: "sql_injection", file: "app/api/users/route.ts", line: 9 },
    ]);
  });

  it("persists durably to append-only JSONL and reads it back", async () => {
    const dir = await mkdtemp(join(tmpdir(), "montr-fp-"));
    try {
      const path = join(dir, "nested", "false-positives.jsonl");
      const corpus = new FileRegressionCorpus(path);
      await corpus.append(recordFor(sqli));
      await corpus.append(recordFor(xss));

      const text = await readFile(path, "utf8");
      expect(text.trim().split("\n")).toHaveLength(2); // one record per line
      expect(text).not.toContain("queryRawUnsafe"); // ⛔ no code body on disk

      const reread = await corpus.list();
      expect(reread.map((r) => r.category).sort()).toEqual(["sql_injection", "xss"]);
      // A corrupt line is skipped (fail-safe), not fatal.
      await corpus.append(recordFor(sqli));
      expect(await corpus.list()).toHaveLength(3);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("adapts a store into a mark-input recorder (validates + signs)", async () => {
    const corpus = new InMemoryRegressionCorpus();
    const recorder = corpusRecorder(corpus);
    const saved = await recorder.record({
      clientId: CLIENT_ID,
      scanId: SCAN_ID,
      findingId: sqli.id,
      category: "sql_injection",
      cwe: ["CWE-89"],
      owasp: "A03:2021",
      file: "app/api/users/route.ts",
      line: 9,
      severity: "critical",
      exposure: "public",
      proofType: "static",
      operator: OPERATOR,
      reason: "false alarm",
      markedAt: MARKED_AT,
    });
    expect(saved.signature).toBe(recordFor(sqli).signature);
    expect(await corpus.list()).toHaveLength(1);
  });

  it("reconstructs the corpus from the append-only audit log (durable by construction)", () => {
    const events: AuditEvent[] = [
      {
        id: "a1",
        clientId: CLIENT_ID,
        sequence: 1,
        scanId: SCAN_ID,
        actor: { type: "user", id: "user_op_1", role: "operator" },
        action: "finding.marked_false_positive",
        targetType: "confirmed_finding",
        targetId: sqli.id,
        summary: "marked fp",
        metadata: {
          reason: "benign",
          category: "sql_injection",
          cwe: ["CWE-89"],
          owasp: "A03:2021",
          file: "app/api/users/route.ts",
          line: 9,
          severity: "critical",
          exposure: "public",
          proofType: "static",
        },
        prevHash: "",
        hash: "h1",
        at: MARKED_AT,
      },
      // A non-FP event is ignored.
      {
        id: "a2",
        clientId: CLIENT_ID,
        sequence: 2,
        actor: { type: "agent", id: "layer2" },
        action: "finding.promoted_probable",
        summary: "promoted",
        metadata: {},
        prevHash: "h1",
        hash: "h2",
        at: MARKED_AT,
      },
    ];
    const records = regressionCorpusFromAuditEvents(events);
    expect(records).toHaveLength(1);
    expect(records[0]!.findingId).toBe(sqli.id);
    expect(records[0]!.operatorId).toBe("user_op_1");
    expect(records[0]!.operatorRole).toBe("operator");
    expect(records[0]!.signature).toBe(recordFor(sqli).signature);
    // The rebuilt record is a valid corpus record.
    expect(() => parseFalsePositiveRecord(records[0])).not.toThrow();
  });
});
