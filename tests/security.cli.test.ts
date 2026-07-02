import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { describe, it, expect } from "vitest";
import type { AuditEvent } from "@montr/contracts";
import { hashAuditEvent } from "@montr/state-store";
import { run } from "../packages/security/src/audit-verify-cli";
import { SEC_EXIT } from "../packages/security/src/exit-codes";

/**
 * WS-N audit-verify CLI exit-code contract (build-plan §4.8). `run()` returns the
 * exit code instead of calling process.exit so CI gating is testable. A broken
 * chain MUST exit non-zero (golden rule #7).
 */

function makeChain(clientId: string, n: number): AuditEvent[] {
  const events: AuditEvent[] = [];
  let prev = "";
  for (let i = 1; i <= n; i++) {
    const draft: AuditEvent = {
      id: `${clientId}-${i}`,
      clientId,
      sequence: i,
      actor: { type: "system", id: "sys" },
      action: "scan.created",
      summary: `event ${i}`,
      metadata: {},
      prevHash: prev,
      hash: "",
      at: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
    };
    const hash = hashAuditEvent(draft, prev);
    events.push({ ...draft, hash });
    prev = hash;
  }
  return events;
}

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out: (s: string) => out.push(s),
    err: (s: string) => err.push(s),
    outText: () => out.join("\n"),
    errText: () => err.join("\n"),
  };
}

const dir = mkdtempSync(join(tmpdir(), "montr-sec-cli-"));

function writeExport(name: string, events: AuditEvent[]): string {
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify({ clientId: events[0]?.clientId, events }));
  return p;
}

describe("montr-audit-verify CLI", () => {
  it("exits 0 (OK) for an intact chain and prints a metadata-only report", async () => {
    const path = writeExport("valid.json", makeChain("c1", 3));
    const io = capture();
    const code = await run(["--file", path], io.out, io.err);
    expect(code).toBe(SEC_EXIT.OK);
    expect(io.outText()).toContain("OK (intact)");
    // never prints hashes or metadata bodies
    expect(io.outText()).not.toMatch(/[a-f0-9]{64}/);
  });

  it("exits 1 (CHAIN_BROKEN) for a tampered chain", async () => {
    const chain = makeChain("c1", 3);
    const tampered = chain.map((e, i) => (i === 1 ? { ...e, summary: "HACKED" } : e));
    const path = writeExport("tampered.json", tampered);
    const io = capture();
    const code = await run(["--file", path], io.out, io.err);
    expect(code).toBe(SEC_EXIT.CHAIN_BROKEN);
    expect(io.outText()).toContain("TAMPER DETECTED");
  });

  it("emits machine-readable JSON with --json", async () => {
    const path = writeExport("valid2.json", makeChain("c1", 2));
    const io = capture();
    const code = await run(["--file", path, "--json"], io.out, io.err);
    expect(code).toBe(SEC_EXIT.OK);
    expect(JSON.parse(io.outText())).toMatchObject({ ok: true, totalEvents: 2 });
  });

  it("reads the export from stdin when no --file is given", async () => {
    const io = capture();
    const stream = Readable.from([JSON.stringify(makeChain("c1", 2))]);
    const code = await run([], io.out, io.err, stream);
    expect(code).toBe(SEC_EXIT.OK);
  });

  it("filters by --client", async () => {
    const path = writeExport("multi.json", [...makeChain("a", 2), ...makeChain("b", 2)]);
    const io = capture();
    const code = await run(["--file", path, "--client", "a", "--json"], io.out, io.err);
    expect(code).toBe(SEC_EXIT.OK);
    expect(JSON.parse(io.outText()).clients).toHaveLength(1);
  });

  it("exits 0 and prints usage for --help", async () => {
    const io = capture();
    const code = await run(["--help"], io.out, io.err);
    expect(code).toBe(SEC_EXIT.OK);
    expect(io.outText()).toContain("montr-audit-verify");
  });

  it("exits 2 (USAGE) on an unknown flag", async () => {
    const io = capture();
    expect(await run(["--bogus"], io.out, io.err)).toBe(SEC_EXIT.USAGE);
  });

  it("exits 2 (USAGE) for an unsupported flag (e.g. --db)", async () => {
    const io = capture();
    expect(await run(["--db", "postgres://x/y"], io.out, io.err)).toBe(SEC_EXIT.USAGE);
  });

  it("exits 3 (INPUT_ERROR) for a missing file", async () => {
    const io = capture();
    expect(await run(["--file", join(dir, "nope.json")], io.out, io.err)).toBe(
      SEC_EXIT.INPUT_ERROR,
    );
  });

  it("exits 3 (INPUT_ERROR) for malformed JSON", async () => {
    const p = join(dir, "bad.json");
    writeFileSync(p, "{not json");
    const io = capture();
    expect(await run(["--file", p], io.out, io.err)).toBe(SEC_EXIT.INPUT_ERROR);
  });
});
