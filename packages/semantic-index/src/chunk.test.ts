/**
 * AST chunker (E5) — exercised against a real fixture repo written to a temp
 * dir (mirrors fix/src/patch.ts's `mkdtemp` workspace convention), parsed by
 * the ACTUAL ts-morph/web-tree-sitter engines via @montr/appmap's loaders —
 * no mocking of the parsers themselves.
 */
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chunkJavaSource, chunkPythonSource, chunkRepo } from "./chunk.js";

const TS_SOURCE = `
export function getUser(id: string) {
  return db.user.findUnique({ where: { id } });
}

export const deleteUser = async (id: string) => {
  await db.user.delete({ where: { id } });
};

export class UserService {
  async getById(id: string) {
    return db.user.findUnique({ where: { id } });
  }

  async remove(id: string) {
    await db.user.delete({ where: { id } });
  }
}

// A trivial one-line class with no methods — should still get a chunk.
export class UserId {
  value = "";
}
`;

const PY_SOURCE = `
def get_user(user_id):
    return User.objects.get(id=user_id)


def delete_user(user_id):
    User.objects.filter(id=user_id).delete()


class UserRepo:
    def get(self, user_id):
        return User.objects.get(id=user_id)

    def remove(self, user_id):
        User.objects.filter(id=user_id).delete()
`;

const JAVA_SOURCE = `
package com.example;

public class UserController {
    public User getUser(String id) {
        return userRepository.findById(id);
    }

    public void deleteUser(String id) {
        userRepository.deleteById(id);
    }
}
`;

describe("chunkPythonSource", () => {
  it("chunks module-level functions and class methods, skipping the class itself when it has methods", async () => {
    const chunks = await chunkPythonSource("app/users.py", PY_SOURCE);
    const names = chunks.map((c) => c.symbolName).sort();

    expect(names).toEqual(["get", "get_user", "remove", "delete_user"].sort());
    for (const c of chunks) {
      expect(c.language).toBe("python");
      expect(c.contentHash).toMatch(/^[0-9a-f]{64}$/);
    }
    // Python's grammar has one node type for both module-level functions and
    // methods (`function_definition`) — chunkPythonSource labels all of them
    // "function" kind (documented in chunk.ts's module doc comment).
    expect(chunks.every((c) => c.kind === "function")).toBe(true);
    const get = chunks.find((c) => c.symbolName === "get");
    expect(get).toBeDefined();
    expect(get?.content).toContain("User.objects.get");
  });
});

describe("chunkJavaSource", () => {
  it("chunks methods and skips the enclosing class (it has methods)", async () => {
    const chunks = await chunkJavaSource("com/example/UserController.java", JAVA_SOURCE);
    const names = chunks.map((c) => c.symbolName).sort();
    expect(names).toEqual(["deleteUser", "getUser"]);
    expect(chunks.every((c) => c.kind === "method")).toBe(true);
    expect(chunks.every((c) => c.language === "java")).toBe(true);
  });
});

describe("chunkRepo — real fixture repo (temp dir, real parsers)", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "semantic-index-fixture-"));
    await mkdir(join(dir, "src"), { recursive: true });
    await mkdir(join(dir, "app"), { recursive: true });
    await mkdir(join(dir, "com", "example"), { recursive: true });
    await writeFile(join(dir, "src", "users.ts"), TS_SOURCE, "utf8");
    await writeFile(join(dir, "app", "users.py"), PY_SOURCE, "utf8");
    await writeFile(join(dir, "com", "example", "UserController.java"), JAVA_SOURCE, "utf8");
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("scans all three languages and produces one chunk per function/method, plus the no-method class", async () => {
    const result = await chunkRepo(dir);

    expect(result.filesScanned).toBe(3);
    const byLanguage = (lang: string) => result.chunks.filter((c) => c.language === lang);

    // TypeScript: getUser, deleteUser, getById, remove (function-like units) + UserId (no-method class).
    const ts = byLanguage("typescript");
    expect(ts.map((c) => c.symbolName).sort()).toEqual(
      ["getUser", "deleteUser", "getById", "remove", "UserId"].sort(),
    );
    expect(ts.find((c) => c.symbolName === "UserId")?.kind).toBe("class");
    expect(ts.find((c) => c.symbolName === "getUser")?.kind).toBe("function");
    expect(ts.find((c) => c.symbolName === "getById")?.kind).toBe("method");

    const py = byLanguage("python");
    expect(py.length).toBe(4); // get_user, delete_user, get, remove (UserRepo itself has methods, skipped)

    const java = byLanguage("java");
    expect(java.length).toBe(2);

    // Every chunk carries a plausible line range and a real content hash.
    for (const c of result.chunks) {
      expect(c.startLine).toBeGreaterThan(0);
      expect(c.endLine).toBeGreaterThanOrEqual(c.startLine);
      expect(c.content.length).toBeGreaterThan(0);
      expect(c.contentHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("is deterministic: chunking the same repo twice yields identical content hashes", async () => {
    const first = await chunkRepo(dir);
    const second = await chunkRepo(dir);
    const hashesOf = (r: typeof first) => r.chunks.map((c) => c.contentHash).sort();
    expect(hashesOf(first)).toEqual(hashesOf(second));
  });
});
