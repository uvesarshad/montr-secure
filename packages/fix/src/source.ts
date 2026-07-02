/**
 * Source access for Layer 4. The fix generator never assumes a filesystem — the
 * caller injects a {@link SourceReader} (the sandboxed workspace in production,
 * an in-memory map or the fixture repo in tests). This keeps the package pure
 * and fully offline-testable.
 */
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

export interface SourceReader {
  /** Returns the file's text, or `null` if it does not exist / cannot be read. */
  read(filePath: string): Promise<string | null>;
}

/**
 * Reads repo-relative POSIX paths from a root directory on disk. Refuses to read
 * outside the root (path-traversal guard) — a defensive default for the sandbox.
 */
export function createFsSourceReader(root: string): SourceReader {
  const base = resolve(root);
  return {
    async read(filePath: string): Promise<string | null> {
      const target = resolve(base, filePath);
      if (target !== base && !target.startsWith(base + sep)) return null;
      try {
        return await readFile(target, "utf8");
      } catch {
        return null;
      }
    },
  };
}

/** In-memory reader — for tests, or when the source is already loaded in RAM. */
export function createMapSourceReader(
  files: Record<string, string> | Map<string, string>,
): SourceReader {
  const map = files instanceof Map ? files : new Map(Object.entries(files));
  return {
    read: (filePath: string): Promise<string | null> => Promise.resolve(map.get(filePath) ?? null),
  };
}
