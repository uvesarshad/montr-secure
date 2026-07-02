/**
 * Minimal, dependency-free semver comparison + range satisfaction — just enough
 * for offline CVE range matching (SCA agent, §5.2). Supports comparator ranges
 * (`>= > <= < =`), space-joined AND, `||` OR, and `^`/`~`/`x`/`*`. Prerelease
 * tags are ignored (coerced to their numeric core), which is the correct,
 * conservative behavior for advisory matching. NOT a full node-semver.
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
}

/** Extract the numeric x.y.z core from a version-ish string (e.g. "^4.17.11" → 4.17.11). */
export function coerce(version: string): SemVer | null {
  const m = version.trim().match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  return {
    major: Number(m[1] ?? "0"),
    minor: Number(m[2] ?? "0"),
    patch: Number(m[3] ?? "0"),
  };
}

/** -1 / 0 / 1 comparison of two SemVers. */
export function compare(a: SemVer, b: SemVer): number {
  return a.major - b.major || a.minor - b.minor || a.patch - b.patch;
}

/** Expand a single `^`/`~` token into two comparator tokens. */
function expandToken(tok: string): string {
  if (tok.startsWith("^")) {
    const s = coerce(tok.slice(1));
    if (!s) return tok;
    const upper =
      s.major > 0
        ? `<${s.major + 1}.0.0`
        : s.minor > 0
          ? `<0.${s.minor + 1}.0`
          : `<0.0.${s.patch + 1}`;
    return `>=${s.major}.${s.minor}.${s.patch} ${upper}`;
  }
  if (tok.startsWith("~")) {
    const s = coerce(tok.slice(1));
    if (!s) return tok;
    return `>=${s.major}.${s.minor}.${s.patch} <${s.major}.${s.minor + 1}.0`;
  }
  return tok;
}

function satisfiesComparator(v: SemVer, comparator: string): boolean {
  const c = comparator.trim();
  if (c === "" || c === "*" || c.toLowerCase() === "x") return true;
  const m = c.match(/^(>=|<=|>|<|=)?\s*(.+)$/);
  if (!m) return false;
  const op = m[1] ?? "=";
  const target = coerce(m[2] ?? "");
  if (!target) return false;
  const cmp = compare(v, target);
  switch (op) {
    case ">":
      return cmp > 0;
    case ">=":
      return cmp >= 0;
    case "<":
      return cmp < 0;
    case "<=":
      return cmp <= 0;
    default:
      return cmp === 0;
  }
}

function satisfiesGroup(v: SemVer, group: string): boolean {
  const trimmed = group.trim();
  if (trimmed === "" || trimmed === "*") return true;
  const comparators = trimmed.split(/\s+/).map(expandToken).join(" ").split(/\s+/).filter(Boolean);
  return comparators.every((c) => satisfiesComparator(v, c));
}

/** True if `version` satisfies the (possibly compound) `range`. */
export function satisfies(version: string, range: string): boolean {
  const v = coerce(version);
  if (!v) return false;
  const r = range.trim();
  if (r === "" || r === "*") return true;
  return r.split("||").some((group) => satisfiesGroup(v, group));
}
