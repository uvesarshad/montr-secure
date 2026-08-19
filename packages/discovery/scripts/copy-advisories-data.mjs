#!/usr/bin/env node
/**
 * Post-build step: `tsc -b` only emits compiled JS/d.ts for `.ts` sources, so
 * the static advisory mirror (`src/advisories-data/*.json`) needs an explicit
 * copy into `dist/advisories-data/` — that's where `advisories.ts`'s
 * `readFileSync(new URL('./advisories-data/...', import.meta.url))` looks for
 * it at runtime (relative to the COMPILED module's own location). Run after
 * `tsc -b` (see the `build` script in package.json); `pnpm test` runs against
 * `src/` directly via vitest, so it never needs this step.
 */
import { cp, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const src = path.join(root, "src", "advisories-data");
const dest = path.join(root, "dist", "advisories-data");

await mkdir(dest, { recursive: true });
await cp(src, dest, { recursive: true });
console.log(`Copied ${src} -> ${dest}`);
