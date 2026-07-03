/**
 * Next.js config for the Montr Secure operator console (App Router).
 *
 * Type-safety and lint are enforced authoritatively by the monorepo gates
 * (`tsc -b` + root ESLint), so we do not double-run them inside `next build`
 * (Next's embedded checks assume a Next-specific tsconfig, which conflicts with
 * this package's composite project-reference setup). `standalone` output matches
 * the distroless runtime image (deploy/docker/Dockerfile.web, owned by WS-O).
 *
 * The codebase uses TypeScript's `moduleResolution: "bundler"` convention of
 * writing `.js` extensions on relative imports that resolve to `.ts`/`.tsx`
 * sources. `tsc` handles that natively. Turbopack (the Next 16 default) has no
 * `.js`→`.ts` extension-alias knob, so `next dev`/`build` are pinned to
 * `--webpack` (see package.json) where `resolve.extensionAlias` below makes the
 * bundler try the TS extensions for a `.js` specifier. Without this, the bundler
 * cannot resolve any of the app's internal modules.
 */
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  typescript: { ignoreBuildErrors: true },
  webpack: (config) => {
    config.resolve.extensionAlias = {
      ...config.resolve.extensionAlias,
      ".js": [".ts", ".tsx", ".js", ".jsx"],
      ".jsx": [".tsx", ".jsx"],
      ".mjs": [".mts", ".mjs"],
    };
    return config;
  },
};

export default nextConfig;
