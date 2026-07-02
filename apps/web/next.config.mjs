/**
 * Next.js config for the Montr Secure operator console (App Router).
 *
 * Type-safety and lint are enforced authoritatively by the monorepo gates
 * (`tsc -b` + root ESLint), so we do not double-run them inside `next build`
 * (Next's embedded checks assume a Next-specific tsconfig, which conflicts with
 * this package's composite project-reference setup). `standalone` output matches
 * the distroless runtime image (deploy/docker/Dockerfile.web, owned by WS-O).
 */
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  typescript: { ignoreBuildErrors: true },
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
