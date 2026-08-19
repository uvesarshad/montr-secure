# Rendering and Client Architecture

Scope: Rendering strategies, client-side hydration, route segmentation, and caching across the web console.
Rendering context: Isomorphic
Project tier: 4
Last updated: auto

Overview
Montr Secure employs a hybrid rendering architecture. The operator console is built on Next.js 14 utilizing the App Router with a minimal server layout shell wrapping client-rendered interactive single-page application views. Dynamic data fetching, real-time scan progress polling, and state caching are delegated to TanStack React Query on the client, which communicates asynchronously with the Fastify REST backend.

Server versus Client Components
Root Layout Shell: apps/web/src/app/layout.tsx executes as a Server Component to output the root HTML document structure, document metadata, font declarations, and dark theme class attributes before mounting client providers.
Interactive Application Pages: All functional route entry points including apps/web/src/app/page.tsx and apps/web/src/app/scans/[scanId]/page.tsx are explicitly marked with the use client directive to support live state interaction, role context inspection, modal dialogs, and dynamic data polling.
UI Component Tree: Components in apps/web/src/components (such as FindingCard, LayerProgress, and CostPanel) operate client-side to reactively render vulnerability details, unified diffs, and proof viewers.

Route Segmentation and Layout Hierarchy
Root Route: apps/web/src/app/page.tsx renders the primary dashboard displaying active scans, repository filters, and trigger buttons.
Scan Detail Layout: apps/web/src/app/scans/[scanId]/layout.tsx is a nested client layout that fetches the parent scan entity and mounts the persistent ScanHeader and ScanTabs navigation bar across all sub-views.
Scan Sub-Views: Sub-routes under scans/[scanId] partition scan data into dedicated tabs including estimate, report, fixes, and dast.
Operational Feature Routes: Distinct top-level routes under apps/web/src/app provide dedicated consoles for pull-requests, audit, dashboards, dast, rules, scenarios, and schedules.

Data Fetching and Client Cache Strategy
Client API Client: apps/web/src/lib/api/client.ts issues standard fetch requests to the Fastify API with Bearer token authentication headers and credentials included.
React Query Cache: apps/web/src/lib/api/hooks.ts wraps API calls in useQuery hooks with unique query keys defined in apps/web/src/lib/api/keys.ts.
Polling Strategy: The useProgress hook polls the API at four-second intervals while a scan status is in the running or queued state, automatically stopping when the scan reaches a terminal or gate state.
Cache Invalidation: Mutations such as useApproveEstimate, useApproveFixGate, useAuthorizeDast, and useKillSwitch automatically invalidate associated query keys across scans, progress, and audit logs upon success.

Edge Runtime and Streaming
Edge Runtime: The application runs on standard Node.js runtimes (Node 20+) to support full compatibility with crypto, filesystem, and native dependencies. Edge runtime is not used.
Streaming: Report exports (SARIF, SOC2, ISO, OWASP) are generated in-memory on the Fastify API server and downloaded by the client as monolithic JSON documents.

Update Triggers
Update this file when Next.js routing patterns change, when new layouts or route segments are added to apps/web/src/app, or when client data fetching and caching strategies are modified.

Related Docs
docs/ui/layout-system.md — Detailed layout hierarchy and navigation structure.
docs/state/client-state.md — Client state management and React Query caching.
