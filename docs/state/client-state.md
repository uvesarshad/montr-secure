# Client-Side State Management

Scope: React Query caching, client role context, polling strategies, and component local state in the operator console.
Rendering context: Client
Project tier: 4
Last updated: auto

Overview
Client-side state across the Montr Secure operator console is managed through TanStack React Query in apps/web/src/lib/api/hooks.ts and a React context provider in apps/web/src/components/role-context.tsx. The application avoids heavy global state libraries, delegating server cache synchronization and automated refetching to React Query while managing local view interactions with standard React component hooks.

React Query Cache and Query Keys in apps/web/src/lib/api/keys.ts
Query Key Factory: Centralized query key definitions in apps/web/src/lib/api/keys.ts isolate cache segments across entities.
qk.scans: Manages the collection of all scans for the current client tenant.
qk.scan(scanId): Caches metadata, gate state, and status for an individual scan.
qk.progress(scanId): Caches real-time Layer 0 through 5 execution progress.
qk.appMap(scanId): Caches the structural application map and route graph.
qk.estimate(scanId): Caches pre-scan Layer 0 token and cost projections.
qk.report(scanId): Caches the finalized Layer 5 report and findings.
qk.fixes(scanId): Caches synthesized code patches and risk classifications.
qk.pullRequests and qk.scanPullRequests(scanId): Caches automated remediation pull requests.
qk.audit(scanId): Caches append-only audit event logs.

Data Queries and Polling Lifecycles in apps/web/src/lib/api/hooks.ts
useScans and useScan: Fetches scan collections and individual scan records.
useProgress: Fetches execution progress for an active scan. Supports a polling option that queries the backend at four-second intervals when scan status is queued or running, terminating automatically upon scan completion or failure.
useAppMap, useEstimate, useReport, and useFixes: On-demand query hooks loading layer artifacts when corresponding scan tabs are viewed.
useAudit: Queries audit log trails scoped to a specific scan or across the entire client tenant.

Mutation Handlers and Invalidation Rules
useApproveEstimate: Calls the estimate gate API endpoint and invalidates qk.scan, qk.scans, qk.progress, and qk.audit queries upon success.
useApproveFixGate: Calls the fix gate API endpoint and invalidates qk.scan, qk.report, and qk.audit queries.
useAuthorizeDast: Calls the live DAST authorization endpoint and invalidates qk.scan, qk.scans, and qk.audit queries.
useKillSwitch: Calls the emergency kill switch endpoint and immediately invalidates qk.scan, qk.scans, qk.progress, and qk.audit queries.
useMarkFalsePositive: Calls the false positive endpoint and invalidates qk.report and qk.audit queries.

Role Context and Actor State in apps/web/src/components/role-context.tsx
RoleProvider: Wraps the application tree in apps/web/src/components/providers.tsx, tracking the currently simulated user identity and role (operator, approver, viewer).
useRole and useActor: Custom hooks providing access to the current actor profile and testing permissions. Components inspect role capabilities using helper functions in apps/web/src/lib/rbac.ts.

Local Component State
Interactive Modals: Components such as KillSwitchButton and FindingCard use local React useState to control dialog open states, tab selections, and diff expansion toggles.

Update Triggers
Update this file when query hooks or mutation handlers are added to apps/web/src/lib/api/hooks.ts, when query keys change in apps/web/src/lib/api/keys.ts, or when role context patterns evolve in apps/web/src/components/role-context.tsx.

Related Docs
docs/architecture/rendering-strategy.md — Client rendering and hydration architecture.
docs/ui/component-library.md — Components consuming client query hooks and role state.
