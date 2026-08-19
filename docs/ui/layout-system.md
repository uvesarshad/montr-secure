# UI Layout System

Scope: Layout hierarchy, application shell structure, nested navigation chrome, and view routing.
Rendering context: Isomorphic
Project tier: 4
Last updated: auto

Overview
The Montr Secure web console utilizes a nested layout hierarchy to provide persistent navigation chrome, global session context, and scan-level tabbed navigation. The root server layout establishes HTML document constraints and global CSS providers, while client-side layout shells encapsulate page views with consistent headers, role switchers, breadcrumbs, and real-time scan headers.

Layout Hierarchy
Root Server Layout: Defined in apps/web/src/app/layout.tsx. Acts as the top-level HTML document wrapper. It configures the dark color scheme, imports global styles from apps/web/src/styles/globals.css, and mounts the Providers component and AppShell around all child pages.
Application Shell Layout: Defined in apps/web/src/components/app-shell.tsx. Client-side shell that provides the primary navigation header, company branding, navigation links to Scans, Pull Requests, DAST, Audit, Rules, Scenarios, Schedules, and Dashboards, tenant client badge, and the interactive RoleSelector widget.
Scan Detail Layout: Defined in apps/web/src/app/scans/[scanId]/layout.tsx. A nested client layout wrapping all route views scoped to a specific scan ID. It extracts the scanId URL parameter, executes the useScan hook to load scan metadata, and mounts the persistent ScanHeader and ScanTabs components above child views.

Navigation Chrome and Scan Sub-Views
Scan Header: Mounted by ScanDetailLayout via apps/web/src/components/scan-header.tsx. Displays the target repository, branch name, commit SHA, real-time status badge, gate state badge, and runtime duration counters.
Scan Navigation Tabs: Mounted via apps/web/src/components/scan-tabs.tsx. Renders horizontal navigation tabs switching between Overview (scans/[scanId]), Estimate (scans/[scanId]/estimate), Report (scans/[scanId]/report), Fixes (scans/[scanId]/fixes), and DAST (scans/[scanId]/dast).
Feature Views: Independent top-level routes under apps/web/src/app (such as audit, dast, rules, scenarios, and schedules) render within the primary AppShell with dedicated page headers and action bars.

Layout-Level Data Fetching and State Guards
Provider Hierarchy: apps/web/src/components/providers.tsx mounts the TanStack QueryClientProvider and the RoleProvider, establishing client-side caching and role state for all descendant components.
Scan Detail Data Guard: ScanDetailLayout monitors the loading and error states of the parent scan query. If the query is pending, it displays LoadingCards; if the query errors or returns not found, it renders ErrorState, preventing broken sub-views.

Update Triggers
Update this file when top-level or nested layout files are added, modified, or removed in apps/web/src/app, or when navigation chrome in apps/web/src/components/app-shell.tsx is updated.

Related Docs
docs/architecture/rendering-strategy.md — Server and client rendering lifecycle across routes.
docs/ui/component-library.md — Navigation and domain components used within layouts.
