# UI Component Library

Scope: Inventory of shared UI primitives, domain components, props, and interaction patterns in the operator console.
Rendering context: Client
Project tier: 4
Last updated: auto

Overview
The Montr Secure operator console UI is constructed from reusable Radix-based UI primitives in apps/web/src/components/ui and domain-specific widgets in apps/web/src/components. All components execute client-side, using Tailwind CSS v4 design tokens and semantic color classes. Components follow accessible patterns with full keyboard navigation and dark-mode styling.

Base UI Primitives in apps/web/src/components/ui
Button: In apps/web/src/components/ui/button.tsx. Renders clickable interactive actions supporting variants default, destructive, outline, secondary, ghost, and link, and sizes default, sm, lg, and icon.
Badge: In apps/web/src/components/ui/badge.tsx. Displays status tags and labels supporting variants default, secondary, destructive, outline, sevCritical, sevHigh, sevMedium, sevLow, and sevInfo.
Card: In apps/web/src/components/ui/card.tsx. Compound component set (Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter) used to encapsulate panels and findings.
Dialog: In apps/web/src/components/ui/dialog.tsx. Accessible modal dialogs (Dialog, DialogTrigger, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogClose) built on Radix Dialog primitives.
DropdownMenu: In apps/web/src/components/ui/dropdown-menu.tsx. Contextual popup menus supporting menu items, separators, and checkbox selections.
Table: In apps/web/src/components/ui/table.tsx. Semantic table elements (Table, TableHeader, TableBody, TableRow, TableHead, TableCell) used across scan and audit listings.
Tabs: In apps/web/src/components/ui/tabs.tsx. Tabbed view switcher (Tabs, TabsList, TabsTrigger, TabsContent) built on Radix Tabs primitives.
EmptyState: In apps/web/src/components/ui/empty-state.tsx. Displays standardized empty placeholder views with title, description, icon, and optional action buttons.
Skeleton: In apps/web/src/components/ui/skeleton.tsx. Renders animated placeholder blocks during asynchronous data fetching.
Separator: In apps/web/src/components/ui/separator.tsx. Renders horizontal or vertical visual divider lines.

Domain Security Components in apps/web/src/components
FindingCard: In apps/web/src/components/finding-card.tsx. Displays a ConfirmedFinding entity, showing severity badges, CWE identifiers, OWASP classifications, exposure tags, root-cause locations, and actions to inspect proofs or view fixes.
ProofViewer: In apps/web/src/components/proof-viewer.tsx. Renders vulnerability evidence, visualizing static taint flow paths or live HTTP request and response transcripts.
DiffViewer: In apps/web/src/components/diff-viewer.tsx. Renders unified diff patches generated in Layer 4 with line additions, line deletions, and line numbers.
FixDetails: In apps/web/src/components/fix-details.tsx. Displays fix rationale, risk classification badges, proof-of-fix test code, and pull request navigation links.
CostPanel: In apps/web/src/components/cost-panel.tsx. Renders real-time token expenditure, dollar costs, model breakdown charts, and budget ceiling warnings.
EstimatePanel: In apps/web/src/components/estimate-panel.tsx. Displays pre-scan Layer 0 token estimates, layer-by-layer cost projections, and the estimate approval button.
LayerProgress: In apps/web/src/components/layer-progress.tsx. Displays a visual 6-stage stepper tracking execution progress across Layers 0 through 5 with active, pending, completed, or failed states.
DastPanel: In apps/web/src/components/dast-panel.tsx. Manages live dynamic security testing, displaying staging target selection, scope contract parameters, authorization controls, and probe logs.
KillSwitchButton: In apps/web/src/components/kill-switch-button.tsx. Renders a high-visibility emergency abort button with a confirmation dialog to halt active scans.
AuditTable: In apps/web/src/components/audit-table.tsx. Displays hash-chained audit events with sequence numbers, actors, actions, timestamps, and cryptographic chain validation status.
ComplianceTable: In apps/web/src/components/compliance-table.tsx. Displays compliance mapping matrices across SOC2, ISO27001, and OWASP Top 10 security controls.
AppMapSummary: In apps/web/src/components/app-map-summary.tsx. Renders detected application routes, data models, entry points, and taint surfaces extracted during Layer 0.
Chips: In apps/web/src/components/chips.tsx. Helper chip components including SeverityChip, StatusChip, RiskClassChip, GateStateChip, and ExposureChip.
States: In apps/web/src/components/states.tsx. Standardized loading and error state screens including LoadingCards, ErrorState, and EmptyCardState.

Component Composition and State Connections
Presentational Primitives: Components in apps/web/src/components/ui are strictly presentational and receive data and callbacks exclusively via React props.
Connected Domain Components: Components such as EstimatePanel, DastPanel, and KillSwitchButton subscribe directly to React Query mutations and role context hooks to perform authenticated actions.

Update Triggers
Update this file when a new component is added to apps/web/src/components or apps/web/src/components/ui, when component props change, or when existing components are removed or restructured.

Related Docs
docs/ui/layout-system.md — Layout structure and container wrappers.
docs/ui/theming.md — Color system, severity tokens, and typography.
