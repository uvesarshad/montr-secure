# Theming and Design Tokens

Scope: Design tokens, semantic color schemes, severity palettes, typography, and dark-mode styling rules.
Rendering context: Client
Project tier: 4
Last updated: auto

Overview
Montr Secure implements a dark-first design system tailored for security operations center environments. Styling is managed using Tailwind CSS v4 in apps/web/src/styles/globals.css, mapping HSL color definitions into semantic CSS variables and design tokens. Standardized color scales clearly distinguish security finding severities, risk classes, and execution statuses.

Color Palette and Semantic Tokens
Background: CSS variable background defined as deep dark slate (HSL 222, 47 percent, 6 percent) providing high contrast for data visualization.
Card and Surface: CSS variables card and popover defined as dark slate (HSL 222, 44 percent, 9 percent) with subtle border dividers (HSL 217, 33 percent, 20 percent).
Foreground and Text: CSS variable foreground defined as off-white (HSL 210, 40 percent, 96 percent) and muted-foreground defined as medium slate (HSL 215, 20 percent, 65 percent).
Primary Accent: CSS variable primary defined as vibrant cyan (HSL 199, 89 percent, 55 percent) used for active indicators, primary buttons, and focus rings.
Destructive Action: CSS variable destructive defined as clear red (HSL 0, 72 percent, 51 percent) used for kill switch actions, scan cancellation, and deletions.

Security Severity Color Scale
Critical Severity: CSS variable sev-critical defined as vibrant red (HSL 0, 72 percent, 58 percent) applied to remote code execution, SQL injection, and high-impact vulnerabilities.
High Severity: CSS variable sev-high defined as deep orange (HSL 22, 90 percent, 58 percent) applied to broken authentication, SSRF, and sensitive data exposures.
Medium Severity: CSS variable sev-medium defined as amber (HSL 38, 92 percent, 55 percent) applied to cross-site scripting, path traversal, and missing rate limits.
Low Severity: CSS variable sev-low defined as bright cyan (HSL 199, 89 percent, 55 percent) applied to permissive CORS, missing security headers, and info disclosures.
Informational Severity: CSS variable sev-info defined as muted slate (HSL 215, 20 percent, 65 percent) applied to general audit notes and low-priority findings.

Typography and Spacing Scale
Font Families: Body text uses modern system sans-serif font stack configured as font-sans. Code snippets, file paths, diff viewers, and proof artifacts use font-mono (JetBrains Mono, SFMono-Regular, Menlo, Consolas).
Corner Radius: Standard radius tokens configured as radius-sm (0.375rem), radius-md (0.5rem), and radius-lg (0.75rem) applied to cards, dialogs, and button elements.
Scrollbars: Custom thin scrollbars styled directly in globals.css using the border color token with transparent tracks to maintain visual consistency across dense data views.

Update Triggers
Update this file when CSS variables or theme tokens change in apps/web/src/styles/globals.css, when severity color mappings are adjusted, or when font scale definitions evolve.

Related Docs
docs/ui/component-library.md — Component implementations utilizing theme tokens.
docs/ui/layout-system.md — Global styling application across layout hierarchies.
