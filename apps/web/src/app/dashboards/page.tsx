"use client";

import * as React from "react";
import { useCurrentUser } from "../../components/role-context.js";
import { PageHeader } from "../../components/page-header.js";
import { Card, CardContent } from "../../components/ui/card.js";
import { EmptyState } from "../../components/ui/empty-state.js";
import { BarChartIcon } from "../../components/icons.js";
import { ROLE_LABEL } from "../../lib/rbac.js";

/**
 * Phase-4 (Wave 5) — org-wide posture dashboards + cross-scan trend intelligence
 * (PRD §16). RBAC-scoped: read-only for every role, per-client isolated.
 *
 * ⛔ Headlines CONFIRMED findings by severity + posture delta over time — never
 *    raw candidate counts (golden rule, §12).
 *
 * STUB SEAM (WS-R fills): render posture-over-time (GET /analytics/trends) and
 * the org aggregate (GET /analytics/posture). This placeholder is intentionally
 * data-free so it builds against the empty stub endpoints.
 */
export default function DashboardsPage() {
  const user = useCurrentUser();
  return (
    <div>
      <PageHeader
        title="Posture Dashboards"
        description="Org-wide security posture and per-repo trends over time. Confirmed, prioritized findings — never raw counts."
      />
      <Card>
        <CardContent className="pt-5">
          <EmptyState
            icon={<BarChartIcon className="h-6 w-6" />}
            title="Trend dashboards arrive with Wave 5"
            description={`Signed in as ${ROLE_LABEL[user.role]}. Posture snapshots are recorded as scans complete; this view will chart confirmed-by-severity and regression deltas per repo.`}
          />
        </CardContent>
      </Card>
    </div>
  );
}
