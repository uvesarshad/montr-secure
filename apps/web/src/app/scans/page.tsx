"use client";

import * as React from "react";
import { useScans } from "../../lib/api/hooks.js";
import { useCurrentUser } from "../../components/role-context.js";
import { PageHeader } from "../../components/page-header.js";
import { Card, CardContent } from "../../components/ui/card.js";
import { Button } from "../../components/ui/button.js";
import { ScanTable } from "../../components/scan-table.js";
import { LoadingCards, ErrorState } from "../../components/states.js";
import { EmptyState } from "../../components/ui/empty-state.js";
import { ListIcon } from "../../components/icons.js";
import { canCreateScan } from "../../lib/rbac.js";

export default function ScansPage() {
  const { data: scans, isLoading, isError, error } = useScans();
  const user = useCurrentUser();

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Every scan and its current pipeline gate."
        actions={
          canCreateScan(user.role) ? (
            <Button size="sm" disabled title="Scan creation is wired with apps/api">
              New scan
            </Button>
          ) : null
        }
      />
      <Card>
        <CardContent className="pt-5">
          {isLoading ? (
            <LoadingCards />
          ) : isError ? (
            <ErrorState error={error} />
          ) : !scans || scans.length === 0 ? (
            <EmptyState icon={<ListIcon className="h-6 w-6" />} title="No scans yet" />
          ) : (
            <ScanTable scans={scans} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
