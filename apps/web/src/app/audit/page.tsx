"use client";

import * as React from "react";
import { useAudit } from "../../lib/api/hooks.js";
import { PageHeader } from "../../components/page-header.js";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card.js";
import { AuditTable } from "../../components/audit-table.js";
import { StatusChip } from "../../components/chips.js";
import { LoadingCards, ErrorState } from "../../components/states.js";

export default function AuditPage() {
  const { data: events, isLoading, isError, error } = useAudit();

  return (
    <div>
      <PageHeader
        title="Audit Log"
        description="Append-only, hash-chained record of every action, LLM call (metadata only), code modification, and human approval (§8.5, §13)."
      />
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>Events</CardTitle>
          <StatusChip tone="success">Tamper-evident · hash-chained</StatusChip>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <LoadingCards />
          ) : isError ? (
            <ErrorState error={error} />
          ) : (
            <AuditTable events={events ?? []} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
