"use client";

import * as React from "react";
import { usePullRequests } from "../../lib/api/hooks.js";
import { PageHeader } from "../../components/page-header.js";
import { Card, CardContent } from "../../components/ui/card.js";
import { PrList } from "../../components/pr-list.js";
import { LoadingCards, ErrorState } from "../../components/states.js";

export default function PullRequestsPage() {
  const { data: pullRequests, isLoading, isError, error } = usePullRequests();

  return (
    <div>
      <PageHeader
        title="Pull Requests"
        description="Gated auto-fix PRs — opened only for auto-eligible fixes, never direct commits. Each is independently reviewable (§7 L5)."
      />
      <Card>
        <CardContent className="pt-5">
          {isLoading ? (
            <LoadingCards />
          ) : isError ? (
            <ErrorState error={error} />
          ) : (
            <PrList pullRequests={pullRequests ?? []} showScan />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
