"use client";

import * as React from "react";
import { useParams } from "next/navigation";
import { useScan } from "../../../lib/api/hooks.js";
import { ScanHeader } from "../../../components/scan-header.js";
import { ScanTabs } from "../../../components/scan-tabs.js";
import { LoadingCards, ErrorState } from "../../../components/states.js";

export default function ScanDetailLayout({ children }: { children: React.ReactNode }) {
  const params = useParams<{ scanId: string }>();
  const scanId = params.scanId;
  const { data: scan, isLoading, isError, error } = useScan(scanId);

  if (isLoading) return <LoadingCards />;
  if (isError || !scan) return <ErrorState error={error} message="Scan not found." />;

  return (
    <div>
      <ScanHeader scan={scan} />
      <ScanTabs scanId={scanId} />
      {children}
    </div>
  );
}
