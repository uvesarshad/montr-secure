"use client";

import * as React from "react";
import { useParams } from "next/navigation";
import { useScan, useEstimate } from "../../../../lib/api/hooks.js";
import { EstimatePanel } from "../../../../components/estimate-panel.js";
import { LoadingCards, ErrorState } from "../../../../components/states.js";

export default function ScanEstimatePage() {
  const { scanId } = useParams<{ scanId: string }>();
  const { data: scan } = useScan(scanId);
  const { data: estimate, isLoading, isError, error } = useEstimate(scanId);

  if (isLoading || !scan) return <LoadingCards count={2} />;
  if (isError || !estimate) return <ErrorState error={error} message="No cost estimate yet." />;

  return (
    <div className="max-w-3xl">
      <EstimatePanel scan={scan} estimate={estimate} />
    </div>
  );
}
