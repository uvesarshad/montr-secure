import * as React from "react";
import { Skeleton } from "./ui/skeleton.js";
import { EmptyState } from "./ui/empty-state.js";
import { AlertTriangleIcon } from "./icons.js";
import { ApiError } from "../lib/api/client.js";

export function LoadingCards({ count = 3 }: { count?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: count }).map((_, i) => (
        <Skeleton key={i} className="h-24 w-full" />
      ))}
    </div>
  );
}

export function ErrorState({ error, message }: { error?: unknown; message?: string }) {
  const detail =
    message ??
    (error instanceof ApiError
      ? error.message
      : error instanceof Error
        ? error.message
        : "Something went wrong.");
  return (
    <EmptyState
      icon={<AlertTriangleIcon className="h-6 w-6 text-amber-300" />}
      title="Unable to load"
      description={detail}
    />
  );
}
