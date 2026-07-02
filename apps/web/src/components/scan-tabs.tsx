"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { Role } from "@montr/contracts";
import { useCurrentUser } from "./role-context.js";
import { cn } from "../lib/utils.js";

interface ScanTab {
  label: string;
  segment: string;
  roles: readonly Role[];
}

const TABS: readonly ScanTab[] = [
  { label: "Overview", segment: "", roles: ["operator", "approver", "viewer"] },
  { label: "Cost Estimate", segment: "estimate", roles: ["operator", "approver", "viewer"] },
  { label: "Report", segment: "report", roles: ["operator", "approver", "viewer"] },
  { label: "Fixes & PRs", segment: "fixes", roles: ["operator", "approver", "viewer"] },
  { label: "DAST", segment: "dast", roles: ["operator", "approver"] },
];

export function ScanTabs({ scanId }: { scanId: string }) {
  const pathname = usePathname();
  const user = useCurrentUser();
  const base = `/scans/${scanId}`;

  return (
    <div className="mb-6 flex flex-wrap gap-1 border-b border-border">
      {TABS.filter((t) => t.roles.includes(user.role)).map((tab) => {
        const href = tab.segment ? `${base}/${tab.segment}` : base;
        const active = tab.segment ? pathname.startsWith(href) : pathname === base;
        return (
          <Link
            key={tab.segment || "overview"}
            href={href}
            className={cn(
              "-mb-px border-b-2 px-3 py-2 text-sm transition-colors",
              active
                ? "border-primary font-medium text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {tab.label}
          </Link>
        );
      })}
    </div>
  );
}
