import * as React from "react";
import { CATEGORY_TAXONOMY, type ComplianceMapping } from "@montr/contracts";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table.js";
import { Badge } from "./ui/badge.js";
import { EmptyState } from "./ui/empty-state.js";
import { ScrollIcon } from "./icons.js";

/** OWASP Top 10 / CWE mapping for every finding (§13). Drops into SOC2 / ISO
 * evidence collection. */
export function ComplianceTable({ mappings }: { mappings: ComplianceMapping[] }) {
  if (mappings.length === 0) {
    return <EmptyState icon={<ScrollIcon className="h-6 w-6" />} title="No compliance mappings" />;
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Category</TableHead>
          <TableHead>CWE</TableHead>
          <TableHead>OWASP Top 10 (2021)</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {mappings.map((m, i) => (
          <TableRow key={`${m.category}-${i}`}>
            <TableCell className="font-medium">{CATEGORY_TAXONOMY[m.category].title}</TableCell>
            <TableCell>
              <div className="flex flex-wrap gap-1">
                {m.cwe.length > 0 ? (
                  m.cwe.map((c) => (
                    <Badge key={c} className="border-border bg-secondary font-mono text-[11px]">
                      {c}
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs text-muted-foreground">—</span>
                )}
              </div>
            </TableCell>
            <TableCell>
              <span className="font-mono text-xs text-muted-foreground">{m.owasp}</span>{" "}
              {m.owaspTitle}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
