import * as React from "react";
import { cn } from "../lib/utils.js";

type LineKind = "add" | "del" | "hunk" | "file" | "meta" | "context";

function classify(line: string): LineKind {
  if (line.startsWith("+++") || line.startsWith("---")) return "file";
  if (line.startsWith("@@")) return "hunk";
  if (line.startsWith("diff ") || line.startsWith("index ")) return "meta";
  if (line.startsWith("+")) return "add";
  if (line.startsWith("-")) return "del";
  return "context";
}

const LINE_CLASS: Record<LineKind, string> = {
  add: "bg-emerald-500/10 text-emerald-200",
  del: "bg-red-500/10 text-red-200",
  hunk: "bg-sky-500/10 text-sky-300",
  file: "text-muted-foreground",
  meta: "text-muted-foreground",
  context: "text-foreground/90",
};

/** Renders a unified-diff patch with add/delete/hunk highlighting (§12.2 fix). */
export function DiffViewer({ patch, className }: { patch: string; className?: string }) {
  const lines = patch.replace(/\n+$/, "").split("\n");
  return (
    <div
      className={cn(
        "overflow-x-auto rounded-md border border-border bg-background/70 font-mono text-xs leading-relaxed",
        className,
      )}
    >
      <pre className="min-w-full">
        {lines.map((line, i) => {
          const kind = classify(line);
          return (
            <div key={i} className={cn("px-3", LINE_CLASS[kind])}>
              {line.length > 0 ? line : " "}
            </div>
          );
        })}
      </pre>
    </div>
  );
}
