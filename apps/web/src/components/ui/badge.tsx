import * as React from "react";
import { cn } from "../../lib/utils.js";

/**
 * Minimal badge/chip. Tone is applied by the caller via `className` (see
 * lib/format.ts `toneClasses` / severity chips) so this stays presentation-only.
 */
export function Badge({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        className,
      )}
      {...props}
    />
  );
}
