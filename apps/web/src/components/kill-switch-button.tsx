"use client";

import * as React from "react";
import { Button } from "./ui/button.js";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "./ui/dialog.js";
import { BanIcon } from "./icons.js";
import { useKillSwitch } from "../lib/api/hooks.js";
import { useCurrentUser } from "./role-context.js";
import { canActivateKillSwitch } from "../lib/rbac.js";

/** ⛔ Kill switch — halts all active work immediately, especially live DAST (§11). */
export function KillSwitchButton({ scanId }: { scanId: string }) {
  const user = useCurrentUser();
  const [open, setOpen] = React.useState(false);
  const [reason, setReason] = React.useState("");
  const mutation = useKillSwitch(scanId);

  if (!canActivateKillSwitch(user.role)) return null;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="destructive" size="sm">
          <BanIcon className="h-4 w-4" /> Kill switch
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Activate kill switch</DialogTitle>
          <DialogDescription>
            Immediately halts all active work for this scan (including any live DAST probing). This
            is recorded in the audit log.
          </DialogDescription>
        </DialogHeader>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={2}
          placeholder="Reason (recorded in the audit log)"
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
        {mutation.isError ? <p className="text-xs text-red-300">Failed to activate.</p> : null}
        <DialogFooter>
          <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            size="sm"
            disabled={mutation.isPending}
            onClick={() =>
              mutation.mutate(reason.trim() || "manual kill switch", {
                onSuccess: () => setOpen(false),
              })
            }
          >
            {mutation.isPending ? "Halting…" : "Halt now"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
