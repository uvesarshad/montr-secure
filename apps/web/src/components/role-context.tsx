"use client";

import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { Role } from "@montr/contracts";
import { api } from "../lib/api/client.js";
import { qk } from "../lib/api/keys.js";
import type { CurrentUser } from "../lib/rbac.js";
import type { Actor } from "../lib/api/types.js";
import { ShieldIcon } from "./icons.js";
import { LoginGate } from "./login-gate.js";

interface RoleContextValue {
  currentUser: CurrentUser;
  actor: Actor;
  availableUsers: CurrentUser[];
  /** Dev role-switcher — pick the demo user for a role. */
  setRole: (role: Role) => void;
}

const RoleContext = React.createContext<RoleContextValue | null>(null);

function Splash({ label, tone = "muted" }: { label: string; tone?: "muted" | "danger" }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-3 bg-background text-center">
      <ShieldIcon className="h-8 w-8 text-primary" />
      <p className={tone === "danger" ? "text-sm text-red-300" : "text-sm text-muted-foreground"}>
        {label}
      </p>
    </div>
  );
}

export function RoleProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient();
  const { data, isLoading, isError } = useQuery({ queryKey: qk.session, queryFn: api.getSession });
  const [activeUserId, setActiveUserId] = React.useState<string | null>(null);

  const value = React.useMemo<RoleContextValue | null>(() => {
    if (!data) return null;
    const availableUsers = data.availableUsers.length > 0 ? data.availableUsers : [data.user];
    const currentUser = availableUsers.find((u) => u.id === activeUserId) ?? data.user;
    const setRole = (role: Role) => {
      const match = availableUsers.find((u) => u.role === role);
      if (match) setActiveUserId(match.id);
    };
    return {
      currentUser,
      actor: { id: currentUser.id, role: currentUser.role },
      availableUsers,
      setRole,
    };
  }, [data, activeUserId]);

  if (isLoading) return <Splash label="Loading session…" />;
  // No valid session (GET /auth/me came back 401, or the mock is unreachable)
  // — show the real login form. On success, re-fetch the session query so the
  // app renders normally with the now-authenticated user.
  if (isError || !value) {
    return <LoginGate onSuccess={() => void qc.invalidateQueries({ queryKey: qk.session })} />;
  }

  return <RoleContext.Provider value={value}>{children}</RoleContext.Provider>;
}

export function useRoleContext(): RoleContextValue {
  const ctx = React.useContext(RoleContext);
  if (!ctx) throw new Error("useRoleContext must be used within <RoleProvider>");
  return ctx;
}

export function useCurrentUser(): CurrentUser {
  return useRoleContext().currentUser;
}

export function useActor(): Actor {
  return useRoleContext().actor;
}
