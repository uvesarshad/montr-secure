"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { navForRole, ROLE_LABEL, ROLE_DESCRIPTION } from "../lib/rbac.js";
import { api } from "../lib/api/client.js";
import { qk } from "../lib/api/keys.js";
import { useRoleContext } from "./role-context.js";
import { NAV_ICONS, ShieldIcon, UserIcon, ChevronDownIcon } from "./icons.js";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu.js";
import { StatusChip } from "./chips.js";
import { cn } from "../lib/utils.js";
import type { Role } from "@montr/contracts";

function isActive(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}

function Brand() {
  return (
    <Link href="/" className="flex items-center gap-2 px-2 py-1">
      <ShieldIcon className="h-6 w-6 text-primary" />
      <div className="leading-tight">
        <p className="text-sm font-semibold">Montr Secure</p>
        <p className="text-[11px] text-muted-foreground">Operator console</p>
      </div>
    </Link>
  );
}

function NavLinks({ role, onNavigate }: { role: Role; onNavigate?: () => void }) {
  const pathname = usePathname();
  const items = navForRole(role);
  return (
    <nav className="flex flex-col gap-1">
      {items.map((item) => {
        const Icon = NAV_ICONS[item.icon];
        const active = isActive(pathname, item.href);
        return (
          <Link
            key={item.id}
            href={item.href}
            onClick={onNavigate}
            className={cn(
              "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
              active
                ? "bg-primary/10 font-medium text-primary"
                : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
            )}
          >
            <Icon className="h-4 w-4" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

function RoleSwitcher() {
  const { currentUser, availableUsers, setRole } = useRoleContext();
  const qc = useQueryClient();

  async function handleLogout() {
    try {
      await api.logout();
    } finally {
      // Session cookie is cleared server-side regardless of outcome (logout
      // never fails on a missing/expired credential — see auth.ts); always
      // drop the client-side session cache so RoleProvider re-prompts to log in.
      void qc.invalidateQueries({ queryKey: qk.session });
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="flex items-center gap-2 rounded-md border border-border bg-card px-3 py-1.5 text-sm hover:bg-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-ring">
        <UserIcon className="h-4 w-4 text-muted-foreground" />
        <span className="hidden sm:inline">{currentUser.name}</span>
        <StatusChip tone="info">{ROLE_LABEL[currentUser.role]}</StatusChip>
        <ChevronDownIcon className="h-4 w-4 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuLabel>Signed in as {currentUser.email}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {availableUsers.length > 1 ? (
          <>
            <DropdownMenuLabel>Switch role (demo)</DropdownMenuLabel>
            <DropdownMenuRadioGroup
              value={currentUser.role}
              onValueChange={(v) => setRole(v as Role)}
            >
              {availableUsers.map((user) => (
                <DropdownMenuRadioItem key={user.id} value={user.role}>
                  <div>
                    <p className="font-medium">{ROLE_LABEL[user.role]}</p>
                    <p className="text-xs text-muted-foreground">{ROLE_DESCRIPTION[user.role]}</p>
                  </div>
                </DropdownMenuRadioItem>
              ))}
            </DropdownMenuRadioGroup>
            <DropdownMenuSeparator />
          </>
        ) : null}
        <button
          type="button"
          onClick={() => void handleLogout()}
          className="w-full rounded-sm px-2 py-1.5 text-left text-sm hover:bg-accent"
        >
          Log out
        </button>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const { currentUser } = useRoleContext();
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col gap-4 border-r border-border bg-card/40 p-3 md:flex">
        <Brand />
        <NavLinks role={currentUser.role} />
        <div className="mt-auto rounded-md border border-border bg-background/50 p-3 text-xs text-muted-foreground">
          <p className="font-medium text-foreground">Mock API active</p>
          <p>UI runs against MSW until apps/api is wired.</p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center justify-between gap-3 border-b border-border bg-background/80 px-4 py-3 backdrop-blur">
          <div className="md:hidden">
            <Brand />
          </div>
          <div className="ml-auto">
            <RoleSwitcher />
          </div>
        </header>

        <div className="border-b border-border px-4 py-2 md:hidden">
          <NavLinks role={currentUser.role} />
        </div>

        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6">{children}</main>
      </div>
    </div>
  );
}
