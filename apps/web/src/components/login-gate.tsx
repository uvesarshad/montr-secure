"use client";

import * as React from "react";
import { api, ApiError } from "../lib/api/client.js";
import { ShieldIcon } from "./icons.js";

/**
 * Real-auth login form. Rendered by RoleProvider whenever GET /auth/me fails
 * (no valid session cookie yet) — the console has no separate `/login` route
 * so this works no matter which page a signed-out visitor lands on. Talks
 * directly to POST /auth/login (apps/api/src/routes/auth.ts), which sets the
 * httpOnly session cookie + JS-readable CSRF cookie on success; `onSuccess`
 * re-fetches the session query so the app renders normally afterward.
 */
export function LoginGate({ onSuccess }: { onSuccess: () => void }) {
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [pending, setPending] = React.useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setPending(true);
    try {
      await api.login(email, password);
      onSuccess();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "Could not reach the API. Try again.";
      setError(message);
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 bg-background px-4 text-center">
      <div className="flex flex-col items-center gap-2">
        <ShieldIcon className="h-8 w-8 text-primary" />
        <p className="text-sm font-semibold">Montr Secure</p>
        <p className="text-xs text-muted-foreground">Sign in to the operator console</p>
      </div>

      <form onSubmit={handleSubmit} className="w-full max-w-xs space-y-3 text-left">
        <div className="space-y-1">
          <label htmlFor="login-email" className="text-xs text-muted-foreground">
            Email
          </label>
          <input
            id="login-email"
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-md border border-border bg-card px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        <div className="space-y-1">
          <label htmlFor="login-password" className="text-xs text-muted-foreground">
            Password
          </label>
          <input
            id="login-password"
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-md border border-border bg-card px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        {error ? <p className="text-xs text-red-300">{error}</p> : null}
        <button
          type="submit"
          disabled={pending}
          className="w-full rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-60"
        >
          {pending ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
