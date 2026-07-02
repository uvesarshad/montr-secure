"use client";

import * as React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RoleProvider } from "./role-context.js";
import { ShieldIcon } from "./icons.js";

/** MSW is on unless explicitly disabled — the console is mock-first until
 * apps/api is wired (WS-L / integration). */
const useMsw = process.env.NEXT_PUBLIC_USE_MSW !== "false";

function StartupSplash({ label }: { label: string }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-3 bg-background text-center">
      <ShieldIcon className="h-8 w-8 animate-pulse text-primary" />
      <p className="text-sm text-muted-foreground">{label}</p>
    </div>
  );
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = React.useState(!useMsw);
  const [client] = React.useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: { retry: false, refetchOnWindowFocus: false, staleTime: 15_000 },
        },
      }),
  );

  React.useEffect(() => {
    if (!useMsw) return;
    let active = true;
    void (async () => {
      try {
        const { worker } = await import("../mocks/browser.js");
        await worker.start({
          onUnhandledRequest: "bypass",
          serviceWorker: { url: "/mockServiceWorker.js" },
          quiet: true,
        });
      } catch (err) {
        console.error("[montr-web] MSW mock API failed to start", err);
      } finally {
        if (active) setReady(true);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  if (!ready) return <StartupSplash label="Starting mock API…" />;

  return (
    <QueryClientProvider client={client}>
      <RoleProvider>{children}</RoleProvider>
    </QueryClientProvider>
  );
}
