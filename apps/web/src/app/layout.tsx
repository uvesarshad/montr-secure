import type { Metadata } from "next";
import "../styles/globals.css";
import { Providers } from "../components/providers.js";
import { AppShell } from "../components/app-shell.js";

export const metadata: Metadata = {
  title: "Montr Secure — Operator Console",
  description:
    "On-prem AI security orchestration: correlated, exploit-confirmed findings with merge-ready fixes.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-background text-foreground antialiased">
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
