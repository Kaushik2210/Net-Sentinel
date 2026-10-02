"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { Sidebar } from "@/components/shell/Sidebar";
import { TopBar } from "@/components/shell/TopBar";
import { useAuth } from "@/lib/auth";
import { SummaryProvider } from "@/lib/summary";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [loading, user, router]);

  if (loading || !user) {
    return (
      <div className="grid min-h-screen place-items-center text-[11px] uppercase tracking-[0.3em] text-muted">
        <span>Authenticating<span className="animate-blink">_</span></span>
      </div>
    );
  }

  return (
    <SummaryProvider>
      <div className="flex h-screen flex-col">
        <TopBar />
        <div className="flex min-h-0 flex-1">
          <Sidebar />
          <main className="bg-grid min-w-0 flex-1 overflow-y-auto p-4">{children}</main>
        </div>
      </div>
    </SummaryProvider>
  );
}
