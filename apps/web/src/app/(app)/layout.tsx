"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import { Sidebar } from "@/components/shell/Sidebar";
import { TopBar } from "@/components/shell/TopBar";
import { useAuth } from "@/lib/auth";
import { SummaryProvider } from "@/lib/summary";

const TITLES: Record<string, string> = {
  dashboard: "Command center", analyze: "Analyze capture", demo: "Attack demo", network: "Network twin", incidents: "Incidents",
  investigate: "Investigate", replay: "PCAP replay", mitre: "MITRE ATT&CK", "threat-intel": "Threat intel", research: "Research",
};

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();
  const path = usePathname();

  const name = TITLES[path.split("/")[1] ?? ""];

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
      {name && <title>{`${name} | NetSentinel`}</title>}
      <div className="flex h-screen flex-col">
        <TopBar />
        <div className="flex min-h-0 flex-1">
          <Sidebar />
          <main id="main" className="bg-grid min-w-0 flex-1 overflow-y-auto p-4">{children}</main>
        </div>
      </div>
    </SummaryProvider>
  );
}
