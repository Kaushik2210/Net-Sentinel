"use client";

import { Activity, Clapperboard, FileUp, Crosshair, FileSearch, GitBranch, Network, Radar, Shield, Telescope, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

interface Item { href: string; label: string; icon: LucideIcon; phase?: number }

// Only routes that exist are links. Upcoming modules are listed (so the roadmap is visible)
// but are inert and tagged with the phase that delivers them.
const ITEMS: Item[] = [
  { href: "/dashboard", label: "Command center", icon: Activity },
  { href: "/analyze", label: "Analyze capture", icon: FileUp },
  { href: "/demo", label: "Attack demo", icon: Clapperboard },
  { href: "/network", label: "Network twin", icon: Network },
  { href: "/incidents", label: "Incidents", icon: GitBranch },
  { href: "/investigate", label: "Investigate", icon: FileSearch },
  { href: "/replay", label: "PCAP replay", icon: Radar },
  { href: "/mitre", label: "MITRE ATT&CK", icon: Crosshair },
  { href: "/threat-intel", label: "Threat intel", icon: Shield },
  { href: "/research", label: "Research", icon: Telescope },
];

export function Sidebar() {
  const path = usePathname();
  return (
    <nav aria-label="Primary" className="flex w-14 shrink-0 flex-col border-r border-border bg-surface/80 py-3 lg:w-52">
      {ITEMS.map(({ href, label, icon: Icon, phase }) => {
        const active = path === href || path.startsWith(href + "/");
        const body = (
          <>
            <Icon className="size-4 shrink-0" />
            <span className="hidden flex-1 truncate lg:block">{label}</span>
            {phase && <span className="hidden text-[8px] tracking-widest text-muted/70 lg:block">P{phase}</span>}
          </>
        );
        const cls = cn("mx-2 mb-0.5 flex items-center gap-3 border-l-2 px-3 py-2 text-[11px] uppercase tracking-[0.15em]");
        return phase ? (
          <div key={href} className={cn(cls, "cursor-not-allowed border-transparent text-muted/40")} title={`${label}: arrives in phase ${phase}`} aria-disabled>
            {body}
          </div>
        ) : (
          <Link key={href} href={href} aria-current={active ? "page" : undefined}
            className={cn(cls, active ? "border-primary bg-primary/10 text-primary" : "border-transparent text-muted hover:bg-panel hover:text-foreground")}>
            {body}
          </Link>
        );
      })}
      <div className="mt-auto hidden px-4 text-[9px] leading-relaxed tracking-widest text-muted/60 lg:block">
        NETSENTINEL v0.1<br />RESEARCH BUILD
      </div>
    </nav>
  );
}
