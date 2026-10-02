"use client";

import { LogOut } from "lucide-react";
import { useEffect, useState } from "react";
import { Logo } from "@/components/cyber/Logo";
import { CommandPalette } from "@/components/shell/CommandPalette";
import { StatusDot } from "@/components/cyber/SeverityIndicator";
import { useAuth } from "@/lib/auth";
import { useSummary } from "@/lib/summary";
import { cn, pad2 } from "@/lib/utils";

function Readout({ label, value, tone = "success" }: { label: string; value: React.ReactNode; tone?: "success" | "warning" | "danger" | "primary" | "muted" }) {
  const c = { success: "text-success", warning: "text-warning", danger: "text-danger", primary: "text-primary", muted: "text-muted" }[tone];
  return (
    <div className="flex flex-col leading-tight">
      <span className="text-[8px] uppercase tracking-[0.25em] text-muted">{label}</span>
      <span className={cn("font-display text-[11px] font-bold tracking-widest tabular-nums", c)}>{value}</span>
    </div>
  );
}

function Clock() {
  const [now, setNow] = useState<string>("--:--:--");
  useEffect(() => {
    const tick = () => setNow(new Date().toISOString().slice(11, 19) + "Z");
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);
  return <span>{now}</span>;
}

export function TopBar() {
  const { user, logout } = useAuth();
  const { summary, error } = useSummary();
  const online = !!summary && !error;
  const simulated = summary?.mode === "SIMULATION";

  return (
    <header className="flex h-14 items-center gap-6 border-b border-border bg-surface/90 px-4 backdrop-blur">
      <Logo href="/dashboard" />
      <div className="hidden h-7 w-px bg-border md:block" />
      <div className="hidden items-center gap-6 md:flex" aria-live="polite">
        <div className="flex items-center gap-2"><StatusDot tone={online ? "success" : "danger"} />
          <Readout label="System" value={online ? "ONLINE" : error ? "OFFLINE" : "SYNC"} tone={online ? "success" : error ? "danger" : "warning"} />
        </div>
        <Readout label="Telemetry" value={simulated ? "SIMULATED" : summary ? "IDLE" : "--"} tone={simulated ? "warning" : "muted"} />
        <Readout label="High-risk" value={summary ? pad2(summary.high_risk_devices) : "--"} tone={summary && summary.high_risk_devices ? "danger" : "success"} />
        <Readout label="Nodes" value={summary ? pad2(summary.active_devices) : "--"} tone="primary" />
        <Readout label="Last update" value={<Clock />} tone="muted" />
      </div>
      <div className="ml-auto flex items-center gap-3">
        <CommandPalette />
        {user && (
          <div className="hidden text-right leading-tight sm:block">
            <div className="text-[11px] text-foreground">{user.display_name}</div>
            <div className="text-[9px] tracking-[0.25em] text-primary">{user.role}</div>
          </div>
        )}
        <button onClick={logout} className="inline-flex size-8 items-center justify-center border border-border text-muted transition hover:border-danger/60 hover:text-danger" aria-label="Sign out" title="Sign out">
          <LogOut className="size-4" />
        </button>
      </div>
    </header>
  );
}
