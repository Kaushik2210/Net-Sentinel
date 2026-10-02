"use client";

import { useState } from "react";
import { AlertRow } from "@/components/cyber/AlertRow";
import { CyberCard } from "@/components/cyber/CyberCard";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useSummary } from "@/lib/summary";
import type { Alert } from "@/lib/types";
import { cn } from "@/lib/utils";

interface Props { alerts: Alert[]; onReset: () => void; simulated: boolean }

export function AlertsPanel({ alerts, onReset, simulated }: Props) {
  const { user } = useAuth();
  const { refresh } = useSummary();
  const [busy, setBusy] = useState<"run" | "reset" | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const canRun = user && user.role !== "VIEWER" && simulated;

  async function run(kind: "run" | "reset") {
    setBusy(kind);
    setMsg(null);
    try {
      if (kind === "run") {
        const r = await api.simulateAttack();
        setMsg(`Injected ${r.events_injected} synthetic events, ${r.alerts_created.length} new alert(s).`);
      } else {
        await api.resetSimulation();
        onReset();
        setMsg("Simulated attack data cleared.");
      }
      refresh();
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  const btn = "border px-2 py-1 text-[9px] uppercase tracking-[0.18em] transition disabled:cursor-not-allowed disabled:opacity-40";
  return (
    <CyberCard title="Detections" tone="danger" bodyClassName="p-0"
      actions={canRun && (
        <div className="flex gap-1.5">
          <button disabled={!!busy} onClick={() => run("run")} className={cn(btn, "border-danger/60 text-danger hover:bg-danger/10")}>{busy === "run" ? "Running…" : "Inject simulated attack"}</button>
          {user?.role === "ADMIN" && <button disabled={!!busy} onClick={() => run("reset")} className={cn(btn, "border-border text-muted hover:text-foreground")}>Reset</button>}
        </div>
      )}>
      {msg && <p role="status" className="border-b border-border/60 px-3 py-1.5 text-[10px] text-warning">{msg}</p>}
      {alerts.length === 0 ? (
        <div className="px-4 py-6 text-center">
          <p className="text-[12px] text-foreground">No detections.</p>
          <p className="mt-1 text-[10px] leading-relaxed text-muted">The baseline traffic is clean.{canRun ? " Inject a labelled synthetic attack to see the engine work." : ""}</p>
        </div>
      ) : (
        <ul className="max-h-[300px] overflow-y-auto">{alerts.map((a) => <AlertRow key={a.id} alert={a} />)}</ul>
      )}
    </CyberCard>
  );
}
