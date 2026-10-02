"use client";

import { useCallback, useEffect, useState } from "react";
import { AttackChain } from "@/components/cyber/AttackChain";
import { CyberCard } from "@/components/cyber/CyberCard";
import { EvidencePanel } from "@/components/cyber/EvidencePanel";
import { ThreatBadge } from "@/components/cyber/ThreatBadge";
import { AnalystPanel } from "@/components/investigate/AnalystPanel";
import { ResponsePanel } from "@/components/investigate/ResponsePanel";
import { WorkflowPanel } from "@/components/investigate/WorkflowPanel";
import { ParamSync } from "@/components/shell/ParamSync";
import { api } from "@/lib/api";
import type { IncidentDetail, IncidentSummary } from "@/lib/types";
import { cn, timeAgo } from "@/lib/utils";

export default function InvestigatePage() {
  const [list, setList] = useState<IncidentSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [step, setStep] = useState(0);
  const [tab, setTab] = useState<"evidence" | "analyst" | "response">("evidence");

  const loadList = useCallback(() => { api.incidents().then((p) => setList(p.items)).catch((e: Error) => setError(e.message)); }, []);
  const activeId = selectedId ?? list?.[0]?.id ?? null;
  const loadDetail = useCallback(() => { if (activeId) api.incident(activeId).then(setDetail).catch((e: Error) => setError(e.message)); }, [activeId]);

  useEffect(() => { loadList(); const t = setInterval(loadList, 10_000); return () => clearInterval(t); }, [loadList]);
  useEffect(() => { loadDetail(); }, [loadDetail]);

  const shown = detail && detail.id === activeId ? detail : null;
  const current = shown?.steps.find((s) => s.position === step) ?? shown?.steps[0];
  const onIncident = useCallback((id: string) => { setSelectedId(id); setStep(0); }, []);
  const changed = () => { loadList(); loadDetail(); };

  return (
    <div className="space-y-3">
      <ParamSync name="incident" onValue={onIncident} />
      {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{error}</p>}
      <div className="grid gap-3 xl:grid-cols-[260px_1fr_380px]">
        <CyberCard title="Incident queue" tone="danger" bodyClassName="p-0" className="xl:self-start">
          {!list ? <p className="p-4 text-[11px] text-muted">Loading…</p> : list.length === 0 ? <p className="p-4 text-[11px] leading-relaxed text-muted">Nothing to investigate. Correlated incidents appear here.</p> : (
            <ul>{list.map((i) => (
              <li key={i.id}><button onClick={() => { setSelectedId(i.id); setStep(0); }} aria-pressed={i.id === activeId}
                className={cn("w-full border-b border-border/60 px-3 py-2.5 text-left hover:bg-panel-2", i.id === activeId && "bg-primary/5")}>
                <div className="flex items-center justify-between"><ThreatBadge severity={i.severity} /><span className="font-display text-sm font-bold tabular-nums">{i.risk_score}</span></div>
                <div className="mt-1.5 text-[12px] leading-snug">{i.title}</div>
                <div className="mt-1 text-[10px] text-muted">{i.status.replace("_", " ")} · {i.assignee ?? "unassigned"} · {timeAgo(i.last_seen)}</div>
              </button></li>))}</ul>
          )}
        </CyberCard>

        <div className="min-w-0 space-y-3">
          {!shown ? <CyberCard><p className="py-14 text-center text-[11px] uppercase tracking-[0.25em] text-muted">{activeId ? "Loading…" : "Select an incident"}</p></CyberCard> : (
            <>
              <CyberCard title={shown.title} tone="primary"><WorkflowPanel key={shown.id} incident={shown} onChanged={changed} /></CyberCard>
              <CyberCard title="Attack timeline" tone="primary"><AttackChain steps={shown.steps} selected={current?.position ?? 0} onSelect={setStep} /></CyberCard>
            </>
          )}
        </div>

        <CyberCard tone="info" bodyClassName="p-0" className="xl:self-start">
          <div role="tablist" className="flex border-b border-border text-[10px] uppercase tracking-[0.2em]">
            {(["evidence", "analyst", "response"] as const).map((t) => (
              <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)} className={cn("flex-1 px-3 py-2.5", tab === t ? "border-b-2 border-info text-info" : "text-muted hover:text-foreground")}>{t === "evidence" ? "Evidence" : t === "analyst" ? "AI analyst" : "Response"}</button>
            ))}
          </div>
          {!shown ? <p className="p-4 text-[11px] text-muted">Select an incident.</p>
            : tab === "evidence" ? (current ? <EvidencePanel step={current} techniques={shown.techniques} /> : <p className="p-4 text-[11px] text-muted">No steps.</p>)
            : tab === "analyst" ? <AnalystPanel key={shown.id} incidentId={shown.id} />
            : <div className="p-3"><ResponsePanel key={shown.id} incidentId={shown.id} /></div>}
        </CyberCard>
      </div>
    </div>
  );
}
