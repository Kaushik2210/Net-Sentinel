"use client";

import { useCallback, useEffect, useState } from "react";
import { AttackChain } from "@/components/cyber/AttackChain";
import { CyberCard } from "@/components/cyber/CyberCard";
import { EvidencePanel } from "@/components/cyber/EvidencePanel";
import { DetectionClassBadge, ThreatBadge } from "@/components/cyber/ThreatBadge";
import { RiskFactors, ThreatScore } from "@/components/cyber/ThreatScore";
import { api } from "@/lib/api";
import type { IncidentDetail, IncidentSummary } from "@/lib/types";
import { cn, formatClock, timeAgo } from "@/lib/utils";

export default function IncidentsPage() {
  const [list, setList] = useState<IncidentSummary[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [step, setStep] = useState(0);

  const load = useCallback(() => {
    api.incidents().then((p) => { setList(p.items); setListError(null); }).catch((e: Error) => setListError(e.message));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 10_000);
    return () => clearInterval(t);
  }, [load]);

  const activeId = selectedId ?? list?.[0]?.id ?? null;

  useEffect(() => {
    if (!activeId) return;
    let live = true;
    api.incident(activeId)
      .then((d) => { if (live) { setDetail(d); setDetailError(null); setStep(0); } })
      .catch((e: Error) => live && setDetailError(e.message));
    return () => { live = false; };
  }, [activeId]);

  const shown = detail && detail.id === activeId ? detail : null;
  const current = shown?.steps.find((s) => s.position === step) ?? shown?.steps[0];

  return (
    <div className="grid gap-3 xl:grid-cols-[280px_1fr_360px]">
      <CyberCard title="Incidents" tone="danger" bodyClassName="p-0" className="xl:self-start">
        {listError ? <p className="p-4 text-[12px] text-danger">{listError}</p>
          : !list ? <p className="p-4 text-[11px] text-muted">Loading…</p>
          : list.length === 0 ? (
            <div className="p-5 text-center"><p className="text-[12px]">No incidents.</p>
              <p className="mt-1 text-[10px] leading-relaxed text-muted">Incidents appear when related alerts are correlated into a chain. Use <b>Inject simulated attack</b> on the dashboard.</p></div>
          ) : (
            <ul>{list.map((i) => (
              <li key={i.id}>
                <button onClick={() => setSelectedId(i.id)} aria-pressed={i.id === activeId}
                  className={cn("w-full border-b border-border/60 px-3 py-2.5 text-left hover:bg-panel-2", i.id === activeId && "bg-primary/5")}>
                  <div className="flex items-center justify-between gap-2"><ThreatBadge severity={i.severity} /><span className="font-display text-sm font-bold tabular-nums">{i.risk_score}</span></div>
                  <div className="mt-1.5 text-[12px] leading-snug">{i.title}</div>
                  <div className="mt-1 text-[10px] text-muted">{i.status} · {timeAgo(i.last_seen)}</div>
                </button>
              </li>))}</ul>
          )}
      </CyberCard>

      <div className="space-y-3">
        {detailError ? <p className="border border-danger/40 bg-danger/10 p-3 text-[12px] text-danger">{detailError}</p>
          : !shown ? <CyberCard><p className="py-10 text-center text-[11px] uppercase tracking-[0.25em] text-muted">{activeId ? "Reconstructing…" : "Select an incident"}</p></CyberCard>
          : (
            <>
              <CyberCard tone="danger">
                <div className="flex flex-wrap items-center gap-4">
                  <ThreatScore score={shown.risk_score} size={88} />
                  <div className="min-w-0 flex-1">
                    <div className="mb-1 flex flex-wrap items-center gap-2"><DetectionClassBadge kind="CORRELATED" /><ThreatBadge severity={shown.severity} /><span className="text-[10px] uppercase tracking-widest text-muted">{shown.status}</span></div>
                    <h1 className="font-display text-lg font-bold leading-tight">{shown.title}</h1>
                    <p className="mt-1 text-[11px] text-muted">{shown.summary}</p>
                    <p className="mt-1 text-[10px] tracking-widest text-muted">
                      {shown.steps.length} STEPS · {shown.techniques.length} TECHNIQUES · {shown.evidence_count} EVIDENCE EVENTS · {formatClock(shown.first_seen)}–{formatClock(shown.last_seen)}Z
                    </p>
                  </div>
                </div>
              </CyberCard>
              <CyberCard title="Attack timeline · click a step" tone="primary">
                <AttackChain steps={shown.steps} selected={current?.position ?? 0} onSelect={setStep} />
              </CyberCard>
              <div className="grid gap-3 md:grid-cols-2">
                <CyberCard title="Why this risk score" tone="warning"><RiskFactors factors={shown.risk_factors} total={shown.risk_score} /></CyberCard>
                <CyberCard title="Supporting signals" tone="info">
                  {shown.supporting.length === 0 ? <p className="text-[11px] text-muted">No behavioral or ML signals on involved hosts.</p> : (
                    <ul className="space-y-2">{shown.supporting.map((a) => (
                      <li key={a.id} className="text-[11px]"><div className="mb-0.5 flex items-center gap-2"><DetectionClassBadge kind={a.detection_class} /><span className="text-muted">{a.source}</span></div>{a.explanation}</li>))}</ul>
                  )}
                  <p className="mt-2 text-[10px] text-muted">Context only: these are not steps in the chain.</p>
                </CyberCard>
              </div>
            </>
          )}
      </div>

      <CyberCard title="Step evidence" tone="primary" bodyClassName="p-0" className="xl:self-start">
        {current && shown ? <EvidencePanel step={current} techniques={shown.techniques} /> : <p className="p-4 text-[11px] text-muted">Select a step to inspect its evidence.</p>}
      </CyberCard>
    </div>
  );
}
