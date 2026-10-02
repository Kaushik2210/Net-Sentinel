"use client";

import { useEffect, useState } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { RiskFactors, ThreatScore } from "@/components/cyber/ThreatScore";
import { ThreatBadge } from "@/components/cyber/ThreatBadge";
import { api } from "@/lib/api";
import { severityForRisk } from "@/lib/severity";
import type { DeviceDetail, DeviceSummary } from "@/lib/types";
import { cn } from "@/lib/utils";

interface Props { devices: DeviceSummary[]; selectedId: string | null; onSelect: (id: string) => void; loading: boolean }

/** Ranked risky devices; selecting one shows the exact factors behind its score. */
export function RiskSummary({ devices, selectedId, onSelect, loading }: Props) {
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedId) return;
    let live = true;
    api.device(selectedId)
      .then((d) => { if (live) { setDetail(d); setDetailError(null); } })
      .catch((e: Error) => live && setDetailError(e.message));
    return () => { live = false; };
  }, [selectedId]);

  const shown = detail && detail.id === selectedId ? detail : null;

  return (
    <CyberCard title="Risk summary" tone="warning" className="h-full" bodyClassName="p-0">
      {loading ? (
        <div className="p-4 text-[11px] text-muted">Scoring devices…</div>
      ) : devices.length === 0 ? (
        <div className="p-6 text-center text-[12px] text-muted">No devices deviate from baseline.</div>
      ) : (
        <ul>
          {devices.map((d) => (
            <li key={d.id}>
              <button onClick={() => onSelect(d.id)} aria-pressed={d.id === selectedId}
                className={cn("flex w-full items-center gap-3 border-b border-border/60 px-3 py-2 text-left transition hover:bg-panel-2", d.id === selectedId && "bg-primary/5")}>
                <span className="w-9 text-right font-display text-sm font-bold tabular-nums">{d.risk_score}</span>
                <span className="flex-1"><span className="block text-[12px]">{d.hostname}</span><span className="block text-[10px] text-muted">{d.ip} · {d.role}</span></span>
                <ThreatBadge severity={severityForRisk(d.risk_score)} />
              </button>
            </li>
          ))}
        </ul>
      )}
      {selectedId && (
        <div className="border-t border-border-strong bg-black/30 p-3">
          {detailError ? <p className="text-[11px] text-danger">{detailError}</p> : !shown ? <p className="text-[11px] text-muted">Loading evidence…</p> : (
            <div className="grid grid-cols-[auto_1fr] gap-4">
              <div className="flex flex-col items-center gap-2">
                <ThreatScore score={shown.risk_score} />
                <span className="text-[9px] tracking-[0.2em] text-muted">DEV {shown.deviation_score}</span>
              </div>
              <div>
                <div className="mb-2 text-[10px] uppercase tracking-[0.2em] text-primary">Why {shown.hostname} is scored {shown.risk_score}</div>
                <RiskFactors factors={shown.risk_factors} total={shown.risk_score} />
              </div>
            </div>
          )}
        </div>
      )}
    </CyberCard>
  );
}
