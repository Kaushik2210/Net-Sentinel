"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { DetectionClassBadge, ThreatBadge } from "@/components/cyber/ThreatBadge";
import { api } from "@/lib/api";
import type { MitreMatrix, TechniqueDetail } from "@/lib/types";
import { cn, formatClock } from "@/lib/utils";

export default function MitrePage() {
  const [matrix, setMatrix] = useState<MitreMatrix | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [onlyObserved, setOnlyObserved] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<TechniqueDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = () => api.mitre().then((m) => live && setMatrix(m)).catch((e: Error) => live && setError(e.message));
    load();
    const t = setInterval(load, 10_000);
    return () => { live = false; clearInterval(t); };
  }, []);

  useEffect(() => {
    if (!selected) return;
    let live = true;
    api.technique(selected)
      .then((d) => { if (live) { setDetail(d); setDetailError(null); } })
      .catch((e: Error) => live && setDetailError(e.message));
    return () => { live = false; };
  }, [selected]);

  const needle = q.trim().toLowerCase();
  const visible = useMemo(
    () => (t: { id: string; name: string; observed: boolean }) =>
      (!onlyObserved || t.observed) && (!needle || t.id.toLowerCase().includes(needle) || t.name.toLowerCase().includes(needle)),
    [needle, onlyObserved],
  );
  const shown = detail && detail.id === selected ? detail : null;

  return (
    <div className="grid gap-3 xl:grid-cols-[1fr_380px]">
      <div className="min-w-0 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-display text-[12px] uppercase tracking-[0.25em]"><span className="mr-2 text-primary">▍</span>MITRE ATT&amp;CK matrix</h1>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="search technique or ID…" aria-label="Search techniques"
            className="w-56 border border-border bg-black/50 px-2 py-1 text-[11px] outline-none focus:border-primary" />
          <label className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-muted">
            <input type="checkbox" checked={onlyObserved} onChange={(e) => setOnlyObserved(e.target.checked)} className="accent-primary" /> observed only
          </label>
          {matrix && <span className="ml-auto text-[10px] tracking-widest text-muted"><b className="text-info">{matrix.observed_techniques}</b> / {matrix.total_techniques} TECHNIQUES OBSERVED</span>}
        </div>

        {error ? <p className="border border-danger/40 bg-danger/10 p-3 text-[12px] text-danger">{error}</p>
          : !matrix ? <p className="py-16 text-center text-[11px] uppercase tracking-[0.3em] text-muted">Loading matrix<span className="animate-blink">_</span></p>
          : (
            <>
              {matrix.observed_techniques === 0 && (
                <p className="border border-border bg-panel px-3 py-2 text-[11px] text-muted">No techniques observed yet. Techniques light up when detections reference them. Inject a simulated attack from the dashboard to see mapping.</p>
              )}
              <div className="overflow-x-auto pb-2">
                <div className="grid min-w-max auto-cols-[148px] grid-flow-col gap-px border border-border bg-border">
                  {matrix.tactics.map((tac) => (
                    <div key={tac.name} className="bg-panel">
                      <div className="border-b border-border bg-panel-2 px-2 py-2 text-[9px] font-bold uppercase leading-tight tracking-[0.14em] text-muted">
                        {tac.name} <span className="text-muted/50">{tac.techniques.length}</span>
                      </div>
                      <div className="space-y-px p-1">
                        {tac.techniques.filter(visible).map((t) => (
                          <button key={t.id} onClick={() => setSelected(t.id)} aria-pressed={selected === t.id}
                            className={cn("block w-full border px-1.5 py-1 text-left text-[10px] leading-snug transition",
                              t.observed ? "border-info/60 bg-info/15 text-foreground shadow-[0_0_10px_-3px_var(--color-info)]" : "border-transparent text-muted/70 hover:border-border-strong hover:text-foreground",
                              selected === t.id && "ring-1 ring-primary")}>
                            <span className={cn("block text-[9px] tracking-widest", t.observed ? "text-info" : "text-muted/50")}>{t.id}{t.observed ? ` · ${t.alert_count}` : ""}</span>
                            {t.name}
                          </button>
                        ))}
                        {tac.techniques.filter(visible).length === 0 && <div className="px-1.5 py-1 text-[9px] text-muted/40">no match</div>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <p className="text-[10px] text-muted">Catalogue is a curated subset of ATT&amp;CK Enterprise stored as data. Highlighted cells are referenced by at least one alert in the last 7 days.</p>
            </>
          )}
      </div>

      <CyberCard title="Technique" tone="info" bodyClassName="p-0" className="xl:self-start">
        {!selected ? <p className="p-4 text-[11px] text-muted">Select a technique to see related detections.</p>
          : detailError ? <p className="p-4 text-[12px] text-danger">{detailError}</p>
          : !shown ? <p className="p-4 text-[11px] text-muted">Loading…</p>
          : (
            <div className="space-y-4 p-4">
              <div>
                <span className="border border-info/50 bg-info/10 px-1 text-[10px] text-info">{shown.id}</span>
                <h2 className="mt-2 font-display text-base font-bold leading-tight">{shown.name}</h2>
                <p className="text-[10px] uppercase tracking-widest text-muted">{shown.tactic}</p>
                <p className="mt-2 text-[11px] leading-relaxed">{shown.description}</p>
              </div>
              {!shown.observed ? <p className="border border-border bg-black/30 p-2 text-[11px] text-muted">Not observed. No alert maps to this technique.</p> : (
                <>
                  <div className="grid grid-cols-3 gap-2 text-center text-[10px] text-muted">
                    <div className="border border-border p-2"><div className="font-display text-lg text-foreground">{shown.alert_count}</div>alerts</div>
                    <div className="border border-border p-2"><div className="font-display text-lg text-foreground">{Math.round((shown.max_confidence ?? 0) * 100)}%</div>max conf</div>
                    <div className="border border-border p-2"><div className="font-display text-lg text-foreground">{shown.evidence_event_ids.length}</div>events</div>
                  </div>
                  <ul className="space-y-3">
                    {shown.alerts.map((a) => (
                      <li key={a.id} className="border-l border-info/40 pl-3 text-[11px]">
                        <div className="mb-1 flex flex-wrap items-center gap-1.5"><ThreatBadge severity={a.severity} /><DetectionClassBadge kind={a.detection_class} /></div>
                        <p>{a.explanation}</p>
                        <p className="mt-1 text-[10px] text-muted">{formatClock(a.ts)}Z · {Math.round(a.confidence * 100)}% conf · {a.detector}</p>
                        {a.incident_id && (
                          <p className="mt-0.5 text-[10px] text-muted">Timeline position: step {a.chain_position} of {a.chain_length} ({a.stage}) · <Link href="/incidents" className="text-primary hover:underline">view incident</Link></p>
                        )}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
      </CyberCard>
    </div>
  );
}
