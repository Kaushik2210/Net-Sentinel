"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Recommendation } from "@/lib/types";
import { cn } from "@/lib/utils";

/** Recommendations only. The single executor is a simulator that changes nothing. */
export function ResponsePanel({ incidentId }: { incidentId: string }) {
  const { user } = useAuth();
  const canSim = !!user && user.role !== "VIEWER";
  const [recs, setRecs] = useState<Recommendation[] | null>(null);
  const [outcome, setOutcome] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api.recommendations(incidentId).then((r) => live && setRecs(r)).catch((e: Error) => live && setError(e.message));
    return () => { live = false; };
  }, [incidentId]);

  async function simulate(r: Recommendation) {
    setBusy(r.id);
    setError(null);
    try {
      const res = await api.simulateResponse(r.id);
      setOutcome((o) => ({ ...o, [r.id]: res.message }));
      setRecs((list) => list?.map((x) => (x.id === r.id ? res.recommendation : x)) ?? null);
    } catch (e) { setError((e as Error).message); } finally { setBusy(null); }
  }

  return (
    <div className="space-y-3">
      <p className="border border-warning/30 bg-warning/5 px-2 py-1 text-[10px] uppercase tracking-[0.18em] text-warning">Recommendations only · safe simulation · no real changes are made</p>
      {error && <p role="alert" className="text-[11px] text-danger">{error}</p>}
      {!recs ? <p className="text-[11px] text-muted">Deriving recommendations…</p> : recs.length === 0 ? <p className="text-[11px] text-muted">Insufficient evidence to recommend a response.</p> : (
        <ul className="space-y-3">{recs.map((r) => (
          <li key={r.id} className="border border-border p-2.5">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0"><div className="text-[9px] uppercase tracking-[0.2em] text-muted">{r.action.replaceAll("_", " ")}</div><div className="break-all text-[12px] text-foreground">{r.target}</div></div>
              {canSim && <button disabled={busy === r.id} onClick={() => simulate(r)} className={cn("shrink-0 border px-2 py-1 text-[9px] uppercase tracking-[0.15em] transition disabled:opacity-40", r.state === "simulated" ? "border-success/50 text-success" : "border-primary/60 text-primary hover:bg-primary hover:text-background")}>[ {r.label} ]</button>}
            </div>
            <p className="mt-1 text-[10px] leading-relaxed text-muted">{r.rationale}</p>
            {outcome[r.id] && <p className="mt-1.5 border-l border-success/60 pl-2 text-[11px] font-bold text-success">{outcome[r.id]}</p>}
          </li>))}</ul>
      )}
    </div>
  );
}
