"use client";

import { CyberCard } from "@/components/cyber/CyberCard";
import { cn } from "@/lib/utils";
import type { Snapshot } from "./share";

function Delta({ label, a, b }: { label: string; a: number; b: number }) {
  const d = b - a;
  return (
    <div className="border border-border px-3 py-2 text-center">
      <div className="text-[9px] uppercase tracking-[0.2em] text-muted">{label}</div>
      <div className="mt-1 text-[13px] tabular-nums">{a} <span className="text-muted">→</span> {b}</div>
      <div className={cn("text-[10px] tabular-nums", d === 0 ? "text-muted" : d > 0 ? "text-warning" : "text-success")}>{d === 0 ? "no change" : `${d > 0 ? "+" : ""}${d}`}</div>
    </div>
  );
}

/** Pinned run versus the current run: what the threshold change gained and what it lost. */
export function Compare({ base, now, onClear }: { base: Snapshot; now: Snapshot; onClear: () => void }) {
  const gained = now.keys.filter((k) => !base.keys.includes(k));
  const lost = base.keys.filter((k) => !now.keys.includes(k));
  return (
    <CyberCard title="Compared with your pinned run" tone="warning" actions={<button onClick={onClear} className="text-[10px] uppercase tracking-widest text-muted hover:text-primary">Unpin</button>}>
      <p className="mb-3 text-[10px] text-muted">Pinned: {base.label} ({base.custom ? "custom" : "default"} thresholds) · Now: {now.label} ({now.custom ? "custom" : "default"} thresholds)</p>
      <div className="grid grid-cols-3 gap-2">
        <Delta label="Threats" a={base.alerts} b={now.alerts} />
        <Delta label="Incident risk" a={base.risk} b={now.risk} />
        <Delta label="Techniques" a={base.techniques} b={now.techniques} />
      </div>
      <div className="mt-3 grid gap-3 text-[11px] sm:grid-cols-2">
        <div>
          <div className="mb-1 text-[9px] uppercase tracking-[0.2em] text-success">Newly flagged</div>
          {gained.length ? gained.map((k) => <div key={k} className="text-success">+ {k}</div>) : <div className="text-muted">nothing new</div>}
        </div>
        <div>
          <div className="mb-1 text-[9px] uppercase tracking-[0.2em] text-danger">No longer flagged</div>
          {lost.length ? lost.map((k) => <div key={k} className="text-danger">− {k}</div>) : <div className="text-muted">nothing lost</div>}
        </div>
      </div>
    </CyberCard>
  );
}
