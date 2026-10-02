"use client";

import { useMemo } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { SEVERITY, severityForRisk } from "@/lib/severity";
import type { Topology } from "@/lib/types";
import { cn } from "@/lib/utils";

interface Props {
  topology: Topology | null;
  selectedId: string | null;
  onSelect: (id: string) => void;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
}

/** Compact SVG view of the digital twin. The full React Flow explorer lives on /network (phase 2). */
export function TopologyPreview({ topology, selectedId, onSelect, loading, error, onRetry }: Props) {
  const view = useMemo(() => {
    if (!topology) return null;
    const xs = topology.nodes.map((n) => n.position.x);
    const ys = topology.nodes.map((n) => n.position.y);
    const pad = 50;
    const minX = Math.min(...xs) - pad, maxX = Math.max(...xs) + pad;
    const minY = Math.min(...ys) - pad, maxY = Math.max(...ys) + pad;
    const pos = Object.fromEntries(topology.nodes.map((n) => [n.id, n.position]));
    return { box: `${minX} ${minY} ${maxX - minX} ${maxY - minY}`, pos };
  }, [topology]);

  return (
    <CyberCard title="Network topology" tone="primary" className="h-full" bodyClassName="relative h-[calc(100%-2.4rem)] min-h-[320px] p-0"
      actions={<span className="text-[9px] tracking-[0.2em] text-muted">{topology ? `${topology.nodes.length} NODES · ${topology.edges.length} LINKS` : ""}</span>}>
      {error ? (
        <div className="grid h-full place-items-center p-6 text-center">
          <div><p className="text-[12px] text-danger">{error}</p>
            <button onClick={onRetry} className="mt-3 border border-border px-3 py-1.5 text-[10px] uppercase tracking-widest text-muted hover:border-primary hover:text-primary">Retry</button></div>
        </div>
      ) : loading || !topology || !view ? (
        <div className="grid h-full place-items-center text-[11px] uppercase tracking-[0.3em] text-muted">Mapping network<span className="animate-blink">_</span></div>
      ) : (
        <svg viewBox={view.box} className="size-full" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Network topology preview">
          {topology.edges.map((e) => {
            const a = view.pos[e.source], b = view.pos[e.target];
            if (!a || !b) return null;
            const w = 0.8 + Math.min(2.2, Math.log10(Math.max(e.bytes_per_hour, 1)) / 4);
            return <line key={e.id} x1={a.x} y1={a.y} x2={b.x} y2={b.y} strokeWidth={w} className={cn(e.suspicious && "edge-flow")} stroke={e.suspicious ? "#ff3b30" : "#1f3a4d"} opacity={e.suspicious ? 0.95 : 0.7} />;
          })}
          {topology.nodes.map((n) => {
            const col = SEVERITY[severityForRisk(n.risk_score)].hex;
            const risky = n.risk_score >= 25;
            const sel = n.id === selectedId;
            return (
              <g key={n.id} transform={`translate(${n.position.x},${n.position.y})`} onClick={() => onSelect(n.id)} className="cursor-pointer" role="button" aria-label={`${n.hostname}, risk ${n.risk_score}`}>
                {risky && <circle r="16" fill="none" stroke={col} strokeWidth="1.5" className="animate-pulse-ring" style={{ transformBox: "fill-box", transformOrigin: "center" }} />}
                {sel && <circle r="19" fill="none" stroke="#00e5ff" strokeWidth="1.5" strokeDasharray="4 3" />}
                <circle r="9" fill="#05070a" stroke={risky ? col : "#2a4256"} strokeWidth="2" />
                {risky && <circle r="3.5" fill={col} />}
                <text y="24" textAnchor="middle" fontSize="11" fill={risky ? col : "#6b8594"} letterSpacing="0.5">{n.hostname}</text>
                <title>{`${n.hostname} (${n.ip}) risk ${n.risk_score}`}</title>
              </g>
            );
          })}
        </svg>
      )}
    </CyberCard>
  );
}
