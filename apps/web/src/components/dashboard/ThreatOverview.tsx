"use client";

import { useMemo } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { Radar, type Blip } from "@/components/cyber/Radar";
import { SEVERITY, severityForRisk, type Severity } from "@/lib/severity";
import type { Topology } from "@/lib/types";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Radar of risky devices (angle derived from the id, radius from risk) plus the risk-band distribution. */
export function ThreatOverview({ topology }: { topology: Topology | null }) {
  const { blips, bands } = useMemo(() => {
    const bands: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const blips: Blip[] = [];
    topology?.nodes.forEach((n) => {
      if (n.device_type === "internet") return;
      const sev = severityForRisk(n.risk_score);
      bands[sev]++;
      if (n.risk_score >= 25) {
        let h = 0;
        for (const ch of n.id) h = (h * 31 + ch.charCodeAt(0)) % 360;
        blips.push({ angle: h, radius: 1 - n.risk_score / 130, tone: n.risk_score >= 50 ? "danger" : "warning" });
      }
    });
    return { blips, bands };
  }, [topology]);
  const total = Object.values(bands).reduce((a, b) => a + b, 0) || 1;

  return (
    <CyberCard title="Threat overview" tone="danger" className="h-full">
      <div className="flex items-center gap-4">
        <Radar size={132} blips={blips} className="shrink-0" />
        <div className="flex-1 space-y-1.5">
          {ORDER.map((s) => (
            <div key={s} className="grid grid-cols-[4.2rem_1fr_1.6rem] items-center gap-2 text-[10px]">
              <span className={SEVERITY[s].text}>{SEVERITY[s].label}</span>
              <span className="h-1.5 bg-border/60"><span className="block h-full" style={{ width: `${(bands[s] / total) * 100}%`, background: SEVERITY[s].hex }} /></span>
              <span className="text-right tabular-nums text-muted">{bands[s]}</span>
            </div>
          ))}
        </div>
      </div>
      <p className="mt-3 text-[10px] leading-relaxed text-muted">Bands are behavioral risk (baseline deviation), not detection alerts. Rule and ML detections arrive with phases 3–4.</p>
    </CyberCard>
  );
}
