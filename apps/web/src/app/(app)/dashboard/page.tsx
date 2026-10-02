"use client";

import { useState } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { EventStream } from "@/components/dashboard/EventStream";
import { MetricsRow } from "@/components/dashboard/MetricsRow";
import { RiskSummary } from "@/components/dashboard/RiskSummary";
import { ThreatOverview } from "@/components/dashboard/ThreatOverview";
import { TopologyPreview } from "@/components/dashboard/TopologyPreview";
import { useDashboardData } from "@/components/dashboard/useDashboardData";
import { useSummary } from "@/lib/summary";
import { useLiveEvents } from "@/lib/useLiveEvents";

export default function Dashboard() {
  const { summary, error: summaryError } = useSummary();
  const { topology, topRisk, loading, error, reload } = useDashboardData();
  const live = useLiveEvents(60);
  const [selected, setSelected] = useState<string | null>(null);
  const active = selected ?? topRisk[0]?.id ?? null;

  return (
    <div className="space-y-3">
      {summaryError && (
        <div role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{summaryError}</div>
      )}
      {summary?.mode === "SIMULATION" && (
        <div className="flex items-center gap-2 border border-warning/30 bg-warning/5 px-3 py-1.5 text-[10px] uppercase tracking-[0.2em] text-warning">
          <span className="size-1.5 animate-blink bg-warning" /> Simulation mode: all telemetry is synthetic
        </div>
      )}
      <MetricsRow summary={summary} />
      <div className="grid gap-3 xl:grid-cols-[1.6fr_1fr]">
        <div className="h-[440px] xl:h-[500px]">
          <TopologyPreview topology={topology} selectedId={active} onSelect={setSelected} loading={loading} error={error} onRetry={reload} />
        </div>
        <RiskSummary devices={topRisk} selectedId={active} onSelect={setSelected} loading={loading} />
      </div>
      <div className="grid gap-3 xl:grid-cols-[1.6fr_1fr]">
        <EventStream events={live.events} status={live.status} loaded={live.loaded} error={live.error} source={summary?.mode === "SIMULATION" ? "simulation" : undefined} />
        <div className="grid gap-3">
          <ThreatOverview topology={topology} />
          <CyberCard title="Attack timeline" tone="muted">
            <div className="py-3 text-center">
              <p className="text-[12px] text-foreground">No correlated incidents.</p>
              <p className="mt-1 text-[10px] leading-relaxed text-muted">The detection and correlation engines (phases 3 and 5) build attack chains here.</p>
            </div>
          </CyberCard>
        </div>
      </div>
    </div>
  );
}
