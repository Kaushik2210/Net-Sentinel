"use client";

import { MetricCard } from "@/components/cyber/MetricCard";
import type { Summary } from "@/lib/types";

const fmt = (n: number | undefined) => (n === undefined ? "--" : n.toLocaleString());

export function MetricsRow({ summary }: { summary: Summary | null }) {
  const s = summary;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
      <MetricCard label="Active devices" value={fmt(s?.active_devices)} tone="primary" hint="online, excl. internet" />
      <MetricCard label="Connections" value={fmt(s?.active_connections)} tone="primary" hint="known relationships" />
      <MetricCard label="Events / min" value={fmt(s?.events_per_min)} tone="success" hint={s?.mode === "SIMULATION" ? "synthetic telemetry" : "live telemetry"} />
      <MetricCard label="Anomalies" value={fmt(s?.anomalous_devices)} tone={s && s.anomalous_devices ? "warning" : "success"} hint="devices off baseline" />
      <MetricCard label="Critical alerts" value={fmt(s?.critical_alerts)} tone={s && s.critical_alerts ? "danger" : "success"} hint="detection engine: phase 3" />
      <MetricCard label="High-risk" value={fmt(s?.high_risk_devices)} tone={s && s.high_risk_devices ? "danger" : "success"} hint="risk score ≥ 50" />
      <MetricCard label="External" value={fmt(s?.external_connections)} tone="info" hint="links to the internet" />
    </div>
  );
}
