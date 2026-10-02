"use client";

import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { StatusDot } from "@/components/cyber/SeverityIndicator";
import { ThreatBadge } from "@/components/cyber/ThreatBadge";
import { RiskFactors, ThreatScore } from "@/components/cyber/ThreatScore";
import { api } from "@/lib/api";
import type { DeviceDetail, MlScore } from "@/lib/types";
import { cn, formatBytes, formatClock, timeAgo } from "@/lib/utils";

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-b border-border/70 px-4 py-3">
      <h3 className="mb-2 text-[9px] uppercase tracking-[0.25em] text-primary">{title}</h3>
      {children}
    </section>
  );
}

const Row = ({ k, v }: { k: string; v: React.ReactNode }) => (
  <div className="flex justify-between gap-3 py-0.5 text-[11px]"><span className="text-muted">{k}</span><span className="text-right text-foreground">{v}</span></div>
);

interface Props { deviceId: string; onClose: () => void; onSelect: (id: string) => void }

/** Everything NetSentinel knows about one device: identity, baseline vs current, risk factors, links, events. */
export function DeviceIntelligence({ deviceId, onClose, onSelect }: Props) {
  const [d, setD] = useState<DeviceDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ml, setMl] = useState<{ id: string; score: MlScore | null } | null>(null);

  useEffect(() => {
    let live = true;
    api.device(deviceId)
      .then((r) => { if (live) { setD(r); setErr(null); } })
      .catch((e: Error) => live && setErr(e.message));
    return () => { live = false; };
  }, [deviceId]);

  useEffect(() => {
    if (!d || d.id !== deviceId) return;
    let live = true;
    api.mlScore(d.ip)
      .then((r) => live && setMl({ id: deviceId, score: r[0] ?? null }))
      .catch(() => live && setMl({ id: deviceId, score: null }));
    return () => { live = false; };
  }, [d, deviceId]);

  const mlScore = ml && ml.id === deviceId ? ml.score : null;
  const ready = d && d.id === deviceId ? d : null;

  return (
    <aside className="flex h-full w-full flex-col border-l border-border-strong bg-surface" aria-label="Device intelligence">
      <header className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <span className="font-display text-[11px] uppercase tracking-[0.22em] text-muted"><span className="mr-2 text-primary">▍</span>Device intelligence</span>
        <button onClick={onClose} aria-label="Close panel" className="text-muted hover:text-foreground"><X className="size-4" /></button>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {err ? <p className="p-4 text-[12px] text-danger">{err}</p> : !ready ? <p className="p-4 text-[11px] text-muted">Loading profile<span className="animate-blink">_</span></p> : (
          <>
            <div className="flex items-center gap-4 border-b border-border/70 px-4 py-4">
              <ThreatScore score={ready.risk_score} />
              <div className="min-w-0">
                <div className="truncate font-display text-lg font-bold">{ready.hostname}</div>
                <div className="text-[11px] text-muted">{ready.role}</div>
                <div className="mt-1.5 flex items-center gap-2"><ThreatBadge severity={ready.risk_severity} />
                  <span className="flex items-center gap-1.5 text-[10px] text-muted"><StatusDot tone={ready.status === "online" ? "success" : "muted"} pulse={false} />{ready.status}</span></div>
              </div>
            </div>

            <Block title="Identity">
              <Row k="IP" v={ready.ip} /><Row k="MAC" v={ready.mac} /><Row k="OS" v={ready.os} />
              <Row k="Zone" v={ready.zone} /><Row k="Criticality" v={`${ready.criticality} / 5`} />
              <Row k="Open ports" v={ready.open_ports.length ? ready.open_ports.join(", ") : "none"} />
              <Row k="Protocols" v={ready.protocols.length ? ready.protocols.join(", ") : "none"} />
              <Row k="Last seen" v={timeAgo(ready.last_seen)} />
            </Block>

            <Block title={`Behavior · baseline vs current · deviation ${ready.deviation_score}`}>
              {ready.metrics.length === 0 ? <p className="text-[11px] text-muted">No behavioral baseline for this node type.</p> : (
                <div className="space-y-3">
                  {ready.metrics.map((m) => {
                    const scale = Math.max(m.current, m.baseline_max, 1);
                    return (
                      <div key={m.key}>
                        <div className="mb-1 flex justify-between text-[10px]">
                          <span>{m.label}</span>
                          <span className={m.deviated ? "text-danger" : "text-muted"}>{m.current} <span className="text-muted">/ normal ≤{m.baseline_max}</span></span>
                        </div>
                        <div className="relative h-1.5 bg-border/60">
                          <span className="absolute inset-y-0 left-0 bg-primary/50" style={{ width: `${(m.baseline_max / scale) * 100}%` }} />
                          <span className={cn("absolute inset-y-0 left-0 opacity-90", m.deviated ? "bg-danger/70" : "bg-success/60")} style={{ width: `${(m.current / scale) * 100}%`, mixBlendMode: "screen" }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </Block>

            <Block title="Why this risk score">
              <RiskFactors factors={ready.risk_factors} total={ready.risk_score} />
            </Block>

            <Block title="ML anomaly · Isolation Forest">
              {!mlScore ? <p className="text-[11px] text-muted">Insufficient recent events to score this device.</p> : (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="border border-info/40 px-1.5 py-0.5 text-[9px] tracking-widest text-info">ML ANOMALY SCORE</span>
                    <span className={mlScore.is_anomaly ? "text-danger" : "text-success"}>{mlScore.risk}/100 · {mlScore.is_anomaly ? "outlier" : "within baseline"}</span>
                  </div>
                  <ul className="space-y-0.5 text-[10px]">
                    {mlScore.contributions.map((c) => (
                      <li key={c.feature} className="flex justify-between gap-2"><span className="text-muted">{c.label}</span><span>{c.value} <span className="text-muted">(baseline {c.baseline_mean}, z {c.z > 0 ? "+" : ""}{c.z})</span></span></li>
                    ))}
                  </ul>
                  <p className="text-[10px] text-muted">{mlScore.note}</p>
                </div>
              )}
            </Block>

            <Block title="Historical anomalies">
              <p className="text-[11px] text-muted">None recorded. Persisted anomalies appear once the detection engine runs (phase 3).</p>
            </Block>

            <Block title={`Connected devices · ${ready.connection_count}`}>
              <ul className="space-y-1">
                {ready.connections.slice(0, 12).map((c, i) => (
                  <li key={c.id + i}>
                    <button onClick={() => onSelect(c.id)} className="grid w-full grid-cols-[1.2rem_1fr_auto] items-center gap-2 text-left text-[11px] hover:text-primary">
                      <span className={c.suspicious ? "text-danger" : "text-muted"}>{c.direction === "outbound" ? "→" : "←"}</span>
                      <span className={cn("truncate", c.suspicious && "text-danger")}>{c.hostname} <span className="text-muted">{c.protocol}{c.port ? `:${c.port}` : ""}</span></span>
                      <span className="tabular-nums text-muted">{formatBytes(c.bytes_per_hour)}/h</span>
                    </button>
                  </li>
                ))}
              </ul>
            </Block>

            <Block title="Recent events">
              {ready.recent_events.length === 0 ? <p className="text-[11px] text-muted">No recent events for this address.</p> : (
                <ul className="space-y-0.5 font-mono text-[10px]">
                  {ready.recent_events.map((e) => (
                    <li key={e.id} className="grid grid-cols-[3.8rem_1fr] gap-2"><span className="tabular-nums text-muted">{formatClock(e.ts)}</span><span className="truncate">{e.event_type} <span className="text-muted">{e.src_ip}›{e.dst_ip}</span></span></li>
                  ))}
                </ul>
              )}
            </Block>
          </>
        )}
      </div>
    </aside>
  );
}
