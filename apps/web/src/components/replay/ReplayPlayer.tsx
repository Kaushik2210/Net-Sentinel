"use client";

import { FastForward, Pause, Play, Rewind, SkipForward } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { DetectionClassBadge, ThreatBadge } from "@/components/cyber/ThreatBadge";
import { ThreatScore } from "@/components/cyber/ThreatScore";
import { SEVERITY } from "@/lib/severity";
import type { ReplayResult } from "@/lib/types";
import { cn } from "@/lib/utils";

const DEFAULT_BASE_SECONDS = 40; // wall-clock seconds for a full replay at 1x
const SPEEDS = [1, 2, 4, 8];
const W = 820, H = 520;

const clock = (s: number) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

/** All playback state is derived client-side from the replay JSON; scrubbing never calls the server. */
interface PlayerProps {
  result: ReplayResult;
  /** Start playing immediately (demo mode). */
  autoPlay?: boolean;
  /** Wall-clock seconds for a full replay at 1x. */
  baseSeconds?: number;
  /** Reports the replay clock so a host page can caption it. */
  onTime?: (t: number) => void;
  /** Called once when playback reaches the end. */
  onComplete?: () => void;
  /** Hide the side panels and controls for a presentation view. */
  presentation?: boolean;
}

export function ReplayPlayer({ result, autoPlay = false, baseSeconds = DEFAULT_BASE_SECONDS, onTime, onComplete, presentation = false }: PlayerProps) {
  const dur = Math.max(result.duration_s, 1);
  const [t, setT] = useState(0);
  const [playing, setPlaying] = useState(autoPlay);
  const [dir, setDir] = useState<1 | -1>(1);
  const [speedIdx, setSpeedIdx] = useState(0);
  const [stepSel, setStepSel] = useState<string | null>(null);

  useEffect(() => {
    if (!playing) return;
    // Interval + real elapsed time (not frame counting) keeps playback correct if the tab is throttled.
    let last = performance.now();
    const id = setInterval(() => {
      const now = performance.now();
      const dt = (now - last) / 1000;
      last = now;
      setT((prev) => {
        const next = prev + dir * dt * SPEEDS[speedIdx] * (dur / baseSeconds);
        if (next >= dur || next <= 0) { setPlaying(false); return Math.min(dur, Math.max(0, next)); }
        return next;
      });
    }, 50);
    return () => clearInterval(id);
  }, [playing, dir, speedIdx, dur, baseSeconds]);

  useEffect(() => { onTime?.(t); }, [t, onTime]);
  const done = useRef(false);
  useEffect(() => {
    if (t >= dur && !done.current) { done.current = true; onComplete?.(); }
    if (t < dur) done.current = false;
  }, [t, dur, onComplete]);

  // Layout: internal hosts on an arc (left), external on a column (right). Deterministic.
  const pos = useMemo(() => {
    const internal = result.hosts.filter((h) => h.internal).sort((a, b) => a.ip.localeCompare(b.ip));
    const external = result.hosts.filter((h) => !h.internal).sort((a, b) => a.ip.localeCompare(b.ip));
    const m = new Map<string, { x: number; y: number }>();
    internal.forEach((h, i) => {
      const a = (i / Math.max(internal.length, 1)) * Math.PI * 2 - Math.PI / 2;
      const r = 150 + (i % 2) * 40;
      m.set(h.ip, { x: 300 + Math.cos(a) * r * 1.35, y: H / 2 + Math.sin(a) * r });
    });
    external.forEach((h, i) => m.set(h.ip, { x: W - 70, y: 50 + (i + 0.5) * ((H - 100) / Math.max(external.length, 1)) }));
    return m;
  }, [result.hosts]);

  const frame = useMemo(() => {
    let f = result.frames[0];
    for (const fr of result.frames) if (fr.t <= t) f = fr;
    return f;
  }, [result.frames, t]);

  const detected = result.alerts.filter((a) => a.detected_offset_s <= t);
  const hot = new Map<string, string>(); // ip -> severity colour
  detected.forEach((a) => hot.set(a.source, SEVERITY[a.severity].hex));

  const windowS = dur / 25;
  const active = useMemo(() => {
    const set = new Map<string, boolean>();
    for (const row of result.events) {
      if (row[0] > t) break;
      if (row[0] >= t - windowS) {
        const src = result.hosts[row[1]]?.ip, dst = result.hosts[row[2]]?.ip;
        if (src && dst) set.set(`${src}>${dst}`, true);
      }
    }
    return set;
  }, [result.events, result.hosts, t, windowS]);

  const steps = result.incident?.steps.filter((s) => {
    const a = result.alerts.find((x) => x.id === s.alert_id);
    return a && a.detected_offset_s <= t;
  }) ?? [];
  const selAlert = result.alerts.find((a) => a.id === (stepSel ?? steps.at(-1)?.alert_id));

  const jump = useCallback((dest: number) => { setPlaying(false); setT(Math.min(dur, Math.max(0, dest))); }, [dur]);
  const nextMark = () => jump(result.alerts.map((a) => a.detected_offset_s).filter((x) => x > t + 0.01).sort((a, b) => a - b)[0] ?? dur);
  const btn = "inline-flex items-center gap-1.5 border border-border px-3 py-1.5 text-[10px] uppercase tracking-[0.2em] text-muted transition hover:border-primary hover:text-primary";

  return (
    <div className={cn("grid gap-3", !presentation && "xl:grid-cols-[1fr_340px]")}>
      <div className="space-y-3">
        <CyberCard title="Replay topology" tone="primary" bodyClassName="p-0"
          actions={<span className="text-[9px] tracking-[0.2em] text-muted">T+{clock(t)} / {clock(dur)}</span>}>
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full bg-black/30" role="img" aria-label="Replay topology at the current time">
            {result.edges.map((e) => {
              const a = pos.get(e.src), b = pos.get(e.dst);
              if (!a || !b || e.first_s > t) return null;
              const isActive = active.has(`${e.src}>${e.dst}`);
              const bad = hot.has(e.src) && isActive;
              return <line key={e.src + e.dst} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={bad ? "#ff3b30" : isActive ? "#00e5ff" : "#1b3243"}
                strokeWidth={bad ? 1.8 : isActive ? 1.2 : 0.6} opacity={isActive ? 0.95 : 0.5} className={isActive ? "edge-flow" : undefined} />;
            })}
            {result.hosts.map((h) => {
              const p = pos.get(h.ip);
              if (!p || h.first_s > t) return null;
              const col = hot.get(h.ip);
              return (
                <g key={h.ip} transform={`translate(${p.x},${p.y})`}>
                  {col && <circle r="13" fill="none" stroke={col} strokeWidth="1.5" className="animate-pulse-ring" style={{ transformBox: "fill-box", transformOrigin: "center" }} />}
                  <circle r={h.internal ? 6 : 7} fill="#05070a" stroke={col ?? (h.internal ? "#2a4256" : "#6b8594")} strokeWidth="1.8" />
                  <text y={-11} textAnchor="middle" fontSize="8" fill={col ?? "#6b8594"}>{h.ip}</text>
                </g>
              );
            })}
          </svg>
          {!presentation && <div className="flex flex-wrap items-center gap-2 border-t border-border p-3">
            <button className={btn} onClick={() => { setDir(-1); setPlaying(true); }} aria-label="Rewind"><Rewind className="size-3.5" /> Rewind</button>
            <button className={cn(btn, playing && dir === 1 && "border-primary text-primary")} onClick={() => { if (t >= dur) setT(0); setDir(1); setPlaying((p) => !(p && dir === 1)); }}>
              {playing && dir === 1 ? <><Pause className="size-3.5" /> Pause</> : <><Play className="size-3.5" /> Play</>}</button>
            <button className={btn} onClick={nextMark} aria-label="Step to next detection"><SkipForward className="size-3.5" /> Step</button>
            <button className={btn} onClick={() => setSpeedIdx((i) => (i + 1) % SPEEDS.length)} aria-label="Change speed"><FastForward className="size-3.5" /> {SPEEDS[speedIdx]}x</button>
            <input type="range" min={0} max={dur} step={dur / 400} value={t} onChange={(e) => jump(Number(e.target.value))} aria-label="Timeline scrubber" className="min-w-40 flex-1 accent-[#00e5ff]" />
          </div>}
          <div className="relative mx-3 mb-3 h-3" aria-hidden>
            {result.alerts.map((a) => (
              <span key={a.id} title={a.event_type} className="absolute top-0 size-2 -translate-x-1/2 rotate-45" style={{ left: `${(a.detected_offset_s / dur) * 100}%`, background: a.detected_offset_s <= t ? SEVERITY[a.severity].hex : "#2a4256" }} />
            ))}
          </div>
        </CyberCard>
      </div>

      <div className={cn("space-y-3", presentation && "grid gap-3 space-y-0 md:grid-cols-3")}>
        <CyberCard title="Threat state" tone="danger">
          <div className="flex items-center gap-4">
            <ThreatScore score={frame?.threat ?? 0} label="THREAT" />
            <dl className="grid flex-1 grid-cols-2 gap-x-3 text-[10px] text-muted">
              <dt>Events</dt><dd className="text-right tabular-nums text-foreground">{frame?.events ?? 0}</dd>
              <dt>Alerts</dt><dd className="text-right tabular-nums text-foreground">{detected.length}</dd>
              <dt>Chain steps</dt><dd className="text-right tabular-nums text-foreground">{steps.length}</dd>
            </dl>
          </div>
        </CyberCard>
        <CyberCard title="Attack chain builds" tone="warning" bodyClassName="p-0">
          {steps.length === 0 ? <p className="p-4 text-[11px] text-muted">No correlated chain yet. Press play.</p> : (
            <ol>{steps.map((s) => {
              const a = result.alerts.find((x) => x.id === s.alert_id)!;
              return (
                <li key={s.alert_id}><button onClick={() => setStepSel(s.alert_id)} className={cn("flex w-full items-center gap-2 border-b border-border/60 px-3 py-2 text-left hover:bg-panel-2", selAlert?.id === s.alert_id && "bg-primary/5")}>
                  <span className="w-4 text-[10px] tabular-nums text-muted">{s.position + 1}</span>
                  <span className="flex-1 text-[11px]">{s.stage}</span><ThreatBadge severity={a.severity} /></button></li>
              );
            })}</ol>
          )}
        </CyberCard>
        {selAlert && (
          <CyberCard title="Detection" tone="info">
            <div className="mb-1 flex items-center gap-2"><DetectionClassBadge kind={selAlert.detection_class} /><span className="text-[10px] text-muted">{selAlert.mitre.join(" · ")}</span></div>
            <p className="text-[11px] leading-relaxed">{selAlert.explanation}</p>
            <p className="mt-1 text-[10px] text-muted">detected T+{clock(selAlert.detected_offset_s)} · {Math.round(selAlert.confidence * 100)}% conf · {selAlert.evidence_event_ids.length} evidence events</p>
          </CyberCard>
        )}
      </div>
    </div>
  );
}
