"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { ThreatBadge } from "@/components/cyber/ThreatBadge";
import { ReplayPlayer } from "@/components/replay/ReplayPlayer";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { severityForRisk } from "@/lib/severity";
import type { ReplayResult } from "@/lib/types";
import { cn } from "@/lib/utils";

const DEMO_SECONDS = 75; // wall-clock length of the guided run

type Phase = "idle" | "building" | "running" | "done";

/** One-click guided demo: replays the synthetic attack through the real pipeline, with stage captions and a final summary. */
export default function DemoPage() {
  const { user } = useAuth();
  const canRun = !!user && user.role !== "VIEWER";
  const [phase, setPhase] = useState<Phase>("idle");
  const [result, setResult] = useState<ReplayResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [t, setT] = useState(0);
  const [runKey, setRunKey] = useState(0);

  async function start() {
    setPhase("building");
    setError(null);
    setT(0);
    try {
      const s = await api.replaySample();
      if (s.status !== "complete") throw new Error(s.error ?? "Sample replay failed");
      const r = await api.replay(s.id);
      setResult(r.result);
      setRunKey((k) => k + 1);
      setPhase("running");
    } catch (e) {
      setError((e as Error).message);
      setPhase("idle");
    }
  }

  const onTime = useCallback((x: number) => setT(x), []);
  const onComplete = useCallback(() => setPhase("done"), []);

  const stages = useMemo(() => {
    if (!result?.incident) return [];
    return result.incident.steps.map((s) => {
      const a = result.alerts.find((x) => x.id === s.alert_id)!;
      return { stage: s.stage, at: a.detected_offset_s, alert: a };
    });
  }, [result]);
  const reached = stages.filter((s) => s.at <= t);
  const current = reached.at(-1);

  const summary = useMemo(() => {
    if (!result?.incident) return null;
    const ids = new Set(result.incident.steps.flatMap((s) => result.alerts.find((a) => a.id === s.alert_id)?.evidence_event_ids ?? []));
    return { score: result.incident.risk_score, techniques: result.incident.techniques.length, evidence: ids.size, steps: result.incident.steps.length };
  }, [result]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="font-display text-[12px] uppercase tracking-[0.25em]"><span className="mr-2 text-primary">▍</span>Attack demonstration</h1>
        <span className="text-[10px] text-muted">~75 s · synthetic traffic through the real pipeline: pcap → flows → detection → correlation</span>
      </div>
      {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{error}</p>}

      {phase === "idle" || phase === "building" ? (
        <CyberCard tone="danger">
          <div className="py-12 text-center">
            <p className="mx-auto max-w-lg text-[12px] leading-relaxed text-muted">
              Builds a synthetic capture of a multi-stage intrusion, then replays it: reconnaissance, scanning, credential attack, access, lateral movement and exfiltration.
              The topology reacts, detections appear as they become possible, and the attack chain assembles itself.
            </p>
            {canRun ? (
              <button onClick={start} disabled={phase === "building"}
                className="mt-6 border border-danger bg-danger/10 px-8 py-4 font-display text-sm font-bold uppercase tracking-[0.3em] text-danger shadow-[0_0_28px_-6px_rgba(255,59,48,0.8)] transition hover:bg-danger hover:text-background disabled:opacity-50">
                {phase === "building" ? "Building capture…" : "Start attack simulation"}
              </button>
            ) : <p className="mt-6 text-[11px] text-warning">Starting a simulation needs the ANALYST or ADMIN role.</p>}
          </div>
        </CyberCard>
      ) : result && (
        <>
          <div className="grid grid-cols-7 gap-1" aria-label="Attack stages">
            {(stages.length ? stages : []).map((s) => {
              const on = s.at <= t;
              return <div key={s.stage + s.at} className={cn("border px-1.5 py-1.5 text-center text-[9px] uppercase leading-tight tracking-wider transition", on ? "border-danger/60 bg-danger/10 text-danger" : "border-border text-muted/50")}>{s.stage}</div>;
            })}
          </div>
          <p role="status" aria-live="polite" className="min-h-10 border border-border bg-black/40 px-3 py-2 text-[12px]">
            {current ? <><span className="text-danger">▍ {current.stage.toUpperCase()}</span> <span className="text-muted">{current.alert.explanation}</span></> : <span className="text-muted">Baseline traffic. Nothing suspicious yet…</span>}
          </p>
          <ReplayPlayer key={runKey} result={result} autoPlay baseSeconds={DEMO_SECONDS} onTime={onTime} onComplete={onComplete} presentation />

          {phase === "done" && summary && (
            <CyberCard tone="danger" className="border-danger/60">
              <div className="flex flex-wrap items-center justify-between gap-6 py-2">
                <div>
                  <div className="font-display text-xl font-black uppercase tracking-[0.2em] text-danger glow-danger">Incident reconstructed</div>
                  <p className="mt-1 text-[11px] text-muted">{summary.steps} correlated stages from a single source, with every step linked to evidence.</p>
                </div>
                <dl className="flex gap-8 text-center">
                  <div><dt className="text-[9px] uppercase tracking-widest text-muted">Risk</dt><dd className="mt-1 flex items-center gap-2"><span className="font-display text-2xl font-bold tabular-nums">{summary.score}</span><ThreatBadge severity={severityForRisk(summary.score)} /></dd></div>
                  <div><dt className="text-[9px] uppercase tracking-widest text-muted">MITRE techniques</dt><dd className="mt-1 font-display text-2xl font-bold tabular-nums text-info">{summary.techniques}</dd></div>
                  <div><dt className="text-[9px] uppercase tracking-widest text-muted">Linked evidence events</dt><dd className="mt-1 font-display text-2xl font-bold tabular-nums text-primary">{summary.evidence}</dd></div>
                </dl>
                <div className="flex gap-2">
                  <button onClick={start} className="border border-border px-3 py-2 text-[10px] uppercase tracking-widest text-muted hover:border-primary hover:text-primary">Run again</button>
                  <Link href="/replay" className="border border-primary px-3 py-2 text-[10px] uppercase tracking-widest text-primary hover:bg-primary hover:text-background">Open full replay</Link>
                </div>
              </div>
            </CyberCard>
          )}
        </>
      )}
    </div>
  );
}
