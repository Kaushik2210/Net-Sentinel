"use client";

import { Download, FileUp, ShieldAlert, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";
import { download, sortThreats, toMarkdown, verdict } from "@/components/analyze/report";
import { CyberCard } from "@/components/cyber/CyberCard";
import { DetectionClassBadge, ThreatBadge } from "@/components/cyber/ThreatBadge";
import { RiskFactors, ThreatScore } from "@/components/cyber/ThreatScore";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { SEVERITY } from "@/lib/severity";
import type { ReplayAlert, ReplayResult } from "@/lib/types";
import { cn } from "@/lib/utils";

const clock = (s: number) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

function Threat({ a }: { a: ReplayAlert }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="border-b border-border/60">
      <button onClick={() => setOpen(!open)} aria-expanded={open} className="grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 px-3 py-2.5 text-left hover:bg-panel-2">
        <ThreatBadge severity={a.severity} />
        <span className="min-w-0"><span className="block truncate text-[12px]">{a.event_type.replaceAll("_", " ")}</span>
          <span className="block truncate text-[10px] text-muted">{a.source} <span className="text-primary">›</span> {a.destination}</span></span>
        <span className="text-right text-[10px] tabular-nums text-muted">T+{clock(a.detected_offset_s)}<br />{Math.round(a.confidence * 100)}% conf</span>
      </button>
      {open && (
        <div className="space-y-2 bg-black/30 px-3 pb-3 pt-1 text-[11px]">
          <p>{a.explanation}</p>
          <div className="flex flex-wrap items-center gap-1.5"><DetectionClassBadge kind={a.detection_class} /><span className="text-muted">via {a.detector}</span>
            {a.mitre.map((t) => <span key={t} className="border border-info/50 bg-info/10 px-1 text-[10px] text-info">{t}</span>)}</div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 text-[10px]">{Object.entries(a.facts).map(([k, v]) => <div key={k} className="contents"><dt className="text-muted">{k.replaceAll("_", " ")}</dt><dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd></div>)}</dl>
          <p className="break-all text-[10px] text-muted">Evidence ({a.evidence_event_ids.length}): {a.evidence_event_ids.slice(0, 6).join(", ")}{a.evidence_event_ids.length > 6 ? " …" : ""}</p>
        </div>
      )}
    </li>
  );
}

export default function AnalyzePage() {
  const { user } = useAuth();
  const canRun = !!user && user.role !== "VIEWER";
  const [state, setState] = useState<"idle" | "analyzing" | "done">("idle");
  const [name, setName] = useState("");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [result, setResult] = useState<ReplayResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  async function run(label: string, start: () => Promise<{ id: string; status: string; error: string | null }>) {
    setState("analyzing");
    setError(null);
    setName(label);
    try {
      const s = await start();
      if (s.status !== "complete") throw new Error(s.error ?? "Analysis failed");
      const full = await api.replay(s.id);
      setSessionId(s.id);
      setResult(full.result);
      setState("done");
    } catch (e) {
      setError((e as Error).message);
      setState("idle");
    }
  }

  const take = (f?: File | null) => { if (f && canRun) run(f.name, () => api.uploadPcap(f)); };
  const v = result && !result.empty ? verdict(result) : null;
  const bad = v && v.count > 0;

  return (
    <div className="space-y-3">
      <div>
        <h1 className="font-display text-[12px] uppercase tracking-[0.25em]"><span className="mr-2 text-primary">▍</span>Analyze a capture</h1>
        <p className="mt-1 text-[11px] text-muted">Drop a network capture and NetSentinel parses it, builds flows, runs the detectors, correlates what it finds and shows the threats with their evidence. Everything runs on this machine.</p>
      </div>
      {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{error}</p>}

      {state !== "done" && (
        <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); take(e.dataTransfer.files[0]); }}
          className={cn("grid place-items-center border-2 border-dashed px-6 py-16 text-center transition", drag ? "border-primary bg-primary/10" : "border-border-strong bg-panel/60")}>
          {state === "analyzing" ? (
            <div><p className="font-display text-sm uppercase tracking-[0.25em] text-primary">Analyzing {name}<span className="animate-blink">_</span></p>
              <p className="mt-2 text-[11px] text-muted">Parsing packets, building flows, running detectors, correlating. This usually takes a few seconds.</p></div>
          ) : (
            <div>
              <FileUp className="mx-auto size-8 text-primary" />
              <p className="mt-3 text-[13px]">{canRun ? "Drag a capture here, or" : "Sign in as an analyst or admin to analyze captures."}</p>
              {canRun && (
                <div className="mt-3 flex flex-wrap items-center justify-center gap-2">
                  <input ref={input} type="file" accept=".pcap,.pcapng,.log,.json" className="hidden" aria-label="Choose a capture file" onChange={(e) => { take(e.target.files?.[0]); e.target.value = ""; }} />
                  <button onClick={() => input.current?.click()} className="border border-primary bg-primary/10 px-4 py-2 text-[11px] uppercase tracking-[0.2em] text-primary hover:bg-primary hover:text-background">Choose file</button>
                  <button onClick={() => run("built-in sample", api.replaySample)} className="border border-border px-4 py-2 text-[11px] uppercase tracking-[0.2em] text-muted hover:border-primary hover:text-primary">Try the built-in sample</button>
                </div>
              )}
              <p className="mt-4 text-[10px] text-muted">PCAP or pcapng, or Zeek conn.log / dns.log · up to 25 MB · IPv4 · parsed on the server, never executed</p>
            </div>
          )}
        </div>
      )}

      {state === "done" && result && (result.empty ? (
        <CyberCard><p className="py-8 text-center text-[12px] text-muted">The capture contained no analysable IPv4 events.</p></CyberCard>
      ) : v && (
        <>
          <CyberCard tone={bad ? "danger" : "success"}>
            <div className="flex flex-wrap items-center gap-5 py-1">
              {bad ? <ShieldAlert className="size-10 text-danger" /> : <ShieldCheck className="size-10 text-success" />}
              <div className="min-w-0 flex-1">
                <div className={cn("font-display text-xl font-black uppercase tracking-[0.15em]", bad ? "text-danger glow-danger" : "text-success glow-success")}>
                  {bad ? `${v.count} threat${v.count > 1 ? "s" : ""} detected` : "No threats detected"}
                </div>
                <p className="mt-1 text-[11px] text-muted">
                  {name} · {result.ingest?.packets} records → {result.ingest?.flows} flows → {result.ingest?.events} events · {clock(result.duration_s)} of traffic
                  {bad && <> · involved source{v.hosts.length > 1 ? "s" : ""}: <span className="text-foreground">{v.hosts.join(", ")}</span></>}
                </p>
                {!bad && <p className="mt-1 text-[11px] text-warning">The rule-based detectors found nothing. That does not prove the capture is safe: subtle, slow or encrypted activity is out of their reach.</p>}
              </div>
              {bad && v.top && <ThreatBadge severity={v.top} className="text-xs" />}
              <div className="flex gap-2">
                <button onClick={() => download(`netsentinel-${name.replace(/\W+/g, "_")}.md`, toMarkdown(name, result))} className="inline-flex items-center gap-1.5 border border-border px-3 py-2 text-[10px] uppercase tracking-widest text-muted hover:border-primary hover:text-primary"><Download className="size-3.5" /> Report</button>
                <Link href="/replay" className="border border-border px-3 py-2 text-[10px] uppercase tracking-widest text-muted hover:border-primary hover:text-primary">Replay</Link>
                <button onClick={() => { setState("idle"); setResult(null); setSessionId(null); }} className="border border-primary px-3 py-2 text-[10px] uppercase tracking-widest text-primary hover:bg-primary hover:text-background">Analyze another</button>
              </div>
            </div>
          </CyberCard>

          {bad && (
            <div className="grid gap-3 xl:grid-cols-[1.4fr_1fr]">
              <CyberCard title={`Threats · ${v.count}`} tone="danger" bodyClassName="p-0">
                <ul>{sortThreats(result.alerts).map((a) => <Threat key={a.id} a={a} />)}</ul>
              </CyberCard>
              <div className="space-y-3">
                {result.incident && (
                  <>
                    <CyberCard title="Reconstructed attack chain" tone="primary">
                      <div className="mb-3 flex items-center gap-3"><ThreatScore score={result.incident.risk_score} size={64} /><p className="text-[11px] text-muted">{result.incident.steps.length} related stages linked by source and time into one incident.</p></div>
                      <ol className="space-y-1.5">{result.incident.steps.map((s) => {
                        const a = result.alerts.find((x) => x.id === s.alert_id);
                        return <li key={s.alert_id} className="grid grid-cols-[1.4rem_1fr_auto] items-center gap-2 text-[11px]"><span className="text-muted tabular-nums">{s.position + 1}</span><span>{s.stage}</span>
                          <span className="text-[10px] tabular-nums" style={{ color: a ? SEVERITY[a.severity].hex : undefined }}>T+{clock(s.offset_s)}</span></li>;
                      })}</ol>
                    </CyberCard>
                    <CyberCard title="Why this risk score" tone="warning"><RiskFactors factors={result.incident.risk_factors} total={result.incident.risk_score} /></CyberCard>
                    <CyberCard title={`MITRE ATT&CK · ${result.incident.techniques.length}`} tone="info">
                      <ul className="space-y-1 text-[11px]">{result.incident.techniques.map((t) => <li key={t.id}><span className="mr-2 border border-info/50 bg-info/10 px-1 text-[10px] text-info">{t.id}</span>{t.name} <span className="text-muted">· {t.tactic}</span></li>)}</ul>
                    </CyberCard>
                  </>
                )}
              </div>
            </div>
          )}
          <p className="text-[10px] leading-relaxed text-muted">
            Session {sessionId} is saved and can be replayed on the Replay page. {result.ingest?.heuristics}
            {Object.keys(result.settings.overrides).length > 0 && ` Threshold overrides in effect: ${JSON.stringify(result.settings.overrides)}.`}
          </p>
        </>
      ))}
    </div>
  );
}
