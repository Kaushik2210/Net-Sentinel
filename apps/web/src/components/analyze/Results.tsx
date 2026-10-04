"use client";

import { Download, ShieldAlert, ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";
import { useState, type ReactNode } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { DetectionClassBadge, ThreatBadge } from "@/components/cyber/ThreatBadge";
import { RiskFactors, ThreatScore } from "@/components/cyber/ThreatScore";
import { SEVERITY } from "@/lib/severity";
import type { ReplayAlert, ReplayResult } from "@/lib/types";
import { cn } from "@/lib/utils";
import { download, sortThreats, toMarkdown, verdict } from "./report";

export const clock = (s: number) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

function Threat({ a, index }: { a: ReplayAlert; index: number }) {
  const [open, setOpen] = useState(false);
  return (
    <motion.li initial={{ opacity: 0, x: -24 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + index * 0.12, duration: 0.35 }} className="border-b border-border/60">
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
    </motion.li>
  );
}

interface Props {
  name: string;
  result: ReplayResult;
  /** Extra buttons shown beside the report download. */
  actions?: ReactNode;
  footer?: ReactNode;
  emptyText?: string;
}

/** Verdict banner, threat list, reconstructed chain, risk factors and MITRE techniques for one analysed capture. */
export function Results({ name, result, actions, footer, emptyText = "The capture contained no analysable IPv4 events." }: Props) {
  if (result.empty) return <CyberCard><p className="py-8 text-center text-[12px] text-muted">{emptyText}</p></CyberCard>;
  const v = verdict(result);
  const bad = v.count > 0;
  return (
    <>
      <CyberCard tone={bad ? "danger" : "success"} className={bad ? "alarm" : undefined}>
        <div className="flex flex-wrap items-center gap-5 py-1">
          {bad ? <ShieldAlert className="size-10 text-danger" /> : <ShieldCheck className="size-10 text-success" />}
          <div className="min-w-0 flex-1">
            <div className={cn("slam font-display text-xl font-black uppercase tracking-[0.15em]", bad ? "text-danger glow-danger" : "text-success glow-success")}>
              {bad ? `${v.count} threat${v.count > 1 ? "s" : ""} detected` : "No threats detected"}
            </div>
            <p className="mt-1 text-[11px] text-muted">
              {name} · {result.ingest?.packets} records → {result.ingest?.flows} flows → {result.ingest?.events} events · {clock(result.duration_s)} of traffic
              {bad && <> · involved source{v.hosts.length > 1 ? "s" : ""}: <span className="text-foreground">{v.hosts.join(", ")}</span></>}
            </p>
            {!bad && <p className="mt-1 text-[11px] text-warning">The rule-based detectors found nothing. That does not prove the capture is safe: subtle, slow or encrypted activity is out of their reach.</p>}
          </div>
          {bad && v.top && <ThreatBadge severity={v.top} className="text-xs" />}
          <div className="flex flex-wrap gap-2">
            <button onClick={() => download(`netsentinel-${name.replace(/\W+/g, "_")}.md`, toMarkdown(name, result))} className="inline-flex items-center gap-1.5 border border-border px-3 py-2 text-[10px] uppercase tracking-widest text-muted hover:border-primary hover:text-primary"><Download className="size-3.5" /> Report</button>
            {actions}
          </div>
        </div>
      </CyberCard>

      {bad && (
        <div className="grid gap-3 xl:grid-cols-[1.4fr_1fr]">
          <CyberCard title={`Threats · ${v.count}`} tone="danger" bodyClassName="p-0">
            <ul>{sortThreats(result.alerts).map((a, i) => <Threat key={a.id} a={a} index={i} />)}</ul>
          </CyberCard>
          <div className="space-y-3">
            {result.incident && (
              <>
                <CyberCard title="Reconstructed attack chain" tone="primary">
                  <div className="mb-3 flex items-center gap-3"><ThreatScore score={result.incident.risk_score} size={64} /><p className="text-[11px] text-muted">{result.incident.steps.length} related stages linked by source and time into one incident.</p></div>
                  <ol className="space-y-1.5">{result.incident.steps.map((s) => {
                    const a = result.alerts.find((x) => x.id === s.alert_id);
                    return <motion.li key={s.alert_id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.8 + s.position * 0.35 }}
                      className="grid grid-cols-[1.4rem_1fr_auto] items-center gap-2 border-l-2 pl-2 text-[11px]" style={{ borderColor: a ? SEVERITY[a.severity].hex : undefined }}><span className="text-muted tabular-nums">{s.position + 1}</span><span>{s.stage}</span>
                      <span className="text-[10px] tabular-nums" style={{ color: a ? SEVERITY[a.severity].hex : undefined }}>T+{clock(s.offset_s)}</span></motion.li>;
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
      {footer && <p className="text-[10px] leading-relaxed text-muted">{footer}</p>}
    </>
  );
}
