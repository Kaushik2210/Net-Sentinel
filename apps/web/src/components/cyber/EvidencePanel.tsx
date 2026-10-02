import type { IncidentStep, Technique } from "@/lib/types";
import { formatClock } from "@/lib/utils";
import { DetectionClassBadge, ThreatBadge } from "./ThreatBadge";

const Row = ({ k, v }: { k: string; v: React.ReactNode }) => (
  <div className="flex justify-between gap-3 py-0.5 text-[11px]"><span className="shrink-0 text-muted">{k}</span><span className="break-all text-right">{v}</span></div>
);

/** Everything known about one chain step. Nothing here is inferred by the UI: it renders stored evidence. */
export function EvidencePanel({ step, techniques }: { step: IncidentStep; techniques: Technique[] }) {
  const tech = step.mitre.map((id) => techniques.find((t) => t.id === id) ?? { id, name: "", tactic: "", description: "" });
  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <ThreatBadge severity={step.severity} />
        <DetectionClassBadge kind={step.detection_class} />
        <span className="font-display text-[12px] font-bold uppercase tracking-wider">{step.stage}</span>
      </div>
      <section>
        <h4 className="mb-1 text-[9px] uppercase tracking-[0.25em] text-primary">Detection reason</h4>
        <p className="text-[12px] leading-relaxed">{step.explanation}</p>
        <p className="mt-1 text-[10px] text-muted">via {step.detector} · confidence {Math.round(step.confidence * 100)}%</p>
      </section>
      <section>
        <h4 className="mb-1 text-[9px] uppercase tracking-[0.25em] text-primary">Details</h4>
        <Row k="Timestamp" v={`${step.timestamp.slice(0, 10)} ${formatClock(step.timestamp)}Z`} />
        <Row k="Source" v={step.source} /><Row k="Destination" v={step.destination} />
        <Row k="Joined because" v={`${step.link_reason} (${Math.round(step.link_confidence * 100)}%)`} />
        {Object.entries(step.facts).map(([k, v]) => <Row key={k} k={k.replaceAll("_", " ")} v={Array.isArray(v) ? v.join(", ") : String(v)} />)}
      </section>
      <section>
        <h4 className="mb-1 text-[9px] uppercase tracking-[0.25em] text-primary">MITRE ATT&amp;CK</h4>
        {tech.length === 0 ? <p className="text-[11px] text-muted">No technique mapped.</p> : tech.map((t) => (
          <div key={t.id} className="mb-2"><span className="border border-info/50 bg-info/10 px-1 text-[10px] text-info">{t.id}</span> <span className="text-[11px]">{t.name}</span>
            {t.tactic && <span className="ml-1 text-[10px] text-muted">· {t.tactic}</span>}</div>
        ))}
      </section>
      <section>
        <h4 className="mb-1 text-[9px] uppercase tracking-[0.25em] text-primary">Related events · {step.evidence_event_ids.length}</h4>
        {step.evidence_event_ids.length === 0 ? <p className="text-[11px] text-muted">No raw events linked (signal derived from device baselines).</p> : (
          <ul className="max-h-40 space-y-0.5 overflow-y-auto font-mono text-[10px] text-muted">
            {step.evidence_event_ids.map((id) => <li key={id}>{id}</li>)}
          </ul>
        )}
      </section>
    </div>
  );
}
