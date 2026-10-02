import { DetectionClassBadge } from "@/components/cyber/ThreatBadge";
import { TerminalPanel } from "@/components/cyber/TerminalPanel";
import { Reveal, Section } from "./primitives";

const BASELINE = [
  { k: "DNS / hour", base: 70, now: 1240, unit: "" },
  { k: "SSH / hour", base: 2, now: 48, unit: "" },
  { k: "Upload / day", base: 50, now: 1200, unit: "MB" },
  { k: "New destinations", base: 5, now: 17, unit: "" },
];

const CHAIN = [
  ["Reconnaissance", "T1595", "Host sweep from PC-07", "09:12:04"],
  ["Network scanning", "T1046", "412 ports across DB-02", "09:13:40"],
  ["Credential attack", "T1110", "48 SSH failures to JUMP-01", "09:15:22"],
  ["Lateral movement", "T1021", "PC-07 > JUMP-01 > DB-02", "09:19:51"],
  ["Possible exfiltration", "T1041", "1.2 GB outbound over TLS", "09:27:08"],
];

const TACTICS = ["Recon", "Initial Access", "Execution", "Persistence", "Cred Access", "Discovery", "Lateral Mvmt", "Collection", "C2", "Exfiltration"];
const HIT: Record<string, string[]> = { Recon: ["T1595"], "Cred Access": ["T1110"], Discovery: ["T1046"], "Lateral Mvmt": ["T1021"], Exfiltration: ["T1041"] };

export function Intelligence() {
  return (
    <>
      <Section id="behavior" index="04" eyebrow="Behavioral intelligence" title="Every device carries a baseline. Deviation is a number you can read." status="LIVE"
        lead="Scoring is transparent arithmetic, not a black box: ratio against the baseline maximum, capped per metric, plus a criticality amplifier that only applies when something already deviates.">
        <Reveal className="grid gap-6 lg:grid-cols-[1.3fr_1fr]">
          <div className="border border-border bg-panel p-5">
            <div className="mb-4 flex items-center justify-between text-[10px] uppercase tracking-[0.2em] text-muted">
              <span>Example: PC-07 baseline vs current</span><DetectionClassBadge kind="BEHAVIORAL" />
            </div>
            <div className="space-y-4">
              {BASELINE.map((m) => {
                const pct = Math.min(100, (m.base / m.now) * 100);
                return (
                  <div key={m.k}>
                    <div className="mb-1 flex justify-between text-[11px]"><span>{m.k}</span><span className="text-muted">{m.base}{m.unit} <span className="text-danger">&rarr; {m.now}{m.unit} ({(m.now / m.base).toFixed(1)}x)</span></span></div>
                    <div className="relative h-2 bg-border/60"><div className="absolute inset-y-0 left-0 bg-danger/80" style={{ width: "100%" }} /><div className="absolute inset-y-0 left-0 bg-primary" style={{ width: `${pct}%` }} /></div>
                  </div>
                );
              })}
            </div>
            <p className="mt-4 text-[10px] text-muted">Cyan = baseline maximum; red = observed. Illustrative values; the live dashboard computes these from the simulated network.</p>
          </div>
          <TerminalPanel title="risk-breakdown --device PC-07" className="self-start">
            <div>+20  SSH connection rate</div><div>+20  External upload volume</div><div>+15  DNS request rate</div><div>+9   New destinations</div><div>+3   Asset criticality</div>
            <div className="mt-2 border-t border-border pt-2 text-primary">RISK SCORE: 67 / 100</div>
          </TerminalPanel>
        </Reveal>
      </Section>

      <Section id="attack" index="05" eyebrow="Attack reconstruction" title="Scattered alerts become one ordered incident" status="LIVE"
        lead="The correlation engine links events by entity, time and behavior, then orders them into a chain you can click through, each step with its evidence and confidence.">
        <ol className="relative border-l border-border-strong pl-6">
          {CHAIN.map(([stage, tech, detail, time], i) => (
            <Reveal key={stage} delay={i * 0.07} className="relative pb-6 last:pb-0">
              <span className="absolute -left-[31px] top-1 size-2.5 border border-danger bg-background" style={{ boxShadow: "0 0 8px #ff3b30" }} />
              <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
                <span className="font-display text-[13px] font-bold uppercase tracking-wider">{stage}</span>
                <span className="text-[10px] tracking-widest text-info">{tech}</span>
                <span className="text-[10px] text-muted">{time}</span>
              </div>
              <div className="text-[12px] text-muted">{detail}</div>
            </Reveal>
          ))}
        </ol>
        <p className="mt-6 text-[10px] text-muted">Example chain for illustration.</p>
      </Section>

      <Section id="mitre" index="06" eyebrow="MITRE ATT&CK" title="Detections mapped to techniques, stored as data, not hard-coded UI" status="LIVE">
        <Reveal className="grid grid-cols-2 gap-px border border-border bg-border sm:grid-cols-5">
          {TACTICS.map((t) => (
            <div key={t} className="bg-panel p-3">
              <div className="text-[9px] uppercase tracking-[0.18em] text-muted">{t}</div>
              <div className="mt-2 flex min-h-5 flex-wrap gap-1">
                {(HIT[t] ?? []).map((id) => <span key={id} className="border border-info/50 bg-info/10 px-1 text-[10px] text-info">{id}</span>)}
              </div>
            </div>
          ))}
        </Reveal>
      </Section>

      <Section id="xai" index="07" eyebrow="Explainable AI analyst" title="An assistant that may only quote the evidence it is given" status="LIVE"
        lead="The analyst receives a structured evidence package from the detection and correlation layers. It cannot invent telemetry; with too little evidence it answers plainly. Answers are deterministic and citation-validated; no language model is used.">
        <Reveal className="grid gap-4 md:grid-cols-2">
          <TerminalPanel title="analyst > why is PC-07 suspicious?">
            <p>PC-07 deviates from its baseline on 4 metrics (see <span className="text-primary">risk factors</span>).</p>
            <p className="mt-1 text-muted">Evidence: evt_3fa91c, evt_8b2e04, evt_c17d90</p>
          </TerminalPanel>
          <TerminalPanel title="analyst > did data leave the network?">
            <p className="text-warning">Insufficient evidence.</p>
            <p className="mt-1 text-muted">No outbound flow above threshold is linked to this incident.</p>
          </TerminalPanel>
        </Reveal>
      </Section>
    </>
  );
}
