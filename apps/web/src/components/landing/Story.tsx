import { Reveal, Section } from "./primitives";

const PIPELINE = [
  ["Telemetry", "Zeek, Suricata, PCAP, NetFlow, syslog"],
  ["Behavior", "Per-device baselines and deviation"],
  ["Detection", "Rules, behavior and ML, labelled apart"],
  ["Correlation", "Events grouped by entity and time"],
  ["Attack chain", "Ordered, evidence-backed stages"],
  ["Response", "Recommendations, simulated only"],
];

export function Story() {
  return (
    <>
      <Section id="what" index="01" eyebrow="What is NetSentinel" title="Answer one question: what is happening on this network, and why is it suspicious?"
        lead="NetSentinel turns raw telemetry into a story an analyst can verify. Every score lists its contributing factors; every conclusion cites the events behind it. When evidence is thin, it says so.">
        <div className="grid gap-px border border-border bg-border md:grid-cols-3">
          {[
            ["Explainable", "No mystery scores. Risk is a sum of named factors you can audit line by line."],
            ["Evidence-first", "Alerts link to the raw events that justify them. The analyst assistant may only cite what exists."],
            ["Honest about provenance", "Rule detections, behavioral anomalies, ML anomalies and correlated incidents are never conflated."],
          ].map(([t, d]) => (
            <Reveal key={t} className="bg-panel p-6">
              <h3 className="font-display text-sm font-bold uppercase tracking-[0.2em] text-primary">{t}</h3>
              <p className="mt-3 text-[12px] leading-relaxed text-muted">{d}</p>
            </Reveal>
          ))}
        </div>
      </Section>

      <Section id="how" index="02" eyebrow="How it works" title="From packets to a defensible incident report" status="IN PROGRESS">
        <ol className="grid gap-px border border-border bg-border sm:grid-cols-2 lg:grid-cols-6">
          {PIPELINE.map(([t, d], i) => (
            <Reveal key={t} delay={i * 0.06} className="relative bg-panel p-4">
              <span className="font-display text-[10px] tracking-[0.3em] text-primary">0{i + 1}</span>
              <h3 className="mt-2 font-display text-[13px] font-bold uppercase tracking-wider">{t}</h3>
              <p className="mt-2 text-[11px] leading-relaxed text-muted">{d}</p>
              {i < PIPELINE.length - 1 && <span aria-hidden className="absolute -right-2 top-1/2 z-10 hidden -translate-y-1/2 text-primary lg:block">›</span>}
            </Reveal>
          ))}
        </ol>
      </Section>

      <Section id="twin" index="03" eyebrow="Network digital twin" title="A living model of the network, banded by trust zone" status="IN PROGRESS"
        lead="Devices, communication edges and risk are modelled as a graph: Internet, perimeter, DMZ, internal, data, IoT and cloud. Edge weight is traffic volume; suspicious flows stand out.">
        <Reveal>
          <svg viewBox="0 0 800 210" className="w-full border border-border bg-black/40" role="img" aria-label="Zones of the digital twin">
            {[
              ["INTERNET", 70, "#6b8594"], ["PERIMETER", 205, "#00e5ff"], ["DMZ + CLOUD", 340, "#00e5ff"], ["INTERNAL", 475, "#39ff88"], ["DATA / IoT", 610, "#ffb000"],
            ].map(([label, x, col], i) => (
              <g key={label as string}>
                <rect x={(x as number) - 55} y="40" width="110" height="120" fill="none" stroke={col as string} strokeOpacity="0.35" strokeDasharray="3 4" />
                <text x={x as number} y="30" textAnchor="middle" fontSize="9" letterSpacing="2" fill={col as string}>{label}</text>
                {[0, 1, 2].map((k) => (
                  <circle key={k} cx={(x as number) + (k - 1) * 28} cy={75 + (k % 2) * 40} r="6" fill="#05070a" stroke={col as string} />
                ))}
                {i < 4 && <path d={`M${(x as number) + 55} 100 L${(x as number) + 80} 100`} stroke="#2a4256" markerEnd="url(#a)" />}
              </g>
            ))}
            <path d="M530 118 C 640 190, 700 190, 740 118" stroke="#ff3b30" fill="none" strokeWidth="1.5" strokeDasharray="5 5" className="edge-flow" />
            <text x="640" y="196" fontSize="8" fill="#ff3b30" letterSpacing="2" textAnchor="middle">SUSPICIOUS FLOW</text>
          </svg>
        </Reveal>
      </Section>
    </>
  );
}
