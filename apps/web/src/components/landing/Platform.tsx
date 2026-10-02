import { ArrowRight } from "lucide-react";
import { GithubMark } from "@/components/cyber/GithubMark";
import Link from "next/link";
import { Reveal, Section, StatusTag, type Status } from "./primitives";

const LAYERS = [
  ["Presentation", "Next.js, TypeScript, React Flow, WebSocket client"],
  ["API", "FastAPI, Pydantic, RBAC, rate limiting, OpenAPI"],
  ["Analysis", "Detection engine, behavior scoring, Isolation Forest, correlation"],
  ["Ingestion", "Telemetry adapters: simulation, PCAP, Zeek, Suricata, NetFlow, syslog"],
  ["Storage", "PostgreSQL (SQLite for local dev), Alembic migrations"],
];

const SECURITY: [string, Status][] = [
  ["JWT authentication, bcrypt password hashing", "LIVE"], ["Role-based access: ADMIN / ANALYST / VIEWER", "LIVE"],
  ["Login rate limits, per-account throttle, generic auth errors", "LIVE"], ["Security headers, strict CSP on the API", "LIVE"],
  ["Append-only audit log", "LIVE"], ["Input validation on every parameter", "LIVE"],
  ["Safe response simulation (no real actions)", "LIVE"], ["Secrets from environment only", "LIVE"],
];

export function Platform() {
  return (
    <>
      <Section id="architecture" index="08" eyebrow="Architecture" title="Clean layers, pluggable at the edges" status="LIVE"
        lead="Telemetry sources and detectors are interfaces. Adding a Zeek adapter or a new detector does not require touching unrelated modules.">
        <div className="space-y-px border border-border bg-border">
          {LAYERS.map(([t, d], i) => (
            <Reveal key={t} delay={i * 0.05} className="grid gap-1 bg-panel px-5 py-4 sm:grid-cols-[10rem_1fr]">
              <span className="font-display text-[12px] font-bold uppercase tracking-[0.2em] text-primary">{t}</span>
              <span className="text-[12px] text-muted">{d}</span>
            </Reveal>
          ))}
        </div>
      </Section>

      <Section id="security" index="09" eyebrow="Security capabilities" title="Built as a security-sensitive application">
        <div className="grid gap-px border border-border bg-border sm:grid-cols-2">
          {SECURITY.map(([t, s]) => (
            <div key={t} className="flex items-center justify-between gap-3 bg-panel px-4 py-3 text-[12px]"><span>{t}</span><StatusTag status={s} /></div>
          ))}
        </div>
      </Section>

      <Section id="research" index="10" eyebrow="Research and experimentation" title="Rules vs ML vs hybrid, measured" status="LIVE"
        lead="Research mode compares detection approaches on a labelled synthetic benchmark: precision, recall, F1, false-positive rate and detection latency. Results are clearly labelled as synthetic. Public datasets (CICIDS/UNSW-NB15-style) are not bundled; the docs describe how to bring your own.">
        <div className="grid gap-4 sm:grid-cols-3">
          {["Rule-based", "ML (Isolation Forest)", "Hybrid"].map((t) => (
            <div key={t} className="border border-border bg-panel p-4 text-center font-display text-[12px] uppercase tracking-widest text-muted">{t}</div>
          ))}
        </div>
      </Section>

      <section id="github" className="mx-auto max-w-6xl px-5 pb-24 pt-10">
        <Reveal className="panel-edge relative border border-primary/30 p-8 text-center sm:p-12">
          <div className="text-[10px] uppercase tracking-[0.3em] text-muted">11 / Open source</div>
          <h2 className="mt-3 font-display text-2xl font-bold tracking-wide sm:text-3xl">Read the code. Run the demo.</h2>
          <p className="mx-auto mt-3 max-w-xl text-[12px] text-muted">An MCA research project. Limitations are documented, not hidden.</p>
          <div className="mt-7 flex flex-wrap justify-center gap-3">
            <a href="https://github.com/Kaushik2210/Net-Sentinel" className="inline-flex items-center gap-2 border border-primary bg-primary px-5 py-3 text-[12px] font-bold uppercase tracking-[0.2em] text-background"><GithubMark className="size-4" /> View on GitHub</a>
            <Link href="/dashboard" className="inline-flex items-center gap-2 border border-border-strong px-5 py-3 text-[12px] uppercase tracking-[0.2em] text-muted hover:border-primary/50 hover:text-primary">Command center <ArrowRight className="size-4" /></Link>
          </div>
        </Reveal>
      </section>

      <footer className="border-t border-border py-6 text-center text-[10px] uppercase tracking-[0.25em] text-muted">
        NetSentinel &middot; experimental research platform &middot; synthetic data unless a real source is attached
      </footer>
    </>
  );
}
