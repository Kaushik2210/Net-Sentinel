"use client";

import { Link2, Pin } from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Results } from "@/components/analyze/Results";
import { CyberCard } from "@/components/cyber/CyberCard";
import { Logo } from "@/components/cyber/Logo";
import { PacketRain } from "@/components/fx/PacketRain";
import { Challenge } from "@/components/playground/Challenge";
import { Compare } from "@/components/playground/Compare";
import { decode, encode, scaled, snapshot, type Snapshot, type Thresholds } from "@/components/playground/share";
import { ReplayPlayer } from "@/components/replay/ReplayPlayer";
import { api } from "@/lib/api";
import type { PlaygroundOptions, ReplayResult } from "@/lib/types";
import { cn } from "@/lib/utils";

const btn = "border px-3 py-2 text-[10px] uppercase tracking-[0.2em] transition disabled:opacity-30";

/** Public, no-login playground: pick a generated scenario, tune detector thresholds, compare runs, watch it replay and try the tuning challenge. */
export default function TryPage() {
  const [opts, setOpts] = useState<PlaygroundOptions | null>(null);
  const [scenario, setScenario] = useState("full");
  const [values, setValues] = useState<Thresholds>({});
  const [result, setResult] = useState<ReplayResult | null>(null);
  const [ran, setRan] = useState<{ scenario: string; custom: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runId, setRunId] = useState(0);
  const [pinned, setPinned] = useState<Snapshot | null>(null);
  const [copied, setCopied] = useState(false);
  const [watch, setWatch] = useState(false);
  const started = useRef(false);

  const run = useCallback(async (sc: string, th: Thresholds) => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.playground(sc, th);
      setResult(res.result);
      setRunId((n) => n + 1);
      setRan({ scenario: sc, custom: Object.keys(th).length > 0 });
      setWatch(false);
    } catch (e) {
      setError((e as Error).message || "The run failed.");
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    api.playgroundOptions()
      .then((o) => {
        setOpts(o);
        const shared = decode(window.location.search, o);
        setScenario(shared.scenario);
        setValues(shared.values);
        return run(shared.scenario, diff(shared.values, o));
      })
      .catch(() => setError("The playground API is not reachable."));
  }, [run]);

  // Only send values that differ from the defaults, so "default thresholds" really means none were changed.
  function diff(v: Thresholds, o: PlaygroundOptions | null): Thresholds {
    const out: Thresholds = {};
    for (const [d, ps] of Object.entries(v)) for (const [k, val] of Object.entries(ps)) {
      const def = o?.tunables.find((t) => t.detector === d)?.params.find((p) => p.key === k)?.default;
      if (val !== def) (out[d] ??= {})[k] = val;
    }
    return out;
  }
  const payload = useMemo(() => diff(values, opts), [values, opts]);
  const custom = Object.keys(payload).length > 0;
  const nameOf = (id: string) => opts?.scenarios.find((s) => s.id === id)?.label ?? id;
  const now = useMemo(() => (result && ran ? snapshot(nameOf(ran.scenario), ran.custom, result) : null), [result, ran, opts]); // eslint-disable-line react-hooks/exhaustive-deps

  async function share() {
    const url = `${window.location.origin}/try?${encode(scenario, payload)}`;
    try { await navigator.clipboard.writeText(url); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { window.prompt("Copy this link", url); }
  }

  return (
    <main className="bg-grid bg-vignette relative min-h-screen">
      <PacketRain className="fixed [mask-image:linear-gradient(to_bottom,black,transparent_70%)]" intensity={0.3} />
      <header className="relative mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
        <Logo />
        <nav className="flex items-center gap-3 text-[11px] uppercase tracking-[0.2em]">
          <Link href="/" className="text-muted hover:text-primary">Home</Link>
          <Link href="/login" className="border border-primary/60 bg-primary/10 px-3 py-1.5 text-primary hover:bg-primary hover:text-background">Sign in</Link>
        </nav>
      </header>

      <div className="relative mx-auto max-w-6xl space-y-3 px-4 pb-16">
        <div>
          <h1 className="font-display text-[12px] uppercase tracking-[0.25em]"><span className="mr-2 text-primary">▍</span>Detection playground</h1>
          <p className="mt-1 max-w-3xl text-[11px] leading-relaxed text-muted">
            No account needed. Pick a traffic scenario, adjust how sensitive the detectors are, and run it. The server generates synthetic packets, parses them
            through the same pipeline used for real captures, and shows what was flagged, how the alerts chain together, and why. Nothing you do here is stored.
          </p>
        </div>

        {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{error}</p>}

        {opts && (
          <div className="grid gap-3 lg:grid-cols-[1fr_1.2fr]">
            <CyberCard title="1 · Scenario" tone="primary">
              <div role="radiogroup" aria-label="Scenario" className="space-y-1.5">
                {opts.scenarios.map((s) => (
                  <button key={s.id} role="radio" aria-checked={scenario === s.id} onClick={() => setScenario(s.id)}
                    className={cn("block w-full border px-3 py-2 text-left transition", scenario === s.id ? "border-primary bg-primary/10" : "border-border hover:border-primary/50")}>
                    <span className={cn("block text-[12px]", scenario === s.id && "text-primary")}>{s.label}</span>
                    <span className="block text-[10px] text-muted">{s.blurb}</span>
                  </button>
                ))}
              </div>
            </CyberCard>

            <CyberCard title="2 · Detector sensitivity" tone="info">
              <p className="mb-3 text-[10px] text-muted">Lower thresholds catch more but raise false alarms; higher ones stay quiet but can miss real activity.</p>
              <div className="mb-4 flex flex-wrap items-center gap-2" role="group" aria-label="Presets">
                <span className="text-[9px] uppercase tracking-[0.2em] text-muted">Presets</span>
                <button onClick={() => setValues(scaled(opts, 0.5))} className={cn(btn, "border-warning/50 text-warning hover:bg-warning/10")}>Sensitive</button>
                <button onClick={() => setValues({})} className={cn(btn, "border-border text-muted hover:border-primary hover:text-primary")}>Default</button>
                <button onClick={() => setValues(scaled(opts, 2))} className={cn(btn, "border-info/50 text-info hover:bg-info/10")}>Strict</button>
              </div>
              <div className="space-y-3">
                {opts.tunables.flatMap((t) => t.params.map((p) => {
                  const v = values[t.detector]?.[p.key] ?? p.default;
                  const id = `${t.detector}-${p.key}`;
                  return (
                    <label key={id} htmlFor={id} className="block">
                      <span className="flex items-baseline justify-between text-[11px]">
                        <span>{p.label} <span className="text-muted">· {t.detector.replace("Detector", "")}</span></span>
                        <span className={cn("tabular-nums", v !== p.default ? "text-warning" : "text-muted")}>{v.toLocaleString()}</span>
                      </span>
                      <input id={id} type="range" min={p.min} max={p.max} step={p.max > 5000 ? 100_000 : 1} value={v} className="mt-1 w-full accent-[var(--color-primary)]"
                        onChange={(e) => setValues((cur) => ({ ...cur, [t.detector]: { ...cur[t.detector], [p.key]: Number(e.target.value) } }))} />
                    </label>
                  );
                }))}
              </div>
              <div className="mt-4 flex flex-wrap items-center gap-2">
                <button disabled={busy} onClick={() => run(scenario, payload)} className="border border-primary bg-primary px-5 py-2 text-[11px] font-bold uppercase tracking-[0.2em] text-background hover:shadow-[0_0_20px_rgba(0,229,255,0.6)] disabled:opacity-40">
                  {busy ? "Running…" : "Run analysis"}
                </button>
                <button disabled={busy || !custom} onClick={() => setValues({})} className={cn(btn, "border-border text-muted hover:border-primary hover:text-primary")}>Reset</button>
                <button onClick={share} className={cn(btn, "inline-flex items-center gap-1.5 border-border text-muted hover:border-primary hover:text-primary")}><Link2 className="size-3.5" /> {copied ? "Link copied" : "Share these settings"}</button>
              </div>
            </CyberCard>
          </div>
        )}

        {opts && <Challenge thresholds={payload} />}

        {result && ran && now && (
          <div className="space-y-3 pt-1">
            <div className="flex flex-wrap items-center gap-3">
              <p className="text-[10px] uppercase tracking-[0.2em] text-muted">Result · {nameOf(ran.scenario)} · {ran.custom ? "custom thresholds" : "default thresholds"}</p>
              <button onClick={() => setPinned(now)} className={cn(btn, "inline-flex items-center gap-1.5 border-warning/50 text-warning hover:bg-warning/10")}><Pin className="size-3.5" /> Pin this run to compare</button>
              {!result.empty && <button onClick={() => setWatch((w) => !w)} className={cn(btn, "border-primary/60 text-primary hover:bg-primary hover:text-background")}>{watch ? "Hide replay" : "Watch it unfold"}</button>}
            </div>
            {pinned && <Compare base={pinned} now={now} onClear={() => setPinned(null)} />}
            {watch && !result.empty && <CyberCard title="Replay" tone="primary"><ReplayPlayer key={runId} result={result} autoPlay /></CyberCard>}
            <Results key={runId} name={nameOf(ran.scenario)} result={result}
              footer={<>Simulation only: this traffic is generated, not captured from a real network. {result.ingest?.heuristics} Thresholds in effect: {JSON.stringify(result.settings.overrides)}.</>} />
          </div>
        )}

        {opts && (
          <CyberCard title="What each detector looks for">
            <ul className="grid gap-x-6 gap-y-2 md:grid-cols-2">
              {opts.detectors.map((d) => (
                <li key={d.name} className="text-[11px]">
                  <span className="text-foreground">{d.name.replace("Detector", "")}</span>
                  {d.mitre.map((m) => <span key={m} className="ml-1.5 border border-info/50 bg-info/10 px-1 text-[9px] text-info">{m}</span>)}
                  <span className="block text-[10px] text-muted">{d.about}</span>
                </li>
              ))}
            </ul>
          </CyberCard>
        )}

        <p className="text-[10px] leading-relaxed text-muted">
          Want to analyze your own capture? Run NetSentinel locally and use the Analyze page. Uploads are limited to signed-in analysts, so the public site never parses files from strangers.
        </p>
      </div>
    </main>
  );
}
