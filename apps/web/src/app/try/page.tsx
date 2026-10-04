"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Results } from "@/components/analyze/Results";
import { CyberCard } from "@/components/cyber/CyberCard";
import { Logo } from "@/components/cyber/Logo";
import { api } from "@/lib/api";
import type { PlaygroundOptions, ReplayResult } from "@/lib/types";
import { cn } from "@/lib/utils";

type Thresholds = Record<string, Record<string, number>>;

/** Public, no-login playground: pick a generated scenario, tune detector thresholds and see what gets flagged. */
export default function TryPage() {
  const [opts, setOpts] = useState<PlaygroundOptions | null>(null);
  const [scenario, setScenario] = useState("full");
  const [values, setValues] = useState<Thresholds>({});
  const [result, setResult] = useState<ReplayResult | null>(null);
  const [ran, setRan] = useState<{ scenario: string; custom: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  const run = useCallback(async (sc: string, th: Thresholds) => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.playground(sc, th);
      setResult(res.result);
      setRan({ scenario: sc, custom: Object.keys(th).length > 0 });
    } catch (e) {
      setError((e as Error).message || "The run failed.");
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    api.playgroundOptions().then((o) => { setOpts(o); return run("full", {}); }).catch(() => setError("The playground API is not reachable."));
  }, [run]);

  const defaultOf = (det: string, key: string) => opts?.tunables.find((t) => t.detector === det)?.params.find((p) => p.key === key)?.default;
  // Only send values that differ from the defaults, so "default thresholds" really means none were changed.
  const payload = (): Thresholds => {
    const out: Thresholds = {};
    for (const [d, ps] of Object.entries(values)) for (const [k, v] of Object.entries(ps)) {
      if (v !== defaultOf(d, k)) (out[d] ??= {})[k] = v;
    }
    return out;
  };
  const custom = Object.keys(payload()).length > 0;
  const nameOf = (id: string) => opts?.scenarios.find((s) => s.id === id)?.label ?? id;

  return (
    <main className="bg-grid bg-vignette min-h-screen">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
        <Logo />
        <nav className="flex items-center gap-3 text-[11px] uppercase tracking-[0.2em]">
          <Link href="/" className="text-muted hover:text-primary">Home</Link>
          <Link href="/login" className="border border-primary/60 bg-primary/10 px-3 py-1.5 text-primary hover:bg-primary hover:text-background">Sign in</Link>
        </nav>
      </header>

      <div className="mx-auto max-w-6xl space-y-3 px-4 pb-16">
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
              <p className="mb-3 text-[10px] text-muted">Lower thresholds catch more but raise false alarms; higher ones stay quiet but can miss real activity. Try making the port scan detector stricter, or the brute force one looser.</p>
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
                <button disabled={busy} onClick={() => run(scenario, payload())} className="border border-primary bg-primary px-5 py-2 text-[11px] font-bold uppercase tracking-[0.2em] text-background hover:shadow-[0_0_20px_rgba(0,229,255,0.6)] disabled:opacity-40">
                  {busy ? "Running…" : "Run analysis"}
                </button>
                <button disabled={busy || !custom} onClick={() => setValues({})} className="border border-border px-4 py-2 text-[11px] uppercase tracking-[0.2em] text-muted hover:border-primary hover:text-primary disabled:opacity-30">Reset to defaults</button>
              </div>
            </CyberCard>
          </div>
        )}

        {result && ran && (
          <div className="space-y-3 pt-1">
            <p className="text-[10px] uppercase tracking-[0.2em] text-muted">Result · {nameOf(ran.scenario)} · {ran.custom ? "custom thresholds" : "default thresholds"}</p>
            <Results name={nameOf(ran.scenario)} result={result}
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
