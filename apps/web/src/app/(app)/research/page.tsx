"use client";

import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CyberCard } from "@/components/cyber/CyberCard";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { MethodMetrics, ResearchPayload } from "@/lib/types";
import { cn } from "@/lib/utils";

const METHODS = ["rule", "ml", "hybrid"] as const;
const LABEL = { rule: "Rule-based", ml: "ML (Isolation Forest)", hybrid: "Hybrid (union)" };
const COLOR = { rule: "#00e5ff", ml: "#9d5cff", hybrid: "#39ff88" };
const pct = (v: number | null) => (v === null ? "n/a" : `${(v * 100).toFixed(1)}%`);

function Confusion({ m }: { m: MethodMetrics }) {
  const cell = "border border-border px-3 py-2 text-center tabular-nums";
  return (
    <table className="w-full text-[11px]" aria-label="Confusion matrix">
      <thead><tr><th /><th className="px-2 text-[9px] font-normal uppercase tracking-widest text-muted">Pred. attack</th><th className="px-2 text-[9px] font-normal uppercase tracking-widest text-muted">Pred. benign</th></tr></thead>
      <tbody>
        <tr><th className="pr-2 text-left text-[9px] font-normal uppercase tracking-widest text-muted">Actual attack</th><td className={cn(cell, "bg-success/10 text-success")}>{m.tp}</td><td className={cn(cell, "bg-danger/10 text-danger")}>{m.fn}</td></tr>
        <tr><th className="pr-2 text-left text-[9px] font-normal uppercase tracking-widest text-muted">Actual benign</th><td className={cn(cell, "bg-warning/10 text-warning")}>{m.fp}</td><td className={cn(cell, "bg-success/5 text-muted")}>{m.tn}</td></tr>
      </tbody>
    </table>
  );
}

export default function ResearchPage() {
  const { user } = useAuth();
  const canRun = !!user && user.role !== "VIEWER";
  const [data, setData] = useState<ResearchPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    let live = true;
    api.research().then((d) => live && setData(d)).catch((e: Error) => live && setError(e.message));
    return () => { live = false; };
  }, []);

  async function run() {
    setRunning(true);
    setError(null);
    try { setData(await api.runResearch()); } catch (e) { setError((e as Error).message); } finally { setRunning(false); }
  }

  const r = data?.result;
  const chart = r ? (["precision", "recall", "f1"] as const).map((k) => ({ metric: k === "f1" ? "F1" : k[0].toUpperCase() + k.slice(1), ...Object.fromEntries(METHODS.map((m) => [m, +(((r.methods[m][k] ?? 0) as number) * 100).toFixed(1)])) })) : [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="font-display text-[12px] uppercase tracking-[0.25em]"><span className="mr-2 text-primary">▍</span>Research mode</h1>
        {canRun && <button disabled={running} onClick={run} className="border border-primary bg-primary/10 px-3 py-1.5 text-[10px] uppercase tracking-[0.2em] text-primary hover:bg-primary hover:text-background disabled:opacity-40">{running ? "Running evaluation (~25 s)…" : r ? "Re-run evaluation" : "Run evaluation"}</button>}
        {r && <span className="text-[10px] tracking-widest text-muted">{r.trials} TRIALS · SEED {r.seed}</span>}
      </div>
      <p className="border border-warning/30 bg-warning/5 px-3 py-2 text-[11px] leading-relaxed text-warning">
        Synthetic benchmark. The data, attacks and detector thresholds were written by the same author, so these results demonstrate the methodology and the rule/ML trade-off on controlled cases.
        They are not evidence of real-world accuracy.
      </p>
      {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{error}</p>}

      {!data ? <p className="py-10 text-center text-[11px] uppercase tracking-[0.3em] text-muted">Loading…</p> : !r ? (
        <CyberCard><p className="py-8 text-center text-[12px] text-muted">No evaluation has been run yet.{canRun ? " Run it to compare rule-based, ML and hybrid detection." : " An analyst can run it."}</p></CyberCard>
      ) : (
        <>
          <div className="grid gap-3 xl:grid-cols-[1.3fr_1fr]">
            <CyberCard title="Rule vs ML vs hybrid" tone="primary" bodyClassName="p-0">
              <div className="overflow-x-auto"><table className="w-full text-[11px]">
                <thead><tr className="border-b border-border text-[9px] uppercase tracking-widest text-muted"><th className="px-3 py-2 text-left">Method</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>Latency (median)</th></tr></thead>
                <tbody>{METHODS.map((m) => { const v = r.methods[m]; return (
                  <tr key={m} className="border-b border-border/60 text-center tabular-nums"><td className="px-3 py-2.5 text-left" style={{ color: COLOR[m] }}>{LABEL[m]}</td><td>{pct(v.precision)}</td><td>{pct(v.recall)}</td><td>{pct(v.f1)}</td><td>{pct(v.fpr)}</td>
                    <td>{v.latency_median_s === null ? "n/a" : `${v.latency_median_s.toFixed(0)} s`}{v.latency_missed > 0 && <span className="text-warning"> ({v.latency_missed} missed)</span>}</td></tr>); })}</tbody>
              </table></div>
              <p className="px-3 py-2 text-[10px] text-muted">{r.latency_note} Unit: {r.dataset.unit}; {r.dataset.attack_windows} attack and {r.dataset.benign_windows} benign windows.</p>
            </CyberCard>
            <CyberCard title="Metrics (%)" tone="muted">
              <div className="h-52" role="img" aria-label="Precision, recall and F1 by method">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chart} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
                    <CartesianGrid stroke="#1b2a38" vertical={false} />
                    <XAxis dataKey="metric" stroke="#6b8594" fontSize={10} /><YAxis domain={[0, 100]} stroke="#6b8594" fontSize={10} />
                    <Tooltip contentStyle={{ background: "#090d12", border: "1px solid #1b2a38", fontSize: 11 }} cursor={{ fill: "rgba(0,229,255,0.05)" }} />
                    <Legend wrapperStyle={{ fontSize: 10 }} />
                    {METHODS.map((m) => <Bar key={m} dataKey={m} name={LABEL[m]} fill={COLOR[m]} />)}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CyberCard>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            {METHODS.map((m) => <CyberCard key={m} title={`Confusion · ${LABEL[m]}`} tone={m === "ml" ? "info" : m === "hybrid" ? "success" : "primary"}><Confusion m={r.methods[m]} /></CyberCard>)}
          </div>

          <CyberCard title="Recall by attack and intensity" tone="muted" bodyClassName="p-0">
            <div className="overflow-x-auto"><table className="w-full text-[11px]">
              <thead><tr className="border-b border-border text-[9px] uppercase tracking-widest text-muted"><th className="px-3 py-2 text-left">Attack</th>{(["strong", "subtle"] as const).flatMap((i) => METHODS.map((m) => <th key={i + m} className="px-2">{i} · {m}</th>))}</tr></thead>
              <tbody>{Object.entries(r.recall_by_attack).map(([a, v]) => (
                <tr key={a} className="border-b border-border/60 text-center tabular-nums"><td className="px-3 py-2 text-left">{a.replaceAll("_", " ")}</td>
                  {(["strong", "subtle"] as const).flatMap((i) => METHODS.map((m) => { const x = v[i][m]; return <td key={i + m} className={cn(x >= 0.99 ? "bg-success/15 text-success" : x > 0 ? "bg-warning/10 text-warning" : "text-muted/60")}>{Math.round(x * 100)}%</td>; }))}</tr>))}</tbody>
            </table></div>
            <p className="px-3 py-2 text-[10px] text-muted">Strong = {r.dataset.intensities.strong}. Subtle = {r.dataset.intensities.subtle}. Subtle cases were built to fall below rule thresholds, which favours non-threshold methods.</p>
          </CyberCard>

          <div className="grid gap-3 md:grid-cols-2">
            <CyberCard title="Model and features" tone="info">
              <p className="text-[11px]">{r.model.algorithm} · {r.model.training_windows} training windows · {r.model.trained_on}</p>
              <p className="mt-2 text-[10px] leading-relaxed text-muted">{r.model.features.join(" · ")}</p>
            </CyberCard>
            <CyberCard title="Caveats" tone="warning"><ul className="list-disc space-y-1 pl-4 text-[11px] text-muted">{r.caveats.map((c) => <li key={c}>{c}</li>)}</ul></CyberCard>
          </div>
        </>
      )}

      <CyberCard title="Dataset support" tone="muted" bodyClassName="p-0">
        <ul>{data?.supported_datasets.map((d) => (
          <li key={d.name} className="grid grid-cols-[12rem_10rem_1fr] gap-3 border-b border-border/60 px-3 py-2 text-[11px]"><span>{d.name}</span><span className={d.status === "available" ? "text-success" : "text-muted"}>{d.status}</span><span className="text-muted">{d.note}</span></li>))}</ul>
      </CyberCard>
    </div>
  );
}
