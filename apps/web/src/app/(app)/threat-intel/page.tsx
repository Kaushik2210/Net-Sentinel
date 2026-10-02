"use client";

import { useCallback, useEffect, useState } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Indicator, IndicatorKind, IntelCheck, IntelMatch } from "@/lib/types";
import { cn, timeAgo } from "@/lib/utils";

const KINDS: IndicatorKind[] = ["ip", "domain", "hash", "url"];
const field = "border border-border bg-black/50 px-2 py-1.5 text-[11px] outline-none focus:border-primary";

export default function ThreatIntelPage() {
  const { user } = useAuth();
  const canWrite = !!user && user.role !== "VIEWER";
  const [items, setItems] = useState<Indicator[] | null>(null);
  const [matches, setMatches] = useState<IntelMatch[]>([]);
  const [filter, setFilter] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [kind, setKind] = useState<IndicatorKind>("ip");
  const [value, setValue] = useState("");
  const [desc, setDesc] = useState("");
  const [conf, setConf] = useState(50);
  const [checkKind, setCheckKind] = useState<IndicatorKind>("ip");
  const [checkValue, setCheckValue] = useState("");
  const [checked, setChecked] = useState<IntelCheck | null>(null);

  const load = useCallback(() => {
    api.indicators(filter || undefined).then((p) => setItems(p.items)).catch((e: Error) => setError(e.message));
    api.intelMatches().then(setMatches).catch(() => undefined);
  }, [filter]);
  useEffect(() => { load(); }, [load]);

  async function run(fn: () => Promise<unknown>) {
    setError(null);
    try { await fn(); load(); } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-3">
      <h1 className="font-display text-[12px] uppercase tracking-[0.25em]"><span className="mr-2 text-primary">▍</span>Threat intelligence</h1>
      <p className="border border-border bg-panel px-3 py-2 text-[11px] leading-relaxed text-muted">
        Local indicator store only. NetSentinel does not ship or fetch any intelligence feed: every indicator here was added by an analyst. External providers plug in through a
        documented adapter interface. A non-match never means an address or file is safe.
      </p>
      {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{error}</p>}

      <div className="grid gap-3 xl:grid-cols-[1.4fr_1fr]">
        <CyberCard title="Indicators" tone="info" bodyClassName="p-0"
          actions={<select value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter by kind" className="border border-border bg-black/60 px-1.5 py-0.5 text-[10px]"><option value="">all</option>{KINDS.map((k) => <option key={k}>{k}</option>)}</select>}>
          {canWrite && (
            <form onSubmit={(e) => { e.preventDefault(); if (value.trim()) run(async () => { await api.addIndicator({ kind, value, description: desc, confidence: conf }); setValue(""); setDesc(""); }); }} className="grid gap-2 border-b border-border p-3 sm:grid-cols-[5rem_1fr_5rem_auto]">
              <select value={kind} onChange={(e) => setKind(e.target.value as IndicatorKind)} aria-label="Indicator kind" className={field}>{KINDS.map((k) => <option key={k}>{k}</option>)}</select>
              <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="value" aria-label="Indicator value" maxLength={512} className={field} />
              <input type="number" min={0} max={100} value={conf} onChange={(e) => setConf(Number(e.target.value))} aria-label="Confidence" className={field} />
              <button disabled={!value.trim()} className="border border-primary px-3 py-1.5 text-[10px] uppercase tracking-widest text-primary hover:bg-primary hover:text-background disabled:opacity-30">Add</button>
              <input value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="description (optional)" aria-label="Description" maxLength={512} className={cn(field, "sm:col-span-4")} />
            </form>
          )}
          {!items ? <p className="p-4 text-[11px] text-muted">Loading…</p> : items.length === 0 ? <p className="p-5 text-center text-[11px] text-muted">No indicators. {canWrite ? "Add one above." : "An analyst can add indicators."}</p> : (
            <ul>{items.map((i) => (
              <li key={i.id} className="grid grid-cols-[3.5rem_1fr_auto] items-start gap-3 border-b border-border/60 px-3 py-2">
                <span className="border border-info/40 px-1 py-0.5 text-center text-[9px] uppercase tracking-widest text-info">{i.kind}</span>
                <span className="min-w-0"><span className="block break-all text-[12px]">{i.value}</span><span className="block text-[10px] text-muted">{i.description || "no description"} · {i.source} · conf {i.confidence} · {timeAgo(i.created_at)}</span></span>
                {user?.role === "ADMIN" && <button onClick={() => run(() => api.deleteIndicator(i.id))} className="text-[10px] uppercase tracking-widest text-muted hover:text-danger">Delete</button>}
              </li>))}</ul>
          )}
        </CyberCard>

        <div className="space-y-3">
          <CyberCard title="Check an indicator" tone="primary">
            <form onSubmit={(e) => { e.preventDefault(); if (checkValue.trim()) run(async () => setChecked(await api.checkIndicator(checkKind, checkValue))); }} className="flex gap-2">
              <select value={checkKind} onChange={(e) => setCheckKind(e.target.value as IndicatorKind)} aria-label="Check kind" className={field}>{KINDS.map((k) => <option key={k}>{k}</option>)}</select>
              <input value={checkValue} onChange={(e) => setCheckValue(e.target.value)} placeholder="value to look up" aria-label="Value to check" className={cn(field, "min-w-0 flex-1")} />
              <button className="border border-border px-3 text-[10px] uppercase tracking-widest text-muted hover:border-primary hover:text-primary">Check</button>
            </form>
            {checked && (
              <div className="mt-3 text-[11px]" role="status">
                <p className={checked.matched ? "text-danger" : "text-muted"}>{checked.matched ? `Match in ${checked.hits.length} record(s)` : "No match in the providers checked."}</p>
                <p className="text-[10px] text-muted">providers: {checked.providers_checked.join(", ")}</p>
                {checked.hits.map((h, i) => <p key={i} className="mt-1">{h.description || h.value} <span className="text-muted">· {h.source} · conf {h.confidence}</span></p>)}
              </div>
            )}
          </CyberCard>
          <CyberCard title="Seen in recent telemetry" tone="danger">
            {matches.length === 0 ? <p className="text-[11px] text-muted">No indicator appears in the last 24 hours of alerts or events.</p> : (
              <ul className="space-y-2">{matches.map((m) => (
                <li key={m.indicator_id} className="text-[11px]"><span className="text-danger">{m.value}</span> <span className="text-muted">({m.kind}, conf {m.confidence}) in {m.where}</span>
                  <p className="text-[10px] text-muted">{m.alert_ids.length} alert(s), {m.event_ids.length} event(s)</p></li>))}</ul>
            )}
          </CyberCard>
        </div>
      </div>
    </div>
  );
}
