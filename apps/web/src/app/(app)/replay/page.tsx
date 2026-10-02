"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { ReplayPlayer } from "@/components/replay/ReplayPlayer";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { ReplayResult, ReplaySummary } from "@/lib/types";
import { cn, timeAgo } from "@/lib/utils";

export default function ReplayPage() {
  const { user } = useAuth();
  const canWrite = user && user.role !== "VIEWER";
  const [sessions, setSessions] = useState<ReplaySummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [result, setResult] = useState<ReplayResult | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const refresh = useCallback(() => {
    api.replays().then(setSessions).catch((e: Error) => setError(e.message));
  }, []);
  useEffect(refresh, [refresh]);

  useEffect(() => {
    if (!activeId) return;
    let live = true;
    api.replay(activeId)
      .then((r) => live && setResult(r.result))
      .catch((e: Error) => live && setError(e.message));
    return () => { live = false; };
  }, [activeId]);

  async function run(label: string, fn: () => Promise<ReplaySummary>) {
    setBusy(label);
    setError(null);
    try {
      const s = await fn();
      if (s.status === "failed") setError(s.error ?? "Replay failed");
      else { setResult(null); setActiveId(s.id); }
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="font-display text-[12px] uppercase tracking-[0.25em]"><span className="mr-2 text-primary">▍</span>Attack replay</h1>
        {canWrite && (
          <>
            <button disabled={!!busy} onClick={() => run("sample", api.replaySample)} className="border border-primary bg-primary/10 px-3 py-1.5 text-[10px] uppercase tracking-[0.2em] text-primary hover:bg-primary hover:text-background disabled:opacity-40">
              {busy === "sample" ? "Building replay…" : "Replay synthetic sample"}
            </button>
            <input ref={fileRef} type="file" accept=".pcap,.pcapng,.log,.json" className="hidden" aria-label="Upload PCAP or Zeek log"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) run("upload", () => api.uploadPcap(f)); e.target.value = ""; }} />
            <button disabled={!!busy} onClick={() => fileRef.current?.click()} className="border border-border px-3 py-1.5 text-[10px] uppercase tracking-[0.2em] text-muted hover:border-primary hover:text-primary disabled:opacity-40">
              {busy === "upload" ? "Analysing capture…" : "Upload PCAP / Zeek log"}
            </button>
          </>
        )}
        <span className="text-[10px] text-muted">PCAP or Zeek conn.log/dns.log (TSV or JSON) · max 25 MB · IPv4 · parsed server-side, never executed</span>
      </div>
      {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{error}</p>}

      <div className="grid gap-3 xl:grid-cols-[260px_1fr]">
        <CyberCard title="Sessions" tone="muted" bodyClassName="p-0" className="xl:self-start">
          {!sessions ? <p className="p-4 text-[11px] text-muted">Loading…</p> : sessions.length === 0 ? (
            <p className="p-4 text-[11px] leading-relaxed text-muted">No replays yet.{canWrite ? " Run the synthetic sample to see the pipeline, or upload a capture." : " An analyst can create one."}</p>
          ) : (
            <ul>{sessions.map((s) => (
              <li key={s.id}><button onClick={() => { setResult(null); setActiveId(s.id); }} aria-pressed={s.id === activeId}
                className={cn("w-full border-b border-border/60 px-3 py-2 text-left hover:bg-panel-2", s.id === activeId && "bg-primary/5")}>
                <div className="truncate text-[12px]">{s.filename}</div>
                <div className="text-[10px] text-muted">{s.status === "complete" ? `${s.packet_count} pkts · ${s.alert_count} alerts` : s.status} · {timeAgo(s.created_at)}</div>
              </button></li>))}</ul>
          )}
        </CyberCard>

        <div className="min-w-0 space-y-3">
          {!activeId ? <CyberCard><p className="py-14 text-center text-[11px] uppercase tracking-[0.25em] text-muted">Select or create a replay</p></CyberCard>
            : !result ? <CyberCard><p className="py-14 text-center text-[11px] uppercase tracking-[0.25em] text-muted">Loading replay<span className="animate-blink">_</span></p></CyberCard>
            : result.empty ? <CyberCard><p className="py-10 text-center text-[12px] text-muted">The capture contained no analysable events.</p></CyberCard>
            : (
              <>
                <ReplayPlayer key={activeId} result={result} />
                <CyberCard title="How this replay was built" tone="muted">
                  <p className="text-[11px] leading-relaxed text-muted">
                    {result.ingest?.packets} packets → {result.ingest?.flows} flows → {result.ingest?.events} events → detection run incrementally → correlation.{" "}
                    {result.ingest?.heuristics} ML anomaly detection is excluded from replay.
                    {Object.keys(result.settings.overrides).length > 0 && (<> Threshold overrides for this synthetic sample: <code className="text-warning">{JSON.stringify(result.settings.overrides)}</code> (the real exfiltration default is 100 MB, which a small sample cannot carry).</>)}
                    {result.ingest?.truncated && <span className="text-warning"> Capture was truncated: {result.ingest.notes.join("; ")}.</span>}
                  </p>
                </CyberCard>
              </>
            )}
        </div>
      </div>
    </div>
  );
}
