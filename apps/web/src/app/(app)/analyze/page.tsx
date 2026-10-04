"use client";

import { FileUp } from "lucide-react";
import Link from "next/link";
import { useRef, useState } from "react";
import { Results } from "@/components/analyze/Results";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { ReplayResult } from "@/lib/types";
import { cn } from "@/lib/utils";

export default function AnalyzePage() {
  const { user } = useAuth();
  const canRun = !!user && user.role !== "VIEWER";
  const [state, setState] = useState<"idle" | "analyzing" | "done">("idle");
  const [name, setName] = useState("");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [result, setResult] = useState<ReplayResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  async function run(label: string, start: () => Promise<{ id: string; status: string; error: string | null }>) {
    setState("analyzing");
    setError(null);
    setName(label);
    try {
      const s = await start();
      if (s.status !== "complete") throw new Error(s.error ?? "Analysis failed");
      const full = await api.replay(s.id);
      setSessionId(s.id);
      setResult(full.result);
      setState("done");
    } catch (e) {
      setError((e as Error).message);
      setState("idle");
    }
  }

  const take = (f?: File | null) => { if (f && canRun) run(f.name, () => api.uploadPcap(f)); };

  return (
    <div className="space-y-3">
      <div>
        <h1 className="font-display text-[12px] uppercase tracking-[0.25em]"><span className="mr-2 text-primary">▍</span>Analyze a capture</h1>
        <p className="mt-1 text-[11px] text-muted">Drop a network capture and NetSentinel parses it, builds flows, runs the detectors, correlates what it finds and shows the threats with their evidence. Everything runs on this machine.</p>
      </div>
      {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{error}</p>}

      {state !== "done" && (
        <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); take(e.dataTransfer.files[0]); }}
          className={cn("grid place-items-center border-2 border-dashed px-6 py-16 text-center transition", drag ? "border-primary bg-primary/10" : "border-border-strong bg-panel/60")}>
          {state === "analyzing" ? (
            <div><p className="font-display text-sm uppercase tracking-[0.25em] text-primary">Analyzing {name}<span className="animate-blink">_</span></p>
              <p className="mt-2 text-[11px] text-muted">Parsing packets, building flows, running detectors, correlating. This usually takes a few seconds.</p></div>
          ) : (
            <div>
              <FileUp className="mx-auto size-8 text-primary" />
              <p className="mt-3 text-[13px]">{canRun ? "Drag a capture here, or" : "Sign in as an analyst or admin to analyze captures."}</p>
              {canRun && (
                <div className="mt-3 flex flex-wrap items-center justify-center gap-2">
                  <input ref={input} type="file" accept=".pcap,.pcapng,.log,.json" className="hidden" aria-label="Choose a capture file" onChange={(e) => { take(e.target.files?.[0]); e.target.value = ""; }} />
                  <button onClick={() => input.current?.click()} className="border border-primary bg-primary/10 px-4 py-2 text-[11px] uppercase tracking-[0.2em] text-primary hover:bg-primary hover:text-background">Choose file</button>
                  <button onClick={() => run("built-in sample", api.replaySample)} className="border border-border px-4 py-2 text-[11px] uppercase tracking-[0.2em] text-muted hover:border-primary hover:text-primary">Try the built-in sample</button>
                </div>
              )}
              <p className="mt-4 text-[10px] text-muted">PCAP or pcapng, or Zeek conn.log / dns.log · up to 25 MB · IPv4 · parsed on the server, never executed</p>
            </div>
          )}
        </div>
      )}

      {state === "done" && result && (
        <Results name={name} result={result}
          actions={<>
            <Link href="/replay" className="border border-border px-3 py-2 text-[10px] uppercase tracking-widest text-muted hover:border-primary hover:text-primary">Replay</Link>
            <button onClick={() => { setState("idle"); setResult(null); setSessionId(null); }} className="border border-primary px-3 py-2 text-[10px] uppercase tracking-widest text-primary hover:bg-primary hover:text-background">Analyze another</button>
          </>}
          footer={<>Session {sessionId} is saved and can be replayed on the Replay page. {result.ingest?.heuristics}
            {Object.keys(result.settings.overrides).length > 0 && ` Threshold overrides in effect: ${JSON.stringify(result.settings.overrides)}.`}</>} />
      )}
    </div>
  );
}
