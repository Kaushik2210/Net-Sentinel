"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import type { AnalystAnswer } from "@/lib/types";
import { cn } from "@/lib/utils";

const QUESTIONS: [string, string][] = [
  ["explain", "Explain this incident"], ["what_changed", "What changed?"], ["timeline", "Summarize the timeline"],
  ["evidence", "What evidence supports this?"], ["next_steps", "What to investigate next?"], ["related_events", "Show related events"],
  ["exfiltration", "Did data leave the network?"], ["report", "Generate incident report"],
];

/** Evidence-bound analyst. Every claim is shown with the IDs it cites; the API rejects uncited-evidence answers. */
export function AnalystPanel({ incidentId }: { incidentId: string }) {
  const [answer, setAnswer] = useState<AnalystAnswer | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function ask(q: string) {
    setBusy(q);
    setError(null);
    try { setAnswer(await api.ask({ incident_id: incidentId }, q)); } catch (e) { setError((e as Error).message); } finally { setBusy(null); }
  }

  return (
    <div className="space-y-3 p-3">
      <div className="flex flex-wrap gap-1.5">
        {QUESTIONS.map(([q, label]) => (
          <button key={q} disabled={!!busy} onClick={() => ask(q)} aria-pressed={answer?.question === q}
            className={cn("border px-2 py-1 text-[10px] transition disabled:opacity-40", answer?.question === q ? "border-info text-info" : "border-border text-muted hover:border-info/60 hover:text-foreground")}>{label}</button>
        ))}
      </div>
      {error && <p role="alert" className="text-[11px] text-danger">{error}</p>}
      {!answer && !error && <p className="text-[11px] text-muted">Ask a question. Answers are assembled only from this incident&apos;s stored alerts, events and risk factors.</p>}
      {answer && (
        <div className="space-y-2">
          <p className={cn("text-[9px] uppercase tracking-[0.2em]", answer.insufficient ? "text-warning" : "text-info")}>
            {answer.mode} · {answer.citations.length} cited ID(s)
          </p>
          <ul className="space-y-2">
            {answer.claims.map((c, i) => (
              <li key={i} className={cn("text-[11px] leading-relaxed", answer.insufficient && "text-warning")}>
                {c.text}
                {c.cites.length > 0 && <span className="mt-0.5 flex flex-wrap gap-1">{c.cites.slice(0, 4).map((id) => <code key={id} className="border border-border px-1 text-[9px] text-muted">{id}</code>)}{c.cites.length > 4 && <span className="text-[9px] text-muted">+{c.cites.length - 4}</span>}</span>}
              </li>
            ))}
          </ul>
          <p className="border-t border-border pt-2 text-[9px] text-muted">{answer.notice}</p>
        </div>
      )}
    </div>
  );
}
