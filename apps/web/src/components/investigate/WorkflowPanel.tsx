"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { AnalystUser, AuditEntry, IncidentDetail, Note, WorkflowStatus } from "@/lib/types";
import { cn, formatClock, timeAgo } from "@/lib/utils";

const ACTIONS: [WorkflowStatus, string, string][] = [
  ["investigating", "Mark investigating", "border-primary/60 text-primary"],
  ["resolved", "Resolve", "border-success/60 text-success"],
  ["false_positive", "False positive", "border-muted/60 text-muted"],
  ["escalated", "Escalate", "border-danger/60 text-danger"],
];

/** Status, assignment, notes and the audit trail for one incident. Writes need ANALYST or ADMIN. */
export function WorkflowPanel({ incident, onChanged }: { incident: IncidentDetail; onChanged: () => void }) {
  const { user } = useAuth();
  const canWrite = !!user && user.role !== "VIEWER";
  const [notes, setNotes] = useState<Note[]>([]);
  const [trail, setTrail] = useState<AuditEntry[]>([]);
  const [analysts, setAnalysts] = useState<AnalystUser[]>([]);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const id = incident.id;

  const load = useCallback(() => {
    Promise.all([api.notes(id), api.auditTrail(id)]).then(([n, a]) => { setNotes(n); setTrail(a); }).catch((e: Error) => setError(e.message));
  }, [id]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { api.analysts().then(setAnalysts).catch(() => undefined); }, []);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try { await fn(); load(); onChanged(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }

  return (
    <div className="space-y-4">
      {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[11px] text-danger">{error}</p>}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest text-muted">Status <b className="text-foreground">{incident.status.replace("_", " ")}</b></span>
        {canWrite && ACTIONS.map(([s, label, tone]) => (
          <button key={s} disabled={busy || incident.status === s} onClick={() => act(() => api.updateWorkflow(id, { status: s }))}
            className={cn("border px-2 py-1 text-[9px] uppercase tracking-[0.18em] transition hover:bg-panel-2 disabled:opacity-30", tone)}>{label}</button>
        ))}
        <label className="ml-auto flex items-center gap-2 text-[10px] uppercase tracking-widest text-muted">
          Assignee
          <select disabled={!canWrite || busy} value={incident.assignee ?? ""} aria-label="Assign analyst"
            onChange={(e) => act(() => api.updateWorkflow(id, { assignee: e.target.value || null }))}
            className="border border-border bg-black/60 px-1.5 py-1 text-[11px] normal-case tracking-normal text-foreground disabled:opacity-50">
            <option value="">unassigned</option>
            {analysts.map((a) => <option key={a.username} value={a.username}>{a.username}</option>)}
          </select>
        </label>
      </div>

      <div>
        <h4 className="mb-1 text-[9px] uppercase tracking-[0.25em] text-primary">Investigation notes · {notes.length}</h4>
        {canWrite && (
          <form onSubmit={(e) => { e.preventDefault(); if (draft.trim()) act(async () => { await api.addNote(id, draft.trim()); setDraft(""); }); }} className="mb-2 flex gap-2">
            <textarea value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={4000} rows={2} placeholder="Add an investigation note…" aria-label="Investigation note"
              className="min-w-0 flex-1 resize-none border border-border bg-black/50 px-2 py-1 text-[11px] outline-none focus:border-primary" />
            <button disabled={busy || !draft.trim()} className="self-end border border-primary px-3 py-1.5 text-[10px] uppercase tracking-widest text-primary hover:bg-primary hover:text-background disabled:opacity-30">Add</button>
          </form>
        )}
        {notes.length === 0 ? <p className="text-[11px] text-muted">No notes yet.</p> : (
          <ul className="max-h-44 space-y-2 overflow-y-auto">{notes.map((n) => (
            <li key={n.id} className="border-l border-primary/40 pl-3 text-[11px]"><p className="whitespace-pre-wrap">{n.body}</p><p className="text-[9px] text-muted">{n.author} · {timeAgo(n.created_at)}</p></li>))}</ul>
        )}
      </div>

      <div>
        <h4 className="mb-1 text-[9px] uppercase tracking-[0.25em] text-primary">Audit trail</h4>
        {trail.length === 0 ? <p className="text-[11px] text-muted">No recorded actions.</p> : (
          <ul className="max-h-36 space-y-0.5 overflow-y-auto font-mono text-[10px]">{trail.map((t, i) => (
            <li key={i} className="grid grid-cols-[3.8rem_5rem_1fr] gap-2"><span className="tabular-nums text-muted">{formatClock(t.ts)}</span><span className="truncate text-primary">{t.actor}</span>
              <span className="truncate text-muted">{t.action.replace("incident.", "")} {Object.keys(t.detail).length ? JSON.stringify(t.detail) : ""}</span></li>))}</ul>
        )}
      </div>
    </div>
  );
}
