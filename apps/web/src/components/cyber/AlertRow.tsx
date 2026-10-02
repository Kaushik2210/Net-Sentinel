"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import type { Alert, AlertDetail } from "@/lib/types";
import { cn, formatClock } from "@/lib/utils";
import { DetectionClassBadge, ThreatBadge } from "./ThreatBadge";

/** One detection. Expands to show the explanation, the structured facts and the supporting event IDs. */
export function AlertRow({ alert }: { alert: Alert }) {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<AlertDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);

  function toggle() {
    const next = !open;
    setOpen(next);
    if (next && !detail) api.alert(alert.id).then(setDetail).catch((e: Error) => setErr(e.message));
  }

  const facts = detail?.evidence.find((e) => e.kind === "facts")?.data ?? {};
  const eventIds = detail?.evidence.filter((e) => e.event_id).map((e) => e.event_id as string) ?? [];

  return (
    <li className="border-b border-border/60">
      <button onClick={toggle} aria-expanded={open} className="grid w-full grid-cols-[auto_1fr_auto] items-center gap-3 px-3 py-2 text-left hover:bg-panel-2">
        <ThreatBadge severity={alert.severity} />
        <span className="min-w-0">
          <span className="block truncate text-[12px]">{alert.event_type.replaceAll("_", " ")}</span>
          <span className="block truncate text-[10px] text-muted">{alert.source} <span className="text-primary">›</span> {alert.destination}</span>
        </span>
        <span className="text-right text-[10px] tabular-nums text-muted">
          <span className="block">{formatClock(alert.ts)}</span>
          <span className="block">{Math.round(alert.confidence * 100)}% conf</span>
        </span>
      </button>
      {open && (
        <div className="space-y-2 bg-black/30 px-3 pb-3 pt-1 text-[11px]">
          <div className="flex flex-wrap items-center gap-1.5">
            <DetectionClassBadge kind={alert.detection_class} />
            <span className="text-muted">via {alert.detector}</span>
            {alert.mitre_techniques.map((t) => <span key={t} className="border border-info/50 bg-info/10 px-1 text-[10px] text-info">{t}</span>)}
          </div>
          <p className="text-foreground">{alert.explanation}</p>
          {err ? <p className="text-danger">{err}</p> : !detail ? <p className="text-muted">Loading evidence…</p> : (
            <>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 text-[10px]">
                {Object.entries(facts).map(([k, v]) => (<div key={k} className="contents"><dt className="text-muted">{k}</dt><dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd></div>))}
              </dl>
              <p className={cn("break-all text-[10px] text-muted")}>Evidence: {eventIds.length ? eventIds.join(", ") : "none linked"}</p>
            </>
          )}
        </div>
      )}
    </li>
  );
}
