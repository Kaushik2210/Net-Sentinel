"use client";

import { Check, X } from "lucide-react";
import { useEffect, useState } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { api } from "@/lib/api";
import type { ChallengeResult } from "@/lib/types";
import { cn } from "@/lib/utils";
import type { Thresholds } from "./share";

/**
 * Tuning game. One attacker and two harmless-but-noisy hosts are scored live against the current sliders:
 * catch every attack stage, flag nothing innocent. Re-scores a moment after the sliders stop moving.
 */
export function Challenge({ thresholds }: { thresholds: Thresholds }) {
  const [res, setRes] = useState<ChallengeResult | null>(null);
  const [error, setError] = useState(false);
  const key = JSON.stringify(thresholds);

  useEffect(() => {
    let live = true;
    const t = setTimeout(() => {
      api.challenge(JSON.parse(key) as Thresholds).then((r) => { if (live) { setRes(r); setError(false); } }).catch(() => live && setError(true));
    }, 500);
    return () => { live = false; clearTimeout(t); };
  }, [key]);

  const caught = res?.stages.filter((s) => s.caught).length ?? 0;
  return (
    <CyberCard title="Tuning challenge" tone={res?.perfect ? "success" : "warning"}>
      <p className="mb-3 text-[10px] leading-relaxed text-muted">
        One attacker (10.0.20.22) is hiding among two innocent hosts: an inventory scanner and a backup job. Move the sliders so every attack stage is caught
        and nobody innocent is flagged. Each false alarm costs 20 points.
      </p>
      {error && <p className="text-[11px] text-danger">Scoring is unavailable right now.</p>}
      {res && (
        <div className="grid gap-4 sm:grid-cols-[auto_1fr]">
          <div className="text-center">
            <div className={cn("font-display text-5xl font-black tabular-nums", res.perfect ? "text-success glow-success" : res.score >= 60 ? "text-warning" : "text-danger")}>{res.score}</div>
            <div className="text-[9px] uppercase tracking-[0.25em] text-muted">score / 100</div>
            {res.perfect && <div className="mt-2 text-[10px] uppercase tracking-[0.2em] text-success">Perfect tuning</div>}
          </div>
          <div className="space-y-3">
            <ul className="grid gap-1 sm:grid-cols-2">
              {res.stages.map((s) => (
                <li key={s.detector} className="flex items-center gap-2 text-[11px]">
                  {s.caught ? <Check className="size-3.5 text-success" /> : <X className="size-3.5 text-danger" />}
                  <span className={s.caught ? "" : "text-muted"}>{s.label}</span>
                </li>
              ))}
            </ul>
            <p className="text-[10px] text-muted">Caught {caught} of {res.stages.length} attack stages.</p>
            <div className="text-[11px]">
              {res.false_alarms.length === 0
                ? <span className="text-success">No innocent hosts flagged.</span>
                : <><span className="text-danger">{res.false_alarms.length} false alarm{res.false_alarms.length > 1 ? "s" : ""}:</span>
                  <ul className="mt-1 space-y-0.5 text-[10px] text-muted">{res.false_alarms.map((f, i) => <li key={i}>{f.source} flagged as {f.event_type.replaceAll("_", " ")} ({f.detector.replace("Detector", "")})</li>)}</ul></>}
            </div>
          </div>
        </div>
      )}
      {!res && !error && <p className="text-[11px] text-muted">Scoring…</p>}
    </CyberCard>
  );
}
