"use client";

import { motion } from "framer-motion";
import { SEVERITY } from "@/lib/severity";
import type { IncidentStep } from "@/lib/types";
import { cn, formatClock } from "@/lib/utils";

interface Props { steps: IncidentStep[]; selected: number; onSelect: (position: number) => void }

/** Animated, clickable kill-chain. Each step draws in sequence; links show why steps were joined. */
export function AttackChain({ steps, selected, onSelect }: Props) {
  return (
    <ol className="relative pl-2" aria-label="Attack chain">
      {steps.map((s, i) => {
        const col = SEVERITY[s.severity].hex;
        const active = s.position === selected;
        return (
          <li key={s.position} className="relative pb-1">
            {i < steps.length - 1 && (
              <motion.span
                aria-hidden
                className="absolute left-[15px] top-8 w-px origin-top bg-gradient-to-b from-border-strong to-border"
                style={{ height: "calc(100% - 1rem)" }}
                initial={{ scaleY: 0 }}
                animate={{ scaleY: 1 }}
                transition={{ duration: 0.35, delay: i * 0.22 + 0.15 }}
              />
            )}
            <motion.button
              onClick={() => onSelect(s.position)}
              aria-current={active ? "step" : undefined}
              initial={{ opacity: 0, x: -14 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.35, delay: i * 0.22 }}
              className={cn("group grid w-full grid-cols-[2rem_1fr] gap-3 border border-transparent px-1 py-2 text-left transition", active ? "border-primary/40 bg-primary/5" : "hover:bg-panel-2")}
            >
              <span className="relative mt-0.5 grid size-7 place-items-center border bg-background text-[10px] font-bold tabular-nums" style={{ borderColor: col, color: col, boxShadow: `0 0 10px -2px ${col}` }}>
                {i + 1}
                {active && <span className="absolute inset-0 animate-pulse-ring border" style={{ borderColor: col }} />}
              </span>
              <span className="min-w-0">
                <span className="flex flex-wrap items-baseline gap-x-3">
                  <span className="font-display text-[12px] font-bold uppercase tracking-wider">{s.stage}</span>
                  <span className="text-[10px] tabular-nums text-muted">{formatClock(s.timestamp)}</span>
                  {s.mitre.slice(0, 3).map((t) => <span key={t} className="text-[10px] tracking-widest text-info">{t}</span>)}
                </span>
                <span className="mt-0.5 block truncate text-[11px] text-muted">{s.explanation}</span>
                {i > 0 && <span className="mt-0.5 block text-[9px] uppercase tracking-widest text-muted/70">↳ {s.link_reason} · link {Math.round(s.link_confidence * 100)}%</span>}
              </span>
            </motion.button>
          </li>
        );
      })}
    </ol>
  );
}
