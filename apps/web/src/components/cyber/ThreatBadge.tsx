import { DETECTION_CLASS, SEVERITY, type Severity } from "@/lib/severity";
import { cn } from "@/lib/utils";

const base = "inline-flex items-center gap-1.5 border px-1.5 py-0.5 text-[10px] font-medium uppercase leading-none tracking-widest";

export function ThreatBadge({ severity, className }: { severity: Severity; className?: string }) {
  const s = SEVERITY[severity];
  return <span className={cn(base, s.text, s.bg, s.border, className)}>{s.label}</span>;
}

/** Provenance chip: RULE vs BEHAVIORAL vs ML vs CORRELATED. */
export function DetectionClassBadge({ kind, className }: { kind: keyof typeof DETECTION_CLASS; className?: string }) {
  const c = DETECTION_CLASS[kind];
  return <span className={cn(base, "bg-transparent", c.text, c.border, className)}>{c.label}</span>;
}
