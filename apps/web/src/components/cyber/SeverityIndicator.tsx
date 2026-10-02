import { SEVERITY, type Severity } from "@/lib/severity";
import { cn } from "@/lib/utils";

/** Four-segment signal-strength style bar plus optional label. */
export function SeverityIndicator({ severity, showLabel = true }: { severity: Severity; showLabel?: boolean }) {
  const s = SEVERITY[severity];
  const filled = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
  return (
    <span className="inline-flex items-center gap-2" role="img" aria-label={`Severity ${s.label}`}>
      <span className="flex items-end gap-0.5" aria-hidden>
        {[1, 2, 3, 4].map((i) => (
          <span
            key={i}
            className="w-1 transition-colors"
            style={{ height: 4 + i * 3, background: i <= filled ? s.hex : "rgba(107,133,148,0.25)" }}
          />
        ))}
      </span>
      {showLabel && <span className={cn("text-[10px] tracking-widest", s.text)}>{s.label}</span>}
    </span>
  );
}

export function StatusDot({ tone = "success", pulse = true }: { tone?: "success" | "warning" | "danger" | "primary" | "muted"; pulse?: boolean }) {
  const color = { success: "bg-success", warning: "bg-warning", danger: "bg-danger", primary: "bg-primary", muted: "bg-muted" }[tone];
  return (
    <span className="relative inline-flex size-2">
      {pulse && <span className={cn("absolute inset-0 animate-pulse-ring rounded-full", color)} />}
      <span className={cn("relative size-2 rounded-full", color)} />
    </span>
  );
}
