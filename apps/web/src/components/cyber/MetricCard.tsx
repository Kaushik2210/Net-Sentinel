import { cn } from "@/lib/utils";
import { CyberCard } from "./CyberCard";

interface Props {
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: "primary" | "success" | "warning" | "danger" | "info" | "muted";
  /** Optional mini visual (sparkline, bar) rendered under the number. */
  visual?: React.ReactNode;
}

const TEXT = { primary: "text-primary glow-primary", success: "text-success glow-success", warning: "text-warning", danger: "text-danger glow-danger", info: "text-info", muted: "text-foreground" };

export function MetricCard({ label, value, hint, tone = "primary", visual }: Props) {
  return (
    <CyberCard tone={tone === "muted" ? "muted" : tone} bodyClassName="p-3">
      <div className="text-[10px] uppercase tracking-[0.2em] text-muted">{label}</div>
      <div className={cn("mt-1 font-display text-3xl font-bold tabular-nums", TEXT[tone])}>{value}</div>
      {hint && <div className="mt-0.5 text-[11px] text-muted">{hint}</div>}
      {visual && <div className="mt-2">{visual}</div>}
    </CyberCard>
  );
}
