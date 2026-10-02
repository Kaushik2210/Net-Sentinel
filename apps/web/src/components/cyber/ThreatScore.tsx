import { SEVERITY, severityForRisk } from "@/lib/severity";
import type { Factor } from "@/lib/types";
import { cn } from "@/lib/utils";

/** Circular gauge for a 0-100 risk score. */
export function ThreatScore({ score, size = 84, label = "RISK" }: { score: number; size?: number; label?: string }) {
  const sev = severityForRisk(score);
  const color = SEVERITY[sev].hex;
  const r = 40;
  const circ = 2 * Math.PI * r;
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" className="-rotate-90" width={size} height={size} aria-hidden>
        <circle cx="50" cy="50" r={r} fill="none" stroke="#1b2a38" strokeWidth="6" />
        <circle
          cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="6" strokeLinecap="butt"
          strokeDasharray={`${(score / 100) * circ} ${circ}`}
          style={{ filter: `drop-shadow(0 0 4px ${color})`, transition: "stroke-dasharray .8s ease" }}
        />
      </svg>
      <div className="absolute text-center">
        <div className="font-display text-xl font-bold tabular-nums" style={{ color }}>{score}</div>
        <div className="text-[8px] tracking-[0.25em] text-muted">{label}</div>
      </div>
    </div>
  );
}

/** The exact factors behind a score. A score is never shown without this breakdown nearby. */
export function RiskFactors({ factors, total }: { factors: Factor[]; total: number }) {
  if (factors.length === 0) {
    return <p className="text-[11px] text-muted">No contributing factors: behaviour is within baseline.</p>;
  }
  const sum = factors.reduce((a, f) => a + f.points, 0);
  return (
    <ul className="space-y-1.5">
      {factors.map((f) => (
        <li key={f.key} className="grid grid-cols-[3rem_1fr] gap-x-2 text-[11px]">
          <span className={cn("text-right font-bold tabular-nums", f.points >= 15 ? "text-danger" : "text-warning")}>+{f.points}</span>
          <span>
            <span className="text-foreground">{f.label}</span>
            <span className="block text-muted">{f.detail}</span>
          </span>
        </li>
      ))}
      <li className="grid grid-cols-[3rem_1fr] gap-x-2 border-t border-border pt-1.5 text-[11px]">
        <span className="text-right font-bold tabular-nums text-primary">{total}</span>
        <span className="text-muted">{sum > total ? `total (capped at 100 from ${sum})` : "total risk score"}</span>
      </li>
    </ul>
  );
}
