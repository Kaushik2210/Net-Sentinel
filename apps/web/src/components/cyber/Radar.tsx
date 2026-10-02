import { cn } from "@/lib/utils";

export interface Blip { angle: number; radius: number; tone?: "primary" | "warning" | "danger" }

const TONE = { primary: "#00e5ff", warning: "#ffb000", danger: "#ff3b30" };

/** Retro radar scope with a rotating sweep. Blips are supplied by the caller (never invented here). */
export function Radar({ size = 160, blips = [], className }: { size?: number; blips?: Blip[]; className?: string }) {
  const c = 50;
  return (
    <svg viewBox="0 0 100 100" width={size} height={size} className={cn("overflow-visible", className)} role="img" aria-label="Radar scope">
      <defs>
        <radialGradient id="radar-bg" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#00e5ff" stopOpacity="0.10" />
          <stop offset="100%" stopColor="#00e5ff" stopOpacity="0" />
        </radialGradient>
        <linearGradient id="sweep-grad" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#39ff88" stopOpacity="0" />
          <stop offset="100%" stopColor="#39ff88" stopOpacity="0.55" />
        </linearGradient>
      </defs>
      <circle cx={c} cy={c} r="48" fill="url(#radar-bg)" stroke="#1b2a38" strokeWidth="0.6" />
      {[16, 32, 48].map((r) => <circle key={r} cx={c} cy={c} r={r} fill="none" stroke="#1b2a38" strokeWidth="0.5" />)}
      <path d="M50 2V98M2 50H98" stroke="#1b2a38" strokeWidth="0.5" />
      <g className="origin-center animate-sweep" style={{ transformOrigin: "50px 50px" }}>
        <path d="M50 50 L98 50 A48 48 0 0 0 91 26 Z" fill="url(#sweep-grad)" transform="rotate(-30 50 50)" />
        <line x1="50" y1="50" x2="98" y2="50" stroke="#39ff88" strokeWidth="0.6" />
      </g>
      {blips.map((b, i) => {
        const a = (b.angle * Math.PI) / 180;
        const x = c + Math.cos(a) * b.radius * 0.46;
        const y = c + Math.sin(a) * b.radius * 0.46;
        const col = TONE[b.tone ?? "primary"];
        return (
          <g key={i}>
            <circle cx={x} cy={y} r="1.6" fill={col} />
            <circle cx={x} cy={y} r="1.6" fill="none" stroke={col} strokeWidth="0.4" className="animate-pulse-ring" style={{ transformOrigin: `${x}px ${y}px`, transformBox: "fill-box" }} />
          </g>
        );
      })}
    </svg>
  );
}
