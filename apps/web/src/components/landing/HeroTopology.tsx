"use client";

import { useEffect, useState } from "react";
import { StatusDot } from "@/components/cyber/SeverityIndicator";
import { cn } from "@/lib/utils";

type Phase = "NORMAL" | "ANOMALY" | "THREAT" | "INVESTIGATION";
const PHASES: { id: Phase; ms: number; note: string }[] = [
  { id: "NORMAL", ms: 4200, note: "Baseline traffic. All devices within learned behaviour." },
  { id: "ANOMALY", ms: 3600, note: "PC-07: DNS 17.7x and SSH 24x over baseline." },
  { id: "THREAT", ms: 4200, note: "Chain: scan > SSH brute force > lateral move > upload." },
  { id: "INVESTIGATION", ms: 4200, note: "Evidence linked. 4 techniques mapped. Awaiting analyst." },
];

interface N { id: string; x: number; y: number; kind: "net" | "server" | "db" | "pc" | "iot" | "cloud" }
const NODES: N[] = [
  { id: "INTERNET", x: 300, y: 28, kind: "cloud" },
  { id: "FW-01", x: 300, y: 92, kind: "net" },
  { id: "RTR-01", x: 300, y: 158, kind: "net" },
  { id: "WEB-01", x: 150, y: 120, kind: "server" },
  { id: "MAIL-01", x: 450, y: 120, kind: "server" },
  { id: "JUMP-01", x: 190, y: 232, kind: "server" },
  { id: "APP-01", x: 300, y: 250, kind: "server" },
  { id: "AD-01", x: 410, y: 232, kind: "server" },
  { id: "DB-01", x: 120, y: 330, kind: "db" },
  { id: "DB-02", x: 240, y: 346, kind: "db" },
  { id: "PC-07", x: 360, y: 340, kind: "pc" },
  { id: "PC-12", x: 470, y: 320, kind: "pc" },
  { id: "CAM-02", x: 548, y: 236, kind: "iot" },
  { id: "S3-BACKUP", x: 70, y: 220, kind: "cloud" },
];
const EDGES: [string, string][] = [
  ["INTERNET", "FW-01"], ["FW-01", "RTR-01"], ["FW-01", "WEB-01"], ["FW-01", "MAIL-01"], ["RTR-01", "JUMP-01"],
  ["RTR-01", "APP-01"], ["RTR-01", "AD-01"], ["JUMP-01", "DB-01"], ["APP-01", "DB-02"], ["PC-07", "RTR-01"],
  ["PC-12", "RTR-01"], ["CAM-02", "RTR-01"], ["DB-01", "S3-BACKUP"], ["PC-07", "JUMP-01"], ["PC-07", "DB-02"], ["PC-07", "AD-01"],
];
// Attack path used during THREAT / INVESTIGATION.
const ATTACK: [string, string][] = [["PC-07", "JUMP-01"], ["JUMP-01", "DB-01"], ["PC-07", "DB-02"], ["PC-07", "RTR-01"], ["RTR-01", "FW-01"], ["FW-01", "INTERNET"]];

const byId = Object.fromEntries(NODES.map((n) => [n.id, n]));
const has = (list: [string, string][], a: string, b: string) => list.some(([x, y]) => (x === a && y === b) || (x === b && y === a));

function nodeTone(id: string, phase: Phase): "ok" | "warn" | "bad" {
  if (phase === "NORMAL") return "ok";
  if (id === "PC-07") return phase === "ANOMALY" ? "warn" : "bad";
  if (phase === "THREAT" || phase === "INVESTIGATION") {
    if (["JUMP-01", "DB-02", "DB-01"].includes(id)) return phase === "THREAT" ? "bad" : "warn";
  }
  return "ok";
}

const COLOR = { ok: "#00e5ff", warn: "#ffb000", bad: "#ff3b30" };

/** Hop distance from `start` along the edges (breadth first), used to time how the compromise spreads. */
function hops(start: string): Record<string, number> {
  const dist: Record<string, number> = { [start]: 0 };
  const queue = [start];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const [a, b] of EDGES) {
      const next = a === cur ? b : b === cur ? a : null;
      if (next && dist[next] === undefined) { dist[next] = dist[cur] + 1; queue.push(next); }
    }
  }
  return dist;
}

export function HeroTopology({ className }: { className?: string }) {
  const [i, setI] = useState(0);
  // Hands-on mode: click a host to compromise it and watch the intrusion spread one hop at a time.
  const [pwn, setPwn] = useState<{ id: string; dist: Record<string, number> } | null>(null);
  const [wave, setWave] = useState(0);
  useEffect(() => {
    if (pwn) return;
    const t = setTimeout(() => setI((v) => (v + 1) % PHASES.length), PHASES[i].ms);
    return () => clearTimeout(t);
  }, [i, pwn]);
  useEffect(() => {
    if (!pwn) return;
    const max = Math.max(...Object.values(pwn.dist));
    const t = setInterval(() => setWave((w) => (w >= max ? w : w + 1)), 650);
    return () => clearInterval(t);
  }, [pwn]);
  const attack = (id: string) => { setWave(0); setPwn({ id, dist: hops(id) }); };
  const hit = (id: string) => (pwn ? pwn.dist[id] !== undefined && pwn.dist[id] <= wave : false);
  const phase = pwn ? { id: "THREAT" as Phase, ms: 0, note: `${pwn.id} compromised. ${Object.values(pwn.dist).filter((d) => d <= wave).length - 1} hosts reached so far, one hop every 0.65s. Isolating ${pwn.id} early is what limits the blast radius.` } : PHASES[i];
  const attacking = !pwn && (phase.id === "THREAT" || phase.id === "INVESTIGATION");
  const reached = pwn ? Object.values(pwn.dist).filter((d) => d <= wave).length : 0;
  const threats = pwn ? reached : phase.id === "NORMAL" ? 0 : phase.id === "ANOMALY" ? 1 : 4;
  const anomalies = pwn ? Math.max(0, reached - 1) : phase.id === "NORMAL" ? 0 : phase.id === "ANOMALY" ? 2 : 5;

  return (
    <div className={cn("panel-edge relative border border-primary/25", className)}>
      <div className="flex items-center justify-between border-b border-border px-3 py-2 text-[10px] uppercase tracking-[0.2em] text-muted">
        <span className="flex items-center gap-2"><StatusDot tone={attacking ? "danger" : "success"} /> NETWORK DIGITAL TWIN</span>
        {pwn
          ? <button onClick={() => setPwn(null)} className="border border-primary/60 px-2 py-0.5 text-primary hover:bg-primary hover:text-background">RESET</button>
          : <span className="hidden sm:inline">CLICK ANY HOST TO ATTACK IT &middot; SIMULATION</span>}
      </div>

      <svg viewBox="0 0 600 390" className="w-full" role="img" aria-label="Animated network topology moving through normal, anomaly, threat and investigation stages">
        <defs>
          <filter id="glow"><feGaussianBlur stdDeviation="3" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
        </defs>
        {EDGES.map(([a, b]) => {
          const A = byId[a], B = byId[b];
          const spread = hit(a) && hit(b);
          const hot = spread || (attacking && has(ATTACK, a, b));
          const warm = !pwn && phase.id === "ANOMALY" && (a === "PC-07" || b === "PC-07");
          const col = hot ? COLOR.bad : warm ? COLOR.warn : "#1f3a4d";
          return (
            <line key={a + b} x1={A.x} y1={A.y} x2={B.x} y2={B.y} stroke={col} strokeWidth={hot ? 1.8 : 1}
              className={hot ? "edge-flow" : undefined} opacity={hot || warm ? 1 : 0.8} />
          );
        })}
        {/* Packets: ambient traffic on every edge, denser on the active chain. */}
        {EDGES.map(([a, b], k) => {
          const A = byId[a], B = byId[b];
          const hot = attacking && has(ATTACK, a, b);
          return (
            <circle key={"p" + a + b} r={hot ? 2.6 : 1.8} fill={hot ? COLOR.bad : "#39ff88"} opacity="0.9">
              <animateMotion dur={`${(hot ? 1.1 : 2.6) + (k % 5) * 0.35}s`} repeatCount="indefinite" path={`M${A.x},${A.y} L${B.x},${B.y}`} />
            </circle>
          );
        })}
        {NODES.map((n) => {
          const tone = pwn ? (hit(n.id) ? "bad" : "ok") : nodeTone(n.id, phase.id);
          const col = COLOR[tone];
          const big = n.kind === "net" || n.id === "INTERNET";
          return (
            <g key={n.id} transform={`translate(${n.x},${n.y})`} onClick={() => attack(n.id)} className="cursor-pointer"
              role="button" tabIndex={0} aria-label={`Compromise ${n.id}`} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && attack(n.id)}>
              <circle r="16" fill="transparent" />
              {tone !== "ok" && (
                <circle r="10" fill="none" stroke={col} strokeWidth="1" className="animate-pulse-ring" style={{ transformBox: "fill-box", transformOrigin: "center" }} />
              )}
              {n.kind === "db" ? (
                <rect x="-8" y="-8" width="16" height="16" fill="#05070a" stroke={col} strokeWidth="1.5" filter="url(#glow)" />
              ) : n.kind === "pc" ? (
                <rect x="-8" y="-6" width="16" height="12" rx="1" fill="#05070a" stroke={col} strokeWidth="1.5" filter="url(#glow)" />
              ) : n.kind === "iot" ? (
                <polygon points="0,-9 9,6 -9,6" fill="#05070a" stroke={col} strokeWidth="1.5" filter="url(#glow)" />
              ) : (
                <circle r={big ? 10 : 7} fill="#05070a" stroke={col} strokeWidth="1.5" filter="url(#glow)" />
              )}
              <text y={big ? 25 : 21} textAnchor="middle" fontSize="8.5" fill={tone === "ok" ? "#6b8594" : col} letterSpacing="1">{n.id}</text>
            </g>
          );
        })}
        {phase.id === "INVESTIGATION" && (
          <g transform={`translate(${byId["PC-07"].x},${byId["PC-07"].y})`}>
            <circle r="26" fill="none" stroke="#00e5ff" strokeWidth="1" strokeDasharray="4 4" className="animate-sweep" style={{ transformBox: "fill-box", transformOrigin: "center" }} />
            <text y="-34" textAnchor="middle" fontSize="8" fill="#00e5ff" letterSpacing="2">EVIDENCE LINKED</text>
          </g>
        )}
      </svg>

      <div className="grid grid-cols-1 items-center gap-3 border-t sm:grid-cols-[1fr_auto] border-border px-3 py-2">
        <div className="flex flex-wrap items-center gap-1" role="list" aria-label="Stage">
          {(pwn ? [] : PHASES).map((p, k) => (
            <span key={p.id} role="listitem" className={cn(
              "border px-1.5 py-0.5 text-[9px] tracking-[0.18em] transition-colors",
              k === i
                ? p.id === "NORMAL" ? "border-success/50 text-success" : p.id === "ANOMALY" ? "border-warning/60 text-warning" : p.id === "THREAT" ? "border-danger/60 text-danger" : "border-primary/60 text-primary"
                : "border-border text-muted/60",
            )}>{p.id}</span>
          ))}
        </div>
        <div className="flex flex-wrap gap-x-4 text-[10px] tracking-widest text-muted">
          <span>NODES <b className="text-foreground">{NODES.length}</b></span>
          <span>ANOM <b className={anomalies ? "text-warning" : "text-foreground"}>{anomalies}</b></span>
          <span>THREATS <b className={threats ? "text-danger" : "text-foreground"}>{threats}</b></span>
        </div>
        <p className="text-[11px] text-muted sm:col-span-2"><span className="text-primary">&gt;</span> {phase.note}<span className="animate-blink">_</span></p>
      </div>
    </div>
  );
}
