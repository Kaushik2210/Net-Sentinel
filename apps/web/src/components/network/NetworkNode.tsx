"use client";

import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Camera, Cloud, Database, Globe, Monitor, Router, Server, ShieldHalf, type LucideIcon } from "lucide-react";
import { SEVERITY, severityForRisk } from "@/lib/severity";
import type { TopologyNode } from "@/lib/types";
import { cn, timeAgo } from "@/lib/utils";

export type NetNodeData = { device: TopologyNode; selected: boolean; dimmed: boolean };
export type NetNode = Node<NetNodeData, "device">;

const ICON: Record<string, LucideIcon> = {
  internet: Globe, firewall: ShieldHalf, router: Router, server: Server, database: Database,
  workstation: Monitor, iot: Camera, cloud: Cloud,
};

const hidden = "!size-1 !min-h-0 !min-w-0 !border-0 !bg-transparent";

export function NetworkNode({ data }: NodeProps<NetNode>) {
  const { device: d, selected, dimmed } = data;
  const sev = severityForRisk(d.risk_score);
  const color = SEVERITY[sev].hex;
  const risky = d.risk_score >= 25;
  const Icon = ICON[d.device_type] ?? Server;

  return (
    <div
      className={cn(
        "relative w-[104px] border bg-panel/95 px-2 py-1.5 text-center transition",
        selected ? "border-primary shadow-[0_0_18px_rgba(0,229,255,0.5)]" : risky ? "" : "border-border-strong",
        dimmed && "opacity-25",
      )}
      style={risky && !selected ? { borderColor: color, boxShadow: `0 0 14px -2px ${color}88` } : undefined}
      title={`${d.hostname} · ${d.ip} · risk ${d.risk_score} · ${d.connection_count} links · seen ${timeAgo(d.last_seen)}`}
    >
      <Handle type="target" position={Position.Top} className={hidden} />
      {risky && <span className="absolute -right-1 -top-1 size-2 animate-pulse-ring rounded-full" style={{ background: color }} />}
      <Icon className="mx-auto size-4" style={{ color: risky ? color : "#6b8594" }} />
      <div className="mt-0.5 truncate text-[10px] font-medium text-foreground">{d.hostname}</div>
      <div className="truncate text-[8px] text-muted">{d.ip}</div>
      <div className="mt-1 flex items-center justify-between text-[8px] tabular-nums text-muted">
        <span style={{ color: risky ? color : undefined }}>R{d.risk_score}</span>
        <span>{d.connection_count}↔</span>
      </div>
      <Handle type="source" position={Position.Bottom} className={hidden} />
    </div>
  );
}
