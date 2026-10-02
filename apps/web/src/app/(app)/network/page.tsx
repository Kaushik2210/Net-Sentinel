"use client";

import "@xyflow/react/dist/style.css";
import { Background, BackgroundVariant, Controls, MarkerType, MiniMap, ReactFlow, type Edge } from "@xyflow/react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { DeviceIntelligence } from "@/components/network/DeviceIntelligence";
import { NetworkNode, type NetNode } from "@/components/network/NetworkNode";
import { ParamSync } from "@/components/shell/ParamSync";
import { api } from "@/lib/api";
import { SEVERITY, severityForRisk } from "@/lib/severity";
import type { Topology } from "@/lib/types";
import { cn } from "@/lib/utils";

const nodeTypes = { device: NetworkNode };
const TYPES = ["all", "firewall", "router", "server", "database", "workstation", "iot", "cloud"] as const;

export default function NetworkPage() {
  const [topo, setTopo] = useState<Topology | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [type, setType] = useState<(typeof TYPES)[number]>("all");
  const [q, setQ] = useState("");
  const [onlyRisky, setOnlyRisky] = useState(false);

  const onDevice = useCallback((id: string) => setSelected(id), []);

  useEffect(() => {
    let live = true;
    api.topology().then((t) => live && setTopo(t)).catch((e: Error) => live && setError(e.message));
    return () => { live = false; };
  }, []);

  const query = q.trim().toLowerCase();
  const matches = (n: Topology["nodes"][number]) =>
    (type === "all" || n.device_type === type) &&
    (!onlyRisky || n.risk_score >= 25) &&
    (!query || n.hostname.toLowerCase().includes(query) || n.ip.includes(query));

  const nodes: NetNode[] = useMemo(
    () => (topo?.nodes ?? []).map((d) => ({
      id: d.id, type: "device" as const, position: d.position, draggable: true,
      data: { device: d, selected: d.id === selected, dimmed: !matches(d) },
    })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [topo, selected, type, query, onlyRisky],
  );

  const edges: Edge[] = useMemo(
    () => (topo?.edges ?? []).map((e) => {
      const hot = e.suspicious;
      const touchesSel = selected && (e.source === selected || e.target === selected);
      const width = 1 + Math.min(3.5, Math.max(0, Math.log10(Math.max(e.bytes_per_hour, 1)) - 5) * 0.9);
      const color = hot ? "#ff3b30" : touchesSel ? "#00e5ff" : "#27465c";
      return {
        id: e.id, source: e.source, target: e.target, animated: hot || e.connections_per_hour > 400,
        style: { stroke: color, strokeWidth: width, opacity: selected && !touchesSel && !hot ? 0.35 : 1 },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 12, height: 12 },
        label: touchesSel ? `${e.protocol}${e.port ? ":" + e.port : ""}` : undefined,
        labelStyle: { fill: "#00e5ff", fontSize: 9 }, labelBgStyle: { fill: "#05070a" },
      };
    }),
    [topo, selected],
  );

  const visible = topo ? topo.nodes.filter(matches).length : 0;

  return (
    <div className="-m-4 flex h-[calc(100vh-3.5rem)] flex-col">
      <ParamSync name="device" onValue={onDevice} />
      <div className="flex flex-wrap items-center gap-3 border-b border-border bg-surface/80 px-4 py-2">
        <h1 className="font-display text-[12px] uppercase tracking-[0.25em]"><span className="mr-2 text-primary">▍</span>Network digital twin</h1>
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="find hostname or IP…" aria-label="Find device"
          className="w-48 border border-border bg-black/50 px-2 py-1 text-[11px] outline-none focus:border-primary" />
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by type">
          {TYPES.map((t) => (
            <button key={t} onClick={() => setType(t)} aria-pressed={type === t}
              className={cn("border px-2 py-0.5 text-[9px] uppercase tracking-widest", type === t ? "border-primary bg-primary/10 text-primary" : "border-border text-muted hover:text-foreground")}>{t}</button>
          ))}
        </div>
        <label className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-muted">
          <input type="checkbox" checked={onlyRisky} onChange={(e) => setOnlyRisky(e.target.checked)} className="accent-primary" /> off-baseline only
        </label>
        <span className="ml-auto text-[10px] tracking-widest text-muted">{topo ? `${visible}/${topo.nodes.length} NODES` : ""}</span>
      </div>

      <div className="flex min-h-0 flex-1">
        <div className="relative min-w-0 flex-1">
          {error ? (
            <div className="grid h-full place-items-center text-[12px] text-danger">{error}</div>
          ) : !topo ? (
            <div className="grid h-full place-items-center text-[11px] uppercase tracking-[0.3em] text-muted">Mapping network<span className="animate-blink">_</span></div>
          ) : topo.nodes.length === 0 ? (
            <div className="grid h-full place-items-center text-[12px] text-muted">No devices discovered yet.</div>
          ) : (
            <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.12 }} minZoom={0.15} maxZoom={1.8}
              onNodeClick={(_, n) => setSelected(n.id)} onPaneClick={() => setSelected(null)} nodesConnectable={false} proOptions={{ hideAttribution: true }}
              colorMode="dark">
              <Background variant={BackgroundVariant.Lines} gap={44} color="rgba(0,229,255,0.05)" />
              <Controls showInteractive={false} />
              <MiniMap pannable zoomable maskColor="rgba(5,7,10,0.8)" style={{ background: "#090d12", border: "1px solid #1b2a38" }}
                nodeColor={(n) => SEVERITY[severityForRisk((n.data as { device: { risk_score: number } }).device.risk_score)].hex} />
            </ReactFlow>
          )}
          <div className="pointer-events-none absolute bottom-3 left-14 border border-border bg-background/80 px-2 py-1 text-[9px] uppercase tracking-widest text-muted">
            <span className="text-danger">━</span> suspicious &nbsp;<span className="text-primary">━</span> selected &nbsp;line width = traffic/h &nbsp;dash = active
          </div>
        </div>
        {selected && (
          <div className="hidden w-[380px] shrink-0 md:block">
            <DeviceIntelligence deviceId={selected} onClose={() => setSelected(null)} onSelect={setSelected} />
          </div>
        )}
      </div>
    </div>
  );
}
