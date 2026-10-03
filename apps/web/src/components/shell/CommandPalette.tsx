"use client";

import { Search } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { DeviceSummary, IncidentSummary, MitreMatrix } from "@/lib/types";
import { cn } from "@/lib/utils";

interface Cmd { id: string; group: string; label: string; hint?: string; href: string; keywords?: string }

const NAV: Cmd[] = [
  { id: "n-dash", group: "Navigate", label: "Open command center", href: "/dashboard", keywords: "dashboard home" },
  { id: "n-net", group: "Navigate", label: "Open network", href: "/network", keywords: "topology twin devices" },
  { id: "n-inc", group: "Navigate", label: "Open incidents", href: "/incidents", keywords: "attack chain timeline" },
  { id: "n-inv", group: "Navigate", label: "Open investigation workspace", href: "/investigate", keywords: "analyst notes" },
  { id: "n-rep", group: "Navigate", label: "Open attack replay", href: "/replay", keywords: "pcap play" },
  { id: "n-mit", group: "Navigate", label: "Search MITRE", href: "/mitre", keywords: "att&ck technique matrix" },
  { id: "n-ti", group: "Navigate", label: "Open threat intel", href: "/threat-intel", keywords: "indicators ioc" },
  { id: "n-res", group: "Navigate", label: "Open research mode", href: "/research", keywords: "evaluation metrics" },
  { id: "n-ana", group: "Navigate", label: "Analyze a capture", hint: "upload pcap", href: "/analyze", keywords: "upload pcap zeek threats scan file" },
  { id: "n-demo", group: "Navigate", label: "Start attack demonstration", href: "/demo", keywords: "demo simulation" },
  { id: "n-crit", group: "Navigate", label: "Show critical alerts", hint: "detections panel", href: "/dashboard", keywords: "alerts severity detections" },
];

/** Global Ctrl/Cmd+K palette: navigation plus live search over devices, IPs, incidents and MITRE techniques. */
export function CommandPalette() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const [devices, setDevices] = useState<DeviceSummary[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [matrix, setMatrix] = useState<MitreMatrix | null>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setOpen((o) => !o); }
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    if (!open) return;
    input.current?.focus();
    let live = true;
    api.incidents().then((p) => live && setIncidents(p.items)).catch(() => undefined);
    api.mitre().then((m) => live && setMatrix(m)).catch(() => undefined);
    return () => { live = false; };
  }, [open]);

  useEffect(() => {
    if (!open || q.trim().length < 2) return;
    let live = true;
    const t = setTimeout(() => api.devices({ q: q.trim(), limit: 6 }).then((p) => live && setDevices(p.items)).catch(() => undefined), 180);
    return () => { live = false; clearTimeout(t); };
  }, [q, open]);

  const results = useMemo<Cmd[]>(() => {
    const needle = q.trim().toLowerCase();
    const nav = NAV.filter((c) => !needle || `${c.label} ${c.keywords}`.toLowerCase().includes(needle));
    if (needle.length < 2) return nav;
    const dev: Cmd[] = devices.flatMap((d) => [
      { id: `d-${d.id}`, group: "Devices", label: `Find device ${d.hostname}`, hint: `${d.ip} · risk ${d.risk_score}`, href: `/network?device=${d.id}` },
      { id: `i-${d.id}`, group: "Devices", label: `Investigate device ${d.hostname}`, hint: d.ip, href: `/network?device=${d.id}` },
    ]).slice(0, 8);
    const inc: Cmd[] = incidents.filter((i) => i.title.toLowerCase().includes(needle)).slice(0, 4)
      .map((i) => ({ id: `inc-${i.id}`, group: "Incidents", label: i.title, hint: `risk ${i.risk_score}`, href: `/investigate?incident=${i.id}` }));
    const mit: Cmd[] = (matrix?.tactics.flatMap((t) => t.techniques) ?? []).filter((t) => `${t.id} ${t.name}`.toLowerCase().includes(needle)).slice(0, 5)
      .map((t) => ({ id: `m-${t.id}`, group: "MITRE", label: `${t.id} ${t.name}`, hint: t.observed ? "observed" : "not observed", href: `/mitre?technique=${t.id}` }));
    return [...dev, ...inc, ...mit, ...nav];
  }, [q, devices, incidents, matrix]);

  function go(c: Cmd) {
    setOpen(false);
    setQ("");
    setActive(0);
    router.push(c.href);
  }

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="hidden items-center gap-2 border border-border px-2.5 py-1.5 text-[10px] uppercase tracking-widest text-muted transition hover:border-primary hover:text-primary md:inline-flex" aria-label="Open command palette">
        <Search className="size-3.5" /> Search <kbd className="border border-border px-1 text-[9px]">Ctrl K</kbd>
      </button>
    );
  }

  const sel = Math.min(active, Math.max(results.length - 1, 0));
  return (
    <div className="fixed inset-0 z-[70] grid place-items-start justify-items-center bg-black/70 px-4 pt-[14vh] backdrop-blur-sm" onMouseDown={(e) => e.target === e.currentTarget && setOpen(false)}>
      <div role="dialog" aria-modal="true" aria-label="Command palette" className="panel-edge w-full max-w-xl border border-primary/40">
        <div className="flex items-center gap-2 border-b border-border px-3">
          <Search className="size-4 text-muted" />
          <input ref={input} value={q} onChange={(e) => { setQ(e.target.value); setActive(0); }} placeholder="Find device, IP, incident, MITRE technique, or a command…"
            role="combobox" aria-expanded aria-controls="palette-list" aria-activedescendant={results[sel] ? `cmd-${results[sel].id}` : undefined}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, results.length - 1)); }
              if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
              if (e.key === "Enter" && results[sel]) go(results[sel]);
            }}
            className="w-full bg-transparent py-3 text-[13px] outline-none placeholder:text-muted/60" />
        </div>
        <ul id="palette-list" role="listbox" className="max-h-[50vh] overflow-y-auto py-1">
          {results.length === 0 && <li className="px-4 py-6 text-center text-[12px] text-muted">No matches.</li>}
          {results.map((c, i) => (
            <li key={c.id} id={`cmd-${c.id}`} role="option" aria-selected={i === sel} onMouseEnter={() => setActive(i)} onClick={() => go(c)}
              className={cn("flex cursor-pointer items-center justify-between gap-3 px-4 py-2 text-[12px]", i === sel ? "bg-primary/10 text-primary" : "text-foreground")}>
              <span className="truncate"><span className="mr-2 text-[9px] uppercase tracking-widest text-muted">{c.group}</span>{c.label}</span>
              {c.hint && <span className="shrink-0 text-[10px] text-muted">{c.hint}</span>}
            </li>
          ))}
        </ul>
        <div className="border-t border-border px-4 py-1.5 text-[9px] uppercase tracking-widest text-muted">↑↓ navigate · enter select · esc close</div>
      </div>
    </div>
  );
}
