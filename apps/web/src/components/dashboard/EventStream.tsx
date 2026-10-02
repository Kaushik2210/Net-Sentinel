"use client";

import { CyberCard } from "@/components/cyber/CyberCard";
import { StatusDot } from "@/components/cyber/SeverityIndicator";
import type { LiveStatus } from "@/lib/useLiveEvents";
import type { NetworkEvent } from "@/lib/types";
import { cn, formatBytes, formatClock } from "@/lib/utils";

const TYPE_TONE: Record<string, string> = {
  dns_query: "text-primary", http_request: "text-foreground", tls_session: "text-foreground", ssh_session: "text-warning",
  smb_session: "text-info", kerberos_auth: "text-info", db_query: "text-success", syslog: "text-muted",
};

interface Props { events: NetworkEvent[]; status: LiveStatus; loaded: boolean; error: string | null; source: string | undefined }

export function EventStream({ events, status, loaded, error, source }: Props) {
  const tone = status === "live" ? "success" : status === "connecting" ? "warning" : "danger";
  return (
    <CyberCard title="Live event stream" tone="success" className="h-full" bodyClassName="p-0"
      actions={<span className="flex items-center gap-2 text-[9px] tracking-[0.2em] text-muted"><StatusDot tone={tone} pulse={status === "live"} />{status.toUpperCase()}{source ? ` · ${source.toUpperCase()}` : ""}</span>}>
      <div className="max-h-[340px] overflow-y-auto font-mono text-[11px]" role="log" aria-live="off">
        {error ? <p className="p-4 text-danger">{error}</p>
          : !loaded ? <p className="p-4 text-muted">Opening stream…</p>
          : events.length === 0 ? <p className="p-6 text-center text-muted">No telemetry received yet.</p>
          : events.map((e) => (
            <div key={e.id} className="grid grid-cols-[4.5rem_6.5rem_1fr_auto] items-baseline gap-2 border-b border-border/40 px-3 py-1 hover:bg-panel-2">
              <span className="tabular-nums text-muted">{formatClock(e.ts)}</span>
              <span className={cn("truncate", TYPE_TONE[e.event_type] ?? "text-foreground")}>{e.event_type}</span>
              <span className="truncate text-muted">{e.src_ip} <span className="text-primary">›</span> {e.dst_ip}{e.dst_port ? `:${e.dst_port}` : ""}{typeof e.attributes?.domain === "string" ? ` · ${e.attributes.domain}` : ""}</span>
              <span className="hidden tabular-nums text-muted/70 sm:block">{formatBytes(e.bytes_sent + e.bytes_received)}</span>
            </div>
          ))}
      </div>
    </CyberCard>
  );
}
