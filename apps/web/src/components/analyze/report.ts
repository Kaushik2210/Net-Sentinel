import type { ReplayAlert, ReplayResult } from "@/lib/types";

const ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const sortThreats = (alerts: ReplayAlert[]) =>
  [...alerts].sort((a, b) => (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9) || b.confidence - a.confidence);

export function verdict(result: ReplayResult) {
  const n = result.alerts.length;
  const top = sortThreats(result.alerts)[0]?.severity ?? null;
  const hosts = [...new Set(result.alerts.map((a) => a.source))];
  return { count: n, top, hosts };
}

const clock = (s: number) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`;

/** Markdown report generated in the browser from the stored analysis result. Nothing is added that the result does not contain. */
export function toMarkdown(filename: string, r: ReplayResult): string {
  const v = verdict(r);
  const L: string[] = [`# NetSentinel analysis: ${filename}`, ""];
  if (r.ingest) L.push(`Source: ${r.ingest.packets} records read, ${r.ingest.flows} flows, ${r.ingest.events} events. ${r.start ?? ""} to ${r.end ?? ""}.`, "");
  L.push(v.count === 0 ? "**Result: no threats detected by the rule-based detectors.** This does not prove the capture is safe." : `**Result: ${v.count} threat(s) detected, highest severity ${v.top}.** Involved source host(s): ${v.hosts.join(", ")}.`, "");
  if (r.incident) {
    L.push(`## Reconstructed incident (risk ${r.incident.risk_score}/100)`, "");
    r.incident.steps.forEach((s) => L.push(`${s.position + 1}. ${s.stage} (T+${clock(s.offset_s)}), joined because: ${s.link_reason}`));
    L.push("", "Risk factors:", ...r.incident.risk_factors.map((f) => `- +${f.points} ${f.label}: ${f.detail}`), "");
  }
  L.push("## Threats", "");
  sortThreats(r.alerts).forEach((a, i) => {
    L.push(`### ${i + 1}. ${a.event_type.replaceAll("_", " ")} (${a.severity}, ${Math.round(a.confidence * 100)}% confidence)`,
      `- ${a.explanation}`, `- Source ${a.source} to ${a.destination}; detected at T+${clock(a.detected_offset_s)} by ${a.detector} (${a.detection_class})`,
      `- MITRE ATT&CK: ${a.mitre.join(", ") || "none mapped"}`, `- Evidence events: ${a.evidence_event_ids.join(", ") || "none linked"}`, "");
  });
  L.push("## Limits of this analysis", "", "- Rule-based detection on flow data. Authentication outcomes on encrypted protocols are inferred from flow shape, not observed.",
    "- Subtle or slow activity below detector thresholds is not reported.", ...(Object.keys(r.settings.overrides).length ? [`- Threshold overrides in effect: ${JSON.stringify(r.settings.overrides)}`] : []));
  return L.join("\n");
}

export function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  URL.revokeObjectURL(url);
}
