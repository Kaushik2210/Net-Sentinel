import type { PlaygroundOptions, ReplayResult } from "@/lib/types";

export type Thresholds = Record<string, Record<string, number>>;

/** `?s=full&t=PortScanDetector.min_ports:30,BruteForceDetector.min_failures:5` */
export function encode(scenario: string, th: Thresholds): string {
  const t = Object.entries(th).flatMap(([d, ps]) => Object.entries(ps).map(([k, v]) => `${d}.${k}:${v}`)).join(",");
  const q = new URLSearchParams({ s: scenario });
  if (t) q.set("t", t);
  return q.toString();
}

/** Only accepts scenarios and parameters the server advertised, so a crafted link cannot smuggle in anything else. */
export function decode(search: string, opts: PlaygroundOptions): { scenario: string; values: Thresholds } {
  const q = new URLSearchParams(search);
  const s = q.get("s");
  const scenario = opts.scenarios.some((x) => x.id === s) ? (s as string) : "full";
  const values: Thresholds = {};
  for (const part of (q.get("t") ?? "").split(",")) {
    const m = /^([A-Za-z]+)\.([a-z_]+):(\d{1,9})$/.exec(part);
    if (!m) continue;
    const spec = opts.tunables.find((t) => t.detector === m[1])?.params.find((p) => p.key === m[2]);
    if (!spec) continue;
    (values[m[1]] ??= {})[m[2]] = Math.max(spec.min, Math.min(spec.max, Number(m[3])));
  }
  return { scenario, values };
}

/** Scale every threshold from its default (clamped to the allowed range) to build the preset profiles. */
export function scaled(opts: PlaygroundOptions, factor: number): Thresholds {
  const out: Thresholds = {};
  for (const t of opts.tunables) for (const p of t.params) {
    const v = Math.max(p.min, Math.min(p.max, Math.round(p.default * factor)));
    if (v !== p.default) (out[t.detector] ??= {})[p.key] = v;
  }
  return out;
}

export interface Snapshot { label: string; custom: boolean; alerts: number; risk: number; techniques: number; keys: string[] }

const keyOf = (a: { detector: string; event_type: string }) => `${a.detector.replace("Detector", "")} · ${a.event_type.replaceAll("_", " ")}`;

export function snapshot(label: string, custom: boolean, r: ReplayResult): Snapshot {
  return { label, custom, alerts: r.alerts.length, risk: r.incident?.risk_score ?? 0, techniques: r.incident?.techniques.length ?? 0, keys: [...new Set(r.alerts.map(keyOf))] };
}
