export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Single source of truth mapping severity -> semantic colour tokens. */
export const SEVERITY: Record<Severity, { label: string; text: string; bg: string; border: string; hex: string }> = {
  info: { label: "INFO", text: "text-muted", bg: "bg-muted/10", border: "border-muted/30", hex: "#6b8594" },
  low: { label: "LOW", text: "text-primary", bg: "bg-primary/10", border: "border-primary/30", hex: "#00e5ff" },
  medium: { label: "MEDIUM", text: "text-warning", bg: "bg-warning/10", border: "border-warning/30", hex: "#ffb000" },
  high: { label: "HIGH", text: "text-warning", bg: "bg-warning/15", border: "border-warning/50", hex: "#ff8a00" },
  critical: { label: "CRITICAL", text: "text-danger", bg: "bg-danger/15", border: "border-danger/50", hex: "#ff3b30" },
};

export function severityForRisk(score: number): Severity {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  if (score > 0) return "low";
  return "info";
}

/** Detection provenance. Kept visually distinct so rules, behaviour and ML are never conflated. */
export const DETECTION_CLASS = {
  RULE: { label: "RULE", text: "text-primary", border: "border-primary/40" },
  BEHAVIORAL: { label: "BEHAVIORAL", text: "text-warning", border: "border-warning/40" },
  ML: { label: "ML ANOMALY", text: "text-info", border: "border-info/40" },
  CORRELATED: { label: "CORRELATED", text: "text-danger", border: "border-danger/40" },
} as const;
