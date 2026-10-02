import type { Severity } from "./severity";

export type Role = "ADMIN" | "ANALYST" | "VIEWER";

export interface User { id: string; username: string; display_name: string; role: Role }

export interface Page<T> { items: T[]; total: number; limit: number; offset: number }

export interface DeviceSummary {
  id: string; hostname: string; ip: string; device_type: string; zone: string; role: string;
  criticality: number; status: string; risk_score: number; last_seen: string;
}

export interface Factor { key: string; label: string; points: number; detail: string }
export interface MetricView { key: string; label: string; baseline_min: number; baseline_max: number; current: number; deviated: boolean }
export interface Neighbor {
  id: string; hostname: string; ip: string; direction: "inbound" | "outbound"; protocol: string;
  port: number | null; bytes_per_hour: number; suspicious: boolean;
}

export interface NetworkEvent {
  id: string; ts: string; source: string; src_ip: string; dst_ip: string; dst_port: number | null;
  protocol: string; event_type: string; bytes_sent: number; bytes_received: number;
  severity: Severity; attributes: Record<string, unknown>;
}

export interface DeviceDetail extends DeviceSummary {
  mac: string; os: string; open_ports: number[]; protocols: string[]; risk_severity: Severity;
  risk_factors: Factor[]; deviation_score: number; metrics: MetricView[]; connections: Neighbor[];
  recent_events: NetworkEvent[]; connection_count: number;
}

export interface TopologyNode extends DeviceSummary { position: { x: number; y: number }; connection_count: number }
export interface TopologyEdge {
  id: string; source: string; target: string; protocol: string; port: number | null;
  bytes_per_hour: number; connections_per_hour: number; suspicious: boolean;
}
export interface Topology { nodes: TopologyNode[]; edges: TopologyEdge[] }

export interface Summary {
  mode: "SIMULATION" | "IDLE"; data_source: string; active_devices: number; active_connections: number;
  events_per_min: number; anomalous_devices: number; high_risk_devices: number; critical_alerts: number;
  external_connections: number; generated_at: string;
}

export type DetectionClassKey = "RULE" | "BEHAVIORAL" | "ML" | "CORRELATED";

export interface Alert {
  id: string; ts: string; source: string; destination: string; event_type: string;
  detection_class: DetectionClassKey; severity: Severity; confidence: number; detector: string;
  mitre_techniques: string[]; explanation: string; status: string; incident_id: string | null;
}
export interface EvidenceItem { id: string; kind: "facts" | "event"; event_id: string | null; summary: string; data: Record<string, unknown> }
export interface AlertDetail extends Alert { evidence: EvidenceItem[] }
export interface SimulationResult { events_injected: number; alerts_created: Alert[] }

export interface MlContribution { feature: string; label: string; value: number; baseline_mean: number; z: number }
export interface MlScore {
  entity: string; hostname: string | null; score: number; risk: number; is_anomaly: boolean;
  contributions: MlContribution[]; classification: string; note: string;
}

export interface IncidentSummary {
  id: string; title: string; status: string; severity: Severity; risk_score: number;
  first_seen: string; last_seen: string; summary: string; classification: "CORRELATED"; assignee?: string | null;
}
export interface IncidentStep {
  position: number; stage: string; alert_id: string | null; timestamp: string; source: string; destination: string;
  detector: string; detection_class: DetectionClassKey; severity: Severity; confidence: number; explanation: string;
  mitre: string[]; evidence_event_ids: string[]; facts: Record<string, unknown>; link_reason: string; link_confidence: number;
}
export interface Technique { id: string; name: string; tactic: string; description: string }
export interface IncidentDetail extends IncidentSummary {
  risk_factors: Factor[]; steps: IncidentStep[];
  supporting: { id: string; detection_class: DetectionClassKey; event_type: string; severity: Severity; confidence: number; explanation: string; source: string }[];
  techniques: Technique[]; evidence_count: number;
}

export interface TechniqueCell {
  id: string; name: string; description: string; observed: boolean; alert_count: number;
  max_confidence: number | null; mean_confidence: number | null; first_seen: string | null;
}
export interface MitreMatrix { tactics: { name: string; techniques: TechniqueCell[] }[]; observed_techniques: number; total_techniques: number }
export interface TechniqueRelatedAlert {
  id: string; ts: string; detector: string; detection_class: DetectionClassKey; severity: Severity; confidence: number;
  explanation: string; source: string; destination: string; incident_id: string | null;
  chain_position: number | null; chain_length: number | null; stage: string | null;
}
export interface TechniqueDetail extends TechniqueCell { tactic: string; alerts: TechniqueRelatedAlert[]; evidence_event_ids: string[] }

export interface ReplaySummary {
  id: string; filename: string; sha256: string; status: string; packet_count: number; duration_s: number;
  alert_count: number; created_at: string; error: string | null;
}
export interface ReplayHost { ip: string; internal: boolean; first_s: number; events: number }
export interface ReplayEdge { src: string; dst: string; first_s: number; count: number; bytes: number }
export interface ReplayFrame { t: number; events: number; alerts: number; chain: number; threat: number; new_alerts: string[] }
export interface ReplayAlert {
  id: string; detected_offset_s: number; first_event_offset_s: number; source: string; destination: string; event_type: string;
  detection_class: DetectionClassKey; severity: Severity; confidence: number; detector: string; mitre: string[];
  explanation: string; facts: Record<string, unknown>; evidence_event_ids: string[];
}
export interface ReplayResult {
  empty: boolean; duration_s: number; start?: string; end?: string; hosts: ReplayHost[]; edges: ReplayEdge[];
  event_types: string[]; events: [number, number, number, number, number, number][]; events_truncated?: boolean;
  frames: ReplayFrame[]; alerts: ReplayAlert[];
  settings: { overrides: Record<string, Record<string, unknown>>; excluded_detectors?: string[] };
  ingest?: { packets: number; flows: number; events: number; heuristics: string; truncated: boolean; notes: string[] };
  incident: null | {
    risk_score: number; risk_factors: Factor[]; techniques: Technique[];
    steps: { position: number; stage: string; alert_id: string; link_reason: string; link_confidence: number; offset_s: number }[];
  };
}

export type WorkflowStatus = "open" | "investigating" | "resolved" | "false_positive" | "escalated";
export interface Note { id: string; author: string; body: string; created_at: string }
export interface AuditEntry { ts: string; actor: string; action: string; detail: Record<string, unknown> }
export interface AnalystUser { username: string; display_name: string; role: Role }
export interface AnalystAnswer {
  question: string; mode: string; insufficient: boolean; claims: { text: string; cites: string[] }[]; citations: string[]; notice: string;
}

export type IndicatorKind = "ip" | "domain" | "hash" | "url";
export interface Indicator { id: string; kind: IndicatorKind; value: string; source: string; confidence: number; description: string; created_at: string }
export interface IntelCheck { value: string; matched: boolean; providers_checked: string[]; hits: { kind: string; value: string; source: string; confidence: number; description: string }[] }
export interface IntelMatch { indicator_id: string; kind: string; value: string; source: string; confidence: number; where: string; alert_ids: string[]; event_ids: string[] }
export interface Recommendation {
  id: string; incident_id: string; action: string; label: string; target: string; rationale: string; state: "proposed" | "simulated"; created_at: string; mode: string;
}
