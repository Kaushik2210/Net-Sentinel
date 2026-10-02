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
