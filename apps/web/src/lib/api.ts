import type { ResearchPayload, Indicator, IndicatorKind, IntelCheck, IntelMatch, Recommendation, AnalystAnswer, AnalystUser, AuditEntry, Note, WorkflowStatus, Alert, AlertDetail, ReplayResult, ReplaySummary, MitreMatrix, TechniqueDetail, IncidentDetail, IncidentSummary, DeviceDetail, DeviceSummary, NetworkEvent, MlScore, Page, SimulationResult, Summary, Topology, User } from "./types";

export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const TOKEN_KEY = "ns.token";

/*
 * Token storage trade-off: sessionStorage keeps the bearer token out of long-lived storage and
 * scoped to the tab, but it is readable by script (XSS). A production deployment should move to
 * an httpOnly, SameSite cookie issued by the API. Documented in docs/SECURITY.md.
 */
export const tokenStore = {
  get: () => (typeof window === "undefined" ? null : window.sessionStorage.getItem(TOKEN_KEY)),
  set: (t: string) => window.sessionStorage.setItem(TOKEN_KEY, t),
  clear: () => window.sessionStorage.removeItem(TOKEN_KEY),
};

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

type Listener = () => void;
let onUnauthorized: Listener | null = null;
export const setUnauthorizedHandler = (fn: Listener | null) => { onUnauthorized = fn; };

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = tokenStore.get();
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: {
        ...(init.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });
  } catch {
    throw new ApiError(0, "Cannot reach the NetSentinel API. Is the backend running?");
  }
  if (res.status === 401 && token) onUnauthorized?.();
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : detail;
    } catch { /* non-JSON error body */ }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string; user: User }>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<User>("/api/v1/auth/me"),
  summary: () => request<Summary>("/api/v1/analytics/summary"),
  topology: () => request<Topology>("/api/v1/network/topology"),
  devices: (params: { q?: string; device_type?: string; min_risk?: number; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== "" && qs.set(k, String(v)));
    return request<Page<DeviceSummary>>(`/api/v1/devices?${qs}`);
  },
  device: (id: string) => request<DeviceDetail>(`/api/v1/devices/${id}`),
  alerts: (limit = 25) => request<Page<Alert>>(`/api/v1/alerts?limit=${limit}`),
  alert: (id: string) => request<AlertDetail>(`/api/v1/alerts/${id}`),
  simulateAttack: () => request<SimulationResult>("/api/v1/detections/simulate-attack", { method: "POST" }),
  resetSimulation: () => request<void>("/api/v1/detections/reset-simulation", { method: "POST" }),
  mlScore: (ip: string) => request<MlScore[]>(`/api/v1/analytics/ml/scores?ip=${encodeURIComponent(ip)}`),
  incidents: () => request<Page<IncidentSummary>>("/api/v1/incidents?limit=50"),
  incident: (id: string) => request<IncidentDetail>(`/api/v1/incidents/${id}`),
  mitre: () => request<MitreMatrix>("/api/v1/mitre"),
  technique: (id: string) => request<TechniqueDetail>(`/api/v1/mitre/${encodeURIComponent(id)}`),
  replays: () => request<ReplaySummary[]>("/api/v1/replay"),
  replay: (id: string) => request<{ summary: ReplaySummary; result: ReplayResult }>(`/api/v1/replay/${id}`),
  replaySample: () => request<ReplaySummary>("/api/v1/replay/sample", { method: "POST" }),
  uploadPcap: (file: File) => {
    const body = new FormData();
    body.append("file", file);
    // request() omits Content-Type for FormData so the browser sets the multipart boundary.
    return request<ReplaySummary>("/api/v1/replay/upload", { method: "POST", body });
  },
  notes: (id: string) => request<Note[]>(`/api/v1/investigations/${id}/notes`),
  addNote: (id: string, body: string) => request<Note>(`/api/v1/investigations/${id}/notes`, { method: "POST", body: JSON.stringify({ body }) }),
  auditTrail: (id: string) => request<AuditEntry[]>(`/api/v1/investigations/${id}/audit`),
  analysts: () => request<AnalystUser[]>("/api/v1/investigations/analysts"),
  updateWorkflow: (id: string, patch: { status?: WorkflowStatus; assignee?: string | null }) =>
    request<{ id: string; status: string; assignee: string | null }>(`/api/v1/investigations/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  ask: (target: { incident_id?: string; device_id?: string }, question: string) =>
    request<AnalystAnswer>("/api/v1/analyst/ask", { method: "POST", body: JSON.stringify({ ...target, question }) }),
  indicators: (kind?: string) => request<Page<Indicator>>(`/api/v1/threat-intel?limit=100${kind ? `&kind=${kind}` : ""}`),
  addIndicator: (b: { kind: IndicatorKind; value: string; description?: string; confidence?: number; source?: string }) =>
    request<Indicator>("/api/v1/threat-intel", { method: "POST", body: JSON.stringify(b) }),
  deleteIndicator: (id: string) => request<void>(`/api/v1/threat-intel/${id}`, { method: "DELETE" }),
  checkIndicator: (kind: IndicatorKind, value: string) => request<IntelCheck>("/api/v1/threat-intel/check", { method: "POST", body: JSON.stringify({ kind, value }) }),
  intelMatches: () => request<IntelMatch[]>("/api/v1/threat-intel/matches"),
  recommendations: (incidentId: string) => request<Recommendation[]>(`/api/v1/response/incidents/${incidentId}`),
  simulateResponse: (recId: string) => request<{ recommendation: Recommendation; message: string; real_changes_made: boolean }>(`/api/v1/response/${recId}/simulate`, { method: "POST" }),
  research: () => request<ResearchPayload>("/api/v1/research"),
  runResearch: () => request<ResearchPayload>("/api/v1/research/run", { method: "POST" }),
  events: (limit = 50) => request<NetworkEvent[]>(`/api/v1/events?limit=${limit}`),
};

export const wsUrl = () => API_URL.replace(/^http/, "ws") + "/api/v1/ws/stream";
