import type { DeviceDetail, DeviceSummary, NetworkEvent, Page, Summary, Topology, User } from "./types";

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
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init.headers,
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
  events: (limit = 50) => request<NetworkEvent[]>(`/api/v1/events?limit=${limit}`),
};

export const wsUrl = () => API_URL.replace(/^http/, "ws") + "/api/v1/ws/stream";
