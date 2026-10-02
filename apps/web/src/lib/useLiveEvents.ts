"use client";

import { useEffect, useRef, useState } from "react";
import { api, tokenStore, wsUrl } from "./api";
import type { Alert, NetworkEvent } from "./types";

export type LiveStatus = "connecting" | "live" | "offline";

/**
 * Seeds the list from the REST API, then appends events pushed over the WebSocket.
 * Keeps only the newest `max` events in memory (the browser never holds the event table).
 */
export function useLiveEvents(max = 60) {
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const retry = useRef(0);

  useEffect(() => {
    let closed = false;
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout>;

    api.events(max)
      .then((rows) => !closed && setEvents(rows))
      .catch((e) => !closed && setError(e.message))
      .finally(() => !closed && setLoaded(true));

    api.alerts(25).then((p) => !closed && setAlerts(p.items)).catch(() => undefined);

    const connect = () => {
      const token = tokenStore.get();
      if (!token || closed) return;
      setStatus("connecting");
      ws = new WebSocket(wsUrl());
      ws.onopen = () => ws?.send(JSON.stringify({ type: "auth", token }));
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data);
        if (msg.type === "ready") {
          retry.current = 0;
          setStatus("live");
        } else if (msg.type === "alert") {
          setAlerts((prev) => [msg.data as Alert, ...prev.filter((a) => a.id !== msg.data.id)].slice(0, 50));
        } else if (msg.type === "event") {
          setEvents((prev) => [msg.data as NetworkEvent, ...prev].slice(0, max));
        }
      };
      ws.onclose = () => {
        if (closed) return;
        setStatus("offline");
        timer = setTimeout(connect, Math.min(15000, 1000 * 2 ** retry.current++));
      };
    };
    connect();

    return () => {
      closed = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, [max]);

  return { events, alerts, setAlerts, status, error, loaded };
}
