"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { DeviceSummary, Topology } from "@/lib/types";

interface State {
  topology: Topology | null;
  topRisk: DeviceSummary[];
  loading: boolean;
  error: string | null;
}

export function useDashboardData() {
  const [state, setState] = useState<State>({ topology: null, topRisk: [], loading: true, error: null });
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let live = true;
    Promise.all([api.topology(), api.devices({ min_risk: 1, limit: 8 })])
      .then(([topology, devices]) => live && setState({ topology, topRisk: devices.items, loading: false, error: null }))
      .catch((e: Error) => live && setState((s) => ({ ...s, loading: false, error: e.message })));
    return () => { live = false; };
  }, [nonce]);

  const reload = useCallback(() => {
    setState((s) => ({ ...s, loading: true, error: null }));
    setNonce((n) => n + 1);
  }, []);

  return { ...state, reload };
}
