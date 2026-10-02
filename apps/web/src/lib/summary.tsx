"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type { Summary } from "./types";

interface SummaryState {
  summary: Summary | null;
  error: string | null;
  refresh: () => void;
}

const Ctx = createContext<SummaryState>({ summary: null, error: null, refresh: () => {} });
const REFRESH_MS = 10_000;

/** Shared aggregate counters for the top bar and dashboard. Light 10s refresh; pushed deltas arrive in a later phase. */
export function SummaryProvider({ children }: { children: React.ReactNode }) {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api.summary().then((s) => { setSummary(s); setError(null); }).catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(t);
  }, [refresh]);

  const value = useMemo(() => ({ summary, error, refresh }), [summary, error, refresh]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useSummary = () => useContext(Ctx);
