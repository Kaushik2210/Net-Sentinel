"use client";

import { useSearchParams } from "next/navigation";
import { Suspense, useEffect } from "react";

function Inner({ name, onValue }: { name: string; onValue: (v: string) => void }) {
  const v = useSearchParams().get(name);
  useEffect(() => { if (v) onValue(v); }, [v, onValue]);
  return null;
}

/** Reports a URL query parameter to the page (used so the command palette can pre-select an entity). */
export function ParamSync(props: { name: string; onValue: (v: string) => void }) {
  return <Suspense fallback={null}><Inner {...props} /></Suspense>;
}
