"use client";

import { useEffect, useState } from "react";

const LINES = [
  "NETSENTINEL // secure console",
  "loading detector registry ......... 8 rules",
  "calibrating isolation forest ...... ok",
  "mapping MITRE ATT&CK .............. 33 techniques",
  "twin online. all traffic below is simulated.",
];
const KEY = "ns.booted";

/** One-time (per tab session) terminal boot on the landing page. Click or press any key to skip. */
export function BootSequence() {
  const [shown, setShown] = useState(0);
  const [active, setActive] = useState(false);
  const [checked, setChecked] = useState(false);

  // Decide after mount (sessionStorage is client-only) via a timer callback so state is not set synchronously in the effect.
  useEffect(() => {
    const t = setTimeout(() => {
      let seen = false;
      try { seen = sessionStorage.getItem(KEY) === "1"; } catch { /* storage unavailable: just show it */ }
      if (!seen && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        try { sessionStorage.setItem(KEY, "1"); } catch { /* ignore */ }
        setActive(true);
      }
      setChecked(true);
    }, 0);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    if (!active) return;
    if (shown >= LINES.length) {
      const t = setTimeout(() => setActive(false), 450);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setShown((n) => n + 1), 320);
    return () => clearTimeout(t);
  }, [active, shown]);

  useEffect(() => {
    if (!active) return;
    const skip = () => setActive(false);
    window.addEventListener("keydown", skip);
    return () => window.removeEventListener("keydown", skip);
  }, [active]);

  if (!active || !checked) return null;
  return (
    <div role="presentation" onClick={() => setActive(false)} className="fixed inset-0 z-[80] grid cursor-pointer place-items-center bg-background px-6">
      <div className="w-full max-w-lg space-y-1.5 font-mono text-[12px] text-primary">
        {LINES.slice(0, shown).map((l, i) => (
          <p key={l} style={{ animation: "boot-line 0.25s both" }} className={i === LINES.length - 1 ? "text-success" : undefined}><span className="text-muted">&gt;</span> {l}</p>
        ))}
        <p className="animate-blink">&#9608;</p>
        <p className="pt-4 text-[10px] uppercase tracking-[0.3em] text-muted">click or press a key to skip</p>
      </div>
    </div>
  );
}
