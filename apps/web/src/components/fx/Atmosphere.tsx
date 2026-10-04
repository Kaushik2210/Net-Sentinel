"use client";

import { useEffect, useRef, useState } from "react";

const KONAMI = ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"];

/**
 * Global effects mounted once in the root layout:
 *  - a soft light that follows the cursor (fine pointers only)
 *  - a hidden "red alert" theme toggled by the Konami code or Ctrl+Shift+R (restyles the colour tokens)
 */
export function Atmosphere() {
  const glow = useRef<HTMLDivElement>(null);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    if (!window.matchMedia("(pointer: fine)").matches) return;
    let raf = 0;
    const onMove = (e: MouseEvent) => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        if (glow.current) glow.current.style.transform = `translate(${e.clientX - 200}px, ${e.clientY - 200}px)`;
      });
    };
    window.addEventListener("mousemove", onMove);
    return () => { window.removeEventListener("mousemove", onMove); cancelAnimationFrame(raf); };
  }, []);

  const alertRef = useRef(false);

  useEffect(() => {
    let seq: string[] = [];
    let timer: ReturnType<typeof setTimeout> | undefined;
    const toggle = () => {
      alertRef.current = !alertRef.current;
      document.documentElement.dataset.alert = alertRef.current ? "true" : "false";
      setToast(alertRef.current ? "RED ALERT MODE · press Ctrl+Shift+R to stand down" : "Standing down");
      clearTimeout(timer);
      timer = setTimeout(() => setToast(null), 2600);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "r") { e.preventDefault(); toggle(); return; }
      seq = [...seq, e.key.length === 1 ? e.key.toLowerCase() : e.key].slice(-KONAMI.length);
      if (seq.join() === KONAMI.join()) { seq = []; toggle(); }
    };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); clearTimeout(timer); };
  }, []);

  return (
    <>
      <div ref={glow} aria-hidden className="cursor-glow" />
      {toast && <div role="status" className="alert-toast">{toast}</div>}
    </>
  );
}
