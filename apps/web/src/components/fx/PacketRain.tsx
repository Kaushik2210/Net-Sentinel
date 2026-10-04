"use client";

import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

const GLYPHS = "0123456789ABCDEF";
const SIZE = 14;

/**
 * Falling columns of hex bytes, like packets streaming past. The cursor lights up the columns near it and
 * leaves a brighter trail. Decorative only: pointer-events none, paused when the tab is hidden, and skipped
 * entirely for visitors who prefer reduced motion.
 */
export function PacketRain({ className, intensity = 0.5 }: { className?: string; intensity?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let w = 0, h = 0, cols = 0, drops: number[] = [], speeds: number[] = [];
    const mouse = { x: -999, y: -999 };
    const color = () => getComputedStyle(document.documentElement).getPropertyValue("--color-primary").trim() || "#00e5ff";

    const resize = () => {
      const r = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = r.width; h = r.height;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cols = Math.ceil(w / SIZE);
      drops = Array.from({ length: cols }, () => Math.random() * -h / SIZE);
      speeds = Array.from({ length: cols }, () => 0.25 + Math.random() * 0.6);
    };
    resize();

    const onMove = (e: MouseEvent) => {
      const r = canvas.getBoundingClientRect();
      mouse.x = e.clientX - r.left; mouse.y = e.clientY - r.top;
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("resize", resize);

    let raf = 0, last = 0;
    const frame = (t: number) => {
      raf = requestAnimationFrame(frame);
      if (document.hidden || t - last < 50) return; // ~20 fps is plenty for a background
      last = t;
      ctx.fillStyle = "rgba(5,7,10,0.14)";
      ctx.fillRect(0, 0, w, h);
      ctx.font = `${SIZE - 3}px ui-monospace, monospace`;
      const c = color();
      for (let i = 0; i < cols; i++) {
        const x = i * SIZE, y = drops[i] * SIZE;
        const dist = Math.hypot(x - mouse.x, y - mouse.y);
        const near = Math.max(0, 1 - dist / 170);
        ctx.globalAlpha = Math.min(1, (0.14 + near * 0.9) * intensity * 2);
        ctx.fillStyle = near > 0.45 ? "#d9faff" : c;
        ctx.fillText(GLYPHS[(Math.random() * GLYPHS.length) | 0] + GLYPHS[(Math.random() * GLYPHS.length) | 0], x, y);
        drops[i] += speeds[i] * (1 + near * 2);
        if (drops[i] * SIZE > h && Math.random() > 0.975) drops[i] = Math.random() * -20;
      }
      ctx.globalAlpha = 1;
    };
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("resize", resize);
    };
  }, [intensity]);

  return <canvas ref={ref} aria-hidden className={cn("pointer-events-none absolute inset-0 size-full", className)} />;
}
