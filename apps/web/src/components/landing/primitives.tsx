"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

export function Reveal({ children, delay = 0, className }: { children: React.ReactNode; delay?: number; className?: string }) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 18 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-60px" }}
      transition={{ duration: 0.55, delay, ease: "easeOut" }}
    >
      {children}
    </motion.div>
  );
}

export type Status = "LIVE" | "IN PROGRESS" | "PLANNED";

/** Honest capability status. The landing page never implies a feature exists before it does. */
export function StatusTag({ status }: { status: Status }) {
  const tone = status === "LIVE" ? "text-success border-success/40" : status === "IN PROGRESS" ? "text-warning border-warning/40" : "text-muted border-border";
  return <span className={cn("border px-1.5 py-0.5 text-[9px] tracking-[0.2em]", tone)}>{status}</span>;
}

interface SectionProps {
  id: string;
  index: string;
  eyebrow: string;
  title: string;
  status?: Status;
  children: React.ReactNode;
  lead?: string;
}

export function Section({ id, index, eyebrow, title, lead, status, children }: SectionProps) {
  return (
    <section id={id} className="relative mx-auto max-w-6xl scroll-mt-20 px-5 py-20">
      <Reveal>
        <div className="mb-8 flex flex-wrap items-center gap-3 text-[10px] uppercase tracking-[0.3em] text-muted">
          <span className="text-primary">{index}</span>
          <span>/</span>
          <span>{eyebrow}</span>
          {status && <StatusTag status={status} />}
        </div>
        <h2 className="max-w-3xl font-display text-2xl font-bold leading-tight tracking-wide text-foreground sm:text-3xl">{title}</h2>
        {lead && <p className="mt-4 max-w-2xl text-[13px] leading-relaxed text-muted">{lead}</p>}
      </Reveal>
      <div className="mt-10">{children}</div>
    </section>
  );
}
