"use client";

import { cn } from "@/lib/utils";

type Tone = "primary" | "success" | "warning" | "danger" | "info" | "muted";

const TONE: Record<Tone, string> = {
  primary: "border-primary/25 [--corner:var(--color-primary)]",
  success: "border-success/25 [--corner:var(--color-success)]",
  warning: "border-warning/30 [--corner:var(--color-warning)]",
  danger: "border-danger/40 [--corner:var(--color-danger)]",
  info: "border-info/30 [--corner:var(--color-info)]",
  muted: "border-border [--corner:var(--color-border-strong)]",
};

interface Props extends React.HTMLAttributes<HTMLDivElement> {
  tone?: Tone;
  title?: string;
  /** Right-aligned header content (status chips, controls). */
  actions?: React.ReactNode;
  bodyClassName?: string;
}

/** Metal/glass panel with bracketed corners and an optional titled header strip. */
export function CyberCard({ tone = "muted", title, actions, className, bodyClassName, children, onMouseMove, ...rest }: Props) {
  return (
    <section
      className={cn("panel-edge spot relative border", TONE[tone], className)}
      onMouseMove={(e) => {
        const r = e.currentTarget.getBoundingClientRect();
        e.currentTarget.style.setProperty("--mx", `${e.clientX - r.left}px`);
        e.currentTarget.style.setProperty("--my", `${e.clientY - r.top}px`);
        onMouseMove?.(e as React.MouseEvent<HTMLDivElement>);
      }}
      {...rest}
    >
      {(["tl", "tr", "bl", "br"] as const).map((c) => (
        <span
          key={c}
          aria-hidden
          className={cn(
            "pointer-events-none absolute size-2 border-[var(--corner)]",
            c === "tl" && "-left-px -top-px border-l border-t",
            c === "tr" && "-right-px -top-px border-r border-t",
            c === "bl" && "-bottom-px -left-px border-b border-l",
            c === "br" && "-bottom-px -right-px border-b border-r",
          )}
        />
      ))}
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-border/80 px-3 py-2">
          <h2 className="font-display text-[11px] font-medium uppercase tracking-[0.22em] text-muted">
            <span className="mr-2 text-primary">▍</span>
            {title}
          </h2>
          {actions}
        </header>
      )}
      <div className={cn("p-3", bodyClassName)}>{children}</div>
    </section>
  );
}
