import { cn } from "@/lib/utils";

/** Text with a chromatic-split glitch on hover/focus (CSS only; the copies are aria-hidden). */
export function GlitchText({ children, className }: { children: string; className?: string }) {
  return (
    <span className={cn("glitch relative inline-block", className)} data-text={children} tabIndex={0}>
      {children}
    </span>
  );
}
