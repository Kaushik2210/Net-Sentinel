import { cn } from "@/lib/utils";

interface Props extends React.HTMLAttributes<HTMLDivElement> {
  prompt?: string;
  title?: string;
}

/** Terminal-styled log/readout surface: dark well, phosphor text, title bar with lights. */
export function TerminalPanel({ prompt, title, className, children, ...rest }: Props) {
  return (
    <div className={cn("border border-border bg-black/60 font-mono", className)} {...rest}>
      {title && (
        <div className="flex items-center gap-2 border-b border-border px-3 py-1.5 text-[10px] uppercase tracking-widest text-muted">
          <span className="size-1.5 rounded-full bg-danger/70" />
          <span className="size-1.5 rounded-full bg-warning/70" />
          <span className="size-1.5 rounded-full bg-success/70" />
          <span className="ml-2">{title}</span>
        </div>
      )}
      <div className="p-3 text-[12px] leading-relaxed text-success/90">
        {prompt && <div className="mb-1 text-muted">{prompt}</div>}
        {children}
      </div>
    </div>
  );
}
