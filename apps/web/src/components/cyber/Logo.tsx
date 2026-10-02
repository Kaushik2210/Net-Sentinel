import Link from "next/link";
import { cn } from "@/lib/utils";

export function Logo({ className, href = "/" }: { className?: string; href?: string }) {
  return (
    <Link href={href} className={cn("group inline-flex items-center gap-2.5", className)} aria-label="NetSentinel home">
      <svg viewBox="0 0 32 32" className="size-7 text-primary" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
        <path d="M16 2 28 8v9c0 6.5-5 11.2-12 13C9 28.200 4 23.500 4 17V8L16 2Z" className="drop-shadow-[0_0_6px_rgba(0,229,255,0.7)]" />
        <circle cx="16" cy="15" r="3.2" />
        <path d="M16 11.800V8M16 22v-3.800M12.800 15H9M23 15h-3.800" strokeLinecap="round" />
      </svg>
      <span className="font-display text-[15px] font-bold tracking-[0.28em] text-foreground group-hover:text-primary">
        NET<span className="text-primary">SENTINEL</span>
      </span>
    </Link>
  );
}
