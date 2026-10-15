import Link from "next/link";
import { Logo } from "@/components/cyber/Logo";

export default function NotFound() {
  return (
    <main id="main" className="bg-grid bg-vignette grid min-h-screen place-items-center px-4 text-center">
      <div className="max-w-md">
        <div className="mb-8 flex justify-center"><Logo /></div>
        <p className="font-display text-6xl font-black tracking-[0.2em] text-primary glow-primary">404</p>
        <h1 className="mt-4 font-display text-sm uppercase tracking-[0.25em]">Signal lost</h1>
        <p className="mt-3 text-[13px] leading-relaxed text-muted">That page does not exist, or it moved. Nothing is wrong with your connection.</p>
        <div className="mt-6 flex flex-wrap justify-center gap-3 text-[12px] uppercase tracking-[0.2em]">
          <Link href="/" className="border border-primary bg-primary px-5 py-3 font-bold text-background">Home</Link>
          <Link href="/try" className="border border-border-strong px-5 py-3 text-muted hover:border-primary hover:text-primary">Try the playground</Link>
        </div>
      </div>
    </main>
  );
}
