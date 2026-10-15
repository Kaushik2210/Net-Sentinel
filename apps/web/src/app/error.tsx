"use client";

import Link from "next/link";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main id="main" className="bg-grid bg-vignette grid min-h-screen place-items-center px-4 text-center">
      <div className="max-w-md">
        <p className="font-display text-sm uppercase tracking-[0.3em] text-danger glow-danger">System fault</p>
        <h1 className="mt-4 font-display text-xl font-bold tracking-wide">Something went wrong on this page</h1>
        <p className="mt-3 text-[13px] leading-relaxed text-muted">The rest of the app is unaffected. Try again, or head back to the start.</p>
        <div className="mt-6 flex flex-wrap justify-center gap-3 text-[12px] uppercase tracking-[0.2em]">
          <button onClick={reset} className="border border-primary bg-primary px-5 py-3 font-bold text-background">Try again</button>
          <Link href="/" className="border border-border-strong px-5 py-3 text-muted hover:border-primary hover:text-primary">Home</Link>
        </div>
      </div>
    </main>
  );
}
