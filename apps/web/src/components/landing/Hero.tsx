"use client";

import { motion } from "framer-motion";
import { ArrowRight } from "lucide-react";
import { GithubMark } from "@/components/cyber/GithubMark";
import Link from "next/link";
import { Logo } from "@/components/cyber/Logo";
import { GlitchText } from "@/components/fx/GlitchText";
import { PacketRain } from "@/components/fx/PacketRain";
import { HeroTopology } from "./HeroTopology";

const NAV = [
  ["#what", "Overview"], ["#how", "How it works"], ["#twin", "Digital twin"], ["#behavior", "Behavior"],
  ["#attack", "Reconstruction"], ["#mitre", "MITRE"], ["#architecture", "Architecture"],
];

export function Nav() {
  return (
    <header className="sticky top-0 z-40 border-b border-border/70 bg-background/80 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-5">
        <Logo />
        <nav className="hidden items-center gap-5 text-[11px] uppercase tracking-widest text-muted lg:flex" aria-label="Sections">
          {NAV.map(([href, label]) => (
            <a key={href} href={href} className="transition-colors hover:text-primary">{label}</a>
          ))}
        </nav>
        <Link href="/dashboard" className="border border-primary/60 bg-primary/10 px-3 py-1.5 text-[11px] font-medium uppercase tracking-[0.2em] text-primary transition hover:bg-primary hover:text-background">
          Enter <span className="hidden sm:inline">command center</span>
        </Link>
      </div>
    </header>
  );
}

export function Hero() {
  return (
    <div className="relative overflow-hidden">
      <div className="bg-grid bg-vignette absolute inset-0 [mask-image:radial-gradient(ellipse_at_center,black_40%,transparent_85%)]" aria-hidden />
      <PacketRain className="[mask-image:radial-gradient(ellipse_at_center,black_20%,transparent_75%)]" intensity={0.45} />
      <div className="relative mx-auto grid max-w-6xl grid-cols-[minmax(0,1fr)] items-center gap-12 px-5 pb-20 pt-16 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)] lg:pt-24">
        <div className="min-w-0">
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }} className="mb-6 flex items-center gap-3 text-[10px] uppercase tracking-[0.3em] text-muted">
            <span className="size-1.5 animate-blink bg-success" /> Network digital twin &middot; v0.1 research build
          </motion.div>
          <motion.h1 initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}
            className="animate-flicker font-display text-[clamp(1.75rem,9vw,3rem)] font-black tracking-[0.12em] text-foreground glow-primary sm:text-6xl">
            NET<GlitchText className="text-primary">SENTINEL</GlitchText>
          </motion.h1>
          <motion.p initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.15 }}
            className="mt-6 font-display text-xl font-medium leading-snug tracking-wide text-foreground sm:text-2xl">
            See the network.<br /><span className="text-primary">Understand the threat.</span>
          </motion.p>
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 }} className="mt-5 max-w-xl text-[13px] leading-relaxed text-muted">
            An explainable network security platform that transforms network telemetry into behavioral intelligence,
            attack timelines, and evidence-backed investigations.
          </motion.p>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.55 }} className="mt-8 flex flex-wrap items-center gap-3">
            <Link href="/dashboard" className="group inline-flex items-center gap-2 border border-primary bg-primary px-5 py-3 text-[12px] font-bold uppercase tracking-[0.22em] text-background shadow-[0_0_24px_-4px_rgba(0,229,255,0.7)] transition hover:shadow-[0_0_34px_0_rgba(0,229,255,0.8)]">
              Enter command center <ArrowRight className="size-4 transition group-hover:translate-x-1" />
            </Link>
            <Link href="/try" className="inline-flex items-center gap-2 border border-primary/60 bg-primary/10 px-4 py-3 text-[12px] uppercase tracking-[0.2em] text-primary transition hover:bg-primary hover:text-background">
              Try it, no sign-in
            </Link>
            <a href="https://github.com/Kaushik2210/Net-Sentinel" className="inline-flex items-center gap-2 border border-border-strong px-4 py-3 text-[12px] uppercase tracking-[0.2em] text-muted transition hover:border-primary/50 hover:text-primary">
              <GithubMark className="size-4" /> Source
            </a>
          </motion.div>
          <p className="mt-6 max-w-md text-[11px] leading-relaxed text-muted/80">
            Research platform. The command center runs on a labelled synthetic network by default; it complements, and does not replace, mature engines such as Zeek and Suricata.
          </p>
        </div>
        <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.7, delay: 0.2 }}>
          <HeroTopology />
        </motion.div>
      </div>
    </div>
  );
}
