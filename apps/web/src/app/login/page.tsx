"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { CyberCard } from "@/components/cyber/CyberCard";
import { Logo } from "@/components/cyber/Logo";
import Link from "next/link";
import { ApiError, api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const { user, loading, login, guest } = useAuth();
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [guestOk, setGuestOk] = useState(false);

  useEffect(() => { api.playgroundOptions().then((o) => setGuestOk(o.guest_access)).catch(() => undefined); }, []);

  async function asGuest() {
    setBusy(true);
    setError(null);
    try {
      await guest();
      router.replace("/dashboard");
    } catch {
      setError("Guest access is unavailable right now.");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!loading && user) router.replace("/dashboard");
  }, [loading, user, router]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? (err.status === 429 ? "Too many attempts. Wait a minute and retry." : err.message) : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  const field = "w-full border border-border bg-black/60 px-3 py-2 text-[13px] text-foreground outline-none transition focus:border-primary focus:shadow-[0_0_0_1px_var(--color-primary)]";

  return (
    <main className="bg-grid bg-vignette grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex justify-center"><Logo /></div>
        <CyberCard tone="primary" title="Operator authentication">
          <form onSubmit={submit} className="space-y-4" noValidate>
            <label className="block">
              <span className="mb-1 block text-[10px] uppercase tracking-[0.25em] text-muted">Username</span>
              <input className={field} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required maxLength={48} />
            </label>
            <label className="block">
              <span className="mb-1 block text-[10px] uppercase tracking-[0.25em] text-muted">Password</span>
              <input className={field} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required maxLength={72} />
            </label>
            {error && <p role="alert" className="border border-danger/40 bg-danger/10 px-3 py-2 text-[11px] text-danger">{error}</p>}
            <button disabled={busy || !username || !password} className="w-full border border-primary bg-primary py-2.5 text-[12px] font-bold uppercase tracking-[0.25em] text-background transition hover:shadow-[0_0_20px_rgba(0,229,255,0.6)] disabled:cursor-not-allowed disabled:opacity-40">
              {busy ? "Authenticating…" : "Authenticate"}
            </button>
          </form>
          <div className="mt-4 space-y-2 border-t border-border pt-4 text-center">
            {guestOk && <button type="button" onClick={asGuest} disabled={busy} className="w-full border border-border py-2 text-[11px] uppercase tracking-[0.2em] text-muted transition hover:border-primary hover:text-primary disabled:opacity-40">Explore the live dashboard as a guest</button>}
            <Link href="/try" className="block text-[11px] uppercase tracking-[0.2em] text-primary hover:underline">Try the detection playground, no sign-in</Link>
          </div>
        </CyberCard>
        <p className="mt-4 text-center text-[10px] leading-relaxed text-muted">Sessions are role-based (ADMIN / ANALYST / VIEWER) and audit-logged.</p>
      </div>
    </main>
  );
}
