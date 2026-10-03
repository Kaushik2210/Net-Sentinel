import type { NextConfig } from "next";

const isProd = process.env.NODE_ENV === "production";
// Empty NEXT_PUBLIC_API_URL means same-origin API (production behind a proxy).
const api = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const apiWs = api.replace(/^http/, "ws");

// Content-Security-Policy is applied in production only: the dev server needs eval for hot reload.
// 'unsafe-inline' for scripts is required by Next's inline bootstrap; moving to nonces is future work (docs/SECURITY.md).
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  `connect-src 'self'${api ? ` ${api} ${apiWs}` : ""}`,
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: "geolocation=(), microphone=(), camera=()" },
          ...(isProd ? [{ key: "Content-Security-Policy", value: csp }] : []),
        ],
      },
    ];
  },
};

export default nextConfig;
