import type { Metadata, Viewport } from "next";
import { JetBrains_Mono, Orbitron } from "next/font/google";
import { Atmosphere } from "@/components/fx/Atmosphere";
import { ScanlineOverlay } from "@/components/cyber/ScanlineOverlay";
import { AuthProvider } from "@/lib/auth";
import "./globals.css";

const orbitron = Orbitron({ subsets: ["latin"], variable: "--font-orbitron", weight: ["500", "700", "900"] });
const jetbrains = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains" });

export const metadata: Metadata = {
  title: "NetSentinel | Explainable Network Digital Twin",
  description:
    "An explainable network security platform that turns network telemetry into behavioral intelligence, attack timelines and evidence-backed investigations.",
};

export const viewport: Viewport = { themeColor: "#05070a" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${orbitron.variable} ${jetbrains.variable}`}>
      <body>
        <AuthProvider>{children}</AuthProvider>
        <ScanlineOverlay />
        <Atmosphere />
      </body>
    </html>
  );
}
