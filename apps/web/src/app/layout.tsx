import type { Metadata, Viewport } from "next";
import { JetBrains_Mono, Orbitron } from "next/font/google";
import { Atmosphere } from "@/components/fx/Atmosphere";
import { ScanlineOverlay } from "@/components/cyber/ScanlineOverlay";
import { AuthProvider } from "@/lib/auth";
import "./globals.css";

const orbitron = Orbitron({ subsets: ["latin"], variable: "--font-orbitron", weight: ["500", "700", "900"] });
const jetbrains = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains" });

const DESCRIPTION =
  "An explainable network security research platform: it turns network telemetry into behavioural intelligence, reconstructed attack chains and evidence-backed investigations. Try the detection playground with no sign-in.";

export const metadata: Metadata = {
  title: { default: "NetSentinel | Explainable Network Digital Twin", template: "%s | NetSentinel" },
  description: DESCRIPTION,
  applicationName: "NetSentinel",
  openGraph: { title: "NetSentinel", description: DESCRIPTION, type: "website", siteName: "NetSentinel" },
  twitter: { card: "summary", title: "NetSentinel", description: DESCRIPTION },
};

export const viewport: Viewport = { themeColor: "#05070a" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${orbitron.variable} ${jetbrains.variable}`}>
      <body>
        <a href="#main" className="skip-link">Skip to content</a>
        <AuthProvider>{children}</AuthProvider>
        <ScanlineOverlay />
        <Atmosphere />
      </body>
    </html>
  );
}
