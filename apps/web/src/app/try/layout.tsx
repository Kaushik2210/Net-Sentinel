import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Detection playground",
  description: "Pick a traffic scenario, tune the detectors, compare runs and try the tuning challenge. No account needed.",
};

export default function TryLayout({ children }: { children: React.ReactNode }) {
  return children;
}
