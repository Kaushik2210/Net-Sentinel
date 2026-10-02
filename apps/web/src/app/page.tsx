import { Hero, Nav } from "@/components/landing/Hero";
import { Intelligence } from "@/components/landing/Intelligence";
import { Platform } from "@/components/landing/Platform";
import { Story } from "@/components/landing/Story";

export default function Landing() {
  return (
    <main className="min-h-screen">
      <Nav />
      <Hero />
      <Story />
      <Intelligence />
      <Platform />
    </main>
  );
}
