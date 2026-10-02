import { describe, expect, it } from "vitest";
import { severityForRisk } from "@/lib/severity";
import { formatBytes, formatClock } from "@/lib/utils";

describe("severityForRisk", () => {
  it("maps score bands consistently with the backend", () => {
    expect([0, 10, 30, 60, 90].map(severityForRisk)).toEqual(["info", "low", "medium", "high", "critical"]);
  });
});

describe("formatters", () => {
  it("formats bytes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(1_200_000_000)).toBe("1.1 GB");
  });
  it("formats UTC clock", () => {
    expect(formatClock("2026-10-02T04:29:24Z")).toBe("04:29:24");
  });
});
