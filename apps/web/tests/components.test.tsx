import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RiskFactors } from "@/components/cyber/ThreatScore";
import { ThreatBadge } from "@/components/cyber/ThreatBadge";

describe("RiskFactors", () => {
  it("shows every factor and the total", () => {
    render(<RiskFactors total={35} factors={[
      { key: "a", label: "SSH rate", points: 20, detail: "48 vs 2" },
      { key: "b", label: "DNS rate", points: 15, detail: "1240 vs 70" },
    ]} />);
    expect(screen.getByText("+20")).toBeTruthy();
    expect(screen.getByText("SSH rate")).toBeTruthy();
    expect(screen.getByText("total risk score")).toBeTruthy();
  });
  it("explains capping when points exceed 100", () => {
    render(<RiskFactors total={100} factors={[{ key: "a", label: "x", points: 70, detail: "" }, { key: "b", label: "y", points: 60, detail: "" }]} />);
    expect(screen.getByText(/capped at 100 from 130/)).toBeTruthy();
  });
  it("has an explicit empty state", () => {
    render(<RiskFactors total={0} factors={[]} />);
    expect(screen.getByText(/within baseline/)).toBeTruthy();
  });
});

describe("ThreatBadge", () => {
  it("renders the severity label", () => {
    render(<ThreatBadge severity="critical" />);
    expect(screen.getByText("CRITICAL")).toBeTruthy();
  });
});
