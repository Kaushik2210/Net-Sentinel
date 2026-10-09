import { describe, expect, it } from "vitest";
import { decode, encode, scaled } from "@/components/playground/share";
import type { PlaygroundOptions } from "@/lib/types";

const opts: PlaygroundOptions = {
  guest_access: false,
  scenarios: [{ id: "full", label: "Full", blurb: "" }, { id: "benign", label: "Benign", blurb: "" }],
  tunables: [{ detector: "PortScanDetector", params: [{ key: "min_ports", default: 15, min: 3, max: 200, label: "" }] }],
  detectors: [],
};

describe("share links", () => {
  it("round-trips scenario and thresholds", () => {
    const q = encode("benign", { PortScanDetector: { min_ports: 30 } });
    expect(decode(q, opts)).toEqual({ scenario: "benign", values: { PortScanDetector: { min_ports: 30 } } });
  });

  it("ignores unknown scenarios, detectors, parameters and malformed values", () => {
    const r = decode("s=evil&t=PortScanDetector.__proto__:1,Evil.min:5,PortScanDetector.min_ports:abc,PortScanDetector.min_ports:9", opts);
    expect(r.scenario).toBe("full");
    expect(r.values).toEqual({ PortScanDetector: { min_ports: 9 } });
  });

  it("clamps values to the advertised range", () => {
    expect(decode("t=PortScanDetector.min_ports:999999", opts).values.PortScanDetector.min_ports).toBe(200);
    expect(decode("t=PortScanDetector.min_ports:0", opts).values.PortScanDetector.min_ports).toBe(3);
  });
});

describe("presets", () => {
  it("scales from the defaults within bounds", () => {
    expect(scaled(opts, 2)).toEqual({ PortScanDetector: { min_ports: 30 } });
    expect(scaled(opts, 0.1)).toEqual({ PortScanDetector: { min_ports: 3 } });
    expect(scaled(opts, 1)).toEqual({});
  });
});
