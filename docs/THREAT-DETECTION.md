# Threat Detection

## Principles

1. **Provenance is part of the data.** Every alert has `detection_class`: `RULE`, `BEHAVIORAL`, `ML` or `CORRELATED`. Only `RULE` exists today; the others arrive in phases 4–5 and are shown with distinct colours.
2. **Every alert is explainable.** Each carries a plain-language explanation, structured facts, confidence, MITRE techniques and the IDs of the events that triggered it (stored as `evidence` rows).
3. **Detectors are pure.** A detector is a function from an event window to findings. It does no I/O, so it is unit-testable and cannot corrupt state.

## Standardized output

`Finding` (`app/detection/base.py`) maps onto the `alerts` table:
`id, timestamp, source, destination, event_type, severity, confidence, detector, mitre_techniques`
plus `explanation`, `detection_class`, and evidence.

## Built-in detectors

| Detector | Fires when (defaults) | MITRE |
|---|---|---|
| `PortScanDetector` | ≥15 distinct ports on one host (vertical) or ≥10 distinct hosts (horizontal) from one source | T1046, T1595 |
| `BruteForceDetector` | ≥10 `auth_failure` events from one source to one service | T1110 |
| `LateralMovementDetector` | one internal source authenticates to ≥3 internal hosts over SSH/SMB/RDP/WinRM | T1021, T1078 |
| `DNSAnomalyDetector` | ≥200 queries with ≥60% unique names, or ≥15 long high-entropy labels (Shannon entropy ≥3.5) | T1071.004 |
| `ConnectionAnomalyDetector` | internal host contacts ≥40 distinct external hosts in the window | T1090 |
| `DataExfiltrationDetector` | ≥100 MB sent from an internal host to one external host in the window | T1041, T1048 |
| `SuspiciousProtocolDetector` | ≥3 connections to ports such as 23, 4444, 6667, 9001 | T1571 |
| `CustomRuleDetector` | analyst-defined data rules (event type, ports, protocol, min count); no expression evaluation | per rule |

Thresholds are starting points, not tuned values. They can be overridden through `detection_rules.parameters`,
and any detector can be disabled (ADMIN, audited).

Confidence rises with how far an observation exceeds its threshold, from 0.55 upward, capped below 1.0.
It expresses *how clear-cut the rule match is*, not the probability of malicious intent.

## Adding a detector

```python
from app.detection import Detector, register

@register
class MyDetector(Detector):
    name = "MyDetector"
    mitre = ("T1xxx",)

    def detect(self, events):  # list[EventRecord] -> list[Finding]
        ...
```

Import the module in `app/detection/__init__.py`. Nothing else changes: the engine, seeding of
`detection_rules`, API listing and persistence pick it up through the registry.
A detector that raises is logged and skipped; the others still run.

## Runtime

A background loop (every 10 s) runs the engine over the last 10 minutes of events, de-duplicates against alerts
raised in the previous 15 minutes (same detector, source and event type) and publishes new alerts to WebSocket clients.

## Validation so far

- Unit tests per detector, including below-threshold silence and the plugin and failure-isolation contract.
- **False-positive check:** 10 minutes of simulated benign traffic at the default rate yields zero findings.
- **End-to-end:** the labelled attack scenario (`sim-attack`) is detected at every stage and maps to T1046, T1110, T1021, T1041.

## Limitations

- Thresholds are fixed and the benign baseline is synthetic; real networks will need tuning.
- Window-based counting misses slow-and-low activity spread beyond the window.
- The attack scenario was written alongside the detectors, so detecting it demonstrates the pipeline,
  not detection accuracy. Honest evaluation against public datasets comes in phase 10.
- Detection of an attacker who uses legitimate services at normal volume is out of scope for these rules.
