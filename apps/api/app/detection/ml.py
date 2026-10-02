from app.detection.base import Detector, EventRecord, Finding, register

ALERT_RISK = 50  # the model's own decision threshold
# Effect-size gate: Isolation Forest scores saturate for extreme outliers (a live attacker scored 72
# while a benign tail sample scored 76), so the score cannot be raised further to cut false positives.
# Instead also require one feature to deviate by >= MIN_Z standard deviations. On 1,656 held-out
# benign windows the largest |z| was 4.6 (see docs/ML-METHODOLOGY.md).
MIN_Z = 6.0


@register
class MLAnomalyDetector(Detector):
    """Isolation Forest outlier detector. Output is always labelled ML and never names an attack type."""

    name = "MLAnomalyDetector"
    detection_class = "ML"

    @classmethod
    def defaults(cls):
        return {"alert_risk": ALERT_RISK, "min_z": MIN_Z}

    def detect(self, events: list[EventRecord]) -> list[Finding]:
        from app.ml.service import score_events  # lazy: app.ml depends on app.detection.base

        by_src: dict[str, list[EventRecord]] = {}
        for e in events:
            by_src.setdefault(e.src_ip, []).append(e)
        out = []
        for r in score_events(events):
            if r.risk < self.params["alert_risk"] or max(abs(c.z) for c in r.contributions) < self.params["min_z"]:
                continue
            evs = by_src.get(r.entity, [])
            drivers = "; ".join(f"{c.label} {c.value:g} (baseline {c.baseline_mean:g}, z={c.z:+.1f})" for c in r.contributions[:3])
            out.append(
                Finding(
                    detector=self.name, detection_class="ML", event_type="ml_anomaly",
                    severity="critical" if r.risk >= 95 else "high" if r.risk >= 85 else "medium",
                    confidence=round(0.5 + 0.4 * r.risk / 100, 2), source=r.entity, destination="multiple",
                    timestamp=min(e.ts for e in evs) if evs else events[0].ts,
                    explanation=f"Statistical outlier vs benign baseline (risk {r.risk}/100). Top drivers: {drivers}.",
                    evidence_ids=[e.id for e in evs][:50], mitre_techniques=[],
                    facts={"anomaly_score": r.score, "risk": r.risk, "drivers": [c.__dict__ for c in r.contributions]},
                )
            )
        return out
