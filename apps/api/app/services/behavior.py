"""Transparent behavioral deviation scoring.

There is no learned model here, by design: every point of risk is attributable to a named
factor so an analyst can audit it. (The ML anomaly detector in Phase 4 is separate and is
always labelled as ML.)

For each baseline metric with an upper bound ``max``:
    ratio  = current / max(max, 1)
    points = min(cap, round(5 * log2(ratio)))   when ratio > 1.5, else 0

A criticality amplifier is added only when some deviation exists: a critical asset that is
behaving normally is not "risky", it is just important.
"""

import math
from dataclasses import dataclass

# metric -> (label, cap). Caps encode how much each behaviour matters as an indicator.
METRICS: dict[str, tuple[str, int]] = {
    "dns_per_hour": ("DNS request rate", 15),
    "http_per_hour": ("HTTP request rate", 10),
    "ssh_per_hour": ("SSH connection rate", 20),
    "upload_mb_per_day": ("External upload volume", 20),
    "new_destinations_per_day": ("New destinations contacted", 15),
}

RATIO_THRESHOLD = 1.5
CRITICALITY_POINTS_PER_LEVEL = 3  # level 1 -> 0, level 5 -> 12


@dataclass(frozen=True)
class Factor:
    key: str
    label: str
    points: int
    detail: str

    def as_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "points": self.points, "detail": self.detail}


def metric_points(current: float, upper: float, cap: int) -> int:
    ratio = current / max(upper, 1.0)
    if ratio <= RATIO_THRESHOLD:
        return 0
    return min(cap, round(5 * math.log2(ratio)))


def score_device(baseline: dict, current: dict, criticality: int) -> tuple[int, list[dict]]:
    """Return (risk 0-100, ordered factor list). Pure function: easy to unit test."""
    factors: list[Factor] = []
    for key, (label, cap) in METRICS.items():
        if key not in baseline or key not in current:
            continue
        upper = float(baseline[key].get("max", 0))
        value = float(current[key])
        pts = metric_points(value, upper, cap)
        if pts > 0:
            factors.append(
                Factor(
                    key,
                    label,
                    pts,
                    f"{value:g} observed vs baseline max {upper:g} ({value / max(upper, 1):.1f}x)",
                )
            )

    if factors:
        crit_pts = (criticality - 1) * CRITICALITY_POINTS_PER_LEVEL
        if crit_pts:
            factors.append(
                Factor("criticality", "Asset criticality", crit_pts, f"criticality level {criticality}/5")
            )
    factors.sort(key=lambda f: f.points, reverse=True)
    total = min(100, sum(f.points for f in factors))
    return total, [f.as_dict() for f in factors]


def deviation_score(baseline: dict, current: dict) -> int:
    """Behavior deviation 0-100 across metrics only (excludes the criticality amplifier)."""
    total = 0
    cap_total = 0
    for key, (_, cap) in METRICS.items():
        if key in baseline and key in current:
            cap_total += cap
            total += metric_points(float(current[key]), float(baseline[key].get("max", 0)), cap)
    return round(100 * total / cap_total) if cap_total else 0


def severity_for_risk(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "info"
