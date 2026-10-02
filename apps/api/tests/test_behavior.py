from app.services.behavior import deviation_score, metric_points, score_device, severity_for_risk

BASELINE = {
    "dns_per_hour": {"min": 28, "max": 70},
    "http_per_hour": {"min": 12, "max": 30},
    "ssh_per_hour": {"min": 0, "max": 2},
    "upload_mb_per_day": {"min": 0, "max": 50},
    "new_destinations_per_day": {"min": 0, "max": 5},
}


def test_normal_behavior_scores_zero_even_for_critical_assets():
    current = {k: v["max"] * 0.8 for k, v in BASELINE.items()}
    risk, factors = score_device(BASELINE, current, criticality=5)
    assert risk == 0
    assert factors == []  # criticality alone must not create risk


def test_below_threshold_ratio_is_not_a_deviation():
    assert metric_points(current=100, upper=70, cap=15) == 0  # 1.43x < 1.5x


def test_points_are_capped():
    assert metric_points(current=1_000_000, upper=2, cap=20) == 20


def test_pc07_style_scenario_is_explained_factor_by_factor():
    current = {"dns_per_hour": 1240, "http_per_hour": 44, "ssh_per_hour": 48,
               "upload_mb_per_day": 1200, "new_destinations_per_day": 17}
    risk, factors = score_device(BASELINE, current, criticality=2)
    keys = {f["key"] for f in factors}
    assert {"dns_per_hour", "ssh_per_hour", "upload_mb_per_day", "criticality"} <= keys
    assert risk == min(100, sum(f["points"] for f in factors))  # score == sum of shown factors
    assert factors == sorted(factors, key=lambda f: f["points"], reverse=True)
    assert all(f["detail"] for f in factors)


def test_deviation_score_excludes_criticality_and_is_bounded():
    current = {"dns_per_hour": 1240, "http_per_hour": 44, "ssh_per_hour": 48,
               "upload_mb_per_day": 1200, "new_destinations_per_day": 17}
    assert 0 < deviation_score(BASELINE, current) <= 100
    assert deviation_score(BASELINE, {}) == 0


def test_severity_bands():
    assert [severity_for_risk(s) for s in (0, 10, 30, 60, 90)] == ["info", "low", "medium", "high", "critical"]
