# ML Methodology

NetSentinel's ML component is an **unsupervised statistical outlier detector**. It answers
"does this host's recent traffic look unlike the benign baseline?" It does **not** classify attacks,
and its alerts never carry MITRE techniques or attack names.

## Pipeline

```
events (10 min window) ─▶ per-source features ─▶ IsolationForest ─▶ score ─▶ risk 0–100 ─▶ effect-size gate ─▶ ML alert
```

### Features (one row per internal source IP)

connection rate, bytes sent/min, bytes received/min, unique destinations, unique destination ports,
failed connections/min, DNS queries/min, protocol entropy, mean connection duration, outbound/inbound byte ratio.
Rates are normalised per minute so windows of different length stay comparable. Sources with fewer than
5 events are not scored (too little data to be honest).

### Model

`sklearn.ensemble.IsolationForest` (200 trees, fixed seed), behind the `AnomalyModel` interface
(`fit`, `score`, `describe`) so an autoencoder, XGBoost or graph model can be swapped in later.

### Training data

12 independent 10-minute windows of **synthetic benign** traffic from the simulator (552 device-windows),
generated at startup in ~2 s. There is no labelled real-world data in the repository.

### Score to risk

`anomaly = -score_samples(x)` (higher is more anomalous). Risk is a linear map where the training median
is 0, the 99.5th percentile of training scores (the decision threshold) is 50, capped at 100.

### Explanation

Isolation Forest has no native feature attribution. Each feature is explained by its standardised deviation
`z = (value − training mean) / training std`; the four largest |z| are reported with value and baseline.
This is a transparent proxy, not SHAP, and is described as such in the UI.

### Alert gate

An ML alert needs **risk ≥ 50 (the model's decision threshold) and max |z| ≥ 6**. Isolation Forest scores
saturate for extreme outliers, so raising the score cutoff does not help: in a live run an attacker scored 72
while a benign tail sample scored 76. The effect size separates them cleanly instead: across 1,656 held-out
benign windows (three unseen seeds) the largest |z| was 4.6 and none passed the gate, while the attacker's
largest |z| was in the tens of thousands.

## Warm-up

Features are rates over a 10-minute window and the model was trained on full windows. Scoring a window that has barely begun makes every host look far quieter than baseline
and produced false ML alerts in the first minutes after startup (found while running the stack in Docker). Two guards now apply: scoring needs the *data* to span at least 75% of the
window, and live scoring additionally needs ingestion to have been running for 75% of the window (back-dated events such as a replayed or injected scenario can make the data span look full
while benign traffic is only minutes old). During warm-up (about 7.5 minutes after start) ML alerts and scores are withheld; rule and behavioral detection are unaffected. Regression tests cover both.

## Behavioral vs ML

Two different things, shown with different labels:

| Class | Source | Meaning |
|---|---|---|
| `BEHAVIORAL` | per-device baseline arithmetic (`services/behavior.py`) | named metrics exceed a stated baseline |
| `ML` | Isolation Forest | multivariate statistical outlier |

## Evaluation status and limitations

- The benign data and the attack scenario are both synthetic and were written by the same author, so the
  result shows the pipeline works, **not** real-world accuracy.
- In the simulator every device shares one benign profile, so the model cannot learn per-role norms (a database
  and a workstation are scored against the same baseline).
- Fixed 10-minute windows miss slow-and-low behaviour.
- Phase 10 will evaluate on public datasets (CICIDS-style, UNSW-NB15-style) with precision, recall, F1,
  false-positive rate and detection latency, comparing rule-only, ML-only and hybrid.
