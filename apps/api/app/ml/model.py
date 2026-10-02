"""Anomaly model interface and the Isolation Forest implementation.

``AnomalyModel`` is the extension point: an autoencoder, XGBoost or graph model can implement the
same three methods and be swapped in without touching detection or the API.

Honesty notes (also in docs/ML-METHODOLOGY.md):
* The score is a statistical outlier score relative to the benign training data. It says "this
  looks unlike the baseline", never "this is attack X".
* Isolation Forest has no native per-feature explanation. Contributions are the standardised
  deviation (z-score) of each feature from the training distribution, a transparent proxy.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.ml.features import FEATURE_LABELS, FEATURES


@dataclass
class Contribution:
    feature: str
    label: str
    value: float
    baseline_mean: float
    z: float


@dataclass
class AnomalyResult:
    entity: str
    score: float  # raw anomaly score, higher = more anomalous
    risk: int  # 0-100, 50 == decision threshold
    is_anomaly: bool
    contributions: list[Contribution]


class AnomalyModel(ABC):
    name: str

    @abstractmethod
    def fit(self, X: pd.DataFrame) -> None: ...

    @abstractmethod
    def score(self, X: pd.DataFrame) -> list[AnomalyResult]: ...

    @abstractmethod
    def describe(self) -> dict: ...


class IsolationForestModel(AnomalyModel):
    name = "IsolationForest"

    def __init__(self, n_estimators: int = 200, contamination: float = 0.005, random_state: int = 42):
        self._params = {"n_estimators": n_estimators, "contamination": contamination, "random_state": random_state}
        self._forest = IsolationForest(**self._params)
        self._mean = pd.Series(dtype=float)
        self._std = pd.Series(dtype=float)
        self._median = 0.0
        self._threshold = 0.0
        self._n_train = 0

    def fit(self, X: pd.DataFrame) -> None:
        if len(X) < 50:
            raise ValueError("need at least 50 training windows")
        self._forest.fit(X[FEATURES])
        train_scores = -self._forest.score_samples(X[FEATURES])
        self._mean = X[FEATURES].mean()
        # Floor the std so near-constant features don't make every deviation look infinite.
        self._std = X[FEATURES].std().replace(0, 1.0).clip(lower=1e-6)
        self._median = float(np.median(train_scores))
        self._threshold = float(np.percentile(train_scores, 99.5))
        self._n_train = len(X)

    def score(self, X: pd.DataFrame) -> list[AnomalyResult]:
        if X.empty:
            return []
        raw = -self._forest.score_samples(X[FEATURES])
        span = max(self._threshold - self._median, 1e-6)
        out = []
        for entity, s in zip(X.index, raw, strict=True):
            risk = int(round(min(100.0, max(0.0, 50.0 * (s - self._median) / span))))
            z = (X.loc[entity, FEATURES] - self._mean) / self._std
            top = z.abs().sort_values(ascending=False).head(4).index
            contribs = [
                Contribution(f, FEATURE_LABELS[f], round(float(X.loc[entity, f]), 2), round(float(self._mean[f]), 2), round(float(z[f]), 1))
                for f in top
            ]
            out.append(AnomalyResult(str(entity), round(float(s), 4), risk, bool(s > self._threshold), contribs))
        return out

    def describe(self) -> dict:
        return {
            "algorithm": self.name,
            "features": FEATURES,
            "training_windows": self._n_train,
            "parameters": self._params,
            "decision_threshold": round(self._threshold, 4),
            "training_median": round(self._median, 4),
            "trained_on": "synthetic benign telemetry (simulation)",
        }
