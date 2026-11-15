"""
Feature definition shared by training and live inference.

Keeping this in one place guarantees the scan-time code feeds the model the
same columns, in the same order, with the same transforms it was trained on.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

import numpy as np

# Order matters: the model is trained on exactly these columns.
FEATURES: tuple[str, ...] = ("cvss_score", "epss_score")

ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "kev_classifier.pkl"
METRICS_PATH = ARTIFACT_DIR / "kev_classifier_metrics.json"

_EPS = 1e-5


def _num(value: Any) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return np.nan
    return f if np.isfinite(f) else np.nan


def to_matrix(rows: Iterable[Mapping[str, Any]]) -> np.ndarray:
    """
    Turn CVE dicts (e.g. VulnDB rows) into the (n, 2) float matrix the model
    expects. Missing or malformed scores become NaN; the pipeline imputes them.
    """
    return np.array([[_num(r.get(f)) for f in FEATURES] for r in rows], dtype=float).reshape(-1, len(FEATURES))


def scale_features(X: np.ndarray) -> np.ndarray:
    """
    Model-side transform used inside the pickled pipeline:
      * CVSS 0-10   -> 0-1
      * EPSS 0-1    -> logit(EPSS). EPSS is extremely skewed (most CVEs < 0.01),
                       so a linear model separates far better on the log-odds scale.
    Must stay a module-level function so the pipeline can be pickled by reference.
    """
    X = np.asarray(X, dtype=float).copy()
    X[:, 0] = X[:, 0] / 10.0
    p = np.clip(X[:, 1], _EPS, 1 - _EPS)
    X[:, 1] = np.log(p / (1 - p))
    return X
