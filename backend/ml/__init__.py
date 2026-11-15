"""
KEV exploitation classifier (owner: Shuja).

Training:   python -m ml.train_kev_classifier
Artifact:   ml/artifacts/kev_classifier.pkl  (a fitted scikit-learn Pipeline)
Inputs:     [[cvss_score, epss_score]]  in that order, NaN allowed for missing values
Output:     predict_proba(X)[:, 1] = probability the CVE is in CISA KEV
"""

from .features import FEATURES, MODEL_PATH, METRICS_PATH, to_matrix

__all__ = ["FEATURES", "MODEL_PATH", "METRICS_PATH", "to_matrix"]
