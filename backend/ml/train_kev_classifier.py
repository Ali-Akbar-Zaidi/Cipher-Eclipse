"""
Train the KEV exploitation classifier for Cipher Eclipse.

Question the model answers: given only a CVE's CVSS base score and its EPSS
probability, how likely is it that the CVE is in CISA's Known Exploited
Vulnerabilities (KEV) catalogue?

Data: the local vulnerabilities.db built by `python -m vulndb.build_db`
(NVD CVSS + FIRST EPSS, with KEV in its own table). KEV is used ONLY as the
label here, never as an input, exactly as the proposal requires.

Method
  1. Load every CVE that has a CVSS and/or EPSS score, label = in KEV.
  2. Stratified 80/20 train/test split (fixed seed). The test split is held
     out until the very end.
  3. 5-fold stratified cross-validation on the training split to choose
     between Logistic Regression and Histogram Gradient Boosting, scored by
     average precision (PR-AUC), which is the honest metric for a ~0.5%
     positive rate.
  4. Refit the winner on the full training split and evaluate it on the test
     split against three non-learned baselines: plain CVSS sorting, plain EPSS
     sorting and the transparent weighted score (CVSS + EPSS).
  5. Export the fitted pipeline as ml/artifacts/kev_classifier.pkl plus a
     metrics JSON and a Markdown report for the project write-up.

Usage (from backend/):
    python -m ml.train_kev_classifier
    python -m ml.train_kev_classifier --db data/vulnerabilities.db --test-size 0.2 --seed 42
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Callable

import joblib
import numpy as np
import sklearn
from sklearn.base import clone
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from .features import ARTIFACT_DIR, FEATURES, METRICS_PATH, MODEL_PATH, scale_features

logger = logging.getLogger("ml.train")

# Weights of the transparent baseline score (CVSS + EPSS part of the proposal's
# weighted score; service exposure is host-level and not available per CVE).
W_CVSS = 0.4
W_EPSS = 0.6


# --------------------------------------------------------------------------- data
def load_dataset(db_path: Path) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Return X (n, 2) [cvss, epss] with NaN for missing, y (n,) KEV labels, CVE IDs."""
    if not db_path.exists():
        raise SystemExit(f"{db_path} not found. Build it first: python -m vulndb.build_db")
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "kev" not in tables:
            raise SystemExit("The database has no `kev` table; rebuild it with KEV available.")
        rows = conn.execute(
            """
            SELECT v.cve_id, v.cvss_score, v.epss_score,
                   CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END AS in_kev
            FROM vulnerabilities v
            LEFT JOIN kev k ON k.cve_id = v.cve_id
            WHERE v.cvss_score IS NOT NULL OR v.epss_score IS NOT NULL
            """
        ).fetchall()
    finally:
        conn.close()
    ids = [r[0] for r in rows]
    X = np.array([[np.nan if r[1] is None else r[1], np.nan if r[2] is None else r[2]] for r in rows],
                 dtype=float)
    y = np.array([r[3] for r in rows], dtype=int)
    return X, y, ids


# --------------------------------------------------------------------------- models
def candidate_models(seed: int) -> dict[str, Pipeline]:
    return {
        # Linear model on [CVSS/10, logit(EPSS)], missing values imputed with the
        # median plus a "was missing" indicator column.
        "logistic_regression": Pipeline([
            ("impute", SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True)),
            ("transform", FunctionTransformer(scale_features)),
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, C=1.0)),
        ]),
        # Gradient boosting handles NaN natively. Monotonic constraints force the
        # model to never lower risk when CVSS or EPSS goes up, which keeps the
        # ranking explainable to a defender.
        "hist_gradient_boosting": Pipeline([
            ("clf", HistGradientBoostingClassifier(
                learning_rate=0.05,
                max_iter=400,
                max_leaf_nodes=15,
                min_samples_leaf=40,
                l2_regularization=1.0,
                monotonic_cst=[1, 1],
                early_stopping=True,
                validation_fraction=0.1,
                n_iter_no_change=30,
                random_state=seed,
            )),
        ]),
    }


# --------------------------------------------------------------------------- metrics
def _fill(x: np.ndarray, value: float = 0.0) -> np.ndarray:
    return np.where(np.isnan(x), value, x)


def baseline_scores(X: np.ndarray) -> dict[str, np.ndarray]:
    cvss = _fill(X[:, 0]) / 10.0
    epss = _fill(X[:, 1])
    return {
        "cvss_only": cvss,
        "epss_only": epss,
        "weighted_score": W_CVSS * cvss + W_EPSS * epss,
    }


def precision_at_k(y: np.ndarray, score: np.ndarray, k: int) -> float:
    k = min(k, len(y))
    # Stable sort with a tiny random tie-break so ties (very common for CVSS)
    # are not resolved in the label's favour by input order.
    rng = np.random.default_rng(0)
    order = np.lexsort((rng.random(len(score)), -score))
    return float(y[order[:k]].mean())


def recall_at_top_fraction(y: np.ndarray, score: np.ndarray, frac: float) -> float:
    k = max(1, int(round(len(y) * frac)))
    rng = np.random.default_rng(0)
    order = np.lexsort((rng.random(len(score)), -score))
    return float(y[order[:k]].sum() / max(1, y.sum()))


def evaluate(y: np.ndarray, score: np.ndarray, *, is_probability: bool) -> dict[str, float]:
    out = {
        "roc_auc": float(roc_auc_score(y, score)),
        "average_precision": float(average_precision_score(y, score)),
        "precision_at_50": precision_at_k(y, score, 50),
        "precision_at_100": precision_at_k(y, score, 100),
        "precision_at_500": precision_at_k(y, score, 500),
        "recall_at_top_1pct": recall_at_top_fraction(y, score, 0.01),
        "recall_at_top_5pct": recall_at_top_fraction(y, score, 0.05),
        "recall_at_top_10pct": recall_at_top_fraction(y, score, 0.10),
    }
    if is_probability:
        out["brier_score"] = float(brier_score_loss(y, score))
    return {k: round(v, 5) for k, v in out.items()}


# --------------------------------------------------------------------------- report
def render_report(summary: dict[str, Any]) -> str:
    cols = ["roc_auc", "average_precision", "precision_at_100", "recall_at_top_1pct",
            "recall_at_top_5pct", "recall_at_top_10pct"]
    lines = [
        "# KEV classifier: training report",
        "",
        f"Generated {summary['trained_at']} with scikit-learn {summary['sklearn_version']}.",
        "",
        "## Data",
        "",
        f"* Source: `{summary['data']['db']}` (NVD CVSS + FIRST EPSS; label = CISA KEV membership)",
        f"* EPSS score date: {summary['data'].get('epss_score_date') or 'unknown'}; "
        f"KEV catalogue version: {summary['data'].get('kev_catalog_version') or 'unknown'}",
        f"* CVEs: {summary['data']['rows']:,} ({summary['data']['positives']:,} in KEV, "
        f"{summary['data']['positive_rate']:.3%})",
        f"* Missing CVSS: {summary['data']['missing_cvss']:,}; missing EPSS: {summary['data']['missing_epss']:,}",
        f"* Split: stratified {1 - summary['split']['test_size']:.0%}/{summary['split']['test_size']:.0%} "
        f"train/test, seed {summary['split']['seed']} "
        f"(train {summary['split']['train_rows']:,}, test {summary['split']['test_rows']:,})",
        "",
        "## Model selection (5-fold CV on the training split, average precision)",
        "",
        "| Model | Mean AP | Std |",
        "|---|---|---|",
    ]
    for name, cv in summary["cross_validation"].items():
        lines.append(f"| {name} | {cv['mean_average_precision']:.4f} | {cv['std']:.4f} |")
    lines += [
        "",
        f"Selected: **{summary['selected_model']}**",
        "",
        "## Held-out test split",
        "",
        "| Ranker | " + " | ".join(cols) + " |",
        "|---|" + "---|" * len(cols),
    ]
    for name, m in summary["test_metrics"].items():
        lines.append(f"| {name} | " + " | ".join(f"{m[c]:.4f}" for c in cols) + " |")
    lines += [
        "",
        "`recall_at_top_k%`: share of all KEV CVEs in the test split that land in the top k% of the ranking.",
        "",
        "## Using the model",
        "",
        "```python",
        "import joblib",
        "from ml.features import MODEL_PATH, to_matrix",
        "model = joblib.load(MODEL_PATH)",
        "p_kev = model.predict_proba(to_matrix([{'cvss_score': 9.8, 'epss_score': 0.97}]))[:, 1]",
        "```",
        "",
    ]
    return "\n".join(lines)


def _display_path(path: Path) -> str:
    """Path relative to backend/ when possible, so the metrics file is machine-independent."""
    backend = Path(__file__).resolve().parents[1]
    try:
        return path.resolve().relative_to(backend).as_posix()
    except ValueError:
        return path.as_posix()


def _db_metadata(db_path: Path) -> dict[str, str]:
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            return {k: v for k, v in conn.execute("SELECT key, value FROM metadata")}
        finally:
            conn.close()
    except sqlite3.Error:
        return {}


# --------------------------------------------------------------------------- main
def train(db_path: Path, *, test_size: float, seed: int, out_dir: Path, folds: int) -> dict[str, Any]:
    t0 = time.perf_counter()
    X, y, _ = load_dataset(db_path)
    if y.sum() < folds * 2:
        raise SystemExit(f"Only {y.sum()} KEV positives found; not enough to train.")
    logger.info("Loaded %d CVEs, %d in KEV (%.3f%%)", len(y), y.sum(), 100 * y.mean())

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=test_size, stratify=y, random_state=seed)

    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    cv_results: dict[str, dict[str, float]] = {}
    models = candidate_models(seed)
    for name, model in models.items():
        scores = cross_val_score(model, X_tr, y_tr, cv=cv, scoring="average_precision", n_jobs=-1)
        cv_results[name] = {"mean_average_precision": round(float(scores.mean()), 5),
                            "std": round(float(scores.std()), 5),
                            "folds": [round(float(s), 5) for s in scores]}
        logger.info("CV %-24s AP %.4f +/- %.4f", name, scores.mean(), scores.std())

    best_name = max(cv_results, key=lambda n: cv_results[n]["mean_average_precision"])
    best = clone(models[best_name]).fit(X_tr, y_tr)

    test_metrics: dict[str, dict[str, float]] = {}
    # Every candidate is reported on the test split for the write-up, but the
    # choice above was made on CV only, so the test split never drove selection.
    for name, model in models.items():
        fitted = best if name == best_name else clone(model).fit(X_tr, y_tr)
        test_metrics[f"model:{name}"] = evaluate(y_te, fitted.predict_proba(X_te)[:, 1], is_probability=True)
    for name, score in baseline_scores(X_te).items():
        test_metrics[f"baseline:{name}"] = evaluate(y_te, score, is_probability=False)

    # Final artifact: refit the selected pipeline on ALL labelled data so the
    # shipped model sees every KEV example; reported metrics stay the held-out ones.
    final = clone(models[best_name]).fit(X, y)

    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / MODEL_PATH.name
    joblib.dump(final, model_path, compress=3)

    meta = _db_metadata(db_path)
    summary: dict[str, Any] = {
        "trained_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "sklearn_version": sklearn.__version__,
        "features": list(FEATURES),
        "label": "in CISA KEV catalogue",
        "selected_model": best_name,
        "model_path": _display_path(model_path),
        "data": {
            "db": str(db_path).replace("\\", "/"),
            "rows": int(len(y)),
            "positives": int(y.sum()),
            "positive_rate": float(y.mean()),
            "missing_cvss": int(np.isnan(X[:, 0]).sum()),
            "missing_epss": int(np.isnan(X[:, 1]).sum()),
            "epss_score_date": meta.get("epss_score_date"),
            "kev_catalog_version": meta.get("kev_catalog_version"),
            "nvd_built_at": meta.get("built_at"),
        },
        "split": {"test_size": test_size, "seed": seed, "train_rows": int(len(y_tr)),
                  "test_rows": int(len(y_te)), "test_positives": int(y_te.sum())},
        "cross_validation": cv_results,
        "test_metrics": test_metrics,
        "baseline_weights": {"cvss": W_CVSS, "epss": W_EPSS},
        "duration_seconds": round(time.perf_counter() - t0, 1),
    }
    (out_dir / METRICS_PATH.name).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "kev_classifier_report.md").write_text(render_report(summary), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    default_db = Path(os.environ.get("VULNDB_PATH", "data/vulnerabilities.db"))
    p = argparse.ArgumentParser(description="Train the CVSS+EPSS -> KEV classifier.")
    p.add_argument("--db", type=Path, default=default_db, help=f"vulnerabilities.db (default {default_db})")
    p.add_argument("--out-dir", type=Path, default=ARTIFACT_DIR)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--folds", type=int, default=5)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    summary = train(args.db, test_size=args.test_size, seed=args.seed, out_dir=args.out_dir, folds=args.folds)
    print(render_report(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
