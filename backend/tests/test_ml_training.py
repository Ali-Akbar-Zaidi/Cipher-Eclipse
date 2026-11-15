"""KEV classifier training on a small synthetic vulnerabilities.db (offline)."""

from __future__ import annotations

import json
import sqlite3

import joblib
import numpy as np
import pytest

from ml.features import FEATURES, to_matrix
from ml.train_kev_classifier import load_dataset, train


@pytest.fixture
def tiny_db(tmp_path):
    rng = np.random.default_rng(1)
    db = tmp_path / "v.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE vulnerabilities (cve_id TEXT PRIMARY KEY, cvss_score REAL, epss_score REAL);
        CREATE TABLE kev (cve_id TEXT PRIMARY KEY);
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
    """)
    rows, kev = [], []
    for i in range(4000):
        cvss = round(float(rng.uniform(2, 10)), 1)
        epss = float(rng.beta(0.3, 8))
        cid = f"CVE-2020-{10000 + i}"
        # exploitation is driven mostly by EPSS, a bit by CVSS
        if rng.random() < 0.005 + 2.5 * epss + 0.02 * (cvss > 9):
            kev.append((cid,))
        rows.append((cid, None if i % 97 == 0 else cvss, epss))
    rows.append(("CVE-2020-99999", None, None))  # no scores at all: excluded
    conn.executemany("INSERT INTO vulnerabilities VALUES (?,?,?)", rows)
    conn.executemany("INSERT INTO kev VALUES (?)", kev)
    conn.execute("INSERT INTO metadata VALUES ('epss_score_date', '2026-11-15')")
    conn.commit()
    conn.close()
    return db


def test_load_dataset_uses_kev_only_as_label(tiny_db):
    X, y, ids = load_dataset(tiny_db)
    assert X.shape == (4000, len(FEATURES)) and len(y) == len(ids) == 4000
    assert np.isnan(X[:, 0]).sum() == len(range(0, 4000, 97))
    assert set(np.unique(y)) == {0, 1}


def test_train_exports_loadable_model_and_metrics(tiny_db, tmp_path):
    out = tmp_path / "artifacts"
    summary = train(tiny_db, test_size=0.25, seed=0, out_dir=out, folds=3)
    assert summary["selected_model"] in summary["cross_validation"]
    assert {"baseline:cvss_only", "baseline:epss_only", "baseline:weighted_score"} <= set(summary["test_metrics"])
    assert (out / "kev_classifier_report.md").exists()
    assert json.loads((out / "kev_classifier_metrics.json").read_text())["features"] == list(FEATURES)

    model = joblib.load(out / "kev_classifier.pkl")
    p = model.predict_proba(to_matrix([
        {"cvss_score": 9.8, "epss_score": 0.95},
        {"cvss_score": 9.8, "epss_score": 0.001},
        {"cvss_score": None, "epss_score": 0.5},   # missing CVSS is imputed, not an error
    ]))[:, 1]
    assert p.shape == (3,) and np.all((p >= 0) & (p <= 1))
    assert p[0] > p[1]
    assert summary["test_metrics"][f"model:{summary['selected_model']}"]["roc_auc"] > 0.7


def test_to_matrix_handles_bad_values():
    X = to_matrix([{"cvss_score": "7.5", "epss_score": None}, {"cvss_score": "x", "epss_score": float("inf")}])
    assert X[0, 0] == 7.5 and np.isnan(X[0, 1]) and np.isnan(X[1]).all()
