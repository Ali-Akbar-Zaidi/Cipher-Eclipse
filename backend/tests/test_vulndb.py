"""Tests for the offline NVD + EPSS SQLite builder and the read-only query layer."""

from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path

import pytest

from vulndb import VulnDB, VulnDBNotReady
from vulndb.build_db import build_database, database_is_valid, main, pick_cvss


def _cve(cve_id, *, metrics=None, status="Analyzed", desc="A bug."):
    return {
        "cve": {
            "id": cve_id,
            "published": "2021-12-10T10:15:09.143",
            "lastModified": "2024-04-03T17:15:00.000",
            "vulnStatus": status,
            "descriptions": [{"lang": "es", "value": "Un fallo."}, {"lang": "en", "value": desc}],
            "metrics": metrics or {},
        }
    }


V31 = {
    "cvssMetricV31": [
        {"source": "cna@x", "type": "Secondary",
         "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:H", "baseScore": 9.0,
                      "baseSeverity": "CRITICAL"}},
        {"source": "nvd@nist.gov", "type": "Primary",
         "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L", "baseScore": 10.0,
                      "baseSeverity": "CRITICAL"}},
    ],
    "cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH",
                      "cvssData": {"version": "2.0", "vectorString": "AV:N", "baseScore": 9.3}}],
}
V2_ONLY = {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM",
                             "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:M",
                                          "baseScore": 5.0}}]}


@pytest.fixture
def datasets(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.mkdir()
    feed2021 = {"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [
        _cve("CVE-2021-44228", metrics=V31, desc="Log4Shell JNDI RCE."),
        _cve("CVE-2021-0001", status="Rejected", desc="** REJECT **"),
        _cve("CVE-2021-0002"),  # awaiting analysis, no metrics
    ]}
    feed2014 = {"format": "NVD_CVE", "version": "2.0", "vulnerabilities": [
        _cve("CVE-2014-0160", metrics=V2_ONLY, desc="Heartbleed."),
    ]}
    for name, feed in [("nvdcve-2.0-2021.json.gz", feed2021), ("nvdcve-2.0-2014.json.gz", feed2014)]:
        with gzip.open(raw / name, "wt") as fh:
            json.dump(feed, fh)
    with gzip.open(raw / "epss_scores-current.csv.gz", "wt") as fh:
        fh.write("#model_version:v2025.03.14,score_date:2026-11-12T12:55:00Z\n")
        fh.write("cve,epss,percentile\n")
        fh.write("CVE-2021-44228,0.94358,0.99950\n")
        fh.write("CVE-2014-0160,0.94470,0.99980\n")
        fh.write("CVE-2026-99999,0.00100,0.10000\n")  # in EPSS only
        fh.write("garbage,row\n")
    (raw / "known_exploited_vulnerabilities.json").write_text(json.dumps({
        "catalogVersion": "2026.11.13", "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
             "knownRansomwareCampaignUse": "Known", "vendorProject": "Apache", "product": "Log4j2",
             "vulnerabilityName": "Apache Log4j2 RCE"},
            {"cveID": "bogus"},
        ]}))
    return raw


def test_pick_cvss_prefers_v31_primary_then_falls_back_to_v2():
    assert pick_cvss(V31) == (10.0, "3.1", "CVSS:3.1/AV:N/AC:L", "CRITICAL")
    assert pick_cvss(V2_ONLY) == (5.0, "2.0", "AV:N/AC:M", "MEDIUM")
    assert pick_cvss({}) == (None, None, None, None)


def test_build_and_query(datasets: Path, tmp_path: Path):
    db_path = tmp_path / "vulnerabilities.db"
    stats = build_database(
        db_path,
        sorted(datasets.glob("nvdcve-*.json.gz")),
        datasets / "epss_scores-current.csv.gz",
    )
    assert database_is_valid(db_path)
    assert not (tmp_path / "vulnerabilities.db.tmp").exists()
    assert stats["nvd_records_parsed"] == 3          # rejected CVE skipped
    assert stats["epss_only_rows"] == 1
    assert stats["total_rows"] == 4
    assert stats["epss_score_date"] == "2026-11-12T12:55:00Z"

    db = VulnDB(db_path)
    log4j = db.get("cve-2021-44228")  # case-insensitive
    assert log4j["cvss_score"] == 10.0
    assert log4j["epss_score"] == pytest.approx(0.94358)
    assert log4j["description"] == "Log4Shell JNDI RCE."
    assert log4j["severity"] == "CRITICAL"

    assert db.get("CVE-2021-0001") is None            # rejected
    assert db.get("CVE-2021-0002")["cvss_score"] is None
    assert db.get("CVE-2026-99999")["epss_score"] == pytest.approx(0.001)
    assert db.get("not-a-cve") is None

    many = db.get_many(["CVE-2014-0160", "CVE-2021-44228", "CVE-1999-0000", "junk"])
    assert set(many) == {"CVE-2014-0160", "CVE-2021-44228"}
    assert db.metadata()["epss_model_version"] == "v2025.03.14"


def test_schema_and_primary_key_index(datasets: Path, tmp_path: Path):
    """The brief requires cve_id to be the indexed primary key: prove the planner uses it."""
    db_path = tmp_path / "v.db"
    build_database(db_path, sorted(datasets.glob("nvdcve-*")), datasets / "epss_scores-current.csv.gz")
    conn = sqlite3.connect(db_path)
    cols = {r[1]: r for r in conn.execute("PRAGMA table_info(vulnerabilities)")}
    for required in ("cve_id", "cvss_score", "epss_score", "description"):
        assert required in cols
    assert cols["cve_id"][5] == 1  # pk flag
    plan = " ".join(
        str(r[-1]) for r in conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM vulnerabilities WHERE cve_id = ?", ("CVE-2014-0160",)
        )
    )
    assert "USING INDEX sqlite_autoindex_vulnerabilities_1" in plan
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_query_layer_is_read_only(datasets: Path, tmp_path: Path):
    db_path = tmp_path / "v.db"
    build_database(db_path, sorted(datasets.glob("nvdcve-*")), datasets / "epss_scores-current.csv.gz")
    db = VulnDB(db_path)
    with pytest.raises(sqlite3.OperationalError):
        db._conn().execute("DELETE FROM vulnerabilities")


async def test_async_lookup(datasets: Path, tmp_path: Path):
    db_path = tmp_path / "v.db"
    build_database(db_path, sorted(datasets.glob("nvdcve-*")), datasets / "epss_scores-current.csv.gz")
    db = VulnDB(db_path)
    assert (await db.aget("CVE-2014-0160"))["cvss_score"] == 5.0
    assert len(await db.aget_many(["CVE-2014-0160", "CVE-2021-44228"])) == 2


def test_missing_db_raises_clear_error(tmp_path: Path):
    with pytest.raises(VulnDBNotReady):
        VulnDB(tmp_path / "nope.db").get("CVE-2014-0160")


def test_cli_offline_and_if_missing(datasets: Path, tmp_path: Path):
    db_path = tmp_path / "out" / "vulnerabilities.db"
    args = ["--db", str(db_path), "--cache-dir", str(datasets), "--offline"]
    assert main(args) == 0
    assert database_is_valid(db_path)
    # Second run without --force refuses; with --if-missing it is a no-op success.
    assert main(args) == 1
    assert main(args + ["--if-missing"]) == 0
    assert main(args + ["--force"]) == 0


def test_failed_build_leaves_no_db(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "nvdcve-2.0-2020.json").write_text('{"vulnerabilities": [ {"cve": ')  # truncated
    (raw / "epss_scores-current.csv").write_text("cve,epss,percentile\n")
    db_path = tmp_path / "vulnerabilities.db"
    with pytest.raises(Exception):
        build_database(db_path, [raw / "nvdcve-2.0-2020.json"], raw / "epss_scores-current.csv")
    assert not db_path.exists()
    assert not (tmp_path / "vulnerabilities.db.tmp").exists()


def test_kev_is_separate_label_table(datasets: Path, tmp_path: Path):
    db_path = tmp_path / "v.db"
    stats = build_database(db_path, sorted(datasets.glob("nvdcve-*")),
                           datasets / "epss_scores-current.csv.gz",
                           datasets / "known_exploited_vulnerabilities.json")
    assert stats["kev_rows"] == 1 and stats["kev_catalog_version"] == "2026.11.13"
    db = VulnDB(db_path)
    assert db.kev_labels(["CVE-2021-44228", "CVE-2014-0160", "junk"]) == {
        "CVE-2021-44228": True, "CVE-2014-0160": False}
    # KEV must not leak into the rows the scan/ranking code reads.
    assert "kev" not in " ".join(db.get("CVE-2021-44228"))


def test_build_without_kev_still_works(datasets: Path, tmp_path: Path):
    db_path = tmp_path / "v.db"
    stats = build_database(db_path, sorted(datasets.glob("nvdcve-*")),
                           datasets / "epss_scores-current.csv.gz")
    assert stats["kev_rows"] == 0
    assert VulnDB(db_path).kev_labels(["CVE-2021-44228"]) == {"CVE-2021-44228": False}
