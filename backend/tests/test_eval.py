"""Tests for the academic evaluation scripts."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from eval import cve_precision as cp
from eval import subdomain_recall as sr


# ------------------------------------------------------------ recall --------
def test_compute_recall_basic():
    ours = {"a.x.com", "b.x.com", "c.x.com"}
    base = {"b.x.com", "c.x.com", "d.x.com", "e.x.com"}
    r = sr.compute_recall("x.com", ours, base)
    assert r.overlap == 2
    assert r.recall == 0.5
    assert r.precision_vs_baseline == pytest.approx(0.6667)
    assert r.jaccard == pytest.approx(0.4)
    assert r.only_ours == ["a.x.com"]
    assert r.only_baseline == ["d.x.com", "e.x.com"]


def test_compute_recall_live_and_empty_baseline():
    r = sr.compute_recall("x.com", {"a.x.com"}, set(), ours_live={"a.x.com"}, baseline_live=set())
    assert r.recall is None and r.live_recall is None
    r = sr.compute_recall("x.com", {"a.x.com", "b.x.com"}, {"a.x.com", "b.x.com", "dead.x.com"},
                          ours_live={"a.x.com"}, baseline_live={"a.x.com", "b.x.com"})
    assert r.recall == pytest.approx(0.6667)
    assert r.live_recall == 0.5


def test_aggregate_macro_vs_micro():
    small = sr.compute_recall("s.com", {"a.s.com"}, {"a.s.com"})                     # 1/1
    big = sr.compute_recall("b.com", {"a.b.com"}, {f"{i}.b.com" for i in range(9)} | {"a.b.com"})  # 1/10
    agg = sr.aggregate([small, big])
    assert agg["macro_recall"] == pytest.approx(0.55)
    assert agg["micro_recall"] == pytest.approx(2 / 11, abs=1e-4)


def test_normalize_names_applies_same_cleaning():
    names = ["*.API.x.com", "api.x.com.", "other.org", "mail@x.com", " www.x.com "]
    assert sr.normalize_names(names, "x.com") == {"api.x.com", "www.x.com"}


def test_read_name_file_plain_and_jsonl(tmp_path: Path):
    f = tmp_path / "x.com.txt"
    f.write_text('a.x.com\n\n# comment\n{"host":"b.x.com","source":"crtsh"}\n')
    assert sr.read_name_file(f) == ["a.x.com", "b.x.com"]


async def test_recall_cli_with_saved_files(tmp_path: Path):
    ours_dir, base_dir, out = tmp_path / "ours", tmp_path / "base", tmp_path / "out"
    ours_dir.mkdir(); base_dir.mkdir()
    (ours_dir / "x.com.json").write_text(json.dumps({
        "subdomains": {"a.x.com": ["1.1.1.1"]}, "unresolved": {"old.x.com": "NXDOMAIN"},
        "skipped": [],
    }))
    (base_dir / "x.com.txt").write_text("a.x.com\nold.x.com\nnew.x.com\n")
    args = sr.argparse.Namespace(
        targets=["x.com"], targets_file=None, baseline_dir=base_dir, run_subfinder=False,
        run_amass=False,
        ours_dir=ours_dir, resolve_baseline=False, out_dir=out, verbose=False,
    )
    assert await sr.amain(args) == 0
    data = json.loads((out / "subdomain_recall.json").read_text())
    assert data["targets"][0]["recall"] == pytest.approx(0.6667)
    assert data["targets"][0]["only_baseline"] == ["new.x.com"]
    assert (out / "subdomain_recall.csv").exists()
    assert "| x.com |" in (out / "subdomain_recall.md").read_text()


# ---------------------------------------------------------- precision -------
@pytest.mark.parametrize(
    "evidence,expected",
    [
        (["cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:canonical:ubuntu_linux"], "canonical"),
        (["cpe:2.3:o:debian:debian_linux:10:*:*:*:*:*:*:*"], "debian"),
        (["OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"], "ubuntu"),
        (["Apache/2.4.38 (Debian)"], "debian"),
        (["openssh 1:7.4p1-21.el7"], ".el7"),
        (["nginx 1.14.2-2+deb10u5"], "+deb10u5"),
        (["cpe:/a:openbsd:openssh:9.6", "nginx/1.25.3"], None),
    ],
)
def test_distro_hint(evidence, expected):
    assert cp.distro_hint(evidence) == expected


def test_load_findings_internetdb_and_flat():
    internetdb = [{"ip": "45.33.32.156", "cpes": ["cpe:/o:canonical:ubuntu_linux"],
                   "vulns": ["CVE-2016-6210", "cve-2015-5600", "junk"], "ports": [22]}]
    flat = {"findings": [{"ip": "1.2.3.4", "cve_id": "CVE-2021-41773", "banner": "Apache/2.4.49"},
                         {"ip": "1.2.3.4", "cve_id": "CVE-2021-41773", "cpe": "cpe:/a:apache:http_server:2.4.49"}]}
    a = cp.load_findings(internetdb)
    assert [f.cve_id for f in a] == ["CVE-2015-5600", "CVE-2016-6210"]
    b = cp.load_findings(flat)
    assert len(b) == 1 and len(b[0].evidence) == 2  # duplicates merged, evidence kept


def _labelled(rows):
    return [cp.LabelledRow(ip, cve, suspect, label, reason) for ip, cve, suspect, label, reason in rows]


def test_score_tracks_backport_fps():
    rows = _labelled([
        ("h1", "CVE-2000-0001", True, "FP", "backport"),
        ("h1", "CVE-2000-0002", True, "FP", "backport"),
        ("h1", "CVE-2000-0003", True, "TP", ""),
        ("h2", "CVE-2000-0004", False, "TP", ""),
        ("h2", "CVE-2000-0005", False, "TP", ""),
        ("h2", "CVE-2000-0006", False, "FP", "version_misdetect"),
        ("h2", "CVE-2000-0007", False, "UNKNOWN", ""),
        ("h3", "CVE-2000-0008", False, "", ""),
    ])
    s = cp.score(rows)
    assert (s["tp"], s["fp"], s["unknown"], s["unlabelled"]) == (3, 3, 1, 1)
    assert s["precision"] == 0.5
    assert s["backport_fp"] == 2
    assert s["backport_share_of_fp"] == pytest.approx(0.6667)
    assert s["precision_without_backport_fp"] == 0.75
    assert s["distro_packaged"]["precision"] == pytest.approx(0.3333)
    assert s["upstream_or_unknown_build"]["precision"] == pytest.approx(0.6667)
    assert s["heuristic"]["flag_precision"] == pytest.approx(0.6667)
    assert s["heuristic"]["backport_fp_recall"] == 1.0


def test_template_then_score_roundtrip(tmp_path: Path):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps([
        {"ip": "45.33.32.156", "cpes": ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:canonical:ubuntu_linux"],
         "vulns": ["CVE-2016-6210", "CVE-2015-5600"]},
        {"ip": "1.2.3.4", "cpes": ["cpe:/a:apache:http_server:2.4.49"], "vulns": ["CVE-2021-41773"]},
    ]))
    labels = tmp_path / "labels.csv"
    assert cp.main(["template", "--scan", str(scan), "--out", str(labels)]) == 0
    assert cp.main(["template", "--scan", str(scan), "--out", str(labels)]) == 1  # no clobber

    rows = list(csv.DictReader(labels.open()))
    assert [r["backport_suspect"] for r in rows] == ["no", "yes", "yes"]
    for r in rows:
        r["label"] = "TP" if r["ip"] == "1.2.3.4" else "FP"
        r["fp_reason"] = "backport" if r["label"] == "FP" else ""
    with labels.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cp.TEMPLATE_COLUMNS)
        w.writeheader(); w.writerows(rows)

    out = tmp_path / "out"
    assert cp.main(["score", "--labels", str(labels), "--out-dir", str(out)]) == 0
    result = json.loads((out / "cve_precision.json").read_text())
    assert result["precision"] == pytest.approx(0.3333)
    assert result["precision_without_backport_fp"] == 1.0


def test_invalid_label_rejected(tmp_path: Path):
    f = tmp_path / "l.csv"
    f.write_text("ip,cve_id,backport_suspect,label,fp_reason\n1.1.1.1,CVE-2020-0001,no,MAYBE,\n")
    with pytest.raises(ValueError):
        cp.read_labels(f)


async def test_recall_union_of_subfinder_and_amass(tmp_path: Path):
    ours_dir, base_dir, out = tmp_path / "ours", tmp_path / "base", tmp_path / "out"
    ours_dir.mkdir(); base_dir.mkdir()
    (ours_dir / "x.com.json").write_text(json.dumps({
        "subdomains": {"a.x.com": ["1.1.1.1"], "b.x.com": ["1.1.1.2"]},
        "unresolved": {}, "skipped": [], "stats": {"duration_seconds": 4.2},
    }))
    (base_dir / "x.com.subfinder.txt").write_text("a.x.com\nc.x.com\n")
    # Amass v4 graph-style output
    (base_dir / "x.com.amass.txt").write_text(
        "b.x.com (FQDN) --> a_record --> 1.1.1.2 (IPAddress)\n"
        "x.com (FQDN) --> ns_record --> ns1.other.net (FQDN)\n")
    # Another target's file must not be picked up for x.com
    (base_dir / "sub.x.com.txt").write_text("zzz.x.com\n")
    args = sr.argparse.Namespace(
        targets=["x.com"], targets_file=None, baseline_dir=base_dir, run_subfinder=False,
        run_amass=False, ours_dir=ours_dir, resolve_baseline=False, out_dir=out, verbose=False,
    )
    assert await sr.amain(args) == 0
    data = json.loads((out / "subdomain_recall.json").read_text())
    t = data["targets"][0]
    assert t["baseline_count"] == 4          # a, c (subfinder) + b, x.com (amass)
    assert t["recall"] == 0.5
    assert t["by_source"]["subfinder"]["recall"] == 0.5
    assert t["by_source"]["amass"]["recall"] == 0.5
    assert t["by_source"]["subfinder"]["unique_to_tool"] == 1   # c.x.com
    assert t["ours_duration_seconds"] == 4.2
    assert data["summary"]["mean_runtime_seconds"] == 4.2
    md = (out / "subdomain_recall.md").read_text()
    assert "amass + subfinder combined" in md and "4.2s" in md


async def test_missing_baseline_raises(tmp_path: Path):
    args = sr.argparse.Namespace(baseline_dir=tmp_path, run_subfinder=False, run_amass=False)
    with pytest.raises(FileNotFoundError):
        await sr.collect_baseline("x.com", args)
