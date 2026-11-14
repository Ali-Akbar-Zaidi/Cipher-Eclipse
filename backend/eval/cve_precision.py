"""
Evaluation metric 2: CVE Mapping Precision, with backport false positives tracked.

    Precision = TP / (TP + FP)

The problem we are measuring
----------------------------
Passive sources (Shodan InternetDB) map a service to CVEs by its *advertised
version*, e.g. "OpenSSH 8.2p1" -> every CVE affecting upstream 8.2p1.
Enterprise Linux distributions (Ubuntu, Debian, RHEL/CentOS, ...) *backport*
security fixes into their packages but keep the old upstream version number,
so a fully patched Ubuntu box still says "OpenSSH_8.2p1 Ubuntu-4ubuntu0.11".
Version-based matching then reports CVEs that are already fixed: false
positives. Because we are 100% passive we cannot confirm exploitability, so
ground truth has to be established by checking each finding against the
distro's security tracker (Ubuntu CVE tracker / Debian security tracker /
Red Hat CVE database) for the package revision visible in the banner/CPE.

Workflow (two subcommands)
--------------------------
1. Generate a labelling sheet from a scan. Every (ip, CVE) pair becomes a row,
   with a heuristic `backport_suspect` flag pre-filled from distro markers in
   the CPEs / banners so you know which rows to check first:

       python -m eval.cve_precision template --scan scan.json --out eval/labels.csv

2. Fill in `label` for each row (TP, FP or UNKNOWN) and, for FPs, `fp_reason`
   (backport | version_misdetect | not_applicable | other). Then score it:

       python -m eval.cve_precision score --labels eval/labels.csv

Accepted scan formats (auto-detected)
-------------------------------------
  a) Shodan InternetDB responses, as a list or {"hosts": [...]}:
       [{"ip": "45.33.32.156", "cpes": ["cpe:/a:openbsd:openssh:6.6.1p1",
         "cpe:/o:canonical:ubuntu_linux"], "vulns": ["CVE-2016-6210", ...], ...}]
  b) Flat findings, as a list or {"findings": [...]}:
       [{"ip": "...", "cve_id": "CVE-...", "cpe": "...", "banner": "...",
         "product": "...", "version": "..."}]

Outputs (score): eval/results/cve_precision.{json,md}
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

DEFAULT_OUT = Path(__file__).resolve().parent / "results"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

# Distribution markers that indicate vendor-patched packages.
#   CPE OS entries Shodan emits, e.g. cpe:/o:canonical:ubuntu_linux
DISTRO_CPE_RE = re.compile(
    r"cpe:(?:/|2\.3:)[oa]:(?P<vendor>canonical|debian|redhat|centos|fedoraproject|"
    r"oracle|suse|opensuse|amazon|rocky|almalinux|alpinelinux):",
    re.I,
)
#   Version-string markers, e.g. "8.2p1 Ubuntu-4ubuntu0.5", "1:7.4p1-21.el7", "2.4.38-3+deb10u8"
DISTRO_VERSION_RE = re.compile(
    r"(?P<marker>ubuntu|debian|\+deb\d+u\d+|deb\d+u\d+|~deb\d+|\.el[5-9](?:_\d+)?\b|\bel[5-9]\b|"
    r"centos|rhel|red ?hat|\.fc\d{2}\b|amzn\d?|\.amzn|suse|\bsles\b|raspbian|\d+ubuntu\d)",
    re.I,
)

LABELS = {"TP", "FP", "UNKNOWN"}
FP_REASONS = {"backport", "version_misdetect", "not_applicable", "other"}

TEMPLATE_COLUMNS = [
    "ip", "cve_id", "backport_suspect", "distro_hint", "evidence",
    "label", "fp_reason", "notes",
]


# --------------------------------------------------------------------------- #
# Backport heuristic
# --------------------------------------------------------------------------- #
def distro_hint(evidence: Iterable[str]) -> str | None:
    """
    Return a short marker (e.g. 'canonical', 'ubuntu', '+deb10u8', '.el7')
    if any CPE/banner/version string suggests a distro-packaged build.
    """
    for text in evidence:
        if not text:
            continue
        m = DISTRO_CPE_RE.search(text)
        if m:
            return m.group("vendor").lower()
        m = DISTRO_VERSION_RE.search(text)
        if m:
            return m.group("marker").lower()
    return None


# --------------------------------------------------------------------------- #
# Scan parsing
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    ip: str
    cve_id: str
    evidence: list[str] = field(default_factory=list)


def load_findings(scan: Any) -> list[Finding]:
    """Normalise either supported scan format into a de-duplicated finding list."""
    if isinstance(scan, dict):
        scan = scan.get("hosts") or scan.get("findings") or scan.get("results") or []
    if not isinstance(scan, list):
        raise ValueError("Scan file must be a list or contain 'hosts'/'findings'")

    merged: dict[tuple[str, str], Finding] = {}
    for item in scan:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip") or item.get("host") or "").strip()
        if "vulns" in item:  # InternetDB host record
            evidence = [str(c) for c in item.get("cpes") or []]
            evidence += [str(b) for b in item.get("banners") or []]
            cves = item.get("vulns") or []
        else:  # flat finding
            evidence = [str(item[k]) for k in ("cpe", "banner", "product", "version") if item.get(k)]
            evidence += [str(c) for c in item.get("cpes") or []]
            cves = [item.get("cve_id") or item.get("cve")]
        for cve in cves:
            if not cve or not _CVE_RE.match(str(cve).strip()):
                continue
            key = (ip, str(cve).strip().upper())
            f = merged.setdefault(key, Finding(ip=key[0], cve_id=key[1]))
            for e in evidence:
                if e not in f.evidence:
                    f.evidence.append(e)
    return sorted(merged.values(), key=lambda f: (f.ip, f.cve_id))


def write_template(findings: list[Finding], out: Path) -> int:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=TEMPLATE_COLUMNS)
        w.writeheader()
        for f in findings:
            hint = distro_hint(f.evidence)
            w.writerow({
                "ip": f.ip,
                "cve_id": f.cve_id,
                "backport_suspect": "yes" if hint else "no",
                "distro_hint": hint or "",
                "evidence": " | ".join(f.evidence),
                "label": "",
                "fp_reason": "",
                "notes": "",
            })
    return len(findings)


# --------------------------------------------------------------------------- #
# Scoring (unit-tested)
# --------------------------------------------------------------------------- #
@dataclass
class LabelledRow:
    ip: str
    cve_id: str
    backport_suspect: bool
    label: str          # TP / FP / UNKNOWN / "" (unlabelled)
    fp_reason: str


def read_labels(path: Path) -> list[LabelledRow]:
    rows = []
    with path.open(newline="", encoding="utf-8") as fh:
        for i, r in enumerate(csv.DictReader(fh), start=2):
            label = (r.get("label") or "").strip().upper()
            reason = (r.get("fp_reason") or "").strip().lower()
            if label and label not in LABELS:
                raise ValueError(f"{path}:{i}: label must be one of {sorted(LABELS)}, got {label!r}")
            if label == "FP" and reason and reason not in FP_REASONS:
                raise ValueError(f"{path}:{i}: fp_reason must be one of {sorted(FP_REASONS)}")
            suspect = (r.get("backport_suspect") or "").strip().lower() in {"yes", "y", "true", "1"}
            rows.append(LabelledRow(r.get("ip", ""), (r.get("cve_id") or "").upper(),
                                    suspect, label, reason if label == "FP" else ""))
    return rows


def _ratio(n: int, d: int) -> float | None:
    return round(n / d, 4) if d else None


def score(rows: list[LabelledRow]) -> dict[str, Any]:
    tp = sum(r.label == "TP" for r in rows)
    fp = sum(r.label == "FP" for r in rows)
    unknown = sum(r.label == "UNKNOWN" for r in rows)
    unlabelled = sum(r.label == "" for r in rows)
    reasons = Counter(r.fp_reason or "unspecified" for r in rows if r.label == "FP")
    fp_backport = reasons.get("backport", 0)

    def subset(pred) -> dict[str, Any]:
        s = [r for r in rows if pred(r)]
        s_tp = sum(r.label == "TP" for r in s)
        s_fp = sum(r.label == "FP" for r in s)
        return {"findings": len(s), "tp": s_tp, "fp": s_fp, "precision": _ratio(s_tp, s_tp + s_fp)}

    suspect_fp = sum(r.backport_suspect and r.label == "FP" for r in rows)
    suspect_labelled = sum(r.backport_suspect and r.label in {"TP", "FP"} for r in rows)
    backport_fp_flagged = sum(
        r.backport_suspect and r.label == "FP" and r.fp_reason == "backport" for r in rows
    )

    return {
        "findings_total": len(rows),
        "labelled": tp + fp,
        "unknown": unknown,
        "unlabelled": unlabelled,
        "tp": tp,
        "fp": fp,
        "precision": _ratio(tp, tp + fp),
        "fp_by_reason": dict(sorted(reasons.items())),
        "backport_fp": fp_backport,
        # Share of all false positives explained by backporting.
        "backport_share_of_fp": _ratio(fp_backport, fp),
        # Upper bound on precision if backport FPs were perfectly filtered out.
        "precision_without_backport_fp": _ratio(tp, tp + fp - fp_backport),
        # Precision split by our distro heuristic: shows the backport effect.
        "distro_packaged": subset(lambda r: r.backport_suspect),
        "upstream_or_unknown_build": subset(lambda r: not r.backport_suspect),
        # How good is the cheap heuristic at predicting backport FPs?
        "heuristic": {
            "flag_precision": _ratio(suspect_fp, suspect_labelled),        # flagged -> really FP
            "backport_fp_recall": _ratio(backport_fp_flagged, fp_backport),  # backport FPs caught
        },
        "unique_hosts": len({r.ip for r in rows}),
    }


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v * 100:.1f}%"


def write_score_reports(summary: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    (out_dir / "cve_precision.json").write_text(
        json.dumps({"generated_at": stamp, **summary}, indent=2)
    )
    d, u = summary["distro_packaged"], summary["upstream_or_unknown_build"]
    lines = [
        f"# CVE Mapping Precision ({stamp})",
        "",
        f"- Findings: {summary['findings_total']} across {summary['unique_hosts']} hosts "
        f"({summary['labelled']} labelled, {summary['unknown']} unknown, {summary['unlabelled']} unlabelled)",
        f"- **Precision: {_pct(summary['precision'])}** (TP {summary['tp']}, FP {summary['fp']})",
        f"- False positives caused by distro backporting: {summary['backport_fp']} "
        f"({_pct(summary['backport_share_of_fp'])} of all FPs)",
        f"- Precision if backport FPs were filtered: {_pct(summary['precision_without_backport_fp'])}",
        "",
        "| Subset | Findings | TP | FP | Precision |",
        "|---|---:|---:|---:|---:|",
        f"| Distro-packaged (backport suspect) | {d['findings']} | {d['tp']} | {d['fp']} | {_pct(d['precision'])} |",
        f"| Upstream / unknown build | {u['findings']} | {u['tp']} | {u['fp']} | {_pct(u['precision'])} |",
        "",
        "| FP reason | Count |",
        "|---|---:|",
        *[f"| {k} | {v} |" for k, v in summary["fp_by_reason"].items()],
        "",
        f"Heuristic flag precision: {_pct(summary['heuristic']['flag_precision'])}; "
        f"backport-FP recall: {_pct(summary['heuristic']['backport_fp_recall'])}",
    ]
    (out_dir / "cve_precision.md").write_text("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="CVE mapping precision with backport FP tracking.")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("template", help="Create a labelling CSV from a scan result")
    t.add_argument("--scan", type=Path, required=True)
    t.add_argument("--out", type=Path, default=DEFAULT_OUT.parent / "labels.csv")
    t.add_argument("--force", action="store_true", help="Overwrite an existing labels file")

    s = sub.add_parser("score", help="Compute precision from a labelled CSV")
    s.add_argument("--labels", type=Path, required=True)
    s.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)

    args = p.parse_args(argv)

    if args.cmd == "template":
        if args.out.exists() and not args.force:
            # Never clobber hours of manual labelling by accident.
            print(f"error: {args.out} exists; pass --force to overwrite", file=sys.stderr)
            return 1
        findings = load_findings(json.loads(args.scan.read_text()))
        n = write_template(findings, args.out)
        flagged = sum(1 for f in findings if distro_hint(f.evidence))
        print(f"wrote {n} findings to {args.out} ({flagged} flagged as backport suspects)")
        return 0

    summary = score(read_labels(args.labels))
    write_score_reports(summary, args.out_dir)
    print((args.out_dir / "cve_precision.md").read_text())
    if summary["unlabelled"]:
        print(f"note: {summary['unlabelled']} rows are not labelled yet", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
