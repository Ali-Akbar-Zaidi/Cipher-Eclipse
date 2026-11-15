"""
Scan orchestration: the glue between every team member's stage.

    domain
      -> ingestion.run_ingestion        (Hadi: crt.sh + DNS)
      -> integrations.filter_cdn        (Azaan: CDN / "origin hidden")
      -> integrations.lookup_internetdb (Azaan: Shodan InternetDB)
      -> VulnDB.aget_many               (Hadi: NVD CVSS + EPSS cache)
      -> integrations.score_vulnerabilities (Azaan: inference on Shuja's model)
      -> llm.generate_summary           (Shuja: JSON summary + hallucination check)
      -> one JSON payload for the dashboard

Everything is awaited on the event loop; blocking work (SQLite, sklearn) runs
in worker threads inside the modules that own it, so one slow scan never
stalls other requests.
"""

from __future__ import annotations

import datetime as dt
import logging
import time
import uuid
from typing import Any

import aiohttp

from ingestion import run_ingestion
from vulndb import VulnDB, VulnDBNotReady

from .integrations import PIPELINE_SOURCES, filter_cdn, lookup_internetdb, score_vulnerabilities
from .llm.summary import generate_summary

try:  # Hadi's backport heuristic, reused so the dashboard and the evaluation agree.
    from eval.cve_precision import distro_hint
except ImportError:  # pragma: no cover
    def distro_hint(evidence):  # type: ignore[no-redef]
        return None

logger = logging.getLogger("cipher.scan")

KEV_LIKELY_THRESHOLD = 0.10


def _severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "NONE"


async def run_scan(
    domain: str,
    *,
    session: aiohttp.ClientSession,
    vulndb: VulnDB,
    include_summary: bool = True,
    use_llm: bool = True,
) -> dict[str, Any]:
    started = dt.datetime.now(dt.timezone.utc)
    t0 = time.perf_counter()
    timings: dict[str, float] = {}
    warnings: list[str] = []

    def lap(stage: str, since: float) -> float:
        now = time.perf_counter()
        timings[stage] = round(now - since, 3)
        return now

    # 1. Passive discovery -------------------------------------------------
    ingest = await run_ingestion(domain, session=session)
    t = lap("ingestion", t0)
    domain = ingest["domain"]
    subdomains: dict[str, list[str]] = ingest["subdomains"]
    unique_ips: list[str] = ingest["unique_ips"]

    # 2. CDN filter ----------------------------------------------------------
    scannable, hidden = await filter_cdn(unique_ips)
    t = lap("cdn_filter", t)

    # 3. Shodan InternetDB ---------------------------------------------------
    idb = await lookup_internetdb(scannable, session)
    t = lap("internetdb", t)

    ip_subs: dict[str, set[str]] = {}
    for name, ips in subdomains.items():
        for ip in ips:
            ip_subs.setdefault(ip, set()).add(name)

    hosts: list[dict[str, Any]] = []
    for ip in unique_ips:
        rec = idb.get(ip)
        hosts.append({
            "ip": ip,
            "subdomains": sorted(ip_subs.get(ip, ())),
            "origin_hidden": ip in hidden,
            "cdn": hidden.get(ip),
            "internetdb": rec is not None,
            "ports": sorted({int(p) for p in (rec or {}).get("ports") or []}),
            "hostnames": sorted({h.lower() for h in (rec or {}).get("hostnames") or []}),
            "cpes": list((rec or {}).get("cpes") or []),
            "tags": list((rec or {}).get("tags") or []),
            "cves": sorted({c.upper() for c in (rec or {}).get("vulns") or []}),
        })
    host_map = {h["ip"]: h for h in hosts}

    # 4. Enrich CVEs from the local NVD/EPSS cache ---------------------------
    cve_hosts: dict[str, list[str]] = {}
    for h in hosts:
        for c in h["cves"]:
            cve_hosts.setdefault(c, []).append(h["ip"])
    try:
        rows = await vulndb.aget_many(cve_hosts.keys())
    except VulnDBNotReady as exc:
        rows = {}
        warnings.append(f"Vulnerability database not ready ({exc}); CVSS/EPSS missing.")
    t = lap("vulndb", t)

    vulns: list[dict[str, Any]] = []
    for cve_id, ips in cve_hosts.items():
        row = rows.get(cve_id) or {}
        evidence = [c for ip in ips for c in host_map[ip]["cpes"]]
        vulns.append({
            "cve_id": cve_id,
            "cvss_score": row.get("cvss_score"),
            "cvss_version": row.get("cvss_version"),
            "cvss_vector": row.get("cvss_vector"),
            "severity": row.get("severity") or _severity_from_cvss(row.get("cvss_score")),
            "epss_score": row.get("epss_score"),
            "epss_percentile": row.get("epss_percentile"),
            "description": row.get("description"),
            "published": row.get("published"),
            "in_vulndb": bool(row),
            "hosts": sorted(ips),
            # InternetDB matches CVEs from software versions: never confirmed.
            "confidence": "potential",
            "backport_suspect": distro_hint(evidence) is not None,
        })

    # 5. Risk scoring with the KEV model --------------------------------------
    vulns = await score_vulnerabilities(vulns, host_map)
    t = lap("risk_scoring", t)
    vulns.sort(key=lambda v: (v.get("risk_score") or 0, v.get("epss_score") or 0), reverse=True)
    risk_by_cve = {v["cve_id"]: v.get("risk_score") or 0 for v in vulns}
    for h in hosts:
        h["max_risk"] = max((risk_by_cve.get(c, 0) for c in h["cves"]), default=None)

    sev_counts = {s: sum(1 for v in vulns if (v.get("severity") or "").upper() == s)
                  for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    istats = ingest["stats"]
    result: dict[str, Any] = {
        "scan_id": uuid.uuid4().hex[:12],
        "domain": domain,
        "started_at": started.replace(microsecond=0).isoformat(),
        "stats": {
            "subdomains": len(subdomains),
            "unresolved": len(ingest.get("unresolved") or {}),
            "unique_ips": len(unique_ips),
            "origin_hidden": len(hidden),
            "scanned_ips": len(scannable),
            "hosts_with_data": len(idb),
            "open_ports": sum(len(h["ports"]) for h in hosts),
            "vulnerabilities": len(vulns),
            "critical": sev_counts["CRITICAL"],
            "high": sev_counts["HIGH"],
            "medium": sev_counts["MEDIUM"],
            "low": sev_counts["LOW"],
            "kev_likely": sum(1 for v in vulns if (v.get("kev_probability") or 0) >= KEV_LIKELY_THRESHOLD),
            "certificates_seen": istats.get("certificates_seen"),
            "wildcard_zones": istats.get("wildcard_zones"),
            "cap_reached": istats.get("cap_reached"),
        },
        "subdomains": [{"name": n, "ips": ips} for n, ips in sorted(subdomains.items())],
        "unresolved": ingest.get("unresolved") or {},
        "hosts": hosts,
        "vulnerabilities": vulns,
        "pipeline": dict(PIPELINE_SOURCES),
        "warnings": warnings,
    }

    # 6. Executive summary -----------------------------------------------------
    if include_summary:
        result["summary"] = await generate_summary(result, use_llm=use_llm)
        lap("summary", t)

    timings["total"] = round(time.perf_counter() - t0, 3)
    result["timings"] = timings
    return result
