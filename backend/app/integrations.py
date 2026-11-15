"""
Adapters between the API and Azaan's data-processing modules.

The orchestrator only talks to the three functions below. Each one first tries
Azaan's module (the contract is in docs/api-and-frontend.md); if that module is
not in the tree yet, a small built-in version keeps /api/scan working end to end.
`PIPELINE_SOURCES` records which implementation ran so the payload is honest
about it.

Contract
--------
filter_cdn(ips)                      -> (scannable_ips, {hidden_ip: provider})
lookup_internetdb(ips, session)      -> {ip: {"ports", "hostnames", "cpes", "vulns", "tags"}}
                                        (IPs Shodan has no data for are simply absent)
score_vulnerabilities(vulns, hosts)  -> same list, each dict gaining
                                        "kev_probability" (0-1) and "risk_score" (0-100)
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from functools import lru_cache
from typing import Any, Iterable

import aiohttp

logger = logging.getLogger("cipher.integrations")

PIPELINE_SOURCES: dict[str, str] = {}

# ------------------------------------------------------------------ CDN filter
try:
    from pipeline.cdn_filter import filter_cdn_ips as _ext_filter_cdn  # type: ignore
    PIPELINE_SOURCES["cdn_filter"] = "pipeline.cdn_filter"
except ImportError:
    _ext_filter_cdn = None
    PIPELINE_SOURCES["cdn_filter"] = "builtin"

# Published edge ranges (cloudflare.com/ips-v4, api.fastly.com/public-ip-list).
_BUILTIN_CDN_RANGES: dict[str, tuple[str, ...]] = {
    "cloudflare": (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ),
    "fastly": (
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
        "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
        "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
        "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    ),
}


@lru_cache(maxsize=1)
def _cdn_networks() -> tuple[tuple[ipaddress.IPv4Network, str], ...]:
    return tuple((ipaddress.IPv4Network(c), name) for name, cidrs in _BUILTIN_CDN_RANGES.items() for c in cidrs)


def _builtin_filter_cdn(ips: Iterable[str]) -> tuple[list[str], dict[str, str]]:
    keep: list[str] = []
    hidden: dict[str, str] = {}
    for ip in ips:
        addr = ipaddress.IPv4Address(ip)
        provider = next((name for net, name in _cdn_networks() if addr in net), None)
        if provider:
            hidden[ip] = provider
        else:
            keep.append(ip)
    return keep, hidden


async def filter_cdn(ips: list[str]) -> tuple[list[str], dict[str, str]]:
    if _ext_filter_cdn is not None:
        result = _ext_filter_cdn(ips)
        if asyncio.iscoroutine(result):
            result = await result
        keep, hidden = result
        return list(keep), {k: str(v) for k, v in dict(hidden).items()}
    return _builtin_filter_cdn(ips)


# ------------------------------------------------------------ Shodan InternetDB
try:
    from pipeline.shodan_internetdb import lookup_ips as _ext_lookup  # type: ignore
    PIPELINE_SOURCES["internetdb"] = "pipeline.shodan_internetdb"
except ImportError:
    _ext_lookup = None
    PIPELINE_SOURCES["internetdb"] = "builtin"

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
_IDB_FIELDS = ("ports", "hostnames", "cpes", "vulns", "tags")


async def _builtin_lookup(ips: list[str], session: aiohttp.ClientSession,
                          concurrency: int = 8) -> dict[str, dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency)
    out: dict[str, dict[str, Any]] = {}

    async def one(ip: str) -> None:
        async with sem:
            for attempt in range(3):
                try:
                    async with session.get(INTERNETDB_URL.format(ip=ip),
                                           timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 404:  # Shodan has no data for this IP
                            return
                        if resp.status == 429:
                            await asyncio.sleep(1.5 * (attempt + 1))
                            continue
                        resp.raise_for_status()
                        data = await resp.json(content_type=None)
                        out[ip] = {k: data.get(k) or [] for k in _IDB_FIELDS}
                        return
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    logger.warning("InternetDB %s attempt %d failed: %s", ip, attempt + 1, exc)
                    await asyncio.sleep(0.5 * (attempt + 1))

    await asyncio.gather(*(one(ip) for ip in ips))
    return out


async def lookup_internetdb(ips: list[str], session: aiohttp.ClientSession) -> dict[str, dict[str, Any]]:
    if not ips:
        return {}
    if _ext_lookup is not None:
        raw = dict(await _ext_lookup(ips, session=session))
        return {ip: {k: (rec or {}).get(k) or [] for k in _IDB_FIELDS} for ip, rec in raw.items() if rec}
    return await _builtin_lookup(ips, session)


# ------------------------------------------------------------------ risk score
try:
    from pipeline.risk_scoring import score_vulnerabilities as _ext_score  # type: ignore
    PIPELINE_SOURCES["risk_scoring"] = "pipeline.risk_scoring"
except ImportError:
    _ext_score = None
    PIPELINE_SOURCES["risk_scoring"] = "builtin"

# Ports whose exposure makes any CVE on the host more urgent (remote admin,
# file sharing, databases, legacy cleartext protocols).
HIGH_EXPOSURE_PORTS = frozenset({21, 22, 23, 25, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900,
                                 6379, 8080, 8443, 9200, 11211, 27017})


@lru_cache(maxsize=1)
def _load_model():
    import joblib

    from ml.features import MODEL_PATH
    if not MODEL_PATH.exists():
        logger.warning("KEV model %s missing; risk scores use CVSS+EPSS only", MODEL_PATH)
        return None
    return joblib.load(MODEL_PATH)


def _builtin_score(vulns: list[dict[str, Any]], hosts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    from ml.features import to_matrix

    model = _load_model()
    if model is not None and vulns:
        probs = list(model.predict_proba(to_matrix(vulns))[:, 1])
    else:
        probs = [None] * len(vulns)
    for v, p in zip(vulns, probs):
        cvss = (v.get("cvss_score") or 0.0) / 10.0
        epss = v.get("epss_score") or 0.0
        weighted = 0.4 * cvss + 0.6 * epss
        exposed = any(set(hosts.get(ip, {}).get("ports") or []) & HIGH_EXPOSURE_PORTS for ip in v.get("hosts", []))
        exposure = 1.0 if exposed else 0.85
        model_part = min(1.0, float(p) / 0.5) if p is not None else weighted
        v["kev_probability"] = None if p is None else round(float(p), 4)
        v["risk_score"] = round(100 * exposure * (0.5 * weighted + 0.5 * model_part), 1)
    return vulns


async def score_vulnerabilities(vulns: list[dict[str, Any]],
                                hosts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if _ext_score is not None:
        result = _ext_score(vulns, hosts)
        return list(await result) if asyncio.iscoroutine(result) else list(result)
    # sklearn inference is CPU work: keep it off the event loop.
    return await asyncio.to_thread(_builtin_score, vulns, hosts)
