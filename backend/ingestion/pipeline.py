"""
Ingestion pipeline: domain -> crt.sh subdomains -> DNS A records.

This is the entry point the rest of the backend calls when a scan starts:

    from ingestion import run_ingestion
    result = await run_ingestion("example.com")
    result["subdomains"]   # {"api.example.com": ["93.184.216.34"], ...}

The output dictionary is the contract between Hadi's stage and Azaan's
Shodan InternetDB stage. Its shape:

{
  "domain": "example.com",
  "subdomains": {"a.example.com": ["1.2.3.4"], ...},   # <= 500 entries
  "unique_ips": ["1.2.3.4", ...],                      # handy for Shodan
  "unresolved": {"old.example.com": "NXDOMAIN", ...},
  "skipped": ["zz.example.com", ...],                  # not queried: cap reached
  "stats": {
      "certificates_seen": 1234,
      "wildcard_zones": 3,        # *.zone certs: hosts under them are invisible to CT
      "candidates": 210,          # unique names after cleaning
      "resolved": 150,
      "unresolved": 55,
      "skipped_due_to_cap": 5,
      "cap": 500,
      "cap_reached": false,
      "duration_seconds": 12.3
  }
}

Run from the command line for debugging:
    python -m ingestion example.com --pretty
"""

from __future__ import annotations

import ipaddress
import time
from typing import Any, Sequence

import aiohttp

from .crtsh import extract_subdomains, fetch_crtsh_records, normalize_domain, wildcard_bases
from .dns_resolver import DEFAULT_NAMESERVERS, MAX_RESOLVED, SubdomainResolver

USER_AGENT = "CipherEclipse/1.0 (passive OSINT research; CS3002 university project)"


async def run_ingestion(
    domain: str,
    *,
    session: aiohttp.ClientSession | None = None,
    nameservers: Sequence[str] | None = DEFAULT_NAMESERVERS,
    max_resolved: int = MAX_RESOLVED,
    dns_concurrency: int = 100,
    exclude_expired_certs: bool = False,
    resolver: SubdomainResolver | None = None,
) -> dict[str, Any]:
    """
    Run the full passive ingestion stage for one target domain.

    Args:
        domain: target domain, e.g. "example.com" (URLs/wildcards are tolerated).
        session: optional shared aiohttp session (recommended inside FastAPI).
        nameservers: public recursive resolvers to use for A lookups.
        max_resolved: hard cap on resolved subdomains (default 500, never raise
            it above what the Shodan stage can handle).
        dns_concurrency: queries in flight at once.
        exclude_expired_certs: only consider currently-valid certificates.
            Off by default: expired certs are exactly how forgotten hosts are found.
        resolver: inject a pre-built resolver (used by tests).
    """
    if max_resolved > MAX_RESOLVED:
        raise ValueError(f"max_resolved may not exceed {MAX_RESOLVED}")

    started = time.perf_counter()
    domain = normalize_domain(domain)

    # ---- Stage 1: Certificate Transparency -------------------------------
    owns_session = session is None
    if owns_session:
        session = aiohttp.ClientSession(headers={"User-Agent": USER_AGENT})
    try:
        records = await fetch_crtsh_records(
            session, domain, exclude_expired=exclude_expired_certs
        )
    finally:
        if owns_session:
            await session.close()

    candidates = set(extract_subdomains(records, domain))
    candidates.add(domain)  # the apex is always in scope

    # ---- Stage 2: DNS resolution -----------------------------------------
    resolver = resolver or SubdomainResolver(nameservers)
    res = await resolver.resolve_many(
        candidates, max_resolved=max_resolved, concurrency=dns_concurrency
    )

    unique_ips = sorted(
        {ip for ips in res.resolved.values() for ip in ips}, key=ipaddress.IPv4Address
    )

    return {
        "domain": domain,
        "subdomains": res.resolved,
        "unique_ips": unique_ips,
        "unresolved": res.unresolved,
        "skipped": res.skipped,
        "stats": {
            "certificates_seen": len(records),
            "wildcard_zones": len(wildcard_bases(records, domain)),
            "candidates": len(candidates),
            "resolved": len(res.resolved),
            "unresolved": len(res.unresolved),
            "skipped_due_to_cap": len(res.skipped),
            "cap": max_resolved,
            "cap_reached": res.cap_reached,
            "duration_seconds": round(time.perf_counter() - started, 3),
        },
    }
