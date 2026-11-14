"""
Cipher Eclipse passive OSINT ingestion (owner: Hadi).

    from ingestion import run_ingestion
    data = await run_ingestion("example.com")
"""

from .crtsh import (
    CrtShError,
    discover_subdomains,
    extract_subdomains,
    fetch_crtsh_records,
    normalize_domain,
)
from .dns_resolver import MAX_RESOLVED, ResolutionResult, SubdomainResolver, resolve_subdomains
from .pipeline import run_ingestion

__all__ = [
    "CrtShError",
    "MAX_RESOLVED",
    "ResolutionResult",
    "SubdomainResolver",
    "discover_subdomains",
    "extract_subdomains",
    "fetch_crtsh_records",
    "normalize_domain",
    "resolve_subdomains",
    "run_ingestion",
]
