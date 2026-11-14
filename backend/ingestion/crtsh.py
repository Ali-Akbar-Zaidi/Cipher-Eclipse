"""
Passive subdomain discovery via Certificate Transparency logs (crt.sh).

Every TLS certificate issued by a publicly trusted CA is logged to public
Certificate Transparency (CT) logs. crt.sh indexes those logs, so asking it
"which certificates mention *.example.com?" gives us a list of hostnames the
organisation has requested certificates for, without ever touching the
target's infrastructure. This is the PASSIVE half of the ingestion stage.

Public API of this module:
    fetch_crtsh_records(session, domain)  -> raw JSON rows from crt.sh
    extract_subdomains(records, domain)   -> cleaned, de-duplicated, sorted names
    discover_subdomains(domain)           -> convenience wrapper doing both

Notes on crt.sh behaviour (learned the hard way):
    * It is a free, community-run service backed by a PostgreSQL replica and
      it is frequently slow or returns 502/503/504 under load. We retry with
      exponential backoff and use a generous timeout.
    * When nothing matches it returns an empty body or "[]" rather than 404.
    * A single certificate's `name_value` can contain several hostnames
      separated by newlines (one per SAN entry), plus occasional e-mail
      addresses or garbage, so we split and validate every line.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from typing import Any, Iterable

import aiohttp

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"

# HTTP status codes worth retrying: rate limiting and crt.sh's habitual
# gateway errors when its database is overloaded.
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

# RFC 1035/1123 label: 1-63 chars, alnum or hyphen, no leading/trailing hyphen.
# Underscores are allowed because they legitimately appear in CT data
# (e.g. "_dmarc", "_acme-challenge" style service names).
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class CrtShError(RuntimeError):
    """Raised when crt.sh cannot be queried successfully after all retries."""


class CrtShFatalError(CrtShError):
    """A non-retryable error (e.g. HTTP 400/404) that should fail immediately."""


# --------------------------------------------------------------------------- #
# Normalisation helpers
# --------------------------------------------------------------------------- #
def normalize_domain(domain: str) -> str:
    """
    Turn user input into a bare, lowercase registrable domain.

    Accepts things people actually type into the scan box, e.g.
    "https://Example.com/", "*.example.com", "example.com." and returns
    "example.com". Internationalised names are converted to punycode so they
    compare equal to what appears in certificates.
    """
    d = domain.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)  # drop URL scheme
    d = d.split("/", 1)[0]  # drop path
    d = d.split(":", 1)[0]  # drop port
    d = d.strip(".")
    while d.startswith("*."):
        d = d[2:]
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid domain: {domain!r}") from exc
    if not is_valid_hostname(d) or "." not in d:
        raise ValueError(f"Invalid domain: {domain!r}")
    return d


def is_valid_hostname(name: str) -> bool:
    """Return True if `name` is a syntactically valid DNS hostname."""
    if not name or len(name) > 253:
        return False
    return all(_LABEL_RE.match(label) for label in name.split("."))


def clean_name(raw: str, domain: str) -> str | None:
    """
    Clean a single hostname taken from a certificate.

    Steps:
      1. lowercase + trim whitespace and trailing dots
      2. strip wildcard prefixes ("*.api.example.com" -> "api.example.com")
      3. drop anything that is not a valid hostname (e-mails, spaces, etc.)
      4. drop anything that is not the target domain or one of its subdomains
         (certificates often carry SANs for unrelated sister domains)

    Returns the cleaned name, or None if it should be discarded.
    """
    name = raw.strip().lower().rstrip(".")
    # Strip any number of leading wildcard labels; "*.*.x.com" does show up.
    while name.startswith("*."):
        name = name[2:]
    if not name or "@" in name or "*" in name:
        return None
    if not is_valid_hostname(name):
        return None
    if name != domain and not name.endswith("." + domain):
        return None
    return name


def extract_subdomains(records: Iterable[dict[str, Any]], domain: str) -> list[str]:
    """
    Pull every hostname out of crt.sh JSON rows and return a sorted,
    de-duplicated list.

    Both `name_value` (the SAN list) and `common_name` are read: the CN is
    usually also in the SANs, but older certificates sometimes only have it
    in the CN. A set handles de-duplication; sorting makes downstream
    behaviour (including the 500-host cap) deterministic between runs.
    """
    domain = normalize_domain(domain)
    found: set[str] = set()
    for row in records:
        for field in ("name_value", "common_name"):
            value = row.get(field)
            if not isinstance(value, str):
                continue
            # One certificate can list many names separated by newlines.
            for line in value.splitlines():
                cleaned = clean_name(line, domain)
                if cleaned:
                    found.add(cleaned)
    return sorted(found)


def wildcard_bases(records: Iterable[dict[str, Any]], domain: str) -> list[str]:
    """
    Names that appear in certificates only as wildcards ("*.dev.example.com" ->
    "dev.example.com"). Hosts under a wildcard certificate are invisible to CT
    logs, a limitation the proposal says we measure and report, so the
    pipeline surfaces how many such zones exist.
    """
    domain = normalize_domain(domain)
    found: set[str] = set()
    for row in records:
        value = row.get("name_value")
        if not isinstance(value, str):
            continue
        for line in value.splitlines():
            if line.strip().startswith("*."):
                cleaned = clean_name(line, domain)
                if cleaned:
                    found.add(cleaned)
    return sorted(found)


# --------------------------------------------------------------------------- #
# Network layer
# --------------------------------------------------------------------------- #
async def fetch_crtsh_records(
    session: aiohttp.ClientSession,
    domain: str,
    *,
    include_subdomains: bool = True,
    exclude_expired: bool = False,
    max_retries: int = 4,
    timeout_s: float = 90.0,
) -> list[dict[str, Any]]:
    """
    Query crt.sh's JSON endpoint for a domain.

    `include_subdomains=True` sends `q=%.example.com` (SQL LIKE wildcard), which
    is what actually returns certificates for subdomains. A plain
    `q=example.com` only matches certificates whose identity is exactly the
    apex. The apex itself is added back by the caller.

    Raises CrtShError if every attempt fails.
    """
    domain = normalize_domain(domain)
    query = f"%.{domain}" if include_subdomains else domain
    params = {"q": query, "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"

    timeout = aiohttp.ClientTimeout(total=timeout_s)
    last_error: Exception | None = None

    for attempt in range(1, max_retries + 1):
        try:
            async with session.get(CRTSH_URL, params=params, timeout=timeout) as resp:
                if resp.status in _RETRYABLE_STATUS:
                    raise CrtShError(f"crt.sh returned HTTP {resp.status}")
                if resp.status != 200:
                    # 4xx other than 429 will not fix itself; fail fast.
                    body = (await resp.text())[:200]
                    raise CrtShFatalError(f"crt.sh returned HTTP {resp.status}: {body!r}")
                text = await resp.text()
                if not text.strip():
                    return []  # crt.sh's way of saying "no results"
                try:
                    data = json.loads(text)
                except json.JSONDecodeError as exc:
                    # Under load crt.sh sometimes returns an HTML error page
                    # with status 200. Treat it as transient.
                    raise CrtShError("crt.sh returned non-JSON content") from exc
                if not isinstance(data, list):
                    raise CrtShError(f"Unexpected crt.sh payload type: {type(data).__name__}")
                logger.info("crt.sh returned %d certificate rows for %s", len(data), domain)
                return data
        except (aiohttp.ClientError, asyncio.TimeoutError, CrtShError) as exc:
            # Non-retryable HTTP errors bubble up immediately.
            if isinstance(exc, CrtShFatalError):
                raise
            last_error = exc
            if attempt == max_retries:
                break
            # Exponential backoff with jitter: ~2s, 4s, 8s ...
            delay = (2 ** attempt) + random.uniform(0, 1)
            logger.warning(
                "crt.sh attempt %d/%d for %s failed (%s); retrying in %.1fs",
                attempt, max_retries, domain, exc, delay,
            )
            await asyncio.sleep(delay)

    raise CrtShError(f"crt.sh query for {domain} failed after {max_retries} attempts: {last_error}")


async def discover_subdomains(
    domain: str,
    *,
    session: aiohttp.ClientSession | None = None,
    **fetch_kwargs: Any,
) -> list[str]:
    """
    Fetch + clean in one call. Always includes the apex domain itself, since
    it is part of the attack surface even if no certificate lists it.

    Pass an existing `session` to reuse connections across calls (the FastAPI
    app should keep one long-lived session); otherwise one is created.
    """
    domain = normalize_domain(domain)
    owns_session = session is None
    if owns_session:
        session = aiohttp.ClientSession(
            headers={"User-Agent": "CipherEclipse/1.0 (passive OSINT research)"}
        )
    try:
        records = await fetch_crtsh_records(session, domain, **fetch_kwargs)
    finally:
        if owns_session:
            await session.close()

    names = set(extract_subdomains(records, domain))
    names.add(domain)
    return sorted(names)
