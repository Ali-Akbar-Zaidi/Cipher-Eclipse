"""
Concurrent DNS A-record resolution with aiodns.

Why this is still "passive": we send ordinary recursive queries to PUBLIC
resolvers (Cloudflare / Google / Quad9 by default), exactly what any browser
does before visiting a site. We never open a connection to the target hosts
themselves and never touch any of their ports.

Behaviour:
  * Subdomains are processed in sorted order, in fixed-size concurrent
    windows (default 100 queries in flight).
  * Resolution stops as soon as MAX_RESOLVED (500) subdomains have produced
    at least one A record. That hard cap protects Azaan's Shodan InternetDB
    stage from timeouts on huge targets. Because input is sorted and results
    are kept in input order, the same input always yields the same 500.
  * Names that do not resolve (NXDOMAIN, no A record, timeouts) are recorded
    as unresolved rather than raising, so one bad name never kills a scan.

Compatible with aiodns 4.x (`query_dns`) and falls back to the 3.x `query`
API so teammates with an older local install still work.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

import aiodns

logger = logging.getLogger(__name__)

# Hard cap required by the Shodan pipeline. Do not raise without talking to Azaan.
MAX_RESOLVED = 500

DEFAULT_NAMESERVERS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


@dataclass
class ResolutionResult:
    """Outcome of resolving a batch of subdomains."""

    # subdomain -> sorted list of unique IPv4 addresses (only names with >= 1 IP)
    resolved: dict[str, list[str]] = field(default_factory=dict)
    # subdomain -> short reason string ("NXDOMAIN", "NODATA", "TIMEOUT", ...)
    unresolved: dict[str, str] = field(default_factory=dict)
    # Names never queried because the MAX_RESOLVED cap was hit first.
    skipped: list[str] = field(default_factory=list)
    cap_reached: bool = False


def _a_records_from_answer(answer: Any) -> list[str]:
    """
    Extract IPv4 strings from whatever aiodns returned.

    aiodns 4.x: pycares.DNSResult with .answer -> [DNSRecord(data=ARecordData(addr))]
                (the answer can also contain CNAME records we must skip)
    aiodns 3.x: list of ares_query_a_result objects with a .host attribute
    """
    ips: list[str] = []
    records = getattr(answer, "answer", answer)
    for rec in records or []:
        data = getattr(rec, "data", rec)
        addr = getattr(data, "addr", None) or getattr(data, "host", None)
        if not addr:
            continue
        try:
            if isinstance(ipaddress.ip_address(addr), ipaddress.IPv4Address):
                ips.append(str(addr))
        except ValueError:
            continue
    return ips


def _error_reason(exc: Exception) -> str:
    """Map an aiodns error to a short human-readable reason."""
    code = exc.args[0] if exc.args else None
    return {
        aiodns.error.ARES_ENOTFOUND: "NXDOMAIN",
        aiodns.error.ARES_ENODATA: "NODATA",
        aiodns.error.ARES_ETIMEOUT: "TIMEOUT",
        aiodns.error.ARES_ESERVFAIL: "SERVFAIL",
        aiodns.error.ARES_EREFUSED: "REFUSED",
        aiodns.error.ARES_ECONNREFUSED: "CONNREFUSED",
    }.get(code, f"ERROR({code})")


class SubdomainResolver:
    """
    Thin async wrapper around aiodns.DNSResolver with a concurrency limit,
    a per-query timeout and a single retry for transient failures.
    """

    def __init__(
        self,
        nameservers: Sequence[str] | None = DEFAULT_NAMESERVERS,
        *,
        timeout_s: float = 3.0,
        tries: int = 2,
        resolver: Any | None = None,
    ) -> None:
        # `resolver` lets tests inject a fake; production builds a real one.
        if resolver is not None:
            self._resolver = resolver
        else:
            kwargs: dict[str, Any] = {"timeout": timeout_s, "tries": tries}
            if nameservers:
                kwargs["nameservers"] = list(nameservers)
            self._resolver = aiodns.DNSResolver(**kwargs)
        self._timeout_s = timeout_s
        self._tries = tries

    async def resolve_a(self, name: str) -> list[str]:
        """
        Resolve one hostname to its IPv4 addresses.
        Raises aiodns.error.DNSError / asyncio.TimeoutError on failure.
        """
        if hasattr(self._resolver, "query_dns"):  # aiodns >= 4
            coro = self._resolver.query_dns(name, "A")
        else:  # aiodns 3.x
            coro = self._resolver.query(name, "A")
        # Belt-and-braces timeout on top of c-ares' own, so a wedged query can
        # never stall the whole window.
        answer = await asyncio.wait_for(coro, timeout=self._timeout_s * (self._tries + 1))
        ips = sorted(set(_a_records_from_answer(answer)), key=ipaddress.IPv4Address)
        if not ips:
            # e.g. the name only has a CNAME to something without an A record
            raise aiodns.error.DNSError(aiodns.error.ARES_ENODATA, "no A records")
        return ips

    async def _resolve_safe(self, name: str) -> tuple[str, list[str] | None, str | None]:
        """Resolve without raising: returns (name, ips | None, reason | None)."""
        try:
            return name, await self.resolve_a(name), None
        except aiodns.error.DNSError as exc:
            return name, None, _error_reason(exc)
        except asyncio.TimeoutError:
            return name, None, "TIMEOUT"
        except Exception as exc:  # never let one name kill the scan
            logger.debug("Unexpected error resolving %s: %r", name, exc)
            return name, None, f"ERROR({type(exc).__name__})"

    async def resolve_many(
        self,
        names: Iterable[str],
        *,
        max_resolved: int = MAX_RESOLVED,
        concurrency: int = 100,
        drop_non_public: bool = True,
    ) -> ResolutionResult:
        """
        Resolve `names` concurrently and stop after `max_resolved` successes.

        `drop_non_public=True` removes private/loopback/reserved addresses
        (e.g. internal hosts leaking into public DNS as 10.x.x.x). They are
        useless for Shodan InternetDB lookups, and a name whose only
        addresses are internal is recorded as unresolved ("NON_PUBLIC").
        """
        if max_resolved <= 0:
            raise ValueError("max_resolved must be positive")
        ordered = sorted(dict.fromkeys(n.strip().lower() for n in names if n and n.strip()))
        result = ResolutionResult()

        for start in range(0, len(ordered), concurrency):
            window = ordered[start : start + concurrency]
            outcomes = await asyncio.gather(*(self._resolve_safe(n) for n in window))

            # Walk the window in input order so the cap is deterministic.
            for idx, (name, ips, reason) in enumerate(outcomes):
                if ips and drop_non_public:
                    ips = [ip for ip in ips if ipaddress.IPv4Address(ip).is_global]
                    if not ips:
                        reason = "NON_PUBLIC"
                if ips:
                    result.resolved[name] = ips
                    if len(result.resolved) >= max_resolved:
                        result.cap_reached = True
                        # Everything after this name (rest of this window and all
                        # later windows) is not part of the output.
                        result.skipped = [o[0] for o in outcomes[idx + 1 :]] + ordered[
                            start + len(window) :
                        ]
                        logger.info("Resolution cap of %d reached; %d names skipped",
                                    max_resolved, len(result.skipped))
                        return result
                else:
                    result.unresolved[name] = reason or "UNKNOWN"

        return result


async def resolve_subdomains(
    names: Iterable[str],
    *,
    nameservers: Sequence[str] | None = DEFAULT_NAMESERVERS,
    max_resolved: int = MAX_RESOLVED,
    concurrency: int = 100,
    timeout_s: float = 3.0,
) -> dict[str, list[str]]:
    """
    Convenience function: resolve and return just {subdomain: [ipv4, ...]}.
    """
    resolver = SubdomainResolver(nameservers, timeout_s=timeout_s)
    res = await resolver.resolve_many(names, max_resolved=max_resolved, concurrency=concurrency)
    return res.resolved
