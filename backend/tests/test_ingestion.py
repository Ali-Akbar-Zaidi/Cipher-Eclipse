"""Offline tests for the ingestion stage (no network: crt.sh and DNS are faked)."""

from __future__ import annotations

import asyncio

import aiodns
import pytest
from aiohttp import web

from ingestion import crtsh
from ingestion.crtsh import clean_name, extract_subdomains, normalize_domain
from ingestion.dns_resolver import SubdomainResolver
from ingestion.pipeline import run_ingestion


# ---------------------------------------------------------------- cleaning --
def test_normalize_domain_accepts_common_inputs():
    assert normalize_domain("https://Example.COM/path") == "example.com"
    assert normalize_domain("*.example.com.") == "example.com"
    assert normalize_domain("example.com:443") == "example.com"
    with pytest.raises(ValueError):
        normalize_domain("not a domain")
    with pytest.raises(ValueError):
        normalize_domain("localhost")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("*.api.example.com", "api.example.com"),
        ("*.*.example.com", "example.com"),
        ("WWW.Example.com.", "www.example.com"),
        ("admin@example.com", None),        # e-mail SAN
        ("evil-example.com", None),         # suffix trick, not a subdomain
        ("other.org", None),                # unrelated SAN
        ("bad host.example.com", None),     # whitespace
        ("-bad.example.com", None),         # invalid label
        ("_dmarc.example.com", "_dmarc.example.com"),
    ],
)
def test_clean_name(raw, expected):
    assert clean_name(raw, "example.com") == expected


def test_extract_subdomains_splits_dedupes_and_sorts():
    rows = [
        {"name_value": "*.example.com\nexample.com\nwww.example.com", "common_name": "example.com"},
        {"name_value": "www.example.com\nmail.example.com", "common_name": "mail.example.com"},
        {"name_value": "*.dev.example.com", "common_name": None},
        {"name_value": "unrelated.net"},
        {"name_value": 12345},  # malformed row
    ]
    assert extract_subdomains(rows, "example.com") == [
        "dev.example.com",
        "example.com",
        "mail.example.com",
        "www.example.com",
    ]


# ------------------------------------------------------------- fake crt.sh --
@pytest.fixture
async def fake_crtsh(aiohttp_server, monkeypatch):
    """A local HTTP server that impersonates crt.sh."""
    state = {"calls": 0, "fail_first": 0, "payload": "[]", "status": 200, "queries": []}

    async def handler(request: web.Request):
        state["calls"] += 1
        state["queries"].append(dict(request.query))
        if state["calls"] <= state["fail_first"]:
            return web.Response(status=503, text="busy")
        return web.Response(status=state["status"], text=state["payload"],
                            content_type="application/json")

    app = web.Application()
    app.router.add_get("/", handler)
    server = await aiohttp_server(app)
    monkeypatch.setattr(crtsh, "CRTSH_URL", str(server.make_url("/")))
    # Make backoff instant in tests.
    real_sleep = asyncio.sleep
    monkeypatch.setattr(crtsh.asyncio, "sleep", lambda s: real_sleep(0))
    return state


async def test_fetch_retries_then_succeeds(fake_crtsh):
    import aiohttp, json
    fake_crtsh["fail_first"] = 2
    fake_crtsh["payload"] = json.dumps([{"name_value": "a.example.com"}])
    async with aiohttp.ClientSession() as s:
        rows = await crtsh.fetch_crtsh_records(s, "example.com")
    assert rows == [{"name_value": "a.example.com"}]
    assert fake_crtsh["calls"] == 3
    assert fake_crtsh["queries"][-1] == {"q": "%.example.com", "output": "json"}


async def test_fetch_gives_up(fake_crtsh):
    import aiohttp
    fake_crtsh["fail_first"] = 99
    async with aiohttp.ClientSession() as s:
        with pytest.raises(crtsh.CrtShError):
            await crtsh.fetch_crtsh_records(s, "example.com", max_retries=3)
    assert fake_crtsh["calls"] == 3


async def test_fetch_fatal_4xx_not_retried(fake_crtsh):
    import aiohttp
    fake_crtsh["status"] = 404
    async with aiohttp.ClientSession() as s:
        with pytest.raises(crtsh.CrtShFatalError):
            await crtsh.fetch_crtsh_records(s, "example.com")
    assert fake_crtsh["calls"] == 1


async def test_fetch_empty_body_means_no_results(fake_crtsh):
    import aiohttp
    fake_crtsh["payload"] = ""
    async with aiohttp.ClientSession() as s:
        assert await crtsh.fetch_crtsh_records(s, "example.com") == []


async def test_fetch_html_error_page_is_retried(fake_crtsh):
    import aiohttp
    fake_crtsh["payload"] = "<html>overloaded</html>"
    async with aiohttp.ClientSession() as s:
        with pytest.raises(crtsh.CrtShError):
            await crtsh.fetch_crtsh_records(s, "example.com", max_retries=2)
    assert fake_crtsh["calls"] == 2


# ---------------------------------------------------------------- fake DNS --
class _Rec:
    def __init__(self, addr):
        self.data = type("A", (), {"addr": addr})()


class _CnameRec:
    def __init__(self):
        self.data = type("CNAME", (), {"cname": "x.cdn.net"})()


class FakeResolver:
    """Mimics aiodns 4.x `query_dns` using a static zone."""

    def __init__(self, zone: dict[str, list[str] | str]):
        self.zone = zone
        self.queried: list[str] = []

    async def query_dns(self, name, qtype):
        assert qtype == "A"
        self.queried.append(name)
        await asyncio.sleep(0)
        val = self.zone.get(name, "NXDOMAIN")
        if val == "NXDOMAIN":
            raise aiodns.error.DNSError(aiodns.error.ARES_ENOTFOUND, "not found")
        if val == "TIMEOUT":
            raise aiodns.error.DNSError(aiodns.error.ARES_ETIMEOUT, "timeout")
        return type("R", (), {"answer": [_CnameRec(), *(_Rec(ip) for ip in val)]})()


async def test_resolve_many_maps_names_and_errors():
    zone = {
        "a.example.com": ["93.184.216.34", "93.184.216.34", "1.1.1.1"],
        "b.example.com": "TIMEOUT",
        "internal.example.com": ["10.0.0.5"],
        "mixed.example.com": ["10.0.0.6", "8.8.8.8"],
    }
    r = SubdomainResolver(resolver=FakeResolver(zone))
    res = await r.resolve_many(list(zone) + ["gone.example.com"])
    assert res.resolved == {
        "a.example.com": ["1.1.1.1", "93.184.216.34"],
        "mixed.example.com": ["8.8.8.8"],
    }
    assert res.unresolved == {
        "b.example.com": "TIMEOUT",
        "gone.example.com": "NXDOMAIN",
        "internal.example.com": "NON_PUBLIC",
    }
    assert not res.cap_reached


async def test_cap_stops_at_exactly_500_and_is_deterministic():
    # 1200 names; every third one does not resolve.
    zone = {}
    for i in range(1200):
        zone[f"h{i:04d}.example.com"] = "NXDOMAIN" if i % 3 == 0 else [f"8.8.{i // 256}.{i % 256}"]
    fake = FakeResolver(zone)
    r = SubdomainResolver(resolver=fake)
    res = await r.resolve_many(reversed(list(zone)), concurrency=64)
    assert len(res.resolved) == 500
    assert res.cap_reached
    # The 500 chosen are the first 500 resolvable names in sorted order.
    expected = [n for n in sorted(zone) if zone[n] != "NXDOMAIN"][:500]
    assert list(res.resolved) == expected
    # Nothing after the cap window was queried.
    assert len(fake.queried) < 1200
    assert len(res.resolved) + len(res.unresolved) + len(res.skipped) == 1200


async def test_run_ingestion_end_to_end(fake_crtsh):
    import json
    fake_crtsh["payload"] = json.dumps([
        {"name_value": "*.example.com\nwww.example.com", "common_name": "example.com"},
        {"name_value": "old.example.com\nadmin@example.com"},
    ])
    zone = {"example.com": ["93.184.216.34"], "www.example.com": ["93.184.216.34"]}
    out = await run_ingestion("example.com", resolver=SubdomainResolver(resolver=FakeResolver(zone)))
    assert out["subdomains"] == zone
    assert out["unique_ips"] == ["93.184.216.34"]
    assert out["unresolved"] == {"old.example.com": "NXDOMAIN"}
    assert out["stats"]["candidates"] == 3
    assert out["stats"]["certificates_seen"] == 2
    assert out["stats"]["wildcard_zones"] == 1  # *.example.com


async def test_run_ingestion_rejects_cap_above_500():
    with pytest.raises(ValueError):
        await run_ingestion("example.com", max_resolved=501)
