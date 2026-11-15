"""POST /api/scan end to end with every network stage faked (no internet needed)."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
import app.scan as scan_mod
from app import integrations
from app.llm import summary as summary_mod
from ingestion import CrtShError

INGEST = {
    "domain": "example.com",
    "subdomains": {"example.com": ["93.184.216.34"], "cdn.example.com": ["104.16.5.5"],
                   "api.example.com": ["93.184.216.34"]},
    "unique_ips": ["93.184.216.34", "104.16.5.5"],
    "unresolved": {"old.example.com": "NXDOMAIN"},
    "skipped": [],
    "stats": {"certificates_seen": 12, "wildcard_zones": 0, "cap_reached": False},
}
IDB = {"93.184.216.34": {"ports": [22, 443], "hostnames": ["www.example.com"],
                         "cpes": ["cpe:/a:apache:http_server:2.4.7", "cpe:/o:canonical:ubuntu_linux"],
                         "vulns": ["CVE-2021-44228", "CVE-2014-0160", "CVE-2099-0001"], "tags": []}}
ROWS = {
    "CVE-2021-44228": {"cve_id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.944,
                       "severity": "CRITICAL", "description": "Log4Shell"},
    "CVE-2014-0160": {"cve_id": "CVE-2014-0160", "cvss_score": 7.5, "epss_score": 0.02,
                      "severity": "HIGH", "description": "Heartbleed"},
}


class FakeDB:
    def __init__(self, *_a, **_k):
        from pathlib import Path
        self.path = Path("fake.db")

    async def aget_many(self, ids):
        return {i: ROWS[i] for i in ids if i in ROWS}


@pytest.fixture
def client(monkeypatch):
    async def fake_ingest(domain, session=None, **_):
        return dict(INGEST)

    seen = {}

    async def fake_lookup(ips, session):
        seen["ips"] = list(ips)
        return {ip: IDB[ip] for ip in ips if ip in IDB}

    monkeypatch.setattr(scan_mod, "run_ingestion", fake_ingest)
    monkeypatch.setattr(scan_mod, "lookup_internetdb", fake_lookup)
    monkeypatch.setattr(main_mod, "VulnDB", FakeDB)
    with TestClient(main_mod.app) as c:
        c.seen = seen
        yield c


def test_scan_returns_unified_payload(client):
    r = client.post("/api/scan", json={"domain": "https://Example.com/", "use_llm": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["domain"] == "example.com"
    # CDN address is tagged and never sent to InternetDB
    assert client.seen["ips"] == ["93.184.216.34"]
    cdn = next(h for h in body["hosts"] if h["ip"] == "104.16.5.5")
    assert cdn["origin_hidden"] and cdn["cdn"] == "cloudflare"
    origin = next(h for h in body["hosts"] if h["ip"] == "93.184.216.34")
    assert origin["subdomains"] == ["api.example.com", "example.com"] and origin["ports"] == [22, 443]
    # every CVE scored, sorted by risk, labelled potential, backport flagged from the Ubuntu CPE
    vulns = body["vulnerabilities"]
    assert [v["cve_id"] for v in vulns][0] == "CVE-2021-44228"
    assert all(0 <= v["risk_score"] <= 100 and v["confidence"] == "potential" for v in vulns)
    assert all(v["backport_suspect"] for v in vulns)
    unknown = next(v for v in vulns if v["cve_id"] == "CVE-2099-0001")
    assert unknown["in_vulndb"] is False and unknown["cvss_score"] is None
    assert body["stats"]["origin_hidden"] == 1 and body["stats"]["vulnerabilities"] == 3
    assert body["summary"]["generator"] == "template"
    assert body["summary"]["validation"]["status"] == "accepted"
    assert set(body["timings"]) >= {"ingestion", "internetdb", "risk_scoring", "total"}
    # cached for re-fetch
    assert client.get(f"/api/scans/{body['scan_id']}").json()["scan_id"] == body["scan_id"]


def test_llm_summary_is_validated_before_returning(client, monkeypatch):
    async def fake_llm(context):
        return ({
            "headline": "Log4Shell exposed on example.com.",
            "overall_risk": "critical",
            "executive_summary": ("CVE-2021-44228 is on 93.184.216.34 (example.com, api.example.com). "
                                  "CVE-2014-0160 is also on 93.184.216.34. Also CVE-2023-9999 on 6.6.6.6."),
            "key_findings": [
                {"title": "Log4Shell", "detail": "CVE-2021-44228 on 93.184.216.34", "severity": "critical",
                 "cve_ids": ["CVE-2021-44228"], "hosts": ["example.com"], "ips": ["93.184.216.34"]},
                {"title": "Invented", "detail": "admin.example.com leaks data", "severity": "high",
                 "cve_ids": [], "hosts": ["admin.example.com"], "ips": []},
            ],
            "recommendations": [{"action": "Patch log4j.", "priority": "immediate",
                                 "cve_ids": ["CVE-2021-44228"], "hosts": [], "ips": []}],
            "limitations": [],
        }, "claude-opus-5-5")

    monkeypatch.setattr(summary_mod, "call_llm", fake_llm)
    body = client.post("/api/scan", json={"domain": "example.com"}).json()
    s = body["summary"]
    assert s["generator"] == "llm" and s["validation"]["status"] == "sanitized"
    assert "6.6.6.6" not in s["executive_summary"] and "CVE-2023-9999" not in s["executive_summary"]
    assert "CVE-2014-0160 is also on 93.184.216.34." in s["executive_summary"]
    assert [f["title"] for f in s["key_findings"]] == ["Log4Shell"]


def test_llm_rejected_payload_falls_back_to_template(client, monkeypatch):
    async def fake_llm(context):
        return ({"headline": "nope"}, "claude-opus-5-5")

    monkeypatch.setattr(summary_mod, "call_llm", fake_llm)
    s = client.post("/api/scan", json={"domain": "example.com"}).json()["summary"]
    assert s["generator"] == "template"
    assert s["llm_validation"]["status"] == "rejected"


def test_bad_domain_is_422(client):
    assert client.post("/api/scan", json={"domain": "not a domain"}).status_code == 422
    assert client.post("/api/scan", json={"domain": "ab"}).status_code == 422


def test_crtsh_outage_is_502(client, monkeypatch):
    async def boom(domain, session=None, **_):
        raise CrtShError("HTTP 502")

    monkeypatch.setattr(scan_mod, "run_ingestion", boom)
    r = client.post("/api/scan", json={"domain": "example.com"})
    assert r.status_code == 502 and "crt.sh" in r.json()["detail"]


def test_scan_timeout_is_504(client, monkeypatch):
    async def slow(domain, session=None, **_):
        await asyncio.sleep(5)

    monkeypatch.setattr(scan_mod, "run_ingestion", slow)
    monkeypatch.setattr(main_mod, "settings", main_mod.settings.__class__(scan_timeout_seconds=0.05))
    assert client.post("/api/scan", json={"domain": "example.com"}).status_code == 504


def test_cors_allows_dashboard_origin(client):
    r = client.options("/api/scan", headers={"Origin": "http://localhost:3000",
                                             "Access-Control-Request-Method": "POST",
                                             "Access-Control-Request-Headers": "content-type"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_unknown_scan_is_404(client):
    assert client.get("/api/scans/doesnotexist").status_code == 404


def test_builtin_cdn_filter():
    keep, hidden = integrations._builtin_filter_cdn(["104.16.0.1", "151.101.1.1", "8.8.8.8"])
    assert keep == ["8.8.8.8"] and hidden == {"104.16.0.1": "cloudflare", "151.101.1.1": "fastly"}
