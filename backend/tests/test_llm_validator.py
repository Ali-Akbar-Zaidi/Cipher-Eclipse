"""Hallucination guard: every entity the LLM mentions must exist in the scan data."""

from __future__ import annotations

import copy

import pytest

from app.llm.summary import SUMMARY_SCHEMA, build_context, template_summary
from app.llm.validator import EvidenceIndex, extract_entities, validate_summary

SCAN = {
    "domain": "example.com",
    "stats": {"subdomains": 2, "unique_ips": 3, "origin_hidden": 1, "vulnerabilities": 2},
    "subdomains": [
        {"name": "example.com", "ips": ["93.184.216.34"]},
        {"name": "api.example.com", "ips": ["93.184.216.35", "104.16.1.1"]},
    ],
    "hosts": [
        {"ip": "93.184.216.34", "subdomains": ["example.com"], "hostnames": ["www.example.com"],
         "ports": [22, 80], "cpes": [], "cves": ["CVE-2021-44228"], "max_risk": 91.0},
        {"ip": "93.184.216.35", "subdomains": ["api.example.com"], "hostnames": [],
         "ports": [443], "cpes": [], "cves": ["CVE-2014-0160"], "max_risk": 40.0},
        {"ip": "104.16.1.1", "subdomains": ["api.example.com"], "hostnames": [], "ports": [],
         "cpes": [], "cves": [], "origin_hidden": True, "cdn": "cloudflare"},
    ],
    "vulnerabilities": [
        {"cve_id": "CVE-2021-44228", "hosts": ["93.184.216.34"], "risk_score": 91.0, "cvss_score": 10.0,
         "epss_score": 0.94, "kev_probability": 0.6, "severity": "CRITICAL"},
        {"cve_id": "CVE-2014-0160", "hosts": ["93.184.216.35"], "risk_score": 40.0, "cvss_score": 7.5,
         "epss_score": 0.2, "kev_probability": 0.05, "severity": "HIGH"},
    ],
}


def good_summary() -> dict:
    return {
        "headline": "Log4Shell is exposed on example.com.",
        "overall_risk": "critical",
        "executive_summary": "CVE-2021-44228 affects 93.184.216.34 (example.com). Patch it now.",
        "key_findings": [
            {"title": "Log4Shell on the main site", "detail": "CVE-2021-44228 on 93.184.216.34.",
             "severity": "critical", "cve_ids": ["CVE-2021-44228"], "hosts": ["example.com"],
             "ips": ["93.184.216.34"]},
            {"title": "Heartbleed on the API", "detail": "api.example.com runs a vulnerable OpenSSL.",
             "severity": "high", "cve_ids": ["cve-2014-0160"], "hosts": ["API.example.com."],
             "ips": ["93.184.216.35"]},
        ],
        "recommendations": [
            {"action": "Upgrade log4j on 93.184.216.34 per nvd.nist.gov guidance.", "priority": "immediate",
             "cve_ids": ["CVE-2021-44228"], "hosts": [], "ips": ["93.184.216.34"]},
        ],
        "limitations": ["CVEs are version-inferred; ASP.NET and Node.js names are not hosts."],
    }


@pytest.fixture
def evidence() -> EvidenceIndex:
    return EvidenceIndex.from_scan(SCAN)


def test_grounded_summary_is_accepted_and_normalised(evidence):
    res = validate_summary(good_summary(), evidence)
    assert res.status == "accepted", res.report()
    assert res.unknown == []
    f2 = res.summary["key_findings"][1]
    assert f2["cve_ids"] == ["CVE-2014-0160"] and f2["hosts"] == ["api.example.com"]


def test_extract_entities_finds_cves_ips_and_target_hosts_only():
    text = ("See CVE-2021-44228 on 10.0.0.1, host dev.example.com, mail.other.com and nvd.nist.gov; "
            "Apache 2.4.7 and version 1.2.3.4.5 and ASP.NET are not entities.")
    ents = extract_entities(text, "example.com")
    assert ("cve", "CVE-2021-44228") in ents
    assert ("ip", "10.0.0.1") in ents
    assert ("hostname", "dev.example.com") in ents
    assert ("hostname", "mail.other.com") in ents
    assert not any(v in {"nvd.nist.gov", "asp.net", "1.2.3.4"} for _, v in ents)


def test_invented_cve_in_list_is_stripped(evidence):
    s = good_summary()
    s["key_findings"][0]["cve_ids"].append("CVE-2099-0001")
    res = validate_summary(s, evidence)
    assert res.status == "sanitized"
    assert res.summary["key_findings"][0]["cve_ids"] == ["CVE-2021-44228"]
    assert {"type": "cve", "value": "CVE-2099-0001", "where": "key_findings[0].cve_ids"} in res.unknown


def test_finding_with_invented_host_in_text_is_dropped(evidence):
    s = good_summary()
    s["key_findings"][1]["detail"] = "staging.example.com also exposes Heartbleed."
    res = validate_summary(s, evidence)
    assert res.status == "sanitized"
    assert [f["title"] for f in res.summary["key_findings"]] == ["Log4Shell on the main site"]
    assert "key_findings[1]" in res.removed_items


def test_invented_ip_sentence_removed_from_executive_summary(evidence):
    s = good_summary()
    s["executive_summary"] += " Host 8.8.4.4 is also affected."
    res = validate_summary(s, evidence)
    assert "8.8.4.4" not in res.summary["executive_summary"]
    assert "Patch it now." in res.summary["executive_summary"]


def test_fabricated_association_between_real_entities_is_removed(evidence):
    s = good_summary()
    # Both entities exist, but Shodan never reported Log4Shell on .35
    s["recommendations"][0]["ips"] = ["93.184.216.34", "93.184.216.35"]
    res = validate_summary(s, evidence)
    assert res.summary["recommendations"][0]["ips"] == ["93.184.216.34"]
    assert any(u["type"] == "association" for u in res.unknown)


def test_mostly_hallucinated_payload_is_rejected(evidence):
    s = good_summary()
    s["executive_summary"] = "CVE-2099-1111 CVE-2099-2222 CVE-2099-3333 on 1.1.1.1 and 2.2.2.2."
    s["key_findings"] = [{"title": "x", "detail": "CVE-2099-4444 on ghost.example.com", "severity": "high",
                          "cve_ids": ["CVE-2099-5555"], "hosts": ["ghost.example.com"], "ips": ["3.3.3.3"]}]
    res = validate_summary(s, evidence)
    assert res.status == "rejected" and res.summary is None


def test_reject_mode_rejects_any_unknown(evidence):
    s = good_summary()
    s["key_findings"][0]["ips"].append("9.9.9.9")
    assert validate_summary(s, evidence, mode="reject").status == "rejected"


@pytest.mark.parametrize("mutate", [
    lambda s: s.pop("headline"),
    lambda s: s.update(overall_risk="apocalyptic"),
    lambda s: s["key_findings"][0].update(cve_ids="CVE-2021-44228"),
    lambda s: s["recommendations"][0].update(priority="whenever"),
])
def test_schema_violations_are_rejected(evidence, mutate):
    s = good_summary()
    mutate(s)
    res = validate_summary(s, evidence)
    assert res.status == "rejected" and res.reasons[0].startswith("schema")


def test_non_object_is_rejected(evidence):
    assert validate_summary("Here is your summary!", evidence).status == "rejected"


def test_validator_does_not_mutate_input(evidence):
    s = good_summary()
    s["key_findings"][0]["cve_ids"].append("CVE-2099-0001")
    before = copy.deepcopy(s)
    validate_summary(s, evidence)
    assert s == before


def test_template_summary_always_passes_validation(evidence):
    res = validate_summary(template_summary(SCAN), evidence)
    assert res.status == "accepted", res.report()


def test_schema_is_strict_json_schema():
    assert SUMMARY_SCHEMA["additionalProperties"] is False
    item = SUMMARY_SCHEMA["properties"]["key_findings"]["items"]
    assert item["additionalProperties"] is False and set(item["required"]) == set(item["properties"])


def test_context_only_contains_scan_entities(evidence):
    ctx = build_context(SCAN)
    for kind, value in extract_entities(str(ctx), "example.com"):
        assert evidence.known(kind, value), (kind, value)
