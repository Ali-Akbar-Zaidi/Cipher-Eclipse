"""
Executive risk summary: LLM call with a forced JSON schema, then validation.

Flow
  1. build_context()  - compact, factual JSON of the scan (top CVEs by risk,
                         affected hosts, exposure stats). This is the ONLY thing
                         the model sees, and the validator checks against the
                         full scan, which is a superset of it.
  2. call_llm()       - Claude Messages API with `output_config.format`
                         (json_schema), so the reply is guaranteed to parse
                         into SUMMARY_SCHEMA rather than conversational text.
  3. validate_summary() strips or rejects anything not in the hard data.
  4. If there is no API key, the call fails, the model refuses, or the
     validator rejects the payload, a deterministic template summary built
     straight from the data is used instead (it passes the same validator).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..config import settings
from .validator import PRIORITIES, SEVERITIES, EvidenceIndex, ValidationResult, validate_summary

logger = logging.getLogger("cipher.llm")

MAX_CONTEXT_CVES = 25
MAX_CONTEXT_HOSTS = 40

_STR_LIST = {"type": "array", "items": {"type": "string"}}

SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["headline", "overall_risk", "executive_summary", "key_findings", "recommendations", "limitations"],
    "properties": {
        "headline": {"type": "string"},
        "overall_risk": {"type": "string", "enum": list(SEVERITIES)},
        "executive_summary": {"type": "string"},
        "key_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["title", "detail", "severity", "cve_ids", "hosts", "ips"],
                "properties": {
                    "title": {"type": "string"},
                    "detail": {"type": "string"},
                    "severity": {"type": "string", "enum": list(SEVERITIES)},
                    "cve_ids": _STR_LIST,
                    "hosts": _STR_LIST,
                    "ips": _STR_LIST,
                },
            },
        },
        "recommendations": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["action", "priority", "cve_ids", "hosts", "ips"],
                "properties": {
                    "action": {"type": "string"},
                    "priority": {"type": "string", "enum": list(PRIORITIES)},
                    "cve_ids": _STR_LIST,
                    "hosts": _STR_LIST,
                    "ips": _STR_LIST,
                },
            },
        },
        "limitations": _STR_LIST,
    },
}

SYSTEM_PROMPT = """\
You write the executive risk summary for Cipher Eclipse, a passive external attack-surface \
mapping tool used by defenders. The reader is a security manager deciding what to fix first.

Ground rules:
- The scan data in the user message is the only source of truth. Mention a CVE ID, IP address \
or hostname only if it appears in that data, spelled exactly as given. Every mention is checked \
automatically against the data, and findings that cite anything else are deleted.
- When you list cve_ids, hosts or ips on a finding or recommendation, list only entities from \
the data that the finding is actually about. Only pair an IP with a CVE if the data shows that \
CVE on that IP.
- Rank by the provided risk_score and kev_probability, not by CVSS alone. A high-CVSS CVE with \
a tiny EPSS is usually less urgent than a medium-CVSS CVE that is likely to be exploited.
- The CVEs come from Shodan InternetDB version matching, so they are potential, not confirmed: \
say so where it matters, and note that distribution back-ports can make some of them false positives.
- Hosts marked origin_hidden sit behind a CDN; their real servers were not assessed.
- Write plain English for a non-specialist: 3 to 6 key findings, 3 to 6 concrete recommendations, \
an executive_summary of at most 120 words, and a one-sentence headline.
- If the scan found nothing exploitable, say that plainly and keep overall_risk low or informational."""


# --------------------------------------------------------------------------- context
def build_context(scan: dict[str, Any]) -> dict[str, Any]:
    vulns = sorted(scan.get("vulnerabilities") or [], key=lambda v: v.get("risk_score") or 0, reverse=True)
    top = vulns[:MAX_CONTEXT_CVES]
    cited_ips = {ip for v in top for ip in v.get("hosts") or []}
    hosts = [h for h in scan.get("hosts") or [] if h["ip"] in cited_ips or h.get("ports")]
    hosts.sort(key=lambda h: (h["ip"] not in cited_ips, -(h.get("max_risk") or 0)))
    return {
        "target_domain": scan.get("domain"),
        "stats": scan.get("stats"),
        "top_vulnerabilities": [
            {
                "cve_id": v["cve_id"],
                "risk_score": v.get("risk_score"),
                "kev_probability": v.get("kev_probability"),
                "cvss_score": v.get("cvss_score"),
                "epss_score": v.get("epss_score"),
                "severity": v.get("severity"),
                "affected_ips": v.get("hosts"),
                "description": (v.get("description") or "")[:300],
            }
            for v in top
        ],
        "hosts": [
            {
                "ip": h["ip"],
                "subdomains": (h.get("subdomains") or [])[:10],
                "open_ports": h.get("ports"),
                "software_cpes": (h.get("cpes") or [])[:10],
                "cve_count": len(h.get("cves") or []),
                "origin_hidden": h.get("origin_hidden", False),
                "cdn": h.get("cdn"),
            }
            for h in hosts[:MAX_CONTEXT_HOSTS]
        ],
        "more_vulnerabilities_not_shown": max(0, len(vulns) - len(top)),
    }


# --------------------------------------------------------------------------- LLM
# Models that accept server-side refusal fallbacks.
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-1", "claude-fable-5-2"}


class LLMUnavailable(RuntimeError):
    pass


async def call_llm(context: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Return (parsed JSON summary, model that answered). Raises LLMUnavailable."""
    if not settings.llm_api_key:
        raise LLMUnavailable("no LLM_API_KEY configured")
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=settings.llm_api_key, timeout=settings.llm_timeout_seconds,
                                      max_retries=2)
    request: dict[str, Any] = {
        "model": settings.llm_model,
        "max_tokens": 16000,
        "system": SYSTEM_PROMPT,
        "messages": [{
            "role": "user",
            "content": "Scan data (JSON):\n" + json.dumps(context, indent=1, sort_keys=True)
                       + "\n\nWrite the executive risk summary for this scan.",
        }],
        "output_config": {
            "effort": settings.llm_effort,
            "format": {"type": "json_schema", "schema": SUMMARY_SCHEMA},
        },
    }
    try:
        if settings.llm_model in _FALLBACK_MODELS:
            response = await client.beta.messages.create(
                betas=["server-side-fallback-2026-07-01"], fallbacks="default", **request)
        else:
            response = await client.messages.create(**request)
    except anthropic.AuthenticationError as exc:
        raise LLMUnavailable("LLM API key rejected") from exc
    except anthropic.RateLimitError as exc:
        raise LLMUnavailable("LLM rate limited") from exc
    except anthropic.APIStatusError as exc:
        raise LLMUnavailable(f"LLM API error {exc.status_code}") from exc
    except anthropic.APIConnectionError as exc:
        raise LLMUnavailable("could not reach the LLM API") from exc
    finally:
        await client.close()

    if response.stop_reason == "refusal":
        raise LLMUnavailable("model declined the request")
    if response.stop_reason == "max_tokens":
        raise LLMUnavailable("model output was truncated")
    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        return json.loads(text), response.model
    except json.JSONDecodeError as exc:
        raise LLMUnavailable("model returned invalid JSON") from exc


# --------------------------------------------------------------------------- template
def _sev(score: float | None) -> str:
    if score is None:
        return "informational"
    return "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"


def template_summary(scan: dict[str, Any]) -> dict[str, Any]:
    """Deterministic summary straight from the data: the fallback and the baseline."""
    domain = scan.get("domain", "the target")
    stats = scan.get("stats") or {}
    vulns = sorted(scan.get("vulnerabilities") or [], key=lambda v: v.get("risk_score") or 0, reverse=True)
    hosts = {h["ip"]: h for h in scan.get("hosts") or []}
    top = vulns[:5]
    overall = _sev(top[0].get("risk_score")) if top else "informational"

    findings = []
    for v in top:
        ips = list(v.get("hosts") or [])
        subs = sorted({s for ip in ips for s in hosts.get(ip, {}).get("subdomains") or []})
        kev = v.get("kev_probability")
        findings.append({
            "title": f"{v['cve_id']} (risk {v.get('risk_score', 0):.0f}/100)",
            "detail": (f"CVSS {v.get('cvss_score') if v.get('cvss_score') is not None else 'n/a'}, "
                       f"EPSS {v.get('epss_score') or 0:.3f}"
                       + (f", estimated KEV likelihood {kev:.0%}" if kev is not None else "")
                       + f". Reported by Shodan InternetDB on {len(ips)} host(s). "
                         "Potential match based on the software version; confirm before patching."),
            "severity": _sev(v.get("risk_score")),
            "cve_ids": [v["cve_id"]],
            "hosts": subs[:5],
            "ips": ips[:5],
        })

    recs = []
    if top:
        recs.append({
            "action": "Patch or upgrade the software behind the highest-risk CVEs first, starting with "
                      + ", ".join(v["cve_id"] for v in top[:3]) + ".",
            "priority": "immediate",
            "cve_ids": [v["cve_id"] for v in top[:3]],
            "hosts": [], "ips": sorted({ip for v in top[:3] for ip in v.get("hosts") or []})[:5],
        })
    exposed = [ip for ip, h in hosts.items() if set(h.get("ports") or []) & {21, 23, 445, 3389, 5900, 3306, 5432, 6379, 27017}]
    if exposed:
        recs.append({
            "action": "Restrict internet access to remote-administration, file-sharing and database ports "
                      "on the listed hosts (firewall or VPN).",
            "priority": "short_term", "cve_ids": [], "hosts": [], "ips": exposed[:5],
        })
    recs.append({
        "action": "Review the discovered subdomains and decommission forgotten or test hosts.",
        "priority": "long_term", "cve_ids": [], "hosts": [], "ips": [],
    })

    def n(count: int, word: str, plural: str | None = None) -> str:
        return f"{count} {word if count == 1 else (plural or word + 's')}"

    n_cves = stats.get("vulnerabilities", len(vulns))
    hidden = stats.get("origin_hidden", 0)
    summary = (f"The passive scan of {domain} found {n(stats.get('subdomains', 0), 'live subdomain')} on "
               f"{n(stats.get('unique_ips', 0), 'IP address', 'IP addresses')}, of which {hidden} "
               f"{'sits' if hidden == 1 else 'sit'} behind a CDN. "
               f"Shodan InternetDB reports {n(n_cves, 'potential CVE')} on the remaining hosts.")
    if top:
        summary += f" The most urgent is {top[0]['cve_id']} with a risk score of {top[0].get('risk_score', 0):.0f}/100."
    return {
        "headline": f"{domain}: {n(n_cves, 'potential CVE')}, overall risk {overall}.",
        "overall_risk": overall,
        "executive_summary": summary,
        "key_findings": findings,
        "recommendations": recs,
        "limitations": [
            "CVEs are inferred from software versions and may include back-ported fixes (false positives).",
            "Hosts behind a CDN were not assessed because their origin servers are hidden.",
            "Certificate Transparency misses hosts without TLS certificates or covered only by wildcard certificates.",
        ],
    }


# --------------------------------------------------------------------------- entry point
async def generate_summary(scan: dict[str, Any], *, use_llm: bool = True) -> dict[str, Any]:
    evidence = EvidenceIndex.from_scan(scan)
    llm_report: dict[str, Any] | None = None
    note = None
    model = None

    if use_llm:
        try:
            raw, model = await call_llm(build_context(scan))
            result = validate_summary(raw, evidence)
            llm_report = result.report()
            if result.summary is not None:
                return {"generator": "llm", "model": model, **result.summary, "validation": llm_report}
            note = "LLM summary rejected by the hallucination check"
        except LLMUnavailable as exc:
            note = f"LLM unavailable: {exc}"
        logger.info("Using template summary (%s)", note)
    else:
        note = "LLM disabled for this request"

    fallback: ValidationResult = validate_summary(template_summary(scan), evidence)
    if fallback.summary is None:  # should never happen; surface it instead of hiding it
        logger.error("Template summary failed validation: %s", fallback.reasons)
        return {"generator": "none", "note": note, "validation": fallback.report(), "llm_validation": llm_report}
    return {"generator": "template", "model": model, "note": note, **fallback.summary,
            "validation": fallback.report(), "llm_validation": llm_report}
