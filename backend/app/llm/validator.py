"""
Hallucination guard for the LLM executive summary.

Every CVE ID, IPv4 address and hostname the model mentions, whether in a
structured list field or buried in free text, is checked against the hard data
the scan actually collected (crt.sh subdomains, DNS answers, Shodan InternetDB
records, the CVE list). The LLM is never trusted to be the source of a fact.

Policy
------
* Structured lists (`cve_ids`, `hosts`, `ips`): unknown entries are removed.
  An IP listed next to CVEs that Shodan never reported on that IP is removed
  too (a fabricated association, even if both entities exist).
* A finding or recommendation whose own text cites an unknown entity is dropped
  whole: its narrative was built on a fact we cannot back up.
* Headline / executive summary: sentences citing unknown entities are removed.
* The whole payload is REJECTED (and the caller falls back to the deterministic
  template) when it fails the schema, when mode="reject" and anything was
  unknown, or when the share of unknown mentions exceeds `max_unknown_ratio`.
* After sanitising, the result is re-scanned; it must contain zero unknown
  entities or it is rejected (defence in depth).
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\w.]){_OCTET}(?:\.{_OCTET}){{3}}(?![\w-]|\.\w)")
HOST_RE = re.compile(
    r"(?<![\w@.-])((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9])(?![\w-]|\.\w)",
    re.I,
)

# Off-target names with these TLDs and at least two dots are treated as host
# claims (e.g. "mail.other.com"). One-dot tokens such as "ASP.NET" or
# "Node.js" are product names far more often than hosts, so they are ignored
# unless they belong to the target domain.
_COMMON_TLDS = frozenset({
    "com", "net", "org", "io", "edu", "gov", "mil", "int", "co", "uk", "us", "pk", "de", "fr",
    "info", "biz", "app", "dev", "cloud", "ai", "me", "tv", "in", "ca", "au", "eu", "xyz",
})
# Reference sites the model may legitimately cite.
REFERENCE_HOSTS = frozenset({
    "nvd.nist.gov", "www.cisa.gov", "cisa.gov", "www.first.org", "first.org", "api.first.org",
    "shodan.io", "internetdb.shodan.io", "crt.sh", "attack.mitre.org", "cve.mitre.org",
    "www.cve.org", "cve.org",
})

SEVERITIES = ("critical", "high", "medium", "low", "informational")
PRIORITIES = ("immediate", "short_term", "long_term")

EntityType = Literal["cve", "ip", "hostname"]


# --------------------------------------------------------------------------- evidence
@dataclass
class EvidenceIndex:
    """Everything the summary is allowed to mention, built from the raw scan."""

    domain: str
    cves: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    cve_ips: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def from_scan(cls, scan: dict[str, Any]) -> "EvidenceIndex":
        domain = str(scan.get("domain", "")).lower()
        idx = cls(domain=domain, hostnames={domain} if domain else set())
        for sub in scan.get("subdomains") or []:
            idx.hostnames.add(str(sub["name"]).lower())
            idx.ips.update(sub.get("ips") or [])
        for host in scan.get("hosts") or []:
            idx.ips.add(host["ip"])
            idx.hostnames.update(h.lower() for h in host.get("hostnames") or [])
            idx.hostnames.update(h.lower() for h in host.get("subdomains") or [])
            for cve in host.get("cves") or []:
                cid = cve.upper()
                idx.cves.add(cid)
                idx.cve_ips.setdefault(cid, set()).add(host["ip"])
        for vuln in scan.get("vulnerabilities") or []:
            cid = str(vuln["cve_id"]).upper()
            idx.cves.add(cid)
            idx.cve_ips.setdefault(cid, set()).update(vuln.get("hosts") or [])
        return idx

    def known(self, kind: EntityType, value: str) -> bool:
        if kind == "cve":
            return value.upper() in self.cves
        if kind == "ip":
            return value in self.ips
        return value.lower().rstrip(".") in self.hostnames


# --------------------------------------------------------------------------- extraction
def _is_target_host(name: str, domain: str) -> bool:
    return bool(domain) and (name == domain or name.endswith("." + domain))


def extract_entities(text: str, domain: str) -> list[tuple[EntityType, str]]:
    """Every CVE / IPv4 / hostname claim in a piece of free text."""
    if not text:
        return []
    found: list[tuple[EntityType, str]] = []
    found += [("cve", m.group(0).upper()) for m in CVE_RE.finditer(text)]
    for m in IPV4_RE.finditer(text):
        try:
            found.append(("ip", str(ipaddress.IPv4Address(m.group(0)))))
        except ValueError:
            continue
    for m in HOST_RE.finditer(text):
        name = m.group(1).lower().rstrip(".")
        if name in REFERENCE_HOSTS:
            continue
        tld = name.rsplit(".", 1)[-1]
        if _is_target_host(name, domain) or (name.count(".") >= 2 and tld in _COMMON_TLDS):
            found.append(("hostname", name))
    return found


# --------------------------------------------------------------------------- schema
def _schema_errors(payload: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(payload, dict):
        return ["summary is not a JSON object"]
    for key, typ in (("headline", str), ("overall_risk", str), ("executive_summary", str),
                     ("key_findings", list), ("recommendations", list), ("limitations", list)):
        if not isinstance(payload.get(key), typ):
            errs.append(f"'{key}' missing or not a {typ.__name__}")
    if payload.get("overall_risk") not in SEVERITIES:
        errs.append("'overall_risk' has an invalid value")

    def check_items(name: str, text_keys: tuple[str, ...], enum_key: str, enum: tuple[str, ...]) -> None:
        for i, item in enumerate(payload.get(name) or []):
            if not isinstance(item, dict):
                errs.append(f"{name}[{i}] is not an object")
                continue
            for k in text_keys:
                if not isinstance(item.get(k), str):
                    errs.append(f"{name}[{i}].{k} missing")
            if item.get(enum_key) not in enum:
                errs.append(f"{name}[{i}].{enum_key} invalid")
            for k in ("cve_ids", "hosts", "ips"):
                if not isinstance(item.get(k), list) or not all(isinstance(x, str) for x in item[k]):
                    errs.append(f"{name}[{i}].{k} must be a list of strings")

    if isinstance(payload.get("key_findings"), list):
        check_items("key_findings", ("title", "detail"), "severity", SEVERITIES)
    if isinstance(payload.get("recommendations"), list):
        check_items("recommendations", ("action",), "priority", PRIORITIES)
    if isinstance(payload.get("limitations"), list) and not all(isinstance(x, str) for x in payload["limitations"]):
        errs.append("limitations must be a list of strings")
    return errs


# --------------------------------------------------------------------------- validation
@dataclass
class ValidationResult:
    status: Literal["accepted", "sanitized", "rejected"]
    summary: dict[str, Any] | None
    entities_checked: int = 0
    unknown: list[dict[str, str]] = field(default_factory=list)
    removed_items: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def hallucination_rate(self) -> float:
        return round(len(self.unknown) / self.entities_checked, 4) if self.entities_checked else 0.0

    def report(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "entities_checked": self.entities_checked,
            "unknown_entities": self.unknown,
            "removed_items": self.removed_items,
            "hallucination_rate": self.hallucination_rate,
            "reasons": self.reasons,
        }


_LIST_KIND: dict[str, EntityType] = {"cve_ids": "cve", "ips": "ip", "hosts": "hostname"}


def _normalise(kind: EntityType, value: str) -> str:
    value = value.strip()
    return value.upper() if kind == "cve" else value.lower().rstrip(".") if kind == "hostname" else value


def _split_sentences(text: str) -> list[str]:
    return [s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s]


def validate_summary(
    payload: Any,
    evidence: EvidenceIndex,
    *,
    mode: Literal["strip", "reject"] = "strip",
    max_unknown_ratio: float = 0.25,
) -> ValidationResult:
    errors = _schema_errors(payload)
    if errors:
        return ValidationResult("rejected", None, reasons=["schema: " + e for e in errors])

    data = copy.deepcopy(payload)
    res = ValidationResult("accepted", None)
    checked: set[tuple[str, str, str]] = set()  # (where, kind, value): count each claim once per location

    def note(where: str, kind: EntityType, value: str) -> bool:
        key = (where, kind, value)
        ok = evidence.known(kind, value)
        if key not in checked:
            checked.add(key)
            if not ok:
                res.unknown.append({"type": kind, "value": value, "where": where})
        return ok

    def text_ok(where: str, text: str) -> bool:
        return all([note(where, k, v) for k, v in extract_entities(text, evidence.domain)])

    def clean_item(section: str, i: int, item: dict[str, Any], text_keys: tuple[str, ...]) -> bool:
        where = f"{section}[{i}]"
        texts_fine = all([text_ok(f"{where}.{k}", item[k]) for k in text_keys])
        for list_key, kind in _LIST_KIND.items():
            kept = []
            for raw in item[list_key]:
                v = _normalise(kind, raw)
                if note(f"{where}.{list_key}", kind, v) and v not in kept:
                    kept.append(v)
            item[list_key] = kept
        # Association check: an IP cited with CVEs must actually carry one of them.
        if item["cve_ids"] and item["ips"]:
            linked = set().union(*(evidence.cve_ips.get(c, set()) for c in item["cve_ids"]))
            bad = [ip for ip in item["ips"] if ip not in linked]
            for ip in bad:
                res.unknown.append({"type": "association", "value": f"{ip} <-> {','.join(item['cve_ids'])}",
                                    "where": f"{where}.ips"})
            item["ips"] = [ip for ip in item["ips"] if ip in linked]
        if not texts_fine:
            res.removed_items.append(where)
        return texts_fine

    # Free-text top-level fields: drop offending sentences.
    for key in ("headline", "executive_summary"):
        kept = [s for s in _split_sentences(data[key]) if text_ok(key, s)]
        if len(kept) != len(_split_sentences(data[key])):
            res.removed_items.append(f"{key} (sentences)")
        data[key] = " ".join(kept)
    if not data["headline"]:
        data["headline"] = f"External attack surface summary for {evidence.domain}"

    data["key_findings"] = [f for i, f in enumerate(data["key_findings"])
                            if clean_item("key_findings", i, f, ("title", "detail"))]
    data["recommendations"] = [r for i, r in enumerate(data["recommendations"])
                               if clean_item("recommendations", i, r, ("action",))]
    limitations = []
    for i, text in enumerate(data["limitations"]):
        if text_ok(f"limitations[{i}]", text):
            limitations.append(text)
        else:
            res.removed_items.append(f"limitations[{i}]")
    data["limitations"] = limitations

    res.entities_checked = len(checked)
    if res.unknown:
        if mode == "reject":
            res.status, res.reasons = "rejected", ["unknown entities present and mode=reject"]
            return res
        ratio = len(res.unknown) / max(1, res.entities_checked)
        if ratio > max_unknown_ratio:
            res.status = "rejected"
            res.reasons = [f"{ratio:.0%} of cited entities are not in the scan data "
                           f"(limit {max_unknown_ratio:.0%})"]
            return res
        res.status = "sanitized"

    # Defence in depth: the cleaned payload must now be fully grounded.
    leftovers = _residual_unknowns(data, evidence)
    if leftovers:
        res.status, res.reasons = "rejected", [f"residual unknown entities after sanitising: {leftovers}"]
        return res
    res.summary = data
    return res


def _iter_texts(data: dict[str, Any]) -> Iterable[str]:
    yield data["headline"]
    yield data["executive_summary"]
    for f in data["key_findings"]:
        yield f["title"]
        yield f["detail"]
        yield from f["cve_ids"] + f["hosts"] + f["ips"]
    for r in data["recommendations"]:
        yield r["action"]
        yield from r["cve_ids"] + r["hosts"] + r["ips"]
    yield from data["limitations"]


def _residual_unknowns(data: dict[str, Any], evidence: EvidenceIndex) -> list[str]:
    bad = []
    for text in _iter_texts(data):
        for kind, value in extract_entities(text, evidence.domain):
            if not evidence.known(kind, value):
                bad.append(value)
    return bad
