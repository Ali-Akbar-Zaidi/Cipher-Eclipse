"""
Guardrail: Cipher Eclipse must stay 100% passive.

Fails the build if anyone adds raw socket use or active scanners to the
backend source. (DNS lookups through aiodns to public resolvers and HTTPS
calls to third-party APIs are the only network activity allowed.)
"""

import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1]
FORBIDDEN = [
    (re.compile(r"^\s*(import|from)\s+socket\b", re.M), "raw socket import"),
    (re.compile(r"^\s*(import|from)\s+(scapy|nmap|masscan)\b", re.M), "active scanner library"),
    (re.compile(r"""["'](nmap|masscan|zmap|naabu|nuclei)["']"""), "active scanner binary"),
    (re.compile(r"\.open_connection\("), "direct TCP connection"),
]


def test_no_active_scanning_code():
    offenders = []
    for path in SRC.rglob("*.py"):
        if "tests" in path.parts or ".venv" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for pattern, why in FORBIDDEN:
            if pattern.search(text):
                offenders.append(f"{path.relative_to(SRC)}: {why}")
    assert not offenders, "Passive-only policy violated:\n" + "\n".join(offenders)
