"""
Local NVD + EPSS vulnerability cache (owner: Hadi).

Build:  python -m vulndb.build_db
Query:  from vulndb import VulnDB; VulnDB().get("CVE-2021-44228")
"""

from .query import VulnDB, VulnDBNotReady

__all__ = ["VulnDB", "VulnDBNotReady"]
