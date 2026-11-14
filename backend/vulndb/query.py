"""
Read-only, low-latency access to vulnerabilities.db for the scan pipeline.

Intended consumer: Azaan's Shodan stage, which receives CVE IDs from
InternetDB and needs CVSS/EPSS/description for each.

    from vulndb import VulnDB
    db = VulnDB()                                  # path from $VULNDB_PATH
    db.get("CVE-2021-44228")                       # -> dict or None
    db.get_many(["CVE-2021-44228", "CVE-2014-0160"])
    await db.aget_many([...])                      # from async code (FastAPI)

Design notes:
  * Opened with SQLite URI `mode=ro`, so the scan code can never modify the cache.
  * One connection per thread (sqlite3 connections must not be shared across
    threads); `aget*` runs the query in asyncio's default thread pool so the
    event loop is never blocked.
  * `get_many` uses `WHERE cve_id IN (...)`, which SQLite answers with one
    primary-key index seek per ID.
"""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

DEFAULT_DB_PATH = Path(os.environ.get("VULNDB_PATH", "data/vulnerabilities.db"))

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# Stay well below SQLite's default max host parameters (32766 on modern builds,
# 999 on old ones) to be portable.
_CHUNK = 900

_COLUMNS = (
    "cve_id, cvss_score, epss_score, description, cvss_version, cvss_vector, "
    "severity, epss_percentile, published, last_modified, vuln_status"
)


class VulnDBNotReady(RuntimeError):
    """The database file does not exist yet (the container may still be building it)."""


class VulnDB:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_DB_PATH
        self._local = threading.local()

    # -- connection management --------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if not self.path.exists():
                raise VulnDBNotReady(
                    f"{self.path} not found. Build it with: python -m vulndb.build_db"
                )
            conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=True)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close this thread's connection (others close when their thread exits)."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    @staticmethod
    def normalize_id(cve_id: str) -> str | None:
        cid = cve_id.strip().upper()
        return cid if _CVE_RE.match(cid) else None

    # -- sync API ------------------------------------------------------------
    def get(self, cve_id: str) -> dict[str, Any] | None:
        """Look up one CVE. Returns None for unknown or malformed IDs."""
        cid = self.normalize_id(cve_id)
        if cid is None:
            return None
        row = self._conn().execute(
            f"SELECT {_COLUMNS} FROM vulnerabilities WHERE cve_id = ?", (cid,)
        ).fetchone()
        return dict(row) if row else None

    def get_many(self, cve_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        """
        Look up many CVEs at once. Returns {cve_id: row}; IDs not in the
        database are simply absent from the result.
        """
        ids = sorted({c for c in (self.normalize_id(x) for x in cve_ids) if c})
        out: dict[str, dict[str, Any]] = {}
        conn = self._conn()
        for i in range(0, len(ids), _CHUNK):
            chunk = ids[i : i + _CHUNK]
            placeholders = ",".join("?" * len(chunk))
            for row in conn.execute(
                f"SELECT {_COLUMNS} FROM vulnerabilities WHERE cve_id IN ({placeholders})", chunk
            ):
                out[row["cve_id"]] = dict(row)
        return out

    def kev_labels(self, cve_ids: Iterable[str]) -> dict[str, bool]:
        """
        KEV membership for evaluation / classifier TRAINING LABELS only.

        Do not feed this into the risk score or model features: the proposal
        evaluates ranking quality against KEV, so using it as an input would
        leak the label. Returns {cve_id: in_kev} for every valid ID given.
        """
        ids = sorted({c for c in (self.normalize_id(x) for x in cve_ids) if c})
        hits: set[str] = set()
        conn = self._conn()
        for i in range(0, len(ids), _CHUNK):
            chunk = ids[i : i + _CHUNK]
            placeholders = ",".join("?" * len(chunk))
            hits.update(r[0] for r in conn.execute(
                f"SELECT cve_id FROM kev WHERE cve_id IN ({placeholders})", chunk))
        return {c: c in hits for c in ids}

    def metadata(self) -> dict[str, str | None]:
        """Build provenance (built_at, epss_score_date, row counts, ...)."""
        return {r["key"]: r["value"] for r in self._conn().execute("SELECT key, value FROM metadata")}

    # -- async API (for FastAPI handlers) ------------------------------------
    async def aget(self, cve_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.get, cve_id)

    async def aget_many(self, cve_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        ids = list(cve_ids)  # materialise before handing to another thread
        return await asyncio.to_thread(self.get_many, ids)
