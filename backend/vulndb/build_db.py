"""
Offline builder for the local vulnerability cache (vulnerabilities.db).

Why: the NIST NVD API allows ~5 requests / 30 s without a key (50 with one).
A single scan can surface hundreds of CVEs, so querying NVD live would stall
every scan. Instead we download the public bulk datasets once, compile them
into a small SQLite file, and let the scan-time code (Azaan's module) do
indexed primary-key lookups in microseconds.

Data sources (all free, no API key):
  * NVD CVE JSON 2.0 yearly data feeds (gzip):
        https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<YEAR>.json.gz
    The 2002 feed also contains all 1999-2001 CVEs.
  * FIRST EPSS daily scores (gzip CSV):
        https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
    First line is a comment like "#model_version:v2025.03.14,score_date:...",
    followed by the header "cve,epss,percentile".
  * CISA Known Exploited Vulnerabilities catalogue (JSON):
        https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    Stored in a SEPARATE `kev` table because the proposal uses KEV membership
    as the evaluation LABEL for the ranking model. It must never be used as a
    model input or ranking feature (that would leak the label). Optional: if
    the download fails the build continues without it.

Memory use: NVD yearly feeds are up to several hundred MB of JSON each once
decompressed. We stream-parse them with `ijson` straight out of the gzip
stream, so peak RAM stays around ~150 MB regardless of feed size.

Usage:
    python -m vulndb.build_db                          # download + build ./data/vulnerabilities.db
    python -m vulndb.build_db --db /app/data/vulnerabilities.db
    python -m vulndb.build_db --start-year 2015         # smaller dev build
    python -m vulndb.build_db --offline                # only use files already in --cache-dir
    python -m vulndb.build_db --force                  # rebuild even if the DB exists

The build writes to "<db>.tmp" and atomically renames on success, so a
crashed or interrupted build never leaves a half-written database that the
backend would mistake for a finished one.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import datetime as dt
import gzip
import io
import json
import logging
import os
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator

import aiohttp
import ijson

logger = logging.getLogger("vulndb.build")

NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_NVD_YEAR = 2002
SCHEMA_VERSION = 2

# Preference order when a CVE has several CVSS versions. v3.x is what most
# tooling (and our ML features) expects, so it wins; v4.0 is still sparsely
# populated in NVD; v2 is the fallback for old CVEs.
CVSS_PREFERENCE = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

SCHEMA_SQL = """
-- Primary table queried by the scan pipeline.
-- cve_id is the PRIMARY KEY, which makes SQLite maintain a unique B-tree
-- index on it (sqlite_autoindex_vulnerabilities_1). Lookups by cve_id are
-- O(log n) index seeks: ~250k rows -> ~18 comparisons, i.e. microseconds.
CREATE TABLE vulnerabilities (
    cve_id           TEXT PRIMARY KEY NOT NULL,   -- e.g. 'CVE-2021-44228'
    cvss_score       REAL,                        -- base score 0.0-10.0 (NULL if not yet scored)
    epss_score       REAL,                        -- probability of exploitation in next 30 days, 0-1
    description      TEXT,                        -- English description from NVD
    cvss_version     TEXT,                        -- '3.1', '3.0', '4.0' or '2.0'
    cvss_vector      TEXT,                        -- full vector string
    severity         TEXT,                        -- LOW / MEDIUM / HIGH / CRITICAL
    epss_percentile  REAL,                        -- EPSS percentile 0-1
    published        TEXT,                        -- ISO-8601
    last_modified    TEXT,                        -- ISO-8601
    vuln_status      TEXT                         -- NVD status, e.g. 'Analyzed'
);

-- Secondary indexes used for ranking queries ("top N by EPSS").
CREATE INDEX idx_vuln_epss ON vulnerabilities (epss_score DESC);
CREATE INDEX idx_vuln_cvss ON vulnerabilities (cvss_score DESC);

-- CISA KEV catalogue. EVALUATION LABEL ONLY (ranking quality / classifier
-- target). Never join this into model features or the risk score.
CREATE TABLE kev (
    cve_id               TEXT PRIMARY KEY NOT NULL,
    date_added           TEXT,
    due_date             TEXT,
    known_ransomware_use TEXT,     -- 'Known' / 'Unknown'
    vendor_project       TEXT,
    product              TEXT,
    vulnerability_name   TEXT
);

-- Build provenance, so the report can say "EPSS data as of <date>".
CREATE TABLE metadata (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT
);
"""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class CveRow:
    cve_id: str
    cvss_score: float | None
    description: str | None
    cvss_version: str | None
    cvss_vector: str | None
    severity: str | None
    published: str | None
    last_modified: str | None
    vuln_status: str | None


@dataclass(slots=True)
class EpssData:
    scores: dict[str, tuple[float, float]]  # cve_id -> (epss, percentile)
    model_version: str | None
    score_date: str | None


# --------------------------------------------------------------------------- #
# Download stage (async)
# --------------------------------------------------------------------------- #
async def _download(
    session: aiohttp.ClientSession,
    url: str,
    dest: Path,
    *,
    max_age_hours: float,
    retries: int = 4,
) -> Path:
    """
    Download `url` to `dest` unless a fresh-enough copy is already cached.
    Writes to a .part file first so an interrupted download is never reused.
    """
    if dest.exists() and dest.stat().st_size > 0:
        age_h = (time.time() - dest.stat().st_mtime) / 3600
        if age_h < max_age_hours:
            logger.info("Using cached %s (%.1fh old)", dest.name, age_h)
            return dest

    part = dest.with_suffix(dest.suffix + ".part")
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=30, sock_read=120)
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, timeout=timeout) as resp:
                if resp.status == 404:
                    raise FileNotFoundError(f"{url} returned 404")
                resp.raise_for_status()
                with part.open("wb") as fh:
                    async for chunk in resp.content.iter_chunked(1 << 16):
                        fh.write(chunk)
            os.replace(part, dest)
            logger.info("Downloaded %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
            return dest
        except FileNotFoundError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            part.unlink(missing_ok=True)
            if attempt == retries:
                raise RuntimeError(f"Failed to download {url}: {exc}") from exc
            delay = 2 ** attempt
            logger.warning("Download of %s failed (%s), retry %d in %ds", url, exc, attempt, delay)
            await asyncio.sleep(delay)
    raise AssertionError("unreachable")


async def download_datasets(
    cache_dir: Path,
    years: list[int],
    *,
    max_age_hours: float = 20.0,
    concurrency: int = 3,
) -> tuple[list[Path], Path, Path | None]:
    """
    Fetch all NVD yearly feeds, the EPSS CSV and the KEV catalogue concurrently
    (politely: a few at a time; NVD asks bulk users not to hammer the feeds).
    Returns (list of NVD feed paths, EPSS path, KEV path or None).
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": "CipherEclipse-VulnDB/1.0 (university research)"}

    async with aiohttp.ClientSession(headers=headers) as session:

        async def fetch(url: str, dest: Path) -> Path | None:
            async with sem:
                try:
                    return await _download(session, url, dest, max_age_hours=max_age_hours)
                except FileNotFoundError:
                    # The current year's feed may not exist yet on Jan 1st.
                    logger.warning("Not found, skipping: %s", url)
                    return None

        nvd_tasks = [
            fetch(NVD_FEED_URL.format(year=y), cache_dir / f"nvdcve-2.0-{y}.json.gz") for y in years
        ]
        epss_task = fetch(EPSS_URL, cache_dir / "epss_scores-current.csv.gz")

        async def fetch_optional(url: str, dest: Path) -> Path | None:
            # KEV is only an evaluation label; never fail the whole build over it.
            try:
                return await fetch(url, dest)
            except RuntimeError as exc:
                logger.warning("Optional dataset skipped (%s)", exc)
                return None

        kev_task = fetch_optional(KEV_URL, cache_dir / "known_exploited_vulnerabilities.json")
        *nvd_paths, epss_path, kev_path = await asyncio.gather(*nvd_tasks, epss_task, kev_task)

    if epss_path is None:
        raise RuntimeError("EPSS dataset could not be downloaded")
    return [p for p in nvd_paths if p is not None], epss_path, kev_path


def local_datasets(cache_dir: Path) -> tuple[list[Path], Path, Path | None]:
    """Find previously downloaded files for an --offline build."""
    nvd = sorted(cache_dir.glob("nvdcve-2.0-*.json*"))
    nvd = [p for p in nvd if not p.name.endswith(".part")]
    epss_candidates = sorted(cache_dir.glob("epss_scores*.csv*"))
    if not nvd:
        raise FileNotFoundError(f"No NVD feeds (nvdcve-2.0-*.json[.gz]) in {cache_dir}")
    if not epss_candidates:
        raise FileNotFoundError(f"No EPSS file (epss_scores*.csv[.gz]) in {cache_dir}")
    kev = cache_dir / "known_exploited_vulnerabilities.json"
    return nvd, epss_candidates[-1], kev if kev.exists() else None


def load_kev(path: Path) -> tuple[list[tuple], str | None]:
    """Parse the CISA KEV JSON into rows for the `kev` table."""
    with path.open("rb") as fh:
        data = json.load(fh)  # ~1.5k entries, tiny
    rows = []
    for v in data.get("vulnerabilities", []):
        cve_id = (v.get("cveID") or "").strip().upper()
        if not _CVE_RE.match(cve_id):
            continue
        rows.append((
            cve_id, v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"),
            v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"),
        ))
    logger.info("Loaded %d KEV entries (catalog %s)", len(rows), data.get("catalogVersion"))
    return rows, data.get("catalogVersion")


# --------------------------------------------------------------------------- #
# Parsing stage
# --------------------------------------------------------------------------- #
def _open_maybe_gzip(path: Path, mode: str = "rb"):
    """Open .gz transparently; everything else as-is."""
    if path.suffix == ".gz":
        return gzip.open(path, mode)
    return path.open(mode)


def _num(value: Any) -> float | None:
    """ijson yields Decimal for numbers; normalise to float."""
    if value is None:
        return None
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def pick_cvss(metrics: dict[str, Any] | None) -> tuple[float | None, str | None, str | None, str | None]:
    """
    Choose one CVSS rating for a CVE.

    Returns (base_score, version, vector, severity). Within a CVSS version we
    prefer NVD's own "Primary" assessment over a CNA's "Secondary" one.
    """
    if not metrics:
        return None, None, None, None
    for key in CVSS_PREFERENCE:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entries = sorted(entries, key=lambda e: 0 if e.get("type") == "Primary" else 1)
        entry = entries[0]
        data = entry.get("cvssData") or {}
        score = _num(data.get("baseScore"))
        if score is None:
            continue
        # v3/v4 keep severity inside cvssData; v2 keeps it on the outer entry.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return score, data.get("version"), data.get("vectorString"), severity
    return None, None, None, None


def pick_description(descriptions: list[dict[str, Any]] | None) -> str | None:
    """Return the English description (NVD always has one, but be defensive)."""
    if not descriptions:
        return None
    for d in descriptions:
        if d.get("lang", "").lower().startswith("en"):
            return (d.get("value") or "").strip() or None
    return (descriptions[0].get("value") or "").strip() or None


def iter_nvd_feed(path: Path, *, include_rejected: bool = False) -> Iterator[CveRow]:
    """
    Stream CVE records out of one NVD 2.0 feed file without loading it all.

    ijson walks the JSON token stream and materialises one element of the
    `vulnerabilities` array at a time.
    """
    with _open_maybe_gzip(path, "rb") as fh:
        for item in ijson.items(fh, "vulnerabilities.item"):
            cve = item.get("cve") or {}
            cve_id = (cve.get("id") or "").strip().upper()
            if not _CVE_RE.match(cve_id):
                continue
            status = cve.get("vulnStatus")
            if status == "Rejected" and not include_rejected:
                continue
            score, version, vector, severity = pick_cvss(cve.get("metrics"))
            yield CveRow(
                cve_id=cve_id,
                cvss_score=score,
                description=pick_description(cve.get("descriptions")),
                cvss_version=version,
                cvss_vector=vector,
                severity=severity.upper() if isinstance(severity, str) else None,
                published=cve.get("published"),
                last_modified=cve.get("lastModified"),
                vuln_status=status,
            )


def load_epss(path: Path) -> EpssData:
    """
    Parse the EPSS CSV into a dict. ~300k rows -> ~40 MB, fine to hold in RAM
    and much faster than a SQL UPDATE-join afterwards.
    """
    scores: dict[str, tuple[float, float]] = {}
    model_version = score_date = None
    with _open_maybe_gzip(path, "rb") as raw:
        text = io.TextIOWrapper(raw, encoding="utf-8", newline="")
        first = text.readline()
        if first.startswith("#"):
            # "#model_version:v2025.03.14,score_date:2026-11-12T12:55:00Z"
            for part in first.lstrip("#").strip().split(","):
                key, _, val = part.partition(":")
                if key == "model_version":
                    model_version = val
                elif key == "score_date":
                    score_date = val
            header_line = text.readline()
        else:
            header_line = first
        header = [h.strip().lower() for h in header_line.split(",")]
        try:
            i_cve, i_epss, i_pct = header.index("cve"), header.index("epss"), header.index("percentile")
        except ValueError as exc:
            raise ValueError(f"Unexpected EPSS header: {header_line!r}") from exc

        for row in csv.reader(text):
            if len(row) <= max(i_cve, i_epss, i_pct):
                continue
            cve_id = row[i_cve].strip().upper()
            if not _CVE_RE.match(cve_id):
                continue
            try:
                scores[cve_id] = (float(row[i_epss]), float(row[i_pct]))
            except ValueError:
                continue
    logger.info("Loaded %d EPSS scores (model %s, date %s)", len(scores), model_version, score_date)
    return EpssData(scores, model_version, score_date)


def _feed_sort_key(path: Path) -> tuple[int, str]:
    """
    Process yearly feeds first and 'modified'/'recent' feeds last, so that if
    someone drops those into the cache their newer data overwrites older rows.
    """
    m = re.search(r"nvdcve-2\.0-(\d{4})", path.name)
    return (0, m.group(1)) if m else (1, path.name)


# --------------------------------------------------------------------------- #
# Build stage
# --------------------------------------------------------------------------- #
def build_database(
    db_path: Path,
    nvd_files: list[Path],
    epss_file: Path,
    kev_file: Path | None = None,
    *,
    include_rejected: bool = False,
    batch_size: int = 5000,
) -> dict[str, Any]:
    """
    Compile the parsed datasets into SQLite. Returns build statistics.

    Performance settings: journal and fsync are disabled because the file is
    being built from scratch into a temp path; if the process dies we simply
    delete the temp file and start over. That makes the bulk load ~10x faster.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = db_path.with_name(db_path.name + ".tmp")
    tmp_path.unlink(missing_ok=True)

    started = time.perf_counter()
    epss = load_epss(epss_file)

    conn = sqlite3.connect(tmp_path)
    try:
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA synchronous = OFF")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA cache_size = -65536")  # 64 MB page cache
        conn.executescript(SCHEMA_SQL)

        # UPSERT so a later feed (e.g. 'modified') overrides an earlier row.
        insert_sql = """
            INSERT INTO vulnerabilities (
                cve_id, cvss_score, epss_score, description, cvss_version,
                cvss_vector, severity, epss_percentile, published,
                last_modified, vuln_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                cvss_score=excluded.cvss_score, description=excluded.description,
                cvss_version=excluded.cvss_version, cvss_vector=excluded.cvss_vector,
                severity=excluded.severity, published=excluded.published,
                last_modified=excluded.last_modified, vuln_status=excluded.vuln_status
        """

        nvd_count = 0
        batch: list[tuple] = []
        conn.execute("BEGIN")
        for feed in sorted(nvd_files, key=_feed_sort_key):
            feed_count = 0
            for row in iter_nvd_feed(feed, include_rejected=include_rejected):
                e, pct = epss.scores.get(row.cve_id, (None, None))
                batch.append((
                    row.cve_id, row.cvss_score, e, row.description, row.cvss_version,
                    row.cvss_vector, row.severity, pct, row.published,
                    row.last_modified, row.vuln_status,
                ))
                feed_count += 1
                if len(batch) >= batch_size:
                    conn.executemany(insert_sql, batch)
                    batch.clear()
            nvd_count += feed_count
            logger.info("Parsed %-28s %7d CVEs", feed.name, feed_count)
        if batch:
            conn.executemany(insert_sql, batch)
            batch.clear()

        # CVEs that EPSS scores but our NVD feeds do not contain (e.g. a
        # partial --start-year build, or very fresh CVEs). Keep them: an EPSS
        # score alone is still valuable to the ranking model.
        existing = {r[0] for r in conn.execute("SELECT cve_id FROM vulnerabilities")}
        epss_only = [
            (cve, e, pct) for cve, (e, pct) in epss.scores.items() if cve not in existing
        ]
        conn.executemany(
            "INSERT INTO vulnerabilities (cve_id, epss_score, epss_percentile) VALUES (?, ?, ?)",
            epss_only,
        )
        conn.execute("COMMIT")

        kev_rows, kev_version = load_kev(kev_file) if kev_file else ([], None)
        conn.executemany("INSERT OR REPLACE INTO kev VALUES (?, ?, ?, ?, ?, ?, ?)", kev_rows)
        conn.commit()

        total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        with_cvss = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE cvss_score IS NOT NULL"
        ).fetchone()[0]
        with_epss = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE epss_score IS NOT NULL"
        ).fetchone()[0]

        stats = {
            "schema_version": SCHEMA_VERSION,
            "built_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "nvd_feeds": ",".join(p.name for p in sorted(nvd_files, key=_feed_sort_key)),
            "nvd_records_parsed": nvd_count,
            "epss_model_version": epss.model_version,
            "epss_score_date": epss.score_date,
            "epss_only_rows": len(epss_only),
            "total_rows": total,
            "rows_with_cvss": with_cvss,
            "rows_with_epss": with_epss,
            "kev_catalog_version": kev_version,
            "kev_rows": len(kev_rows),
        }
        conn.executemany(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            [(k, None if v is None else str(v)) for k, v in stats.items()],
        )
        conn.commit()

        # ANALYZE gives the query planner statistics; VACUUM compacts the file.
        conn.execute("ANALYZE")
        conn.execute("VACUUM")
        # Switch to WAL so many concurrent readers (uvicorn workers) are cheap.
        conn.execute("PRAGMA journal_mode = WAL")
    except BaseException:
        conn.close()
        tmp_path.unlink(missing_ok=True)
        raise
    conn.close()

    # Remove the WAL side files of the temp DB before renaming. A cleanly
    # closed WAL database has none, but be defensive.
    for suffix in ("-wal", "-shm"):
        Path(str(tmp_path) + suffix).unlink(missing_ok=True)
    os.replace(tmp_path, db_path)

    stats["duration_seconds"] = round(time.perf_counter() - started, 1)
    logger.info(
        "Built %s: %d rows (%d with CVSS, %d with EPSS) in %.1fs",
        db_path, total, with_cvss, with_epss, stats["duration_seconds"],
    )
    return stats


def database_is_valid(db_path: Path) -> bool:
    """True if `db_path` exists and looks like a completed build."""
    if not db_path.exists() or db_path.stat().st_size == 0:
        return False
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT value FROM metadata WHERE key='total_rows'").fetchone()
            return bool(row and int(row[0]) > 0)
        finally:
            conn.close()
    except (sqlite3.Error, ValueError):
        return False


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    default_db = Path(os.environ.get("VULNDB_PATH", "data/vulnerabilities.db"))
    default_cache = Path(os.environ.get("VULNDB_CACHE_DIR", str(default_db.parent / "raw")))
    this_year = dt.date.today().year

    p = argparse.ArgumentParser(description="Build the local NVD + EPSS SQLite cache.")
    p.add_argument("--db", type=Path, default=default_db, help=f"Output DB (default {default_db})")
    p.add_argument("--cache-dir", type=Path, default=default_cache,
                   help="Where downloaded feeds are stored/reused")
    p.add_argument("--start-year", type=int,
                   default=int(os.environ.get("VULNDB_START_YEAR", FIRST_NVD_YEAR)))
    p.add_argument("--end-year", type=int, default=this_year)
    p.add_argument("--offline", action="store_true",
                   help="Do not download; use whatever is already in --cache-dir")
    p.add_argument("--max-age-hours", type=float, default=20.0,
                   help="Re-download cached files older than this")
    p.add_argument("--include-rejected", action="store_true", help="Keep REJECTED CVEs")
    p.add_argument("--force", action="store_true", help="Rebuild even if a valid DB exists")
    p.add_argument("--if-missing", action="store_true",
                   help="Exit 0 immediately if a valid DB already exists (used by the container)")
    p.add_argument("--keep-cache", action="store_true",
                   help="Keep downloaded raw files after building (default: delete to save space)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if database_is_valid(args.db) and not args.force:
        if args.if_missing:
            logger.info("%s already exists, skipping build", args.db)
            return 0
        logger.error("%s already exists; pass --force to rebuild", args.db)
        return 1

    if args.start_year < FIRST_NVD_YEAR or args.start_year > args.end_year:
        p.error(f"--start-year must be between {FIRST_NVD_YEAR} and --end-year")

    try:
        if args.offline:
            nvd_files, epss_file, kev_file = local_datasets(args.cache_dir)
        else:
            years = list(range(args.start_year, args.end_year + 1))
            nvd_files, epss_file, kev_file = asyncio.run(
                download_datasets(args.cache_dir, years, max_age_hours=args.max_age_hours)
            )
        stats = build_database(
            args.db, nvd_files, epss_file, kev_file, include_rejected=args.include_rejected
        )
    except (RuntimeError, FileNotFoundError, ValueError, ijson.JSONError, sqlite3.Error,
            json.JSONDecodeError) as exc:
        logger.error("Build failed: %s", exc)
        return 1

    if not args.keep_cache and not args.offline:
        for f in [*nvd_files, epss_file, *([kev_file] if kev_file else [])]:
            f.unlink(missing_ok=True)

    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
