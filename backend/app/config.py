"""Runtime settings for the API, read once from the environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    vulndb_path: str = field(default_factory=lambda: os.environ.get("VULNDB_PATH", "/app/data/vulnerabilities.db"))
    cors_origins: tuple[str, ...] = field(default_factory=lambda: tuple(
        o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()))
    # Whole-scan wall clock limit (crt.sh alone can take a minute on big domains).
    scan_timeout_seconds: float = field(default_factory=lambda: _float("SCAN_TIMEOUT_SECONDS", 240.0))
    # Scans running at once; keeps us inside crt.sh / InternetDB free-tier limits.
    max_concurrent_scans: int = field(default_factory=lambda: _int("MAX_CONCURRENT_SCANS", 2))
    # Finished scans kept in memory for GET /api/scans/{id}.
    scan_cache_size: int = field(default_factory=lambda: _int("SCAN_CACHE_SIZE", 20))
    # LLM (executive summary). Empty key -> deterministic template summary.
    llm_api_key: str = field(
        default_factory=lambda: os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", ""))
    llm_model: str = field(default_factory=lambda: os.environ.get("LLM_MODEL") or "claude-opus-5-5")
    llm_effort: str = field(default_factory=lambda: os.environ.get("LLM_EFFORT", "medium"))
    llm_timeout_seconds: float = field(default_factory=lambda: _float("LLM_TIMEOUT_SECONDS", 120.0))


settings = Settings()
