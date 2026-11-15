"""
Cipher Eclipse API (FastAPI).

Endpoints
    GET  /health                  liveness + whether the vuln DB / model / LLM are available
    POST /api/scan                full passive scan of one domain -> unified JSON for the dashboard
    GET  /api/scans/{scan_id}     a recent scan result again (in-memory, last SCAN_CACHE_SIZE scans)
    GET  /api/model               KEV classifier metrics (training report)
    GET  /api/ingest?domain=x     ingestion stage only (crt.sh + DNS), for debugging
    GET  /api/cve/{cve_id}        one row from vulnerabilities.db

Design
  * One shared aiohttp session and one VulnDB for the app's lifetime.
  * Scans are fully async; a semaphore caps concurrent scans so the free
    crt.sh / InternetDB tiers are not hammered, and a wall-clock timeout turns
    a hung upstream into a clean 504 instead of a stuck request.
  * Upstream failures map to proper HTTP codes (422 bad domain, 502 upstream
    down, 503 busy/not ready, 504 timeout); unexpected errors return a generic
    500 without leaking internals.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import OrderedDict
from contextlib import asynccontextmanager
from typing import Any

import aiohttp
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ingestion import CrtShError, normalize_domain, run_ingestion
from ingestion.pipeline import USER_AGENT
from ml.features import METRICS_PATH, MODEL_PATH
from vulndb import VulnDB, VulnDBNotReady

from .config import settings
from .integrations import PIPELINE_SOURCES
from .scan import run_scan

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("cipher.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = aiohttp.ClientSession(headers={"User-Agent": USER_AGENT})
    app.state.vulndb = VulnDB(settings.vulndb_path)
    app.state.scan_slots = asyncio.Semaphore(settings.max_concurrent_scans)
    app.state.scans: OrderedDict[str, dict[str, Any]] = OrderedDict()
    try:
        yield
    finally:
        await app.state.http.close()


app = FastAPI(title="Cipher Eclipse API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal error while processing the request."})


# --------------------------------------------------------------------------- models
class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253, examples=["vulnweb.com"])
    include_summary: bool = Field(True, description="Generate the executive summary")
    use_llm: bool = Field(True, description="Use the LLM for the summary (else the deterministic template)")


# --------------------------------------------------------------------------- routes
@app.get("/health")
async def health() -> dict:
    db: VulnDB = app.state.vulndb
    return {
        "status": "ok",
        "vulndb_ready": db.path.exists(),
        "vulndb_path": str(db.path),
        "model_ready": MODEL_PATH.exists(),
        "llm_configured": bool(settings.llm_api_key),
        "llm_model": settings.llm_model,
        "pipeline": PIPELINE_SOURCES,
    }


@app.post("/api/scan")
async def scan(req: ScanRequest) -> dict:
    try:
        domain = normalize_domain(req.domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    slots: asyncio.Semaphore = app.state.scan_slots
    try:
        await asyncio.wait_for(slots.acquire(), timeout=30)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=503, detail="Scanner busy, try again shortly.") from exc
    try:
        result = await asyncio.wait_for(
            run_scan(domain, session=app.state.http, vulndb=app.state.vulndb,
                     include_summary=req.include_summary, use_llm=req.use_llm),
            timeout=settings.scan_timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail=f"Scan of {domain} exceeded "
                                                    f"{settings.scan_timeout_seconds:.0f}s.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CrtShError as exc:
        raise HTTPException(status_code=502, detail=f"crt.sh unavailable: {exc}") from exc
    except aiohttp.ClientError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream data source error: {exc}") from exc
    finally:
        slots.release()

    cache: OrderedDict = app.state.scans
    cache[result["scan_id"]] = result
    while len(cache) > settings.scan_cache_size:
        cache.popitem(last=False)
    return result


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    result = app.state.scans.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found (results are kept in memory only).")
    return result


@app.get("/api/model")
async def model_info() -> dict:
    if not METRICS_PATH.exists():
        raise HTTPException(status_code=404, detail="Model has not been trained yet.")
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


@app.get("/api/ingest")
async def ingest(domain: str = Query(..., min_length=3, max_length=253)) -> dict:
    try:
        return await run_ingestion(domain, session=app.state.http)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CrtShError as exc:
        raise HTTPException(status_code=502, detail=f"crt.sh unavailable: {exc}") from exc


@app.get("/api/cve/{cve_id}")
async def cve(cve_id: str) -> dict:
    try:
        row = await app.state.vulndb.aget(cve_id)
    except VulnDBNotReady as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    return row
