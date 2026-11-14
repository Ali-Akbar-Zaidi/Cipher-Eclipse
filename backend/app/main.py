"""
Starter FastAPI application for the Cipher Eclipse backend container.

Shuja owns the real API routing. This file gives the container something to
serve from day one and shows how to wire in Hadi's modules correctly:

  * one shared aiohttp.ClientSession for the app's lifetime (connection reuse)
  * a single VulnDB instance (read-only SQLite, per-thread connections)
  * /health reports whether the vulnerability DB has finished building, which
    docker-compose uses as the container healthcheck

Endpoints:
    GET /health                     -> {"status": "ok", "vulndb_ready": true, ...}
    GET /api/ingest?domain=x.com    -> crt.sh + DNS ingestion result
    GET /api/cve/{cve_id}           -> one row from vulnerabilities.db
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import aiohttp
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from ingestion import CrtShError, run_ingestion
from ingestion.pipeline import USER_AGENT
from vulndb import VulnDB, VulnDBNotReady

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = aiohttp.ClientSession(headers={"User-Agent": USER_AGENT})
    app.state.vulndb = VulnDB(os.environ.get("VULNDB_PATH", "/app/data/vulnerabilities.db"))
    try:
        yield
    finally:
        await app.state.http.close()


app = FastAPI(title="Cipher Eclipse API", version="0.1.0", lifespan=lifespan)

# The Next.js dev server / container calls us from another origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict:
    db: VulnDB = app.state.vulndb
    ready = db.path.exists()
    return {"status": "ok", "vulndb_ready": ready, "vulndb_path": str(db.path)}


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
