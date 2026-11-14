#!/bin/sh
# Backend container entrypoint.
#
# 1. If /app/data/vulnerabilities.db does not exist (first start, or the
#    volume was wiped), build it from the NVD + EPSS bulk feeds.
# 2. Start the API (or whatever command was passed, e.g. `pytest`).
#
# Environment knobs (all optional):
#   VULNDB_PATH        DB location (default /app/data/vulnerabilities.db)
#   VULNDB_BUILD_MODE  blocking   - build before the API starts (default; API never runs without data)
#                      background - start the API immediately, build in parallel
#                      skip       - never build (e.g. frontend-only work, no internet)
#   VULNDB_START_YEAR  first NVD year to include (default 2002 = everything).
#                      Set e.g. 2018 for a much faster dev build.
#   VULNDB_OFFLINE     1 = build only from feeds already placed in /app/data/raw
#                      (no downloads; handy for demos without internet)
#   UVICORN_WORKERS    number of API worker processes (default 1)
set -eu

: "${VULNDB_PATH:=/app/data/vulnerabilities.db}"
: "${VULNDB_BUILD_MODE:=blocking}"
export VULNDB_PATH

build_db() {
    # --if-missing makes this a no-op when a valid DB is already present,
    # so restarts are instant. The builder writes to a .tmp file and renames
    # atomically, so a crash never leaves a half-built DB behind.
    if [ "${VULNDB_OFFLINE:-0}" = "1" ]; then
        python -m vulndb.build_db --db "$VULNDB_PATH" --if-missing --offline
    else
        python -m vulndb.build_db --db "$VULNDB_PATH" --if-missing
    fi
}

case "$VULNDB_BUILD_MODE" in
    blocking)
        if ! build_db; then
            echo "[entrypoint] WARNING: vulnerability DB build failed; starting API anyway." >&2
            echo "[entrypoint] /api/cve will return 503 until you run: docker compose exec backend python -m vulndb.build_db" >&2
        fi
        ;;
    background)
        build_db &
        ;;
    skip)
        echo "[entrypoint] VULNDB_BUILD_MODE=skip, not building the vulnerability DB." >&2
        ;;
    *)
        echo "[entrypoint] Unknown VULNDB_BUILD_MODE=$VULNDB_BUILD_MODE" >&2
        exit 2
        ;;
esac

# No arguments: run the API server. exec replaces this shell with uvicorn so
# `docker stop` delivers SIGTERM straight to it and it shuts down gracefully.
if [ "$#" -eq 0 ]; then
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 \
        --workers "${UVICORN_WORKERS:-1}" --proxy-headers
fi
exec "$@"
