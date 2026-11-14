# syntax=docker/dockerfile:1.7
#
# Cipher Eclipse backend (FastAPI) image
#   docker build -t aliakbarzaidi/cipher-eclipse-backend:latest ./backend
#
# Two stages:
#   builder  - pip + build cache, installs every dependency into an isolated venv
#   runtime  - slim image that only receives the finished venv + our code
# Result: no pip cache or build tooling in the shipped image, smaller and
# fewer CVEs (fitting, for a vulnerability-mapping tool).
#
# PID 1: run with `--init` (docker run) / `init: true` (compose, already set)
# so signals are forwarded and the background DB-build process is reaped.

ARG PYTHON_VERSION=3.12

############################ builder ##########################################
FROM python:${PYTHON_VERSION}-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Every pinned dependency ships prebuilt manylinux wheels for both x86_64 and
# arm64 (Apple Silicon), so no compiler/apt step is needed. If you add a
# package without wheels, add `apt-get install build-essential` HERE only;
# it must never reach the runtime image.

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only the requirements first: this layer is cached until requirements
# change, so editing Python code does not trigger a full reinstall.
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip \
    && pip install -r requirements.txt

############################ runtime ##########################################
FROM python:${PYTHON_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="cipher-eclipse-backend" \
      org.opencontainers.image.description="Cipher Eclipse passive OSINT attack-surface API" \
      org.opencontainers.image.vendor="CS3002 Information Security, Fall 2026"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    VULNDB_PATH=/app/data/vulnerabilities.db \
    VULNDB_CACHE_DIR=/app/data/raw

# Run as an unprivileged user.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app . .
RUN chmod 0755 docker-entrypoint.sh \
    && mkdir -p /app/data \
    && chown app:app /app/data

USER app

# The DB lives here; mount a named volume so it survives container rebuilds.
VOLUME ["/app/data"]

EXPOSE 8000

# Uses Python instead of curl so we don't need to install curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD []
