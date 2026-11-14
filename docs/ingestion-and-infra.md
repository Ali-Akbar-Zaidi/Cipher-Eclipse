# Cipher Eclipse: ingestion, vulnerability cache, containers, evaluation

Hadi's slice of Cipher Eclipse (CS3002 Information Security, Fall 2026): passive
OSINT ingestion, the offline NVD + EPSS (+ CISA KEV) SQLite cache, Docker setup for
the whole team, and the evaluation scripts. The project overview is the root
[README](../README.md).

Hand-off to Azaan: ingestion returns resolved subdomains and IPs only. CDN
detection ("origin hidden" hosts) and the Shodan InternetDB lookups happen in his
stage, on top of `result["subdomains"]` / `result["unique_ips"]`.

**Everything here is passive.** Network activity is limited to HTTPS calls to
public datasets (crt.sh, NVD feeds, EPSS, CISA KEV) and ordinary DNS lookups through public
resolvers (1.1.1.1 / 8.8.8.8 / 9.9.9.9). Nothing connects to the target's ports.
`backend/tests/test_passive_scope.py` fails the test run if anyone adds raw
sockets or active scanners.

## Layout

```
README.md                   team README (project overview)
docs/ingestion-and-infra.md this file
docker-compose.yml          both services, ports 8000 / 3000, named volume for the DB
.env.example                compose knobs (copy to .env)
backend/
  .env.example              backend secrets, e.g. LLM API key (copy to backend/.env)
  Dockerfile                multi-stage, non-root, healthcheck
  docker-entrypoint.sh      builds vulnerabilities.db if missing, then starts uvicorn
  requirements.txt          pinned runtime deps (requirements-dev.txt for tests)
  app/main.py               starter FastAPI app (Shuja's routing replaces/extends it)
  ingestion/                crt.sh fetch + cleaning, aiodns resolution, pipeline, CLI
  vulndb/                   build_db.py (offline builder), query.py (read-only lookups)
  eval/                     subdomain_recall.py, cve_precision.py, README
  tests/                    50 offline tests (no network needed)
frontend/
  Dockerfile                Next.js standalone multi-stage build
  app/, package.json        PLACEHOLDER app so compose works today; Shuja's code replaces it
```

## Quick start (whole team)

```bash
cp backend/.env.example backend/.env    # add the LLM API key
cp frontend/.env.example frontend/.env
cp .env.example .env                    # optional compose knobs
docker compose up --build
# backend:  http://localhost:8000/docs
# frontend: http://localhost:3000
```

The first start downloads the NVD feeds (2002 to now), the EPSS CSV and the CISA KEV
catalogue and builds
`vulnerabilities.db` in the `vulndb-data` volume. That takes a few minutes; watch it
with `docker compose logs -f backend`. Later starts skip the build. For a faster dev
build set `VULNDB_START_YEAR=2018` in `.env`. To rebuild:
`docker compose run --rm backend python -m vulndb.build_db --force`.

Push images to Docker Hub: `docker login && docker compose push`
(tags: `aliakbarzaidi/cipher-eclipse-backend`, `aliakbarzaidi/cipher-eclipse-frontend`).

## 1. Ingestion (crt.sh + DNS)

```python
from ingestion import run_ingestion
result = await run_ingestion("example.com")
result["subdomains"]   # {"api.example.com": ["93.184.216.34"], ...}  (max 500)
result["unique_ips"]   # de-duplicated IPv4 list for Azaan's Shodan stage
```

CLI: `python -m ingestion example.com --pretty`

* Queries `https://crt.sh/?q=%.example.com&output=json`. The `%.` wildcard is what
  makes crt.sh return subdomain certificates; plain `q=example.com` only matches the apex.
  The apex is always added back.
* Splits multi-line `name_value` (and `common_name`), strips `*.`, lowercases, drops
  e-mails, invalid names and out-of-scope SANs, de-duplicates and sorts.
* Retries crt.sh's frequent 502/503/timeouts and HTML error pages with backoff.
* Resolves A records with aiodns (100 queries in flight), stops at exactly
  **500 resolved** subdomains (the proposal's per-target cap; pass a lower
  `max_resolved` to shrink it). Input is sorted, so the same 500 come back every run.
  Private/reserved IPs are dropped (useless to InternetDB).
* `stats.wildcard_zones` counts zones seen only as `*.zone` certificates. Hosts
  under those are invisible to CT, one of the visibility limits the proposal reports.

## 2. Vulnerability cache (SQLite)

```bash
cd backend && python -m vulndb.build_db            # -> data/vulnerabilities.db
```

```python
from vulndb import VulnDB
db = VulnDB()                                   # path from $VULNDB_PATH
db.get("CVE-2021-44228")                        # dict or None
await db.aget_many(["CVE-2021-44228", ...])     # non-blocking, for FastAPI
```

Table `vulnerabilities`: `cve_id` (TEXT PRIMARY KEY, auto-indexed), `cvss_score`,
`epss_score`, `description`, plus `cvss_version`, `cvss_vector`, `severity`,
`epss_percentile`, `published`, `last_modified`, `vuln_status`. Table `metadata`
records build time, the EPSS score date and the KEV catalogue version.

Table `kev` holds the CISA Known Exploited Vulnerabilities catalogue. It is kept
separate on purpose: the proposal uses KEV membership as the **label** for ranking
quality and the classifier, so it must never be a model input or part of the risk
score. Read it only through `VulnDB().kev_labels([...])` in training/evaluation code.

* NVD JSON 2.0 yearly feeds are stream-parsed with `ijson`, so RAM stays low.
* CVSS preference: v3.1 > v3.0 > v4.0 > v2, NVD "Primary" over CNA scores.
* Rejected CVEs are skipped. CVEs that only EPSS knows about are kept (EPSS score, no CVSS).
* Builds into a `.tmp` file and renames atomically, so a crash never leaves a half DB.
* Benchmark on 308k synthetic rows: build 4 s, single lookup ~9 µs, 500-ID batch ~3 ms.

## 3. Docker

* Backend: Python 3.12-slim, two stages, venv copied into a clean runtime, runs as
  uid 10001, healthcheck on `/health`. The entrypoint builds the DB if missing
  (`VULNDB_BUILD_MODE=blocking|background|skip`, `VULNDB_OFFLINE=1` to use only
  feeds already in `/app/data/raw`).
* Frontend: node 22-alpine, three stages, Next.js `output: "standalone"` (required in
  Shuja's `next.config`; the build fails with a clear message if it is missing),
  non-root. `NEXT_PUBLIC_API_URL` is a build arg; server-side code can use
  `API_URL_INTERNAL=http://backend:8000`.

## 4. Evaluation

See [backend/eval/README.md](../backend/eval/README.md). In short:

```bash
# baseline = subfinder ∪ Amass (passive), as in the proposal
python -m eval.subdomain_recall --targets-file eval/targets.txt --baseline-dir baselines/ \
    --run-subfinder --run-amass --resolve-baseline
python -m eval.cve_precision template --scan scan.json --out eval/labels.csv   # then hand-label
python -m eval.cve_precision score --labels eval/labels.csv
```

## Tests

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
pytest
```
