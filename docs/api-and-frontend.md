# Cipher Eclipse: API, ML classifier, LLM summary and dashboard

Shuja's slice of Cipher Eclipse (CS3002 Information Security, Fall 2026): the FastAPI
routing that runs the whole pipeline, the KEV classifier, the LLM executive summary
with its hallucination check, and the Next.js dashboard. The project overview is the
root [README](../README.md); ingestion, the vulnerability cache and Docker are in
[ingestion-and-infra.md](ingestion-and-infra.md).

## Layout

```
backend/
  app/main.py            FastAPI app: routes, CORS, error mapping, scan concurrency + timeout
  app/scan.py            orchestrator: ingestion -> CDN filter -> InternetDB -> VulnDB -> risk -> summary
  app/integrations.py    adapters for Azaan's modules (built-in fallbacks until they land)
  app/config.py          settings from environment variables
  app/llm/summary.py     prompt, JSON schema, Claude call, deterministic template fallback
  app/llm/validator.py   hallucination check: every CVE / IP / hostname vs the scan data
  ml/train_kev_classifier.py   training script (isolated; reads vulnerabilities.db)
  ml/features.py         feature order + transforms shared by training and inference
  ml/artifacts/          kev_classifier.pkl, metrics JSON, Markdown training report
  tests/test_scan_api.py, test_llm_validator.py, test_ml_training.py
frontend/
  app/page.js            dashboard: scan form, stats, graph + details, summary, tables
  components/ThreatGraph.js   React Flow graph (dagre layout)
  components/DataTables.js    sortable vulnerability + asset tables
  components/SummaryPanel.js  executive summary with validation badge
  components/DetailsPanel.js  side panel for the selected node
  lib/graph.js           scan JSON -> nodes/edges: domain -> subdomain -> IP -> service (CPE) -> CVE
```

## Running locally without Docker

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate      # Windows; use .venv/bin/activate elsewhere
pip install -r requirements.txt -r requirements-dev.txt
python -m vulndb.build_db                           # once, a few minutes
VULNDB_PATH=data/vulnerabilities.db uvicorn app.main:app --port 8000

cd ../frontend
npm ci
npm run dev                                         # http://localhost:3000
```

`docker compose up --build` works exactly as before (see the root README).

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | DB / model / LLM readiness and which pipeline implementations are active |
| POST | `/api/scan` | Full passive scan. Body: `{"domain": "nmap.org", "use_llm": true, "include_summary": true}` |
| GET | `/api/scans/{scan_id}` | A recent result again (in memory, last `SCAN_CACHE_SIZE`) |
| GET | `/api/model` | KEV classifier metrics |
| GET | `/api/ingest?domain=` | Ingestion stage only (debugging) |
| GET | `/api/cve/{id}` | One CVE from the local cache |

Errors: `422` invalid domain, `502` crt.sh / upstream down, `503` scanner busy,
`504` scan exceeded `SCAN_TIMEOUT_SECONDS`, `500` generic (details only in the log).
CORS allows `CORS_ORIGINS` (default `http://localhost:3000`).

Everything in the request path is `async`. Blocking work runs off the event loop:
SQLite through `VulnDB.aget_many` and model inference through `asyncio.to_thread`.
At most `MAX_CONCURRENT_SCANS` scans run at once to stay inside the free crt.sh and
InternetDB limits.

### `POST /api/scan` response

```jsonc
{
  "scan_id": "5e9d...", "domain": "nmap.org", "started_at": "...",
  "stats": { "subdomains": 4, "unique_ips": 1, "origin_hidden": 0, "scanned_ips": 1,
             "hosts_with_data": 1, "vulnerabilities": 181, "critical": 27, "high": 66,
             "kev_likely": 15, ... },
  "subdomains": [ { "name": "issues.nmap.org", "ips": ["50.116.1.184"] } ],
  "hosts": [ { "ip": "50.116.1.184", "subdomains": [...], "origin_hidden": false, "cdn": null,
               "internetdb": true, "ports": [22, 25, 80, 443], "cpes": [...], "hostnames": [...],
               "tags": [...], "cves": [...], "max_risk": 98.7 } ],
  "vulnerabilities": [ { "cve_id": "CVE-2021-44790", "cvss_score": 9.8, "epss_score": 0.968,
                         "severity": "CRITICAL", "kev_probability": 0.59, "risk_score": 98.7,
                         "hosts": ["50.116.1.184"], "confidence": "potential",
                         "backport_suspect": true, "description": "...", ... } ],
  "summary": { "generator": "llm" | "template", "headline": "...", "overall_risk": "critical",
               "executive_summary": "...", "key_findings": [...], "recommendations": [...],
               "limitations": [...], "validation": { "status": "accepted" | "sanitized",
               "entities_checked": 45, "unknown_entities": [], "hallucination_rate": 0.0 } },
  "pipeline": { "cdn_filter": "builtin", "internetdb": "builtin", "risk_scoring": "builtin" },
  "timings": { "ingestion": 29.6, "internetdb": 0.19, "risk_scoring": 1.2, "total": 31.0 },
  "warnings": []
}
```

Every CVE is labelled `"confidence": "potential"` (InternetDB infers CVEs from versions)
and `backport_suspect` reuses `eval.cve_precision.distro_hint`, so the dashboard and the
precision evaluation flag the same rows. The payload is also a valid input for
`python -m eval.cve_precision template --scan scan.json` (it has a `hosts` list).

## Hand-off to Azaan: integration points

`app/integrations.py` imports Azaan's modules if they exist and otherwise uses small
built-in versions, so the API works today and switches over automatically. `/health`
and the `pipeline` field in every scan show which one ran. Expected modules
(package `backend/pipeline/`, with an `__init__.py`):

| Module | Function | Contract |
|---|---|---|
| `pipeline/cdn_filter.py` | `filter_cdn_ips(ips)` (sync or async) | returns `(scannable_ips, {hidden_ip: provider})` |
| `pipeline/shodan_internetdb.py` | `async lookup_ips(ips, session=...)` | returns `{ip: {"ports", "hostnames", "cpes", "vulns", "tags"}}`; IPs with a 404 are left out |
| `pipeline/risk_scoring.py` | `score_vulnerabilities(vulns, hosts)` (sync or async) | adds `kev_probability` (0-1) and `risk_score` (0-100) to each vuln dict and returns the list |

`vulns` are the dicts shown above (CVSS/EPSS already filled from the SQLite cache,
`hosts` = list of IPs); `hosts` is `{ip: host_dict}` so exposure (open ports) can be
weighted in. Loading the model:

```python
import joblib
from ml.features import MODEL_PATH, to_matrix
model = joblib.load(MODEL_PATH)                       # load once, reuse
p_kev = model.predict_proba(to_matrix(vulns))[:, 1]   # NaN CVSS/EPSS are imputed inside the pipeline
```

The built-in risk score (replace freely): `100 × exposure × (0.5 × (0.4·CVSS/10 + 0.6·EPSS) + 0.5 × min(1, p_kev / 0.5))`,
with `exposure = 1.0` if the host exposes an admin/database/file-sharing port, else `0.85`.

## KEV classifier

```bash
cd backend
python -m ml.train_kev_classifier          # reads data/vulnerabilities.db, writes ml/artifacts/
```

* Features: CVSS base score and EPSS probability only. KEV membership is the label and is
  never an input (it is read from the separate `kev` table purely for training).
* Data: every CVE in the cache with a CVSS or EPSS score (406,615 CVEs, 1,781 in KEV, 0.44%).
* Stratified 80/20 split, seed 42. Model choice by 5-fold CV average precision on the
  training split only; the held-out test split is used once, for the report.
* Candidates: Logistic Regression on `[CVSS/10, logit(EPSS)]` (median imputation plus
  missing-value indicators) and Histogram Gradient Boosting with monotonic constraints
  (risk never drops when CVSS or EPSS rises). Logistic Regression won (CV AP 0.367 vs 0.261).
* The shipped `.pkl` is refit on all labelled data; reported numbers are held-out.

Held-out test split (81,323 CVEs, 356 in KEV):

| Ranker | ROC-AUC | Avg. precision | Precision@100 | KEV recall in top 1% | top 5% |
|---|---|---|---|---|---|
| **Logistic Regression (shipped)** | 0.955 | **0.316** | **0.68** | 0.47 | 0.78 |
| Gradient Boosting | 0.959 | 0.251 | 0.51 | 0.46 | 0.80 |
| EPSS only | 0.953 | 0.308 | 0.65 | 0.47 | 0.77 |
| Weighted score (0.4 CVSS + 0.6 EPSS) | 0.914 | 0.313 | 0.67 | 0.48 | 0.70 |
| CVSS only | 0.751 | 0.011 | 0.01 | 0.02 | 0.13 |

Reading: plain CVSS sorting is close to useless for finding exploited CVEs. EPSS does most
of the work; the classifier adds a small, consistent gain on top of EPSS and the weighted
score. This is the comparison the proposal asks for. Full numbers, including the CV folds,
are in `ml/artifacts/kev_classifier_report.md` and `/api/model`.

The `.pkl` must be loaded with the pinned scikit-learn version (1.9.1, in requirements.txt).
Retrain after rebuilding the database to pick up new KEV entries.

## LLM executive summary and hallucination check

* Model: Claude via the Anthropic Messages API (`LLM_API_KEY`, `LLM_MODEL`, default
  `claude-opus-5-5`, `LLM_EFFORT` default `medium`). The request uses `output_config.format`
  with a strict JSON schema (`SUMMARY_SCHEMA`), so the reply is always parseable JSON with
  `headline`, `overall_risk`, `executive_summary`, `key_findings[]`, `recommendations[]`,
  `limitations[]`; findings and recommendations carry `cve_ids`, `hosts`, `ips` lists.
  Server-side refusal fallbacks are enabled for the models that support them.
* The model only sees a compact context: the top 25 CVEs by risk and their hosts.
* `validate_summary()` then checks every CVE ID, IPv4 address and hostname, both in the
  list fields and inside the free text (regex extraction), against the full scan:
  * unknown list entries are removed; an IP paired with CVEs Shodan never reported on that
    IP is removed too (fabricated association);
  * a finding or recommendation whose text cites an unknown entity is dropped whole;
  * headline / summary sentences citing unknown entities are removed;
  * the payload is rejected outright on a schema violation or when more than 25% of the
    cited entities are unknown; the cleaned payload is re-scanned and must be fully grounded.
* No key, an API error, a refusal or a rejected payload falls back to a deterministic summary
  built from the data, which passes the same validator. The response reports
  `generator`, `validation` (entities checked, removed, hallucination rate) and, after a
  rejection, `llm_validation`, so the hallucination rate can be measured for the evaluation.

## Dashboard

* Threat graph (React Flow + dagre, left to right): root domain → subdomains → resolved IPs →
  services (CPEs) → CVEs. CDN addresses are dashed grey "Origin hidden" nodes. CVE nodes are
  coloured by CVSS severity, with critical/high in deep red and a red glow, and a
  `KEV-likely` tag when the model gives ≥10%. InternetDB reports CVEs per host, so each CVE
  is attached to the CPE its NVD description names; others go to an "Unattributed software"
  node rather than to a guessed service. "CVEs per service" and "Min risk" controls keep large
  hosts readable (the rest are in the table).
* Clicking a node, a table row or an entity chip in the summary selects it everywhere:
  the graph centres on it and the side panel shows its details.
* Tables: vulnerabilities (sortable by risk score, severity, CVSS, EPSS, KEV probability)
  and assets (subdomain, IP, CDN status, ports, software, CVE count, max risk), with a filter box.
* Export / open scan JSON, so a demo does not depend on crt.sh being up.

## Tests

```bash
cd backend && pytest        # 79 tests, all offline
```

`test_scan_api.py` runs `POST /api/scan` with every network stage faked (CDN tagging,
InternetDB hand-off, scoring, caching, 422/502/504 mapping, CORS, LLM sanitising and
fallback). `test_llm_validator.py` covers the hallucination rules. `test_ml_training.py`
trains on a synthetic database and reloads the exported model.
