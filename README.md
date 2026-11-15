# Cipher Eclipse 🌐🔍

**Passive Attack Surface Mapping and Exploit-Aware Risk Prioritisation**

Cipher Eclipse is a defensive Open Source Intelligence (OSINT) tool designed to map an organization's external attack surface using strictly passive, public data sources. It discovers forgotten subdomains, maps exposed services to known vulnerabilities, and prioritizes remediation efforts using exploit-likelihood scoring and Machine Learning—without sending any active scanning traffic to the target.

---

## 🚀 Features

- **Passive Subdomain Discovery:** Aggregates subdomains from public Certificate Transparency logs via `crt.sh`.
- **CDN & WAF Filtering:** Automatically filters out "origin hidden" hosts (e.g., Cloudflare, Fastly) to prevent polluting the attack graph with CDN edge server data.
- **Vulnerability Mapping:** Queries Shodan InternetDB (free API) for exposed ports, CPEs, and CVEs without sending active probes or banner-grabbing payloads.
- **Risk Prioritization Engine:** Enriches CVEs with local NVD severity data and FIRST EPSS (Exploit Prediction Scoring System) scores, supplemented by an experimental ML classifier trained on CISA KEV data.
- **Interactive Attack Graph:** Visualizes the threat landscape hierarchically (Domain → Subdomains → IP Addresses → Services → CVEs) on a web dashboard.
- **AI-Generated Executive Summary:** Uses an LLM to generate a plain-English, prioritized risk report enforced via strict JSON parsing and hallucination checks.

---

## 🛠️ Tech Stack

**Frontend**
- **Framework:** Next.js (App Router)
- **Styling:** Tailwind CSS
- **Visualization:** React Flow / Cytoscape.js (Attack Graph rendering)

**Backend & ML**
- **Framework:** Python (FastAPI)
- **Data Sources:** `crt.sh` API, Shodan InternetDB API
- **AI/LLM:** Pro LLM API (prompted for strict JSON output and hallucination validation)
- **Machine Learning:** Scikit-learn (Logistic Regression / Gradient Boosting for risk classification)

**Data Ingestion & Ops**
- **Caching:** Local SQLite database (Bulk NVD and EPSS ingestion to bypass API limits)
- **Containerization:** Docker & Docker Compose (`aliakbarzaidi` registry namespace)

---

## ⚙️ Local Development & Setup

*(Ensure Docker and Docker Compose are installed on your machine.)*

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Ali-Akbar-Zaidi/Cipher-Eclipse.git
   cd Cipher-Eclipse
   ```

2. **Set up Environment Variables:**
   * Copy the example `.env` files for both frontend and backend:
     `cp backend/.env.example backend/.env` and `cp frontend/.env.example frontend/.env`.
   * Add your LLM API keys to the backend `.env`.
   * Optional: `cp .env.example .env` for compose settings (image tag, faster dev DB build).

3. **Run with Docker Compose** (Compose v2.24+, i.e. the `docker compose` plugin):
   ```bash
   docker compose up --build
   ```
   * The Next.js frontend will be available at `http://localhost:3000`
   * The FastAPI backend will be available at `http://localhost:8000` (API docs at `/docs`)
   * The first start downloads the NVD, EPSS and CISA KEV datasets and builds the local
     SQLite cache, which takes a few minutes. Follow it with `docker compose logs -f backend`.

Ingestion, vulnerability cache, Docker and evaluation details:
[docs/ingestion-and-infra.md](docs/ingestion-and-infra.md).

API, KEV classifier, LLM summary validation and dashboard details:
[docs/api-and-frontend.md](docs/api-and-frontend.md).

---

## ⚠️ Ethics & Scope

**Cipher Eclipse is built strictly for passive reconnaissance and academic research.**
- The tool performs **zero active network scanning, probing, or exploitation**.
- Usage is restricted to domains owned by the user, public test targets (e.g., `scanme.nmap.org`), or organizations with public vulnerability disclosure programs permitting OSINT research.

*Developed for CS3002 Information Security, Fall 2026 at FAST-NUCES Lahore.*
